from pathlib import Path
from datetime import datetime, timezone
from PIL import Image
import json
import struct
import sys
import zlib

source_dir = Path(sys.argv[1])
report_dir = Path(sys.argv[2])
findings_path = Path(sys.argv[3])

reports = sorted(
    report_dir.glob("lsb_payload_analysis_*.json"),
    key=lambda p: p.stat().st_mtime,
    reverse=True
)

if not reports:
    raise FileNotFoundError("No Analysis 09 JSON report found.")

source_report = reports[0]
previous = json.loads(source_report.read_text(encoding="utf-8"))

SIGNATURES = {
    "PNG": bytes.fromhex("89504e470d0a1a0a"),
    "JPEG": bytes.fromhex("ffd8ff"),
    "PDF": b"%PDF-",
    "ZIP": bytes.fromhex("504b0304"),
    "GZIP": bytes.fromhex("1f8b08"),
    "GIF87a": b"GIF87a",
    "GIF89a": b"GIF89a",
    "7ZIP": bytes.fromhex("377abcaf271c"),
    "RAR": bytes.fromhex("526172211a07"),
}

CHANNEL_ORDERS = {
    "R": (0,),
    "G": (1,),
    "B": (2,),
    "RGB": (0,1,2),
    "BGR": (2,1,0),
}

def extract_stream(pixels, order, bit_position, alignment):
    bits = []
    for pixel in pixels:
        for channel in order:
            bits.append((pixel[channel] >> bit_position) & 1)

    bits = bits[alignment:]
    usable = len(bits) // 8 * 8
    out = bytearray()

    for i in range(0, usable, 8):
        value = 0
        for bit in bits[i:i+8]:
            value = (value << 1) | bit
        out.append(value)

    return bytes(out)

def validate_png(data, offset):
    try:
        if data[offset:offset+8] != SIGNATURES["PNG"]:
            return False, "bad PNG signature"

        pos = offset + 8
        chunks = 0

        while pos + 12 <= len(data) and chunks < 10000:
            length = struct.unpack(">I", data[pos:pos+4])[0]

            if length > 100_000_000:
                return False, "implausible PNG chunk length"

            kind = data[pos+4:pos+8]
            end = pos + 12 + length

            if end > len(data):
                return False, "PNG extends beyond extracted stream"

            payload = data[pos+8:pos+8+length]
            stored = struct.unpack(">I", data[end-4:end])[0]
            actual = zlib.crc32(kind + payload) & 0xffffffff

            if stored != actual:
                return False, "PNG CRC mismatch"

            pos = end
            chunks += 1

            if kind == b"IEND":
                return True, f"valid PNG structure ({chunks} chunks)"

        return False, "no valid PNG IEND"

    except Exception as exc:
        return False, str(exc)

def validate_candidate(fmt, data, offset):
    remaining = data[offset:]

    if fmt == "PNG":
        return validate_png(data, offset)

    if fmt == "JPEG":
        end = remaining.find(b"\xff\xd9", 3)
        return (
            end != -1,
            "JPEG EOI found" if end != -1 else "no JPEG EOI"
        )

    if fmt == "PDF":
        end = remaining.find(b"%%EOF")
        return (
            end != -1,
            "PDF EOF found" if end != -1 else "no PDF EOF"
        )

    if fmt == "ZIP":
        # Local header requires at least 30 bytes and sane fields.
        if len(remaining) < 30:
            return False, "truncated ZIP header"

        version = int.from_bytes(remaining[4:6], "little")
        method = int.from_bytes(remaining[8:10], "little")
        name_len = int.from_bytes(remaining[26:28], "little")
        extra_len = int.from_bytes(remaining[28:30], "little")

        sane = (
            version <= 1000 and
            method in {0,1,6,8,9,12,14,93,95,98,99} and
            name_len <= 4096 and
            extra_len <= 65535 and
            30 + name_len + extra_len <= len(remaining)
        )

        return sane, (
            f"ZIP header fields plausible "
            f"(method={method}, filename_length={name_len})"
            if sane else "implausible ZIP local header"
        )

    if fmt == "GZIP":
        if len(remaining) < 10:
            return False, "truncated GZIP header"

        method = remaining[2]
        flags = remaining[3]
        sane = method == 8 and (flags & 0xE0) == 0

        return sane, (
            "plausible GZIP header"
            if sane else "invalid GZIP method/flags"
        )

    if fmt in ("GIF87a", "GIF89a"):
        if len(remaining) < 13:
            return False, "truncated GIF header"

        width = int.from_bytes(remaining[6:8], "little")
        height = int.from_bytes(remaining[8:10], "little")
        sane = 0 < width <= 65535 and 0 < height <= 65535

        return sane, (
            f"plausible GIF dimensions {width}x{height}"
            if sane else "invalid GIF dimensions"
        )

    if fmt == "7ZIP":
        return (
            len(remaining) >= 32,
            "7ZIP signature present; deeper CRC validation required"
        )

    if fmt == "RAR":
        return (
            len(remaining) >= 16,
            "RAR signature present; deeper validation required"
        )

    return False, "unsupported validator"

results = []

print("LSB SIGNATURE VALIDATION")
print("=" * 70)
print("Analysis 09 source:", source_report.name)

for exhibit in previous["exhibits"]:
    name = exhibit["exhibit"]
    candidate_tests = [
        t for t in exhibit["tests"] if t["signatures"]
    ]

    print(f"\nEXHIBIT: {name}")
    print("Candidate configurations:", len(candidate_tests))

    if not candidate_tests:
        continue

    path = source_dir / name
    with Image.open(path) as image:
        pixels = list(image.convert("RGB").getdata())

    for test in candidate_tests:
        order_name = test["channel_order"]
        bit_position = test["bit_position"]
        alignment = test["alignment"]

        stream = extract_stream(
            pixels,
            CHANNEL_ORDERS[order_name],
            bit_position,
            alignment
        )

        for hit in test["signatures"]:
            fmt = hit["format"]
            offset = hit["offset"]

            valid, reason = validate_candidate(
                fmt, stream, offset
            )

            result = {
                "exhibit": name,
                "channel_order": order_name,
                "bit_position": bit_position,
                "alignment": alignment,
                "format": fmt,
                "offset": offset,
                "structurally_valid": valid,
                "validation_reason": reason,
                "control_signature_count":
                    test["control_signature_count"],
                "control_text_count":
                    test["control_text_count"]
            }

            results.append(result)

            print(
                f"{order_name} bit={bit_position} "
                f"align={alignment} | "
                f"{fmt} @ {offset:,} | "
                f"{'VALID' if valid else 'REJECTED'} | "
                f"{reason} | "
                f"control signatures="
                f"{test['control_signature_count']}"
            )

stamp = datetime.now(timezone.utc)
report_path = report_dir / (
    "lsb_signature_validation_"
    + stamp.strftime("%Y%m%d_%H%M%S_%f")
    + ".json"
)

valid_results = [
    result for result in results
    if result["structurally_valid"]
]

output = {
    "analysis": "LSB signature candidate validation",
    "timestamp_utc": stamp.isoformat(),
    "source_analysis": source_report.name,
    "total_candidates": len(results),
    "structurally_valid_candidates": len(valid_results),
    "results": results
}

report_path.write_text(
    json.dumps(output, indent=2),
    encoding="utf-8"
)

with findings_path.open("a", encoding="utf-8") as f:
    f.write(
        f"\n\n## LSB Signature Validation — "
        f"{stamp.isoformat()}\n\n"
    )
    f.write(f"Source: `{source_report.name}`\n\n")
    f.write(f"- Candidates tested: {len(results)}\n")
    f.write(
        f"- Structurally valid candidates: "
        f"{len(valid_results)}\n"
    )

    for item in valid_results:
        f.write(
            f"- VALID: {item['exhibit']} "
            f"{item['channel_order']} bit "
            f"{item['bit_position']} alignment "
            f"{item['alignment']}: "
            f"{item['format']} at byte "
            f"{item['offset']} — "
            f"{item['validation_reason']}\n"
        )

    f.write(
        "\nInterpretation: Magic-byte matches that fail "
        "structural validation are consistent with accidental "
        "matches in large extracted bitstreams. A structurally "
        "valid candidate warrants targeted extraction and "
        "independent verification.\n"
    )

print("\n" + "=" * 70)
print("TOTAL CANDIDATES:", len(results))
print(
    "STRUCTURALLY VALID CANDIDATES:",
    len(valid_results)
)
print("JSON REPORT:", report_path)
print("FINDINGS APPENDED:", findings_path)
