from pathlib import Path
from datetime import datetime, timezone
from PIL import Image
import gzip
import io
import json
import sys

source_dir = Path(sys.argv[1])
report_dir = Path(sys.argv[2])
findings_path = Path(sys.argv[3])

prior = sorted(
    report_dir.glob("lsb_signature_validation_*.json"),
    key=lambda p: p.stat().st_mtime,
    reverse=True
)

if not prior:
    raise FileNotFoundError("Analysis 10 report not found")

source_report = prior[0]
analysis10 = json.loads(source_report.read_text(encoding="utf-8"))

ORDERS = {
    "R": (0,),
    "G": (1,),
    "B": (2,),
    "RGB": (0,1,2),
    "BGR": (2,1,0),
}

def extract_stream(path, order, bit, alignment):
    with Image.open(path) as image:
        pixels = list(image.convert("RGB").getdata())

    bits = []
    for pixel in pixels:
        for c in order:
            bits.append((pixel[c] >> bit) & 1)

    bits = bits[alignment:]
    usable = len(bits) // 8 * 8

    output = bytearray()

    for i in range(0, usable, 8):
        value = 0
        for b in bits[i:i+8]:
            value = (value << 1) | b
        output.append(value)

    return bytes(output)

def validate_jpeg(data):
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return False, None, "missing SOI"

    pos = 2
    saw_sos = False

    while pos < len(data):
        if data[pos] != 0xff:
            if saw_sos:
                pos += 1
                continue
            return False, None, "invalid marker boundary"

        while pos < len(data) and data[pos] == 0xff:
            pos += 1

        if pos >= len(data):
            return False, None, "truncated marker"

        marker = data[pos]
        pos += 1

        if marker == 0xd9:
            if saw_sos:
                return True, pos, "valid JPEG marker structure"
            return False, None, "EOI before image scan"

        if marker == 0xda:
            saw_sos = True

            if pos + 2 > len(data):
                return False, None, "truncated SOS"

            length = int.from_bytes(data[pos:pos+2], "big")

            if length < 2 or pos + length > len(data):
                return False, None, "invalid SOS length"

            pos += length

            while pos + 1 < len(data):
                if data[pos] == 0xff:
                    nxt = data[pos+1]

                    if nxt == 0x00:
                        pos += 2
                        continue

                    if 0xd0 <= nxt <= 0xd7:
                        pos += 2
                        continue

                    break

                pos += 1

            continue

        # Standalone JPEG markers.
        if marker in (0x01,) or 0xd0 <= marker <= 0xd7:
            continue

        if pos + 2 > len(data):
            return False, None, "truncated segment"

        length = int.from_bytes(data[pos:pos+2], "big")

        if length < 2 or pos + length > len(data):
            return False, None, "invalid segment length"

        pos += length

    return False, None, "no valid EOI"

def validate_gzip(data):
    try:
        bio = io.BytesIO(data)

        with gzip.GzipFile(fileobj=bio, mode="rb") as gz:
            decoded = gz.read()

        consumed = bio.tell()

        if not decoded:
            return False, None, None, "decompressed to empty data"

        return (
            True,
            consumed,
            decoded,
            f"valid GZIP; decompressed {len(decoded):,} bytes"
        )

    except Exception as exc:
        return False, None, None, f"GZIP decompression failed: {exc}"

stamp = datetime.now(timezone.utc)
results = []
confirmed = []

print("LSB CANDIDATE EXTRACTION")
print("=" * 70)
print("Source:", source_report.name)

for candidate in analysis10["results"]:

    if not candidate["structurally_valid"]:
        continue

    exhibit = candidate["exhibit"]
    order_name = candidate["channel_order"]
    bit = candidate["bit_position"]
    alignment = candidate["alignment"]
    fmt = candidate["format"]
    offset = candidate["offset"]

    stream = extract_stream(
        source_dir / exhibit,
        ORDERS[order_name],
        bit,
        alignment
    )

    payload = stream[offset:]

    valid = False
    reason = ""
    saved = None

    if fmt == "JPEG":
        valid, length, reason = validate_jpeg(payload)

        if valid:
            carved = payload[:length]

            filename = (
                f"{exhibit}_{order_name}_bit{bit}_"
                f"align{alignment}_offset{offset}.jpg"
            )

            out = report_dir / filename
            out.write_bytes(carved)
            saved = str(out)

    elif fmt == "GZIP":
        valid, consumed, decoded, reason = validate_gzip(payload)

        if valid:
            filename = (
                f"{exhibit}_{order_name}_bit{bit}_"
                f"align{alignment}_offset{offset}_gzip_payload.bin"
            )

            out = report_dir / filename
            out.write_bytes(decoded)
            saved = str(out)

    else:
        reason = "No deep validator implemented"

    result = {
        **candidate,
        "deep_validation": valid,
        "deep_validation_reason": reason,
        "saved_payload": saved
    }

    results.append(result)

    print(
        f"{exhibit} | {order_name} bit={bit} "
        f"align={alignment} | {fmt} @{offset:,} | "
        f"{'CONFIRMED' if valid else 'REJECTED'} | {reason}"
    )

    if valid:
        confirmed.append(result)

report_path = report_dir / (
    "lsb_candidate_extraction_"
    + stamp.strftime("%Y%m%d_%H%M%S_%f")
    + ".json"
)

report_path.write_text(
    json.dumps({
        "analysis": "Deep LSB candidate validation and extraction",
        "timestamp_utc": stamp.isoformat(),
        "source_analysis": source_report.name,
        "candidates_deep_tested": len(results),
        "confirmed_payloads": len(confirmed),
        "results": results
    }, indent=2),
    encoding="utf-8"
)

with findings_path.open("a", encoding="utf-8") as f:
    f.write(
        f"\n\n## Deep LSB Candidate Validation — "
        f"{stamp.isoformat()}\n\n"
    )

    f.write(f"- Deep-tested candidates: {len(results)}\n")
    f.write(f"- Confirmed payloads: {len(confirmed)}\n")

    for item in confirmed:
        f.write(
            f"- CONFIRMED: {item['exhibit']} "
            f"{item['channel_order']} bit "
            f"{item['bit_position']} alignment "
            f"{item['alignment']} — "
            f"{item['format']} at byte "
            f"{item['offset']}; "
            f"{item['deep_validation_reason']}; "
            f"saved={item['saved_payload']}\n"
        )

    f.write(
        "\nInterpretation: Analysis 10's JPEG EOI test was "
        "only preliminary. This pass requires coherent JPEG "
        "marker structure or successful GZIP decompression "
        "before a candidate is treated as an extracted payload.\n"
    )

print("\n" + "=" * 70)
print("DEEP-TESTED:", len(results))
print("CONFIRMED PAYLOADS:", len(confirmed))
print("JSON REPORT:", report_path)
print("FINDINGS APPENDED:", findings_path)
