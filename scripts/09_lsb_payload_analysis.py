from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
import hashlib
import json
import random
import sys

from PIL import Image

source_dir = Path(sys.argv[1])
report_dir = Path(sys.argv[2])
findings_path = Path(sys.argv[3])

timestamp = datetime.now(timezone.utc)
stamp = timestamp.strftime("%Y%m%d_%H%M%S_%f")

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
    "RGB": (0, 1, 2),
    "BGR": (2, 1, 0),
}

MAX_SCAN_BYTES = 262144
MIN_TEXT_LENGTH = 24
MAX_EXAMPLES = 5

def bits_to_bytes(bits, offset=0):
    bits = bits[offset:]
    usable = len(bits) // 8 * 8
    output = bytearray()

    for i in range(0, usable, 8):
        value = 0
        for bit in bits[i:i+8]:
            value = (value << 1) | bit
        output.append(value)

    return bytes(output)

def extract_bits(pixels, order, bit_position, limit):
    bits = []

    for pixel in pixels:
        for channel in order:
            bits.append((pixel[channel] >> bit_position) & 1)
            if len(bits) >= limit:
                return bits

    return bits

def signature_matches(data):
    matches = []

    for name, signature in SIGNATURES.items():
        start = 0
        while True:
            index = data.find(signature, start)
            if index == -1:
                break

            matches.append({
                "format": name,
                "offset": index,
                "header_hex": data[
                    index:index+min(24, len(data)-index)
                ].hex()
            })

            if len(matches) >= 25:
                return matches

            start = index + 1

    return matches

def readable_sequences(data):
    results = []
    start = None

    for i, byte in enumerate(data):
        printable = 32 <= byte <= 126

        if printable and start is None:
            start = i

        if not printable and start is not None:
            if i - start >= MIN_TEXT_LENGTH:
                results.append({
                    "offset": start,
                    "text": data[start:i][:160].decode(
                        "ascii", errors="replace"
                    )
                })
            start = None

    if start is not None and len(data)-start >= MIN_TEXT_LENGTH:
        results.append({
            "offset": start,
            "text": data[start:start+160].decode(
                "ascii", errors="replace"
            )
        })

    return results[:MAX_EXAMPLES]

def repeated_patterns(data):
    counts = Counter(
        data[i:i+8]
        for i in range(0, len(data)-7, 8)
    )

    return [
        {
            "hex": pattern.hex(),
            "count": count
        }
        for pattern, count in counts.most_common(5)
        if count >= 4
    ]

records = []

print("LSB PAYLOAD ANALYSIS")
print("=" * 65)

for path in sorted(source_dir.glob("exhibit-*")):
    print(f"\nEXHIBIT: {path.name}")

    with Image.open(path) as image:
        pixels = list(image.convert("RGB").getdata())

    tests = []

    for order_name, order in CHANNEL_ORDERS.items():
        for bit_position in (0, 1):
            # Include enough bits for every alignment.
            bits = extract_bits(
                pixels,
                order,
                bit_position,
                MAX_SCAN_BYTES * 8 + 7
            )

            for alignment in range(8):
                data = bits_to_bytes(bits, alignment)[
                    :MAX_SCAN_BYTES
                ]

                signatures = signature_matches(data)
                text_hits = readable_sequences(data)
                patterns = repeated_patterns(data)

                # Deterministic shuffled-bit control.
                control_bits = bits.copy()
                rng = random.Random(20261117 + alignment)
                rng.shuffle(control_bits)

                control = bits_to_bytes(
                    control_bits, alignment
                )[:MAX_SCAN_BYTES]

                control_signatures = signature_matches(control)
                control_text = readable_sequences(control)

                result = {
                    "channel_order": order_name,
                    "bit_position": bit_position,
                    "alignment": alignment,
                    "bytes_examined": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "signatures": signatures,
                    "readable_sequences": text_hits,
                    "repeated_patterns": patterns,
                    "control_signature_count": len(
                        control_signatures
                    ),
                    "control_text_count": len(control_text)
                }

                tests.append(result)

                if signatures or text_hits:
                    print(
                        f"  {order_name} bit={bit_position} "
                        f"alignment={alignment}: "
                        f"{len(signatures)} signatures, "
                        f"{len(text_hits)} text candidates"
                    )

    records.append({
        "exhibit": path.name,
        "tests": tests
    })

    print("Extraction configurations:", len(tests))

report = {
    "analysis": "LSB payload analysis",
    "timestamp_utc": timestamp.isoformat(),
    "methods": {
        "channel_orders": list(CHANNEL_ORDERS),
        "bit_positions": [0, 1],
        "alignments": list(range(8)),
        "max_bytes_per_test": MAX_SCAN_BYTES,
        "note": (
            "Only the beginning of each extraction stream is "
            "examined. Signature matches and printable text "
            "may be false positives. Shuffled-bit controls "
            "are exploratory, not formal statistical tests."
        )
    },
    "exhibits": records
}

report_path = report_dir / (
    f"lsb_payload_analysis_{stamp}.json"
)

report_path.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

with findings_path.open("a", encoding="utf-8") as f:
    f.write(
        f"\n\n## LSB Payload Analysis — "
        f"{timestamp.isoformat()}\n\n"
    )
    f.write(f"Source report: `{report_path.name}`\n\n")

    for record in records:
        tests = record["tests"]
        signature_count = sum(
            len(t["signatures"]) for t in tests
        )
        text_count = sum(
            len(t["readable_sequences"]) for t in tests
        )

        f.write(
            f"- {record['exhibit']}: "
            f"{len(tests)} configurations; "
            f"{signature_count} signature candidates; "
            f"{text_count} text candidates\n"
        )

    f.write(
        "\nInterpretation: Candidate matches require validation "
        "against their expected file structure and comparison "
        "with control results. No candidate alone establishes "
        "the presence of a hidden payload.\n"
    )

print("\n" + "=" * 65)
print("JSON REPORT:", report_path)
print("FINDINGS APPENDED:", findings_path)

for record in records:
    signature_count = sum(
        len(t["signatures"]) for t in record["tests"]
    )
    text_count = sum(
        len(t["readable_sequences"]) for t in record["tests"]
    )

    print(
        f"{record['exhibit']}: "
        f"{signature_count} signature candidates, "
        f"{text_count} text candidates"
    )
