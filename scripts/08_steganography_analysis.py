from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
from PIL import Image
import hashlib
import json
import math
import sys

source_dir = Path(sys.argv[1])
report_dir = Path(sys.argv[2])
findings_path = Path(sys.argv[3])

timestamp = datetime.now(timezone.utc)
stamp = timestamp.strftime("%Y%m%d_%H%M%S_%f")

MAGIC = {
    b"PK\x03\x04": "ZIP",
    b"%PDF": "PDF",
    b"\x89PNG": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF8": "GIF",
    b"\x1f\x8b": "GZIP",
    b"7z\xbc\xaf\x27\x1c": "7ZIP",
}

def entropy(counts):
    total = sum(counts.values())
    if not total:
        return 0.0
    return -sum(
        (n / total) * math.log2(n / total)
        for n in counts.values() if n
    )

def extract_lsb_bytes(values, bit=0, max_bytes=64):
    bits = [(v >> bit) & 1 for v in values[:max_bytes * 8]]
    output = bytearray()

    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        output.append(byte)

    return bytes(output)

def inspect_channel(values):
    results = {}

    for bit in range(8):
        bits = [(v >> bit) & 1 for v in values]
        counts = Counter(bits)

        transitions = sum(
            a != b for a, b in zip(bits, bits[1:])
        )

        results[f"bit_{bit}"] = {
            "zeros": counts[0],
            "ones": counts[1],
            "entropy": round(entropy(counts), 6),
            "transition_ratio": round(
                transitions / max(1, len(bits) - 1), 6
            )
        }

    pair_counts = Counter(v // 2 for v in values)

    results["lsb_pairs"] = {
        "unique_pairs": len(pair_counts),
        "pair_entropy": round(entropy(pair_counts), 6)
    }

    return results

records = []

print("STEGANOGRAPHY ANALYSIS")
print("=" * 65)

for path in sorted(source_dir.glob("exhibit-*")):
    print(f"\nEXHIBIT: {path.name}")

    record = {
        "exhibit": path.name,
        "status": "pending",
        "channels": {},
        "signature_candidates": [],
        "error": None
    }

    try:
        with Image.open(path) as image:
            im = image.convert("RGB")
            pixels = list(im.getdata())

        record["dimensions"] = list(im.size)
        record["status"] = "analyzed"

        for index, name in enumerate("RGB"):
            values = [p[index] for p in pixels]
            stats = inspect_channel(values)
            record["channels"][name] = stats

            extracted = extract_lsb_bytes(values)

            for signature, label in MAGIC.items():
                if extracted.startswith(signature):
                    record["signature_candidates"].append({
                        "channel": name,
                        "bit": 0,
                        "signature": label
                    })

            low = stats["bit_0"]

            print(
                f"{name}: "
                f"LSB entropy={low['entropy']:.4f}, "
                f"transition={low['transition_ratio']:.4f}, "
                f"zeros={low['zeros']}, "
                f"ones={low['ones']}"
            )

        print(
            "Signature candidates:",
            record["signature_candidates"]
        )

    except Exception as exc:
        record["status"] = "error"
        record["error"] = str(exc)
        print("ERROR:", exc)

    records.append(record)

report = {
    "analysis": "Steganography statistical screening",
    "timestamp_utc": timestamp.isoformat(),
    "methodology": {
        "channels": "RGB",
        "bit_planes": "0 through 7",
        "entropy": "Binary Shannon entropy per bit plane",
        "transition_ratio": "Adjacent bit changes in raster order",
        "signature_detection": "First 64 LSB-extracted bytes per RGB channel, MSB-first",
        "limitations": (
            "Statistical indicators do not prove hidden data. "
            "The scan does not exhaust all steganography methods, "
            "bit orders, offsets, or payload encodings."
        )
    },
    "exhibits": records
}

report_path = report_dir / (
    f"steganography_analysis_{stamp}.json"
)

report_path.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

with findings_path.open("a", encoding="utf-8") as f:
    f.write(
        f"\n\n## Steganography Analysis — "
        f"{timestamp.isoformat()}\n\n"
    )
    f.write(f"Source report: `{report_path.name}`\n\n")

    for record in records:
        if record["status"] != "analyzed":
            f.write(
                f"- {record['exhibit']}: "
                f"ERROR {record['error']}\n"
            )
            continue

        f.write(f"\n### {record['exhibit']}\n")

        for channel in "RGB":
            stats = record["channels"][channel]["bit_0"]
            f.write(
                f"- {channel} LSB: "
                f"entropy={stats['entropy']}, "
                f"transition={stats['transition_ratio']}\n"
            )

        f.write(
            f"- Signature candidates: "
            f"{record['signature_candidates']}\n"
        )

    f.write(
        "\nInterpretation: These are statistical screening "
        "results. High entropy, unusual bit distributions, "
        "or matching file signatures require independent "
        "verification before concluding that hidden "
        "information is present.\n"
    )

print("\nJSON REPORT:", report_path)
print("FINDINGS APPENDED:", findings_path)
