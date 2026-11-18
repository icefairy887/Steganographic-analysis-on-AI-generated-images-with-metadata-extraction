from pathlib import Path
import hashlib
import json
import struct
import sys
from datetime import datetime, timezone

source_dir = Path(sys.argv[1])
report_dir = Path(sys.argv[2])
report_dir.mkdir(parents=True, exist_ok=True)

results = []
payloads = {}

for path in sorted(source_dir.glob("exhibit-*")):
    data = path.read_bytes()
    print(f"\n{'=' * 55}")
    print(f"EXHIBIT: {path.name}")

    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        print("Invalid PNG signature")
        continue

    pos = 8
    chunks = []

    while pos + 12 <= len(data):
        size = struct.unpack(">I", data[pos:pos+4])[0]
        kind = data[pos+4:pos+8]
        end = pos + 12 + size

        if end > len(data):
            print("Malformed PNG chunk")
            break

        payload = data[pos+8:pos+8+size]

        if kind == b"caBX":
            digest = hashlib.sha256(payload).hexdigest()
            chunks.append({
                "offset": pos,
                "size": size,
                "sha256": digest,
                "first_32_bytes_hex": payload[:32].hex(),
                "first_32_bytes_ascii": "".join(
                    chr(b) if 32 <= b <= 126 else "."
                    for b in payload[:32]
                )
            })

            payloads.setdefault(path.name, []).append(payload)

            print(f"caBX offset: {pos}")
            print(f"Payload size: {size:,} bytes")
            print(f"SHA256: {digest}")
            print(f"First 32 bytes (hex): {payload[:32].hex()}")
            print("ASCII preview:", chunks[-1]["first_32_bytes_ascii"])

        pos = end
        if kind == b"IEND":
            break

    if not chunks:
        print("No caBX chunk found")

    results.append({
        "exhibit": path.name,
        "caBX_chunks": chunks
    })

print(f"\n{'=' * 55}")
print("CROSS-EXHIBIT COMPARISON")

names = sorted(payloads)

comparisons = []
for i, name_a in enumerate(names):
    for name_b in names[i+1:]:
        a = payloads[name_a]
        b = payloads[name_b]

        identical = len(a) == len(b) and all(
            x == y for x, y in zip(a, b)
        )

        comparisons.append({
            "exhibit_a": name_a,
            "exhibit_b": name_b,
            "identical_caBX_payloads": identical
        })

        print(f"{name_a} vs {name_b}: "
              f"{'IDENTICAL' if identical else 'DIFFERENT'}")

report = {
    "analysis": "caBX chunk analysis",
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "source_directory": str(source_dir),
    "exhibits": results,
    "comparisons": comparisons
}

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
output = report_dir / f"caBX_analysis_{timestamp}.json"

output.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

print(f"\nJSON REPORT: {output}")
