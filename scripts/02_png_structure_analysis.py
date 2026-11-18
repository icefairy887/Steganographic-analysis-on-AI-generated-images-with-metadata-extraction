from pathlib import Path
import struct
import zlib
import sys

root = Path(sys.argv[1])

for path in sorted(root.glob("exhibit-*")):
    data = path.read_bytes()
    print(f"\n{'='*55}")
    print(f"EXHIBIT: {path.name}")
    print(f"SIZE: {len(data):,} bytes")

    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        print("INVALID PNG SIGNATURE")
        continue

    pos = 8
    found_iend = False

    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos+4])[0]
        kind = data[pos+4:pos+8]
        end = pos + 12 + length

        if end > len(data):
            print("TRUNCATED OR MALFORMED CHUNK")
            break

        payload = data[pos+8:pos+8+length]
        stored_crc = struct.unpack(">I", data[end-4:end])[0]
        actual_crc = zlib.crc32(kind + payload) & 0xffffffff

        name = kind.decode("ascii", errors="replace")
        status = "OK" if stored_crc == actual_crc else "CRC MISMATCH"

        print(f"{name:8} {length:>10,} bytes  {status}")

        if kind in (b"tEXt", b"iTXt", b"zTXt", b"eXIf"):
            print("  >>> METADATA CHUNK FOUND")

        pos = end

        if kind == b"IEND":
            found_iend = True
            print(f"TRAILING BYTES: {len(data) - pos:,}")
            break

    if not found_iend:
        print("WARNING: No valid IEND chunk found")
