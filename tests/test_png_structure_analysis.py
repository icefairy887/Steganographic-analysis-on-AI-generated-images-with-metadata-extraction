import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "02_png_structure_analysis.py"


def png_chunk(kind, payload):
    crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)


def minimal_png():
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\x00\x00\x00")
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", pixels)
        + png_chunk(b"IEND", b"")
    )


class PngStructureSmokeTest(unittest.TestCase):
    def test_valid_png_reports_clean_structure(self):
        with tempfile.TemporaryDirectory() as directory:
            exhibit = Path(directory) / "exhibit-test"
            exhibit.write_bytes(minimal_png())

            result = subprocess.run(
                [sys.executable, str(SCRIPT), directory],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertIn("EXHIBIT: exhibit-test", result.stdout)
        self.assertIn("IHDR", result.stdout)
        self.assertIn("IDAT", result.stdout)
        self.assertIn("IEND", result.stdout)
        self.assertIn("TRAILING BYTES: 0", result.stdout)
        self.assertNotIn("CRC MISMATCH", result.stdout)

    def test_invalid_signature_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            exhibit = Path(directory) / "exhibit-invalid"
            exhibit.write_bytes(b"not a png")

            result = subprocess.run(
                [sys.executable, str(SCRIPT), directory],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertIn("INVALID PNG SIGNATURE", result.stdout)


if __name__ == "__main__":
    unittest.main()
