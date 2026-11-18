from pathlib import Path
from datetime import datetime, timezone
from itertools import combinations
from PIL import Image, ImageOps, ImageChops, ImageStat
import hashlib
import json
import math
import sys

source_dir = Path(sys.argv[1])
report_dir = Path(sys.argv[2])
findings_path = Path(sys.argv[3])

timestamp = datetime.now(timezone.utc)
images = {}
records = []
comparisons = []

def perceptual_hash(image):
    # 64-bit difference hash (dHash).
    gray = ImageOps.grayscale(image)
    small = gray.resize((9, 8), Image.Resampling.LANCZOS)
    pixels = list(small.getdata())

    bits = []
    for y in range(8):
        for x in range(8):
            bits.append(
                pixels[y * 9 + x] > pixels[y * 9 + x + 1]
            )

    return sum(int(bit) << i for i, bit in enumerate(bits))

def hamming_distance(a, b):
    return (a ^ b).bit_count()

print("IMAGE SIMILARITY ANALYSIS")
print("=" * 65)

for path in sorted(source_dir.glob("exhibit-*")):
    try:
        with Image.open(path) as original:
            im = original.convert("RGB").copy()

        images[path.name] = im
        pixels_sha256 = hashlib.sha256(im.tobytes()).hexdigest()
        dhash = perceptual_hash(im)

        record = {
            "exhibit": path.name,
            "width": im.width,
            "height": im.height,
            "pixel_sha256": pixels_sha256,
            "dhash": f"{dhash:016x}",
            "status": "parsed"
        }

        records.append(record)

        print(f"\nEXHIBIT: {path.name}")
        print(f"Dimensions: {im.width} x {im.height}")
        print(f"Pixel SHA256: {pixels_sha256}")
        print(f"dHash: {dhash:016x}")

    except Exception as exc:
        records.append({
            "exhibit": path.name,
            "status": "error",
            "error": str(exc)
        })
        print(f"\nERROR {path.name}: {exc}")

print("\nPAIRWISE IMAGE COMPARISON")
print("=" * 65)

for name_a, name_b in combinations(sorted(images), 2):
    a = images[name_a]
    b = images[name_b]

    hash_a = perceptual_hash(a)
    hash_b = perceptual_hash(b)

    distance = hamming_distance(hash_a, hash_b)

    same_dimensions = a.size == b.size
    identical_pixels = (
        same_dimensions and a.tobytes() == b.tobytes()
    )

    # Normalize both images to a common size for comparison.
    target_size = (256, 256)
    norm_a = ImageOps.fit(
        a, target_size, method=Image.Resampling.LANCZOS
    )
    norm_b = ImageOps.fit(
        b, target_size, method=Image.Resampling.LANCZOS
    )

    diff = ImageChops.difference(norm_a, norm_b)
    rms = ImageStat.Stat(diff).rms
    normalized_rmse = math.sqrt(
        sum(v * v for v in rms) / len(rms)
    ) / 255

    comparison = {
        "exhibit_a": name_a,
        "exhibit_b": name_b,
        "same_dimensions": same_dimensions,
        "identical_pixels": identical_pixels,
        "dhash_distance": distance,
        "normalized_rmse": round(normalized_rmse, 6)
    }

    comparisons.append(comparison)

    print(
        f"{name_a} vs {name_b} | "
        f"Identical: {identical_pixels} | "
        f"dHash distance: {distance}/64 | "
        f"Normalized RMSE: {normalized_rmse:.4f}"
    )

report = {
    "analysis": "Image similarity analysis",
    "timestamp_utc": timestamp.isoformat(),
    "methodology": {
        "pixel_hash": "SHA256 of decoded RGB pixel bytes",
        "perceptual_hash": "64-bit difference hash",
        "rmse": "RGB RMSE after center-crop and resize to 256x256",
        "note": "Similarity metrics are indicators, not proof of common origin."
    },
    "exhibits": records,
    "comparisons": comparisons
}

report_path = report_dir / (
    "image_similarity_analysis_"
    + timestamp.strftime("%Y%m%d_%H%M%S_%f")
    + ".json"
)

report_path.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

with findings_path.open("a", encoding="utf-8") as f:
    f.write(
        f"\n\n## Image Similarity Analysis — "
        f"{timestamp.isoformat()}\n\n"
    )
    f.write(f"Source report: `{report_path.name}`\n\n")

    for item in records:
        if item["status"] == "parsed":
            f.write(
                f"- {item['exhibit']}: "
                f"{item['width']}x{item['height']}, "
                f"dHash={item['dhash']}\n"
            )
        else:
            f.write(
                f"- {item['exhibit']}: ERROR {item['error']}\n"
            )

    f.write("\n### Pairwise results\n\n")

    for item in comparisons:
        f.write(
            f"- {item['exhibit_a']} vs {item['exhibit_b']}: "
            f"identical={item['identical_pixels']}, "
            f"dHash distance={item['dhash_distance']}/64, "
            f"normalized RMSE={item['normalized_rmse']}\n"
        )

    f.write(
        "\nInterpretation: Low dHash distances can indicate "
        "similar visual structure, but do not establish "
        "shared provenance. RMSE is sensitive to cropping, "
        "alignment, color, and resizing.\n"
    )

print("\nJSON REPORT:", report_path)
print("FINDINGS APPENDED:", findings_path)
