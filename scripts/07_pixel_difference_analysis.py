from pathlib import Path
from datetime import datetime, timezone
from PIL import Image, ImageChops, ImageEnhance
import json
import math
import sys

source_dir = Path(sys.argv[1])
report_dir = Path(sys.argv[2])
findings_path = Path(sys.argv[3])

a_path = source_dir / "exhibit-b"
b_path = source_dir / "exhibit-c"

timestamp = datetime.now(timezone.utc)
stamp = timestamp.strftime("%Y%m%d_%H%M%S_%f")

with Image.open(a_path) as image:
    a = image.convert("RGB").copy()

with Image.open(b_path) as image:
    b = image.convert("RGB").copy()

if a.size != b.size:
    raise ValueError(
        f"Image dimensions differ: {a.size} vs {b.size}"
    )

width, height = a.size
difference = ImageChops.difference(a, b)

raw_path = report_dir / f"bc_pixel_difference_{stamp}.png"
enhanced_path = report_dir / f"bc_enhanced_difference_{stamp}.png"
heatmap_path = report_dir / f"bc_difference_heatmap_{stamp}.png"

difference.save(raw_path)

enhanced = ImageEnhance.Contrast(difference).enhance(4)
enhanced.save(enhanced_path)

# Heatmap intensity represents average RGB difference.
heatmap = Image.new("RGB", a.size)
heat_pixels = []

changed = 0
total_absolute_difference = 0
total_squared_difference = 0
maximum_difference = 0

for pixel in difference.getdata():
    magnitude = sum(pixel) / 3
    intensity = int(magnitude)

    if any(pixel):
        changed += 1

    total_absolute_difference += sum(pixel)
    total_squared_difference += sum(v * v for v in pixel)
    maximum_difference = max(maximum_difference, max(pixel))

    # Red = greater difference, dark = less difference.
    heat_pixels.append((intensity, 0, 0))

heatmap.putdata(heat_pixels)
heatmap.save(heatmap_path)

pixel_count = width * height
channel_count = pixel_count * 3

mae = total_absolute_difference / channel_count
rmse = math.sqrt(total_squared_difference / channel_count)

changed_percent = changed / pixel_count * 100

report = {
    "analysis": "Pixel difference analysis",
    "timestamp_utc": timestamp.isoformat(),
    "exhibits": ["exhibit-b", "exhibit-c"],
    "dimensions": [width, height],
    "total_pixels": pixel_count,
    "changed_pixels": changed,
    "changed_percentage": round(changed_percent, 4),
    "mean_absolute_error": round(mae, 6),
    "root_mean_square_error": round(rmse, 6),
    "maximum_channel_difference": maximum_difference,
    "outputs": {
        "raw_difference": str(raw_path),
        "enhanced_difference": str(enhanced_path),
        "heatmap": str(heatmap_path)
    }
}

json_path = report_dir / (
    f"pixel_difference_analysis_{stamp}.json"
)

json_path.write_text(
    json.dumps(report, indent=2),
    encoding="utf-8"
)

print("PIXEL DIFFERENCE ANALYSIS")
print("=" * 60)
print("Exhibits: B vs C")
print("Dimensions:", width, "x", height)
print("Total pixels:", pixel_count)
print("Changed pixels:", changed)
print(f"Changed percentage: {changed_percent:.4f}%")
print(f"Mean absolute error: {mae:.6f}")
print(f"RMSE: {rmse:.6f}")
print("Maximum channel difference:", maximum_difference)
print("\nRaw difference:", raw_path)
print("Enhanced difference:", enhanced_path)
print("Heatmap:", heatmap_path)
print("JSON report:", json_path)

with findings_path.open("a", encoding="utf-8") as f:
    f.write(
        f"\n\n## Pixel Difference Analysis — "
        f"{timestamp.isoformat()}\n\n"
    )
    f.write("Comparison: exhibit-b vs exhibit-c\n\n")
    f.write(f"- Dimensions: {width} x {height}\n")
    f.write(f"- Changed pixels: {changed:,}\n")
    f.write(f"- Changed percentage: {changed_percent:.4f}%\n")
    f.write(f"- Mean absolute error: {mae:.6f}\n")
    f.write(f"- RMSE: {rmse:.6f}\n")
    f.write(f"- Maximum channel difference: {maximum_difference}\n")
    f.write(f"- JSON report: `{json_path.name}`\n")
    f.write(
        "\nInterpretation: These measurements describe "
        "direct pixel differences between aligned images. "
        "They do not independently establish whether one "
        "image was derived from the other.\n"
    )

print("FINDINGS APPENDED:", findings_path)
