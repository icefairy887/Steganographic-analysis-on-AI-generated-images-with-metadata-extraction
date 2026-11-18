from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import sys

from c2pa import Reader

source_dir = Path(sys.argv[1])
report_dir = Path(sys.argv[2])

timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
results = []

for path in sorted(source_dir.glob("exhibit-*")):
    print("\n" + "=" * 60)
    print("EXHIBIT:", path.name)

    record = {
        "exhibit": path.name,
        "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "file_size": path.stat().st_size,
        "status": None,
        "manifest_data": None,
        "error": None
    }

    try:
        # Explicit PNG format supports extensionless exhibits.
        with open(path, "rb") as stream:
            with Reader("image/png", stream) as reader:
                manifest = json.loads(reader.json())

        record["status"] = "parsed"
        record["manifest_data"] = manifest

        print("Manifest parsed successfully")

        active = manifest.get("active_manifest")
        manifests = manifest.get("manifests", {})

        print("Active manifest:", active)
        print("Manifest count:", len(manifests))

        for label, item in manifests.items():
            print("\nManifest label:", label)
            print("Claim generator:", item.get("claim_generator"))

            for action in item.get("assertions", []):
                print("Assertion:", action.get("label"))

            ingredients = item.get("ingredients", [])
            print("Ingredient count:", len(ingredients))

        validation = manifest.get("validation_status", [])
        print("\nValidation status:")
        print(json.dumps(validation, indent=2))

    except Exception as exc:
        record["status"] = "error"
        record["error"] = str(exc)
        print("ANALYSIS ERROR:", exc)

    results.append(record)

output = {
    "analysis": "C2PA manifest analysis",
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "source_directory": str(source_dir),
    "exhibits": results
}

report_path = report_dir / f"c2pa_manifest_analysis_{timestamp}.json"

report_path.write_text(
    json.dumps(output, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

print("\n" + "=" * 60)
print("JSON REPORT:", report_path)
