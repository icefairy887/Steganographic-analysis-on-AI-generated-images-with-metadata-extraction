from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from itertools import combinations
import hashlib
import json
import sys

from c2pa import Reader

source_dir = Path(sys.argv[1])
report_dir = Path(sys.argv[2])
findings_path = Path(sys.argv[3])

timestamp = datetime.now(timezone.utc)
records = []

for path in sorted(source_dir.glob("exhibit-*")):
    record = {
        "exhibit": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "status": "pending",
        "manifest_id": None,
        "claim_generators": [],
        "actions": [],
        "all_actions_included": None,
        "signature": {},
        "validation_status": [],
        "error": None
    }

    try:
        with path.open("rb") as stream:
            with Reader("image/png", stream) as reader:
                data = json.loads(reader.json())

        active = data.get("active_manifest")
        manifest = data.get("manifests", {}).get(active)

        if not manifest:
            raise ValueError("Active manifest not found")

        record["status"] = "parsed"
        record["manifest_id"] = active
        record["claim_generators"] = manifest.get(
            "claim_generator_info", []
        )
        record["signature"] = manifest.get(
            "signature_info", {}
        )
        record["validation_status"] = data.get(
            "validation_status", []
        )

        for assertion in manifest.get("assertions", []):
            if assertion.get("label") == "c2pa.actions.v2":
                details = assertion.get("data", {})
                record["actions"].extend(
                    details.get("actions", [])
                )
                record["all_actions_included"] = (
                    details.get("allActionsIncluded")
                )

    except Exception as exc:
        record["status"] = "error"
        record["error"] = str(exc)

    records.append(record)

print("\nC2PA ASSERTION COMPARISON")
print("=" * 65)

for record in records:
    print(f"\nEXHIBIT: {record['exhibit']}")
    print("Status:", record["status"])

    if record["status"] != "parsed":
        print("Error:", record["error"])
        continue

    sig = record["signature"]

    print("Algorithm:", sig.get("alg"))
    print("Certificate serial:", sig.get("cert_serial_number"))
    print("Issuer:", sig.get("issuer"))
    print("Signing time:", sig.get("time"))
    print("All actions included:",
          record["all_actions_included"])

    for action in record["actions"]:
        agent = action.get("softwareAgent") or {}
        print(
            "ACTION:",
            action.get("action"),
            "| TIME:", action.get("when"),
            "| AGENT:", agent.get("name"),
            agent.get("version")
        )

    codes = [
        item.get("code")
        for item in record["validation_status"]
    ]
    print("Validation codes:", codes)

groups = defaultdict(list)

for record in records:
    if record["status"] != "parsed":
        continue

    sig = record["signature"]
    key = (
        sig.get("alg"),
        str(sig.get("cert_serial_number"))
    )
    groups[key].append(record["exhibit"])

print("\nSIGNING GROUPS")
print("=" * 65)

for (algorithm, serial), exhibits in groups.items():
    print(f"{algorithm}: {', '.join(exhibits)}")
    print("Certificate serial:", serial)

comparisons = []

for a, b in combinations(
    [r for r in records if r["status"] == "parsed"], 2
):
    names_a = [x.get("action") for x in a["actions"]]
    names_b = [x.get("action") for x in b["actions"]]

    comparisons.append({
        "exhibits": [a["exhibit"], b["exhibit"]],
        "same_action_sequence": names_a == names_b,
        "same_signature_algorithm": (
            a["signature"].get("alg")
            == b["signature"].get("alg")
        ),
        "same_certificate_serial": (
            str(a["signature"].get("cert_serial_number"))
            == str(b["signature"].get("cert_serial_number"))
        )
    })

print("\nPAIRWISE COMPARISON")
print("=" * 65)

for item in comparisons:
    print(
        " vs ".join(item["exhibits"]),
        "| Same actions:", item["same_action_sequence"],
        "| Same algorithm:",
        item["same_signature_algorithm"],
        "| Same certificate:",
        item["same_certificate_serial"]
    )

report = {
    "analysis": "C2PA assertion comparison",
    "timestamp_utc": timestamp.isoformat(),
    "records": records,
    "signing_groups": [
        {
            "algorithm": algorithm,
            "certificate_serial": serial,
            "exhibits": exhibits
        }
        for (algorithm, serial), exhibits in groups.items()
    ],
    "comparisons": comparisons
}

report_path = report_dir / (
    "c2pa_assertion_analysis_"
    + timestamp.strftime("%Y%m%d_%H%M%S_%f")
    + ".json"
)

report_path.write_text(
    json.dumps(report, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

print("\nJSON REPORT:", report_path)

with findings_path.open("a", encoding="utf-8") as f:
    f.write(
        f"\n\n## C2PA Assertion Analysis — "
        f"{timestamp.isoformat()}\n\n"
    )

    f.write(
        f"Source: `{report_path.name}`\n\n"
    )

    f.write(
        f"- Successfully parsed: "
        f"{sum(r['status'] == 'parsed' for r in records)}"
        f"/{len(records)} exhibits\n"
    )

    for (algorithm, serial), exhibits in groups.items():
        f.write(
            f"- Signing group {algorithm}, "
            f"certificate {serial}: "
            f"{', '.join(exhibits)}\n"
        )

    for record in records:
        if record["status"] != "parsed":
            f.write(
                f"- {record['exhibit']}: "
                f"analysis error: {record['error']}\n"
            )
            continue

        names = [
            action.get("action")
            for action in record["actions"]
        ]

        codes = [
            item.get("code")
            for item in record["validation_status"]
        ]

        f.write(
            f"- {record['exhibit']}: "
            f"actions={names}; "
            f"validation={codes}; "
            f"allActionsIncluded="
            f"{record['all_actions_included']}\n"
        )

    f.write(
        "\nInterpretation: Matching action sequences or "
        "certificate identifiers do not establish shared "
        "image content, user identity, or generation session. "
        "Untrusted signing credentials prevent independent "
        "trust establishment under the current validator "
        "configuration.\n"
    )

print("FINDINGS APPENDED:", findings_path)
