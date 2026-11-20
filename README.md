# AI-Generated Image Forensics

A reproducible digital-forensics workflow for examining metadata, C2PA provenance, PNG structure, image similarity, pixel-level differences, and possible steganographic content in AI-generated images.

The repository contains five extensionless PNG exhibits (`exhibit-a` through `exhibit-e`), numbered analysis scripts, and preserved baseline reports. The workflow deliberately separates an interesting signal from a validated finding: statistical anomalies and magic-byte matches are not treated as proof of hidden content without structural validation.

## What this project examines

- PNG signatures, chunks, CRC values, and trailing data
- `caBX` chunks containing JUMBF/C2PA structures
- C2PA manifests, recorded actions, signatures, and validation status
- Decoded-pixel hashes and perceptual similarity
- Direct pixel differences and visual comparison images
- RGB bit-plane statistics and sequential LSB extraction
- Candidate JPEG/GZIP signatures and deeper structural validation

## Repository layout

```text
.
|-- .agents/skills/ai-image-steg-forensics/\n|   `-- SKILL.md      Codex workflow and interpretation rules
|-- sources/          Original extensionless PNG exhibits
|-- scripts/          Numbered forensic analyses
|-- reports/          Preserved baseline results
|-- metasweep/        Metadata inspection utility
|-- tests/            Automated smoke tests
|-- requirements.txt  Python dependencies
`-- LICENSE
```

## Setup

Use Python 3.10 or newer. From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install c2pa-python
```

The virtual environment is machine-local state and must not be committed.

## Quick verification

The PNG structure check is read-only and has no optional C2PA dependency:

```powershell
python .\scripts\02_png_structure_analysis.py .\sources
```

Run the standard-library smoke test:

```powershell
python -m unittest discover -s tests -v
```

## Full workflow

Create a separate output directory so a new run does not mix with the preserved baseline reports:

```powershell
$sources = (Resolve-Path .\sources).Path
$reports = Join-Path (Get-Location) "work\reports"
$findings = Join-Path $reports "forensic_findings.md"
New-Item -ItemType Directory -Force -Path $reports | Out-Null
New-Item -ItemType File -Force -Path $findings | Out-Null
```

Run the analyses in order:

```powershell
python .\scripts\02_png_structure_analysis.py $sources
python .\scripts\03_caBX_analysis.py $sources $reports
python .\scripts\04_c2pa_manifest_analysis.py $sources $reports
python .\scripts\05_c2pa_assertion_analysis.py $sources $reports $findings
python .\scripts\06_image_similarity_analysis.py $sources $reports $findings
python .\scripts\07_pixel_difference_analysis.py $sources $reports $findings
python .\scripts\08_steganography_analysis.py $sources $reports $findings
python .\scripts\09_lsb_payload_analysis.py $sources $reports $findings
python .\scripts\10_lsb_signature_validation.py $sources $reports $findings
python .\scripts\11_lsb_candidate_extraction.py $sources $reports $findings
```

Keep stages 09 through 11 in the same output directory. Later stages locate and validate candidates reported by earlier stages.

## Baseline findings

The preserved run supports these conclusions:

1. All five exhibits are structurally recognizable PNG files and contain a `caBX` chunk.
2. The `caBX` data contains JUMBF/C2PA provenance structures.
3. The manifests identify trained algorithmic media and record `c2pa.created`, `c2pa.converted`, and `c2pa.watermarked.unbound` actions.
4. The exhibits use two observed signing configurations.
5. The images do not contain identical decoded pixel data.
6. Initial sequential-LSB searches produced apparent file signatures.
7. Deeper JPEG parsing and GZIP decompression rejected every candidate tested.
8. No conventional sequential LSB payload was confirmed by this workflow.

The last point is intentionally narrow. It does not prove that an image contains no watermark, transform-domain signal, keyed traversal, or proprietary steganographic scheme.

## Evidence rules

- Preserve source files byte-for-byte and write results elsewhere.
- Record hashes and exact commands for any new exhibit set.
- Treat C2PA validation status as validator output, not an accusation of tampering.
- Treat entropy, similarity, and file signatures as screening indicators.
- Require format-aware parsing or successful decompression before calling a candidate an embedded payload.
- State limitations and negative findings explicitly.

## Scope and authorization

Use this project only on files you own or are authorized to examine. Metadata and provenance results do not independently prove origin, authorship, tampering, identity, or intent.

## License and attribution

The repository is distributed under the included MIT license. `metasweep/` originated as a separate metadata-analysis project; retain its attribution when redistributing or modifying that code.
