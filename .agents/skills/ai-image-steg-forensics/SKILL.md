---
name: ai-image-steg-forensics
description: Analyze authorized AI-generated image files for metadata, PNG structure, C2PA provenance, image similarity, pixel differences, and possible sequential-LSB steganography using this repository's evidence-preserving scripts. Use for forensic examination or reproducible review of image exhibits; do not use it to claim authorship, tampering, or hidden payloads from unvalidated indicators.
---

# AI Image Steganography Forensics

Use the repository's numbered scripts to produce a reproducible, evidence-linked analysis of authorized image files.

## Preserve evidence

- Confirm that the user owns the files or is authorized to analyze them.
- Treat source files as read-only.
- Hash new source files before analysis and record their original paths.
- Write every new run to a separate output directory. Do not mix new output with `reports/`, which contains the preserved baseline run.
- Do not rename extensionless exhibits merely to make a library accept them; the scripts explicitly handle the current PNG inputs.

## Prepare a run

From the repository root, create and activate a local virtual environment, install `requirements.txt`, and install `c2pa-python` when C2PA stages are required.

Define three paths:

- `sources`: the directory containing files named `exhibit-*`
- `reports`: a new output directory for this run
- `findings`: a Markdown file inside that output directory

Create the reports directory and an empty findings file before running stages that append findings.

## Select the analysis depth

Use the smallest workflow that answers the request:

- Structure only: run `scripts/02_png_structure_analysis.py`.
- PNG provenance: run stages 02 through 05.
- Visual relationship: run stages 06 and 07.
- Sequential-LSB screening: run stages 08 through 11 in order.
- Full investigation: run stages 02 through 11 in order.

Do not call the workflow exhaustive. It does not cover every transform-domain, spatially selective, keyed, encrypted, proprietary, or model-specific watermarking technique.

## Run the stages

Use these argument shapes:

```text
python scripts/02_png_structure_analysis.py <sources>
python scripts/03_caBX_analysis.py <sources> <reports>
python scripts/04_c2pa_manifest_analysis.py <sources> <reports>
python scripts/05_c2pa_assertion_analysis.py <sources> <reports> <findings>
python scripts/06_image_similarity_analysis.py <sources> <reports> <findings>
python scripts/07_pixel_difference_analysis.py <sources> <reports> <findings>
python scripts/08_steganography_analysis.py <sources> <reports> <findings>
python scripts/09_lsb_payload_analysis.py <sources> <reports> <findings>
python scripts/10_lsb_signature_validation.py <sources> <reports> <findings>
python scripts/11_lsb_candidate_extraction.py <sources> <reports> <findings>
```

Keep stages 09 through 11 in the same output directory. Later stages locate and validate candidates reported by earlier stages.

## Interpret conservatively

Separate observations, validation, and conclusions:

1. Report the direct observation: chunk, assertion, metric, bit distribution, or signature match.
2. Report the validation performed: CRC check, C2PA parser result, format parser, or decompression attempt.
3. State only the conclusion supported by that validation.

Apply these boundaries:

- A `caBX` chunk may carry JUMBF/C2PA material; parse it before describing its meaning.
- `signingCredential.untrusted` means the configured validator did not establish trust. It does not independently prove tampering or fraud.
- `c2pa.watermarked.unbound` records a provenance action. It does not identify a recoverable payload or imply that ordinary LSB extraction should find one.
- Similar dimensions, perceptual hashes, or RMSE values do not prove a shared generation session or derivation.
- Balanced or high-entropy low-order bits do not prove steganography.
- A short magic-byte match is a candidate, not a payload.
- Confirm an embedded JPEG only after coherent marker parsing; confirm GZIP only after successful decompression.
- A rejected sequential-LSB candidate does not prove that no other watermark or steganographic method is present.

## Review output

- Confirm every expected exhibit produced a record.
- Surface per-file errors instead of averaging them away.
- Link conclusions to the exact JSON report and exhibit.
- Include extraction order, channel order, bit position, alignment, and offset for any candidate.
- Preserve negative results and rejected candidates when they explain why an apparent finding was not confirmed.

## Deliver the result

Summarize:

- scope and authorization assumption
- source hashes or identifiers
- tools and stages run
- validated findings
- rejected candidates and why they failed
- limitations and untested methods
- paths to machine-readable reports and generated visual evidence

Use precise phrases such as "no conventional sequential LSB payload was confirmed by the tested configurations" instead of "there is no hidden data."
