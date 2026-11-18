
## C2PA Manifest Findings � Exhibits A�E

### Generator Identification
All five manifests identify:
- Software agent: ChatGPT
- Version: gpt-image
- Claim generator: OpenAI Media Service API
- C2PA specification: 2.2.0

### Signing Configurations
- Exhibits A, B, E: PS256, shared certificate serial
- Exhibits C, D: ES256, shared certificate serial

### Recorded Actions
All five include:
- c2pa.created
- c2pa.converted
- c2pa.watermarked.unbound

All five report allActionsIncluded=false.

### Validation
All five returned signingCredential.untrusted.
Certificate trust was not established.

### Interpretation
The manifests record a common image-generation source
but two different signing configurations.

The watermark-related assertion does not establish
the existence of an extractable hidden payload.

### Next Analysis
05_c2pa_assertion_analysis.py



## C2PA Assertion Analysis — 2026-11-18T00:07:50.737795+00:00

Source: `c2pa_assertion_analysis_20261118_000750_737795.json`

- Successfully parsed: 5/5 exhibits
- Signing group Ps256, certificate 15483366567143162630298612244848338035: exhibit-a, exhibit-b, exhibit-e
- Signing group Es256, certificate 471440979205905794604524502504016020624908622401: exhibit-c, exhibit-d
- exhibit-a: actions=['c2pa.created', 'c2pa.converted', 'c2pa.watermarked.unbound']; validation=['signingCredential.untrusted']; allActionsIncluded=False
- exhibit-b: actions=['c2pa.created', 'c2pa.converted', 'c2pa.watermarked.unbound']; validation=['signingCredential.untrusted']; allActionsIncluded=False
- exhibit-c: actions=['c2pa.created', 'c2pa.converted', 'c2pa.watermarked.unbound']; validation=['signingCredential.untrusted']; allActionsIncluded=False
- exhibit-d: actions=['c2pa.created', 'c2pa.converted', 'c2pa.watermarked.unbound']; validation=['signingCredential.untrusted']; allActionsIncluded=False
- exhibit-e: actions=['c2pa.created', 'c2pa.converted', 'c2pa.watermarked.unbound']; validation=['signingCredential.untrusted']; allActionsIncluded=False

Interpretation: Matching action sequences or certificate identifiers do not establish shared image content, user identity, or generation session. Untrusted signing credentials prevent independent trust establishment under the current validator configuration.


## Image Similarity Analysis — 2026-11-18T00:09:24.111389+00:00

Source report: `image_similarity_analysis_20261118_000924_111389.json`

- exhibit-a: 1536x1024, dHash=bb91e9d164484945
- exhibit-b: 1086x1448, dHash=47e5a3a374f29055
- exhibit-c: 1086x1448, dHash=0b4111615979797c
- exhibit-d: 1312x1199, dHash=b1776a6172b1d8f1
- exhibit-e: 1312x1199, dHash=303032a13134b1ab

### Pairwise results

- exhibit-a vs exhibit-b: identical=False, dHash distance=29/64, normalized RMSE=0.2779
- exhibit-a vs exhibit-c: identical=False, dHash distance=28/64, normalized RMSE=0.255392
- exhibit-a vs exhibit-d: identical=False, dHash distance=29/64, normalized RMSE=0.328616
- exhibit-a vs exhibit-e: identical=False, dHash distance=36/64, normalized RMSE=0.548944
- exhibit-b vs exhibit-c: identical=False, dHash distance=29/64, normalized RMSE=0.205219
- exhibit-b vs exhibit-d: identical=False, dHash distance=26/64, normalized RMSE=0.305617
- exhibit-b vs exhibit-e: identical=False, dHash distance=31/64, normalized RMSE=0.51233
- exhibit-c vs exhibit-d: identical=False, dHash distance=29/64, normalized RMSE=0.288652
- exhibit-c vs exhibit-e: identical=False, dHash distance=30/64, normalized RMSE=0.551468
- exhibit-d vs exhibit-e: identical=False, dHash distance=25/64, normalized RMSE=0.527786

Interpretation: Low dHash distances can indicate similar visual structure, but do not establish shared provenance. RMSE is sensitive to cropping, alignment, color, and resizing.


## Pixel Difference Analysis — 2026-11-18T00:10:32.221199+00:00

Comparison: exhibit-b vs exhibit-c

- Dimensions: 1086 x 1448
- Changed pixels: 1,571,823
- Changed percentage: 99.9552%
- Mean absolute error: 32.268663
- RMSE: 53.462449
- Maximum channel difference: 244
- JSON report: `pixel_difference_analysis_20261118_001032_221199.json`

Interpretation: These measurements describe direct pixel differences between aligned images. They do not independently establish whether one image was derived from the other.


## Steganography Analysis — 2026-11-18T00:11:22.642497+00:00

Source report: `steganography_analysis_20261118_001122_642497.json`


### exhibit-a
- R LSB: entropy=0.999988, transition=0.498469
- G LSB: entropy=0.99999, transition=0.498693
- B LSB: entropy=0.999861, transition=0.493894
- Signature candidates: []

### exhibit-b
- R LSB: entropy=0.999999, transition=0.500629
- G LSB: entropy=0.999998, transition=0.499945
- B LSB: entropy=0.999993, transition=0.499427
- Signature candidates: []

### exhibit-c
- R LSB: entropy=1.0, transition=0.50095
- G LSB: entropy=0.999999, transition=0.50039
- B LSB: entropy=0.999996, transition=0.500635
- Signature candidates: []

### exhibit-d
- R LSB: entropy=1.0, transition=0.49636
- G LSB: entropy=0.999941, transition=0.493571
- B LSB: entropy=0.998503, transition=0.474179
- Signature candidates: []

### exhibit-e
- R LSB: entropy=0.99938, transition=0.449611
- G LSB: entropy=0.999802, transition=0.458225
- B LSB: entropy=0.999984, transition=0.470271
- Signature candidates: []

Interpretation: These are statistical screening results. High entropy, unusual bit distributions, or matching file signatures require independent verification before concluding that hidden information is present.


## LSB Payload Analysis — 2026-11-18T00:13:21.746775+00:00

Source report: `lsb_payload_analysis_20261118_001321_746775.json`

- exhibit-a: 80 configurations; 2 signature candidates; 0 text candidates
- exhibit-b: 80 configurations; 2 signature candidates; 0 text candidates
- exhibit-c: 80 configurations; 0 signature candidates; 0 text candidates
- exhibit-d: 80 configurations; 3 signature candidates; 0 text candidates
- exhibit-e: 80 configurations; 22 signature candidates; 0 text candidates

Interpretation: Candidate matches require validation against their expected file structure and comparison with control results. No candidate alone establishes the presence of a hidden payload.


## LSB Signature Validation — 2026-11-18T00:19:40.671927+00:00

Source: `lsb_payload_analysis_20261118_001321_746775.json`

- Candidates tested: 29
- Structurally valid candidates: 25
- VALID: exhibit-a B bit 0 alignment 0: JPEG at byte 65359 — JPEG EOI found
- VALID: exhibit-b RGB bit 0 alignment 3: JPEG at byte 40723 — JPEG EOI found
- VALID: exhibit-d R bit 1 alignment 2: JPEG at byte 126374 — JPEG EOI found
- VALID: exhibit-d B bit 1 alignment 6: JPEG at byte 79633 — JPEG EOI found
- VALID: exhibit-d RGB bit 0 alignment 1: JPEG at byte 89515 — JPEG EOI found
- VALID: exhibit-e R bit 0 alignment 4: JPEG at byte 131102 — JPEG EOI found
- VALID: exhibit-e R bit 0 alignment 6: JPEG at byte 117538 — JPEG EOI found
- VALID: exhibit-e G bit 1 alignment 0: JPEG at byte 167337 — JPEG EOI found
- VALID: exhibit-e G bit 1 alignment 1: JPEG at byte 97338 — JPEG EOI found
- VALID: exhibit-e G bit 1 alignment 1: JPEG at byte 127150 — JPEG EOI found
- VALID: exhibit-e G bit 1 alignment 2: JPEG at byte 85818 — JPEG EOI found
- VALID: exhibit-e G bit 1 alignment 2: JPEG at byte 124492 — JPEG EOI found
- VALID: exhibit-e G bit 1 alignment 2: JPEG at byte 132345 — JPEG EOI found
- VALID: exhibit-e G bit 1 alignment 3: JPEG at byte 158493 — JPEG EOI found
- VALID: exhibit-e G bit 1 alignment 5: JPEG at byte 20037 — JPEG EOI found
- VALID: exhibit-e G bit 1 alignment 7: JPEG at byte 18313 — JPEG EOI found
- VALID: exhibit-e B bit 0 alignment 0: JPEG at byte 14211 — JPEG EOI found
- VALID: exhibit-e B bit 1 alignment 1: JPEG at byte 101269 — JPEG EOI found
- VALID: exhibit-e B bit 1 alignment 1: JPEG at byte 113776 — JPEG EOI found
- VALID: exhibit-e B bit 1 alignment 4: JPEG at byte 9572 — JPEG EOI found
- VALID: exhibit-e RGB bit 0 alignment 5: JPEG at byte 106553 — JPEG EOI found
- VALID: exhibit-e RGB bit 1 alignment 4: GZIP at byte 11602 — plausible GZIP header
- VALID: exhibit-e BGR bit 1 alignment 2: JPEG at byte 78727 — JPEG EOI found
- VALID: exhibit-e BGR bit 1 alignment 2: JPEG at byte 104529 — JPEG EOI found
- VALID: exhibit-e BGR bit 1 alignment 4: JPEG at byte 165518 — JPEG EOI found

Interpretation: Magic-byte matches that fail structural validation are consistent with accidental matches in large extracted bitstreams. A structurally valid candidate warrants targeted extraction and independent verification.


## Deep LSB Candidate Validation — 2026-11-18T00:20:26.173547+00:00

- Deep-tested candidates: 25
- Confirmed payloads: 0

Interpretation: Analysis 10's JPEG EOI test was only preliminary. This pass requires coherent JPEG marker structure or successful GZIP decompression before a candidate is treated as an extracted payload.
