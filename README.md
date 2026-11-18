# Steganographic Analysis of AI-Generated Images with Metadata Extraction

# 

# A reproducible digital-forensics project investigating metadata, C2PA provenance, PNG structure, image similarity, pixel-level characteristics, and potential steganographic content in AI-generated images.

# 

# The project analyzes five PNG source images, identified as `exhibit-a` through `exhibit-e`, using a sequence of Python-based forensic analyses.

# 

# The investigation moves from conventional metadata and file-structure inspection into C2PA/JUMBF provenance analysis, image comparison, statistical bit-plane analysis, LSB extraction, and validation of suspected embedded payloads.

# 

# Rather than treating statistical anomalies or file-signature matches as evidence by themselves, later stages attempt to independently validate earlier findings.

# 

# \---

# 

# \# Objectives

# 

# The project was designed to investigate:

# 

# \- Metadata contained in AI-generated images

# \- PNG internal structure and nonstandard chunks

# \- C2PA/JUMBF provenance information

# \- Recorded image-generation and processing actions

# \- Relationships between multiple AI-generated images

# \- Pixel-level differences between images

# \- Low-order RGB bit characteristics

# \- Possible least-significant-bit (LSB) steganography

# \- Embedded file signatures within extracted bitstreams

# \- False positives produced during steganographic analysis

# 

# The original source files are preserved while analysis results are written separately to the `reports/` directory.

# 

# \---

# 

# \# Repository Structure

# 

# ```text

# metadata-steg-forensics-ai-gen-images/

# │

# ├── sources/

# │   ├── exhibit-a

# │   ├── exhibit-b

# │   ├── exhibit-c

# │   ├── exhibit-d

# │   └── exhibit-e

# │

# ├── scripts/

# │   ├── 02\_png\_structure\_analysis.py

# │   ├── 03\_caBX\_analysis.py

# │   ├── 04\_c2pa\_manifest\_analysis.py

# │   ├── 05\_c2pa\_assertion\_analysis.py

# │   ├── 06\_image\_similarity\_analysis.py

# │   ├── 07\_pixel\_difference\_analysis.py

# │   ├── 08\_steganography\_analysis.py

# │   ├── 09\_lsb\_payload\_analysis.py

# │   ├── 10\_lsb\_signature\_validation.py

# │   └── 11\_lsb\_candidate\_extraction.py

# │

# ├── reports/

# │   ├── forensic\_runs.log

# │   ├── forensic\_findings.md

# │   ├── \*.json

# │   └── generated comparison images

# │

# ├── metasweep/

# │   └── MetaSweep source and documentation

# │

# ├── tests/

# ├── requirements.txt

# ├── LICENSE

# └── README.md

# ```

# 

# \---

# 

# \# Requirements

# 

# The project was developed and tested with Python 3.

# 

# Recommended environment:

# 

# \- Windows 10/11

# \- PowerShell

# \- Python 3.8+

# \- pip

# \- Git

# 

# The analysis scripts use packages including:

# 

# \- Pillow

# \- C2PA Python bindings

# \- PyPDF2

# \- python-docx

# \- exifread

# \- lxml

# \- hachoir

# \- geopy

# \- tabulate

# 

# See `requirements.txt` for the project's recorded Python dependencies.

# 

# \---

# 

# \# Installation

# 

# \## 1. Clone the Repository

# 

# Open PowerShell and run:

# 

# ```powershell

# git clone https://github.com/icefairy887/steganographic-analysis-on-AI-generated-images-with-metadata-extraction.git

# ```

# 

# Enter the repository:

# 

# ```powershell

# cd steganographic-analysis-on-AI-generated-images-with-metadata-extraction

# ```

# 

# \---

# 

# \## 2. Create a Python Virtual Environment

# 

# ```powershell

# python -m venv .venv

# ```

# 

# Activate it:

# 

# ```powershell

# .\\.venv\\Scripts\\Activate.ps1

# ```

# 

# The PowerShell prompt should now begin with:

# 

# ```text

# (.venv)

# ```

# 

# If the repository was cloned with the existing `.venv` directory, creating a new local virtual environment is still preferable when reproducing the project on another machine because virtual environments can contain machine-specific paths and compiled packages.

# 

# \---

# 

# \## 3. Install Dependencies

# 

# Upgrade pip:

# 

# ```powershell

# python -m pip install --upgrade pip

# ```

# 

# Install the project requirements:

# 

# ```powershell

# python -m pip install -r requirements.txt

# ```

# 

# The C2PA analyses also require the C2PA Python package used by the project.

# 

# If it is not already installed:

# 

# ```powershell

# python -m pip install c2pa-python

# ```

# 

# Verify Pillow:

# 

# ```powershell

# python -m pip show Pillow

# ```

# 

# Verify C2PA:

# 

# ```powershell

# python -m pip show c2pa-python

# ```

# 

# \---

# 

# \# Source Images

# 

# The forensic source files are stored in:

# 

# ```text

# sources/

# ```

# 

# The current dataset contains:

# 

# ```text

# exhibit-a

# exhibit-b

# exhibit-c

# exhibit-d

# exhibit-e

# ```

# 

# The files intentionally do not require filename extensions for the analysis scripts.

# 

# Their file signatures identify them as PNG images.

# 

# The analysis scripts are designed to read the source files without modifying them.

# 

# \---

# 

# \# Running the Analysis

# 

# The scripts are numbered according to the investigative workflow.

# 

# From the repository root, define the paths in PowerShell:

# 

# ```powershell

# $project = (Get-Location).Path

# $sources = Join-Path $project "sources"

# $reports = Join-Path $project "reports"

# $findings = Join-Path $reports "forensic\_findings.md"

# ```

# 

# Create the reports directory if necessary:

# 

# ```powershell

# New-Item -ItemType Directory -Force -Path $reports | Out-Null

# ```

# 

# \---

# 

# \# Analysis 02 — PNG Structure Analysis

# 

# Script:

# 

# ```text

# scripts/02\_png\_structure\_analysis.py

# ```

# 

# Purpose:

# 

# \- Validate PNG structure

# \- Enumerate PNG chunks

# \- Check chunk sizes

# \- Validate CRC values

# \- Detect malformed chunks

# \- Detect metadata-related chunks

# \- Detect bytes following `IEND`

# 

# Run:

# 

# ```powershell

# python .\\scripts\\02\_png\_structure\_analysis.py $sources

# ```

# 

# This analysis identified the following general structure in the source files:

# 

# ```text

# IHDR

# caBX

# IDAT

# IEND

# ```

# 

# No trailing data was detected after `IEND` in the analyzed exhibits.

# 

# \---

# 

# \# Analysis 03 — caBX Analysis

# 

# Script:

# 

# ```text

# scripts/03\_caBX\_analysis.py

# ```

# 

# Purpose:

# 

# \- Locate `caBX` chunks

# \- Record offsets and payload sizes

# \- Calculate SHA-256 hashes

# \- Compare payloads between exhibits

# \- Inspect initial payload bytes

# 

# Run:

# 

# ```powershell

# python .\\scripts\\03\_caBX\_analysis.py $sources $reports

# ```

# 

# The analysis identified JUMBF-related structures inside the `caBX` payloads, including markers associated with C2PA.

# 

# \---

# 

# \# Analysis 04 — C2PA Manifest Analysis

# 

# Script:

# 

# ```text

# scripts/04\_c2pa\_manifest\_analysis.py

# ```

# 

# Purpose:

# 

# \- Parse embedded C2PA manifests

# \- Identify active manifests

# \- Extract assertions

# \- Examine claim-generator information

# \- Examine signature information

# \- Record validation results

# 

# Run:

# 

# ```powershell

# python .\\scripts\\04\_c2pa\_manifest\_analysis.py $sources $reports

# ```

# 

# The manifests contained `c2pa.actions.v2` assertions.

# 

# Recorded provenance information included:

# 

# ```text

# Software Agent: ChatGPT

# Version: gpt-image

# Claim Generator: OpenAI Media Service API

# ```

# 

# The creation action classified the source as:

# 

# ```text

# trainedAlgorithmicMedia

# ```

# 

# The manifests also recorded:

# 

# ```text

# c2pa.created

# c2pa.converted

# c2pa.watermarked.unbound

# ```

# 

# \---

# 

# \# Analysis 05 — C2PA Assertion Analysis

# 

# Script:

# 

# ```text

# scripts/05\_c2pa\_assertion\_analysis.py

# ```

# 

# Purpose:

# 

# \- Compare C2PA assertions between exhibits

# \- Compare action sequences

# \- Compare signing algorithms

# \- Compare certificate serial numbers

# \- Compare signing timestamps

# \- Compare validation results

# 

# Run:

# 

# ```powershell

# python .\\scripts\\05\_c2pa\_assertion\_analysis.py $sources $reports $findings

# ```

# 

# Two signing groups were observed.

# 

# \### Group 1

# 

# ```text

# Algorithm: PS256

# Exhibits: A, B, E

# ```

# 

# \### Group 2

# 

# ```text

# Algorithm: ES256

# Exhibits: C, D

# ```

# 

# All five manifests produced:

# 

# ```text

# signingCredential.untrusted

# ```

# 

# This indicates that trust in the signing credential was not established by the validator configuration used during the investigation.

# 

# It does not independently establish tampering or a fraudulent signature.

# 

# \---

# 

# \# Analysis 06 — Image Similarity Analysis

# 

# Script:

# 

# ```text

# scripts/06\_image\_similarity\_analysis.py

# ```

# 

# Purpose:

# 

# \- Calculate hashes of decoded RGB pixel data

# \- Calculate perceptual difference hashes

# \- Compare Hamming distances

# \- Calculate normalized RMSE

# \- Compare image dimensions

# 

# Run:

# 

# ```powershell

# python .\\scripts\\06\_image\_similarity\_analysis.py $sources $reports $findings

# ```

# 

# No pair contained identical decoded pixel data.

# 

# The analysis identified several pairs warranting closer examination based on dimensions and similarity measurements.

# 

# Similarity metrics are treated as investigative indicators rather than evidence of shared origin.

# 

# \---

# 

# \# Analysis 07 — Pixel Difference Analysis

# 

# Script:

# 

# ```text

# scripts/07\_pixel\_difference\_analysis.py

# ```

# 

# Purpose:

# 

# \- Perform direct pixel comparison

# \- Calculate changed-pixel percentages

# \- Calculate mean absolute error

# \- Calculate RMSE

# \- Generate raw difference images

# \- Generate enhanced difference images

# \- Generate difference heatmaps

# 

# Run:

# 

# ```powershell

# python .\\scripts\\07\_pixel\_difference\_analysis.py $sources $reports $findings

# ```

# 

# The implemented comparison examines Exhibits B and C, which share identical dimensions.

# 

# The analysis found that approximately 99.96% of corresponding pixels differed.

# 

# This indicated that the images were not simple pixel-identical copies despite their dimensional relationship.

# 

# \---

# 

# \# Analysis 08 — Steganography Statistical Screening

# 

# Script:

# 

# ```text

# scripts/08\_steganography\_analysis.py

# ```

# 

# Purpose:

# 

# \- Analyze RGB low-order bit planes

# \- Measure zero/one distributions

# \- Calculate binary Shannon entropy

# \- Measure adjacent-bit transition ratios

# \- Search basic extracted streams for recognizable signatures

# 

# Run:

# 

# ```powershell

# python .\\scripts\\08\_steganography\_analysis.py $sources $reports $findings

# ```

# 

# Exhibits A-C showed LSB distributions close to balanced random-looking bitstreams.

# 

# Exhibits D and E displayed somewhat greater spatial structure in selected channels.

# 

# These differences were treated as statistical observations rather than evidence of hidden data.

# 

# \---

# 

# \# Analysis 09 — LSB Payload Analysis

# 

# Script:

# 

# ```text

# scripts/09\_lsb\_payload\_analysis.py

# ```

# 

# Purpose:

# 

# \- Extract actual LSB bitstreams

# \- Test R, G, and B independently

# \- Test RGB and BGR ordering

# \- Test multiple bit positions

# \- Test all eight bit alignments

# \- Search for file signatures

# \- Search for printable text

# \- Search repeated byte patterns

# \- Compare findings with shuffled controls

# 

# Run:

# 

# ```powershell

# python .\\scripts\\09\_lsb\_payload\_analysis.py $sources $reports $findings

# ```

# 

# Several apparent file signatures were discovered.

# 

# Exhibit E produced substantially more initial signature candidates than the other images.

# 

# No readable text candidates were detected.

# 

# These signature matches were \*\*not considered confirmed payloads\*\*.

# 

# \---

# 

# \# Analysis 10 — LSB Signature Validation

# 

# Script:

# 

# ```text

# scripts/10\_lsb\_signature\_validation.py

# ```

# 

# Purpose:

# 

# \- Reconstruct candidate extraction streams

# \- Examine apparent embedded-file headers

# \- Apply basic structural checks

# \- Compare results with control data

# 

# Run:

# 

# ```powershell

# python .\\scripts\\10\_lsb\_signature\_validation.py $sources $reports $findings

# ```

# 

# Initial validation produced multiple apparently plausible JPEG candidates and one plausible GZIP header.

# 

# However, these tests were intentionally followed by stricter structural validation.

# 

# This stage demonstrates an important forensic issue:

# 

# > Searching sufficiently large pseudo-random bitstreams for short magic-byte sequences can produce convincing false positives.

# 

# \---

# 

# \# Analysis 11 — Deep LSB Candidate Validation

# 

# Script:

# 

# ```text

# scripts/11\_lsb\_candidate\_extraction.py

# ```

# 

# Purpose:

# 

# \- Reconstruct candidate bitstreams

# \- Parse JPEG marker structures

# \- Validate segment lengths

# \- Require coherent JPEG structure

# \- Attempt actual GZIP decompression

# \- Extract payloads only after successful validation

# 

# Run:

# 

# ```powershell

# python .\\scripts\\11\_lsb\_candidate\_extraction.py $sources $reports $findings

# ```

# 

# Results:

# 

# ```text

# Deep-tested candidates: 25

# Confirmed payloads: 0

# ```

# 

# Every apparent JPEG candidate failed deeper JPEG structure validation.

# 

# The apparent GZIP candidate failed DEFLATE decompression.

# 

# Therefore, the current investigation has found \*\*no confirmed conventional sequential LSB payload\*\* in the five analyzed images.

# 

# \---

# 

# \# Reports

# 

# Analysis output is stored under:

# 

# ```text

# reports/

# ```

# 

# The project preserves several types of evidence.

# 

# \## JSON Reports

# 

# Timestamped JSON files contain machine-readable analysis results.

# 

# Examples include:

# 

# ```text

# caBX\_analysis\_\*.json

# c2pa\_manifest\_analysis\_\*.json

# c2pa\_assertion\_analysis\_\*.json

# image\_similarity\_analysis\_\*.json

# pixel\_difference\_analysis\_\*.json

# steganography\_analysis\_\*.json

# lsb\_payload\_analysis\_\*.json

# lsb\_signature\_validation\_\*.json

# lsb\_candidate\_extraction\_\*.json

# ```

# 

# \## Forensic Findings

# 

# ```text

# reports/forensic\_findings.md

# ```

# 

# Contains accumulated findings and interpretation from the investigation.

# 

# \## Execution Log

# 

# ```text

# reports/forensic\_runs.log

# ```

# 

# Records analysis executions and terminal output.

# 

# \## Visual Evidence

# 

# The reports directory also contains generated visualizations such as:

# 

# ```text

# bc\_pixel\_difference\_\*.png

# bc\_enhanced\_difference\_\*.png

# bc\_difference\_heatmap\_\*.png

# ```

# 

# \---

# 

# \# MetaSweep Integration

# 

# MetaSweep was incorporated into this repository as an additional metadata-forensics tool during the investigation.

# 

# Its code is retained under:

# 

# ```text

# metasweep/

# ```

# 

# MetaSweep provided an initial framework for metadata-oriented examination and supports forensic inspection of file metadata.

# 

# The custom numbered scripts developed for this project extend the investigation beyond conventional metadata extraction into:

# 

# \- PNG container analysis

# \- `caBX` extraction

# \- JUMBF inspection

# \- C2PA provenance parsing

# \- Signing-configuration comparison

# \- Image similarity analysis

# \- Pixel-level comparison

# \- Bit-plane statistics

# \- LSB extraction

# \- Candidate payload validation

# 

# MetaSweep remains a separate third-party project. Its included README and license provide its original documentation and attribution.

# 

# The presence of MetaSweep in this repository should not be interpreted as authorship of MetaSweep by the maintainer of this investigation.

# 

# \---

# 

# \# Key Findings

# 

# The investigation currently supports the following findings:

# 

# 1\. All five analyzed exhibits are PNG files.

# 

# 2\. Each contains a `caBX` chunk.

# 

# 3\. The `caBX` data contains JUMBF/C2PA provenance structures.

# 

# 4\. The manifests record the source type as trained algorithmic media.

# 

# 5\. The recorded software agent is ChatGPT with `gpt-image`.

# 

# 6\. Claim-generator information identifies the OpenAI Media Service API.

# 

# 7\. All five contain the recorded actions:

# 

# ```text

# c2pa.created

# c2pa.converted

# c2pa.watermarked.unbound

# ```

# 

# 8\. Two signing configurations were observed across the five exhibits.

# 

# 9\. The images contain different decoded pixel data.

# 

# 10\. Statistical differences occur among their low-order RGB bit planes.

# 

# 11\. Initial LSB extraction produced multiple apparent embedded-file signatures.

# 

# 12\. Deeper structural analysis rejected those candidates.

# 

# 13\. No conventional sequential LSB payload has been confirmed by the analyses performed so far.

# 

# \---

# 

# \# Why False Positives Are Preserved

# 

# An important goal of this project is not merely finding unusual patterns but determining whether those patterns survive additional validation.

# 

# During LSB analysis, short byte sequences resembling JPEG and GZIP headers appeared in extracted bitstreams.

# 

# A weaker analysis could have classified these as hidden files.

# 

# Instead, subsequent analyses reconstructed the candidate streams and attempted to parse the supposed files.

# 

# The candidates failed.

# 

# These negative results are intentionally preserved because they demonstrate the difference between:

# 

# ```text

# interesting pattern

# ```

# 

# and:

# 

# ```text

# validated forensic evidence

# ```

# 

# That distinction is essential in steganographic and digital-forensics research.

# 

# \---

# 

# \# Current Scope

# 

# The project has tested:

# 

# \- PNG structural integrity

# \- PNG ancillary chunks

# \- C2PA/JUMBF provenance

# \- Decoded pixel hashes

# \- Perceptual similarity

# \- Direct pixel differences

# \- RGB bit-plane statistics

# \- Sequential LSB extraction

# \- Multiple channel orders

# \- Multiple bit positions

# \- Multiple bit alignments

# \- Embedded-file signature detection

# \- JPEG candidate validation

# \- GZIP candidate validation

# 

# \---

# 

# \# Limitations

# 

# The absence of a confirmed sequential LSB payload does \*\*not\*\* establish that the images contain no watermarking or steganographic information.

# 

# The current investigation does not exhaustively test:

# 

# \- Transform-domain steganography

# \- Spatially selective embedding

# \- Keyed or pseudo-random pixel traversal

# \- Encrypted payloads without identifiable headers

# \- Proprietary watermarking systems

# \- Model-specific invisible watermark detection

# \- Every possible channel permutation

# \- Every possible bit-packing convention

# 

# Additionally, the C2PA assertion:

# 

# ```text

# c2pa.watermarked.unbound

# ```

# 

# records a watermark-related action but does not by itself disclose a recoverable watermark payload or provide evidence that conventional LSB techniques should detect it.

# 

# Future work may investigate watermark-specific detection separately from conventional steganographic extraction.

# 

# \---

# 

# \# Reproducibility

# 

# The repository preserves:

# 

# ```text

# source image

# &#x20;   ↓

# analysis script

# &#x20;   ↓

# raw result

# &#x20;   ↓

# validation stage

# &#x20;   ↓

# interpreted finding

# ```

# 

# This structure allows findings—including negative findings—to be independently reviewed against the code and source material used to produce them.

# 

# \---

# 

# \# Disclaimer

# 

# This repository is intended for digital-forensics research, security education, metadata analysis, and investigation of files for which the researcher has authorization to analyze.

# 

# Metadata, provenance assertions, statistical anomalies, perceptual similarity, and file-signature matches should not be treated as proof of origin, authorship, tampering, or hidden content without appropriate independent validation.

