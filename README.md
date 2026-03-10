# LOCAL AI SCANNER

Local AI Scanner is a local security scanner for machine learning model files.
It is designed to detect suspicious model content before model loading or deployment.

The scanner focuses on:

- risky serialization formats
- suspicious static signatures
- indicators of shadow logic and backdoor behavior
- file-level security anomalies and risk scoring

## Why use it

Model files from untrusted sources can include hidden behavior or dangerous payload markers.
Local AI Scanner helps you perform an offline pre-check and quickly triage risk before integration.

## Main capabilities

- Scan single files, directories, and Hugging Face model IDs.
- Analyze common model formats: `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.h5`, `.keras`, `.hdf5`, `.safetensors`, `.onnx`, `.pb`, `.zip`.
- Produce output in `text`, `json`, or `csv`.
- Return concise JSON by default, with full JSON details via `--detailed-json`.
- Assign risk levels: `SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

## Version and install strategy

Recommended installation method by version:

- `v1.0` to `v1.2`: prefer pre-built executable install (`RELEASE` mode).
- `v1.3` to `v1.5`: prefer source install (`SOURCE` mode) for latest logic and dependency behavior.

The latest source code is in `src/1.5`.

## What's new in v1.5

- Expanded YARA signatures for more precise threat correlation instead of single-token hits.
- Added dedicated detection rules for:
  - deserialization-to-RCE chains
  - reverse shell techniques
  - obfuscated payload execution
  - secret collection with exfiltration channels
  - persistence and defense evasion
  - encoded PowerShell payloads
  - potential `trust_remote_code` abuse in model pipelines
- Full release notes: `RELEASE_v1.5.md`

## Direct download links

Repository:

- Open repository root: [Open](./)

Installers:

- Windows installer (`install.bat`, ZIP): [Download](../../raw/refs/heads/main/installers/windows/LocalAIScanner-Windows-Installer.zip)
- Linux installer (`install.sh`, ZIP): [Download](../../raw/refs/heads/main/installers/linux/LocalAIScanner-Linux-Installer.zip)

Program versions:

- `v1.5` source package (`main.zip`): [Download](../../archive/refs/heads/main.zip)
- `v1.4` source package (`main.zip`): [Download](../../archive/refs/heads/main.zip)
- `v1.3` Windows `RELEASE` (`LocalAIScanner.rar`): [Download](../../raw/refs/heads/main/releases/1.3/windows/LocalAIScanner.rar)
- `v1.2` Windows `RELEASE` (`Local AI Scaner.zip`): [Download](../../raw/refs/heads/main/releases/1.2/windows/Local%20AI%20Scaner.zip)
- `v1.1` Windows `RELEASE` (`LocalAIScanner.zip`): [Download](../../raw/refs/heads/main/releases/1.1/windows/LocalAIScanner.zip)
- `v1.0` Windows `RELEASE` (`Local AI Scanner.zip`): [Download](../../raw/refs/heads/main/releases/1.0/windows/Local%20AI%20Scanner.zip)

## Quick start from source

```bash
cd src/1.5
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate
pip install -r ../../requirements.txt
python main.py --help
```

## Quick scan examples

```bash
python main.py model.pt
python main.py ./models --output-format json -o results.json
python main.py ./models --output-format json --detailed-json -o full_results.json
```

## CLI

```text
python main.py <path_or_hf_id> [--scan-type full|format|security|backdoor]
                             [--output-format text|json|csv]
                             [--detailed-json]
                             [--output-file FILE]
                             [--verbose]
```

Important flags:

- `--scan-type`: analysis depth (`full` by default)
- `--output-format` / `-f`: output format (`text`, `json`, `csv`)
- `--detailed-json`: include full raw scan payload in JSON output
- `--output-file` / `-o`: save output to file
- `--verbose` / `-v`: verbose logs

## Installer behavior

Installers are in:

- `installers/windows/install.bat`
- `installers/linux/install.sh`

After installer-based setup, the scanner is available globally as:

```text
local-ai-scanner
```

This command works for both installation modes:

- pre-built executable install (`RELEASE`)
- source + virtualenv install (`SOURCE`)

Also available:

- `las`
- `local-ai-scaner` (compatibility alias)
- `UPDATE` mode in installers for in-place update of an already installed selected version

Installers download required files from internet by default, so a full local repository copy is not required.
To override source URL (fork/mirror), set environment variable `LAS_REPO_ZIP_URL`.

## Output and interpretation

- `text` output is best for manual review.
- `json` output is best for automation and CI.
- `csv` output is best for batch result aggregation.

Operational guidance:

- `HIGH` and `CRITICAL` should block automatic deployment.
- `MEDIUM` should trigger manual review.
- `LOW` and `SAFE` can proceed with normal controls.

## Repository layout

```text
project/
  README.md
  RELEASE_v1.5.md
  RELEASE_v1.4.md
  requirements.txt
  src/
    1.5/
    1.4/
    1.3/
    1.2/
    1.1/
    1.0/
  installers/
    README.md
    windows/install.bat
    windows/LocalAIScanner-Windows-Installer.zip
    linux/install.sh
    linux/LocalAIScanner-Linux-Installer.zip
  releases/
    1.0/
    1.1/
    1.2/
    1.3/
```
