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
- `v1.3` to `v1.4`: prefer source install (`SOURCE` mode) for latest logic and dependency behavior.

The latest source code is in `src/1.4`.

## Quick start from source

```bash
cd src/1.4
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
local-ai-scaner
```

This command works for both installation modes:

- pre-built executable install (`RELEASE`)
- source + virtualenv install (`SOURCE`)

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
  RELEASE_v1.4.md
  requirements.txt
  src/
    1.4/
    1.3/
    1.2/
    1.1/
    1.0/
  installers/
    README.md
    windows/install.bat
    linux/install.sh
  releases/
    1.0/
    1.1/
    1.2/
    1.3/
```
