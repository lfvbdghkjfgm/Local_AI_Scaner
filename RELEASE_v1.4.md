# Release 1.4

Date: 2026-03-07
Scope: threat detection quality update, false-positive reduction, and installer/docs refresh.

## Highlights

- Improved risk engine calibration (`RISK_ENGINE_VERSION = 2.6`) to reduce over-classification of safe models as `CRITICAL`.
- Added support for scanning PyTorch-style `.bin` model files (including common names like `pytorch_model.bin`) with filtering to avoid non-model `.bin` artifacts.
- Added cache schema/version invalidation so old cached scores are not reused after risk logic changes.
- Improved quick-signature processing and mapping into security findings.
- Improved shadow logic heuristics with stricter thresholds and better weighting.
- Stabilized tensor statistics in `safe_loader.py` with NaN/Inf filtering before metric computation.
- Replaced SciPy entropy dependency with NumPy-only entropy calculation in `safe_loader.py`.
- Kept JSON output concise by default, with full payload available via `--detailed-json`.

## Behavior Changes

- Directory scans now include `.bin` files when they look like PyTorch model artifacts.
- Risk level assignment uses a combination of normalized score and rule-based floors for high-confidence indicators (trojan signatures + system/network markers).
- Detailed backdoor pattern lines (indented helper lines) no longer inflate risk score directly.

## Upgrade Notes

- Recommended source path for this release: `src/1.4`.
- If you rely on cached scan results, run a fresh scan after upgrading to 1.4.
- For automation, default JSON is summary-level; use `--detailed-json` only when full internals are required.

## Known Limitations

- Static scanning can still produce false positives/false negatives on heavily obfuscated or novel payloads.
- Final security decisions should include behavioral testing in an isolated environment.
