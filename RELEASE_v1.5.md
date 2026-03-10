# LOCAL AI SCANNER v1.5

Release date: 2026-03-10

## Summary

Version `1.5` improves static threat detection quality by extending `rules.yar` with higher-confidence, multi-indicator YARA rules.

## Key changes

- Added a new source version folder: `src/1.5`.
- Expanded YARA ruleset with targeted detections for:
  - deserialization-to-RCE chains
  - command execution combined with network access
  - reverse shell techniques and C2 markers
  - obfuscated payload execution patterns
  - secret collection with exfiltration channels
  - persistence with defense-evasion indicators
  - encoded PowerShell payloads
  - suspicious `trust_remote_code` usage in model pipelines

## Installer support

- Windows installer now includes `v1.5` in version selection.
- Linux installer now includes `v1.5` in version selection.
- `v1.5` is intended to be installed in `SOURCE` mode.

## Backward compatibility

- Version `1.4` remains unchanged.
- Existing scan CLI workflow is unchanged.

## Changed paths

- `src/1.5/*` (new version folder, based on `1.4`)
- `src/1.5/rules.yar` (expanded threat rules)
- `README.md` (version and `v1.5` notes)
- `installers/windows/install.bat` (added `v1.5` choice)
- `installers/linux/install.sh` (added `v1.5` choice)
- `installers/README.md` (updated version strategy)
