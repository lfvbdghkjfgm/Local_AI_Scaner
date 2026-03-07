# Installer Guide

This folder contains interactive installers for LOCAL AI SCANNER:

- Windows: `installers/windows/install.bat`
- Linux: `installers/linux/install.sh`

## Global command after installation

After successful install, the scanner can be started from any directory with:

```text
local-ai-scaner
```

This applies to both installer modes:

- `RELEASE` (pre-built executable)
- `SOURCE` (source code + virtual environment)

## Version strategy

Recommended install method by version:

- `v1.0` to `v1.2`: prefer `RELEASE`
- `v1.3` to `v1.4`: prefer `SOURCE`

Why:

- older versions are usually easier to run as pre-built packages
- latest versions are better kept aligned with source and dependencies

## Windows installer

Requirements:

- Windows 10/11 (or compatible)
- Administrator rights
- Python 3.8+ (for `SOURCE` mode only)

Run:

```cmd
cd installers\windows
install.bat
```

What it does:

- installs selected version
- creates launcher `local-ai-scaner.bat`
- adds install directory to system `PATH`
- creates uninstaller in the installed version folder

## Linux installer

Requirements:

- Bash
- Python 3.8+ with `venv` module (for `SOURCE` mode only)
- optional root/sudo for system-wide install

Run:

```bash
cd installers/linux
bash install.sh
```

Install paths:

- user mode: `~/.local/share/local-ai-scanner/v<version>`
- system mode: `/usr/local/share/local-ai-scanner/v<version>`

What it does:

- installs selected version
- creates global launcher `local-ai-scaner` in `<prefix>/bin`
- updates PATH for user installs (`.bashrc`/`.zshrc`)
- creates uninstaller in the installed version folder

## Progress for dependency install

In `SOURCE` mode, dependency installation uses visible pip progress output.
This is enabled in both Windows and Linux installers.

## Release files vs source

- `RELEASE` mode expects files under `releases/<version>/...`
- `SOURCE` mode uses files from `src/<version>`

If release artifacts are missing, use `SOURCE` mode.

## Uninstall

- Windows: run `uninstall.bat` inside the installed version folder.
- Linux: run `uninstall.sh` inside the installed version folder.
