# LOCAL AI SCANNER - Installation Guides

This directory contains working installation scripts for Windows and Linux platforms.

## Features

Both installers include:

- Version selection (v1.0 through v1.3)
- Admin/privilege checking
- Automatic file discovery and copying
- PATH configuration for command-line access
- Desktop shortcut creation (Windows)
- Uninstaller generation
- Installation verification
- Clear usage instructions

## Windows Installation (install.bat)

### Prerequisites
- Windows 7 SP1 or later
- Administrator privileges (required)
- Release files in `../releases/windows/` directory structure

### Installation Steps

1. **Extract the installer**: Ensure `install.bat` is in `installers/windows/`
2. **Run as Administrator**: 
   - Right-click `install.bat`
   - Select "Run as administrator"
3. **Follow the prompts**:
   - Select version (1-4)
   - Confirm installation directory
   - Wait for installation to complete

### Installation Locations

```
Program Files\LocalAIScanner\
  ├── LocalAIScanner.bat           (command-line wrapper)
  └── v1.3\                        (or v1.2, v1.1, v1.0)
      ├── LocalAIScanner.exe
      ├── uninstall.bat
      └── (other files)
```

### After Installation

- Command prompt: `LocalAIScanner model.pkl`
- Desktop shortcut: Double-click icon on desktop
- Start menu: Search for "LocalAIScanner"

### Uninstall

Run `C:\Program Files\LocalAIScanner\v1.3\uninstall.bat` (or your selected version)

## Linux Installation (install.sh)

### Prerequisites
- Ubuntu 18.04+, Debian 10+, CentOS 7+, or Fedora 30+
- Bash shell
- File permissions for `/usr/local` or `~/.local` (depending on root access)

### Installation Steps

1. **Make script executable**:
   ```bash
   chmod +x installers/linux/install.sh
   ```

2. **Run the installer**:
   ```bash
   sudo ./installers/linux/install.sh     # for system-wide installation
   # OR
   ./installers/linux/install.sh          # for user-only installation
   ```

3. **Follow the prompts**:
   - Select version (1-4)
   - Confirm installation directory
   - Wait for installation to complete

### Installation Locations

**System-wide (with sudo)**:
```
/usr/local/share/local-ai-scanner/
  └── v1.3/                    (or v1.2, v1.1, v1.0)
      ├── LocalAIScanner
      ├── uninstall.sh
      └── (other files)

/usr/local/bin/
  ├── LocalAIScanner           (executable link)
  └── scan                     (convenience alias)
```

**User installation**:
```
~/.local/share/local-ai-scanner/
  └── v1.3/

~/.local/bin/
  ├── LocalAIScanner
  └── scan
```

### After Installation

1. **Reload shell**:
   ```bash
   source ~/.bashrc
   # or
   source ~/.zshrc
   ```

2. **Use the scanner**:
   ```bash
   LocalAIScanner model.pkl
   LocalAIScanner ./models
   scan model.h5 -v
   ```

### Uninstall

- System-wide: `bash /usr/local/share/local-ai-scanner/v1.3/uninstall.sh`
- User: `bash ~/.local/share/local-ai-scanner/v1.3/uninstall.sh`


## Adding Custom Versions

To add a new version installer:

1. Create release directory: `releases/windows/1.4/` or `releases/linux/1.4/`
2. Place executable and files in the directory
3. Run installer and select the new version

## Troubleshooting

### Windows

**Error: "Administrator privileges required"**
- Right-click installer and select "Run as administrator"

**Error: "Release files not found"**
- Ensure `releases/windows/1.3/` directory exists with executable
- Verify repository structure hasn't changed

**Command not found after installation**
- Restart command prompt or terminal
- Verify installation completed successfully

### Linux

**Error: "Permission denied"**
- Use `sudo ./installers/linux/install.sh` for system-wide installation
- Or run without sudo to install to `~/.local/`

**Command not found after installation**
- Run `source ~/.bashrc` to reload shell configuration
- Verify `~/.local/bin` is in PATH: `echo $PATH`

**Release files not found**
- Check `releases/windows/` or `releases/linux/` directory
- Ensure version directories match structure

## Script Features in Detail

### Windows (install.bat)

- **Admin Check**: Verifies administrator privileges before proceeding
- **Version Selection**: Interactive menu for v1.0-v1.3
- **Directory Creation**: Creates `Program Files\LocalAIScanner` structure
- **File Copying**: Uses `xcopy` for reliable copying
- **Executable Detection**: Finds `LocalAIScanner.exe` or `main.exe`
- **Batch Wrapper**: Creates wrapper for command-line access
- **PATH Update**: Uses `setx` to update system PATH (requires admin)
- **Shortcuts**: Desktop shortcut and Start Menu integration
- **Uninstaller**: Generates removal script
- **Verification**: Tests executable functionality

### Linux (install.sh)

- **Privilege Detection**: Checks if running as root
- **Prefix Selection**: Automatic `/usr/local` or `~/.local` based on privileges
- **Version Selection**: Interactive menu for v1.0-v1.3
- **Directory Creation**: Creates installation hierarchy
- **File Copying**: Recursive copy with error handling
- **Executable Detection**: Finds appropriate executable format
- **Wrapper Scripts**: Creates shell wrapper for command-line access
- **Symlinks**: Convenience alias `scan` command
- **PATH Configuration**: Updates `.bashrc` and `.zshrc`
- **Uninstaller**: Generates removal script
- **Verification**: Tests executable functionality

## Version Information

The installers support all released versions:

- **v1.3**: Latest (directory scanning, 8-metric analysis) - Recommended
- **v1.2**: Output format enhancements, ZIP support
- **v1.1**: Improved detection algorithms
- **v1.0**: Initial release

## Integration with Release Files

The installers expect the following directory structure in the repository:

```
local-ai-scanner/
├── installers/
│   ├── windows/install.bat
│   └── linux/install.sh
└── releases/
    └── windows/
        ├── 1.0/
        ├── 1.1/
        ├── 1.2/
        └── 1.3/
```

Alternative for Linux-specific releases:
```
releases/
└── linux/
    ├── 1.0/
    ├── 1.1/
    ├── 1.2/
    └── 1.3/
```

## Support

For installation issues:

1. Verify the repository structure matches expectations
2. Ensure release files are in correct directories
3. Check that executables have proper permissions
4. Review error messages outputted by installer
5. Verify system requirements are met

## Security Notes

- Installers require administrator privileges (Windows) or sudo (Linux)
- Files are copied from trusted release directories
- Installers verify executable functionality before completion
- Uninstallers safely remove only installed files

## License

Installation scripts are provided as part of LOCAL AI SCANNER project.
