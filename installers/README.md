# LOCAL AI SCANNER - Advanced Installation Guides

Complete installation scripts for **Windows** and **Linux** with flexible options for both pre-built executables and source-based installations.

## ✨ Features

Both installers now support:

- **Two installation methods**:
  - 📦 Pre-built executable (fast, recommended)
  - 🐍 From source with virtual environment (customizable)
- **Version selection** (v1.0, v1.1, v1.2, v1.3)
- **Smart path detection** and automatic configuration
- **Virtual environment creation** for source installations
- **Dependency management** from `requirements.txt`
- **Command-line integration** with PATH configuration
- **Desktop shortcuts** and quick-access commands
- **Uninstaller scripts** for clean removal
- **Clear usage instructions** and examples

---

## 🪟 Windows Installation (install.bat)

### Prerequisites
- Windows 7 SP1 or later (Windows 10/11 recommended)
- **Administrator privileges** (required)
- Python 3.8+ (if installing from source)
- ~500 MB disk space

### Installation Steps

1. **Open Command Prompt as Administrator**
   - Press `Win + R`
   - Type `cmd`
   - Right-click and select "Run as administrator"

2. **Navigate to installer**
   ```cmd
   cd C:\path\to\vsosh_project\installers\windows
   ```

3. **Run the installer**
   ```cmd
   install.bat
   ```

4. **Follow the interactive prompts**
   - Select version: 1-4 (1 is latest, recommended)
   - Choose installation method:
     - Option 1: Pre-built executable
     - Option 2: From source with venv
   - Confirm installation path
   - Wait for completion

### Installation Methods

#### Method 1: Pre-built Executable ⚡ (Recommended)
- **Speed**: Fast (~2-3 minutes)
- **Size**: ~450 MB per version
- **Requirements**: No Python needed
- **Best for**: Most users, quick deployment

```
Install flow:
├── Select version
├── Copy executable from releases\windows\
├── Create shortcuts and PATH entries
└── Ready to use!
```

#### Method 2: From Source with Venv 🔧
- **Speed**: Slower (~5-10 minutes, depends on internet)
- **Size**: ~200 MB base + dependencies
- **Requirements**: Python 3.8+
- **Best for**: Developers, customization, running latest code

```
Install flow:
├── Select version
├── Create Python virtual environment
├── Copy source files from src\
├── Install dependencies from requirements.txt
├── Create launcher batch file
└── Ready to use!
```

### Installation Locations

**Pre-built installation:**
```
Program Files\LocalAIScanner\
├── v1.3\
│   ├── LocalAIScanner.exe
│   ├── uninstall.bat
│   └── (libraries and data files)
├── v1.2\
├── v1.1\
└── v1.0\
```

**Source installation:**
```
Program Files\LocalAIScanner\
└── v1.3\
    ├── source\              (Python source code)
    │   ├── main.py
    │   ├── output.py
    │   └── ...
    ├── venv\                (Python virtual environment)
    │   ├── Scripts\
    │   ├── Lib\
    │   └── ...
    ├── LocalAIScanner.bat   (launcher)
    └── uninstall.bat
```

### After Installation

**Run from command prompt:**
```cmd
LocalAIScanner model.pkl
LocalAIScanner C:\path\to\models
LocalAIScanner model.h5 -f json -o report.json
```

**Or use Start Menu shortcut:**
- Look for "LocalAIScanner" in Start Menu

**Or use the executable directly:**
```cmd
"C:\Program Files\LocalAIScanner\v1.3\LocalAIScanner.exe" model.pkl
```

### Uninstallation

- Run: `C:\Program Files\LocalAIScanner\v1.3\uninstall.bat`
- Or: Control Panel → Programs → Uninstall

---

## 🐧 Linux Installation (install.sh)

### Prerequisites
- Linux: Ubuntu 18.04+, Debian 10+, CentOS 7+, or Fedora 30+
- Bash shell
- Python 3.8+ (if installing from source)
- ~500 MB disk space
- Internet connection (for dependencies)

### Installation Steps

1. **Navigate to installer**
   ```bash
   cd ~/vsosh_project/installers/linux
   ```

2. **Make script executable** (if needed)
   ```bash
   chmod +x install.sh
   ```

3. **Run the installer**
   ```bash
   ./install.sh
   ```

   Or with sudo for system-wide installation:
   ```bash
   sudo ./install.sh
   ```

4. **Follow the interactive prompts**
   - Select version: 1-4 (1 is latest)
   - Choose installation method (1 or 2)
   - Confirm installation path
   - Wait for completion

5. **Reload shell configuration**
   ```bash
   source ~/.bashrc
   # or for zsh:
   source ~/.zshrc
   ```

### Installation Methods

#### Method 1: Pre-built Executable ⚡
- Copies pre-compiled binary from releases
- No Python required
- ~450 MB per version
- **Recommended for most users**

#### Method 2: From Source with Venv 🔧
- Creates Python virtual environment
- Copies source from `src/` directory
- Installs dependencies from `requirements.txt`
- Better for development and customization

### Installation Locations

**User Installation** (without sudo):
```
~/.local/
├── share/local-ai-scanner/
│   └── v1.3/
│       ├── (executable or source files)
│       ├── venv/          (if from source)
│       └── uninstall.sh
└── bin/
    ├── LocalAIScanner    (symlink to launcher)
    └── scan              (shortcut alias)
```

**System Installation** (with sudo):
```
/usr/local/
├── share/local-ai-scanner/
│   └── v1.3/
│       └── ...
└── bin/
    ├── LocalAIScanner
    └── scan
```

### After Installation

**Run from terminal:**
```bash
# Command will be available in PATH after reload
LocalAIScanner model.pkl
LocalAIScanner ./models
LocalAIScanner model.h5 -f json -o report.json

# Or use the 'scan' alias
scan model.pt --scan-type security -v
```

**Or call directly:**
```bash
~/.local/bin/LocalAIScanner model.pkl
```

### Uninstallation

```bash
bash ~/.local/share/local-ai-scanner/v1.3/uninstall.sh
```

---

## 📋 Version Information

| Version | Release | Features |
|---------|---------|----------|
| v1.3 | Latest | Directory scanning, multi-file support |
| v1.2 | Stable | Output format enhancements |
| v1.1 | Stable | Improved detection algorithms |
| v1.0 | Initial | Core functionality |

---

## 🔧 Common Tasks

### Switch to Different Version

**Windows:**
```cmd
install.bat
REM Select different version when prompted
```

**Linux:**
```bash
./install.sh
# Select different version when prompted
```

### Installing with Source (Manual Method)

If the automatic installer fails, you can manually set up:

**Windows (PowerShell):**
```powershell
# Create venv
python -m venv LocalAIScanner_venv
.\LocalAIScanner_venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run
python src/1.3/main.py model.pkl
```

**Linux (Bash):**
```bash
# Create venv
python3 -m venv LocalAIScanner_venv
source LocalAIScanner_venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python src/1.3/main.py model.pkl
```

### Verify Installation

```cmd
REM Windows
LocalAIScanner --help

# Linux
LocalAIScanner --help
```

---

## 🆘 Troubleshooting

### Issue: "Administrator privileges required" (Windows)

**Solution**: 
- Right-click `install.bat`
- Select "Run as administrator"

### Issue: "Python not found" (Source installation)

**Windows Solution**:
1. Install Python from https://www.python.org/downloads/
2. Check "Add Python to PATH" during installation
3. Restart terminal and try again

**Linux Solution**:
```bash
# Ubuntu/Debian
sudo apt-get install python3 python3-venv

# Fedora/RedHat
sudo dnf install python3 python3-venv
```

### Issue: "Release files not found"

**Solution**: 
- Make sure `releases/windows/` or `releases/linux/` directories exist
- Check that version folders (1.3, 1.2, etc.) contain files
- Pre-extract any ZIP archives

### Issue: Command not found after installation

**Windows**:
- Restart Command Prompt
- Or add manually to PATH in System Properties → Environment Variables

**Linux**:
- Run: `source ~/.bashrc`
- Or restart terminal
- Or add to PATH manually: `export PATH="~/.local/bin:$PATH"`

### Issue: Permission denied (Linux)

**Solution**:
```bash
chmod +x install.sh
./install.sh
```

---

## 📖 Additional Resources

- **GitHub Repository**: https://github.com/lfvbdghkjfgm/Local_AI_Scaner/tree/main
- **System Requirements**: See main README.md
- **Usage Guide**: Run `LocalAIScanner --help`

---
