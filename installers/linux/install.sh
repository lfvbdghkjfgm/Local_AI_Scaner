#!/bin/bash

# LOCAL AI SCANNER - Linux Installer
# Supports pre-built executables or installation from source with venv

echo ""
echo "====================================================="
echo "  LOCAL AI SCANNER - Installation Wizard"
echo "====================================================="
echo ""

# Check if running as root (needed for system-wide installation)
if [ "$EUID" -ne 0 ]; then
    INSTALL_PREFIX="$HOME/.local"
    INSTALL_TYPE="user"
else
    INSTALL_PREFIX="/usr/local"
    INSTALL_TYPE="system"
fi

# Get installation version from user
echo "Available versions:"
echo " [1] v1.3 Latest (Recommended)"
echo " [2] v1.2"
echo " [3] v1.1"
echo " [4] v1.0"
echo ""
read -p "Select version (1-4, default is 1): " VERSION
VERSION=${VERSION:-1}

case "$VERSION" in
    1)
        VERSION_NUM="1.3"
        RELEASE_DIR="1.3"
        ;;
    2)
        VERSION_NUM="1.2"
        RELEASE_DIR="1.2"
        ;;
    3)
        VERSION_NUM="1.1"
        RELEASE_DIR="1.1"
        ;;
    4)
        VERSION_NUM="1.0"
        RELEASE_DIR="1.0"
        ;;
    *)
        echo "Invalid selection"
        exit 1
        ;;
esac

# Choose installation method
echo ""
echo "Installation method:"
echo " [1] Pre-built executable (Recommended - fast)"
echo " [2] From source with venv (Requires Python)"
echo ""
read -p "Select method (1-2, default is 1): " INSTALL_METHOD
INSTALL_METHOD=${INSTALL_METHOD:-1}

case "$INSTALL_METHOD" in
    1)
        METHOD="RELEASE"
        ;;
    2)
        METHOD="SOURCE"
        ;;
    *)
        echo "Invalid selection"
        exit 1
        ;;
esac

# Define installation paths
INSTALL_PATH="$INSTALL_PREFIX/share/local-ai-scanner/v$VERSION_NUM"
BIN_PATH="$INSTALL_PREFIX/bin"

echo ""
echo "Installation details:"
echo " Version: v$VERSION_NUM"
echo " Method: $METHOD"
echo " Location: $INSTALL_PATH"
echo " Install type: $INSTALL_TYPE"
echo ""
read -p "Continue? (Y/n): " CONFIRM
CONFIRM=${CONFIRM:-Y}

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled"
    exit 0
fi

# Set error handling
set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Create directories
echo ""
echo "Creating installation directories..."
mkdir -p "$INSTALL_PATH"
mkdir -p "$BIN_PATH"

# ===== INSTALLATION FROM PRE-BUILT RELEASE =====
if [ "$METHOD" = "RELEASE" ]; then
    echo ""
    echo "Installing from pre-built release..."
    
    # Try Linux release first, then Windows
    RELEASE_PATH="$SCRIPT_DIR/releases/linux"
    
    if [ ! -d "$RELEASE_PATH/$RELEASE_DIR" ]; then
        RELEASE_PATH="$SCRIPT_DIR/releases/windows"
    fi
    
    if [ ! -d "$RELEASE_PATH/$RELEASE_DIR" ]; then
        echo ""
        echo "Error: Release files not found"
        echo "Checked paths:"
        echo "  - $SCRIPT_DIR/releases/linux/$RELEASE_DIR"
        echo "  - $SCRIPT_DIR/releases/windows/$RELEASE_DIR"
        echo ""
        exit 1
    fi
    
    echo "Copying files from: $RELEASE_PATH/$RELEASE_DIR"
    cp -r "$RELEASE_PATH/$RELEASE_DIR"/* "$INSTALL_PATH/" 2>/dev/null || {
        echo "Error: Failed to copy files"
        exit 1
    }
    
    # Find executable
    EXE_FILE=""
    if [ -f "$INSTALL_PATH/LocalAIScanner" ]; then
        EXE_FILE="$INSTALL_PATH/LocalAIScanner"
    elif [ -f "$INSTALL_PATH/main" ]; then
        EXE_FILE="$INSTALL_PATH/main"
    fi
    
    if [ -z "$EXE_FILE" ]; then
        echo "Error: Could not find executable in release"
        ls -la "$INSTALL_PATH/"
        exit 1
    fi
    
    # Make executable
    chmod +x "$EXE_FILE"
fi

# ===== INSTALLATION FROM SOURCE WITH VENV =====
if [ "$METHOD" = "SOURCE" ]; then
    echo ""
    echo "Installing from source with Python virtual environment..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo ""
        echo "Error: Python 3 not found"
        echo "Please install Python 3.8 or higher"
        echo "Ubuntu/Debian: sudo apt-get install python3 python3-venv"
        echo "RedHat/Fedora: sudo dnf install python3 python3-venv"
        echo ""
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo "Python $PYTHON_VERSION found"
    
    # Create venv
    echo "Creating virtual environment..."
    python3 -m venv "$INSTALL_PATH/venv"
    
    # Activate venv
    source "$INSTALL_PATH/venv/bin/activate"
    
    # Copy source files
    SRC_PATH="$SCRIPT_DIR/src/$RELEASE_DIR"
    
    if [ ! -d "$SRC_PATH" ]; then
        echo ""
        echo "Error: Source files not found at: $SRC_PATH"
        echo ""
        deactivate 2>/dev/null || true
        exit 1
    fi
    
    echo "Copying source files..."
    cp -r "$SRC_PATH"/* "$INSTALL_PATH/source/" 2>/dev/null || {
        echo "Error: Failed to copy source files"
        deactivate 2>/dev/null || true
        exit 1
    }
    
    # Install requirements
    echo "Installing Python dependencies..."
    REQUIREMENTS="$SCRIPT_DIR/requirements.txt"
    
    if [ -f "$REQUIREMENTS" ]; then
        pip install -q -r "$REQUIREMENTS" || {
            echo "Warning: Some dependencies failed to install"
            echo "You may need to install them manually"
        }
    else
        echo "Warning: requirements.txt not found"
    fi
    
    # Create wrapper script
    echo "Creating wrapper script..."
    EXE_FILE="$BIN_PATH/LocalAIScanner"
    cat > "$EXE_FILE" << 'SCRIPT_EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Find the install directory
INSTALL_DIR=$(find "$SCRIPT_DIR" -name "venv" -type d 2>/dev/null | head -1 | sed 's/\/venv.*//')
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR=$(dirname "$(python3 -c 'import site; print(site.getsitepackages()[0])' 2>/dev/null)")
fi
source "$INSTALL_DIR/venv/bin/activate" 2>/dev/null || true
cd "$INSTALL_DIR/source" 2>/dev/null || cd "$INSTALL_DIR" 2>/dev/null
python main.py "$@"
SCRIPT_EOF
    
    chmod +x "$EXE_FILE"
    
    # Deactivate venv
    deactivate 2>/dev/null || true
fi

# Create symlink shortcut
ln -sf "$EXE_FILE" "$BIN_PATH/scan" 2>/dev/null || true

# Add to PATH
echo ""
echo "Configuring PATH..."
SHELL_RC=""
if [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

if [ -n "$SHELL_RC" ] && ! grep -q "$BIN_PATH" "$SHELL_RC" 2>/dev/null; then
    echo "export PATH=\"$BIN_PATH:\$PATH\"" >> "$SHELL_RC"
    echo "Added $BIN_PATH to ~/.bashrc"
fi

if [ -f "$HOME/.zshrc" ] && ! grep -q "$BIN_PATH" "$HOME/.zshrc" 2>/dev/null; then
    echo "export PATH=\"$BIN_PATH:\$PATH\"" >> "$HOME/.zshrc"
    echo "Added $BIN_PATH to ~/.zshrc"
fi

# Create uninstaller
UNINSTALL_SCRIPT="$INSTALL_PATH/uninstall.sh"
cat > "$UNINSTALL_SCRIPT" << EOF
#!/bin/bash
echo "Removing LOCAL AI SCANNER v$VERSION_NUM..."
rm -rf "$INSTALL_PATH"
rm -f "$BIN_PATH/LocalAIScanner"
rm -f "$BIN_PATH/scan"
echo "Uninstallation complete"
EOF
chmod +x "$UNINSTALL_SCRIPT"

# Print summary
echo ""
echo "====================================================="
echo "  Installation Complete!"
echo "====================================================="
echo ""
echo "Version: v$VERSION_NUM"
echo "Location: $INSTALL_PATH"
if [ "$METHOD" = "SOURCE" ]; then
    echo "Method: From source with venv"
else
    echo "Method: Pre-built executable"
fi
echo ""
echo "To use the scanner:"
echo "  1. Reload shell: source ~/.bashrc"
echo "  2. Run: LocalAIScanner [options] PATH"
echo ""
echo "Examples:"
echo "  LocalAIScanner model.pkl"
echo "  LocalAIScanner ./models"
echo "  LocalAIScanner ./model.h5 -f json -o report.json"
echo "  scan model.pt --scan-type security -v"
echo ""
echo "Installation type: $INSTALL_TYPE"
if [ "$INSTALL_TYPE" = "user" ]; then
    echo "Note: Installed to user directory ($INSTALL_PREFIX)"
else
    echo "Note: Installed to system directory ($INSTALL_PREFIX)"
fi
echo ""
echo "To uninstall: bash $UNINSTALL_SCRIPT"
echo "====================================================="
echo ""
