#!/bin/bash

set -e

# LOCAL AI SCANNER - Linux Installer
# Version 1.3

echo ""
echo "====================================================="
echo "  LOCAL AI SCANNER - Installation Wizard"
echo "====================================================="
echo ""

# Check if running as root (needed for system-wide installation)
if [ "$EUID" -ne 0 ]; then
    echo "Note: Running as user will install to home directory instead of system-wide"
    INSTALL_PREFIX="$HOME/.local"
    NEED_SUDO=0
else
    INSTALL_PREFIX="/usr/local"
    NEED_SUDO=1
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

# Define installation paths
INSTALL_PATH="$INSTALL_PREFIX/share/local-ai-scanner/v$VERSION_NUM"
BIN_PATH="$INSTALL_PREFIX/bin"

echo ""
echo "Installation directory: $INSTALL_PATH"
echo ""
read -p "Continue with installation? (Y/n): " CONFIRM
CONFIRM=${CONFIRM:-Y}

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled"
    exit 0
fi

# Check for release files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_PATH="$SCRIPT_DIR/releases/windows"

if [ ! -d "$RELEASE_PATH/$RELEASE_DIR" ]; then
    echo ""
    echo "Error: Release files not found at $RELEASE_PATH/$RELEASE_DIR"
    echo "Using alternative Linux release path..."
    
    RELEASE_PATH="$SCRIPT_DIR/releases/linux"
    if [ ! -d "$RELEASE_PATH/$RELEASE_DIR" ]; then
        echo "Error: Release files not found"
        echo "Please ensure the release package is properly extracted"
        exit 1
    fi
fi

# Create installation directories
echo ""
echo "Creating installation directories..."
mkdir -p "$INSTALL_PATH"
mkdir -p "$BIN_PATH"

# Copy files
echo "Copying files..."
cp -r "$RELEASE_PATH/$RELEASE_DIR"/* "$INSTALL_PATH/" 2>/dev/null || {
    echo "Error: Failed to copy files"
    exit 1
}

# Find the actual executable name
EXE_FILE=""
if [ -f "$INSTALL_PATH/LocalAIScanner" ]; then
    EXE_FILE="$INSTALL_PATH/LocalAIScanner"
elif [ -f "$INSTALL_PATH/main" ]; then
    EXE_FILE="$INSTALL_PATH/main"
elif [ -f "$INSTALL_PATH/LocalAIScanner.exe" ]; then
    EXE_FILE="$INSTALL_PATH/LocalAIScanner.exe"
fi

if [ -z "$EXE_FILE" ]; then
    echo "Warning: Could not find executable file in $INSTALL_PATH"
    echo "Available files:"
    ls -la "$INSTALL_PATH/" 2>/dev/null || true
    echo "Installation completed but executable not found"
    exit 1
fi

# Make executable
chmod +x "$EXE_FILE"
echo "Executable located at: $EXE_FILE"

# Create wrapper script in bin directory
echo "Creating command-line wrapper..."
cat > "$BIN_PATH/LocalAIScanner" << EOF
#!/bin/bash
"$EXE_FILE" "\$@"
EOF

chmod +x "$BIN_PATH/LocalAIScanner"

# Create symlink with different name
ln -sf "$BIN_PATH/LocalAIScanner" "$BIN_PATH/scan" 2>/dev/null || true

# Add PATH update instructions
echo "Checking PATH configuration..."
SHELL_RC=""
if [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.bash_profile" ]; then
    SHELL_RC="$HOME/.bash_profile"
fi

if [ -n "$SHELL_RC" ] && ! grep -q "export PATH=.*$BIN_PATH" "$SHELL_RC"; then
    echo "Adding $BIN_PATH to PATH..."
    echo "export PATH=\"$BIN_PATH:\$PATH\"" >> "$SHELL_RC"
fi

# Also check zsh
if [ -f "$HOME/.zshrc" ] && ! grep -q "export PATH=.*$BIN_PATH" "$HOME/.zshrc"; then
    echo "export PATH=\"$BIN_PATH:\$PATH\"" >> "$HOME/.zshrc"
fi

# Create uninstaller script
echo "Creating uninstaller..."
UNINSTALL_SCRIPT="$INSTALL_PATH/uninstall.sh"
cat > "$UNINSTALL_SCRIPT" << EOF
#!/bin/bash
echo "Removing LOCAL AI SCANNER v$VERSION_NUM..."
rm -rf "$INSTALL_PATH"
rm -f "$BIN_PATH/LocalAIScanner"
rm -f "$BIN_PATH/scan"
if [ -d "${INSTALL_PATH%/*}" ] && [ -z "\$(ls -A ${INSTALL_PATH%/*} 2>/dev/null)" ]; then
    rmdir "${INSTALL_PATH%/*}" 2>/dev/null || true
fi
echo "Uninstallation complete"
EOF
chmod +x "$UNINSTALL_SCRIPT"

# Test installation
echo ""
echo "Testing installation..."
if "$EXE_FILE" --help >/dev/null 2>&1; then
    echo "Installation verified successfully"
else
    echo "Warning: Executable test failed"
    echo "Installation may be incomplete"
fi

# Print summary
echo ""
echo "====================================================="
echo "  Installation Complete!"
echo "====================================================="
echo ""
echo "LOCAL AI SCANNER v$VERSION_NUM installed to:"
echo "$INSTALL_PATH"
echo ""
echo "Usage:"
echo " 1. Reload shell or run: source ~/.bashrc"
echo ""
echo " 2. From command line:"
echo "    LocalAIScanner model.pkl"
echo "    LocalAIScanner ./models"
echo "    scan model.h5"
echo ""
echo " 3. Parameters:"
echo "    --scan-type {full,security,backdoor,format}"
echo "    -f, --output-format {text,json,csv,html}"
echo "    -o, --output-file FILE"
echo "    -v, --verbose"
echo ""
echo "Examples:"
echo "  LocalAIScanner model.pkl"
echo "  LocalAIScanner ./models -f json -o report.json"
echo "  scan model.h5 --scan-type security -v"
echo ""
echo "To uninstall: bash $UNINSTALL_SCRIPT"
echo ""
echo "====================================================="
echo ""
