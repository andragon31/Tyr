#!/bin/bash
set -e

REPO="andragon31/Tyr"
INSTALL_DIR="/usr/local/bin"

if [[ "$OSTYPE" == "darwin"* ]]; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "arm64" ]; then
        BIN="tyr-darwin-arm64"
    else
        BIN="tyr-darwin-amd64"
    fi
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        BIN="tyr-linux-arm64"
    else
        BIN="tyr-linux-amd64"
    fi
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

TMP=$(mktemp)
URL="https://github.com/${REPO}/releases/latest/download/${BIN}"

echo "Downloading Tyr..."
curl -fsSL "$URL" -o "$TMP"
chmod +x "$TMP"

if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP" "$INSTALL_DIR/tyr"
    echo "Installed to $INSTALL_DIR/tyr"
else
    echo "Installing to $INSTALL_DIR requires sudo..."
    sudo mv "$TMP" "$INSTALL_DIR/tyr"
    echo "Installed to $INSTALL_DIR/tyr"
fi

echo ""
echo "Tyr installed! Run:"
echo "  tyr version          # Verify"
echo "  tyr init            # Initialize"
echo ""
