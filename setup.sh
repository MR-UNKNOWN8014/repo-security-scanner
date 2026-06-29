#!/bin/bash
# Install for Linux/Mac

set -e

echo "============================================================"
echo "  Repository Security Scanner - Installer"
echo "============================================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 not found. Please install Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || [ "$PYTHON_MINOR" -lt 8 ]; then
    echo "[ERROR] Python 3.8+ required. You have $PYTHON_VERSION"
    exit 1
fi

echo "[OK] Python $PYTHON_VERSION detected"
echo ""

# Install dependencies
echo "Installing dependencies..."
python3 -m pip install --upgrade pip --quiet
python3 -m pip install -r requirements.txt --quiet

echo "[OK] Installation complete"