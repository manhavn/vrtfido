#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "      VrtFido Extension Build Tool        "
echo "=========================================="

bash "$SCRIPT_DIR/build-chrome.sh"
echo ""
bash "$SCRIPT_DIR/build-firefox.sh"
echo ""
bash "$SCRIPT_DIR/build-safari.sh"

echo ""
echo "=========================================="
echo "✓ Đã build xong tiện ích cho Chrome, Firefox & Safari!"
echo "  - Chrome / Chromium (Load unpacked): $SCRIPT_DIR/dist/chrome"
echo "  - Firefox (Load zip):               $SCRIPT_DIR/dist/vrtfido-firefox.zip"
echo "  - Safari (Web Extension):           $SCRIPT_DIR/dist/safari"
echo "=========================================="
