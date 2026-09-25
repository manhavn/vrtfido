#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$SCRIPT_DIR/extension"
DIST_DIR="$SCRIPT_DIR/dist"
CHROME_DIST="$DIST_DIR/chrome"

echo "=== [1/3] Chuẩn bị thư mục build Chrome ==="
rm -rf "$CHROME_DIST" "$DIST_DIR/vrtfido-chrome.zip"
mkdir -p "$CHROME_DIST"

echo "=== [2/3] Sao chép tệp nguồn extension ==="
cp "$EXT_DIR/popup.html" "$CHROME_DIST/"
cp "$EXT_DIR/popup.js" "$CHROME_DIST/"
cp "$EXT_DIR/background.js" "$CHROME_DIST/"
cp "$EXT_DIR/content.js" "$CHROME_DIST/"
cp "$EXT_DIR/inject.js" "$CHROME_DIST/"
cp -r "$EXT_DIR/_locales" "$CHROME_DIST/"
cp -r "$EXT_DIR/icons" "$CHROME_DIST/"
node -e '
const fs = require("fs");
const manifest = JSON.parse(fs.readFileSync("'"$EXT_DIR"'/manifest.json", "utf8"));
// Chrome tối ưu: dùng service_worker duy nhất trong background
manifest.background = {
  service_worker: "background.js"
};
// Xoá cấu hình riêng của Firefox
delete manifest.browser_specific_settings;
fs.writeFileSync("'"$CHROME_DIST"'/manifest.json", JSON.stringify(manifest, null, 2));
'

echo "=== [3/3] Đóng gói ZIP Chrome: $DIST_DIR/vrtfido-chrome.zip ==="
python3 -c '
import zipfile, os
dist = "'"$CHROME_DIST"'"
out_zip = "'"$DIST_DIR"'/vrtfido-chrome.zip"
with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(dist):
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, dist))
'

echo "✓ Build Chrome Extension thành công!"
echo "  - Thư mục nạp trực tiếp (Load unpacked): $CHROME_DIST"
echo "  - Tệp zip đóng gói: $DIST_DIR/vrtfido-chrome.zip"
