#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$SCRIPT_DIR/extension"
DIST_DIR="$SCRIPT_DIR/dist"
SAFARI_DIST="$DIST_DIR/safari"

echo "=== [1/3] Chuẩn bị thư mục build Safari ==="
rm -rf "$SAFARI_DIST" "$DIST_DIR/vrtfido-safari.zip"
mkdir -p "$SAFARI_DIST"

echo "=== [2/3] Sao chép tệp nguồn extension ==="
cp "$EXT_DIR/popup.html" "$SAFARI_DIST/"
cp "$EXT_DIR/popup.js" "$SAFARI_DIST/"
cp "$EXT_DIR/background.js" "$SAFARI_DIST/"
cp "$EXT_DIR/content.js" "$SAFARI_DIST/"
cp "$EXT_DIR/inject.js" "$SAFARI_DIST/"
cp -r "$EXT_DIR/_locales" "$SAFARI_DIST/"
cp -r "$EXT_DIR/icons" "$SAFARI_DIST/"

# Tạo manifest chuẩn cho Safari Web Extensions (MV3)
node -e '
const fs = require("fs");
const manifest = JSON.parse(fs.readFileSync("'"$EXT_DIR"'/manifest.json", "utf8"));

// Safari MV3: sử dụng service_worker cho background
manifest.background = {
  service_worker: "background.js"
};

// Loại bỏ các trường không tương thích với Safari
delete manifest.browser_specific_settings;
delete manifest.key;

// Đảm bảo content_scripts chỉ định đúng
manifest.content_scripts = [
  {
    matches: ["<all_urls>"],
    js: ["content.js"],
    run_at: "document_start",
    all_frames: true
  }
];

fs.writeFileSync("'"$SAFARI_DIST"'/manifest.json", JSON.stringify(manifest, null, 2));
'

echo "=== [3/3] Đóng gói ZIP Safari: $DIST_DIR/vrtfido-safari.zip ==="
python3 -c '
import zipfile, os
dist = "'"$SAFARI_DIST"'"
out_zip = "'"$DIST_DIR"'/vrtfido-safari.zip"
with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(dist):
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, dist))
'

echo "✓ Build Safari Extension thành công!"
echo "  - Thư mục nguồn Safari Web Extension: $SAFARI_DIST"
echo "  - Tệp zip đóng gói: $DIST_DIR/vrtfido-safari.zip"

# Nếu chạy trên macOS có sẵn Xcode xcrun, tự động convert sang Xcode project
if command -v xcrun &>/dev/null && xcrun --find safari-web-extension-converter &>/dev/null; then
  echo ""
  echo "=== [macOS phát hiện] Tự động tạo Xcode Project cho Safari ==="
  XCODE_PROJ_DIR="$DIST_DIR/safari-xcode"
  rm -rf "$XCODE_PROJ_DIR"
  xcrun safari-web-extension-converter "$SAFARI_DIST" \
    --project-location "$XCODE_PROJ_DIR" \
    --app-name "VrtFido" \
    --bundle-identifier "com.vrtfido.passkey" \
    --no-open
  echo "✓ Đã tạo Xcode Project tại: $XCODE_PROJ_DIR/VrtFido"
fi
