#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$SCRIPT_DIR/extension"
DIST_DIR="$SCRIPT_DIR/dist"
FIREFOX_DIST="$DIST_DIR/firefox"
ZIP_FILE="$DIST_DIR/vrtfido-firefox.zip"

echo "=== [1/4] Chuẩn bị thư mục build Firefox ==="
rm -rf "$FIREFOX_DIST" "$ZIP_FILE"
mkdir -p "$FIREFOX_DIST"

echo "=== [2/4] Sao chép tệp nguồn extension ==="
cp "$EXT_DIR/popup.html" "$FIREFOX_DIST/"
cp "$EXT_DIR/popup.js" "$FIREFOX_DIST/"
cp "$EXT_DIR/background.js" "$FIREFOX_DIST/"
cp "$EXT_DIR/content.js" "$FIREFOX_DIST/"
cp "$EXT_DIR/inject.js" "$FIREFOX_DIST/"
cp -r "$EXT_DIR/_locales" "$FIREFOX_DIST/"
cp -r "$EXT_DIR/icons" "$FIREFOX_DIST/"
node -e '
const fs = require("fs");
const manifest = JSON.parse(fs.readFileSync("'"$EXT_DIR"'/manifest.json", "utf8"));
// Firefox MV3 dùng scripts array
manifest.background = {
  scripts: ["background.js"]
};
// Firefox content script: chỉ cần content.js inject script vào DOM, tránh lỗi MAIN world
manifest.content_scripts = [
  {
    matches: ["<all_urls>"],
    js: ["content.js"],
    run_at: "document_start",
    all_frames: true
  }
];
// Đảm bảo gecko ID hợp lệ + khai báo dữ liệu bắt buộc cho addons.mozilla.org
manifest.browser_specific_settings = {
  gecko: {
    id: "vrtfido@local",
    strict_min_version: "140.0",
    data_collection_permissions: {
      required: ["authenticationInfo", "personallyIdentifyingInfo"]
    }
  },
  gecko_android: {
    strict_min_version: "142.0"
  }
};
fs.writeFileSync("'"$FIREFOX_DIST"'/manifest.json", JSON.stringify(manifest, null, 2));
'

echo "=== [3/4] Đóng gói ZIP Firefox: $ZIP_FILE ==="
python3 -c '
import zipfile, os
dist = "'"$FIREFOX_DIST"'"
out_zip = "'"$ZIP_FILE"'"
with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(dist):
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, dist))
'

echo "=== [4/4] Kiểm tra bằng addons-linter (mozilla/addons-linter) ==="
if [ "${SKIP_LINT:-0}" = "1" ]; then
  echo "  (bỏ qua: SKIP_LINT=1)"
elif command -v npx >/dev/null 2>&1; then
  set +e
  npx --yes addons-linter@latest "$ZIP_FILE"
  lint_rc=$?
  set -e
  if [ "$lint_rc" -ne 0 ]; then
    echo "✗ addons-linter phát hiện lỗi (exit $lint_rc) — sửa trước khi public." >&2
    exit "$lint_rc"
  fi
else
  echo "  ! Không tìm thấy npx (Node.js); bỏ qua addons-linter." >&2
fi

echo
echo "✓ Build Firefox Extension thành công!"
echo "  - Thư mục nạp trực tiếp: $FIREFOX_DIST"
echo "  - Tệp zip đóng gói: $ZIP_FILE"
