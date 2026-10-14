#!/usr/bin/env bash
#
# publish-chrome.sh — Build -> upload -> publish extension lên Chrome Web Store (CWS).
# Chạy 1 lệnh, sau đó script hỏi lần lượt từng tham số.
#
#   ./publish-chrome.sh                      # tương tác đầy đủ
#   ./publish-chrome.sh --dry-run            # chỉ build + in lệnh gọi API
#   ./publish-chrome.sh --version 0.3.5 --yes
#
# LƯU Ý QUAN TRỌNG
#   • Lần đầu phải tạo item thủ công trên Dashboard (upload zip + điền Store listing
#     & Privacy), sau đó mới dùng API để update/publish.
#   • Mỗi lần upload, `version` trong manifest PHẢI lớn hơn bản đang publish.
#   • Tài khoản Google bật 2-Step Verification; đã đóng phí đăng ký (một lần, US$5).
#
# Tùy chọn:
#   --publisher-id ID    Publisher ID (Dashboard > Publisher > Settings)
#   --extension-id ID    Item ID của extension trên CWS
#   --credentials FILE   File chứa CWS_CLIENT_ID / CWS_CLIENT_SECRET / CWS_REFRESH_TOKEN
#                        / CWS_PUBLISHER_ID / CWS_EXTENSION_ID
#   --version X.Y.Z      Đặt version trước khi build (bỏ qua bước hỏi)
#   --no-publish         Chỉ upload, không publish (giữ ở bản nháp)
#   --dry-run            Build + in lệnh, KHÔNG gọi API
#   --no-build           Dùng dist/vrtfido-chrome.zip có sẵn
#   -y, --yes            Không hỏi xác nhận
#   -h, --help
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/extension/manifest.json"
CHROME_DIST="$SCRIPT_DIR/dist/chrome"
ZIP_FILE="$SCRIPT_DIR/dist/vrtfido-chrome.zip"
DEFAULT_CRED_FILE="${VRTFIDO_CWS_CREDENTIALS:-$HOME/.config/vrtfido/cws.env}"
API_BASE="https://chromewebstore.googleapis.com"
TOKEN_URL="https://oauth2.googleapis.com/token"

PUBLISHER_ID=""
EXTENSION_ID=""
NEW_VERSION=""
DRY_RUN=0
NO_BUILD=0
NO_PUBLISH=0
ASSUME_YES=0
CRED_FILE=""

# ---------------------------------------------------------------- tiện ích ---
c_reset=$'\033[0m'; c_bold=$'\033[1m'; c_dim=$'\033[2m'
c_ok=$'\033[32m'; c_warn=$'\033[33m'; c_err=$'\033[31m'; c_step=$'\033[36m'

step()  { printf '\n%s%s==> %s%s\n' "$c_step" "$c_bold" "$*" "$c_reset"; }
info()  { printf '    %s\n' "$*"; }
dim()   { printf '    %s%s%s\n' "$c_dim" "$*" "$c_reset"; }
ok()    { printf '%s✓%s %s\n' "$c_ok" "$c_reset" "$*"; }
warn()  { printf '%s!%s %s\n' "$c_warn" "$c_reset" "$*" >&2; }
die()   { printf '%s✗ %s%s\n' "$c_err" "$*" "$c_reset" >&2; exit 1; }

is_tty() { [ -t 0 ]; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Thiếu '$1'. Cài rồi chạy lại."; }

ask() { # ask "câu hỏi" "mặc định"
  local prompt="$1" def="${2:-}" ans=""
  is_tty || die "Cần nhập tương tác cho: $prompt — hãy truyền tham số dòng lệnh (xem --help)."
  if [ -n "$def" ]; then
    read -r -p "$prompt [$def]: " ans || true
    printf '%s' "${ans:-$def}"
  else
    read -r -p "$prompt: " ans || true
    printf '%s' "$ans"
  fi
}

ask_secret() { # ask_secret "câu hỏi"
  local prompt="$1" ans=""
  is_tty || die "Cần nhập bí mật cho: $prompt — hãy đặt biến môi trường / dùng --credentials."
  read -rs -p "$prompt: " ans || true
  printf '\n' >&2
  printf '%s' "$ans"
}

confirm() { # confirm "câu hỏi" -> 0 = đồng ý
  [ "$ASSUME_YES" = "1" ] && return 0
  local ans=""
  is_tty || return 0
  read -r -p "$1 [y/N]: " ans || true
  [[ "$ans" =~ ^[Yy]$ ]]
}

get_version() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["version"])' "$MANIFEST"; }
valid_version() { [[ "$1" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]]; }

bump_version() { # bump_version "0.3.4" patch|minor|major
  python3 - "$1" "$2" <<'PY'
import sys
cur, mode = sys.argv[1], sys.argv[2]
p = [int(x) for x in cur.split('.')]
while len(p) < 4:
    p.append(0)
if mode == 'patch':
    p[2] += 1; p[3] = 0
elif mode == 'minor':
    p[1] += 1; p[2] = 0; p[3] = 0
elif mode == 'major':
    p[0] += 1; p[1] = 0; p[2] = 0; p[3] = 0
print(".".join(str(x) for x in p[:3]))
PY
}

set_version() { # set_version "0.3.5" — chỉ sửa đúng dòng "version"
  python3 - "$MANIFEST" "$1" <<'PY'
import re, sys
path, new = sys.argv[1], sys.argv[2]
src = open(path, encoding='utf-8').read()
out, n = re.subn(r'("version"\s*:\s*")[^"]*(")', lambda m: m.group(1) + new + m.group(2), src, count=1)
if n != 1:
    sys.exit('Không tìm thấy khóa "version" trong manifest')
open(path, 'w', encoding='utf-8').write(out)
PY
}

json_get() { # json_get '<json>' key1 key2 ... -> in giá trị hoặc rỗng
  python3 - "$@" <<'PY'
import json, sys
try:
    data = json.loads(sys.argv[1])
except Exception:
    sys.exit(0)
for key in sys.argv[2:]:
    if isinstance(data, dict) and key in data:
        data = data[key]
    else:
        sys.exit(0)
print(data if isinstance(data, str) else json.dumps(data))
PY
}

usage() {
  cat <<'EOF'
publish-chrome.sh — Build -> upload -> publish extension lên Chrome Web Store.

  ./publish-chrome.sh                    # tương tác đầy đủ
  ./publish-chrome.sh --dry-run          # build + in lệnh API, không gọi mạng
  ./publish-chrome.sh --version 0.3.5 --yes

Tùy chọn:
  --publisher-id ID    Publisher ID (Dashboard > Publisher > Settings)
  --extension-id ID    Item ID của extension trên CWS
  --credentials FILE   File chứa CWS_CLIENT_ID / CWS_CLIENT_SECRET / CWS_REFRESH_TOKEN
                       / CWS_PUBLISHER_ID / CWS_EXTENSION_ID
  --version X.Y.Z      Đặt version trước khi build
  --no-publish         Chỉ upload, không publish
  --dry-run            Build + in lệnh, không gọi API
  --no-build           Dùng dist/vrtfido-chrome.zip có sẵn
  -y, --yes            Không hỏi xác nhận
  -h, --help
EOF
}

# ------------------------------------------------------------------ args ----
while [ $# -gt 0 ]; do
  case "$1" in
    --publisher-id) PUBLISHER_ID="${2:-}"; shift 2 ;;
    --extension-id) EXTENSION_ID="${2:-}"; shift 2 ;;
    --credentials)  CRED_FILE="${2:-}"; shift 2 ;;
    --version)      NEW_VERSION="${2:-}"; shift 2 ;;
    --no-publish)   NO_PUBLISH=1; shift ;;
    --dry-run)      DRY_RUN=1; shift ;;
    --no-build)     NO_BUILD=1; shift ;;
    -y|--yes)       ASSUME_YES=1; shift ;;
    -h|--help)      usage; exit 0 ;;
    *)              die "Tham số không hợp lệ: $1 (xem --help)" ;;
  esac
done

printf '%s%s\n' "$c_bold" "=========================================="
printf '   VrtFido — Publish Chrome Extension      \n'
printf '%s' "$c_reset"
printf '%s\n' "=========================================="

# --------------------------------------------------- [1/6] môi trường ---------
step "[1/6] Kiểm tra môi trường"
need_cmd python3
need_cmd curl
[ -f "$MANIFEST" ] || die "Không thấy $MANIFEST — chạy script trong thư mục repo."
CURRENT_VERSION="$(get_version)"
ok "curl $(curl --version | head -1 | awk '{print $2}'), python3 OK"
ok "Version hiện tại trong manifest: ${c_bold}$CURRENT_VERSION${c_reset}"
[ "$DRY_RUN" = "1" ] && warn "DRY-RUN: sẽ không gọi API Chrome Web Store."

# ------------------------------------------- [2/6] version -------------------
step "[2/6] Version"
if [ -n "$NEW_VERSION" ]; then
  valid_version "$NEW_VERSION" || die "Version không hợp lệ: $NEW_VERSION."
elif [ "$ASSUME_YES" = "1" ] || ! is_tty; then
  NEW_VERSION="$CURRENT_VERSION"
  dim "Giữ nguyên version $NEW_VERSION"
else
  info "Chrome Web Store yêu cầu version MỚI cao hơn bản đang publish."
  info "Version hiện tại: ${c_bold}$CURRENT_VERSION${c_reset}"
  info "  ${c_bold}k${c_reset}) giữ nguyên   ${c_bold}p${c_reset}) tăng patch   ${c_bold}m${c_reset}) tăng minor   ${c_bold}M${c_reset}) tăng major   ${c_bold}n${c_reset}) tự nhập"
  case "$(ask 'Chọn' 'p')" in
    k|K) NEW_VERSION="$CURRENT_VERSION" ;;
    m)   NEW_VERSION="$(bump_version "$CURRENT_VERSION" minor)" ;;
    M)   NEW_VERSION="$(bump_version "$CURRENT_VERSION" major)" ;;
    n|N) NEW_VERSION="$(ask 'Nhập version mới')"; valid_version "$NEW_VERSION" || die "Version không hợp lệ: $NEW_VERSION" ;;
    *)   NEW_VERSION="$(bump_version "$CURRENT_VERSION" patch)" ;;
  esac
fi

if [ "$NEW_VERSION" != "$CURRENT_VERSION" ]; then
  if confirm "Cập nhật version $CURRENT_VERSION -> $NEW_VERSION trong extension/manifest.json?"; then
    set_version "$NEW_VERSION"
    ok "Đã đặt version = $NEW_VERSION"
  else
    NEW_VERSION="$CURRENT_VERSION"
    dim "Giữ nguyên version $CURRENT_VERSION"
  fi
else
  dim "Không đổi version."
fi

# ------------------------------------------------- [3/6] build ----------------
step "[3/6] Build Chrome"
if [ "$NO_BUILD" = "1" ]; then
  warn "Bỏ qua build (--no-build)."
  [ -f "$ZIP_FILE" ] || die "Không thấy $ZIP_FILE."
else
  bash "$SCRIPT_DIR/build-chrome.sh"
fi
[ -f "$ZIP_FILE" ] || die "Không thấy $ZIP_FILE sau khi build."
ok "Gói: $ZIP_FILE ($(du -h "$ZIP_FILE" | cut -f1))"

# ------------------------------------------------ [4/6] thông tin CWS --------
step "[4/6] Thông tin Chrome Web Store"

CLIENT_ID="${CWS_CLIENT_ID:-}"
CLIENT_SECRET="${CWS_CLIENT_SECRET:-}"
REFRESH_TOKEN="${CWS_REFRESH_TOKEN:-}"
[ -z "$PUBLISHER_ID" ] && PUBLISHER_ID="${CWS_PUBLISHER_ID:-}"
[ -z "$EXTENSION_ID" ] && EXTENSION_ID="${CWS_EXTENSION_ID:-}"

CF="$CRED_FILE"
[ -z "$CF" ] && [ -f "$DEFAULT_CRED_FILE" ] && CF="$DEFAULT_CRED_FILE"
if [ -n "$CF" ] && [ -f "$CF" ]; then
  # shellcheck disable=SC1090
  . "$CF"
  CLIENT_ID="${CWS_CLIENT_ID:-}"; CLIENT_SECRET="${CWS_CLIENT_SECRET:-}"
  REFRESH_TOKEN="${CWS_REFRESH_TOKEN:-}"
  [ -z "$PUBLISHER_ID" ] && PUBLISHER_ID="${CWS_PUBLISHER_ID:-}"
  [ -z "$EXTENSION_ID" ] && EXTENSION_ID="${CWS_EXTENSION_ID:-}"
  dim "Đã nạp thông tin từ $CF"
fi

if [ "$DRY_RUN" != "1" ]; then
  [ -n "$CLIENT_ID" ] || CLIENT_ID="$(ask 'CWS_CLIENT_ID (OAuth client ID)')"
  [ -n "$CLIENT_SECRET" ] || CLIENT_SECRET="$(ask_secret 'CWS_CLIENT_SECRET')"
  [ -n "$REFRESH_TOKEN" ] || REFRESH_TOKEN="$(ask_secret 'CWS_REFRESH_TOKEN')"
  [ -n "$PUBLISHER_ID" ] || PUBLISHER_ID="$(ask 'Publisher ID')"
  [ -n "$EXTENSION_ID" ] || EXTENSION_ID="$(ask 'Extension (item) ID')"
  [ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ] && [ -n "$REFRESH_TOKEN" ] \
    || die "Thiếu OAuth client/refresh token."
  [ -n "$PUBLISHER_ID" ] && [ -n "$EXTENSION_ID" ] || die "Thiếu Publisher ID / Extension ID."

  if is_tty && confirm "Lưu thông tin vào $DEFAULT_CRED_FILE (chmod 600) để lần sau không phải nhập?"; then
    mkdir -p "$(dirname "$DEFAULT_CRED_FILE")"
    umask 077
    {
      printf 'CWS_CLIENT_ID=%q\n' "$CLIENT_ID"
      printf 'CWS_CLIENT_SECRET=%q\n' "$CLIENT_SECRET"
      printf 'CWS_REFRESH_TOKEN=%q\n' "$REFRESH_TOKEN"
      printf 'CWS_PUBLISHER_ID=%q\n' "$PUBLISHER_ID"
      printf 'CWS_EXTENSION_ID=%q\n' "$EXTENSION_ID"
    } > "$DEFAULT_CRED_FILE"
    chmod 600 "$DEFAULT_CRED_FILE"
    ok "Đã lưu: $DEFAULT_CRED_FILE"
  fi
else
  [ -n "$PUBLISHER_ID" ] || PUBLISHER_ID="<PUBLISHER_ID>"
  [ -n "$EXTENSION_ID" ] || EXTENSION_ID="<EXTENSION_ID>"
fi

ITEM_URL="$API_BASE/v2/publishers/$PUBLISHER_ID/items/$EXTENSION_ID"
UPLOAD_URL="$API_BASE/upload/v2/publishers/$PUBLISHER_ID/items/$EXTENSION_ID:upload"

# ------------------------------------------------- [5/6] xác nhận -------------
step "[5/6] Xác nhận"
info "Version       : ${c_bold}$NEW_VERSION${c_reset}"
info "Gói           : $ZIP_FILE"
info "Publisher ID  : $PUBLISHER_ID"
info "Extension ID  : $EXTENSION_ID"
info "Hành động     : upload$([ "$NO_PUBLISH" = "1" ] && echo '' || echo ' + publish')"
[ "$DRY_RUN" = "1" ] && info "Chế độ        : ${c_bold}DRY-RUN${c_reset}"

if [ "$DRY_RUN" = "1" ]; then
  step "[6/6] DRY-RUN — lệnh sẽ chạy"
  dim "# 1. Lấy access token từ refresh token:"
  printf '    curl -s %s -d "client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>&grant_type=refresh_token&refresh_token=<REFRESH_TOKEN>"\n' "$TOKEN_URL"
  dim "# 2. Kiểm tra trạng thái item:"
  printf '    curl -H "Authorization: Bearer <TOKEN>" %s:fetchStatus\n' "$ITEM_URL"
  dim "# 3. Upload gói:"
  printf '    curl -X POST -T %q -H "Authorization: Bearer <TOKEN>" %s\n' "$ZIP_FILE" "$UPLOAD_URL"
  if [ "$NO_PUBLISH" != "1" ]; then
    dim "# 4. Publish:"
    printf '    curl -X POST -H "Authorization: Bearer <TOKEN>" %s:publish\n' "$ITEM_URL"
  fi
  ok "DRY-RUN xong: build đã sẵn sàng, không gọi API."
  exit 0
fi

if ! confirm "Tiến hành upload lên Chrome Web Store?"; then
  die "Đã hủy theo yêu cầu."
fi

# --------------------------------------------- [6/6] upload & publish --------
step "[6/6] Upload & publish"

info "Lấy access token..."
TOKEN_JSON="$(curl -s "$TOKEN_URL" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN")"
ACCESS_TOKEN="$(json_get "$TOKEN_JSON" access_token)"
[ -n "$ACCESS_TOKEN" ] || die "Không lấy được access token: $TOKEN_JSON"
ok "Đã có access token."

info "Trạng thái item hiện tại..."
STATUS_JSON="$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$ITEM_URL:fetchStatus")"
dim "$STATUS_JSON"

info "Upload gói $NEW_VERSION..."
UPLOAD_JSON="$(curl -s -X POST -T "$ZIP_FILE" \
  -H "Authorization: Bearer $ACCESS_TOKEN" "$UPLOAD_URL")"
STATE="$(json_get "$UPLOAD_JSON" uploadState)"
[ -n "$STATE" ] || STATE="$(json_get "$UPLOAD_JSON" error code)"

# Chờ upload xử lý xong nếu đang IN_PROGRESS.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ "$STATE" = "IN_PROGRESS" ] || break
  sleep 3
  STATUS_JSON="$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$ITEM_URL:fetchStatus")"
  STATE="$(json_get "$STATUS_JSON" lastAsyncUploadState)"
  [ -n "$STATE" ] || STATE="$(json_get "$STATUS_JSON" uploadState)"
done

if [ "$STATE" != "SUCCESS" ]; then
  printf '\n' >&2
  warn "Upload thất bại (uploadState=$STATE)."
  warn "  • NOT_FOUND: item chưa tồn tại -> tạo thủ công tại https://chrome.google.com/webstore/devconsole/"
  warn "  • Version phải CAO HƠN bản đang publish (hiện tại $NEW_VERSION)."
  warn "  • Gói phải là .zip đúng định dạng, manifest_version 3, có icon 128x128."
  dim "$UPLOAD_JSON"
  die "Upload thất bại."
fi
ok "Upload thành công."

if [ "$NO_PUBLISH" = "1" ]; then
  info "Bỏ qua publish (--no-publish). Bản mới đang ở dạng nháp, publish sau trên Dashboard."
  exit 0
fi

info "Publish..."
PUBLISH_JSON="$(curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" "$ITEM_URL:publish")"
PSTATE="$(json_get "$PUBLISH_JSON" state)"
[ -n "$PSTATE" ] || PSTATE="$(json_get "$PUBLISH_JSON" error code)"

printf '\n'
ok "ĐÃ GỬI LÊN CHROME WEB STORE: version $NEW_VERSION (state=${PSTATE:-unknown})."
info "Bản phải qua review của Google rồi mới hiện public; theo dõi tại:"
info "  https://chrome.google.com/webstore/devconsole/"
[ -n "$(json_get "$PUBLISH_JSON" error message)" ] && dim "$PUBLISH_JSON" || true
