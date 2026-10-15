#!/usr/bin/env bash
#
# publish-firefox.sh — Build -> kiểm tra (mozilla/addons-linter) -> ký AMO -> public
# extension Firefox. Chạy 1 lệnh, sau đó script hỏi lần lượt từng tham số.
#
#   ./publish-firefox.sh                     # tương tác đầy đủ (hỏi từng bước)
#   ./publish-firefox.sh --dry-run           # chạy hết luồng nhưng KHÔNG gọi AMO
#   ./publish-firefox.sh --channel unlisted --version 0.4.0 --yes
#
# Tùy chọn:
#   --channel listed|unlisted  listed = public trên addons.mozilla.org (mặc định),
#                              unlisted = .xpi đã ký để tự host
#   --version X.Y.Z            Đặt version trước khi build (bỏ qua bước hỏi)
#   --dry-run                  Chỉ build + lint, in lệnh ký thay vì gọi AMO
#   --no-build                 Dùng dist/firefox có sẵn, bỏ qua build/lint
#   --credentials FILE         File nguồn chứa WEB_EXT_API_KEY / WEB_EXT_API_SECRET
#   --license SLUG             (listed) Giấy phép AMO; mặc định MIT (MIT, MPL-2.0, GPL-3.0, ...)
#   --amo-metadata FILE        (listed) File metadata JSON đầy đủ (categories, summary, license, ...)
#   --wait                     (listed) Chờ AMO duyệt xong mới thoát
#   -y, --yes                  Không hỏi xác nhận
#   -h, --help
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$SCRIPT_DIR/extension"
MANIFEST="$EXT_DIR/manifest.json"
DIST_DIR="$SCRIPT_DIR/dist"
FIREFOX_DIST="$DIST_DIR/firefox"
ZIP_FILE="$SCRIPT_DIR/releases/vrtfido-firefox.zip"
SIGNED_XPI="$DIST_DIR/vrtfido-firefox-signed.xpi"
ARTIFACTS_DIR="$SCRIPT_DIR/web-ext-artifacts"
DEFAULT_CRED_FILE="${VRTFIDO_AMO_CREDENTIALS:-$HOME/.config/vrtfido/amo.env}"

CHANNEL=""
NEW_VERSION=""
DRY_RUN=0
NO_BUILD=0
ASSUME_YES=0
WAIT_APPROVAL=0
CRED_FILE=""
AMO_METADATA_FILE=""
AMO_METADATA_WRITE=0
LICENSE="MIT"

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
  is_tty || die "Cần nhập bí mật cho: $prompt — hãy đặt WEB_EXT_API_KEY/WEB_EXT_API_SECRET."
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

get_version() {
  python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["version"])' "$MANIFEST"
}

valid_version() { [[ "$1" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]]; }

bump_version() { # bump_version "0.4.0" patch|minor|major
  python3 - "$1" "$2" <<'PY'
import sys
cur, mode = sys.argv[1], sys.argv[2]
p = [int(x) for x in cur.split('.')]
while len(p) < 3:
    p.append(0)
if mode == 'patch':
    p[2] += 1
elif mode == 'minor':
    p[1] += 1; p[2] = 0
elif mode == 'major':
    p[0] += 1; p[1] = 0; p[2] = 0
print(f"{p[0]}.{p[1]}.{p[2]}")
PY
}

set_version() { # set_version "0.4.0" — chỉ sửa đúng dòng "version"
  python3 - "$MANIFEST" "$1" <<'PY'
import re, sys
path, new = sys.argv[1], sys.argv[2]
src = open(path, encoding='utf-8').read()
out, n = re.subn(r'("version"\s*:\s*")[^"]*(")', lambda m: m.group(1) + new + m.group(2), src, count=1)
if n != 1:
    sys.exit("Không tìm thấy khóa \"version\" trong manifest")
open(path, 'w', encoding='utf-8').write(out)
PY
}

amo_metadata_prepare() { # $1=path $2=license $3=write|verify|parse -> in ra license đang dùng
  python3 - "$1" "$2" "$3" <<'PY'
import json, os, sys

path, license_, mode = sys.argv[1], sys.argv[2], sys.argv[3]
if mode not in ("write", "verify", "parse"):
    sys.exit(f"✗ mode không hợp lệ: {mode}")

if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        sys.exit(f"✗ Không đọc được {path}: {exc}")
    if not isinstance(data, dict):
        sys.exit(f"✗ {path} phải là một JSON object")
else:
    if mode != "write":
        sys.exit(f"✗ Không tìm thấy metadata: {path}")
    data = {}

version = data.get("version")
if not isinstance(version, dict):
    version = {}
    data["version"] = version

if mode == "write":
    version["license"] = license_
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
elif not (version.get("license") or version.get("custom_license")):
    if mode == "verify":
        sys.exit(f'✗ {path} thiếu "version.license" (hoặc "version.custom_license") — AMO bắt buộc cho kênh listed.')

print(version.get("license") or ("custom_license" if version.get("custom_license") else "?"))
PY
}

usage() {
  cat <<'EOF'
publish-firefox.sh — Build -> kiểm tra (mozilla/addons-linter) -> ký AMO -> public extension Firefox.
Chạy 1 lệnh, script hỏi lần lượt từng tham số.

  ./publish-firefox.sh                     # tương tác đầy đủ (hỏi từng bước)
  ./publish-firefox.sh --dry-run           # chạy hết luồng nhưng KHÔNG gọi AMO
  ./publish-firefox.sh --channel unlisted --version 0.4.0 --yes

Tùy chọn:
  --channel listed|unlisted  listed = public trên addons.mozilla.org (mặc định),
                             unlisted = .xpi đã ký để tự host
  --version X.Y.Z            Đặt version trước khi build (bỏ qua bước hỏi)
  --dry-run                  Chỉ build + lint, in lệnh ký thay vì gọi AMO
  --no-build                 Dùng dist/firefox có sẵn, bỏ qua build/lint
  --credentials FILE         File nguồn chứa WEB_EXT_API_KEY / WEB_EXT_API_SECRET
  --license SLUG             (listed) Giấy phép AMO; mặc định MIT (MIT, MPL-2.0, GPL-3.0, ...)
  --amo-metadata FILE        (listed) File metadata JSON đầy đủ (categories, summary, license, ...)
  --wait                     (listed) Chờ AMO duyệt xong mới thoát
  -y, --yes                  Không hỏi xác nhận
  -h, --help
EOF
}

# ------------------------------------------------------------------ args ----
while [ $# -gt 0 ]; do
  case "$1" in
    --channel)     CHANNEL="${2:-}"; shift 2 ;;
    --listed)      CHANNEL="listed"; shift ;;
    --unlisted)    CHANNEL="unlisted"; shift ;;
    --version)     NEW_VERSION="${2:-}"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --no-build)    NO_BUILD=1; shift ;;
    --credentials) CRED_FILE="${2:-}"; shift 2 ;;
    --license)     LICENSE="${2:-}"; shift 2 ;;
    --amo-metadata) AMO_METADATA_FILE="${2:-}"; shift 2 ;;
    --wait)        WAIT_APPROVAL=1; shift ;;
    -y|--yes)      ASSUME_YES=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             die "Tham số không hợp lệ: $1 (xem --help)" ;;
  esac
done

[ -n "$CHANNEL" ] && [[ "$CHANNEL" =~ ^(listed|unlisted)$ ]] || [ -z "$CHANNEL" ] \
  || die "--channel chỉ nhận 'listed' hoặc 'unlisted'."

printf '%s%s\n' "$c_bold" "=========================================="
printf '   VrtFido — Publish Firefox Extension    \n'
printf '%s' "$c_reset"
printf '%s\n' "=========================================="

# --------------------------------------------------- [1/6] môi trường ---------
step "[1/6] Kiểm tra môi trường"
need_cmd python3
need_cmd node
need_cmd npx
[ -f "$MANIFEST" ] || die "Không thấy $MANIFEST — chạy script trong thư mục repo."
[ -d "$EXT_DIR/icons" ] || die "Thiếu extension/icons — repo chưa đầy đủ."
CURRENT_VERSION="$(get_version)"
ok "node $(node -v), npx $(npx -v 2>/dev/null || echo '?'), python3 OK"
ok "Version hiện tại trong manifest: ${c_bold}$CURRENT_VERSION${c_reset}"
[ "$DRY_RUN" = "1" ] && warn "DRY-RUN: sẽ không gọi AMO, chỉ build + lint."

# ------------------------------------------- [2/6] kênh + version -------------
step "[2/6] Kênh phát hành & version"

if [ -z "$CHANNEL" ]; then
  if [ "$ASSUME_YES" = "1" ]; then
    CHANNEL="listed"
    dim "Mặc định (--yes): listed"
  else
    info "Chọn kênh ký:"
    info "  ${c_bold}1)${c_reset} listed   — public trên addons.mozilla.org (hiện trong store, duyệt thủ công)"
    info "  ${c_bold}2)${c_reset} unlisted — chỉ ký, trả .xpi để bạn tự host (không hiện trên store)"
    ans="$(ask 'Nhập 1 hoặc 2' '1')"
    case "$ans" in
      2) CHANNEL="unlisted" ;;
      *) CHANNEL="listed" ;;
    esac
  fi
fi
ok "Kênh: ${c_bold}$CHANNEL${c_reset}"

if [ -n "$NEW_VERSION" ]; then
  valid_version "$NEW_VERSION" || die "Version không hợp lệ: $NEW_VERSION (dạng X.Y hoặc X.Y.Z)."
elif [ "$ASSUME_YES" = "1" ] || ! is_tty; then
  NEW_VERSION="$CURRENT_VERSION"
  dim "Giữ nguyên version $NEW_VERSION"
else
  info "Version hiện tại: ${c_bold}$CURRENT_VERSION${c_reset}"
  info "  ${c_bold}k${c_reset}) giữ nguyên   ${c_bold}p${c_reset}) tăng patch   ${c_bold}m${c_reset}) tăng minor   ${c_bold}M${c_reset}) tăng major   ${c_bold}n${c_reset}) tự nhập"
  case "$(ask 'Chọn' 'k')" in
    p|P) NEW_VERSION="$(bump_version "$CURRENT_VERSION" patch)" ;;
    m)   NEW_VERSION="$(bump_version "$CURRENT_VERSION" minor)" ;;
    M)   NEW_VERSION="$(bump_version "$CURRENT_VERSION" major)" ;;
    n|N) NEW_VERSION="$(ask 'Nhập version mới')"; valid_version "$NEW_VERSION" || die "Version không hợp lệ: $NEW_VERSION" ;;
    *)   NEW_VERSION="$CURRENT_VERSION" ;;
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

# ------------------------------------------------- [3/6] build + lint ---------
step "[3/6] Build Firefox + addons-linter"
if [ "$NO_BUILD" = "1" ]; then
  warn "Bỏ qua build (--no-build). Yêu cầu dist/firefox đã có sẵn."
  [ -f "$FIREFOX_DIST/manifest.json" ] || die "Không thấy $FIREFOX_DIST/manifest.json."
else
  info "Chạy build-firefox.sh (tự chạy addons-linter, dừng nếu có lỗi)..."
  bash "$SCRIPT_DIR/build-firefox.sh"
  ok "Build + lint hoàn tất: $ZIP_FILE"
fi

# ------------------------------------------------ [4/6] thông tin AMO ---------
step "[4/6] Thông tin AMO"

AMO_METADATA_ARG=()
LICENSE_USED=""
if [ "$CHANNEL" = "listed" ]; then
  if [ -z "$AMO_METADATA_FILE" ]; then
    AMO_METADATA_FILE="$SCRIPT_DIR/amo-metadata.json"
    AMO_METADATA_WRITE=1
  else
    AMO_METADATA_WRITE=0
    [ -f "$AMO_METADATA_FILE" ] || die "Không thấy file metadata: $AMO_METADATA_FILE"
  fi

  if [ "$AMO_METADATA_WRITE" = "1" ] && is_tty && [ "$ASSUME_YES" != "1" ]; then
    info "AMO bắt buộc khai báo giấy phép cho bản listed."
    info "Slug hợp lệ, ví dụ: MIT, MPL-2.0, GPL-3.0, Apache-2.0, BSD-2-Clause"
    LICENSE="$(ask 'Giấy phép (license slug)' "$LICENSE")"
  fi
  [ -n "$LICENSE" ] || die "License không được để trống."

  if [ "$AMO_METADATA_WRITE" = "1" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      LICENSE_USED="$LICENSE"
      # Kiểm tra file đọc được (nếu có), nhưng không ghi trong dry-run.
      amo_metadata_prepare "$AMO_METADATA_FILE" "$LICENSE" parse >/dev/null \
        || die "Chuẩn bị metadata AMO thất bại."
      dim "DRY-RUN: sẽ đặt license=$LICENSE trong $AMO_METADATA_FILE"
    else
      LICENSE_USED="$(amo_metadata_prepare "$AMO_METADATA_FILE" "$LICENSE" write)" \
        || die "Chuẩn bị metadata AMO thất bại."
    fi
  else
    LICENSE_USED="$(amo_metadata_prepare "$AMO_METADATA_FILE" "$LICENSE" verify)" \
      || die "Chuẩn bị metadata AMO thất bại."
  fi
  AMO_METADATA_ARG=(--amo-metadata "$AMO_METADATA_FILE")
  ok "Metadata : $AMO_METADATA_FILE (license=$LICENSE_USED)"
else
  dim "Kênh unlisted: không cần metadata AMO."
fi

KEY="${WEB_EXT_API_KEY:-}"
SECRET="${WEB_EXT_API_SECRET:-}"

if [ "$DRY_RUN" != "1" ]; then
  if [ -z "$KEY" ] || [ -z "$SECRET" ]; then
    CF="$CRED_FILE"
    [ -z "$CF" ] && [ -f "$DEFAULT_CRED_FILE" ] && CF="$DEFAULT_CRED_FILE"
    if [ -n "$CF" ] && [ -f "$CF" ]; then
      # shellcheck disable=SC1090
      . "$CF"
      KEY="${WEB_EXT_API_KEY:-}"; SECRET="${WEB_EXT_API_SECRET:-}"
      [ -n "$KEY" ] && dim "Đã nạp API key từ $CF"
    fi
  fi
  if [ -z "$KEY" ] || [ -z "$SECRET" ]; then
    info "Lấy API key/secret tại: https://addons.mozilla.org/developers/addon/api/key/"
    KEY="$(ask_secret 'WEB_EXT_API_KEY')"
    SECRET="$(ask_secret 'WEB_EXT_API_SECRET')"
    [ -n "$KEY" ] && [ -n "$SECRET" ] || die "API key/secret không được để trống."
    if is_tty && confirm "Lưu key vào $DEFAULT_CRED_FILE (chmod 600) để lần sau không phải nhập?"; then
      mkdir -p "$(dirname "$DEFAULT_CRED_FILE")"
      umask 077
      { printf 'WEB_EXT_API_KEY=%q\n' "$KEY"; printf 'WEB_EXT_API_SECRET=%q\n' "$SECRET"; } > "$DEFAULT_CRED_FILE"
      chmod 600 "$DEFAULT_CRED_FILE"
      ok "Đã lưu: $DEFAULT_CRED_FILE"
    fi
  else
    ok "Đã có API key/secret (từ biến môi trường / file credentials)."
  fi
else
  dim "DRY-RUN: bỏ qua API key."
fi

# ------------------------------------------------- [5/6] xác nhận -------------
step "[5/6] Xác nhận"
info "Kênh          : ${c_bold}$CHANNEL${c_reset}"
info "Version       : ${c_bold}$NEW_VERSION${c_reset}"
info "Nguồn         : $FIREFOX_DIST"
info "Artifacts     : $ARTIFACTS_DIR"
if [ "$CHANNEL" = "listed" ]; then
  info "License       : ${c_bold}$LICENSE_USED${c_reset}"
  info "Metadata      : $AMO_METADATA_FILE"
fi
[ "$DRY_RUN" = "1" ] && info "Chế độ        : ${c_bold}DRY-RUN${c_reset}"
[ "$CHANNEL" = "listed" ] \
  && info "Lưu ý         : listed cần add-on đã tồn tại trên AMO; bản đầu còn cần categories + summary trong metadata."

if [ "$DRY_RUN" != "1" ] && ! confirm "Tiến hành ký với AMO?"; then
  die "Đã hủy theo yêu cầu."
fi

# --------------------------------------------- [6/6] ký & public --------------
step "[6/6] Ký và phát hành"

SIGN_CMD=(npx --yes web-ext@latest sign
  --source-dir "$FIREFOX_DIST"
  --artifacts-dir "$ARTIFACTS_DIR"
  --channel "$CHANNEL"
  --api-key "$KEY"
  --api-secret "$SECRET"
  ${AMO_METADATA_ARG[@]+"${AMO_METADATA_ARG[@]}"})
# listed: mặc định submit rồi trả về, không chờ duyệt thủ công (tránh treo).
if [ "$CHANNEL" = "listed" ] && [ "$WAIT_APPROVAL" != "1" ]; then
  SIGN_CMD+=(--approval-timeout 0)
fi

if [ "$DRY_RUN" = "1" ]; then
  warn "DRY-RUN: lệnh sẽ chạy là:"
  printf '    %s' "${SIGN_CMD[0]}"
  for a in "${SIGN_CMD[@]:1}"; do
    case "$a" in
      "$KEY"|"$SECRET") printf ' %s' "<API-KEY-SECRET>" ;;
      *) printf ' %q' "$a" ;;
    esac
  done
  printf '\n'
  ok "DRY-RUN xong: build + lint đã pass, sẵn sàng public."
  exit 0
fi

mkdir -p "$ARTIFACTS_DIR"
if ! "${SIGN_CMD[@]}"; then
  if [ "$CHANNEL" = "listed" ]; then
    printf '\n' >&2
    warn "Ký listed thất bại. Nguyên nhân thường gặp:"
    warn "  • Thiếu license/name/summary/categories (bắt buộc cho bản listed đầu tiên) -> sửa $AMO_METADATA_FILE:"
    warn "      {\"name\": {\"en-US\": \"...\"}, \"summary\": {\"en-US\": \"...\"}, \"categories\": {\"firefox\": [\"privacy-security\"], \"android\": [\"privacy-security\"]}, \"version\": {\"license\": \"MIT\"}}"
    warn "  • Add-on ID 'vrtfido@local' chưa có listing trên AMO -> tạo tại:"
    warn "    https://addons.mozilla.org/developers/addon/submit/"
    warn "  • Version $NEW_VERSION đã tồn tại -> tăng version rồi chạy lại."
    warn "  • API key/secret sai hoặc thiếu quyền."
  fi
  die "Ký thất bại."
fi

XPI="$(ls -t "$ARTIFACTS_DIR"/*.xpi 2>/dev/null | head -1 || true)"
if [ -z "$XPI" ]; then
  [ "$CHANNEL" = "listed" ] && ok "Đã submit lên AMO (đang chờ duyệt) — chưa có .xpi ngay." && exit 0
  die "Không tìm thấy .xpi trong $ARTIFACTS_DIR."
fi

cp -f "$XPI" "$SIGNED_XPI"
ok "Bản đã ký: $XPI"
ok "Bản sao   : $SIGNED_XPI"

if [ "$CHANNEL" = "listed" ]; then
  printf '\n'
  ok "ĐÃ PUBLIC: bản $NEW_VERSION đã gửi lên addons.mozilla.org."
  info "Theo dõi duyệt: https://addons.mozilla.org/developers/addons/"
else
  info "Kênh unlisted: tệp đã ký không tự lên mạng — cần tự host."
  if command -v gh >/dev/null 2>&1 && git -C "$SCRIPT_DIR" remote get-url origin >/dev/null 2>&1; then
    TAG="v$NEW_VERSION"
    if confirm "Đăng $SIGNED_XPI lên GitHub Release '$TAG' bằng gh?"; then
      if git -C "$SCRIPT_DIR" rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
        warn "Tag $TAG đã tồn tại — bỏ qua bước tạo release."
      else
        gh release create "$TAG" "$SIGNED_XPI" \
          --title "VrtFido Extension v$NEW_VERSION" \
          --notes "Firefox extension (signed) v$NEW_VERSION." \
          && ok "ĐÃ PUBLIC: GitHub Release $TAG"
      fi
    fi
  else
    warn "Không có 'gh' (GitHub CLI) — tự đăng tệp đã ký lên nơi public, ví dụ:"
    dim "gh release create v$NEW_VERSION \"$SIGNED_XPI\" --title \"VrtFido Extension v$NEW_VERSION\""
    info "Nhớ thêm browser_specific_settings.gecko.update_url nếu muốn auto-update."
  fi
fi
