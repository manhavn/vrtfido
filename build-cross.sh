#!/usr/bin/env bash
set -euo pipefail

# Standalone local release builder for vrtfido.
# Automatically installs missing tools (zig, cargo-zigbuild, rust targets)
# and outputs upload-ready archives to dist/packages/.
#
# Usage:
#   ./build-cross.sh
#   TARGETS=x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu ./build-cross.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/share/mise/shims:${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
if command -v mise >/dev/null 2>&1; then
  eval "$(mise activate bash --shims 2>/dev/null || true)"
fi

PROJECT_NAME="vrtfido"
BIN_NAME="vrtfido"
DEFAULT_TARGETS="x86_64-unknown-linux-gnu,x86_64-unknown-linux-musl,aarch64-unknown-linux-gnu,aarch64-unknown-linux-musl"
TARGETS_CSV="${TARGETS:-$DEFAULT_TARGETS}"

have() { command -v "$1" >/dev/null 2>&1; }

echo "============================================================"
echo "      vrtfido - Local Cross-Platform Release Builder        "
echo "============================================================"

# 1. Tự động kiểm tra và cài đặt zig nếu thiếu
if ! have zig; then
  echo "[SETUP] Không tìm thấy 'zig'. Đang tự động cài đặt..."
  if have mise; then
    echo "[SETUP] Cài đặt zig@0.13.0 thông qua mise..."
    mise use -g zig@0.13.0
    export PATH="${HOME}/.local/share/mise/shims:${PATH}"
  elif have brew; then
    echo "[SETUP] Cài đặt zig thông qua Homebrew..."
    brew install zig
  elif have snap; then
    echo "[SETUP] Cài đặt zig thông qua snap..."
    sudo snap install zig --classic --beta || true
  fi

  # Fallback tải trực tiếp binary chính thức nếu vẫn chưa có
  if ! have zig; then
    ARCH="$(uname -m)"
    echo "[SETUP] Tải trực tiếp binary chính thức zig 0.13.0 cho $ARCH..."
    mkdir -p "$HOME/.local/bin" "$HOME/.local/opt"
    curl -sSL "https://ziglang.org/download/0.13.0/zig-linux-${ARCH}-0.13.0.tar.xz" | tar -xJ -C "$HOME/.local/opt/"
    ln -sf "$HOME/.local/opt/zig-linux-${ARCH}-0.13.0/zig" "$HOME/.local/bin/zig"
    export PATH="${HOME}/.local/bin:${PATH}"
  fi

  have zig || { echo "error: Không thể cài đặt zig tự động. Vui lòng cài đặt thủ công." >&2; exit 1; }
  echo "[SETUP] [+] Đã cài đặt zig thành công: $(zig version)"
else
  echo "[SETUP] [+] Đã tìm thấy zig: $(zig version)"
fi

# 2. Tự động kiểm tra và cài đặt cargo-zigbuild nếu thiếu
if ! have cargo-zigbuild; then
  echo "[SETUP] Không tìm thấy 'cargo-zigbuild'. Đang tự động cài đặt..."
  if curl --proto '=https' --tlsv1.2 -LsSf https://github.com/rust-cross/cargo-zigbuild/releases/latest/download/cargo-zigbuild-installer.sh | sh; then
    export PATH="${HOME}/.cargo/bin:${PATH}"
  else
    echo "[SETUP] Fallback biên dịch cargo-zigbuild qua cargo..."
    cargo install cargo-zigbuild --locked
  fi

  have cargo-zigbuild || { echo "error: Không thể cài đặt cargo-zigbuild tự động." >&2; exit 1; }
  echo "[SETUP] [+] Đã cài đặt cargo-zigbuild thành công: $(cargo-zigbuild --version)"
else
  echo "[SETUP] [+] Đã tìm thấy cargo-zigbuild: $(cargo-zigbuild --version)"
fi

IFS=',' read -r -a BUILD_TARGETS <<< "$TARGETS_CSV"
mkdir -p "$ROOT/dist/packages"

echo ""
echo "Các mục tiêu cần biên dịch: ${BUILD_TARGETS[*]}"
echo "------------------------------------------------------------"

built=()
for target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$target" | xargs)"
  [[ -n "$target" ]] || continue
  echo "==> Đang biên dịch $PROJECT_NAME cho target: $target"

  # Tự động thêm target vào rustup nếu thiếu
  rustup target add "$target" >/dev/null 2>&1 || true

  cargo zigbuild --release --target "$target"

  ext=""
  [[ "$target" == *windows* ]] && ext=".exe"
  src="$ROOT/target/$target/release/${BIN_NAME}${ext}"
  [[ -f "$src" ]] || { echo "error: Không tìm thấy binary đầu ra tại: $src" >&2; exit 1; }

  target_dist="$ROOT/dist/$target"
  mkdir -p "$target_dist"
  cp -f "$src" "$target_dist/"
  archive="$ROOT/dist/packages/${PROJECT_NAME}-${target}.tar.gz"
  tar -C "$target_dist" -czf "$archive" .
  (cd "$ROOT/dist/packages" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
  built+=("$target")
  echo "    [+] Hoàn thành gói: $archive"
done

echo ""
echo "============================================================"
echo "  TẤT CẢ CÁC GÓI ĐÃ ĐƯỢC BIÊN DỊCH VÀ ĐÓNG GÓI THÀNH CÔNG   "
echo "============================================================"
echo "Các kiến trúc đã build: ${built[*]}"
echo "Thư mục chứa các file tải lên GitHub Releases: $ROOT/dist/packages/"
ls -lh "$ROOT/dist/packages/"
