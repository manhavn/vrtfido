#!/usr/bin/env bash
set -euo pipefail

# Standalone local release builder for vrtfido.
# Outputs unpacked binaries to dist/<target>/ and upload-ready archives to
# dist/packages/. Override targets with TARGETS=target1,target2 ./build-cross.sh.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
export PATH="${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"

PROJECT_NAME="vrtfido"
BIN_NAME="vrtfido"
DEFAULT_TARGETS="x86_64-unknown-linux-gnu,x86_64-unknown-linux-musl,aarch64-unknown-linux-gnu,aarch64-unknown-linux-musl"
TARGETS_CSV="${TARGETS:-$DEFAULT_TARGETS}"

have() { command -v "$1" >/dev/null 2>&1; }
fail() { echo "error: $*" >&2; exit 1; }

# Check for cargo-zigbuild and zig; if absent, allow fallback to standard cargo if building host target only
USE_ZIG=1
if ! have cargo-zigbuild || ! have zig; then
  echo "warn: cargo-zigbuild or zig not found."
  echo "      For full cross-compilation, install them: cargo install cargo-zigbuild --locked && mise use -g zig"
  echo "      Attempting fallback to standard cargo..."
  USE_ZIG=0
fi

IFS=',' read -r -a BUILD_TARGETS <<< "$TARGETS_CSV"
mkdir -p "$ROOT/dist/packages"

built=()
for target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$target" | xargs)"
  [[ -n "$target" ]] || continue
  echo "==> Building $PROJECT_NAME for $target"
  rustup target add "$target" >/dev/null 2>&1 || true

  if [[ "$USE_ZIG" -eq 1 ]]; then
    cargo zigbuild --release --target "$target"
  else
    cargo build --release --target "$target"
  fi

  ext=""
  [[ "$target" == *windows* ]] && ext=".exe"
  src="$ROOT/target/$target/release/${BIN_NAME}${ext}"
  [[ -f "$src" ]] || fail "binary not found: $src"

  target_dist="$ROOT/dist/$target"
  mkdir -p "$target_dist"
  cp -f "$src" "$target_dist/"
  archive="$ROOT/dist/packages/${PROJECT_NAME}-${target}.tar.gz"
  tar -C "$target_dist" -czf "$archive" .
  (cd "$ROOT/dist/packages" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
  built+=("$target")
  echo "    $archive"
done

echo "Built: ${built[*]}"
echo "Upload-ready files: $ROOT/dist/packages/"
