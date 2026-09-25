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

# 1. Automatically check and install zig if missing
if ! have zig; then
  echo "[SETUP] 'zig' not found. Installing automatically..."
  if have mise; then
    echo "[SETUP] Installing zig@0.13.0 via mise..."
    mise use -g zig@0.13.0
    export PATH="${HOME}/.local/share/mise/shims:${PATH}"
  elif have brew; then
    echo "[SETUP] Installing zig via Homebrew..."
    brew install zig
  elif have snap; then
    echo "[SETUP] Installing zig via snap..."
    sudo snap install zig --classic --beta || true
  fi

  # Fallback to direct official binary download if still missing
  if ! have zig; then
    ARCH="$(uname -m)"
    echo "[SETUP] Downloading official zig 0.13.0 binary for $ARCH..."
    mkdir -p "$HOME/.local/bin" "$HOME/.local/opt"
    curl -sSL "https://ziglang.org/download/0.13.0/zig-linux-${ARCH}-0.13.0.tar.xz" | tar -xJ -C "$HOME/.local/opt/"
    ln -sf "$HOME/.local/opt/zig-linux-${ARCH}-0.13.0/zig" "$HOME/.local/bin/zig"
    export PATH="${HOME}/.local/bin:${PATH}"
  fi

  have zig || { echo "error: Failed to install zig automatically. Please install manually." >&2; exit 1; }
  echo "[SETUP] [+] Successfully installed zig: $(zig version)"
else
  echo "[SETUP] [+] Found zig: $(zig version)"
fi

# 2. Automatically check and install cargo-zigbuild if missing
if ! have cargo-zigbuild; then
  echo "[SETUP] 'cargo-zigbuild' not found. Installing automatically..."
  if curl --proto '=https' --tlsv1.2 -LsSf https://github.com/rust-cross/cargo-zigbuild/releases/latest/download/cargo-zigbuild-installer.sh | sh; then
    export PATH="${HOME}/.cargo/bin:${PATH}"
  else
    echo "[SETUP] Fallback compiling cargo-zigbuild via cargo..."
    cargo install cargo-zigbuild --locked
  fi

  have cargo-zigbuild || { echo "error: Failed to install cargo-zigbuild automatically." >&2; exit 1; }
  echo "[SETUP] [+] Successfully installed cargo-zigbuild: $(cargo-zigbuild --version)"
else
  echo "[SETUP] [+] Found cargo-zigbuild: $(cargo-zigbuild --version)"
fi

IFS=',' read -r -a BUILD_TARGETS <<< "$TARGETS_CSV"
mkdir -p "$ROOT/dist/packages"

# rustc links every artifact with -Wl,-O1 and the lld that zig ships deprecates that value, so each
# cross build used to print "ignoring deprecated linker optimization setting '1'" through the
# linker_messages lint. The notice describes the toolchain, not this crate, so the lint is allowed
# for these builds only - a plain `cargo build` / `cargo test` keeps it enabled.
CROSS_RUSTFLAGS="${RUSTFLAGS:-}"

echo ""
echo "Targets to build: ${BUILD_TARGETS[*]}"
echo "------------------------------------------------------------"

built=()
for target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$target" | xargs)"
  [[ -n "$target" ]] || continue
  echo "==> Building $PROJECT_NAME for target: $target"

  # A musl build additionally drops `cdylib` (only the Android JNI library needs that crate type and
  # Cargo cannot scope [lib] crate-type per target), and that notice carries no lint name of its
  # own. Nothing in this crate is gated on target_env, and the host build plus the GNU targets lint
  # every line, so the warnings group is allowed for the musl packaging builds alone.
  case "$target" in
    *musl*) export RUSTFLAGS="$CROSS_RUSTFLAGS -A warnings" ;;
    *) export RUSTFLAGS="$CROSS_RUSTFLAGS -A linker_messages" ;;
  esac

  # Automatically add target to rustup if missing
  rustup target add "$target" >/dev/null 2>&1 || true

  cargo zigbuild --release --target "$target"

  ext=""
  [[ "$target" == *windows* ]] && ext=".exe"
  src="$ROOT/target/$target/release/${BIN_NAME}${ext}"
  [[ -f "$src" ]] || { echo "error: Output binary not found at: $src" >&2; exit 1; }

  target_dist="$ROOT/dist/$target"
  mkdir -p "$target_dist"
  cp -f "$src" "$target_dist/"

  # Package from a private staging directory and publish atomically: packaging straight out of
  # dist/<target> raced with the linker rewriting the binary and produced corrupt archives.
  archive="$ROOT/dist/packages/${PROJECT_NAME}-${target}.tar.gz"
  stage_dir="$(mktemp -d)"
  cp -f "$target_dist/${BIN_NAME}${ext}" "$stage_dir/"
  tar -C "$stage_dir" -czf "${archive}.tmp" .
  mv -f "${archive}.tmp" "$archive"
  rm -rf "$stage_dir"
  # The checksum is written only after the archive is final.
  (cd "$ROOT/dist/packages" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
  built+=("$target")
  echo "    [+] Package completed: $archive"
done

echo ""
echo "============================================================"
echo "     ALL PACKAGES BUILT AND ARCHIVED SUCCESSFULLY           "
echo "============================================================"
echo "Built architectures: ${built[*]}"
echo "GitHub Releases upload directory: $ROOT/dist/packages/"
ls -lh "$ROOT/dist/packages/"
