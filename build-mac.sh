#!/usr/bin/env bash
set -euo pipefail

# Standalone release builder for vrtfido on macOS: the one script that has to run on a Mac, since
# the Apple SDK may not be used off Apple hardware. build-cross.sh builds the Linux and Windows
# packages on any host and refuses the Apple targets with a pointer here.
# Builds both Apple Silicon (aarch64-apple-darwin) and Intel (x86_64-apple-darwin),
# stages the binaries, compresses to .tar.gz, generates .sha256 checksums,
# and moves the final artifacts to releases/.
#
# Usage:
#   ./build-mac.sh
#   TARGETS=aarch64-apple-darwin ./build-mac.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/share/mise/shims:${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
if command -v mise >/dev/null 2>&1; then
  eval "$(mise activate bash --shims 2>/dev/null || true)"
fi

PROJECT_NAME="vrtfido"
BIN_NAME="vrtfido"
GUI_BIN_NAME="vrtfido-gui"
DEFAULT_TARGETS="aarch64-apple-darwin,x86_64-apple-darwin"
TARGETS_CSV="${TARGETS:-$DEFAULT_TARGETS}"

have() { command -v "$1" >/dev/null 2>&1; }

echo "============================================================"
echo "          vrtfido - macOS Release Builder                   "
echo "============================================================"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: the macOS packages are built on a Mac, because they need the Apple SDK." >&2
  echo "       On this host, build the packages it can produce instead: ./build-cross.sh" >&2
  exit 1
fi

# The Apple command line tools carry clang and the SDK headers, and `xcode-select --install` is the
# only way to get them - a GUI installer, so the script starts it and stops there; the next run
# finds the tools in place. Without them the build fails much later, in the linker.
if ! xcode-select -p >/dev/null 2>&1; then
  echo "[SETUP] The Apple command line tools are missing: no clang, no SDK headers."
  echo "[SETUP] Starting the installer; finish it and run this script again."
  xcode-select --install 2>/dev/null || true
  exit 1
fi

if ! have cargo; then
  echo "error: 'cargo' is required but not found in PATH." >&2
  exit 1
fi

IFS=',' read -r -a BUILD_TARGETS <<< "$TARGETS_CSV"

RELEASES="$ROOT/releases"
mkdir -p "$ROOT/dist/packages" "$RELEASES"
for target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$target" | xargs)"
  [[ -n "$target" ]] || continue
  rm -f "$RELEASES/${PROJECT_NAME}-${target}.tar.gz" "$RELEASES/${PROJECT_NAME}-${target}.tar.gz.sha256"
done

echo ""
echo "Targets to build: ${BUILD_TARGETS[*]}"
echo "------------------------------------------------------------"

compute_sha256() {
  local file="$1"
  if have sha256sum; then
    sha256sum "$file"
  elif have shasum; then
    shasum -a 256 "$file"
  else
    echo "error: neither sha256sum nor shasum found." >&2
    exit 1
  fi
}

built=()
for target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$target" | xargs)"
  [[ -n "$target" ]] || continue
  echo "==> Building $PROJECT_NAME for macOS target: $target"

  # Automatically install rustup target if missing
  if have rustup; then
    rustup target add "$target" >/dev/null 2>&1 || true
  fi

  # Build daemon and GUI prompt window
  cargo build --release --features gui --target "$target"

  src="$ROOT/target/$target/release/${BIN_NAME}"
  gui_src="$ROOT/target/$target/release/${GUI_BIN_NAME}"

  [[ -f "$src" ]] || { echo "error: Output binary not found at: $src" >&2; exit 1; }
  [[ -f "$gui_src" ]] || { echo "error: GUI binary not found at: $gui_src" >&2; exit 1; }

  target_dist="$ROOT/dist/$target"
  mkdir -p "$target_dist"
  cp -f "$src" "$gui_src" "$target_dist/"

  archive="$ROOT/dist/packages/${PROJECT_NAME}-${target}.tar.gz"
  # The template is explicit because BSD/macOS `mktemp` refuses to run without one.
  stage_dir="$(mktemp -d "${TMPDIR:-/tmp}/vrtfido-package.XXXXXX")"
  cp -f "$src" "$gui_src" "$stage_dir/"
  tar -C "$stage_dir" -czf "${archive}.tmp" .
  mv -f "${archive}.tmp" "$archive"
  rm -rf "$stage_dir"

  (
    cd "$ROOT/dist/packages"
    compute_sha256 "$(basename "$archive")" > "$(basename "$archive").sha256"
  )
  mv -f "$archive" "${archive}.sha256" "$RELEASES/"
  built+=("$target")
  echo "    [+] Package completed: $RELEASES/$(basename "$archive")"
done

echo ""
echo "============================================================"
echo "     ALL macOS PACKAGES BUILT AND ARCHIVED SUCCESSFULLY     "
echo "============================================================"
echo "Built architectures: ${built[*]}"
echo "Publish-ready artifacts: $RELEASES/"
ls -lh "$RELEASES/"
