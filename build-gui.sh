#!/usr/bin/env bash
set -euo pipefail

# Standalone release builder for vrtfido with native desktop GUI (GTK3).
# Builds upload-ready packages for GitHub Releases and mise installation:
#   - vrtfido-x86_64-unknown-linux-gnu.tar.gz (.sha256)
#   - vrtfido-aarch64-unknown-linux-gnu.tar.gz (.sha256)
#
# Usage:
#   ./build-gui.sh
#   TARGETS=x86_64-unknown-linux-gnu ./build-gui.sh
#   TARGETS=aarch64-unknown-linux-gnu ./build-gui.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/share/mise/shims:${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
if command -v mise >/dev/null 2>&1; then
  eval "$(mise activate bash --shims 2>/dev/null || true)"
fi

PROJECT_NAME="vrtfido"
BIN_NAME="vrtfido"
DEFAULT_TARGETS="x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu"
TARGETS_CSV="${TARGETS:-$DEFAULT_TARGETS}"

have() { command -v "$1" >/dev/null 2>&1; }

echo "============================================================"
echo "    vrtfido - Native GUI Release Builder (GTK3 Desktop)     "
echo "============================================================"

# Detect container engine for cross-compiling GTK (podman or docker)
CONTAINER_ENGINE=""
if have podman; then
  CONTAINER_ENGINE="podman"
elif have docker; then
  CONTAINER_ENGINE="docker"
fi

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64|amd64) HOST_TARGET="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) HOST_TARGET="aarch64-unknown-linux-gnu" ;;
  *) HOST_TARGET="unknown" ;;
esac

IFS=',' read -r -a BUILD_TARGETS <<< "$TARGETS_CSV"
mkdir -p "$ROOT/dist/packages"

# Ensure host Rust target is available
ensure_rust_target() {
  local target="$1"
  rustup target add "$target" >/dev/null 2>&1 || true
}

# Ensure cross-compilation container image exists
IMAGE_NAME="vrtfido-cross-arm64"
ensure_arm64_container_image() {
  if ! $CONTAINER_ENGINE image exists "$IMAGE_NAME" >/dev/null 2>&1 && \
     ! $CONTAINER_ENGINE inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "[SETUP] Building cross-compilation image '$IMAGE_NAME' using $CONTAINER_ENGINE..."
    $CONTAINER_ENGINE build -t "$IMAGE_NAME" - << 'EOF'
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture arm64 && \
    apt-get update -qq && \
    apt-get install -y --download-only --no-install-recommends \
      gcc libc6-dev gcc-aarch64-linux-gnu pkgconf libgtk-3-dev:arm64 libusb-1.0-0-dev:arm64 ca-certificates && \
    for deb in /var/cache/apt/archives/*.deb; do dpkg -x "$deb" / 2>/dev/null || true; done && \
    ln -sf /usr/bin/gcc /usr/bin/cc && \
    ln -sf /usr/bin/pkgconf /usr/bin/pkg-config && \
    rm -rf /var/cache/apt/archives/*.deb /var/lib/apt/lists/*
EOF
  fi
}

echo ""
echo "Targets to build: ${BUILD_TARGETS[*]}"
echo "Host platform:    $HOST_ARCH ($HOST_TARGET)"
echo "------------------------------------------------------------"

built=()
for target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$target" | xargs)"
  [[ -n "$target" ]] || continue
  echo ""
  echo "==> Building $PROJECT_NAME (GUI) for target: $target"

  ensure_rust_target "$target"

  if [[ "$target" == "$HOST_TARGET" ]]; then
    echo "    [*] Compiling natively on host for $target..."
    cargo build --release --target "$target"
  elif [[ "$target" == "aarch64-unknown-linux-gnu" && "$HOST_TARGET" == "x86_64-unknown-linux-gnu" ]]; then
    if [[ -z "$CONTAINER_ENGINE" ]]; then
      echo "error: Cross-compiling GUI for aarch64 on x86_64 requires podman or docker." >&2
      echo "       Please install podman or build natively on an ARM64 machine / GitHub Actions." >&2
      exit 1
    fi
    echo "    [*] Using $CONTAINER_ENGINE with cross-compilation image for $target..."
    ensure_arm64_container_image

    $CONTAINER_ENGINE run --rm -i \
      -v "$ROOT:/work:rw" \
      -v "${HOME}/.cargo:/root/.cargo:ro" \
      -v "${HOME}/.rustup:/root/.rustup:ro" \
      -w /work \
      "$IMAGE_NAME" bash << 'INNER'
set -e
export PATH="/root/.cargo/bin:$PATH"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
export PKG_CONFIG_ALLOW_CROSS=1
export CC_x86_64_unknown_linux_gnu=gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
export CC=gcc
export RUSTFLAGS="-C link-arg=-Wl,-rpath-link=/usr/lib/aarch64-linux-gnu -C link-arg=-L/usr/lib/aarch64-linux-gnu"
export LIBRARY_PATH="/usr/lib/aarch64-linux-gnu"
ln -sf /usr/bin/gcc /usr/bin/cc 2>/dev/null || true
ln -sf /usr/bin/pkgconf /usr/bin/pkg-config 2>/dev/null || true

cargo build --release --target aarch64-unknown-linux-gnu
INNER
  else
    echo "    [*] Standard cargo build for target: $target..."
    cargo build --release --target "$target"
  fi

  ext=""
  [[ "$target" == *windows* ]] && ext=".exe"
  src="$ROOT/target/$target/release/${BIN_NAME}${ext}"
  [[ -f "$src" ]] || { echo "error: Output binary not found at: $src" >&2; exit 1; }

  target_dist="$ROOT/dist/$target"
  mkdir -p "$target_dist"
  cp -f "$src" "$target_dist/"

  # Package archive for GitHub Releases and mise (expects vrtfido binary in root of tar.gz)
  archive="$ROOT/dist/packages/${PROJECT_NAME}-${target}.tar.gz"
  stage_dir="$(mktemp -d)"
  cp -f "$target_dist/${BIN_NAME}${ext}" "$stage_dir/"
  tar -C "$stage_dir" -czf "${archive}.tmp" .
  mv -f "${archive}.tmp" "$archive"
  rm -rf "$stage_dir"

  # Write sha256 checksum file
  (cd "$ROOT/dist/packages" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
  built+=("$target")
  echo "    [+] Package completed: $archive"
  echo "    [+] Checksum created:  ${archive}.sha256"
done

echo ""
echo "============================================================"
echo "     ALL PACKAGES BUILT AND ARCHIVED SUCCESSFULLY           "
echo "============================================================"
echo "Built architectures: ${built[*]}"
echo "Upload artifacts directory: $ROOT/dist/packages/"
ls -lh "$ROOT/dist/packages/"
