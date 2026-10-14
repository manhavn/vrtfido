#!/usr/bin/env bash
set -euo pipefail

# Standalone local release builder for vrtfido: every Linux package in one run. The `gnu`
# archives carry the daemon plus the GTK window and are built inside a container, so the
# build needs no host GTK3; the `musl` archives are static CLI-only builds made with
# cargo-zigbuild. Missing tools are installed automatically and the finished archives are
# moved from dist/packages/ into releases/.
#
# Usage:
#   ./build-cross.sh
#   TARGETS=x86_64-unknown-linux-gnu,aarch64-unknown-linux-musl ./build-cross.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/share/mise/shims:${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
if command -v mise >/dev/null 2>&1; then
  eval "$(mise activate bash --shims 2>/dev/null || true)"
fi

PROJECT_NAME="vrtfido"
BIN_NAME="vrtfido"
# The GTK window is a second binary (`vrtfido-gui`) inside the `gnu` packages, so one build
# produces the daemon and its window together. The static `musl` packages stay CLI-only:
# musl has no GTK3 to link against, and the daemon runs headless without it.
GUI_BIN_NAME="vrtfido-gui"
DEFAULT_TARGETS="x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu,x86_64-unknown-linux-musl,aarch64-unknown-linux-musl"
TARGETS_CSV="${TARGETS:-$DEFAULT_TARGETS}"

have() { command -v "$1" >/dev/null 2>&1; }

echo "============================================================"
echo "      vrtfido - Local Cross-Platform Release Builder        "
echo "============================================================"

# 0. The CLI tools below are installed through mise when its registry ships them, so mise
# comes first. `mise.run` is the project's own installer and needs nothing but curl.
if ! have mise; then
  echo "[SETUP] 'mise' not found. Installing it with the official installer..."
  if have curl; then
    curl -fsSL https://mise.run | sh
    export PATH="${HOME}/.local/bin:${HOME}/.local/share/mise/shims:$PATH"
  fi
  if have mise; then
    echo "[SETUP] [+] Successfully installed mise: $(mise --version)"
  else
    echo "[SETUP] [!] mise is still missing; install it with: curl -fsSL https://mise.run | sh"
  fi
fi

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

# ------------------------------------------------------------------ gnu targets -----
# Building the window needs GTK3 development files, and cross-building them for a second
# architecture needs the foreign GTK stack as well. A container image carries both sets,
# which keeps the build independent of the host's GTK3 installation, its linker and its
# pkg-config cache.
CONTAINER_ENGINE=""
engine_usable() { command -v "$1" >/dev/null 2>&1 && "$1" info >/dev/null 2>&1; }

detect_container_engine() {
  local engine
  for engine in podman docker; do
    if engine_usable "$engine"; then
      CONTAINER_ENGINE="$engine"
      return 0
    fi
    if have "$engine"; then
      echo "[SETUP] [!] '$engine' is on PATH but not usable: a client-only build (mise installs one) cannot reach a local daemon."
      echo "[SETUP]     Install it from the system package manager instead: $(container_engine_hint)"
    fi
  done
  return 1
}

# The container engine has to come from the system package manager on the real machine: a
# podman installed through mise (or any client-only build) cannot run a local daemon, so
# mise is deliberately never offered for it. Print the command for the machine at hand.
container_engine_hint() {
  if have apt-get; then
    echo "sudo apt-get install -y podman   (or: sudo apt-get install -y docker.io)"
  elif have dnf; then
    echo "sudo dnf install -y podman   (or: sudo dnf install -y docker-ce)"
  elif have yum; then
    echo "sudo yum install -y podman"
  elif have pacman; then
    echo "sudo pacman -S --noconfirm podman   (or: sudo pacman -S --noconfirm docker)"
  elif have zypper; then
    echo "sudo zypper install -y podman   (or: sudo zypper install -y docker)"
  elif have apk; then
    echo "sudo apk add podman"
  elif have brew; then
    echo "brew install podman"
  else
    echo "install podman or docker with your system package manager"
  fi
}

# The image carries the GTK3 development stack for both architectures plus the cross
# compiler. Native and aarch64 packages are unpacked into the same filesystem; their
# headers and .pc files live in per-architecture directories, so both sets coexist.
IMAGE_NAME="vrtfido-gui-builder-v2"
ensure_gui_container_image() {
  if ! $CONTAINER_ENGINE image exists "$IMAGE_NAME" >/dev/null 2>&1 && \
     ! $CONTAINER_ENGINE inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "[SETUP] Building GUI build image '$IMAGE_NAME' using $CONTAINER_ENGINE..."
    $CONTAINER_ENGINE build -t "$IMAGE_NAME" - << 'EOF'
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture arm64 && \
    apt-get update -qq && \
    apt-get install -y --download-only --no-install-recommends \
      gcc libc6-dev pkgconf libgtk-3-dev libusb-1.0-0-dev ca-certificates \
      gcc-aarch64-linux-gnu libgtk-3-dev:arm64 libusb-1.0-0-dev:arm64 && \
    for deb in /var/cache/apt/archives/*.deb; do dpkg -x "$deb" / 2>/dev/null || true; done && \
    ln -sf /usr/bin/gcc /usr/bin/cc && \
    ln -sf /usr/bin/pkgconf /usr/bin/pkg-config && \
    rm -rf /var/cache/apt/archives/*.deb /var/lib/apt/lists/*
EOF
  fi
}

IFS=',' read -r -a BUILD_TARGETS <<< "$TARGETS_CSV"

# releases/ holds only finished packages. Every target that is about to be rebuilt
# drops its previous archive first, so a failed build cannot leave a stale package
# behind that looks current.
RELEASES="$ROOT/releases"
mkdir -p "$ROOT/dist/packages" "$RELEASES"
for target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$target" | xargs)"
  [[ -n "$target" ]] || continue
  rm -f "$RELEASES/${PROJECT_NAME}-${target}.tar.gz" "$RELEASES/${PROJECT_NAME}-${target}.tar.gz.sha256"
done

# The `gnu` packages are built in the container; a machine without an engine can still
# produce the portable `musl` ones.
if printf '%s\n' "${BUILD_TARGETS[@]}" | grep -q 'gnu'; then
  if ! detect_container_engine; then
    echo "error: the gnu packages (daemon + GTK window) are built inside a container, and no usable container engine was found." >&2
    echo "" >&2
    echo "       Install podman (or docker) on this machine, from its system package manager" >&2
    echo "       rather than through mise - a client-only podman from mise cannot run a daemon:" >&2
    echo "         $(container_engine_hint)" >&2
    echo "" >&2
    echo "       Or build only the portable packages, e.g. TARGETS=x86_64-unknown-linux-musl ./build-cross.sh" >&2
    exit 1
  fi
fi

# rustc links every artifact with -Wl,-O1 and the lld that zig ships deprecates that value, so each
# cross build used to print "ignoring deprecated linker optimization setting '1'" through the
# linker_messages lint. The notice describes the toolchain, not this crate, so the lint is allowed
# for these builds only - a plain `cargo build` / `cargo test` keeps it enabled.
CROSS_RUSTFLAGS="${RUSTFLAGS:-}"

echo ""
echo "Targets to build: ${BUILD_TARGETS[*]}"
[[ -n "$CONTAINER_ENGINE" ]] && echo "gnu builds run in: $CONTAINER_ENGINE image $IMAGE_NAME"
echo "------------------------------------------------------------"

built=()
for target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$target" | xargs)"
  [[ -n "$target" ]] || continue
  echo "==> Building $PROJECT_NAME for target: $target"

  # Automatically add target to rustup if missing
  rustup target add "$target" >/dev/null 2>&1 || true

  case "$target" in
    *musl*)
      # A musl build additionally drops `cdylib` (only the Android JNI library needs that crate type
      # and Cargo cannot scope [lib] crate-type per target), and that notice carries no lint name of
      # its own. Nothing in this crate is gated on target_env, and the GNU targets lint every line,
      # so the warnings group is allowed for the musl packaging builds alone.
      export RUSTFLAGS="$CROSS_RUSTFLAGS -A warnings"
      cargo zigbuild --release --target "$target"
      ;;
    *)
      # `gnu`: the daemon together with the GTK window, from the prepared image.
      echo "    [*] Building inside $CONTAINER_ENGINE ($IMAGE_NAME) for $target..."
      ensure_gui_container_image
      $CONTAINER_ENGINE run --rm -i \
        -e "TARGET=$target" \
        -v "$ROOT:/work:rw" \
        -v "${HOME}/.cargo:/root/.cargo:ro" \
        -v "${HOME}/.rustup:/root/.rustup:ro" \
        -w /work \
        "$IMAGE_NAME" bash << 'INNER'
set -e
export PATH="/root/.cargo/bin:$PATH"
TARGET="${TARGET:-x86_64-unknown-linux-gnu}"

# The image ships the compilers and the GTK3 stack, but no Rust: the host toolchain is
# mounted at /root/.cargo. A host that only has Rust through mise shims has nothing to
# mount, so Rust is installed inside the container in that case.
if ! command -v cargo >/dev/null 2>&1; then
  echo "[container] No host Rust toolchain mounted; installing Rust inside the container..."
  apt-get update -qq
  apt-get install -y --no-install-recommends curl ca-certificates
  export CARGO_HOME=/tmp/cargo RUSTUP_HOME=/tmp/rustup
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
  export PATH="/tmp/cargo/bin:$PATH"
  rustup target add "$TARGET"
fi

ln -sf /usr/bin/gcc /usr/bin/cc 2>/dev/null || true
ln -sf /usr/bin/pkgconf /usr/bin/pkg-config 2>/dev/null || true
export CC=gcc

if [ "$TARGET" = "aarch64-unknown-linux-gnu" ]; then
  # The arm64 GTK stack sits next to the native one inside the image. The vendored C
  # dependencies (libusb) are compiled by the cc crate, so the cross compiler has to be
  # named explicitly: with the host `cc` they would land in the archive as x86-64 objects
  # and the aarch64 link would fail with "file in wrong format" (EM 62).
  export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
  export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
  export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
  export PKG_CONFIG_ALLOW_CROSS=1
  export RUSTFLAGS="-C link-arg=-Wl,-rpath-link=/usr/lib/aarch64-linux-gnu -C link-arg=-L/usr/lib/aarch64-linux-gnu"
  export LIBRARY_PATH=/usr/lib/aarch64-linux-gnu
else
  export LIBRARY_PATH="/usr/lib/$(gcc -dumpmachine)"
fi

cargo build --release --features gui --target "$TARGET"
INNER
      ;;
  esac

  ext=""
  [[ "$target" == *windows* ]] && ext=".exe"
  src="$ROOT/target/$target/release/${BIN_NAME}${ext}"
  [[ -f "$src" ]] || { echo "error: Output binary not found at: $src" >&2; exit 1; }

  target_dist="$ROOT/dist/$target"
  mkdir -p "$target_dist"
  cp -f "$src" "$target_dist/"

  # The gnu packages also carry the GTK window: the daemon starts it where the host can run
  # it and stays headless where it cannot, so one package serves both.
  stage_bins=("$target_dist/${BIN_NAME}${ext}")
  case "$target" in
    *musl*) ;;
    *)
      gui_src="$ROOT/target/$target/release/${GUI_BIN_NAME}${ext}"
      [[ -f "$gui_src" ]] || { echo "error: GUI binary not found at: $gui_src" >&2; exit 1; }
      cp -f "$gui_src" "$target_dist/"
      stage_bins+=("$target_dist/${GUI_BIN_NAME}${ext}")
      ;;
  esac

  # Package from a private staging directory and publish atomically: packaging straight out of
  # dist/<target> raced with the linker rewriting the binary and produced corrupt archives.
  archive="$ROOT/dist/packages/${PROJECT_NAME}-${target}.tar.gz"
  stage_dir="$(mktemp -d)"
  cp -f "${stage_bins[@]}" "$stage_dir/"
  tar -C "$stage_dir" -czf "${archive}.tmp" .
  mv -f "${archive}.tmp" "$archive"
  rm -rf "$stage_dir"
  # The checksum is written only after the archive is final, and both files travel
  # together into releases/ so a staged package is never there without its checksum.
  (cd "$ROOT/dist/packages" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
  mv -f "$archive" "${archive}.sha256" "$RELEASES/"
  built+=("$target")
  echo "    [+] Package completed: $RELEASES/$(basename "$archive")"
done

echo ""
echo "============================================================"
echo "     ALL PACKAGES BUILT AND ARCHIVED SUCCESSFULLY           "
echo "============================================================"
echo "Built architectures: ${built[*]}"
echo "Publish-ready artifacts: $RELEASES/"
ls -lh "$RELEASES/"
