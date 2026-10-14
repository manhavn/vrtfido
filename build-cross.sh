#!/usr/bin/env bash
set -euo pipefail

# Standalone local release builder for vrtfido: every Linux package in one run. The `gnu`
# archives carry the daemon plus the prompt window, the `musl` archives are static CLI-only,
# and all four come out of cargo-zigbuild, so a run needs neither a container engine nor a
# host toolchain for the second architecture. Missing tools are installed automatically and
# the finished archives are moved from dist/packages/ into releases/.
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
# The prompt window is a second binary (`vrtfido-gui`) inside the `gnu` packages, so one
# build produces the daemon and its window together. The static `musl` packages stay
# CLI-only: they target servers and containers, where a window has no display to open on.
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

# rustc links every artifact with -Wl,-O1 and the lld that zig ships deprecates that value, so each
# cross build used to print "ignoring deprecated linker optimization setting '1'" through the
# linker_messages lint. The notice describes the toolchain, not this crate, so the lint is allowed
# for these builds only - a plain `cargo build` / `cargo test` keeps it enabled.
CROSS_RUSTFLAGS="${RUSTFLAGS:-}"

# Every package is cross-built with cargo-zigbuild: zig compiles the C parts (bundled SQLite
# through rusqlite, libusb through rusb) and links the binaries, so the build no longer needs
# a container, a foreign toolchain or a host GTK3 installation. The `gnu` packages pin an
# explicit glibc floor: linking against whatever the build machine happens to ship silently
# raises the minimum every user needs, and the floor is what the release notes promise.
GLIBC_FLOOR="${GLIBC_FLOOR:-2.17}"

echo ""
echo "Targets to build: ${BUILD_TARGETS[*]}"
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
      #
      # The static musl archives stay CLI-only: they exist for servers and containers that need one
      # self-contained file, where the prompt window has no display to draw on anyway.
      export RUSTFLAGS="$CROSS_RUSTFLAGS -A warnings"
      cargo zigbuild --release --target "$target"
      ;;
    *)
      # `gnu`: the daemon together with the prompt window, for a desktop host.
      export RUSTFLAGS="$CROSS_RUSTFLAGS"
      cargo zigbuild --release --features gui --target "${target}.${GLIBC_FLOOR}"
      ;;
  esac

  ext=""
  [[ "$target" == *windows* ]] && ext=".exe"
  src="$ROOT/target/$target/release/${BIN_NAME}${ext}"
  [[ -f "$src" ]] || { echo "error: Output binary not found at: $src" >&2; exit 1; }

  target_dist="$ROOT/dist/$target"
  mkdir -p "$target_dist"
  cp -f "$src" "$target_dist/"

  # The gnu packages also carry the prompt window: the daemon starts it where the host can
  # run it and stays headless where it cannot, so one package serves both a desktop and a
  # server.
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
