#!/usr/bin/env bash
set -euo pipefail

# Standalone release builder for vrtfido on any host: one run produces the four Linux archives
# plus the two Windows ones, whatever the machine is.
#
# Linux: the `gnu` archives carry the daemon plus the prompt window and come out of
# cargo-zigbuild, so neither a container engine nor a foreign toolchain is needed; the `musl`
# archives are static CLI-only.
#
# Windows: `*-pc-windows-msvc` is built with cargo-xwin, which needs clang-cl, lld-link, llvm-lib
# and nasm - mise does not carry those, so they are installed through the system package manager
# (apt/dnf/... with sudo on Linux, Homebrew on macOS). `*-pc-windows-gnu` and
# `*-pc-windows-gnullvm` need nothing extra, because zig carries the whole toolchain, and they
# are the fallback when no LLVM can be installed.
#
# The macOS packages are not built here: they belong to ./build-mac.sh, because the Apple SDK
# confines that build to a Mac, and every `*-apple-darwin` target is refused with that pointer.
#
# Missing tools are installed automatically and the finished archives are moved from
# dist/packages/ into releases/.
#
# Usage:
#   ./build-cross.sh
#   TARGETS=x86_64-unknown-linux-gnu,aarch64-unknown-linux-musl ./build-cross.sh
#   TARGETS=x86_64-pc-windows-gnu ./build-cross.sh   # Windows without the LLVM/nasm install

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/share/mise/shims:${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
if command -v mise >/dev/null 2>&1; then
  eval "$(mise activate bash --shims 2>/dev/null || true)"
fi

PROJECT_NAME="vrtfido"
BIN_NAME="vrtfido"
# The script runs on Linux and on macOS, and the packages are the same on both - the macOS ones
# come from build-mac.sh. What the host decides is where the extra packages come from: the
# distribution's package manager on Linux, Homebrew on macOS. A Windows shell (MSYS/Git Bash) is
# refused, because it has neither that package manager nor the toolchain this script drives.
HOST_OS="$(uname -s)"
case "$HOST_OS" in
  Linux*) HOST_KIND="linux" ;;
  Darwin*) HOST_KIND="macos" ;;
  *)
    echo "error: the release packages are built on Linux and macOS; $HOST_OS is not supported." >&2
    echo "       Use WSL (Ubuntu) or a Linux/macOS machine." >&2
    exit 1
    ;;
esac

# Homebrew installs into /opt/homebrew (Apple silicon) or /usr/local (Intel), and an unattended
# script does not inherit the login shell's PATH with them. They go at the end, so a Homebrew
# tool can never shadow the system one; the keg-only LLVM is added separately, where it is used.
if [[ "$HOST_KIND" == "macos" ]]; then
  export PATH="$PATH:/opt/homebrew/bin:/usr/local/bin"
fi
# The prompt window is a second binary (`vrtfido-gui`) inside the `gnu` packages, so one
# build produces the daemon and its window together. The static `musl` packages stay
# CLI-only: they target servers and containers, where a window has no display to open on.
GUI_BIN_NAME="vrtfido-gui"
LINUX_TARGETS="x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu,x86_64-unknown-linux-musl,aarch64-unknown-linux-musl"
# x86_64 uses the MSVC ABI, which is the flavour mise prefers in a Windows asset name, and it
# links the C runtime statically so the Visual C++ redistributable is not a prerequisite.
# arm64 uses zig's toolchain instead: cargo-xwin hands the aarch64 target's C sources to clang in
# GNU mode together with MSVC-style `/imsvc` include flags, which fails inside ring/libz-sys
# (cargo-xwin 0.23.1), while gnullvm builds the same ARM64 binaries with no extra package.
WINDOWS_TARGETS="x86_64-pc-windows-msvc,aarch64-pc-windows-gnullvm"

# What this script produces is the same on every host it runs on: both flavours of Linux plus the
# two Windows packages. The macOS ones come from build-mac.sh, which needs a Mac. TARGETS=
# replaces the list, which is also how a Linux-only run avoids the MSVC toolchain install.
DEFAULT_TARGETS="$LINUX_TARGETS,$WINDOWS_TARGETS"
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
    # zig publishes per-host archives (linux-x86_64, linux-aarch64, macos-x86_64,
    # macos-aarch64), while `uname -m` reports arm64 on Apple silicon.
    ARCH="$(uname -m)"
    [[ "$ARCH" == "arm64" ]] && ARCH="aarch64"
    ZIG_PLATFORM="linux"
    [[ "$HOST_KIND" == "macos" ]] && ZIG_PLATFORM="macos"
    echo "[SETUP] Downloading official zig 0.13.0 binary for $ZIG_PLATFORM-$ARCH..."
    mkdir -p "$HOME/.local/bin" "$HOME/.local/opt"
    curl -sSL "https://ziglang.org/download/0.13.0/zig-${ZIG_PLATFORM}-${ARCH}-0.13.0.tar.xz" | tar -xJ -C "$HOME/.local/opt/"
    ln -sf "$HOME/.local/opt/zig-${ZIG_PLATFORM}-${ARCH}-0.13.0/zig" "$HOME/.local/bin/zig"
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
# 3. The Windows MSVC targets are compiled with cargo-xwin, which drives clang-cl, lld-link and
#    llvm-lib from LLVM, and ring assembles its x86_64 backend with nasm. mise carries none of
#    those four, so they come from the system package manager - apt/dnf/... with sudo on Linux
#    (sudo is what prompts for the password), Homebrew on macOS. Everything here is skipped
#    unless a windows-msvc target is being built, so a Linux-only run never asks for a package.
MSVC_PACKAGES_LINUX="clang lld llvm nasm"
MSVC_PACKAGES_MACOS="llvm nasm"
msvc_tools_ready() {
  have clang-cl && have lld-link && have llvm-lib && have nasm
}

install_system_packages() { # install_system_packages "pkg pkg ..."
  local packages="$1" manager
  if [[ "$HOST_KIND" == "macos" ]]; then
    if ! have brew; then
      # Homebrew is a multi-gigabyte, sometimes interactive system change, so the script prints
      # its installer instead of running it.
      echo "error: Homebrew is needed to install '$packages' on macOS." >&2
      echo "       Install it, then run this script again:" >&2
      echo '         /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"' >&2
      exit 1
    fi
    brew install $packages
    return $?
  fi
  for manager in apt-get dnf yum pacman zypper apk; do
    have "$manager" || continue
    case "$manager" in
      apt-get) sudo apt-get update -qq && sudo apt-get install -y $packages ;;
      dnf | yum) sudo "$manager" install -y $packages ;;
      pacman) sudo pacman -S --noconfirm $packages ;;
      zypper) sudo zypper --non-interactive install $packages ;;
      apk) sudo apk add $packages ;;
    esac
    return $?
  done
  return 1
}

# Several distributions ship the LLVM tools only under versioned names (llvm-lib-18,
# /usr/lib/llvm-18/bin/lld-link) and Homebrew keeps LLVM in a keg outside PATH, while cargo-xwin
# and the C compilers look for the bare names. Link whatever is missing into ~/.local/bin. clang
# can act as clang-cl - the driver is chosen by the program name - so a box whose clang has no
# clang-cl entry point gets one the same way.
link_missing_msvc_tools() {
  local tool path llvm_bin=""
  mkdir -p "$HOME/.local/bin"
  if have brew; then
    llvm_bin="$(brew --prefix llvm 2>/dev/null)/bin"
    if [[ -d "$llvm_bin" ]]; then
      export PATH="$llvm_bin:$PATH"
    fi
  fi
  for tool in llvm-lib lld-link clang-cl; do
    have "$tool" && continue
    if [[ -n "$llvm_bin" && -x "$llvm_bin/$tool" ]]; then
      ln -sf "$llvm_bin/$tool" "$HOME/.local/bin/$tool"
      continue
    fi
    # Linux packages keep the versioned LLVM trees under /usr/lib/llvm-*; `sort -V` is GNU-only,
    # so it is used here and nowhere a Mac run reaches.
    path="$(ls -d /usr/lib/llvm-*/bin 2>/dev/null | sort -V | tail -1)"
    [[ -n "$path" && -x "$path/$tool" ]] && ln -sf "$path/$tool" "$HOME/.local/bin/$tool"
  done
  if ! have clang-cl && have clang; then
    ln -sf "$(command -v clang)" "$HOME/.local/bin/clang-cl"
  fi
}

ensure_windows_msvc_toolchain() {
  if ! msvc_tools_ready; then
    local packages="$MSVC_PACKAGES_LINUX"
    [[ "$HOST_KIND" == "macos" ]] && packages="$MSVC_PACKAGES_MACOS"
    echo "[SETUP] The windows-msvc targets need clang-cl, lld-link, llvm-lib and nasm."
    echo "[SETUP] Installing what is missing with the system package manager: $packages"
    if ! install_system_packages "$packages"; then
      echo "error: could not install '$packages' automatically." >&2
      echo "       Install them and run this script again:" >&2
      if [[ "$HOST_KIND" == "macos" ]]; then
        echo "         brew install $packages" >&2
      else
        echo "         sudo apt install -y $packages   (or: sudo dnf install -y $packages)" >&2
      fi
      echo "       Or build the same two targets without extra tooling:" >&2
      echo "         TARGETS=x86_64-pc-windows-gnu,aarch64-pc-windows-gnullvm ./build-cross.sh" >&2
      exit 1
    fi
    link_missing_msvc_tools
    if ! msvc_tools_ready; then
      echo "error: '$packages' are installed, but clang-cl, lld-link, llvm-lib and nasm are still not on PATH." >&2
      exit 1
    fi
    echo "[SETUP] [+] MSVC toolchain ready: clang-cl, lld-link, llvm-lib, nasm"
  fi

  if ! have cargo-xwin; then
    echo "[SETUP] 'cargo-xwin' not found. Installing automatically..."
    cargo install cargo-xwin --locked
    export PATH="${HOME}/.cargo/bin:${PATH}"
    have cargo-xwin || { echo "error: Failed to install cargo-xwin automatically." >&2; exit 1; }
    echo "[SETUP] [+] Successfully installed cargo-xwin"
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
  rm -f "$RELEASES/${PROJECT_NAME}-${target}.tar.gz" "$RELEASES/${PROJECT_NAME}-${target}.tar.gz.sha256" \
        "$RELEASES/${PROJECT_NAME}-${target}.zip" "$RELEASES/${PROJECT_NAME}-${target}.zip.sha256"
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
    *apple-ios*)
      # An iOS app is a separate project (a credential provider extension), not another row in
      # this list: no part of the daemon's model - kernel device, local HTTP CMS, autostart -
      # survives on iOS.
      echo "error: $target is not part of this release; an iOS app would be a separate project." >&2
      exit 1
      ;;
    *apple-darwin*)
      # build-mac.sh owns the macOS packages - the Apple command line tools check, both
      # architectures, the tar with its checksum - and the Apple SDK confines that build to a Mac.
      # This script builds what is the same on every host, so it points there rather than doing
      # half of that work here.
      echo "error: $target is built by ./build-mac.sh, on the Mac itself." >&2
      echo "       Run that script on the Mac; this one builds the Linux and Windows packages," >&2
      echo "       which any host can produce." >&2
      exit 1
      ;;
    *windows*msvc*)
      # The MSVC ABI is what the Windows release archives carry, because mise prefers it when it
      # picks an asset there. cargo-xwin downloads the Microsoft CRT and the Windows SDK headers
      # and libraries once (into ~/.cache/cargo-xwin) and drives clang-cl + lld-link with them.
      ensure_windows_msvc_toolchain
      # The C runtime is linked statically: without +crt-static the binaries import
      # VCRUNTIME140.dll, which would make the Visual C++ redistributable a prerequisite on every
      # machine that installs the daemon with mise. The flag goes into RUSTFLAGS rather than into
      # this target's own variable, because cargo-xwin merges RUSTFLAGS into the flags it hands to
      # the target - and because a set RUSTFLAGS wins over a target-specific variable in the cargo
      # it spawns, so putting it only there would have it ignored.
      #
      # LNK4099 is switched off as well: the CRT that cargo-xwin downloads is Microsoft's own
      # libcmt/libvcruntime, whose debug info points at .pdb files from their build machine that
      # are not part of the package, so every object in them reports "cannot use debug info". It
      # says nothing about this crate, and there is no way to ship those files.
      export RUSTFLAGS="$CROSS_RUSTFLAGS -C target-feature=+crt-static -C link-arg=/ignore:4099"
      cargo xwin build --release --features gui --target "$target"
      ;;
    *windows*)
      # gnu / gnullvm: zig carries compiler, assembler and linker, so this flavour needs no
      # system package at all, and its binaries import only DLLs that ship with Windows.
      #
      # zig's LLD rejects the `-Wl,-O1` that rustc passes it ("ignoring deprecated linker
      # optimization setting") and the linker_messages lint forwards that line as a warning of
      # this crate. It describes the toolchain, so only that lint is allowed - the same allowance
      # build-android.sh makes for the same reason.
      export RUSTFLAGS="$CROSS_RUSTFLAGS -A linker_messages"
      cargo zigbuild --release --features gui --target "$target"
      ;;
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
      # Linux `gnu`: the daemon together with the prompt window, for a desktop host. Same
      # `-A linker_messages` as the other zig-linked targets: rustc hands zig's LLD a `-Wl,-O1`
      # that LLD reports as deprecated, and that line is not about this crate.
      export RUSTFLAGS="$CROSS_RUSTFLAGS -A linker_messages"
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
  # The template is explicit because BSD/macOS `mktemp` refuses to run without one.
  stage_dir="$(mktemp -d "${TMPDIR:-/tmp}/vrtfido-package.XXXXXX")"
  cp -f "${stage_bins[@]}" "$stage_dir/"
  if [[ "$target" == *windows* ]]; then
    # Windows gets a .zip so it opens with a double click there, with the members at the archive
    # root like the Linux ones. The archive is written by python3, which the repository's publish
    # scripts already require, so no zip tool has to be installed next to the LLVM packages.
    have python3 || { echo "error: python3 is required to package the Windows archive." >&2; exit 1; }
    archive="$ROOT/dist/packages/${PROJECT_NAME}-${target}.zip"
    rm -f "${archive}.tmp"
    python3 - "${archive}.tmp" "${stage_bins[@]}" <<'PY'
import os, sys, zipfile

with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as archive:
    for path in sys.argv[2:]:
        archive.write(path, os.path.basename(path))
PY
    mv -f "${archive}.tmp" "$archive"
  else
    archive="$ROOT/dist/packages/${PROJECT_NAME}-${target}.tar.gz"
    tar -C "$stage_dir" -czf "${archive}.tmp" .
    mv -f "${archive}.tmp" "$archive"
  fi
  rm -rf "$stage_dir"
  # The checksum is written only after the archive is final, and both files travel
  # together into releases/ so a staged package is never there without its checksum. macOS has no
  # sha256sum, and `shasum -a 256` writes the same "<hash>  <file>" line the Linux releases use.
  if have sha256sum; then
    (cd "$ROOT/dist/packages" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
  else
    (cd "$ROOT/dist/packages" && shasum -a 256 "$(basename "$archive")" > "$(basename "$archive").sha256")
  fi
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
