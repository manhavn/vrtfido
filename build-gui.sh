#!/usr/bin/env bash
set -euo pipefail

# Standalone release builder for vrtfido with native desktop GUI (GTK3).
# Builds upload-ready packages for GitHub Releases and mise installation:
#   - vrtfido-x86_64-unknown-linux-gnu.tar.gz (.sha256)
#   - vrtfido-aarch64-unknown-linux-gnu.tar.gz (.sha256)
#
# One run is enough: everything the build needs is resolved first. CLI tools are
# taken from mise whenever its registry ships them, GTK3 development files come
# from the system package manager, and when that would need a password the .deb
# archives are unpacked into a private sysroot instead - see bootstrap_sysroot.
#
# A container engine (podman or docker) is only detected, never installed: it is
# needed for the aarch64 cross build alone. Install it yourself when you ask for
# that target.
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
# Started by the daemon when the host can run GTK; packaged alongside it in the same tarball.
GUI_BIN_NAME="vrtfido-gui"
DEFAULT_TARGETS="x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu"
TARGETS_CSV="${TARGETS:-$DEFAULT_TARGETS}"
# Rootless fallback data (downloaded .debs + unpacked sysroot); outside the repo
# because it is host state, not project state.
GUI_CACHE="${VRTFIDO_GUI_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/vrtfido-gui}"
# Publish-ready packages (archive + checksum) are staged here, the same directory
# every other build script in this repository uses.
RELEASES="$ROOT/releases"

have() { command -v "$1" >/dev/null 2>&1; }
log() { echo "[SETUP] $*"; }
die() { echo "error: $*" >&2; exit 1; }

echo "============================================================"
echo "    vrtfido - Native GUI Release Builder (GTK3 Desktop)     "
echo "============================================================"

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64|amd64) HOST_TARGET="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) HOST_TARGET="aarch64-unknown-linux-gnu" ;;
  *) HOST_TARGET="unknown" ;;
esac

# ===========================================================================
# Host bootstrap
# ===========================================================================

# Every tool mise ships goes to mise first, so installs stay in the user's own
# toolchain and are reproducible through ~/.config/mise/config.toml.
ensure_mise() {
  have mise && return 0
  log "'mise' not found. Installing it with the official installer..."
  ensure_curl
  curl -fsSL https://mise.run | sh
  export PATH="${HOME}/.local/bin:${HOME}/.local/share/mise/shims:$PATH"
  have mise || die "mise could not be installed automatically; see https://mise.run"
}

ensure_curl() {
  have curl && return 0
  pm_install curl || die "curl is missing and could not be installed automatically."
  have curl || die "curl is still missing after installation."
}

PM=""
detect_pm() {
  [[ -n "$PM" ]] && return 0
  if have apt-get; then PM=apt
  elif have dnf; then PM=dnf
  elif have pacman; then PM=pacman
  elif have zypper; then PM=zypper
  elif have apk; then PM=apk
  elif have brew; then PM=brew
  else die "No supported package manager found (apt, dnf, pacman, zypper, apk, brew)."
  fi
}

# Logical dependency -> native package name per manager, so the call sites stay
# distro agnostic. An entry may hold several space separated packages.
declare -A PKG_apt=(
  [curl]=curl
  [pkgconf]=pkg-config
  [cc]=build-essential
  [gtk-dev]=libgtk-3-dev
  [usb-dev]=libusb-1.0-0-dev
)
declare -A PKG_dnf=(
  [curl]=curl
  [pkgconf]=pkgconf-pkg-config
  [cc]="gcc make"
  [gtk-dev]=gtk3-devel
  [usb-dev]=libusb1-devel
)
declare -A PKG_pacman=(
  [curl]=curl
  [pkgconf]=pkgconf
  [cc]=base-devel
  [gtk-dev]=gtk3
  [usb-dev]=libusb
)
declare -A PKG_zypper=(
  [curl]=curl
  [pkgconf]=pkg-config
  [cc]="gcc make"
  [gtk-dev]=gtk3-devel
  [usb-dev]=libusb-1_0-devel
)
declare -A PKG_apk=(
  [curl]=curl
  [pkgconf]=pkgconf
  [cc]=build-base
  [gtk-dev]=gtk+3.0-dev
  [usb-dev]=libusb-dev
)
declare -A PKG_brew=(
  [curl]=curl
  [pkgconf]=pkg-config
  [gtk-dev]=gtk+3
  [usb-dev]=libusb
)

# sudo is only used when it can actually complete without hanging: already root,
# passwordless sudo, or an interactive terminal where the user can answer the
# prompt. Headless runs fall through to the rootless .deb sysroot instead.
can_escalate() {
  [[ "$(id -u)" -eq 0 ]] && return 0
  have sudo || return 1
  sudo -n true 2>/dev/null && return 0
  [[ -t 0 && -t 2 ]]
}

pm_install() {
  detect_pm
  local -a names=() cmd=()
  local dep ref name
  for dep in "$@"; do
    ref="PKG_${PM}[$dep]"
    name="${!ref:-}"
    [[ -n "$name" ]] || continue
    names+=($name)
  done
  [[ "${#names[@]}" -gt 0 ]] || return 0

  if [[ "$PM" == brew ]]; then
    cmd=(brew install)
  else
    can_escalate || return 1
    if [[ "$(id -u)" -eq 0 ]]; then cmd=(); else cmd=(sudo); fi
    case "$PM" in
      apt) cmd+=(env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends) ;;
      dnf) cmd+=(dnf install -y) ;;
      pacman) cmd+=(pacman -S --noconfirm --needed) ;;
      zypper) cmd+=(zypper --non-interactive install) ;;
      apk) cmd+=(apk add --no-cache) ;;
    esac
  fi

  # Stale apt indexes are the usual reason a package is "not found", so refresh
  # the lists once before installing; a failed refresh is not fatal because the
  # install or the sysroot fallback reports the real problem.
  if [[ "$PM" == apt ]] && ! apt-cache show "${names[0]}" >/dev/null 2>&1; then
    if [[ "$(id -u)" -eq 0 ]]; then apt-get update -qq || true; else sudo apt-get update -qq || true; fi
  fi

  log "Installing with $PM: ${names[*]}"
  "${cmd[@]}" "${names[@]}"
}

# Cargo builds the bundled C dependencies (SQLite, libusb) itself, so a C
# compiler is needed even though this crate contains no C sources.
ensure_host_tools() {
  ensure_curl
  have pkg-config || pm_install pkgconf || die "pkg-config is missing and could not be installed automatically."
  { have cc || have gcc || have clang; } || pm_install cc || die "No C compiler found; install gcc and re-run."
  have pkg-config || die "pkg-config is still missing after installation."
}

# ===========================================================================
# Rust toolchain
# ===========================================================================

ensure_rust() {
  have cargo && return 0
  log "'cargo' not found. Installing Rust..."
  if have mise && mise registry rust >/dev/null 2>&1; then
    log "Installing rust via mise..."
    mise use -g rust@latest >/dev/null 2>&1 || true
    export PATH="${HOME}/.local/share/mise/shims:$PATH"
    have cargo && { log "[+] Rust $(rustc --version)"; return 0; }
  fi
  ensure_curl
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
  export PATH="${HOME}/.cargo/bin:$PATH"
  have cargo || die "Rust could not be installed automatically; see https://rustup.rs"
}

ensure_rust_target() {
  local target="$1"
  have rustup || return 0
  rustup target add "$target" >/dev/null 2>&1 || true
}

# ===========================================================================
# GTK3 development files
# ===========================================================================

gtk_dev_ready() { have pkg-config && pkg-config --exists 'gtk+-3.0' 2>/dev/null; }

# Rootless fallback for hosts where the system install is not permitted.
#
# `apt-get download` needs no privileges and `dpkg -x` unpacks a .deb anywhere,
# so the development files (headers, .pc files and the .so symlinks) can be
# assembled in a private sysroot. PKG_CONFIG_SYSROOT_DIR rewrites the /usr paths
# recorded inside those .pc files to that sysroot, which is what makes the
# headers and -L flags resolve without touching /usr. Linking happens against
# the sysroot copies while the runtime loader keeps using the system libraries,
# so no rpath is embedded in the shipped binary.
bootstrap_sysroot() {
  have apt-get && have dpkg && have apt-cache || return 1

  local multiarch sysroot debs pkgs deb
  multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo "${HOST_ARCH}-linux-gnu")"
  sysroot="$GUI_CACHE/sysroot"
  debs="$GUI_CACHE/debs"
  mkdir -p "$sysroot" "$debs"

  export PKG_CONFIG_SYSROOT_DIR="$sysroot"
  export PKG_CONFIG_LIBDIR="$sysroot/usr/lib/$multiarch/pkgconfig:$sysroot/usr/share/pkgconfig"

  if ! gtk_dev_ready; then
    log "Downloading GTK3 development packages as .deb (~230 MB, no root needed)..."
    pkgs="$(apt-cache depends --recurse --no-recommends --no-suggests \
              --no-conflicts --no-breaks --no-replaces --no-enhances \
              libgtk-3-dev libusb-1.0-0-dev 2>/dev/null |
            grep -E '^[a-zA-Z0-9]' | sed 's/:.*$//' | sort -u | tr '\n' ' ')"
    [[ -n "${pkgs// /}" ]] || return 1
    ( cd "$debs" && apt-get download $pkgs >/dev/null 2>&1 || true )
    log "Unpacking into $sysroot ..."
    for deb in "$debs"/*.deb; do
      [[ -f "$deb" ]] || continue
      dpkg -x "$deb" "$sysroot" 2>/dev/null || true
    done
  fi

  gtk_dev_ready || return 1

  export LIBRARY_PATH="$sysroot/usr/lib/$multiarch${LIBRARY_PATH:+:$LIBRARY_PATH}"
  log "[+] GTK3 development files ready in private sysroot: $sysroot"
}

# GTK3 has no mise entry, so it goes through the system package manager; the
# sysroot above covers the case where that is not allowed.
ensure_gtk_dev() {
  if gtk_dev_ready; then
    log "[+] Found GTK3 development files: $(pkg-config --modversion 'gtk+-3.0')"
    return 0
  fi
  log "GTK3 development files (gtk+-3.0.pc) not found. Installing..."
  if pm_install gtk-dev usb-dev && gtk_dev_ready; then
    log "[+] Found GTK3 development files: $(pkg-config --modversion 'gtk+-3.0')"
    return 0
  fi
  bootstrap_sysroot ||
    die "GTK3 development files are missing and could not be installed automatically.
       Install them yourself and re-run, or clear $GUI_CACHE to retry the download:
         sudo apt-get install -y libgtk-3-dev libusb-1.0-0-dev"
}

# ===========================================================================
# Container engine (user installed; used for the aarch64 cross build only)
# ===========================================================================

CONTAINER_ENGINE=""
engine_usable() { command -v "$1" >/dev/null 2>&1 && "$1" info >/dev/null 2>&1; }

detect_container_engine() {
  local engine
  for engine in podman docker; do
    if engine_usable "$engine"; then
      CONTAINER_ENGINE="$engine"
      return 0
    fi
    have "$engine" && log "[!] '$engine' is on PATH but not usable, ignoring it."
  done
  return 1
}

cross_needs_container() {
  [[ "$1" == "aarch64-unknown-linux-gnu" && "$HOST_TARGET" == "x86_64-unknown-linux-gnu" ]]
}

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

# ===========================================================================
# Preflight: resolve every prerequisite before the first compile
# ===========================================================================

IFS=',' read -r -a BUILD_TARGETS <<< "$TARGETS_CSV"

native_targets=()
cross_targets=()
for raw_target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$raw_target" | xargs)"
  [[ -n "$target" ]] || continue
  if cross_needs_container "$target"; then
    cross_targets+=("$target")
  else
    native_targets+=("$target")
  fi
done

if [[ "${#native_targets[@]}" -gt 0 ]]; then
  ensure_mise
  ensure_host_tools
  ensure_gtk_dev
fi

ensure_rust

if [[ "${#cross_targets[@]}" -gt 0 ]]; then
  detect_container_engine || die "Cross-compiling the GUI for aarch64 on x86_64 needs a working container engine.
       Install it yourself and re-run (podman is enough, rootless works):
         sudo apt-get install -y podman"
fi

mkdir -p "$ROOT/dist/packages" "$RELEASES"

for raw_target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$raw_target" | xargs)"
  [[ -n "$target" ]] || continue
  # releases/ holds only finished packages, so the previous archive of a target that
  # is about to be rebuilt is dropped first: a failed build then cannot leave a stale
  # package behind that looks current.
  rm -f "$RELEASES/${PROJECT_NAME}-${target}.tar.gz" "$RELEASES/${PROJECT_NAME}-${target}.tar.gz.sha256"
  ensure_rust_target "$target"
done

echo ""
echo "Targets to build: ${BUILD_TARGETS[*]}"
echo "Host platform:    $HOST_ARCH ($HOST_TARGET)"
[[ -n "$CONTAINER_ENGINE" ]] && echo "Container engine: $CONTAINER_ENGINE"
echo "------------------------------------------------------------"

built=()
for target in "${BUILD_TARGETS[@]}"; do
  target="$(echo "$target" | xargs)"
  [[ -n "$target" ]] || continue
  echo ""
  echo "==> Building $PROJECT_NAME (GUI) for target: $target"

  if [[ "$target" == "$HOST_TARGET" ]]; then
    echo "    [*] Compiling natively on host for $target..."
    cargo build --release --features gui --target "$target"
  elif cross_needs_container "$target"; then
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

# The image ships the cross toolchain and the aarch64 GTK stack, but no Rust: the
# host toolchain is mounted at /root/.cargo. When the host only has Rust through
# mise shims there is nothing mountable, so install Rust inside the container.
if ! command -v cargo >/dev/null 2>&1; then
  echo "[container] No host Rust toolchain mounted; installing Rust inside the container..."
  apt-get update -qq
  apt-get install -y --no-install-recommends curl ca-certificates
  export CARGO_HOME=/tmp/cargo RUSTUP_HOME=/tmp/rustup
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
  export PATH="/tmp/cargo/bin:$PATH"
  rustup target add aarch64-unknown-linux-gnu
fi

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

cargo build --release --features gui --target aarch64-unknown-linux-gnu
INNER
  else
    echo "    [*] Standard cargo build for target: $target..."
    cargo build --release --features gui --target "$target"
  fi

  ext=""
  [[ "$target" == *windows* ]] && ext=".exe"
  src="$ROOT/target/$target/release/${BIN_NAME}${ext}"
  [[ -f "$src" ]] || { echo "error: Output binary not found at: $src" >&2; exit 1; }
  # The GTK window is a second binary in the same package: the daemon starts it where the
  # host can run it and stays headless where it cannot, so one package serves both.
  gui_src="$ROOT/target/$target/release/${GUI_BIN_NAME}${ext}"
  [[ -f "$gui_src" ]] || { echo "error: GUI client not found at: $gui_src (build with --features gui)" >&2; exit 1; }

  target_dist="$ROOT/dist/$target"
  mkdir -p "$target_dist"
  cp -f "$src" "$target_dist/"
  cp -f "$gui_src" "$target_dist/"

  # Package archive for GitHub Releases and mise (both binaries in the root of the tar.gz)
  archive="$ROOT/dist/packages/${PROJECT_NAME}-${target}.tar.gz"
  stage_dir="$(mktemp -d)"
  cp -f "$target_dist/${BIN_NAME}${ext}" "$target_dist/${GUI_BIN_NAME}${ext}" "$stage_dir/"
  tar -C "$stage_dir" -czf "${archive}.tmp" .
  mv -f "${archive}.tmp" "$archive"
  rm -rf "$stage_dir"

  # Write sha256 checksum file, then stage both files in releases/ so a package is
  # never published without its checksum.
  (cd "$ROOT/dist/packages" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
  mv -f "$archive" "${archive}.sha256" "$RELEASES/"
  built+=("$target")
  echo "    [+] Package completed: $RELEASES/$(basename "$archive")"
  echo "    [+] Checksum created:  $RELEASES/$(basename "$archive").sha256"
done

echo ""
echo "============================================================"
echo "     ALL PACKAGES BUILT AND ARCHIVED SUCCESSFULLY           "
echo "============================================================"
echo "Built architectures: ${built[*]}"
echo "Publish-ready artifacts: $RELEASES/"
ls -lh "$RELEASES/"
