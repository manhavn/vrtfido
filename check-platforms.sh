#!/usr/bin/env bash
set -euo pipefail

# Type-check the platform-gated backends of this repository for the platform families a machine
# cannot necessarily build for - the ones that need an Apple SDK, an Android NDK or a second
# toolchain nowhere near it.
#
# `rustc --emit=metadata` needs no SDK, no linker and no C toolchain, and the module it checks
# (src/autostart, one backend per operating system) depends on nothing but the standard library.
# That matters because a `#[cfg]` naming the wrong platforms compiles everywhere except on the
# platform it left out: the Android build once stopped with "unresolved import `super::quote_arg`"
# because that helper was gated to `linux` and `windows`, and a Mac has no way to build the
# Android package (or the other way round) to notice before release day.
#
# Deliberately not in the list:
#   * the Windows families, because src/autostart/windows.rs uses the `winreg` crate and a bare
#     rustc call has no way to resolve it; `build-cross.sh` compiles them for real,
#   * src/platform, whose two backends are gated on `unix` / `windows` and share no helper, so
#     there is no gating to get wrong,
#   * and gui.rs, which needs the windowing crates and only compiles its macOS/Windows tray on
#     those two platforms.
#
# Usage:
#   ./check-platforms.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

TARGETS=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  aarch64-linux-android
  x86_64-apple-darwin
  aarch64-apple-darwin
)

have() { command -v "$1" >/dev/null 2>&1; }
have rustc || { echo "error: rustc is required (install the Rust toolchain first)." >&2; exit 1; }

echo "============================================================"
echo "      vrtfido - Platform Gating Check (no SDK needed)        "
echo "============================================================"

# The harness compiles the real module tree through `#[path]`, so the platform cfgs inside it are
# the ones under test; `probe` names the public API, which forces the per-platform `backend` alias
# and every helper the selected backend imports to resolve.
work="$(mktemp -d "${TMPDIR:-/tmp}/vrtfido-platforms.XXXXXX")"
trap 'rm -rf "$work"' EXIT
cat > "$work/check.rs" <<EOF
#[path = "$ROOT/src/autostart/mod.rs"]
pub mod autostart;

pub fn probe() {
    let _ = autostart::is_autostart_enabled();
    let _ = autostart::set_autostart_enabled(false);
    let _ = autostart::get_retained_startup_args();
}
EOF

failed=()
for target in "${TARGETS[@]}"; do
  # A target that is not installed yet is not an error here: the compiler reports it below.
  rustup target add "$target" >/dev/null 2>&1 || true
  if rustc --edition 2021 --crate-name platform_check --target "$target" \
      --crate-type lib --emit=metadata -o "$work/$target.rmeta" "$work/check.rs" \
      > "$work/$target.out" 2>&1; then
    echo "  [+] $target"
  else
    echo "  [!] $target"
    grep -E '^error' "$work/$target.out" | head -3 | sed 's/^/      /' >&2 || true
    failed+=("$target")
  fi
done

echo ""
if [[ ${#failed[@]} -eq 0 ]]; then
  echo "All ${#TARGETS[@]} platform families type-check (Windows is covered by build-cross.sh)."
  exit 0
fi
echo "error: ${#failed[@]} platform famil(y|ies) failed to type-check: ${failed[*]}" >&2
exit 1
