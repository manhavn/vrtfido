#!/usr/bin/env bash
set -euo pipefail

# One-command release build: runs every build script in this repository in order,
# so a release no longer needs the scripts to be launched one by one.
#
#   extensions -> build-extension.sh (Chrome + Firefox + Safari)
#   android    -> build-android.sh (release APK)
#   linux      -> build-cross.sh  (gnu packages with the prompt window, static musl packages)
#
# The Windows packages are part of the linux step: build-cross.sh builds them here with
# cargo-xwin. The macOS packages are the exception - no other host may use the Apple SDK - so
# run build-cross.sh once on the Mac too and attach its two archives to the same tag.
#
# Every step stages its own publish-ready files in releases/, so when this command
# finishes that single directory holds the whole release set. Each step prepares
# its own prerequisites (mise tools first, then the system package manager) - see
# the individual scripts for what they install.
#
# The extension step already chains build-chrome.sh, build-firefox.sh and
# build-safari.sh, so those three are never built twice.
#
# A failing step does not stop the remaining ones: everything that can be built is
# built, and the summary at the end lists what failed (exit status 1 in that case).
#
# Usage:
#   ./release-build-all.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

STEP_NAMES=(extensions android linux)
STEP_SCRIPTS=(
  ./build-extension.sh
  ./build-android.sh
  ./build-cross.sh
)

RELEASES="$ROOT/releases"
mkdir -p "$RELEASES"

echo "============================================================"
echo "      vrtfido - Full Release Build (all packages)           "
echo "============================================================"
echo "Steps: ${STEP_NAMES[*]}"
echo "Staging directory: $RELEASES"
echo "------------------------------------------------------------"

built=()
failed=()
for index in "${!STEP_NAMES[@]}"; do
  name="${STEP_NAMES[$index]}"
  script="${STEP_SCRIPTS[$index]}"
  echo ""
  echo "############################################################"
  echo "# [$((index + 1))/${#STEP_NAMES[@]}] $name -> $script"
  echo "############################################################"
  if bash "$script"; then
    built+=("$name")
  else
    failed+=("$name")
    echo "[RELEASE] Step '$name' FAILED ($script) - continuing with the remaining steps." >&2
  fi
done

echo ""
echo "============================================================"
echo "                 RELEASE BUILD SUMMARY                      "
echo "============================================================"
echo "Completed: ${built[*]:-none}"
echo "Failed:    ${failed[*]:-none}"
echo ""
echo "Staged artifacts in $RELEASES:"
ls -lh "$RELEASES/"

if [ "${#failed[@]}" -gt 0 ]; then
  echo "" >&2
  echo "error: ${#failed[@]} build step(s) failed: ${failed[*]}" >&2
  exit 1
fi

echo ""
echo "============================================================"
echo "        ALL RELEASE PACKAGES BUILT SUCCESSFULLY             "
echo "============================================================"
