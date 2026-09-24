#!/usr/bin/env bash
set -euo pipefail

# Install the built APK on a connected device, with actionable messages for the
# failures that actually happen on this project (ADB mode, signature change).
# Usage: ./install-android.sh [--reinstall] [path/to/app.apk]
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE="${VRTFIDO_ANDROID_CACHE:-$ROOT/.android-build}"
PACKAGE=com.vrtfido

fail() { printf 'Android install failed: %s\n' "$*" >&2; exit 1; }

reinstall=0
apk=""
for arg in "$@"; do
    case "$arg" in
        --reinstall) reinstall=1 ;;
        -*) fail "Unknown option: $arg" ;;
        *) [ -z "$apk" ] || fail "Only one APK path may be given"; apk="$arg" ;;
    esac
done
if [ -z "$apk" ]; then
    for candidate in \
        "$ROOT/android/app/build/outputs/apk/release/app-release.apk" \
        "$ROOT/android/app/build/outputs/apk/debug/app-debug.apk"; do
        [ -f "$candidate" ] && { apk="$candidate"; break; }
    done
fi
[ -n "$apk" ] || fail "No APK found; run ./build-android.sh first"
[ -f "$apk" ] || fail "APK not found: $apk"
apk="$(readlink -f "$apk")"

find_adb() {
    local candidate
    for candidate in \
        "${ADB:-}" \
        "$(command -v adb 2>/dev/null || true)" \
        "${ANDROID_HOME:-}/platform-tools/adb" \
        "${ANDROID_SDK_ROOT:-}/platform-tools/adb" \
        "$HOME/Android/Sdk/platform-tools/adb" \
        "$CACHE/sdk/platform-tools/adb"; do
        if [ -n "$candidate" ] && [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

ADB_BIN="$(find_adb)" || fail "adb not found. Install Android platform-tools \
(Android Studio -> SDK Manager, or 'apt install adb') or set ADB=/path/to/adb"
echo "[install] adb: $ADB_BIN"
echo "[install] apk: $apk"

devices="$(mktemp)"
trap 'rm -f "$devices"' EXIT
"$ADB_BIN" devices | tail -n +2 | grep -E '[^[:space:]]' >"$devices" || true
[ -s "$devices" ] || fail "adb sees no device.

  1. Phone: Settings -> Developer options -> USB debugging = ON
     On vivo/iQOO also enable 'USB debugging (Security settings)' and 'Install via USB'
     (both live under Developer options next to USB debugging; the USB-install toggle is
     what allows any adb install at all).
  2. Reconnect the USB cable, set the USB mode to 'File Transfer' / 'MTP' if asked,
     and accept the 'Allow USB debugging?' prompt from this computer.
  3. Then 'adb devices' must list a serial with state 'device'."

serial=""
requested="${ANDROID_SERIAL:-}"
while read -r candidate state _; do
    if [ -n "$requested" ] && [ "$candidate" != "$requested" ]; then
        continue
    fi
    case "$state" in
        device)
            [ -z "$serial" ] || fail "Multiple devices connected; set ANDROID_SERIAL=<serial> or unplug one"
            serial="$candidate"
            ;;
        unauthorized)
            fail "$candidate is unauthorized: unlock the phone and tap 'Allow' on the USB debugging prompt"
            ;;
        offline)
            fail "$candidate is offline: run '$ADB_BIN kill-server' and replug the cable"
            ;;
        no|"")
            fail "$candidate: adb has no USB permission. Add a udev rule for the vendor ID:
  echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"2d95\", MODE=\"0666\"' | sudo tee /etc/udev/rules.d/51-android.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
then replug the cable and re-run this script."
            ;;
        *)
            fail "$candidate is '$state'; replug the cable and check the phone's authorization prompt"
            ;;
    esac
done <"$devices"
[ -n "$serial" ] || fail "No usable device in 'device' state${requested:+ (ANDROID_SERIAL=$requested is not attached or not authorized)}"

echo "[install] device: $serial"

if [ "$reinstall" -eq 1 ]; then
    echo "[install] --reinstall: removing existing $PACKAGE (app data is deleted)"
    "$ADB_BIN" -s "$serial" uninstall "$PACKAGE" || true
fi

install_timeout="${VRTFIDO_INSTALL_TIMEOUT:-180}"
run_install() {
    timeout "$install_timeout" "$ADB_BIN" -s "$serial" install -r -g "$apk" 2>&1
}

# vivo/iQOO (OriginOS) shows its own "Chăm sóc bảo mật - Đang thực hiện quét sâu" screen
# before an adb install may proceed. That scan can wedge: the dialog then renders no install
# button at all, so the install either hangs forever or is aborted. The state lives in these
# processes, so stopping them clears it without the reboot the ROM would otherwise need.
clear_wedged_install_dialog() {
    "$ADB_BIN" -s "$serial" shell am force-stop com.android.packageinstaller >/dev/null 2>&1 || true
    "$ADB_BIN" -s "$serial" shell am force-stop com.vivo.safecenter >/dev/null 2>&1 || true
}

status=0
output="$(run_install)" || status=$?
if [ "$status" -ne 0 ]; then
    wedged=0
    if [ "$status" -eq 124 ]; then
        wedged=1
    else
        case "$output" in *INSTALL_FAILED_ABORTED*) wedged=1 ;; esac
    fi
    if [ "$wedged" -eq 1 ]; then
        echo "[install] the ROM's install-verification dialog did not complete; clearing it and retrying once"
        clear_wedged_install_dialog
        status=0
        output="$(run_install)" || status=$?
    fi
fi

if [ "$status" -eq 0 ]; then
    printf '%s\n' "$output"
else
    case "$output" in
        *INSTALL_FAILED_UPDATE_INCOMPATIBLE*|*INCONSISTENT_CERTIFICATES*)
            fail "an app with the same package ID but a different signing key is installed.
This is expected after switching between debug and release builds, or after the release
keystore was regenerated. Removing the old build deletes its settings and passkeys:
  $ADB_BIN -s $serial uninstall $PACKAGE
  $0 --reinstall '$apk'" ;;
        *INSTALL_FAILED_ABORTED*)
            fail "the ROM's install-verification dialog aborted again after the wedged state
was cleared, so the phone is rejecting the install rather than hanging: watch the phone's
screen for the confirmation prompt and tap it." ;;
        *INSTALL_FAILED_USER_RESTRICTED*)
            fail "the phone's ROM blocked the install. On vivo/iQOO enable Developer
options -> 'Install via USB' (and 'USB debugging (Security settings)', which vivo only
reveals after the former is on); MIUI/ColorOS need 'Install via USB' too." ;;
        *INSTALL_FAILED_INSUFFICIENT_STORAGE*)
            fail "not enough free storage on the phone (the APK is ~50 MB unpacked twice over, once per ABI)" ;;
        *INSTALL_FAILED_NO_MATCHING_ABIS*)
            fail "the phone's CPU ABI is not in the APK (only arm64-v8a and x86_64 are packaged)" ;;
        *)
            if [ -z "$output" ]; then
                fail "install produced no output after ${install_timeout}s: the phone's ROM
install-verification dialog never completed. Dismiss it on the phone, or clear it with:
  $ADB_BIN -s $serial shell am force-stop com.android.packageinstaller"
            fi
            fail "$output" ;;
    esac
fi

path="$("$ADB_BIN" -s "$serial" shell pm path "$PACKAGE" | tr -d '\r')"
[ -n "$path" ] || fail "install reported success but $PACKAGE is not registered"
echo "[install] installed: ${path#package:}"
"$ADB_BIN" -s "$serial" shell dumpsys package "$PACKAGE" |
    grep -E 'versionCode=|versionName=|firstInstallTime=' | head -3 || true
