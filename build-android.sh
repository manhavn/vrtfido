#!/usr/bin/env bash
set -euo pipefail

# One-command Android build. Missing host tools may require sudo; SDK/JDK/Gradle stay local.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE="${VRTFIDO_ANDROID_CACHE:-$ROOT/.android-build}"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$CACHE/sdk}}"
NDK_VERSION=26.3.11579264
GRADLE_VERSION=8.7
CMDLINE_TOOLS=https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
JNILIBS="$ROOT/android/app/src/main/jniLibs"
VARIANT="${1:-release}"
case "$VARIANT" in
    release) GRADLE_TASK=assembleRelease ;;
    debug) GRADLE_TASK=assembleDebug ;;
    *) printf 'Usage: %s [release|debug]\n' "$0" >&2; exit 2 ;;
esac

fail() { printf 'Android build failed: %s\n' "$*" >&2; exit 1; }
fetch() { curl --fail --location --retry 3 --retry-delay 2 --silent --show-error "$1" -o "$2"; }

[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] ||
    fail "This bootstrap supports Linux x86_64 only"
missing=()
for tool in curl unzip tar python3 sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
    echo "[bootstrap] Installing missing host utilities: ${missing[*]}"
    if [ "$(id -u)" -eq 0 ]; then
        elevate=()
    else
        command -v sudo >/dev/null 2>&1 || fail "Host utilities missing and sudo unavailable: ${missing[*]}"
        elevate=(sudo)
    fi
    packages=(ca-certificates)
    for tool in "${missing[@]}"; do
        case "$tool" in
            sha256sum) packages+=(coreutils) ;;
            python3) packages+=(python3) ;;
            *) packages+=("$tool") ;;
        esac
    done
    if command -v apt-get >/dev/null 2>&1; then
        "${elevate[@]}" apt-get update
        "${elevate[@]}" apt-get install -y "${packages[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        "${elevate[@]}" dnf install -y "${packages[@]}"
    elif command -v pacman >/dev/null 2>&1; then
        for index in "${!packages[@]}"; do
            [ "${packages[$index]}" = python3 ] && packages[$index]=python
        done
        "${elevate[@]}" pacman -Sy --needed --noconfirm "${packages[@]}"
    else
        fail "Unsupported host package manager; missing: ${missing[*]}"
    fi
fi
for tool in curl unzip tar python3 sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || fail "Installation did not provide $tool"
done
if ! command -v cargo >/dev/null 2>&1 || ! command -v rustup >/dev/null 2>&1; then
    echo '[bootstrap] Installing Rust via rustup'
    mkdir -p "$CACHE"
    fetch https://sh.rustup.rs "$CACHE/rustup-init.sh"
    sh "$CACHE/rustup-init.sh" -y --no-modify-path
    rm -f "$CACHE/rustup-init.sh"
    export PATH="$HOME/.cargo/bin:$PATH"
fi
command -v cargo >/dev/null 2>&1 && command -v rustup >/dev/null 2>&1 ||
    fail "Rust installation failed"
mkdir -p "$CACHE" "$SDK"

# Download the official Temurin JDK 17 when the host has no suitable JDK.
if ! command -v javac >/dev/null 2>&1 || ! javac -version 2>&1 | grep -q '^javac 17\.'; then
    if [ ! -x "$CACHE/jdk/bin/javac" ]; then
        echo '[bootstrap] Downloading Eclipse Temurin JDK 17'
        fetch 'https://api.adoptium.net/v3/assets/latest/17/hotspot?architecture=x64&image_type=jdk&os=linux&vendor=eclipse' "$CACHE/temurin.json"
        python3 - "$CACHE/temurin.json" "$CACHE/temurin.url" "$CACHE/temurin.sha256" <<'PY'
import json, sys
asset = json.load(open(sys.argv[1]))[0]['binary']['package']
open(sys.argv[2], 'w').write(asset['link'])
open(sys.argv[3], 'w').write(asset['checksum'])
PY
        fetch "$(cat "$CACHE/temurin.url")" "$CACHE/temurin.tar.gz"
        printf '%s  %s\n' "$(cat "$CACHE/temurin.sha256")" "$CACHE/temurin.tar.gz" | sha256sum -c -
        mkdir -p "$CACHE/jdk"
        tar -xzf "$CACHE/temurin.tar.gz" -C "$CACHE/jdk" --strip-components=1
    fi
    export JAVA_HOME="$CACHE/jdk"
    export PATH="$JAVA_HOME/bin:$PATH"
else
    export JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
fi
if [ "$VARIANT" = release ]; then
    # Reuse the same key across releases; losing it prevents updates to installed apps.
    if [ -n "${VRTFIDO_KEYSTORE:-}${VRTFIDO_KEYSTORE_PASSWORD:-}${VRTFIDO_KEY_ALIAS:-}${VRTFIDO_KEY_PASSWORD:-}" ]; then
        [ -n "${VRTFIDO_KEYSTORE:-}" ] && [ -n "${VRTFIDO_KEYSTORE_PASSWORD:-}" ] &&
        [ -n "${VRTFIDO_KEY_ALIAS:-}" ] && [ -n "${VRTFIDO_KEY_PASSWORD:-}" ] ||
            fail "Provide all four VRTFIDO_KEYSTORE, VRTFIDO_KEYSTORE_PASSWORD, VRTFIDO_KEY_ALIAS and VRTFIDO_KEY_PASSWORD"
        [ -f "$VRTFIDO_KEYSTORE" ] || fail "Signing keystore not found: $VRTFIDO_KEYSTORE"
        export VRTFIDO_KEYSTORE="$(readlink -f "$VRTFIDO_KEYSTORE")"
    else
        SIGNING_DIR="$CACHE/signing"
        mkdir -p "$SIGNING_DIR"
        VRTFIDO_KEYSTORE="$SIGNING_DIR/vrtfido-release.p12"
        PASSWORD_FILE="$SIGNING_DIR/password"
        if [ ! -f "$VRTFIDO_KEYSTORE" ]; then
            [ ! -e "$PASSWORD_FILE" ] || fail "Signing password exists but keystore is missing; restore the keystore"
            echo '[bootstrap] Generating a persistent local release signing key'
            (umask 077; python3 -c 'import secrets,sys; open(sys.argv[1],"w").write(secrets.token_urlsafe(32))' "$PASSWORD_FILE")
            "$JAVA_HOME/bin/keytool" -genkeypair -noprompt -keystore "$VRTFIDO_KEYSTORE" \
                -storetype PKCS12 -alias vrtfido -keyalg RSA -keysize 3072 -validity 9125 \
                -dname "CN=vrtfido Android" -storepass "$(cat "$PASSWORD_FILE")" \
                -keypass "$(cat "$PASSWORD_FILE")"
        fi
        [ -s "$PASSWORD_FILE" ] || fail "Signing password missing; restore $PASSWORD_FILE from backup"
        chmod 600 "$VRTFIDO_KEYSTORE" "$PASSWORD_FILE"
        export VRTFIDO_KEYSTORE VRTFIDO_KEY_ALIAS=vrtfido
        export VRTFIDO_KEYSTORE_PASSWORD="$(cat "$PASSWORD_FILE")"
        export VRTFIDO_KEY_PASSWORD="$VRTFIDO_KEYSTORE_PASSWORD"
        echo "[signing] Local release key: $VRTFIDO_KEYSTORE (back up this file and $PASSWORD_FILE)"
    fi
fi

# Respect an existing command-line-tools SDK, but install missing SDK parts there.
if [ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
    echo '[bootstrap] Downloading Android SDK command-line tools'
    fetch "$CMDLINE_TOOLS" "$CACHE/cmdline-tools.zip"
    unzip -tq "$CACHE/cmdline-tools.zip" >/dev/null
    mkdir -p "$CACHE/cmdline-extract" "$SDK/cmdline-tools"
    unzip -qo "$CACHE/cmdline-tools.zip" -d "$CACHE/cmdline-extract"
    mv "$CACHE/cmdline-extract/cmdline-tools" "$SDK/cmdline-tools/latest"
fi
export ANDROID_HOME="$SDK" ANDROID_SDK_ROOT="$SDK"
SDKMANAGER="$SDK/cmdline-tools/latest/bin/sdkmanager"
# sdkmanager reads repeated 'y' answers; no manual license prompt needed.
python3 -c "print('y\\n' * 100)" | "$SDKMANAGER" --sdk_root="$SDK" --licenses >/dev/null
"$SDKMANAGER" --sdk_root="$SDK" \
    'platforms;android-35' 'build-tools;35.0.0' "ndk;$NDK_VERSION"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$SDK/ndk/$NDK_VERSION}"
[ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" ] || fail "NDK not installed at $ANDROID_NDK_HOME"

if [ ! -x "$CACHE/gradle-$GRADLE_VERSION/bin/gradle" ]; then
    echo "[bootstrap] Downloading Gradle $GRADLE_VERSION"
    fetch "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip" "$CACHE/gradle.zip"
    fetch "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip.sha256" "$CACHE/gradle.sha256"
    printf '%s  %s\n' "$(cat "$CACHE/gradle.sha256")" "$CACHE/gradle.zip" | sha256sum -c -
    unzip -qo "$CACHE/gradle.zip" -d "$CACHE"
fi

if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo '[bootstrap] Installing cargo-ndk'
    cargo install cargo-ndk --locked
fi
rustup target add aarch64-linux-android x86_64-linux-android

# Output directly into Gradle's jniLibs; any native failure aborts the APK build.
mkdir -p "$JNILIBS"
rm -f "$JNILIBS/arm64-v8a/libvrtfido.so" "$JNILIBS/x86_64/libvrtfido.so"
(
    cd "$ROOT"
    cargo ndk -t arm64-v8a -t x86_64 -o "$JNILIBS" build --release --lib --features jni-bridge
)
for abi in arm64-v8a x86_64; do
    [ -s "$JNILIBS/$abi/libvrtfido.so" ] || fail "Native library missing for $abi"
done

APK="$ROOT/android/app/build/outputs/apk/$VARIANT/app-$VARIANT.apk"
rm -f "$APK"
(
    cd "$ROOT/android"
    "$CACHE/gradle-$GRADLE_VERSION/bin/gradle" --no-daemon "$GRADLE_TASK"
)
[ -s "$APK" ] || fail "Gradle finished without APK: $APK"
if [ "$VARIANT" = release ]; then
    "$SDK/build-tools/35.0.0/apksigner" verify --verbose --print-certs "$APK" ||
        fail "Release APK signature verification failed"
fi
echo "Android APK: $APK"
