# VrtFido

**VrtFido** is a **Virtual FIDO2 / WebAuthn Authenticator** hardware emulator for **Linux, macOS and Windows**. On Linux it presents itself to browsers as a real USB security key through the kernel character device `/dev/uhid`; on macOS and Windows it runs as the daemon, the Web CMS and the prompt window, without a virtual device (see **Platform support** under the installation section).

The application includes an embedded **Web CMS Dashboard** on port **10209**, supports multiple database backends (**SQLite**, **PostgreSQL**, **LibSQL/Turso**, **MySQL**, **MariaDB**, **MongoDB**), features **100% Data Export / Import to JSON** for migration, and supports multi-factor authentication policies (6-digit passkey PIN, hardware USB fingerprint sensor management, and future biometric modalities).

---

## 🌟 Key Features

1. **Kernel Virtual HID (`/dev/uhid`):**
   - Creates a virtual USB HID device with the FIDO Usage Page (`0xF1D0`). **Opt-in:** the device is only created when the daemon is started with `--uhid`; without it VrtFido runs as the Web CMS alone and leaves `/dev/uhid` untouched.
   - All browsers (Chrome, Chromium, Firefox, Edge) automatically recognize it as a physical USB Security Key.
   - Full support for standard CTAP2 commands: `authenticatorGetInfo`, `authenticatorMakeCredential` (Passkey Registration), and `authenticatorGetAssertion` (WebAuthn Sign-in).

2. **Interactive Verification Modal:**
   - When a website (e.g. `webauthn.io`, GitHub, Google) sends a WebAuthn verification request, the Web CMS displays a real-time verification modal.
   - If security is not yet configured: Prompts to set up a 6-digit PIN.
   - If configured: Allows verification via 6-digit PIN or USB fingerprint sensor.
   - **Remember for this app run:** ticking the box extends a successful PIN / sensor verification to the rest of the process run. Later requests that have nothing to choose are approved without a prompt, and one that still needs an account choice shows the picker plus a single **Approve** button instead of asking for the PIN or the finger again. Approving is never automatic in that case, the tick is never persisted, and both the tick and the remembered session disappear when the app restarts. Leaving the box unticked keeps the standard flow.
   - **Account selection:** shown only when the relying party sends no `allowList` and several stored credentials match that domain. Choosing an account never approves the request by itself — the approve button still has to be pressed.

3. **Security & Biometrics Policies:**
   - **6-Digit PIN (Passkey Password):** Enforces 6 numeric digits, hashed with SHA-256 and salt. Supports setup, changing (requires old PIN), and removal.
   - **Fingerprint Management:** Enrolls up to 10 fingerprints (or unlimited with `--unlimited-fps`), with customizable labels and slot deletion.
   - **6-stage enrollment (USB sensor):** The MAFP chip builds one template from six independent captures, so every stage needs its own press: touch the sensor, lift the finger when the modal says so, then touch again. Holding the finger down does not advance the enrollment — the modal keeps asking for a lift and the attempt is abandoned after 60s rather than storing a template built from a single press.
   - **Sensor re-enumeration:** The 3274:8012 dongle regularly drops off the USB bus and comes back on its own. The daemon notices the dead handle, re-opens the device and re-arms the chip on the next command, so a replug resumes an in-flight enrollment without restarting the app; while the sensor is away the modal says so, and after two fruitless wait windows the attempt ends with "replug the sensor" instead of waiting forever.
   - **Nothing is recorded without a scan:** Enrolling with no sensor attached is refused up front (no dashboard slot is written that could never match), and approving a WebAuthn request with the **Fingerprint** button requires the sensor — without it the request stays pending so the PIN can still be used.
   - **Future Biometrics:** Modular architecture ready for Face ID, Iris, and Voiceprint extensions.

4. **Web Management CMS (Port 10209):**
   - Modern, lightweight Dark theme embedded directly into the binary (zero Node.js/npm dependencies).
   - Manage registered passkey credentials (Relying Party domain, username, sign count, creation date, last used date).
   - **Search box** filters the credential list live by domain, username or display name (case-insensitive substring, client-side).
   - Edit usernames and display names, or delete credentials.
   - **Operational Audit Trail:** Complete operation history with detailed logs.
   - **Debug & Error Logs:** System logs and CTAP2 packet inspection.
   - **Clean Logs:** Dedicated buttons to clear audit logs, debug logs, or all logs at once.

5. **CLI Debug & Log Management:**
   - Debug output disabled by default for clean logs.
   - Enable via `--debug` or `-d` flag to print raw CTAPHID packets and record to `debug_logs`.
   - Clear logs via `--clean-logs` or `clean-logs` [all|auth|debug].

6. **Multi-Database Support & 100% Data Migration:**
   - Connects flexibly to **SQLite**, **PostgreSQL**, **LibSQL (Turso Cloud)**, **MySQL**, **MariaDB**, and **MongoDB**.
   - Export and Import 100% of data (Credentials, PIN, Fingerprints, Audit Logs, Debug Logs) to a single JSON file.
   - Integrated REST API endpoints `/api/database/export` and `/api/database/import`.

7. **System Tray & Autostart:**
   - Integrated system tray icon with direct access to the Web CMS Dashboard.
   - Click the tray icon or select **Dashboard** from the tray menu to open your default browser.
   - Toggle **Start with the system** directly in the tray menu (with checkmark status) to enable or disable automatic startup upon system login — `~/.config/autostart/vrtfido.desktop` on Linux, `~/Library/LaunchAgents/dev.vrtfido.daemon.plist` on macOS, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` on Windows.
   - Option `--no-tray` to disable system tray on headless/server systems.
   - The native verification window ships as the companion binary `vrtfido-gui`, an egui/eframe process that renders on its own (winit + OpenGL/EGL, own fonts and widgets) and needs no system toolkit installed. The daemon starts it by itself and it talks to the daemon over the same local API as the Web CMS: a headless VPS keeps running without it (the Web CMS prompt modal still works), and no flag is needed anywhere. On macOS and Windows the tray icon lives in this process, because the menu-bar and notification-area APIs there require the event loop that owns the main thread; on Linux the tray item stays in the daemon.
   - The card opens at 480x440 and is **resizable**: it follows the space it is given, the rows re-wrap as the window narrows and the request scrolls inside it when the window is shorter than the card needs, so one dialog serves a 1024x600 netbook and a 4K desktop. On Linux the window also only exists while a request is on screen - the Wayland protocol cannot unmap a window, so the client polls the daemon with no window in between and opens a fresh card per request - while macOS and Windows keep one window for the whole run and hide it between requests, since the tray icon they own lives in that event loop.

8. **Android System Passkey Provider (Android 14+):**
   - Acts as a system-level Passkey / Credential Provider via Android Credential Manager API.
   - Minimal Android UI: single ON / OFF switch to run the background service daemon.
   - 100% full feature parity with Web CMS at `http://localhost:10209` accessible directly on mobile browser.
   - Uses **Android BiometricPrompt** (Fingerprint, Face Unlock, or Lock Screen PIN/Pattern) for instant native verification instead of the desktop PIN modal.
---

## 🚀 Installation & Usage

### 1. Install via [mise](https://mise.jdx.dev/) (Recommended)

You can install and update the `vrtfido` binaries directly from GitHub Releases on **Linux, macOS and Windows** with `mise`:

```bash
# Global install
mise use -g github:manhavn/vrtfido

# Or install for current directory/project
mise use github:manhavn/vrtfido

# Or run directly without installation
mise x github:manhavn/vrtfido -- vrtfido --daemon
```

Or add to your `mise.toml`:

```toml
[tools]
"github:manhavn/vrtfido" = "latest"
```

`mise` reads the operating system, the CPU architecture and the C library from the file name, so the release assets carry them explicitly:

| Machine | Asset |
|---|---|
| Linux x86_64 (glibc) | `vrtfido-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 (glibc) | `vrtfido-aarch64-unknown-linux-gnu.tar.gz` |
| Linux x86_64 (musl) | `vrtfido-x86_64-unknown-linux-musl.tar.gz` |
| Linux aarch64 (musl) | `vrtfido-aarch64-unknown-linux-musl.tar.gz` |
| macOS Intel | `vrtfido-x86_64-apple-darwin.tar.gz` |
| macOS Apple silicon | `vrtfido-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `vrtfido-x86_64-pc-windows-msvc.zip` |
| Windows arm64 | `vrtfido-aarch64-pc-windows-gnullvm.zip` |

Every archive unpacks to binaries at its root: `vrtfido` (the daemon) plus `vrtfido-gui` (the prompt window, `.exe` on Windows) in the `gnu`, macOS and Windows archives, and the statically linked daemon alone in the `musl` ones. Each archive is published together with its `<archive>.sha256` checksum. The Linux and Windows archives are built by `build-cross.sh`, the macOS ones on a Mac; see [release-build.md](release-build.md).

**Platform support**

- **Linux** — everything: the daemon, the Web CMS on port **10209**, PIN and passkey management, the fingerprint sensor, the tray icon, the `vrtfido-gui` prompt window, and the virtual FIDO2 USB key that `--uhid` creates on `/dev/uhid`.
- **macOS** and **Windows** — the daemon, the Web CMS on port **10209**, PIN and passkey management, fingerprint management, the tray icon and the `vrtfido-gui` prompt window. The USB sensor is driven through libusb, so on Windows the `3274:8012` dongle has to be bound to **WinUSB** first (Zadig can do that): its own driver claims the device and locks libusb out.
- **No kernel virtual device on macOS or Windows.** `/dev/uhid` has no equivalent on those systems, and publishing a virtual USB HID authenticator there requires a signed kernel driver — which a `mise` install can neither ship nor install. Browsers on macOS and Windows can still be served by the bundled browser extension, which talks to the daemon over its local API and shows the passkey prompt itself.

### 2. Granting `/dev/uhid` Access Permissions (Linux)

On Linux, the virtual FIDO2 device is **opt-in**: only a run started with `--uhid` opens `/dev/uhid`, and only then does VrtFido check the node and request elevated access via `sudo`/`pkexec` when it is not writable. A run without the flag serves the Web CMS only and never touches `/dev/uhid`, so it never prompts for a password. macOS and Windows have no such device and need no step here.

To configure a permanent udev rule (avoiding password prompts):

```bash
echo 'KERNEL=="uhid", MODE="0666"' | sudo tee /etc/udev/rules.d/99-uhid.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### 3. Build & Run from Source

```bash
# Build release binary
cargo build --release

# Build the daemon plus the prompt window (`gui` adds the `vrtfido-gui` binary; this is
# what the release archives do):
cargo build --release --features gui

# Run normally (default 10 fingerprints limit)
./target/release/vrtfido

# Run in background (DAEMON MODE):
./target/release/vrtfido --daemon

# Run as daemon with PostgreSQL and unlimited fingerprints:
./target/release/vrtfido --database "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres" --unlimited-fps --daemon

# Stop running vrtfido process (foreground or daemon):
./target/release/vrtfido --quit

# Clear logs via CLI:
./target/release/vrtfido clean-logs
./target/release/vrtfido --clean-logs auth
./target/release/vrtfido --clean-logs debug

# View daemon log file:
tail -f /tmp/vrtfido.log

# Run with UNLIMITED FINGERPRINTS (--unlimited-fps or -u):
./target/release/vrtfido --unlimited-fps

# Run with debug mode enabled:
./target/release/vrtfido --debug

# Create the virtual FIDO2 device on /dev/uhid (off by default; asks for sudo/pkexec once if the node is not writable):
./target/release/vrtfido --uhid

# Bind the dashboard to a specific address/port (defaults: 0.0.0.0:10209, every interface;
# the same two values are read from HOST and PORT). The service has no built-in
# authentication, so who can reach it is decided by the bind address you choose:
./target/release/vrtfido --host 127.0.0.1 --port 8080

# Impersonate Google Password Manager's AAGUID instead of the project AAGUID:
./target/release/vrtfido --uhid --google-aaguid
```

### 4. Release Builds

Release targets are built with `--features gui` — that feature adds the `vrtfido-gui` prompt-window binary next to the daemon, so one archive serves the desktop — except the static `musl` archives, which stay CLI-only.

**Linux and Windows come from the local script.** `build-cross.sh` cross-builds all six packages with `cargo-zigbuild` (Linux) and `cargo-xwin` (Windows MSVC), so one run on this machine produces them:

```bash
# Build everything (the script installs its own prerequisites):
./build-cross.sh

# Linux only:
TARGETS=x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu ./build-cross.sh

# Or the Windows packages without the LLVM/nasm install, using zig's toolchain:
TARGETS=x86_64-pc-windows-gnu,aarch64-pc-windows-gnullvm ./build-cross.sh
```

`zig` and `cargo-zigbuild`/`cargo-xwin` are installed through [mise](https://mise.jdx.dev/) and `cargo install` when they are missing. The Windows MSVC targets additionally need `clang-cl`, `lld-link`, `llvm-lib` and `nasm`, which mise does not carry: the script installs those with the system package manager — `sudo apt install -y clang lld llvm nasm` on Debian/Ubuntu — the one place it asks for a password. `cargo-xwin` downloads Microsoft's CRT and Windows SDK headers once into `~/.cache/cargo-xwin`.

Release packages (`.tar.gz`/`.zip`) and checksums (`.sha256`) are moved into `releases/`:
- `vrtfido-x86_64-unknown-linux-gnu.tar.gz`
- `vrtfido-x86_64-unknown-linux-musl.tar.gz`
- `vrtfido-aarch64-unknown-linux-gnu.tar.gz`
- `vrtfido-aarch64-unknown-linux-musl.tar.gz`
- `vrtfido-x86_64-pc-windows-msvc.zip`
- `vrtfido-aarch64-pc-windows-gnullvm.zip`

The `gnu`, macOS and Windows archives carry the prompt window and the `musl` archives do not, so one run serves both a desktop and a server:

- `vrtfido-<target>.tar.gz` (`gnu`): `vrtfido` (daemon) plus `vrtfido-gui` (the prompt window)
- `vrtfido-<target>.tar.gz` (`musl`): `vrtfido` only, statically linked
- `vrtfido-<target>.zip` (Windows): `vrtfido.exe` plus `vrtfido-gui.exe`

The `gnu` packages pin an explicit glibc floor (`GLIBC_FLOOR`, default `2.17` — e.g. `GLIBC_FLOOR=2.28 ./build-cross.sh`), because linking against whatever the build machine happens to ship silently raises the minimum libc every user needs.

**macOS is built on a Mac**, by `build-mac.sh`, which is the one script that cannot run anywhere else: the Apple SDK may not be used off Apple hardware. It builds both architectures and refuses any other host with that reason, and `build-cross.sh` refuses the `*-apple-darwin*` targets with a pointer to it — one way to build each package. A Mac run of `./release-build-all.sh` adds that step automatically; the script starts `xcode-select --install` by itself when the command line tools are missing. The asset names are fixed, because `mise` picks an archive by the OS and CPU it reads in that name.

The daemon starts the window itself and falls back to headless mode whenever the host cannot run it — no display, or a failed start — so one archive serves a desktop laptop and a headless VPS with no flag and no per-machine configuration. The window is self-contained as far as toolkits go: `vrtfido-gui` draws through egui/eframe (winit + OpenGL 3.3 / GLES 3.0) and ships its own fonts and widgets, so no GTK or Qt has to be present, and it can also be started by hand for debugging. What it does need at runtime is a display, a GL driver, and `libxkbcommon` (both Wayland and X11) — plus `libxkbcommon-x11` on an X11 session, which every X11 desktop already has. When one of those is missing the daemon says so and keeps running headless.

Every release package (browser extensions, Android APK, CLI and GUI) can be built with a single command instead:

```bash
./release-build-all.sh
```

Each build type drops its previous output and stages the new one in `releases/`, so that directory always holds the current release set.

### 5. Getting Started

1. Start the daemon with `--uhid` (the virtual device is off by default) and open Web CMS in your browser: **http://localhost:10209**
2. In another tab, open a test site: **https://webauthn.io/**
3. Enter any username $\rightarrow$ Click **Register** or **Authenticate**.
4. The popup window on Web CMS will appear for you to enter your 6-digit PIN or touch the fingerprint sensor.
5. **Device identity:** Linux sees the virtual authenticator as `HID_ID=0003:5652:F1D0` with `HID_NAME=VrtFido - Virtual FIDO2 Authenticator` (`udevadm info /dev/hidrawN`, `/sys/class/hidraw/*/device/uevent`); WebAuthn clients read the AAGUID from `authenticatorGetInfo` and from `authData` — the project AAGUID `e672fbec-badd-58f1-a951-dcfa1a7f2b43` by default, or Google Password Manager's `ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4` when the daemon runs with `--google-aaguid` — and take the CTAP 2.1 `transports` member (`ble`, `hybrid`, `internal`, `nfc`, `usb`) from `authenticatorGetInfo` for the transport list they return with a credential.


### 6. Android Passkey Provider Build & Deployment

On Linux x86_64, build a **signed release APK** with one command (internet required; sudo may prompt if host utilities are missing):

```bash
./build-android.sh
```

Output: `releases/app-release.apk` (Gradle writes it under `android/app/build/outputs/apk/release/` first, then the script moves it into `releases/`). For a debug build, run `./build-android.sh debug`.

Install it on a connected phone with:

```bash
./install-android.sh             # picks release, then debug, APK
./install-android.sh --reinstall # uninstall first (deletes app settings and passkeys)
```

The script locates `adb` (PATH, `./.android-build/sdk`, `~/Android/Sdk`, `ANDROID_HOME`, or `ADB=/path/to/adb`), refuses to guess when several devices are attached unless `ANDROID_SERIAL` is set, and turns the usual `adb install` failures into instructions: no device (`USB debugging`, plus vivo/iQOO's `USB debugging (Security settings)` and `Install via USB`), `unauthorized`, missing udev permission, and `INSTALL_FAILED_UPDATE_INCOMPATIBLE`. That last one is expected here because the debug APK is signed with the Android debug key and the release APK with the local release key, so **switching between `./build-android.sh` and `./build-android.sh debug` requires `--reinstall`**, which removes the existing app and its `authenticator.db`. Success is verified with `pm path`, not with the installer's exit code alone.

On vivo/iQOO (OriginOS) the package chooser runs a `Chăm sóc bảo mật — Đang thực hiện quét sâu` scan before it renders the install button. That scan service can wedge, after which the dialog never gets a button and the install either hangs or times out as `INSTALL_FAILED_ABORTED: User rejected permissions`. Each attempt is bounded by `VRTFIDO_INSTALL_TIMEOUT` (default 180s); on a hang or that abort the script force-stops `com.android.packageinstaller` and `com.vivo.safecenter` — which clears the wedged state without a reboot — and retries once, with `adb reboot` left as the fallback. Two further vivo quirks: the ROM's own package record can survive an uninstall (`installed=false`, `ceDataInode=-1`, empty `pm path`) and still block a new signature until the record is removed, which `--reinstall` does; and the on-device toggles are `USB debugging`, `USB debugging (Security settings)` and `Install via USB`.

On a host whose udev rules grant no access to an ADB interface (`ff/42/01`; Ubuntu's `70-uaccess.rules` only tags cameras), `adb devices` lists the phone as `no permissions` and the install aborts. Allow the phone's USB vendor ID — for vivo/iQOO that is `2d95`:

```bash
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="2d95", GROUP="plugdev", MODE="0660"' | sudo tee /etc/udev/rules.d/51-android.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

The script installs missing host utilities with apt/dnf/pacman, bootstraps Rust if needed, downloads JDK 17, Android SDK/NDK, Gradle and `cargo-ndk`, accepts SDK licenses, builds both native ABIs and verifies the release APK signature. Downloads and a generated local signing key live under `.android-build/` (override with `VRTFIDO_ANDROID_CACHE`); existing `ANDROID_HOME`/`ANDROID_NDK_HOME` are respected. **Back up `.android-build/signing/vrtfido-release.p12` and `.android-build/signing/password` securely**: without both files, a later build cannot update an installed release. For production, set all four variables `VRTFIDO_KEYSTORE`, `VRTFIDO_KEYSTORE_PASSWORD`, `VRTFIDO_KEY_ALIAS`, `VRTFIDO_KEY_PASSWORD` to sign with your own keystore. No key or password is committed. Native, Gradle or signature failures stop the build.

**Android 14+ usage:**
   - Install the generated APK, configure **Host (IPv4)** and **Port** before switching ON. Defaults: `0.0.0.0:10209`; settings persist across app restarts. Use `127.0.0.1` if access must stay on the phone.
   - **Daemon parameters (CLI parity):** the main screen also exposes the desktop CLI options — **Database** (`--database` / `DATABASE_URL`: a file name, `sqlite:…`, or a `postgresql://`, `mysql://`, `mariadb://`, `mongodb://`, `libsql://` URL), **DB type** (`--db-type`, optional; auto-detected when empty), **Auth token** (`--auth-token` for LibSQL/Turso), plus the boolean flags **--debug** and **--unlimited-fps** as checkboxes. A relative file name resolves inside the app's private storage; the default is `authenticator.db`. Parameters are applied at daemon start and persisted with the rest of the settings.
   - The daemon keeps **two separate SQLite files** for offline operation: a shadow for reads when the primary disconnects, and a durable queue for writes replayed in order when it reconnects. A failed primary connection does **not** turn the Android service OFF: the local shadow and queue open first, and connection attempts run in the background every five seconds. On a fresh install without a prior shadow, remote data is unavailable until the primary connects. Android passes explicit paths in the native daemon options: for a local `authenticator.db`, `authenticator.shadow.db` and `authenticator.queue.db` live next to it under app-private `filesDir` (including `sqlite:authenticator.db`). Remote or externally located primary databases use separate, spec-derived filenames under app-private `filesDir`. No offline cache defaults to shared/public storage.
   - **The Database field is masked.** A connection string can carry credentials (`mongodb://user:password@host/db`), so the field renders like a password box with an eye button that reveals it on demand; every app launch and screen rotation starts masked again.
   - ON turns green after the native HTTP server answers `/api/health`, which does not query the primary database. Failure to open either local sidecar or to bind the server still displays a startup error instead of claiming it is running. OFF stops the server.
   - While ON, an ongoing foreground notification displays the bound address. Tapping the notification returns to the app; closing the app UI or swiping its task away does not intentionally stop the service. Android may still stop foreground services via system controls or battery policies. The notification is optional: denying `POST_NOTIFICATIONS` (Android 13+) or turning the app's notifications off only hides that ongoing notice — the daemon still starts and runs, and the status line then says so while keeping the switch ON.
   - Open the Web Dashboard at the shown local URL; when bound to `0.0.0.0`, other devices on the same network can connect using the phone's LAN IP and configured port.
   - **Security:** The current Web CMS/API has no LAN authentication; database export exposes private keys. Binding to `0.0.0.0` makes this data accessible to other devices that can reach the phone. Use `127.0.0.1` unless the network is trusted and access is restricted externally.
   - Enable **VrtFido Passkey Provider** in Android settings (**Settings → Passwords & accounts → VrtFido**), turn the daemon ON, and keep it ON while using passkeys. System biometrics / screen unlock is used for credential operations.
   - **Browsers (Chrome on Android 14+)** route WebAuthn through Android Credential Manager, which only lists providers that declare the passkey capability. With the provider enabled and the daemon ON, `VrtFido` appears as an entry when a site (for example webauthn.io) asks to register or sign in with a passkey. Browsers send only a client-data hash, so the created credential is bound to the site's own origin and challenge; the app never sees the visited domain.
   - **Account already known → no list.** When the site pins the account (`allowCredentials` names a credential), VrtFido returns only that single matching passkey and marks it auto-selectable; Android Credential Manager then goes straight to the biometric / screen-lock prompt, like a desktop authenticator, instead of asking you to choose an account. When the site sends no account at all (usernameless / conditional UI), the system lists the matching passkeys for that site so you can pick one.
   - If `VrtFido` is missing from the browser's passkey prompt, re-check that the provider is enabled: the capability declaration is read when the service is registered, so an app update can require re-enabling it.
   - **Authenticator identity (AAGUID):** every credential is attested with `fmt: "none"` and Google Password Manager's AAGUID `ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4`, emitted by both the CTAP2 `authenticatorGetInfo` response and `authData`. The phone has no command line, so the JNI bridge keeps that identity; the desktop CLI stays opt-in through `--google-aaguid`, where the default is the project AAGUID `e672fbec-badd-58f1-a951-dcfa1a7f2b43` (`uuid5(NAMESPACE_URL, "https://vrtfido.local/webauthn-cms")`). Relying parties that restrict authenticators by AAGUID can allow-list the value their surface reports. A human-readable provider name is resolved by the client from vendor metadata (FIDO MDS) or from the OS provider registry, so it does not appear in UIs that look the AAGUID up in a registry — and since the value is only written at creation time, switching identity only affects newly created credentials.
   - **Language (EN / VI):** the main screen carries an **EN / VI** switch and the Web CMS has the same control in its header. English is the default; the choice is written to the database (`POST /api/settings`) and shared by both surfaces, so the app, the dashboard and a later restore all follow the same language.
   - `--unlimited-fps` / `--unlimited-fingerprints` is not exposed on the phone: Android has no USB fingerprint sensor, so the fingerprint slots cannot be enrolled there and the 10-slot limit is irrelevant. The flag stays available on the desktop CLI and is read by the Web CMS from the running daemon.
   - **Nothing has to be re-entered:** host, port, database spec, DB type, auth token and the `--debug` / `--unlimited-fps` flags are cached on the device and mirrored into the database. If the daemon was ON when you closed the app, the next launch starts it again automatically with the same parameters.
   - **JSON backup / restore:** with the daemon ON, **Xuất JSON** writes a full backup through the system file picker and **Nhập JSON** imports one. Both use exactly the same file format as the desktop CLI (`--export` / `--import`), so a backup can be moved between the phone and Ubuntu in either direction and restored on either side. Importing merges the file into the current database (credentials, audit logs, debug logs, fingerprint slots and PIN settings), overwriting entries that share an ID, so the same backup can be imported repeatedly.
---

## 📂 Database & Data Migration

Supported database backends: **SQLite**, **PostgreSQL**, **LibSQL (Turso)**, **MySQL**, **MariaDB**, and **MongoDB**.

### 1. Database Configuration via CLI or Environment Variables

By default, the application uses local SQLite file `authenticator.db`. Configure another database via `--database` / `--db` / `-D` or `DATABASE_URL`:

```bash
# SQLite with custom file:
./vrtfido --database my_data.db

# PostgreSQL:
./vrtfido --database "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres"

# LibSQL / Turso Cloud (with auth token):
./vrtfido --database "libsql://my-db.turso.io" --auth-token "my-turso-token"

# MySQL / MariaDB:
./vrtfido --database "mysql://root:secret@127.0.0.1:3306/vrtfido"
./vrtfido --database "mariadb://root:secret@127.0.0.1:3306/vrtfido"

# MongoDB (replica set or standalone; credentials in the URL):
./vrtfido --database "mongodb://root:secret@127.0.0.1:27017/vrtfido"
./vrtfido --database "mongodb+srv://user:pass@cluster.example.net/vrtfido"

# Or configure via environment variable:
export DATABASE_URL="postgresql://postgres:vrtfido@127.0.0.1:5435/postgres"
./vrtfido
```

### Offline shadow and write queue

Normal desktop daemon startup uses a **SQLite shadow database for reads** when the configured primary is offline and a **different SQLite database for pending writes**. The daemon starts even when the primary cannot be reached; primary connection attempts and ordered replay run in a background worker every five seconds, without blocking daemon startup or offline requests. The shadow refreshes from an available primary at most once every two seconds. Previously synced data can be read offline, but a fresh shadow cannot supply remote records until the primary has been reached. Do not delete or edit the shadow and queue files while writes are pending.

Replay uses stable IDs and absolute credential counters so ordinary retries do not duplicate logs or increments. Cross-device concurrent changes to the same credential cannot be resolved automatically without a transactional idempotency protocol on the primary; a conflicting replay remains queued and its error is reported rather than discarding the write.

On Ubuntu, **no extra parameters are required**: the daemon creates a private `0700` directory at `/tmp/vrtfido-<uid>/` and two distinct `0600` SQLite files there. Names are derived from the primary database identity (without exposing credentials in the filename), so different primary databases get separate queues. **`/tmp` can be cleared on reboot or by system cleanup; pending writes will then be lost.** If pending writes must survive reboot, choose two persistent paths outside `/tmp`:

```bash
./vrtfido --database "postgresql://user:pass@host/db" \
  --shadow-db /private/vrtfido/primary.shadow.db \
  --queue-db /private/vrtfido/primary.queue.db
# Or: SHADOW_DB=/private/vrtfido/primary.shadow.db
#     QUEUE_DB=/private/vrtfido/primary.queue.db
```

Flags take precedence over `SHADOW_DB` and `QUEUE_DB`. Override paths must be writable **local SQLite files**, separate from each other and from the primary SQLite file; neither should point to `:memory:` or a URL. The shadow contains credentials and private keys, and the queue may contain pending credential/security changes: restrict directory and file access (for example, a private `0700` directory and `0600` files), including **existing files** and SQLite `-wal`/`-shm` siblings; protect backups and do not put them on shared/public storage. When switching primary databases, use a distinct pair of sidecars per primary; never replay another primary's pending queue into the new one.

Desktop `--export`, `--import`, and `--clean-logs` operate **directly on the primary** and require it online (rather than silently exporting stale shadow data or queuing migration/cleanup). An `--import` that continues to serve switches to the resilient daemon after the import succeeds. Android requires no extra path options: it creates the shadow and queue SQLite files automatically inside the app's private `filesDir` (application data), not Ubuntu's `/tmp`.

### 2. Export & Import 100% Data

```bash
# 1. Export 100% data to JSON and exit:
./vrtfido --database authenticator.db --export backup.json

# 2. Import JSON file into PostgreSQL and exit:
./vrtfido --database "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres" --import backup.json --exit-after-import

# 3. Import and continue running:
./vrtfido --database "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres" --import backup.json
```

UI settings API:
- `GET /api/settings`: current language and daemon parameters.
- `POST /api/settings`: updates them, for example `{"language":"vi"}`. Supported languages are `en` and `vi`; the value is stored in the database and included in database exports.

Web CMS API endpoints:
- `GET /api/database/export`: Download all database data as JSON.
- `POST /api/database/import`: Upload and import JSON payload into active database.

### 3. Database Schema

* `credentials`: Stores private keys (P-256 SEC1), public keys (COSE), sign counter, and Relying Party metadata.
* `auth_logs`: Audit trail for registration and authentication operations.
* `security_settings`: PIN configuration (hash + salt) and verification policies.
* `fingerprints`: Fingerprint slot mappings and labels.
* `debug_logs`: CTAPHID/CTAP2 packet trace logs and system errors.

For **MongoDB** the same fields live in collections of the same name. The MongoDB auth tokens / TLS material is taken from the connection URL (`mongodb://user:pass@host:port/dbname` or `mongodb+srv://…`). A unique index on `credentials.rp_id + user_name` mirrors the SQL indexes.

## 📜 License
MIT
