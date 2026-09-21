# vrtfido

**vrtfido** is a **Virtual FIDO2 / WebAuthn Authenticator** hardware emulator running on Linux through the kernel character device `/dev/uhid`.

The application includes an embedded **Web CMS Dashboard** on port **10209**, supports multiple database backends (**SQLite**, **PostgreSQL**, **LibSQL/Turso**, **MySQL**, **MariaDB**), features **100% Data Export / Import to JSON** for migration, and supports multi-factor authentication policies (6-digit passkey PIN, hardware USB fingerprint sensor management, and future biometric modalities).

---

## 🌟 Key Features

1. **Kernel Virtual HID (`/dev/uhid`):**
   - Creates a virtual USB HID device with the FIDO Usage Page (`0xF1D0`).
   - All browsers (Chrome, Chromium, Firefox, Edge) automatically recognize it as a physical USB Security Key.
   - Full support for standard CTAP2 commands: `authenticatorGetInfo`, `authenticatorMakeCredential` (Passkey Registration), and `authenticatorGetAssertion` (WebAuthn Sign-in).

2. **Interactive Verification Modal:**
   - When a website (e.g. `webauthn.io`, GitHub, Google) sends a WebAuthn verification request, the Web CMS displays a real-time verification modal.
   - If security is not yet configured: Prompts to set up a 6-digit PIN.
   - If configured: Allows verification via 6-digit PIN or USB fingerprint sensor.

3. **Security & Biometrics Policies:**
   - **6-Digit PIN (Passkey Password):** Enforces 6 numeric digits, hashed with SHA-256 and salt. Supports setup, changing (requires old PIN), and removal.
   - **Fingerprint Management:** Enrolls up to 10 fingerprints (or unlimited with `--unlimited-fps`), with customizable labels and slot deletion.
   - **Future Biometrics:** Modular architecture ready for Face ID, Iris, and Voiceprint extensions.

4. **Web Management CMS (Port 10209):**
   - Modern, lightweight Dark theme embedded directly into the binary (zero Node.js/npm dependencies).
   - Manage registered passkey credentials (Relying Party domain, username, sign count, creation date, last used date).
   - Edit usernames and display names, or delete credentials.
   - **Operational Audit Trail:** Complete operation history with detailed logs.
   - **Debug & Error Logs:** System logs and CTAP2 packet inspection.
   - **Clean Logs:** Dedicated buttons to clear audit logs, debug logs, or all logs at once.

5. **CLI Debug & Log Management:**
   - Debug output disabled by default for clean logs.
   - Enable via `--debug` or `-d` flag to print raw CTAPHID packets and record to `debug_logs`.
   - Clear logs via `--clean-logs` or `clean-logs` [all|auth|debug].

6. **Multi-Database Support & 100% Data Migration:**
   - Connects flexibly to **SQLite**, **PostgreSQL**, **LibSQL (Turso Cloud)**, **MySQL**, and **MariaDB**.
   - Export and Import 100% of data (Credentials, PIN, Fingerprints, Audit Logs, Debug Logs) to a single JSON file.
   - Integrated REST API endpoints `/api/database/export` and `/api/database/import`.

---

## 🚀 Installation & Usage

### 1. Install via [mise](https://mise.jdx.dev/) (Recommended)

You can install and update the `vrtfido` binary directly from GitHub Releases on any Linux machine with `mise`:

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

### 2. Granting `/dev/uhid` Access Permissions

`vrtfido` automatically checks and requests permission via `sudo`/`pkexec` upon startup if `/dev/uhid` is not accessible.

To configure a permanent udev rule (avoiding password prompts):

```bash
echo 'KERNEL=="uhid", MODE="0666"' | sudo tee /etc/udev/rules.d/99-uhid.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### 3. Build & Run from Source

```bash
# Build release binary
cargo build --release

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
```

### 4. Local Cross-Compilation for GitHub Releases

The repository includes `build-cross.sh` (using `cargo-zigbuild`) to compile release binaries across architectures (x86_64 GNU/musl, aarch64 GNU/musl) locally:

```bash
# Install cross-build prerequisites:
cargo install cargo-zigbuild --locked
mise use -g zig

# Build all targets:
./build-cross.sh

# Or build specific targets:
TARGETS=x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu ./build-cross.sh
```

Release packages (`.tar.gz`) and checksums (`.sha256`) are generated in `dist/packages/`:
- `vrtfido-x86_64-unknown-linux-gnu.tar.gz`
- `vrtfido-x86_64-unknown-linux-musl.tar.gz`
- `vrtfido-aarch64-unknown-linux-gnu.tar.gz`
- `vrtfido-aarch64-unknown-linux-musl.tar.gz`

### 5. Getting Started

1. Open Web CMS in your browser: **http://localhost:10209**
2. In another tab, open a test site: **https://webauthn.io/**
3. Enter any username $\rightarrow$ Click **Register** or **Authenticate**.
4. The popup window on Web CMS will appear for you to enter your 6-digit PIN or touch the fingerprint sensor.

---

## 📂 Database & Data Migration

Supported database backends: **SQLite**, **PostgreSQL**, **LibSQL (Turso)**, **MySQL**, and **MariaDB**.

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

# Or configure via environment variable:
export DATABASE_URL="postgresql://postgres:vrtfido@127.0.0.1:5435/postgres"
./vrtfido
```

### 2. Export & Import 100% Data

```bash
# 1. Export 100% data to JSON and exit:
./vrtfido --database authenticator.db --export backup.json

# 2. Import JSON file into PostgreSQL and exit:
./vrtfido --database "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres" --import backup.json --exit-after-import

# 3. Import and continue running:
./vrtfido --database "postgresql://postgres:vrtfido@127.0.0.1:5435/postgres" --import backup.json
```

Web CMS API endpoints:
- `GET /api/database/export`: Download all database data as JSON.
- `POST /api/database/import`: Upload and import JSON payload into active database.

### 3. Database Schema

* `credentials`: Stores private keys (P-256 SEC1), public keys (COSE), sign counter, and Relying Party metadata.
* `auth_logs`: Audit trail for registration and authentication operations.
* `security_settings`: PIN configuration (hash + salt) and verification policies.
* `fingerprints`: Fingerprint slot mappings and labels.
* `debug_logs`: CTAPHID/CTAP2 packet trace logs and system errors.

## 📜 License
MIT
