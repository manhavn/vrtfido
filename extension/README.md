# VrtFido Browser Extension (Platform Passkey Provider)

Cross-browser extension (**Google Chrome**, **Chromium**, **Brave**, **Microsoft Edge**, **Mozilla Firefox**, **Apple Safari**) connecting directly to the **VrtFido HTTP REST API** to act as a native **Platform Passkey Authenticator** (`authenticatorAttachment: "platform"`, `transports: ["internal", "hybrid"]`).

---

## 1. Architecture & Core Features

- **Pure HTTP REST API**: Calls the VrtFido backend (`/api/passkey/create`, `/api/passkey/get`) over HTTP/HTTPS, eliminating any need for local Native Messaging hosts or USB drivers.
- **Deploy Anywhere**: The backend can run locally (`http://127.0.0.1:10209`) or on a remote VPS/cloud server with flexible Host/Port settings.
- **Platform Authenticator Emulation**: Uses official Google Password Manager (GPM AAGUID: `ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4`) and `ES256` ECDSA P-256 keys, passing strict platform verification on sites like Nvidia, Google, and webauthn.io.
- **Mandatory Approval Prompt (Approve / Cancel)**:
  - Whenever a website initiates passkey creation or login, the extension presents an interactive **Modal Prompt** (isolated using Shadow DOM to prevent any website CSS collisions).
  - Never auto-approves silently: user must explicitly click **Approve** or **Cancel** (shortcuts: `Enter` to approve, `Escape` to cancel).
- **Full Discoverable Credential Handling (1-Click Login Without Username)**:
  - When a site triggers authentication without specifying accounts (`allowCredentials` empty):
    - **0 accounts found:** Displays a clear warning that no passkey exists for this domain, safely cancelling the request.
    - **1 account found:** Automatically identifies the stored account, displays the account name, and waits for user confirmation.
    - **Multiple accounts (2+):** Renders an interactive account selector card list (showing username and display name) for the user to choose their preferred identity before approving (matching Web CMS and Android Credential Manager).
- **Integrated Extension CMS Dashboard (similar to the Android App)**:
  - Flexible **Host & Port** configuration with live URL preview.
  - Real-time service status card (Online / Offline indicator, stored passkey count, version, USB sensor / UHID status).
  - Quick actions: Open Web Dashboard, Export JSON database backup, Import JSON database backup.
  - Stored passkeys management: Live search/filter by domain/user, and one-click deletion with confirmation dialog.
- **Full Internationalization (i18n)**:
  - Seamless toggle between **Vietnamese (VI)** and **English (EN)** with 1 click, synchronizing automatically across popup and in-page prompts.
  - Standard WebExtension `_locales` directory structure.
  - Popout button **↗** to open the CMS in a dedicated full-screen browser tab.

---

## 2. Automated Build Scripts

From the repository root directory, run:

```bash
# Build extensions for Chrome, Firefox, and Safari simultaneously:
./build-extension.sh

# Or build individually:
./build-chrome.sh
./build-firefox.sh
./build-safari.sh
```

Build outputs are generated in `dist/`:
- **Chrome / Chromium / Brave / Edge / Opera**: Directory `dist/chrome/` and package `dist/vrtfido-chrome.zip`.
- **Firefox**: Directory `dist/firefox/` and package `dist/vrtfido-firefox.zip`.
- **Apple Safari**: Directory `dist/safari/` and package `dist/vrtfido-safari.zip`.

---

## 3. Installation Guide

### A. For Google Chrome / Chromium / Brave / Microsoft Edge / Opera:
1. Navigate to `chrome://extensions/` (or `edge://extensions/`, `brave://extensions/`).
2. Toggle on **Developer mode** in the top-right corner.
3. Click the **Load unpacked** button.
4. Select the directory:
   ```text
   vrtfido/dist/chrome
   ```

### B. For Mozilla Firefox (including Ubuntu Snap):
1. Open Firefox and go to `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...**.
3. Select the package file:
   ```text
   vrtfido/dist/vrtfido-firefox.zip
   ```

### C. For Apple Safari (macOS & iOS/iPadOS):
Safari packages Web Extensions inside a native macOS/iOS application wrapper via Apple Xcode's `safari-web-extension-converter`:

1. **On a Mac**, run from the project root:
   ```bash
   xcrun safari-web-extension-converter dist/safari --app-name "VrtFido"
   ```
   *(If you run `./build-safari.sh` directly on macOS, it automatically invokes this conversion)*.
2. **Launch in Xcode:**
   - Open the generated `VrtFido.xcodeproj` file in Xcode.
   - Click the **Run** button (`Cmd + R`) to compile and launch the wrapper app.
3. **Enable in Safari:**
   - Open Safari > go to **Settings** (`Cmd + ,`) > **Extensions** tab.
   - Check the box next to **VrtFido Passkey Provider**.
   - *(For development/unsigned extensions: Open the **Develop** menu > check **Allow Unsigned Extensions**)*.

---

## 4. Extension CMS Configuration & Usage

1. Click the **VrtFido** key icon in your browser toolbar.
2. Under **Connection & Authentication Settings**:
   - **Protocol**: Choose `http://` or `https://`.
   - **Host**: Enter your server address (`127.0.0.1` for local, or your VPS/cloud IP).
   - **Port**: Enter the service port (default: `10209`).
   - Confirm the live endpoint in the URL preview box (`http://127.0.0.1:10209`).
3. Click **Save Settings**.
   - The button will display *Saving...* and update to *✓ Saved!*.
   - The status badge will switch to **🟢 VrtFido is active at http://...** once connected.
4. **Quick Management Tools:**
   - Click **Open Web CMS Dashboard** to navigate directly to the advanced web interface.
   - Click **Export JSON** to download a backup file of your credentials.
   - Click **Import JSON** to restore a backup file to the server.
   - Use the search bar in the **Stored Passkeys** card to quickly filter credentials by domain or username, with one-click deletion.
