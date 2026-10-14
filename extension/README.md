# VrtFido Browser Extension (Platform Passkey Provider)

Cross-browser extension (**Google Chrome**, **Chromium**, **Brave**, **Microsoft Edge**, **Mozilla Firefox**, **Apple Safari**) connecting directly to the **VrtFido HTTP REST API** to act as a native **Platform Passkey Authenticator** (`authenticatorAttachment: "platform"`, `transports: ["internal", "hybrid"]`).

---

## 1. Architecture & Core Features

- **Pure HTTP REST API**: Calls the VrtFido backend (`/api/passkey/create`, `/api/passkey/get`) over HTTP/HTTPS, eliminating any need for local Native Messaging hosts or USB drivers.
- **Deploy Anywhere**: The backend can run locally (`http://127.0.0.1:10209`) or on a remote VPS/cloud server with flexible Host/Port settings.
- **Platform Authenticator Emulation**: Reports official Google Password Manager's AAGUID (GPM AAGUID: `ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4`) when the backend is started with `--google-aaguid` (without it the backend attests with its own AAGUID `e672fbec-badd-58f1-a951-dcfa1a7f2b43`) and signs with `ES256` ECDSA P-256 keys, passing strict platform verification on sites like Nvidia, Google, and webauthn.io while the GPM identity is enabled.
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

Packaged archives are staged in `releases/`; the unpacked directories stay in `dist/`:
- **Chrome / Chromium / Brave / Edge / Opera**: Directory `dist/chrome/` and package `releases/vrtfido-chrome.zip`.
- **Firefox**: Directory `dist/firefox/` and package `releases/vrtfido-firefox.zip`.
- **Apple Safari**: Directory `dist/safari/` and package `releases/vrtfido-safari.zip`.

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
   vrtfido/releases/vrtfido-firefox.zip
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

---

## 5. Publishing the Firefox Build (addons.mozilla.org)

`releases/vrtfido-firefox.zip` cannot be installed permanently in release Firefox until Mozilla signs it, so "public" means a signed build on [addons.mozilla.org](https://addons.mozilla.org) (AMO) or a self-hosted signed `.xpi`.

**One command (interactive).** From the repository root:

```bash
./publish-firefox.sh             # hỏi lần lượt: kênh, version, license, API key -> ký -> public
./publish-firefox.sh --dry-run   # build + lint, KHÔNG gọi AMO
./publish-firefox.sh --channel unlisted --version 0.3.6 --yes   # không tương tác
```

The script verifies the toolchain, asks for the channel (`listed` = public AMO listing, `unlisted` = signed `.xpi` you host), optionally bumps the version, runs `build-firefox.sh` (which enforces addons-linter), prompts for the AMO license (listed only) and API key/secret (offer to cache them under `~/.config/vrtfido/amo.env`, `chmod 600`), signs, and finally publishes (AMO submission for `listed`; GitHub Release via `gh` when available for `unlisted`). The manual steps below are what it automates.

**AMO metadata (required for `listed`).** AMO rejects listed versions without a license, so the script writes/updates `amo-metadata.json` (repo root) and passes it with `--amo-metadata`. Default license is `MIT` (override with `--license SLUG`, or supply your own file with `--amo-metadata FILE`). A user-supplied file is validated but never rewritten. For the *first* listed version AMO also requires `name`, `summary`, and `categories` for every compatible application — these live in `amo-metadata.json`:

```json
{
  "name": { "en-US": "VrtFido Passkey Provider", "vi": "VrtFido Passkey Provider" },
  "summary": { "en-US": "…", "vi": "…" },
  "categories": { "firefox": ["privacy-security"], "android": ["privacy-security"] },
  "version": { "license": "MIT" }
}
```

Valid category slugs: <https://addons.mozilla.org/api/v5/addons/categories/>.

**Validation (`mozilla/addons-linter`).** `./build-firefox.sh` runs the official linter on the packaged zip and aborts on errors (`SKIP_LINT=1` skips it, useful offline). Run it standalone with:

```bash
npx --yes addons-linter@latest releases/vrtfido-firefox.zip
```

**Prerequisites.** An AMO account and API credentials from <https://addons.mozilla.org/developers/addon/api/key/>, exported as `WEB_EXT_API_KEY` and `WEB_EXT_API_SECRET`.

**Listed (public store listing).** Create the listing once through the web submission flow at <https://addons.mozilla.org/developers/addon/submit/>, then upload later versions by signing with the `listed` channel (or drag-and-drop the zip on the AMO version page):

```bash
npx --yes web-ext sign \
  --source-dir dist/firefox \
  --api-key "$WEB_EXT_API_KEY" \
  --api-secret "$WEB_EXT_API_SECRET" \
  --amo-metadata amo-metadata.json \
  --channel listed
```

**Unlisted (self-distribution).** Returns a signed `.xpi` you host yourself (for example as a GitHub Release asset):

```bash
npx --yes web-ext sign \
  --source-dir dist/firefox \
  --api-key "$WEB_EXT_API_KEY" \
  --api-secret "$WEB_EXT_API_SECRET" \
  --channel unlisted
```

Signed artifacts are written to `web-ext-artifacts/`. The extension ID (`vrtfido@local`) and the pinned `key` keep the ID stable across versions. When self-hosting, add `browser_specific_settings.gecko.update_url` pointing at your update manifest so installed copies receive new versions.

**Data collection declaration.** The manifest sets `browser_specific_settings.gecko.data_collection_permissions.required: ["authenticationInfo", "personallyIdentifyingInfo"]` because the extension transmits WebAuthn/passkey data — including the user name / display name a website supplies — to the configured VrtFido backend, which may be remote. Since AMO requires this key for new submissions, removing it will block signing. If the backend is restricted to the local machine only, you may reduce it to `["none"]`. The key is honored by desktop Firefox 140+ and Android 142+, which is why the manifest pins `strict_min_version` to `140.0` and `gecko_android.strict_min_version` to `142.0` — versions older than that are not supported, so no unsupported-key warnings are emitted.

**Store compliance.** The public privacy policy is `PRIVACY.md` (used as the privacy policy URL on both stores); `store/REVIEW-CHECKLIST.md` contains paste-ready answers for every Chrome Web Store and AMO review field — single purpose, permission justifications, data-usage checkboxes, Limited Use certifications and reviewer test instructions.

---

## 6. Publishing to the Chrome Web Store

Chrome has no `web-ext` equivalent: the [Chrome Web Store API v2](https://developer.chrome.com/docs/webstore/using-api) needs OAuth, and the very first item must be created in the [Developer Dashboard](https://chrome.google.com/webstore/devconsole/) (upload `releases/vrtfido-chrome.zip`, fill the **Store listing** and **Privacy** tabs). After that, updates can be automated:

```bash
./publish-chrome.sh                      # hỏi lần lượt: version, OAuth, Publisher/Extension ID -> upload -> publish
./publish-chrome.sh --dry-run            # build + in lệnh API, không gọi mạng
./publish-chrome.sh --no-publish --yes   # chỉ upload, giữ ở bản nháp
```

Prerequisites:

1. Register a Chrome Web Store developer account (one-time US$5 fee) and enable **2-Step Verification** for the Google account.
2. In [Google Cloud Console](https://console.developers.google.com): enable **Chrome Web Store API**, configure an OAuth consent screen, then create an **OAuth client ID** of type *Web application* with `https://developers.google.com/oauthplayground` as an authorized redirect URI.
3. Obtain a refresh token from the [OAuth 2.0 Playground](https://developers.google.com/oauthplayground) using your own client ID/secret and the scope `https://www.googleapis.com/auth/chromewebstore`.
4. Note your **Publisher ID** (Dashboard → Publisher → Settings) and the extension's **Item ID**.

The script reads `CWS_CLIENT_ID`, `CWS_CLIENT_SECRET`, `CWS_REFRESH_TOKEN`, `CWS_PUBLISHER_ID`, `CWS_EXTENSION_ID` from the environment or from `~/.config/vrtfido/cws.env` (it offers to save them there with `chmod 600`). It refreshes the access token, checks `fetchStatus`, uploads the zip, then calls `publish`.

Notes:
- Every upload must use a **higher `version`** than the published one — the script offers a patch/minor/major bump.
- Items are always published with the existing visibility settings.
- Because the extension transmits authentication data to the configured VrtFido backend, the Dashboard **Privacy practices** tab needs a declared data usage and a privacy policy URL.
