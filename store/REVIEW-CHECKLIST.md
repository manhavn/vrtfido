# Store submission checklist — Chrome Web Store & addons.mozilla.org

Paste-ready values for the fields that decide whether VrtFido passes review. Keep every answer
consistent with `PRIVACY.md` and with the extension's actual behaviour — the stores treat
discrepancies between the dashboard, the policy and the code as a violation.

Privacy policy URL (use everywhere a URL is asked for):

```
https://github.com/manhavn/vrtfido/blob/main/PRIVACY.md
```

---

## 1. Chrome Web Store — Privacy practices tab

### Single purpose description

```
VrtFido is a virtual FIDO2/WebAuthn authenticator. It lets the user create and use passkeys on any
website by forwarding WebAuthn requests to a VrtFido server the user runs (by default on
127.0.0.1:10209), after the user approves each request in an on-page dialog.
```

### Permissions justification

- **`storage`**

```
Stores the user's VrtFido server address (protocol, host, port) and the interface language in
storage.sync so settings survive browser restarts. No user data is stored by the extension.
```

- **Host permission — `<all_urls>`**

```
A WebAuthn passkey request can be initiated by any website the user visits, so the content script
must be present on all origins to intercept navigator.credentials.create()/get() and forward the
request to the authenticator the user configured. The script only relays the WebAuthn request and
shows the approval dialog; it never reads, collects or modifies page content. Nothing is transmitted
anywhere unless the user presses "Approve" in that dialog.
```

### Remote code

Select **“No, I am not using remote code.”** All JavaScript ships inside the package; the extension
never loads or evaluates code from a remote source.

### Data usage — check exactly these boxes

- [x] **Authentication information**
- [x] **Personally identifiable information**

Leave the others unchecked: the extension does not collect health, financial, location, personal
communications, web history, user activity or website content. (The site domain passed as the
WebAuthn relying-party ID belongs to the request the user itself triggered, not to browsing history.)

### Limited Use certifications — check every statement

All statements in the certification group must be checked. They are true for VrtFido: data is used
only to provide the disclosed single purpose, is not sold, is not transferred to third parties, is
not used for advertising, and is not read by humans.

### Privacy policy

- Item-level field and the account-level field on the Developer Dashboard: the URL above
  (`https://github.com/manhavn/vrtfido/blob/main/PRIVACY.md`).
- Remote-code and privacy answers must match the uploaded package version.

### Test instructions (Reviewer notes)

```
VrtFido is a client for a WebAuthn authenticator the user runs themselves, so the extension is
inert without that server.

1. Install and start the VrtFido server (free, MIT licensed):
     mise use -g github:manhavn/vrtfido
     vrtfido --daemon
   On Ubuntu, grant /dev/uhid access once if you also want the native security-key path
   (`vrtfido --uhid`; the extension itself needs only the HTTP server):
     echo 'KERNEL=="uhid", MODE="0666"' | sudo tee /etc/udev/rules.d/99-uhid.rules
   The server then listens on http://127.0.0.1:10209 and the extension's popup shows a green
   "active" badge.
2. Open https://webauthn.io, type any username and click "Register".
3. The extension shows an approval dialog; press "Approve" (set a 6-digit PIN if prompted).
4. The site confirms registration. Sign out and use "Authenticate" with the same username to test
   the login path.

No account, credentials or payment are required. If the server is not running the extension shows
"cannot connect" and sends nothing.
```

---

## 2. addons.mozilla.org — listing fields

`amo-metadata.json` already supplies name, summary, categories and license for API submissions. The
same values go into the Describe Add-on form:

| Field | Value |
| --- | --- |
| Name | `VrtFido Passkey Provider` |
| Summary | see `amo-metadata.json` → `summary` |
| Categories | `Privacy & Security` (at most 2; Android uses the same slug) |
| License | `MIT` |
| This add-on has a privacy policy | **checked** — paste the content of `PRIVACY.md` |
| Experimental | unchecked |

### Notes for Reviewers

```
VrtFido is a client for a WebAuthn authenticator the user runs themselves; without that server the
extension only shows "cannot connect" and transmits nothing.

Setup (free, MIT):
  mise use -g github:manhavn/vrtfido
  vrtfido --daemon
On Ubuntu grant /dev/uhid once if you also want the native security-key path (`vrtfido --uhid`;
the extension itself needs only the HTTP server):
  echo 'KERNEL=="uhid", MODE="0666"' | sudo tee /etc/udev/rules.d/99-uhid.rules

Test: open https://webauthn.io, enter any username, click Register, then press "Approve" in the
extension dialog (set a 6-digit PIN when asked). Repeat with "Authenticate" to test sign-in.

Data handling: the extension sends WebAuthn request/response data to the address the user
configures (default 127.0.0.1:10209) and only after the user presses Approve. It uses no remote
code, no analytics, and no developer-operated server.
```

### `data_collection_permissions`

The manifest declares `required: ["authenticationInfo", "personallyIdentifyingInfo"]`, matching the
Chrome disclosures. The extension requests no optional categories.

---

## 3. Common rejection causes — already handled

| Cause | Status |
| --- | --- |
| Missing privacy policy while transmitting data | `PRIVACY.md` + URL set in both dashboards |
| Under-declared data types | Authentication info + PII declared in the manifest and in both forms |
| `UNSAFE_VAR_ASSIGNMENT` / dynamic `innerHTML` (AMO flags it as rejection-prone) | Removed — `addons-linter` reports 0 errors / 0 warnings |
| Permissions broader than needed | Only `storage` + host access required for the single purpose, each justified above |
| Remote code | None; declared as such |
| Reviewer cannot exercise the feature | Test instructions above stand up the whole flow in a few commands |
| Version not increasing on update | `publish-firefox.sh` / `publish-chrome.sh` offer a version bump before building |
