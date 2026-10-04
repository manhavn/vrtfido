# VrtFido Browser Extension — Privacy Policy

Last updated: 2026-10-04

VrtFido is a virtual FIDO2/WebAuthn authenticator. This policy covers the browser extension for
Chrome/Chromium/Brave/Edge and Firefox (the "extension"). It explains what data the extension
handles, why, where it goes, and how you stay in control.

## Summary

- The extension talks **only** to the VrtFido server **you** configure (default `http://127.0.0.1:10209`).
- There is **no** developer-operated backend, **no** analytics, **no** advertising, **no** tracking.
- Data is transmitted only after you explicitly approve each passkey request in the on-page dialog.

## What data is handled

| Data | Why it is needed | When |
| --- | --- | --- |
| WebAuthn request data: relying-party ID (the site's domain), challenge, `allowCredentials` / `excludeCredentials` credential IDs, and — for registration — the user name / display name the website supplies | Required to create or use a passkey for that site | Only when a website starts a WebAuthn request **and** you press **Approve** |
| Passkey result data: credential ID, public key / attestation, `authenticatorData`, `clientDataJSON`, signature | Required to complete the WebAuthn ceremony | Same as above |
| Extension settings: protocol, host, port, interface language | To reach your VrtFido server and to display the UI in your language | Stored in `storage.sync` in your browser profile |

In the store taxonomies this is **Authentication information** and **Personally identifiable
information** (the user name / display name a website sends is typically an account name or email
address).

The extension does **not** read page content, form data, browsing history, bookmarks, cookies or
keystroke data, does **not** use remote code, and does **not** inject any remote script.

## Where the data goes

Only to the server address **you** configure in the extension popup — by default the VrtFido daemon
on the same computer at `127.0.0.1:10209`. You may point it at a remote host you control; the
operator of that host then handles the data under their own policy. The extension's developer
receives no data at all.

Transmissions between the extension and a program on the same computer are not required to be
encrypted under the Chrome Web Store User Data Policy. If you configure a **remote** host, use
`https://` so traffic is encrypted in transit.

The VrtFido server stores credentials in the local database you chose (SQLite, PostgreSQL, …) and does
not encrypt them by itself — protect the database file and any backups, as described in the project
README.

## What is shared

Nothing is sold, rented, transferred or shared with third parties, except where required by law. Data
is never used for advertising, profiling, creditworthiness, or any purpose unrelated to the passkey
operation you approved.

## Retention

The extension keeps **no copy** of your passkeys. Credentials live in the VrtFido server you run;
delete them there at any time (Web CMS dashboard, CLI, or by deleting the database). Extension
settings remain in your browser profile until you remove the extension.

## Your control

- Every passkey operation shows an approval dialog; pressing **Cancel** prevents any transmission.
- The dialog states which server will receive the data before you approve.
- The "Remember for this run" option, when shown, applies only to the current run of the server
  process, is never persisted, and disappears on restart.
- You choose the server address, and you can disable or remove the extension at any time.

## Chrome Web Store Limited Use disclosure

VrtFido's use of information received from Chrome APIs adheres to the Chrome Web Store User Data
Policy, including the Limited Use requirements. Data is used solely to provide the extension's single
purpose — performing FIDO2/WebAuthn ceremonies against the server the user configured. It is not
transferred to others, not used or transferred for advertising, and not read by humans, except as
permitted by the Limited Use policy. Transmission to a user-specified server is exempt from the
Limited Use restrictions under the User Data Policy FAQ (client applications for user-specified
servers).

## Legal basis and changes

The extension processes data only to perform the action you requested. Material changes to this
policy will be published in this file and noted in the extension's release notes.

## Contact

Questions, access or deletion requests: open an issue at
<https://github.com/manhavn/vrtfido/issues>.
