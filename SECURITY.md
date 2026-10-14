# Security Policy

## Status

FSS Mobile is a **preliminary (0.x) release**. Its cryptography reuses the design of File Secure Suite desktop and has been cross-tested against the desktop core and OpenSSL, but the app has **not had an independent security review** and has been tested on only a few devices. Take this into account before relying on it for highly sensitive material.

## Supported Versions

| Version | Supported |
|---|---|
| 0.5.x   | ✅ |
| < 0.5.3 | ❌ (internal test builds, never published) |

Only the latest release receives security fixes.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting: go to the repository's **Security** tab → **Report a vulnerability**. This opens a private advisory visible only to the maintainer until a fix is ready.

Please include, where possible: the app version (shown under the app name), your phone model and Android version, a description of the issue, and steps to reproduce it. You will receive an acknowledgement and, once the issue is confirmed and fixed, credit in the release notes (unless you prefer to remain anonymous).

## Cryptographic Design

FSS Mobile uses the same primitives and container format as File Secure Suite desktop:

- **RSA-4096 with OAEP** (SHA-256, MGF1-SHA-256) to wrap a random 256-bit AES key, in public-key (hybrid) mode. Keys of 4096 to 8192 bits are accepted; smaller keys are rejected.
- **AES-256-GCM** for authenticated payload encryption.
- The authenticated **FSS2** container format, unchanged from the desktop (see the desktop's [`FORMAT_SPECIFICATIONS.md`](https://github.com/marianopeluso/FileSecureSuite/blob/main/FORMAT_SPECIFICATIONS.md)). A text with an attachment is a ZIP (`message.txt` + the file) inside an FSS2 file container.
- **PBKDF2-HMAC-SHA-256 with 600,000 iterations** wherever a key is derived from a password.

### Key and data storage on the phone

- **Private key**: encrypted with your FSS password (PBKDF2-HMAC-SHA-256, 600,000 iterations, random 16-byte salt, AES-256-GCM), then encrypted again with an AES-256-GCM key held by the **Android Keystore**, which never leaves the device's secure key storage.
- **Contacts and your public key**: encrypted with AES-256-GCM under a random 256-bit data key. That data key is stored inside the password-protected key file and, for fingerprint/PIN entry, in a separate Android Keystore key that requires user authentication.
- All app files live in the app's private storage and are **excluded from cloud backup and device-to-device transfer** (`allowBackup="false"` and data extraction rules).
- **Delete key and all data** deletes the Keystore key first (crypto-erasure), then the files.

### Exports

- **Private key export**: PKCS#8 PEM encrypted with PBES2 (PBKDF2-HMAC-SHA-256, 600,000 iterations, AES-256-CBC), readable by File Secure Suite desktop and OpenSSL.
- **Contacts backup**: an FSS2 password container (`.aes`), protected by its own password of at least 12 characters, deliberately separate from the key password.

## What FSS Mobile Protects

- The **confidentiality** of a message or file, given an uncompromised private key and a strong key password
- The **integrity** of encrypted containers: a modified, truncated or tampered container fails authentication instead of producing altered text
- The private key **at rest** on the phone, behind both your password and the device's Keystore
- **Anonymity of the key itself**: a key identifies only itself, never a verified real-world identity

## What FSS Mobile Does NOT Protect

- **A compromised phone.** Malware, a rooted or tampered device, accessibility-service abuse or screen recorders can bypass this or any encryption app.
- **Your keyboard.** Text you type into FSS Mobile passes through your keyboard app. A third-party keyboard with cloud features or "learning" could see the plaintext before it is encrypted. Prefer a keyboard you trust, and turn off cloud sync and suggestions-learning for sensitive messages.
- **Metadata.** The chat or e-mail app that carries the message still knows who writes to whom, when, and how big the message is.
- **Sender identity or authenticity.** There is no digital signature: a valid message proves only that it can be opened by the matching private key, not who wrote it.
- **Saved attachments.** Once you save a decrypted attachment, it is a normal, unencrypted file in the folder you chose.
- **Forward secrecy.** Whoever later obtains your private key and its password can decrypt any message previously recorded for it.
- **Post-quantum security.** RSA-4096 is not post-quantum.
- **A forgotten password or an uninstalled app.** There is no recovery mechanism, backdoor or key escrow. Uninstalling the app or clearing its data deletes the key and the contacts permanently, so keep your own exported backups.

## Hardening Measures

- No Internet permission and no storage permission: the app cannot send anything anywhere by itself
- Screenshots and screen recording of the app are blocked (`FLAG_SECURE`), including on the QR scanner
- The camera is used only by the live QR scanner; frames are analysed in memory and never saved
- Decrypted text is never written to disk; copied decrypted text is cleared from the clipboard after 15 seconds (if it is still there) and is marked as sensitive, so Android 13 and later hide it from clipboard previews. Keyboard apps with their own clipboard history may still keep a copy
- The private key unloads when the app locks: on leaving the app after a chosen delay, and after 2 minutes without interaction
- The phone's fingerprint/PIN only opens the app; loading the private key always needs the FSS password
- Key passwords must be at least 12 characters long
- Size limits: 1 MiB for text and 25 MB for attachments; oversized or malformed input is rejected before decryption
- The app warns before saving attachments, more strongly for programs, scripts, macros, archives and files without an extension

## Recommended Practices

1. Use a long, unique password for your key, and a **different** one for the contacts backup.
2. When you add a contact, compare the key fingerprint with the owner through a separate channel (in person, or in a voice call).
3. Keep an exported, password-protected copy of your private key and a contacts backup **off the phone**, stored separately from the passwords.
4. Lock your phone with a PIN, password or biometrics, and keep Android up to date.
5. Install only APKs whose checksum, GPG signature and signing certificate match the ones published in the [README](README.md#verifying-the-download).

## Verifying Releases

Each release ships the APK with a SHA-256 checksum and a detached GPG signature of that checksum, made with the same GPG key as File Secure Suite desktop (fingerprint `0FD9 7EB8 55F7 C5BB 1048 D424 F204 94B9 FAB5 3C10`, public key in [`fssmobile.asc`](fssmobile.asc)). Every official APK is also signed with the same Android certificate, SHA-256 fingerprint:

`05:F3:80:A3:CC:34:0C:EA:32:53:2E:9B:9D:0C:B0:75:8B:A3:9F:0C:0D:0B:4F:BA:17:01:B1:D6:E3:86:87:7F`

Step-by-step commands are in the [README](README.md#verifying-the-download).

## Known Limitations

- No digital signatures, sender authentication or non-repudiation
- No key server or web of trust: public keys must be checked out of band, by comparing fingerprints
- One key pair per phone and one recipient per message
