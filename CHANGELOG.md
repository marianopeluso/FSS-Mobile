# Changelog

All notable changes to FSS Mobile are documented here. Dates use the ISO 8601 format (YYYY-MM-DD).

## [0.5.3] - 2026-10-14

First public release. Preliminary (0.x): fully compatible with File Secure Suite 2.0.x, tested on a few devices, no independent security review yet.

### Features
- One RSA-4096 key pair kept on the phone, generated in the app or imported from a desktop or OpenSSL `.pem` (keys under 4096 bits rejected)
- Encrypt a text for one contact, or for yourself, as Base64 to copy or share into any chat or e-mail app
- Text plus one attached file (up to 25 MB) as a single `.rsa` package (a ZIP inside an FSS2 file container) that File Secure Suite desktop opens with *File → Decrypt*
- Decrypt pasted text, text shared to the app, and `.rsa` files opened with "Open with"; decrypted text is never saved, attachments are saved only on request to a folder you pick
- Contacts: address book of public keys, added with the built-in live QR scanner, from a QR image, by pasting, or from a `.pem` (also via "Open with"); fingerprint shown on adding; duplicates detected; optional names
- Contacts backup and restore in a separate password-protected FSS2 file, which the desktop can also open
- My key: fingerprint, QR code compatible with the desktop, public-key export, encrypted private-key export (PKCS#8, PBKDF2-SHA256 600,000 iterations), password change, key replacement that keeps contacts
- Two-step access: phone fingerprint/face/PIN to open the app, FSS password to load the private key; configurable auto-lock and inactivity lock
- Self-clearing clipboard (15 seconds), screenshots blocked, no Internet permission, app data excluded from all backups
- Works on phones without Google services
- Introductory guide on first launch; About page with limitations, responsible-use note and licenses

### Security
- Private key stored encrypted with the user's password (PBKDF2-HMAC-SHA256, 600,000 iterations, AES-256-GCM) and wrapped again with an Android Keystore key; contacts stored encrypted
- Release APK signed with the project's release certificate (SHA-256 `05:F3:80:A3:CC:34:0C:EA:32:53:2E:9B:9D:0C:B0:75:8B:A3:9F:0C:0D:0B:4F:BA:17:01:B1:D6:E3:86:87:7F`); checksum signed with the same GPG key as File Secure Suite desktop

---

*Versions 0.1.0 to 0.5.2 were internal test builds, signed with a test key and never published (called "FSS Mobile Lite" until 0.4.0). Because the signing key changed, those builds cannot be updated in place: export the private key and back up the contacts, uninstall, install 0.5.3, then import and restore.*
