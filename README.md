# FSS Mobile

**FSS Mobile** is a free, open-source Android companion to [File Secure Suite](https://github.com/marianopeluso/FileSecureSuite), the desktop encryption app. It keeps one RSA-4096 key pair on your phone and encrypts short texts to paste into any chat, e-mail or web page, with an optional attached file. It also keeps a small address book of your contacts' public keys, which you can exchange as QR codes. It uses the same **FSS2** format as the desktop app, so what you encrypt on the phone opens on the desktop and vice versa.

No account, no server, no Internet permission, no telemetry.

> Secret is what you hide. Private is what you choose to reveal. Privacy is the power to selectively reveal oneself to the world. You don't need something to hide to need privacy.
>
> — Inspired by Eric Hughes, *A Cypherpunk's Manifesto*, 1993

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Android](https://img.shields.io/badge/Android-8.0%2B-green.svg)
![Status](https://img.shields.io/badge/status-preliminary%20(0.x)-orange.svg)

> **⚠ Preliminary release (0.x).** FSS Mobile works and is fully compatible with File Secure Suite 2.0.x, but it has been tested on only a few phones so far (including one without Google services), and it has **not had an independent security review**. The version number stays below 1.0 until it has been tried on many more devices. If you install it, please [report your phone model and how it went](https://github.com/marianopeluso/FSS-Mobile/issues/new/choose): that is the most useful contribution right now.

## Why FSS Mobile

Most of our private conversations happen on the phone, inside apps we don't control. FSS Mobile adds a layer that belongs to you. You encrypt a message for one contact, paste the result into the chat or e-mail app you already use, and only that contact's private key can open it. The carrier app sees only an unreadable block of text.

Like the desktop app, it is anonymous by design: a key identifies only itself, never a verified real-world identity. It has no signing or identity features of any kind: it only encrypts and decrypts.

## Key Features

- **One key pair on the phone**: RSA-4096, generated on the phone or imported from a desktop or OpenSSL `.pem` file (keys under 4096 bits are rejected). It stays on the phone until you delete it.
- **Encrypt** for a contact, or "for myself":
  - **text only**: Base64 text with **Copy** and **Share** buttons;
  - **text + one file** (up to 25 MB): a single `.rsa` file with a neutral name, to send as a document. The desktop opens it with *File → Decrypt*.
- **Decrypt** a pasted text, a text shared to the app from WhatsApp, Telegram or e-mail, or a `.rsa` file opened with "Open with". Decrypted text is shown on screen and never saved. A received attachment is saved only when you choose to, in a folder you pick.
- **Contacts**: a small address book of public keys, added with the built-in live QR scanner, from a QR image (photo, screenshot, or received in a chat), by pasting the key, or from a `.pem` file. When you add a key, the app shows its fingerprint so you can compare it. Contacts can be backed up to a separate password-protected file that the desktop can also open.
- **My key**: fingerprint, QR code (same content as the desktop QR), export of the public key, encrypted export of the private key (opens in File Secure Suite and OpenSSL), and password change (same key, same fingerprint).
- **Two-step access**: you open the app with your phone's fingerprint, face or PIN, and you load the private key separately with your FSS password before encrypting or decrypting. The key unloads when the app locks.
- **Self-clearing clipboard** (15 seconds) after copying decrypted text, **screenshots blocked**, app data **excluded from all backups**.
- Works on phones **without Google services**.

## Download and Install

1. Download `FSS_Mobile_0.5.3.apk` from the [Releases](https://github.com/marianopeluso/FSS-Mobile/releases) page.
2. *(Recommended)* Verify it: see [Verifying the download](#verifying-the-download).
3. Open the APK on your phone. Android will ask you to allow installing apps from that source (your browser or file manager): allow it for this install.

Requirements: Android 8.0 or later.

**Updates** install over the previous version and keep your key, contacts and settings, as long as they are signed with the same release key (see below). You can also track new releases automatically with an app such as [Obtainium](https://github.com/ImranR98/Obtainium), pointing it at this repository.

> **Never uninstall to update.** Uninstalling the app, or clearing its data, permanently deletes your private key and your contacts. They are deliberately excluded from phone backups. Before uninstalling for any reason, use **My key → Export private key** and **Contacts → Back up contacts**.

### Verifying the download

Each release contains three files:

- `FSS_Mobile_0.5.3.apk`: the app;
- `FSS_Mobile_0.5.3.apk.sha256`: its SHA-256 checksum;
- `FSS_Mobile_0.5.3.apk.sha256.asc`: a detached GPG signature of the checksum file.

**1. Checksum and GPG signature.** The release is signed with the same GPG key as File Secure Suite desktop. The public key is in this repository as [`fssmobile.asc`](fssmobile.asc). Use *that* copy, not one from an unknown source. Its fingerprint is:

```
0FD9 7EB8 55F7 C5BB 1048 D424 F204 94B9 FAB5 3C10
```

```bash
# Linux / macOS
sha256sum -c FSS_Mobile_0.5.3.apk.sha256          # must print "OK"
gpg --import fssmobile.asc
gpg --fingerprint mariano@peluso.me               # must show the fingerprint above
gpg --verify FSS_Mobile_0.5.3.apk.sha256.asc FSS_Mobile_0.5.3.apk.sha256
```

```powershell
# Windows (PowerShell): the two hashes must be identical
(Get-FileHash FSS_Mobile_0.5.3.apk -Algorithm SHA256).Hash
Get-Content FSS_Mobile_0.5.3.apk.sha256
```

GnuPG prints "Good signature from Mariano Peluso" and, unless you have certified the key yourself, a warning that the key is not trusted. That warning is expected: what matters is that the fingerprint matches.

**2. APK signing certificate.** Android itself checks the APK signature at every install and update. All official releases are signed with the same certificate (`CN=FSS Mobile`), whose SHA-256 fingerprint is:

```
05:F3:80:A3:CC:34:0C:EA:32:53:2E:9B:9D:0C:B0:75:8B:A3:9F:0C:0D:0B:4F:BA:17:01:B1:D6:E3:86:87:7F
```

You can check it with `apksigner verify --print-certs FSS_Mobile_0.5.3.apk` (Android SDK build-tools), or with an app inspector on the phone. Obtainium can also pin it. An APK with a different certificate is not an official release.

## Working with File Secure Suite (desktop)

FSS Mobile uses the desktop's FSS2 container format unchanged. The byte-level specification is in the desktop repository: [`FORMAT_SPECIFICATIONS.md`](https://github.com/marianopeluso/FileSecureSuite/blob/main/FORMAT_SPECIFICATIONS.md).

| From the phone | On the desktop (File Secure Suite 2.0.x) |
|---|---|
| Encrypted text (Base64) | *Text* panel, RSA decrypt |
| `.rsa` file (text + attachment) | *File → Decrypt*: gives back a ZIP with `message.txt` and the attachment |
| Exported private key (`.pem`) | Usable as a desktop private key, same password |
| Public key (`.pem` or QR) | Usable as a desktop public key; the QR has the same content |
| Contacts backup (`.aes`) | *File → Decrypt* with the backup password |

It works the other way round too: texts and `.rsa` files encrypted on the desktop for your phone's public key open in FSS Mobile, and desktop `.pem` keys can be imported. Desktop 2.0.1 or later is recommended, because it protects private-key files with the same 600,000-iteration PBKDF2 as the phone.

## Access and Protection

- **Opening the app**: phone fingerprint, face or PIN. A phone with no screen lock opens with the FSS password instead. This gives access to the contacts and your public key only.
- **Loading the private key**: your FSS password, required before encrypting or decrypting. The phone PIN or fingerprint never opens the private key.
- **Auto-lock**: when you leave the app, after a delay you choose (immediately, 1 minute by default, 3, 5 or 10 minutes), and after 2 minutes without interaction while it is open.
- **Forgotten password**: there is no recovery. You can replace the key and keep your contacts (messages encrypted for the old key can no longer be opened), or delete everything.

## Permissions

- `USE_BIOMETRIC`: granted at install time without a prompt; used to open the app with fingerprint, face or PIN.
- `CAMERA`: requested only the first time you open the live QR scanner. Frames are analysed in memory only: no photo is taken or stored. If you deny it, you can still add keys from a QR image or by pasting them.
- **No Internet permission and no storage permission.** Files come and go only through the system file picker and the share menu.

## Security

- **RSA-4096 with OAEP** (SHA-256, MGF1-SHA-256) wrapping a random **AES-256-GCM** key (hybrid encryption), in the authenticated FSS2 container
- **Private key on the phone**: encrypted with your password (PBKDF2-HMAC-SHA256, 600,000 iterations, AES-256-GCM), then wrapped again with a key held by the Android Keystore; contacts are stored encrypted too
- **Private key export**: standard PKCS#8 with PBES2 (PBKDF2-HMAC-SHA256, 600,000 iterations, AES-256-CBC), OpenSSL-compatible
- **Contacts backup**: FSS2 password container with its own password (at least 12 characters), separate from the key password
- No signing, no identity verification, no key escrow, no backdoor, no network access

Full details, including what FSS Mobile does **not** protect against, are in [`SECURITY.md`](SECURITY.md).

## Limitations

- The app that carries the message (WhatsApp, e-mail…) still sees who writes to whom, when, and how big the message is.
- No signature: a message does not prove who wrote it.
- It is not an antivirus: check attachments before opening them.
- No forward secrecy: whoever gets your private key and its password can read past messages.
- No password recovery: a forgotten password means a lost key.
- Uninstalling the app deletes your key and contacts: keep your own backups.
- One recipient per message, and attachments up to 25 MB.

## Building from Source

The app is built without Gradle or Android Studio, with a short shell script: [`source/build.sh`](source/build.sh). You need:

- JDK 17 or later
- `android.jar` for API 34 (for example from [Sable/android-platforms](https://github.com/Sable/android-platforms))
- `aapt2` (included in the [Apktool](https://github.com/iBotPeaches/Apktool/releases) release jar)
- D8 (included in [jadx](https://github.com/skylot/jadx/releases) `jadx-all.jar`)

```bash
cd source
JDK=/path/to/jdk ANDROID_JAR=/path/to/android.jar AAPT2=/path/to/aapt2 D8_JAR=/path/to/jadx-all.jar ./build.sh
```

The script produces an **unsigned** APK. To install it you must sign it with a key of your own, for example with `apksigner` or [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer). An APK you sign yourself has a different signature from the official releases, so Android will not install it over the official app, or the other way round.

`source/third_party/` contains only the [ZXing](https://github.com/zxing/zxing) 3.5.3 files the app actually uses (QR code reading and writing), unmodified from the upstream release, with their Apache 2.0 license.

## A Note on Responsible Use

FSS Mobile is a neutral tool, like a lock or a pen: it can be used well or poorly, and that choice belongs entirely to the person using it. It exists to protect privacy, not to enable harm. Please use it responsibly and lawfully, and extend that same respect to others' privacy. As open-source software, it is provided as-is, without warranty, and its author accepts no liability for how others choose to use it.

## Contributing

Device reports, bug reports and suggestions are welcome: see [`CONTRIBUTING.md`](CONTRIBUTING.md). For security vulnerabilities, see [`SECURITY.md`](SECURITY.md).

## License

FSS Mobile is released under the [MIT License](LICENSE). It includes ZXing (QR code library), licensed under the [Apache License 2.0](source/third_party/zxing-core-3.5.3/LICENSE).

## Support the Project

If FSS Mobile is useful to you, you can support its development with a Lightning Network donation:

```
lnurl1dp68gurn8ghj7ampd3kx2ar0veekzar0wd5xjtnrdakj7tnhv4kxctttdehhwm30d3h82unvwqhk6ctjd9skummcxu6qs3rtcq
```

Issues and ideas: [GitHub Issues](https://github.com/marianopeluso/FSS-Mobile/issues)

## Release History

See [`CHANGELOG.md`](CHANGELOG.md).
