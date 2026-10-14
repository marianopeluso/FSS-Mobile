# Contributing to FSS Mobile

Thanks for your interest. This is a small, single-maintainer open-source project, so please bear with response times. Device reports, bug reports, ideas and pull requests are all welcome.

## The most useful contribution right now: device reports

FSS Mobile has been tested on only a few phones. If you install it, please open a **Device report** issue ([new issue](https://github.com/marianopeluso/FSS-Mobile/issues/new/choose)) with:

- phone brand and model, Android version, and whether it has Google services
- the app version (shown under the app name)
- what you tried (create or import a key, encrypt/decrypt text, attachment, QR scan, fingerprint/PIN entry, contacts backup, exchange with the desktop app…) and whether it worked
- anything that looked wrong: cut-off text, crashes, buttons that do nothing

Even a short "everything worked on my phone" report is valuable.

## Before you start

- For a **security vulnerability**, do not open a public issue: see [`SECURITY.md`](SECURITY.md) for private reporting.
- For anything else, open an [issue](https://github.com/marianopeluso/FSS-Mobile/issues) first, especially before significant work, so we can agree on the approach before you invest time in a pull request.

## Reporting a bug

Please include your phone model, Android version and app version, exact steps to reproduce, and what you expected compared with what happened. **Never share a password, a private key, an exported key file, or real encrypted messages** in an issue.

## Proposing a feature

Describe the use case, not just the mechanism: what problem it solves and for whom. The app is deliberately small and simple (one key pair, one recipient per message, no network access), so features that add significant complexity, permissions or dependencies will be discussed carefully.

## Development

The app is plain Java with no external dependencies besides the bundled ZXing QR sources, and it is built without Gradle: see [Building from Source](README.md#building-from-source) and [`source/build.sh`](source/build.sh).

```
source/
  AndroidManifest.xml
  build.sh
  res/                                      resources (icon, licenses, backup rules)
  src/org/filesecuresuite/mobilelite/       app code
  third_party/zxing-core-3.5.3/             ZXing QR code sources used by the app (Apache 2.0)
```

The internal package name stays `org.filesecuresuite.mobilelite` (the app was called "FSS Mobile Lite" during development). Changing it would make Android treat the app as a different app.

## Code guidelines

- **Keep `FssCrypto.java` UI-free.** It is the security-critical part, kept small and auditable on its own.
- **Never weaken a security default silently.** Any change to cryptographic parameters (KDF iterations, key sizes, algorithms, size limits) must be called out explicitly in the pull request and in `CHANGELOG.md`.
- **Stay compatible with File Secure Suite desktop.** The FSS2 container format is shared and must not change in place. Any change must keep phone↔desktop round trips working in both directions.
- **No new permissions** without a discussion first, and never the Internet permission.
- Test on a real device or emulator running Android 8.0 (API 26) as well as a recent version, at least: key creation, encrypt/decrypt round trip, attachment, QR scan, lock and unlock.

## Versioning

The project follows [Semantic Versioning](https://semver.org/). While the version is below 1.0, the app is considered preliminary. Every release increases the internal `versionCode` in `build.sh`, so Android accepts it as an update.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep each pull request focused on one change.
3. Describe *what* changed and *why*, and call out any security-relevant implication explicitly.
4. Update `CHANGELOG.md`, and `SECURITY.md` if the change touches the security model.

Official releases are signed only by the maintainer with the project's release key. Builds from pull requests are never published as official APKs.

## License

By contributing, you agree that your contribution is licensed under the project's [MIT License](LICENSE).
