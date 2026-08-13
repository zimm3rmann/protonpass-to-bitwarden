# Changelog

All notable changes will be documented here. This project follows semantic versioning once public releases begin.

## 0.1.0 — Unreleased

- Added offline conversion of unencrypted Proton Pass ZIP and raw JSON exports to native Bitwarden JSON.
- Added strict ES256/P-256 passkey validation and PKCS#8 conversion.
- Added passkey-only carrier output for vaults whose ordinary records were already imported.
- Added mapping for supported logins, notes, cards, identities, aliases, SSH keys, Wi-Fi items, custom items, fields, folders, and dates.
- Added redacted migration reports, strict-mode outcomes, bounded parsing, hostile-ZIP checks, duplicate credential detection, and private atomic output handling.
- Added Linux, macOS, and Windows CI; Rust 1.88 compatibility checking; dependency auditing; independent passkey validation; and a pinned Bitwarden importer bridge.
- Added support for Proton item content format versions through 7.

This release is a public beta. Preserve the source vault and verify every important credential after migration.
