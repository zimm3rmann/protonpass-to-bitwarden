# protonpass-to-bitwarden

`protonpass-to-bitwarden` is an offline command-line converter for unencrypted Proton Pass exports. It creates native Bitwarden JSON and a separate migration report, including support for compatible Proton Pass passkeys. (The native Bitwarden importer does not import passkeys from a Proton Pass export.)

Clone it, build it with Rust, and run it locally against your export.

This is an independent community project and is not affiliated with, endorsed by, or supported by Proton or Bitwarden.

> [!CAUTION]
> Proton exports and Bitwarden JSON files contain plaintext vault secrets. Keep them out of repositories, cloud-synced folders, issue trackers, chat systems, and backups you do not control. Keep Proton Pass and the original export until every important credential has been tested.

## Quick start

### Requirements

- Git
- Rust 1.88 or newer, installed with [rustup](https://rustup.rs/)
- The normal platform linker/build tools used by Rust
- An **unencrypted** Proton Pass ZIP export

Clone this repository, then build the locked dependency set:

```sh
git clone https://github.com/zimm3rmann/protonpass-to-bitwarden.git
cd protonpass-to-bitwarden
cargo build --release --locked
```

The executable is `target/release/protonpass-to-bitwarden` on Linux and macOS, or `target\release\protonpass-to-bitwarden.exe` on Windows. Building may download Rust crates; running the converter does not make network requests.

### 1. Inspect the export

Inspection prints aggregate compatibility counts without writing a vault:

```sh
./target/release/protonpass-to-bitwarden inspect \
  "/path/to/Proton Pass_export.zip"
```

Raw Proton `data.json` is accepted too.

### 2. Choose the conversion mode

| Your situation | Command | Result |
|---|---|---|
| Moving the whole Proton vault into an empty Bitwarden vault | `convert` | Converts supported logins, notes, cards, identities, aliases, SSH keys, Wi-Fi/custom items, and passkeys. |
| Passwords and ordinary records are already in Bitwarden | `convert-passkeys` | Creates one stripped standalone Bitwarden login carrier per compatible passkey. It retains a recognizable item name but omits the source password, TOTP, URL, note, fields, and other ordinary login data. |

Bitwarden's native JSON importer creates new records; it cannot merge a passkey into an existing login. Passkey-only carriers therefore coexist with the password logins already in Bitwarden.

### 3. Create a private output directory

On Linux or macOS:

```sh
chmod 600 "/path/to/Proton Pass_export.zip"
mkdir -m 700 "$HOME/bitwarden-migration"
umask 077
```

The converter does not change permissions on the source export. `chmod 600` protects it from other nonprivileged users on the same Unix machine.

On Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force "$HOME\bitwarden-migration"
```

Choose a location outside repositories and cloud-synced folders.

### 4A. Convert the whole vault

```sh
./target/release/protonpass-to-bitwarden convert \
  "/path/to/Proton Pass_export.zip" \
  --output "$HOME/bitwarden-migration/bitwarden-import.json" \
  --report "$HOME/bitwarden-migration/migration-report.json"
```

### 4B. Convert only passkeys

Use this when the ordinary Proton records were already imported:

```sh
./target/release/protonpass-to-bitwarden convert-passkeys \
  "/path/to/Proton Pass_export.zip" \
  --output "$HOME/bitwarden-migration/bitwarden-passkeys-only.json" \
  --report "$HOME/bitwarden-migration/passkey-migration-report.json"
```

Each output item contains exactly one `fido2Credentials` entry. It intentionally contains no Proton password, TOTP, URL, note, custom field, folder, favorite state, or original item timestamp. The carrier name ends in `— Proton passkey`.

Add `--strict` if you want incomplete or lossy outcomes to return exit code 5. Strict mode writes both files before returning 5, so always inspect the report even after a nonzero exit. Proton creation-device metadata cannot be represented by Bitwarden and can cause a strict fallback even when the credential itself converted successfully.

The converter refuses to overwrite existing destinations unless `--force` is supplied. Avoid `--force` unless you have intentionally checked the existing files.

On Windows PowerShell, the same passkey-only flow is:

```powershell
$InputExport = "C:\Users\you\Downloads\Proton Pass_export.zip"
$MigrationDir = Join-Path $env:LOCALAPPDATA "protonpass-to-bitwarden-migration"
$OutputFile = Join-Path $MigrationDir "bitwarden-passkeys-only.json"
$ReportFile = Join-Path $MigrationDir "passkey-migration-report.json"

New-Item -ItemType Directory -Force $MigrationDir | Out-Null
.\target\release\protonpass-to-bitwarden.exe inspect $InputExport
.\target\release\protonpass-to-bitwarden.exe convert-passkeys $InputExport `
  --output $OutputFile `
  --report $ReportFile
```

Use `convert` with full-vault output names instead when Bitwarden does not already contain the ordinary records.

### 5. Review and import

Read the migration report before importing. A successful non-strict exit does not mean every record was converted.

In Bitwarden:

1. Open the vault import page.
2. Select native **Bitwarden (json)**, not the Proton Pass importer.
3. Import the generated Bitwarden JSON once.
4. Compare the imported batch with `output_items_created`, `folders_created`, and the passkey counts in the report.
5. Disable Proton Pass as the credential provider while testing migrated passkeys.
6. Keep Proton and the original export until every important credential works.

Importing the same JSON twice creates duplicates. A passkey-only import creates separate, usually unfiled carrier logins rather than modifying existing password entries.

## What is supported

| Proton data | Result |
|---|---|
| Login | Username/email fallback, password, TOTP, URLs and supported match modes, note, favorite state, fields, dates, and compatible passkeys are mapped. |
| ES256/P-256 passkey with private key and no PRF/HMAC-secret | Key material and duplicated metadata are validated; the private scalar is re-encoded as PKCS#8 for Bitwarden. |
| Multiple compatible passkeys on one login | Split into separate Bitwarden items because the pinned Bitwarden runtime uses only the first passkey on a login. |
| Secure note, credit card, identity, alias | Converted to the closest native Bitwarden type. |
| SSH key | Unencrypted Ed25519 and RSA relationships are validated. Encrypted OpenSSH keys are preserved with a reported fallback because their ciphertext cannot be verified without the passphrase. |
| Wi-Fi and custom items/sections | Preserved as secure notes and fields where representable, with fallback outcomes when needed. |
| Trashed item | Skipped and reported. |
| Attachment-bearing item | Item data is converted, but attachments are not migrated and are reported for manual handling. |
| Unknown item type | Rejected or reported rather than silently discarded. |

These passkeys are not converted:

- PRF/HMAC-secret credentials;
- RSA, EdDSA, non-P-256, public-only, malformed, or inconsistent credentials;
- duplicate credential identities;
- credentials whose required WebAuthn fields exceed the enforced bounds.

Proton export content format versions through 7 are accepted. Version 8 and newer fail closed until their schema changes are reviewed.

## Reports and exit codes

Report names are redacted by default. `--redact-report-names=false` includes source item names and prints an additional warning.

| Exit code | Meaning | Files written |
|---:|---|---|
| 0 | Inspection or conversion completed; still review the report | Conversion writes both requested files |
| 2 | Command-line usage error | None |
| 3 | Input is unreadable, unsupported, malformed, unsafe, encrypted, or over a limit | None |
| 4 | Output path or persistence safety check failed | None, one, or both may exist depending on the persistence point |
| 5 | Strict conversion found incomplete migration outcomes | Both vault and report were persisted |

The vault and report are committed independently through private same-directory temporary files. They are not a two-file transaction, so a storage failure or crash between renames can leave only one final file.

For an independent check of emitted passkeys, install Node.js 22 and use the report's `summary.passkeys_converted` value:

```sh
PASSKEYS_CONVERTED=1 # replace 1 with summary.passkeys_converted from the report
node scripts/validate-bitwarden-output.mjs \
  "$HOME/bitwarden-migration/bitwarden-passkeys-only.json" \
  --expected-count "$PASSKEYS_CONVERTED"
```

The validator checks encodings, bounds, PKCS#8 import, and ECDSA sign/verify. Passing it does not prove that a particular Bitwarden client, browser, service, or relying party will complete a WebAuthn ceremony.

## Security model

- Conversion is fully local and performs no network requests, telemetry, account login, browser automation, or update checks.
- ZIP entries are read without extraction. Traversal, unsafe names, links, overlaps, duplicate data entries, encryption, unsupported compression, and oversized inputs are rejected.
- Passkey MessagePack, COSE metadata, private scalars, public coordinates, duplicated credential metadata, and output field sizes are validated before serialization.
- Existing destinations are refused by default. Unix outputs are created as mode `0600`; Windows outputs receive and reverify a protected owner/System/Administrators DACL.
- Default reports use redacted stable identifiers and must not contain vault secrets.
- Selected sensitive buffers are zeroized on normal drop, but complete memory erasure cannot be guaranteed across allocators, libraries, the operating system, swap, crash dumps, or compiler-generated copies.
- Deleting a plaintext file does not guarantee erasure from SSDs, snapshots, journals, backups, or synchronized storage.

Never attach a real Proton export, generated Bitwarden JSON, passkey blob, private key, TOTP seed, password, note, card record, or unredacted report to a public issue. See [SECURITY.md](SECURITY.md) for the complete threat model and vulnerability-reporting guidance.

## Verify important credentials

For every migration:

- compare converted, skipped, unsupported, folder, and output-item counts;
- try each critical passkey with Proton Pass disabled;
- test both explicit and discoverable passkey flows when the site supports them;
- verify passwords and TOTP independently after a full-vault conversion;
- manually migrate attachments and unsupported records;
- import only once and keep the original Proton account/export until verification is complete.

A successful JSON import is not, by itself, proof that a migrated passkey can authenticate.

## Troubleshooting

### Strict mode returned exit code 5

Both files were written. Review `summary.strict_failures` and the detailed outcomes. Creation-device metadata, unsupported URL modes, attachments, encrypted SSH private material, or unsupported credentials can all require review.

### No passkeys were converted

Run `inspect` and review the report. Common causes are trashed credentials, PRF/HMAC-secret data, unsupported key algorithms, duplicate credentials, or over-limit user handles. Passkey-only mode refuses to write a misleading empty import.

### Output creation was rejected

Use a new destination in a directory you own. On Unix, group- or world-writable non-sticky directories are rejected; `mkdir -m 700` creates the recommended layout. Existing files require an intentional `--force`.

### Bitwarden created duplicate entries

Native JSON imports always create new records. Import each generated file only once. If ordinary records are already present, use `convert-passkeys` instead of `convert`.

### The Proton export was rejected

The converter accepts only unencrypted ZIP exports and raw `data.json`. PGP/encrypted exports and unknown content format versions are rejected without guessing.


## Upstream compatibility pins

The implementation was checked against:

- [Bitwarden clients `2be53da5b7ec6f7608f2fc28a6f63d70d89ec53f`](https://github.com/bitwarden/clients/commit/2be53da5b7ec6f7608f2fc28a6f63d70d89ec53f)
- [Proton Pass common `533d7c0a2660bc63701bc17b932697579383e5e0`](https://github.com/protonpass/proton-pass-common/commit/533d7c0a2660bc63701bc17b932697579383e5e0)
- [Proton WebClients `1ee27e1b54a4a3d0462ca1e35051bc58a0c4ac7b`](https://github.com/ProtonMail/WebClients/commit/1ee27e1b54a4a3d0462ca1e35051bc58a0c4ac7b)
- [passkey-rs `46f3a936671d80842d1808871780a3a331bffbdb`](https://github.com/1Password/passkey-rs/commit/46f3a936671d80842d1808871780a3a331bffbdb)
- [Proton content-format-v7 change `61858d08ac1842cdd4eb1e16b7690279a38193cb`](https://github.com/ProtonMail/WebClients/commit/61858d08ac1842cdd4eb1e16b7690279a38193cb)

Upstream formats are active. Recheck them before changing passkey decoding or publishing new release artifacts.

## Contributing and releases

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request. Contributions must use synthetic fixtures; never share a real vault or unredacted migration output.

The manual release workflow gates builds on all-platform checks, the independent passkey validator, the declared minimum Rust version, RustSec, and dependency reachability. It creates unsigned workflow artifacts with `BUILDINFO.txt` and `SHA256SUMS`; it does not automatically publish a GitHub release.

This project is licensed under [GPL-3.0-or-later](LICENSE).
