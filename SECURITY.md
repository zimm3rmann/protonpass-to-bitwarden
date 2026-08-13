# Security policy

## Current safety status

Do not supply a real vault export for debugging. Do not upload one to ChatGPT, GitHub, an issue tracker, email, cloud storage, or any third party.

## Protected assets

The input and output may contain:

- passwords and usernames;
- TOTP seeds;
- passkey private keys, credential IDs, user handles, and relying-party metadata;
- SSH private keys;
- card and identity data;
- secure notes, recovery codes, and custom fields.

Disclosure of either vault file can compromise the entire account set. The migration report is intended to be safer, but names and metadata can still be sensitive.

## Threat model

The converter is designed to reduce these risks:

- accidental network disclosure or telemetry;
- secrets printed to terminals, logs, panic messages, or reports;
- ZIP path traversal and decompression bombs;
- silent loss of unsupported items or passkeys;
- accepting malformed or mismatched passkey key material;
- silently dropping PRF/HMAC-secret behavior;
- overwriting an existing output file;
- permissive output-file access on Unix or Windows;
- temporary plaintext left behind after normal operation.

The converter assumes:

- the local operating system, Rust toolchain, and executable are trusted;
- the user controls the input and output paths;
- the Bitwarden client used for import is genuine and current;
- the machine is not already compromised by malware, a debugger, keylogger, or privileged observer.

## Out of scope

This version does not protect against:

- a compromised host, compiler, dependency registry, browser, or password-manager client;
- privileged inspection of process memory;
- swap, hibernation, filesystem snapshots, editor recovery, antivirus copies, or crash dumps;
- secure erasure guarantees on SSDs, copy-on-write filesystems, journaled filesystems, or cloud backups;
- decryption of encrypted or PGP Proton exports;
- migration of attachments;
- unsupported passkey algorithms, curves, extensions, or missing private keys;
- any service contacted after the generated file is imported.

## Security properties

The implementation and tests should maintain all of these properties:

- No runtime networking, analytics, telemetry, crash upload, update check, browser automation, or account credential use.
- ZIP contents are read without extraction. Raw central-directory duplicates, absolute and platform-specific paths, traversal, links, overlap, encryption, and unsupported compression are rejected.
- Archive bytes, selected JSON bytes, raw entry count, vault/item/passkey counts, passkey MessagePack size, and MessagePack nesting are bounded. The fixed ceilings are 2 GiB per ZIP, 64 MiB selected JSON, 100,000 ZIP entries, 256 MiB central directory, 128 MiB aggregate preflight metadata, 4 KiB entry names, 10,000 vaults, 500,000 total items, 100 passkeys per item, 100,000 elements in one nested collection, 1,000,000 aggregate nested elements, 512 MiB projected output, 64 KiB decoded passkey MessagePack, and 32 MessagePack levels. Identifier, folder, SSH, and validator limits are listed in the README. Parser and allocator scratch use cannot be bounded exactly.
- Existing output and report files are refused unless the user explicitly supplies `--force`.
- Input, output, and report aliases are rejected using canonical paths and file identities, with conservative Windows filename folding and macOS Unicode normalization for nonexistent destinations.
- Unix files are created and reverified with mode `0600`. The destination directory must be owned by the current effective user; group- or world-writable directories are rejected unless the sticky bit is set. Windows files are created with a protected DACL granting full control only to the owner, Local System, and local administrators, and that DACL is reverified before and after persistence. Hosted Windows CI exercises private temporary-file creation, DACL verification before secret bytes are written, and post-persistence reverification on the runner's local filesystem. Administrator, backup-privilege, non-NTFS, and network-share behavior remains outside the guarantee.
- The vault JSON is never written to standard output in normal operation.
- Reports default to redacted stable identifiers and contain no passwords, TOTP seeds, private scalars, PKCS#8 data, SSH private keys, card numbers, note bodies, or recovery codes.
- Every active modeled item and every passkey in the JSON receives a converted, split, skipped, or unsupported outcome. A future item type is reported unsupported only when it has no unmodeled `passkeys` array; otherwise the whole export is rejected rather than silently omitting credential outcomes.
- Passkey-only mode emits one new minimal login carrier per successfully converted active credential and never serializes source passwords, TOTP values, URLs, notes, custom fields, folders, favorite state, or item timestamps. It cannot merge into an existing Bitwarden login.
- Proton passkey creation-device provenance is not authentication material, but Bitwarden cannot represent it. The report records its omission and strict mode still fails to preserve the meaning of exact migration.
- Item and passkey report entries retain a primary reason plus every additional simultaneous fallback reason so one lossy mapping cannot hide another manual-review requirement.
- Unknown passkey serialization versions, algorithms, curves, malformed values, missing private components, public/private coordinate mismatches, and duplicated-metadata mismatches are rejected rather than guessed.
- Duplicate passkey credential identities are rejected across the complete export, and nonempty unsupported inner key metadata is rejected rather than discarded.
- PRF/HMAC-secret extension data is detected and rejected rather than silently discarded.
- SSH private keys are parsed. For unencrypted Ed25519 and RSA keys, public material is independently derived and RSA private relationships are checked. Encrypted OpenSSH keys are preserved without decryption or private-mathematics validation; their unencrypted embedded public header must match the supplied public key and fingerprint, but the ciphertext private material is not fully cryptographically verified and requires a fallback/strict review outcome. Unsupported unencrypted algorithms are rejected.
- The independent Node.js 22 validator requires a positive expected passkey count, bounds its file, item, credential, and field inputs, rechecks the opened file and path endpoint before accepting the read, imports every private key through WebCrypto's PKCS#8 path, derives a public SPKI without exporting a private JWK, and signs and verifies with every emitted key.
- The optional pinned Bitwarden importer bridge suppresses upstream Jest diagnostics and emits only fixed success or failure text, so assertion diffs cannot expose parsed vault metadata.
- The converter never deletes or modifies the source Proton export or vault.

## Passkey-specific risks

For supported ES256/P-256 credentials, the converter decodes Proton's versioned MessagePack, validates COSE parameters and private/public consistency, constructs PKCS#8 DER from the same private scalar, and emits the original credential ID and user handle in Bitwarden's required encodings.

Re-encoding the same key is not the same as live interoperability proof. A mistake in RP ID, credential ID, user handle, signature format, discoverability, counter behavior, backup flags, or client import behavior can still make an apparently valid credential unusable. Keep the source credential available until authentication succeeds.

The converter emits Bitwarden's string `discoverable` value as `"true"` only after the inner Proton credential supplies a nonempty user handle. Proton Pass common pins passkey-rs revision `46f3a936671d80842d1808871780a3a331bffbdb`, constructs `Authenticator<Option<Passkey>, ...>`, and uses its `Option<Passkey>` store; that revision's store reports `DiscoverabilitySupport::ForcedDiscoverable`, which maps to `true`. The pinned Bitwarden importer bridge confirms that the emitted string parses as boolean `true`. This exact source chain supports the mapping but is not proof of a discoverable browser ceremony.

The pinned Bitwarden export schema permits an array of passkeys, while the pinned authenticator and autofill paths repeatedly select only element zero. Multiple Proton passkeys must therefore be split into separate Bitwarden login items unless a newer client has been integration-tested to support them.

The pinned Bitwarden export model has no field for Proton PRF/HMAC-secret state. Removing that state could break derived secrets or encrypted site data even if signatures still work, so affected credentials are unsupported by default.

## Safe development and validation

Use generated fixtures and disposable accounts for development and release validation:

1. Build with the pinned toolchain and `--locked` dependencies.
2. Run formatting, lint, unit, property/negative, integration, generated-output Node.js validator, minimum-Rust, and dependency-audit checks.
3. Inspect a generated fixture and confirm output/report permissions and overwrite refusal.
4. Register a disposable Proton Pass passkey on a disposable WebAuthn account.
5. Export it unencrypted and convert it locally in strict mode.
6. Import it into an empty disposable Bitwarden account.
7. Disable Proton Pass and prove explicit and discoverable authentication through Bitwarden.
8. Confirm unsupported fixtures fail without leaking their contents.
9. Record versions and results without recording secrets.

Record versioned results without recording credential values. A successful field migration does not remove the need to exercise this matrix when changing schemas, cryptography, output mappings, or compatibility claims.

## Safe operation

- Use a dedicated, fully patched machine with full-disk encryption.
- Close editors, sync clients, backup tools, and unrelated applications where practical.
- Use an output directory outside repositories and cloud-synced paths.
- Set `umask 077` on Unix before running the converter.
- Run `inspect` before `convert`.
- Use `--strict` and avoid `--force`.
- If ordinary records are already in Bitwarden, use `convert-passkeys`; the full `convert` command would create a second copy of every active item.
- Remember that strict exit code 5 is returned only after both output files are persisted; inspect or remove those files before retrying.
- Read the redacted report before import.
- Import a full-vault conversion once into an empty destination. Import passkey-only carriers once into the intended existing vault.
- Verify critical credentials individually with Proton Pass disabled.
- Keep Proton and the original export until all important credentials work.

## Memory and deletion limitations

Sensitive buffers should use best-effort zeroization where the data model and dependencies permit it. Rust moves, copies, formatting, allocator behavior, JSON and ZIP libraries, operating-system buffering, and compiler optimization mean complete zeroization of every allocation cannot be promised.

Deletion is also best effort. Prefer preventing persistent plaintext through restrictive permissions, full-disk encryption, nonsynced storage, and short retention. Removing a file does not guarantee that SSD cells, snapshots, journal entries, swap, backups, or recovery systems no longer contain it.

Output and report files are each committed atomically from a same-directory temporary file, but the pair is not transactional. A failure between renames can leave only one new file, and a crash or power loss can leave a hidden temporary file. Atomic replacement and directory synchronization guarantees can also be weaker on network or unusual filesystems.

## Dependency and release hygiene

- Commit `Cargo.lock` and build with `cargo build --release --locked`.
- Review dependency additions and feature flags for network, telemetry, unsafe code, and unnecessary parser surface.
- Run `cargo audit` and investigate every advisory before a release artifact is trusted.
- Keep the `RUSTSEC-2023-0071` exception narrow. `rsa 0.9.10` currently appears only as inactive optional lockfile metadata from `ssh-key`; CI and release checks fail closed unless `cargo tree --locked --target all -i rsa -e normal` succeeds with empty standard output. Remove the exception or stop the release if that proof changes.
- Treat release artifacts as untrusted until their workflow source, compiler pin, dependency lock, and digest have been reviewed.
- The manual release workflow is gated on all-platform checks, the Node.js passkey validator, the declared Rust 1.88.0 minimum, RustSec, and dependency reachability. Artifacts carry a SHA-256 manifest, build provenance, both validator scripts, the Bitwarden importer bridge spec, and this audit record. It uploads workflow artifacts only and does not publish or sign a release.

The pre-remediation static scan, corresponding fixes, synthetic validation, and field-evidence boundary are recorded in [aidocs/security-audit-2026-08-13.md](aidocs/security-audit-2026-08-13.md).

## Reporting a vulnerability

Report security problems without attaching a vault, passkey blob, private key, TOTP seed, password, note, card record, or unredacted report. Use a minimal synthetic fixture and describe the affected commit and platform.

Use the repository's **Security → Report a vulnerability** form for sensitive reports. Repository owners must enable GitHub private vulnerability reporting before public launch. If that form is unavailable, do not post vulnerability details publicly; open only a minimal, nontechnical issue asking the maintainer to enable a private reporting channel.
