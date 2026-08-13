# Security audit record — 2026-08-13

## Scope and status

A repository-wide Codex Security static scan reviewed the Rust CLI, JavaScript validator, dependency manifests, tests, workflows, README, and security policy. The pre-remediation scan ID was `3e31592a-cad4-4007-925b-b4ac96e608f1`; its snapshot digest was `codex-security-snapshot/v1:sha256:a985953e2858f746fc4b89f231b3def121b389fcc7535b0f33934a2e00ab696f`.

Final remediated deliverable content/path digest: `deliverable-file-set/v1:sha256:85ad3d3951830fa96bebbe135a147defa6bb10185a9aee4ed75188912db74fb4`. This is a non-self-referential digest of every repository file except Git metadata, build/release output, and this audit record. It covers sorted relative paths and file contents, but not filesystem mode metadata. The exact GNU-coreutils command was:

```sh
find . -type f -not -path './.git/*' -not -path './target/*' -not -path './dist/*' -not -path './aidocs/security-audit-2026-08-13.md' -print0 |
  LC_ALL=C sort -z |
  xargs -0 sha256sum --zero |
  sha256sum
```

Excluding this file lets the recorded value be inserted without changing the measured file set. The pre-remediation scan ID and snapshot digest above must not be presented as the final-state digest.

The scan reported eleven findings: eight medium and three low. They were remediated or bounded as described below and covered by focused regressions plus the full test suite. This is an engineering audit record, not a universal Proton-to-Bitwarden interoperability claim. After remediation, the passkey-only workflow was used on a real Proton Pass export and the operator reported a successful Bitwarden migration; exact client, browser, operating-system, and separate WebAuthn-flow details were not recorded.

## Finding disposition

| Pre-remediation finding | Disposition |
|---|---|
| JSON collections allocated before count limits | Count-aware deserializers now cap vaults, items, passkeys, fields, sections, URLs, and aggregate nested elements while parsing; post-parse aggregate validation remains a second layer. |
| ZIP metadata parsed before resource limits; quadratic overlap check | EOCD, ZIP64, central-directory size, entry count, and filename bytes are preflighted before `ZipArchive`; overlap detection uses sorted ranges. |
| SSH private/public/fingerprint components were not matched | Private keys are parsed and supplied public keys and fingerprints must match. Unencrypted Ed25519 public keys are independently derived and unencrypted RSA private relationships are validated. Encrypted private ciphertext cannot be validated without its passphrase, so only its embedded public header is checked and the result is explicitly reported as fallback/strict. |
| Passkey notes were discarded | Nonempty notes are preserved as attributed custom data on the corresponding main or split login. |
| Known Proton schemas silently ignored unknown members | Security-relevant and known item structures reject unknown fields; explicitly modeled future item kinds receive an unsupported ledger outcome. |
| Folder and split-login output amplification | Aggregate projected-output and folder-name budgets are enforced before conversion; folder construction is incremental. |
| Duplicate JSON vault keys were collapsed | The vault-map deserializer rejects duplicate keys before insertion. |
| Windows privacy verification was a no-op | Output is created with a protected owner/System/Administrators DACL before the first secret byte and reverified before and after persistence. Hosted Windows CI exercises private temporary-file creation, pre-write DACL verification, and post-persistence reverification on the runner's local filesystem; privileged and nonstandard-filesystem behavior remains outside the claim. |
| Duplicate passkey credential identities were accepted | Exact and conflicting duplicates are detected across the export, rejected, and assigned explicit report outcomes. |
| No-clobber persistence could leave a temporary hard link | Temporary and persisted identities and link counts are checked; a surviving alias is removed only after identity verification. |
| Output authorization was exposed to mutable path races | Parent and endpoint identities are captured and rechecked, symlink/reparse traversal is rejected, and persisted identity is verified. A hostile same-user process able to mutate filesystem state remains outside the trusted-host assumption. |

## Dependency advisory exception

`cargo-audit 0.22.2` reports `RUSTSEC-2023-0071` for `rsa 0.9.10` recorded in `Cargo.lock`. Cargo lockfile version 4 retains that package as inactive optional metadata of `ssh-key 0.6.7`; the converter's normal dependency graph does not include it. `.cargo/audit.toml` ignores only that advisory, while CI separately requires this proof to stay empty:

```sh
set -euo pipefail
rsa_tree="$(cargo tree --locked --target all -i rsa -e normal)"
test -z "$rsa_tree"
```

Dependency-tree resolution failure or any standard output invalidates the exception and blocks release. The converter's RSA SSH validation uses `num-bigint-dig`, not the advisory-affected `rsa` crate.

## Acceptance hardening

The independent validator now requires a caller-supplied positive expected passkey count, enforces its own practical file/item/credential/field limits, verifies a stable regular-file endpoint around the read, imports each private key with WebCrypto's PKCS#8 path, derives a public SPKI without exporting a private JWK, and signs and verifies. CI runs that validator against converter-generated output containing one passkey rather than accepting a zero-passkey no-op.

CI pins Node.js 22 through a commit-pinned setup action, tests Linux, macOS, and Windows, and separately checks Rust 1.88.0. Both CI and the manual release gate use an all-target, fail-closed RSA reachability proof. Release builds are blocked on formatting, lint, tests, validator execution, the minimum-version check, and RustSec. Staged artifacts include both validator scripts, the Bitwarden importer bridge spec, this audit record, build provenance, and a SHA-256 manifest; the same-runner clean rebuild comparison is not cross-environment reproducibility proof.

The fixed converter and validator rejection thresholds, CLI exit codes, strict-mode file semantics, encrypted-SSH validation boundary, passkey discoverability source basis, and release-verification procedure are documented in the README and SECURITY policy. The discoverability basis follows Proton's pinned passkey-rs revision `46f3a936671d80842d1808871780a3a331bffbdb`: Proton constructs `Authenticator<Option<Passkey>, ...>`, whose `Option<Passkey>` store reports `ForcedDiscoverable`, mapping to `true`. This does not replace a live discoverable ceremony. Separately, an encrypted OpenSSH key exposes a public header that can be compared with supplied public metadata, but its ciphertext private material cannot be fully cryptographically verified without the passphrase and therefore requires a fallback/strict review outcome.

The final cross-platform review also normalized composed and decomposed macOS destination names before comparing nonexistent output paths, preventing a vault/report alias from bypassing the preflight on normalization-aware filesystems.

The optional pinned Bitwarden importer bridge now reduces its exact credential checks to a boolean result and suppresses upstream Jest diagnostics, emitting only fixed text so a mismatch cannot print parsed credential metadata. Its passkey-only mode additionally requires zero folders, one FIDO credential per carrier, and no parsed password, TOTP, URI, note, field, or folder relationship.

The final ledger review added a streaming count cross-check between every JSON `passkeys` array and modeled login credentials, rejecting future item shapes that could otherwise conceal unledgered credentials. Item and passkey outcomes now retain additional reason codes for simultaneous losses, and report summaries distinguish attachment-bearing item sets while recording exact generated folder and output-item counts. Rust conversion enforces the same credential-ID, user-handle, RP-ID, and label bounds as the independent validator, so a strict-success output cannot fail that validator solely because those fields exceed its WebAuthn limits. Proton section names are retained in deterministic `Section / Field` labels rather than silently discarded; repeated derived prefixes are included in the projected-output budget. Native JSON URIs retain their complete trimmed values instead of inheriting the legacy Proton importer’s 1,000-character truncation.

The later passkey-only path addresses previously imported vaults without generating a second full copy of every item. It still parses the complete source and classifies duplicate credentials globally, but serializes exactly one minimal, unfiled login carrier per supported active passkey. Tests prove that source passwords, TOTP values, URLs, notes, fields, attachments, folders, favorite state, and item timestamps do not enter that output. Unsupported and trashed passkeys retain explicit outcomes, zero convertible credentials write no file, and each carrier is independently accepted by the pinned schema and cryptographic validator. Proton content format version 7 is accepted from the official schema-changing commit `61858d08ac1842cdd4eb1e16b7690279a38193cb`; version 8 remains rejected.

## Verification boundaries

The remediation was checked locally with formatting, warning-free Clippy, unit/property/integration/CLI tests, RustSec auditing with the reachability proof above, and the independent Node.js 22 validator. The published `SERIALIZED_V1`, `SERIALIZED_V2`, and `SERIALIZED_V3` historical-shape payloads were transcribed from pinned Proton Pass common source and remain outer format version 1. A separate passkey payload manually transcribed from `Proton Pass/data.json` inside Proton WebClients' synthetic `protonpass.zip` at commit `1ee27e1b54a4a3d0462ca1e35051bc58a0c4ac7b` is stored in regression-test constants; the ZIP itself is not vendored. Both pinned repositories license their code and data under GPL version 3 or later, matching this `GPL-3.0-or-later` repository. The WebClients payload deterministically produces a 138-byte PKCS#8 value with SHA-256 `b11a2fba5dfff80cdfd9ee13004599393a28b2edcb2ee2986aec73eb33908c9a`.

In addition, the actual `BitwardenJsonImporter` from pinned Bitwarden clients commit `2be53da5b7ec6f7608f2fc28a6f63d70d89ec53f` was run under Node.js 22.22.2 against converter output from the pinned Proton synthetic ZIP. It passed with 7 ciphers, 3 folders, and 1 exact FIDO credential view. `tests/bitwarden-json-importer.bridge.spec.ts` and `scripts/validate-bitwarden-importer.sh` record the repeatable bridge. This is parser-level compatibility evidence only. Separately, one real passkey-only migration was reported successful on August 13, 2026, but its exact environment and separate allowed-credential/discoverable outcomes were not recorded.

## Final verification matrix

The final measured file set above was checked on Ubuntu 24.04.4 LTS, Linux 7.0.0-28-generic x86-64, using Rust/Cargo 1.96.0, the declared Rust/Cargo 1.88.0 minimum, Node.js 22.22.2, and cargo-audit 0.22.2.

| Check | Final result |
|---|---|
| `cargo fmt --all -- --check` | Passed. |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with no warnings. |
| `cargo test --locked --all` | Passed: 56 unit/property, 13 CLI, 17 conversion/report, 26 hostile-input, and 4 passkey-only tests; 116 total. |
| `cargo +1.88.0 check --locked --all-targets --all-features` | Passed under the declared minimum Rust version. |
| JavaScript, shell, and workflow syntax | Both Node scripts passed `node --check`; the bridge shell script passed `bash -n`; both workflow files parsed as YAML. |
| `cargo audit --no-fetch --file Cargo.lock` | Passed against 1,216 advisories at database revision `69f93e1d081d8b6fbee010e48f0b5e0d13661415`, scanning 170 locked dependencies with only the documented inactive-`rsa` exception. |
| `cargo tree --locked --offline --target all -i rsa -e normal` | Succeeded with an empty normal dependency graph. |
| Release repeatability | The normal release build and a build in a newly empty target directory were byte-identical, SHA-256 `7b9a7395273ba4bf34b7356d482c356a17f09e21936a52df06b4905ab889bdf3`. This proves only same-host repeatability. |
| Pinned Proton WebClients ZIP | Strict conversion exited 0 with 7/7 items, 1/1 passkey, 3 folders, 7 output items, and zero strict failures. The output and report were both mode `0600`; their SHA-256 values were `f7eb8d0d2c94f05589d892aeea3a9f8dcc492a5a72ecd6a4bd45adf753e271cb` and `ad4e26940d8dc0983a84c1965f9ca8497fdd0fdcab597b9d04c2cd56ee5a6630`. |
| Independent passkey validator | Passed PKCS#8 import and ECDSA sign/verify for exactly one credential. |
| Pinned Bitwarden importer bridge | Passed with 7 full-vault ciphers, 3 folders, and one exact FIDO credential view; the parameterized passkey-only carrier checks also passed. |
| GitHub Actions CI | [Run `31749867742`](https://github.com/zimm3rmann/protonpass-to-bitwarden/actions/runs/31749867742) passed at commit `ebb76ce2da1b717b648dcd02dd1eb3d404c3c7b5` on Ubuntu 24.04, macOS 14, and Windows Server 2022. Platform jobs ran formatting, warning-free Clippy, the Rust test suite, Node validator syntax, and generated nonzero-passkey validation; the minimum-Rust and dependency-audit jobs also passed. |

The local verification rows above used only public synthetic fixtures, as did the hosted CI run. The manual release workflow was not run. The later user-reported field migration is recorded separately and is not presented as part of that controlled matrix.

The following remain deliberately unclaimed:

- a versioned, independently repeatable live Bitwarden import and authentication matrix;
- separately recorded discoverable and allowed-credential browser ceremonies after import;
- administrator/backup-privilege and non-NTFS/network-share Windows ACL behavior;
- a completed run of the new release workflow and independent cross-environment binary reproducibility;
- secure erasure, perfect zeroization, or resistance to a privileged/local-compromised host;
- atomic commitment of the vault and report as a pair.
