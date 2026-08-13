# Contributing

Contributions are welcome, especially focused compatibility fixes, hostile-input tests, documentation improvements, and updates tied to reviewed Proton or Bitwarden source changes.

## Protect vault data

Never submit a real Proton export, generated Bitwarden JSON, passkey blob, private key, TOTP seed, password, note, card record, recovery code, or unredacted migration report. This applies to issues, pull requests, commits, CI artifacts, chat, and email.

Use minimal synthetic fixtures with clearly fake domains such as `example.test`. If a problem can only be reproduced with real data, describe the structural shape without copying the value. Maintainers should never ask a reporter to upload a vault.

The OpenSSH private-key blocks already present in the test suite are intentionally generated synthetic fixtures. Secret-scanner exceptions, if needed, must be limited to those exact fixtures; do not disable private-key detection for the repository.

## Before opening an issue

1. Check that the export is unencrypted and its item content format is supported.
2. Run `inspect` and record only aggregate output.
3. Run the latest commit or release candidate.
4. Search existing issues.
5. Build a synthetic reproducer when possible.

Do not paste dependency or parser errors if they contain attacker-controlled source text. The CLI intentionally emits bounded messages; preserve that property in reports.

## Development setup

Install Rust through [rustup](https://rustup.rs/) and Node.js 22. The repository pins the normal compiler in `rust-toolchain.toml` and declares Rust 1.88 as its minimum supported version.

Run the same checks as CI:

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all
cargo +1.88.0 check --locked --all-targets --all-features
node --check scripts/validate-bitwarden-output.mjs
```

Changes to dependencies must update and review `Cargo.lock`. Changes to passkey decoding, Proton item versions, or Bitwarden output fields must cite the exact upstream source revision and include positive and negative regressions.

## Pull requests

Keep changes focused. Explain:

- the compatibility or safety behavior being changed;
- the upstream evidence or synthetic reproduction;
- the tests run;
- any data that remains unsupported or lossy;
- whether report or strict-mode behavior changes.

Do not add runtime networking, telemetry, update checks, account authentication, or secret-bearing diagnostics. Do not weaken resource limits, duplicate detection, cryptographic validation, redacted reporting, private output creation, or overwrite refusal without an explicit security review.

Do not stage, commit, or publish generated vaults or reports. Review `git status` before every commit.

## Security issues

Do not open a public issue for a vulnerability that would reveal sensitive exploitation details. Follow [SECURITY.md](SECURITY.md) and use GitHub private vulnerability reporting when it is enabled for the repository.
