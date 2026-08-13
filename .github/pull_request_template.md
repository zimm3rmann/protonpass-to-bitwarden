## Summary

Describe the compatibility, safety, or documentation change.

## Evidence

Link the exact upstream revision or describe the synthetic reproduction. Do not attach real vault data or unredacted output.

## Verification

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked --all`
- [ ] Rust 1.88 compatibility checked when dependencies or public APIs changed
- [ ] No real export, generated vault, report, or credential material is included
- [ ] Report and strict-mode behavior were reviewed
- [ ] Documentation and changelog were updated when user behavior changed

## Compatibility and security impact

List unsupported cases, lossy mappings, new limits, dependency changes, or security assumptions. Write `None` only after checking.
