use std::fs;
use std::io::Write;
use std::process::{Command as ProcessCommand, Output};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use tempfile::Builder;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

const PASSWORD_SENTINEL: &str = "SYNTHETIC_PASSWORD_MUST_NOT_BE_PRINTED";
const NAME_SENTINEL: &str = "SYNTHETIC_NAME_MUST_NOT_BE_PRINTED";
const TOTP_SENTINEL: &str = "SYNTHETIC_TOTP_MUST_NOT_BE_COPIED";
const NOTE_SENTINEL: &str = "SYNTHETIC_NOTE_MUST_NOT_BE_COPIED";
const FIELD_SENTINEL: &str = "SYNTHETIC_FIELD_MUST_NOT_BE_COPIED";
const URL_SENTINEL: &str = "synthetic-url-must-not-be-copied.invalid";
const PROTON_WEBCLIENTS_PASSKEY_CONTENT: &str = "gqFj3AGxzIXMo2tlecyGzKNrdHnMgsyhdMymYXNzaWduzKFjzKNFQzLMo2tpZMyQzKNhbGfMgsyhdMymYXNzaWduzKFjzKVFUzI1Nsyka29wc8yQzKNiaXbMkMyjcGFyzJTMksyCzKF0zKNpbnTMoWPM/8yCzKF0zKNpbnTMoWPMgcylaW5uZXLM3AAQAQAAAAAAAAAAAAAAAAAAAMySzILMoXTMo2ludMyhY8z+zILMoXTMpWJ5dGVzzKFjzNwAIMzMzM/MzMygKMzMzN9rzMzMrszMzPFPzMzM1ArMzMyOdszMzPxfQMzMzILMzMzdzMzMqVjMzMyyzMzM8kAAzMzM6nXMzMzjFczMzLUazMzM51AfzJLMgsyhdMyjaW50zKFjzP3MgsyhdMylYnl0ZXPMoWPM3AAgMXFgzMzM2MzMzLEeZkIAzMzMykVuKVk1zMzMxi/MzMyoaMzMzI/MzMzxzMzM0szMzLHMzMz+zMzM2czMzLIczMzMqMzMzJ/MzMzACF7MksyCzKF0zKNpbnTMoWPM/MyCzKF0zKVieXRlc8yhY8zcACAyF8zMzLfMzMyYzMzM/gjMzMy7HzAnJczMzN4veAQIY8zMzO7MzMyedszMzNNXZ2UeCMzMzJ/MzMzYzMzMwDA0XMyjY2lkzNwAEGEXcszMzIo+zMzM0czMzLLMzMypzMzMnMzMzPBBH8zMzK3MzMyOzMzMrszMzNzMo3JpZMyrd2ViYXV0aG4uaW/Mo3VoZMzcACtqRVdtTE5HVndtYXozdk15YVd6SW16ejFFRWxOUDVvUXhWSnlld3hubjNFzKNjbnTMwKF2AQ==";

fn private_tempdir() -> tempfile::TempDir {
    let temporary_root = fs::canonicalize(std::env::temp_dir()).unwrap();
    let directory = Builder::new().tempdir_in(temporary_root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

fn export_with(item_type: &str, content: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "version": "1",
        "vaults": {
            "fixture-vault-id": {
                "name": "Fixture Vault",
                "items": [{
                    "itemId": "fixture-item-id",
                    "shareId": "fixture-vault-id",
                    "state": 1,
                    "createTime": 1_700_000_000,
                    "modifyTime": 1_700_000_001,
                    "pinned": false,
                    "data": {
                        "metadata": {
                            "name": NAME_SENTINEL,
                            "note": "",
                            "itemUuid": "fixture-item-uuid"
                        },
                        "type": item_type,
                        "content": content
                    }
                }]
            }
        }
    }))
    .unwrap()
}

fn login_export() -> Vec<u8> {
    export_with(
        "login",
        json!({
            "itemUsername": "fixture-user",
            "password": PASSWORD_SENTINEL,
            "urls": ["example.test"],
            "passkeys": []
        }),
    )
}

fn passkey_login_export() -> Vec<u8> {
    export_with(
        "login",
        json!({
            "itemUsername": "yo",
            "password": PASSWORD_SENTINEL,
            "urls": ["webauthn.io"],
            "passkeys": [{
                "keyId": "YRdyij7Rsqmc8EEfrY6u3A",
                "content": PROTON_WEBCLIENTS_PASSKEY_CONTENT,
                "domain": "webauthn.io",
                "rpId": "webauthn.io",
                "rpName": "webauthn.io",
                "userName": "yo",
                "userDisplayName": "yo",
                "userId": "akVXbUxOR1Z3bWF6M3ZNeWFXekltenoxRUVsTlA1b1F4Vkp5ZXd4bm4zRQ==",
                "createTime": 1_714_982_805,
                "note": "",
                "credentialId": "YRdyij7Rsqmc8EEfrY6u3A==",
                "userHandle": "akVXbUxOR1Z3bWF6M3ZNeWFXekltenoxRUVsTlA1b1F4Vkp5ZXd4bm4zRQ=="
            }]
        }),
    )
}

fn passkey_only_login_export() -> Vec<u8> {
    let mut export: Value = serde_json::from_slice(&passkey_login_export()).unwrap();
    let data = &mut export["vaults"]["fixture-vault-id"]["items"][0]["data"];
    data["metadata"]["note"] = NOTE_SENTINEL.into();
    data["extraFields"] = json!([{
        "fieldName": "private fixture field",
        "type": "hidden",
        "data": { "content": FIELD_SENTINEL }
    }]);
    data["content"]["totpUri"] = format!("otpauth://totp/fixture?secret={TOTP_SENTINEL}").into();
    data["content"]["urls"] = json!([format!("https://{URL_SENTINEL}")]);
    serde_json::to_vec(&export).unwrap()
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8(output.stdout.clone()).unwrap(),
        String::from_utf8(output.stderr.clone()).unwrap(),
    )
}

fn assert_no_fixture_secrets(text: &str) {
    assert!(!text.contains(PASSWORD_SENTINEL));
    assert!(!text.contains(NAME_SENTINEL));
    assert!(!text.contains(TOTP_SENTINEL));
    assert!(!text.contains(NOTE_SENTINEL));
    assert!(!text.contains(FIELD_SENTINEL));
    assert!(!text.contains(URL_SENTINEL));
}

fn write_zip_export(path: &std::path::Path, content: &[u8]) {
    let mut writer = zip::ZipWriter::new(fs::File::create(path).unwrap());
    writer
        .start_file(
            "Proton Pass/data.json",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(content).unwrap();
    writer.finish().unwrap();
}

#[test]
fn inspect_prints_raw_source_and_aggregate_counts_only() {
    let directory = private_tempdir();
    let input = directory.path().join("proton.json");
    fs::write(&input, login_export()).unwrap();

    let output = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("inspect")
        .arg(&input)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&output);

    assert_eq!(output.status.code(), Some(0));
    assert!(stdout.contains("source: raw_json\n"));
    assert!(stdout.contains("items total: 1\n"));
    assert!(stdout.contains("items converted: 1\n"));
    assert!(stdout.contains("items skipped or unsupported: 0\n"));
    assert!(stdout.contains("passkeys total: 0\n"));
    assert!(stdout.contains("passkeys skipped: 0\n"));
    assert!(stdout.contains("strict failures: 0\n"));
    assert!(stderr.contains("WARNING:"));
    assert_no_fixture_secrets(&stdout);
    assert_no_fixture_secrets(&stderr);
}

#[test]
fn inspect_labels_zip_input_and_preserves_aggregate_output() {
    let directory = private_tempdir();
    let input = directory.path().join("ProtonPass.zip");
    write_zip_export(&input, &login_export());

    let output = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("inspect")
        .arg(&input)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&output);

    assert_eq!(output.status.code(), Some(0));
    assert!(stdout.contains("source: zip\n"));
    assert!(stdout.contains("items total: 1\n"));
    assert!(stdout.contains("items converted: 1\n"));
    assert_no_fixture_secrets(&stdout);
    assert_no_fixture_secrets(&stderr);
}

#[test]
fn convert_writes_native_json_redacted_report_and_aggregate_counts() {
    let directory = private_tempdir();
    let input = directory.path().join("proton.json");
    let destination = directory.path().join("bitwarden.json");
    let report = directory.path().join("report.json");
    fs::write(&input, login_export()).unwrap();

    let output = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert")
        .arg(&input)
        .arg("--output")
        .arg(&destination)
        .arg("--report")
        .arg(&report)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&output);

    assert_eq!(output.status.code(), Some(0));
    assert!(stdout.contains("items total: 1\n"));
    assert!(stdout.contains("items converted: 1\n"));
    assert!(stdout.contains("strict failures: 0\n"));
    assert!(stderr.contains("The source export was not modified or deleted."));
    assert_no_fixture_secrets(&stdout);
    assert_no_fixture_secrets(&stderr);

    let converted: Value = serde_json::from_slice(&fs::read(&destination).unwrap()).unwrap();
    assert_eq!(converted["encrypted"], false);
    assert_eq!(converted["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        converted["items"][0]["login"]["password"],
        PASSWORD_SENTINEL
    );

    let report_bytes = fs::read(&report).unwrap();
    let report_json: Value = serde_json::from_slice(&report_bytes).unwrap();
    assert_eq!(report_json["names_redacted"], true);
    assert_eq!(report_json["summary"]["items_total"], 1);
    assert_no_fixture_secrets(std::str::from_utf8(&report_bytes).unwrap());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&report).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn overwrite_is_refused_and_force_replaces_both_files() {
    let directory = private_tempdir();
    let input = directory.path().join("proton.json");
    let destination = directory.path().join("bitwarden.json");
    let report = directory.path().join("report.json");
    fs::write(&input, login_export()).unwrap();
    fs::write(&destination, b"existing output").unwrap();
    fs::write(&report, b"existing report").unwrap();

    let refused = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert")
        .arg(&input)
        .arg("--output")
        .arg(&destination)
        .arg("--report")
        .arg(&report)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&refused);

    assert_eq!(refused.status.code(), Some(4));
    assert!(stderr.contains("destination already exists"));
    assert_eq!(fs::read(&destination).unwrap(), b"existing output");
    assert_eq!(fs::read(&report).unwrap(), b"existing report");
    assert_no_fixture_secrets(&stdout);
    assert_no_fixture_secrets(&stderr);

    let replaced = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert")
        .arg(&input)
        .arg("--output")
        .arg(&destination)
        .arg("--report")
        .arg(&report)
        .arg("--force")
        .output()
        .unwrap();

    assert_eq!(replaced.status.code(), Some(0));
    assert!(serde_json::from_slice::<Value>(&fs::read(&destination).unwrap()).is_ok());
    assert!(serde_json::from_slice::<Value>(&fs::read(&report).unwrap()).is_ok());
}

#[test]
fn input_output_and_output_report_aliases_are_rejected() {
    let directory = private_tempdir();
    let input = directory.path().join("proton.json");
    let report = directory.path().join("report.json");
    fs::write(&input, login_export()).unwrap();
    let original = fs::read(&input).unwrap();

    let input_alias = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert")
        .arg(&input)
        .arg("--output")
        .arg(&input)
        .arg("--report")
        .arg(&report)
        .arg("--force")
        .output()
        .unwrap();

    assert_eq!(input_alias.status.code(), Some(4));
    assert!(text(&input_alias).1.contains("paths must be distinct"));
    assert_eq!(fs::read(&input).unwrap(), original);
    assert!(!report.exists());

    let shared_destination = directory.path().join("shared.json");
    let output_alias = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert")
        .arg(&input)
        .arg("--output")
        .arg(&shared_destination)
        .arg("--report")
        .arg(&shared_destination)
        .output()
        .unwrap();

    assert_eq!(output_alias.status.code(), Some(4));
    assert!(text(&output_alias).1.contains("paths must be distinct"));
    assert!(!shared_destination.exists());
}

#[test]
fn strict_mode_writes_report_then_exits_with_strict_failure() {
    let directory = private_tempdir();
    let input = directory.path().join("proton.json");
    let destination = directory.path().join("bitwarden.json");
    let report = directory.path().join("report.json");
    fs::write(
        &input,
        export_with(
            "wifi",
            json!({
                "ssid": "fixture-network",
                "password": PASSWORD_SENTINEL,
                "security": 2,
                "sections": []
            }),
        ),
    )
    .unwrap();

    let output = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert")
        .arg(&input)
        .arg("--output")
        .arg(&destination)
        .arg("--report")
        .arg(&report)
        .arg("--strict")
        .output()
        .unwrap();
    let (stdout, stderr) = text(&output);

    assert_eq!(output.status.code(), Some(5));
    assert!(stdout.contains("items converted: 1\n"));
    assert!(stdout.contains("strict failures: 1\n"));
    assert!(stderr.contains("strict mode found records that were not fully migrated"));
    assert!(destination.exists());
    let report_json: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(report_json["summary"]["strict_failures"], 1);
    assert_no_fixture_secrets(&stdout);
    assert_no_fixture_secrets(&stderr);
}

#[test]
fn malformed_json_error_redacts_content_and_path() {
    let directory = private_tempdir();
    let input = directory.path().join("secretly-named-input.json");
    let malformed_secret = "SYNTHETIC_MALFORMED_SECRET_MUST_NOT_BE_PRINTED";
    fs::write(
        &input,
        format!(r#"{{"vaults":{{}},"password":"{malformed_secret}""#),
    )
    .unwrap();

    let output = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("inspect")
        .arg(&input)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&output);

    assert_eq!(output.status.code(), Some(3));
    assert!(stderr.contains("JSON is malformed at line"));
    assert!(!stderr.contains(malformed_secret));
    assert!(!stderr.contains("secretly-named-input.json"));
    assert!(!stdout.contains(malformed_secret));
}

#[test]
fn clap_usage_errors_exit_with_code_two() {
    let output = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output).1.contains("Usage:"));
}

#[test]
fn help_explains_output_and_strict_mode_behavior() {
    let root = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("--help")
        .output()
        .unwrap();
    let convert = cargo_bin_cmd!("protonpass-to-bitwarden")
        .args(["convert", "--help"])
        .output()
        .unwrap();
    let passkeys = cargo_bin_cmd!("protonpass-to-bitwarden")
        .args(["convert-passkeys", "--help"])
        .output()
        .unwrap();

    assert_eq!(root.status.code(), Some(0));
    assert!(
        text(&root)
            .0
            .contains("native Bitwarden JSON entirely offline")
    );
    assert_eq!(convert.status.code(), Some(0));
    let stdout = text(&convert).0;
    assert!(stdout.contains("New native Bitwarden JSON destination"));
    assert!(stdout.contains("Exit with code 5 after writing both files"));
    assert!(stdout.contains("false can expose sensitive metadata"));
    assert_eq!(passkeys.status.code(), Some(0));
    let passkeys_stdout = text(&passkeys).0;
    assert!(passkeys_stdout.contains("does not merge with existing Bitwarden items"));
    assert!(passkeys_stdout.contains("intentionally omits Proton passwords"));
}

#[test]
fn convert_passkeys_writes_only_minimal_standalone_carriers() {
    let directory = private_tempdir();
    let input = directory.path().join("proton.json");
    let destination = directory.path().join("bitwarden-passkeys.json");
    let report = directory.path().join("passkey-report.json");
    fs::write(&input, passkey_only_login_export()).unwrap();

    let output = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert-passkeys")
        .arg(&input)
        .arg("--output")
        .arg(&destination)
        .arg("--report")
        .arg(&report)
        .arg("--strict")
        .output()
        .unwrap();
    let (stdout, stderr) = text(&output);

    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("new standalone Bitwarden login carriers"));
    assert!(stdout.contains("passkeys converted: 1\n"));
    assert!(stdout.contains("items intentionally filtered: 1\n"));
    assert_no_fixture_secrets(&stdout);
    assert_no_fixture_secrets(&stderr);

    let output_bytes = fs::read(&destination).unwrap();
    let output_text = std::str::from_utf8(&output_bytes).unwrap();
    assert!(!output_text.contains(PASSWORD_SENTINEL));
    assert!(!output_text.contains(TOTP_SENTINEL));
    assert!(!output_text.contains(NOTE_SENTINEL));
    assert!(!output_text.contains(FIELD_SENTINEL));
    assert!(!output_text.contains(URL_SENTINEL));

    let converted: Value = serde_json::from_slice(&output_bytes).unwrap();
    assert_eq!(converted["folders"], json!([]));
    let items = converted["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let item = items[0].as_object().unwrap();
    assert_eq!(item["type"], 1);
    assert_eq!(item["reprompt"], 0);
    assert_eq!(item["favorite"], false);
    for omitted in [
        "folderId",
        "notes",
        "fields",
        "secureNote",
        "card",
        "identity",
        "sshKey",
        "creationDate",
        "revisionDate",
    ] {
        assert!(!item.contains_key(omitted), "unexpected field {omitted}");
    }
    let login = item["login"].as_object().unwrap();
    assert_eq!(login.len(), 1);
    assert_eq!(login["fido2Credentials"].as_array().unwrap().len(), 1);

    let report_json: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(report_json["mode"], "passkeys_only");
    assert_eq!(report_json["summary"]["items_filtered"], 1);
    assert_eq!(report_json["summary"]["passkeys_converted"], 1);
    assert_eq!(report_json["summary"]["output_items_created"], 1);

    let validator = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts/validate-bitwarden-output.mjs");
    let validated = ProcessCommand::new("node")
        .arg(validator)
        .arg(&destination)
        .args(["--expected-count", "1"])
        .output()
        .unwrap();
    assert_eq!(validated.status.code(), Some(0), "{:?}", text(&validated));
}

#[test]
fn convert_passkeys_refuses_empty_output() {
    let directory = private_tempdir();
    let input = directory.path().join("proton.json");
    let destination = directory.path().join("bitwarden-passkeys.json");
    let report = directory.path().join("passkey-report.json");
    fs::write(&input, login_export()).unwrap();

    let output = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert-passkeys")
        .arg(&input)
        .arg("--output")
        .arg(&destination)
        .arg("--report")
        .arg(&report)
        .output()
        .unwrap();
    let (stdout, stderr) = text(&output);

    assert_eq!(output.status.code(), Some(3));
    assert!(stderr.contains("no active passkeys could be converted"));
    assert!(!destination.exists());
    assert!(!report.exists());
    assert_no_fixture_secrets(&stdout);
    assert_no_fixture_secrets(&stderr);
}

#[test]
fn independent_validator_checks_generated_nonzero_passkey() {
    let directory = private_tempdir();
    let input = directory.path().join("proton.json");
    let destination = directory.path().join("bitwarden.json");
    let report = directory.path().join("report.json");
    fs::write(&input, passkey_login_export()).unwrap();

    let conversion = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert")
        .arg(&input)
        .arg("--output")
        .arg(&destination)
        .arg("--report")
        .arg(&report)
        .arg("--strict")
        .output()
        .unwrap();
    assert_eq!(conversion.status.code(), Some(0), "{:?}", text(&conversion));

    let validator = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts/validate-bitwarden-output.mjs");
    let validated = ProcessCommand::new("node")
        .arg(&validator)
        .arg(&destination)
        .args(["--expected-count", "1"])
        .output()
        .unwrap();
    let (stdout, stderr) = text(&validated);
    assert_eq!(validated.status.code(), Some(0), "{stderr}");
    assert_eq!(
        stdout,
        "validated cryptographic key material for 1 passkey\n"
    );
    assert!(stderr.is_empty());
    assert_no_fixture_secrets(&stdout);

    let mismatch = ProcessCommand::new("node")
        .arg(&validator)
        .arg(&destination)
        .args(["--expected-count", "2"])
        .output()
        .unwrap();
    let (stdout, stderr) = text(&mismatch);
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(stdout.is_empty());
    assert_eq!(
        stderr,
        "validation failed without displaying vault contents\n"
    );
    assert_no_fixture_secrets(&stderr);

    let missing_count = ProcessCommand::new("node")
        .arg(&validator)
        .arg(&destination)
        .output()
        .unwrap();
    assert_eq!(missing_count.status.code(), Some(2));
    assert!(text(&missing_count).1.starts_with("usage:"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let alias = directory.path().join("bitwarden-link.json");
        symlink(&destination, &alias).unwrap();
        let symlinked = ProcessCommand::new("node")
            .arg(&validator)
            .arg(&alias)
            .args(["--expected-count", "1"])
            .output()
            .unwrap();
        let (stdout, stderr) = text(&symlinked);
        assert_eq!(symlinked.status.code(), Some(1));
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "validation failed without displaying vault contents\n"
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_destination_is_rejected_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let directory = private_tempdir();
    let input = directory.path().join("proton.json");
    let target = directory.path().join("target.json");
    let destination = directory.path().join("bitwarden.json");
    let report = directory.path().join("report.json");
    fs::write(&input, login_export()).unwrap();
    fs::write(&target, b"target sentinel").unwrap();
    symlink(&target, &destination).unwrap();

    let output = cargo_bin_cmd!("protonpass-to-bitwarden")
        .arg("convert")
        .arg(&input)
        .arg("--output")
        .arg(&destination)
        .arg("--report")
        .arg(&report)
        .arg("--force")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    assert!(text(&output).1.contains("path is invalid or unsafe"));
    assert_eq!(fs::read(&target).unwrap(), b"target sentinel");
    assert!(!report.exists());
}
