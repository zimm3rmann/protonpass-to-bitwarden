use std::fs;
use std::io::Write;
use std::path::Path;

use protonpass_to_bitwarden::{AppError, InputLimits, load_export};
use tempfile::NamedTempFile;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

const DATA_JSON: &str = "Proton Pass/data.json";
const MINIMAL: &[u8] = br#"{"version":"1","vaults":{}}"#;
const LOCAL_HEADER: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CENTRAL_HEADER: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const CENTRAL_DIRECTORY_END: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

fn stored_options() -> SimpleFileOptions {
    SimpleFileOptions::default().compression_method(CompressionMethod::Stored)
}

fn zip_with(entries: &[(&str, &[u8])]) -> NamedTempFile {
    let archive = NamedTempFile::new().unwrap();
    {
        let mut writer = zip::ZipWriter::new(archive.reopen().unwrap());
        for (name, content) in entries {
            writer.start_file(*name, stored_options()).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap();
    }
    archive
}

fn write_raw(content: &[u8]) -> NamedTempFile {
    let mut input = NamedTempFile::new().unwrap();
    input.write_all(content).unwrap();
    input
}

fn assert_unsafe_archive(path: &Path) {
    assert!(matches!(
        load_export(path, InputLimits::default()),
        Err(AppError::UnsafeArchive)
    ));
}

fn header_positions(bytes: &[u8], signature: [u8; 4]) -> Vec<usize> {
    bytes
        .windows(signature.len())
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == signature).then_some(index))
        .collect()
}

fn patch_u16(bytes: &mut [u8], header: usize, field_offset: usize, value: u16) {
    bytes[header + field_offset..header + field_offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], header: usize, field_offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[header + field_offset..header + field_offset + 2]
            .try_into()
            .unwrap(),
    )
}

fn read_u32(bytes: &[u8], header: usize, field_offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[header + field_offset..header + field_offset + 4]
            .try_into()
            .unwrap(),
    )
}

fn patch_u32(bytes: &mut [u8], header: usize, field_offset: usize, value: u32) {
    bytes[header + field_offset..header + field_offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn end_position(bytes: &[u8]) -> usize {
    *header_positions(bytes, CENTRAL_DIRECTORY_END)
        .last()
        .unwrap()
}

fn replace_fixed(bytes: &mut [u8], from: &[u8], to: &[u8]) -> usize {
    assert_eq!(from.len(), to.len());
    let positions: Vec<_> = bytes
        .windows(from.len())
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == from).then_some(index))
        .collect();
    for position in &positions {
        bytes[*position..*position + to.len()].copy_from_slice(to);
    }
    positions.len()
}

#[test]
fn rejects_traversal_absolute_drive_backslash_and_nul_entry_names() {
    let unsafe_names = [
        "../Proton Pass/data.json",
        "Proton Pass/../data.json",
        "Proton Pass//data.json",
        "Proton Pass/./data.json",
        "/Proton Pass/data.json",
        "//server/share/data.json",
        "C:/Proton Pass/data.json",
        "C:\\Proton Pass\\data.json",
        "Proton Pass\\data.json",
        "Proton Pass/data.json\0ignored",
    ];

    for name in unsafe_names {
        let archive = zip_with(&[(name, b"unsafe"), (DATA_JSON, MINIMAL)]);
        assert!(
            matches!(
                load_export(archive.path(), InputLimits::default()),
                Err(AppError::UnsafeArchive)
            ),
            "unsafe ZIP entry was not rejected: {name:?}"
        );
    }
}

#[test]
fn rejects_non_utf8_entry_names() {
    let alternate = "Proton Pass/evil.json";
    let archive = zip_with(&[(DATA_JSON, MINIMAL), (alternate, b"unsafe")]);
    let mut bytes = fs::read(archive.path()).unwrap();
    let mut invalid = alternate.as_bytes().to_vec();
    invalid[12] = 0xff;
    assert_eq!(replace_fixed(&mut bytes, alternate.as_bytes(), &invalid), 2);
    fs::write(archive.path(), bytes).unwrap();

    assert_unsafe_archive(archive.path());
}

#[test]
fn rejects_duplicate_data_json_entries() {
    let alternate = "Proton Pass/evil.json";
    let archive = zip_with(&[(DATA_JSON, MINIMAL), (alternate, MINIMAL)]);
    let mut bytes = fs::read(archive.path()).unwrap();
    assert_eq!(
        replace_fixed(&mut bytes, alternate.as_bytes(), DATA_JSON.as_bytes()),
        2
    );
    fs::write(archive.path(), bytes).unwrap();

    assert!(matches!(
        load_export(archive.path(), InputLimits::default()),
        Err(AppError::MissingOrAmbiguousData | AppError::UnsafeArchive)
    ));
}

#[test]
fn rejects_json_zip_that_also_contains_pgp() {
    let archive = zip_with(&[
        (DATA_JSON, MINIMAL),
        ("Proton Pass/data.pgp", b"synthetic encrypted payload"),
    ]);

    assert!(matches!(
        load_export(archive.path(), InputLimits::default()),
        Err(AppError::EncryptedExport)
    ));
}

#[test]
fn rejects_raw_armored_pgp_after_whitespace() {
    let input = write_raw(b" \n\t-----BEGIN PGP MESSAGE-----\nsynthetic");

    assert!(matches!(
        load_export(input.path(), InputLimits::default()),
        Err(AppError::EncryptedExport)
    ));
}

#[test]
fn rejects_zip_entries_with_unsupported_compression() {
    let archive = zip_with(&[(DATA_JSON, MINIMAL)]);
    let mut bytes = fs::read(archive.path()).unwrap();
    let local = header_positions(&bytes, LOCAL_HEADER);
    let central = header_positions(&bytes, CENTRAL_HEADER);
    assert_eq!(local.len(), 1);
    assert_eq!(central.len(), 1);
    patch_u16(&mut bytes, local[0], 8, 93);
    patch_u16(&mut bytes, central[0], 10, 93);
    fs::write(archive.path(), bytes).unwrap();

    assert_unsafe_archive(archive.path());
}

#[test]
fn rejects_zip_entries_marked_as_encrypted() {
    let archive = zip_with(&[(DATA_JSON, MINIMAL)]);
    let mut bytes = fs::read(archive.path()).unwrap();
    let local = header_positions(&bytes, LOCAL_HEADER);
    let central = header_positions(&bytes, CENTRAL_HEADER);
    assert_eq!(local.len(), 1);
    assert_eq!(central.len(), 1);
    let local_flags = read_u16(&bytes, local[0], 6) | 1;
    let central_flags = read_u16(&bytes, central[0], 8) | 1;
    patch_u16(&mut bytes, local[0], 6, local_flags);
    patch_u16(&mut bytes, central[0], 8, central_flags);
    fs::write(archive.path(), bytes).unwrap();

    assert_unsafe_archive(archive.path());
}

#[test]
fn rejects_overlapping_zip_entries() {
    let archive = zip_with(&[(DATA_JSON, MINIMAL), ("decoy", b"x")]);
    let mut bytes = fs::read(archive.path()).unwrap();
    let central = header_positions(&bytes, CENTRAL_HEADER);
    assert_eq!(central.len(), 2);
    let first_local_offset = read_u32(&bytes, central[0], 42);
    patch_u32(&mut bytes, central[1], 42, first_local_offset);
    fs::write(archive.path(), bytes).unwrap();

    assert_unsafe_archive(archive.path());
}

#[test]
fn rejects_symlink_entries() {
    let archive = NamedTempFile::new().unwrap();
    {
        let mut writer = zip::ZipWriter::new(archive.reopen().unwrap());
        writer
            .add_symlink(DATA_JSON, "elsewhere", stored_options())
            .unwrap();
        writer.finish().unwrap();
    }

    assert_unsafe_archive(archive.path());
}

#[test]
fn enforces_archive_json_and_entry_count_limits() {
    let archive = zip_with(&[(DATA_JSON, MINIMAL), ("metadata", b"x")]);
    let archive_size = fs::metadata(archive.path()).unwrap().len();

    let archive_limit = InputLimits {
        max_archive_bytes: archive_size - 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(archive.path(), archive_limit),
        Err(AppError::InputTooLarge)
    ));

    let json_limit = InputLimits {
        max_json_bytes: MINIMAL.len() as u64 - 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(archive.path(), json_limit),
        Err(AppError::InputTooLarge)
    ));

    let entry_limit = InputLimits {
        max_entries: 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(archive.path(), entry_limit),
        Err(AppError::UnsafeArchive)
    ));
}

#[test]
fn enforces_raw_file_and_json_limits() {
    let input = write_raw(MINIMAL);

    let archive_limit = InputLimits {
        max_archive_bytes: MINIMAL.len() as u64 - 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(input.path(), archive_limit),
        Err(AppError::InputTooLarge)
    ));

    let json_limit = InputLimits {
        max_json_bytes: MINIMAL.len() as u64 - 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(input.path(), json_limit),
        Err(AppError::InputTooLarge)
    ));
}

#[test]
fn enforces_vault_item_and_passkey_count_limits() {
    let one_vault = write_raw(
        serde_json::to_string(&serde_json::json!({
            "version": "1",
            "vaults": {"v": {"items": []}}
        }))
        .unwrap()
        .as_bytes(),
    );
    let vault_limit = InputLimits {
        max_vaults: 0,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(one_vault.path(), vault_limit),
        Err(AppError::InputTooLarge)
    ));

    let one_item = write_raw(
        serde_json::to_string(&serde_json::json!({
            "version": "1",
            "vaults": {"v": {"items": [{
                "data": {
                    "type": "note",
                    "content": {}
                }
            }]}}
        }))
        .unwrap()
        .as_bytes(),
    );
    let item_limit = InputLimits {
        max_items: 0,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(one_item.path(), item_limit),
        Err(AppError::InputTooLarge)
    ));

    let passkey = serde_json::json!({
        "keyId": "",
        "content": "",
        "domain": "",
        "rpId": "",
        "rpName": "",
        "userName": "",
        "userDisplayName": "",
        "userId": "",
        "note": "",
        "credentialId": "",
        "userHandle": ""
    });
    let one_passkey = write_raw(
        serde_json::to_string(&serde_json::json!({
            "version": "1",
            "vaults": {"v": {"items": [{
                "data": {
                    "type": "login",
                    "content": {"passkeys": [passkey]}
                }
            }]}}
        }))
        .unwrap()
        .as_bytes(),
    );
    let passkey_limit = InputLimits {
        max_passkeys_per_item: 0,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(one_passkey.path(), passkey_limit),
        Err(AppError::InputTooLarge)
    ));
}

#[test]
fn preflights_declared_count_and_central_directory_budgets() {
    let archive = zip_with(&[(DATA_JSON, MINIMAL)]);
    let original = fs::read(archive.path()).unwrap();
    let eocd = end_position(&original);

    let mut excessive_count = original.clone();
    patch_u16(&mut excessive_count, eocd, 8, 101);
    patch_u16(&mut excessive_count, eocd, 10, 101);
    fs::write(archive.path(), excessive_count).unwrap();
    let count_limit = InputLimits {
        max_entries: 100,
        ..InputLimits::default()
    };
    assert_unsafe_archive_with_limits(archive.path(), count_limit);

    fs::write(archive.path(), &original).unwrap();
    let directory_limit = InputLimits {
        max_central_directory_bytes: 1,
        ..InputLimits::default()
    };
    assert_unsafe_archive_with_limits(archive.path(), directory_limit);

    let name_limit = InputLimits {
        max_entry_name_bytes: DATA_JSON.len() - 1,
        ..InputLimits::default()
    };
    assert_unsafe_archive_with_limits(archive.path(), name_limit);
}

#[test]
fn preflights_zip64_declared_entry_count() {
    let archive = zip_with(&[(DATA_JSON, MINIMAL)]);
    let original = fs::read(archive.path()).unwrap();
    let eocd = end_position(&original);
    let directory_size = read_u32(&original, eocd, 12) as u64;
    let directory_offset = read_u32(&original, eocd, 16) as u64;
    let mut bytes = original[..eocd].to_vec();
    bytes.extend_from_slice(&[0x50, 0x4b, 0x06, 0x06]);
    bytes.extend_from_slice(&44_u64.to_le_bytes());
    bytes.extend_from_slice(&45_u16.to_le_bytes());
    bytes.extend_from_slice(&45_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&101_u64.to_le_bytes());
    bytes.extend_from_slice(&101_u64.to_le_bytes());
    bytes.extend_from_slice(&directory_size.to_le_bytes());
    bytes.extend_from_slice(&directory_offset.to_le_bytes());
    bytes.extend_from_slice(&[0x50, 0x4b, 0x06, 0x07]);
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&(eocd as u64).to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    let standard_eocd = bytes.len();
    bytes.extend_from_slice(&original[eocd..]);
    patch_u16(&mut bytes, standard_eocd, 8, u16::MAX);
    patch_u16(&mut bytes, standard_eocd, 10, u16::MAX);
    patch_u32(&mut bytes, standard_eocd, 12, u32::MAX);
    patch_u32(&mut bytes, standard_eocd, 16, u32::MAX);
    fs::write(archive.path(), bytes).unwrap();

    let limits = InputLimits {
        max_entries: 100,
        ..InputLimits::default()
    };
    assert_unsafe_archive_with_limits(archive.path(), limits);
}

#[test]
fn rejects_multidisk_and_ambiguous_eocd_records() {
    let archive = zip_with(&[(DATA_JSON, MINIMAL)]);
    let original = fs::read(archive.path()).unwrap();
    let eocd = end_position(&original);

    let mut multidisk = original.clone();
    patch_u16(&mut multidisk, eocd, 4, 1);
    fs::write(archive.path(), multidisk).unwrap();
    assert_unsafe_archive(archive.path());

    let mut ambiguous = original;
    let eocd = end_position(&ambiguous);
    patch_u16(&mut ambiguous, eocd, 20, 22);
    ambiguous.extend_from_slice(&[
        0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    fs::write(archive.path(), ambiguous).unwrap();
    assert_unsafe_archive(archive.path());
}

#[test]
fn rejects_duplicate_vault_keys_and_unknown_known_record_fields() {
    let duplicate =
        write_raw(br#"{"version":"1","vaults":{"same":{"items":[]},"same":{"items":[]}}}"#);
    assert!(matches!(
        load_export(duplicate.path(), InputLimits::default()),
        Err(AppError::InvalidJson { .. })
    ));

    let unknown_top =
        write_raw(br#"{"version":"1","vaults":{},"unexpected":{"password":"SYNTHETIC_SECRET"}}"#);
    assert!(matches!(
        load_export(unknown_top.path(), InputLimits::default()),
        Err(AppError::InvalidJson { .. })
    ));

    let unknown_login = write_raw(
        br#"{"version":"1","vaults":{"v":{"items":[{"itemId":"i","state":1,"data":{"type":"login","content":{"unexpected":"SYNTHETIC_SECRET"}}}]}}}"#,
    );
    assert!(matches!(
        load_export(unknown_login.path(), InputLimits::default()),
        Err(AppError::InvalidJson { .. })
    ));
}

#[test]
fn accepts_current_display_and_share_count_fields() {
    let input = write_raw(
        br#"{"version":"5.0.999.999","vaults":{"v":{"display":{"icon":0,"color":0},"items":[{"itemId":"i","state":1,"contentFormatVersion":6,"shareCount":2,"data":{"type":"note","content":{}}}]}}}"#,
    );
    let loaded = load_export(input.path(), InputLimits::default()).unwrap();
    assert_eq!(loaded.export.vaults["v"].items.len(), 1);

    let invalid_display = write_raw(
        br#"{"version":"5.0.999.999","vaults":{"v":{"display":{"color":"red"},"items":[]}}}"#,
    );
    assert!(matches!(
        load_export(invalid_display.path(), InputLimits::default()),
        Err(AppError::InvalidJson { .. })
    ));

    let invalid_share_count = write_raw(
        br#"{"version":"5.0.999.999","vaults":{"v":{"items":[{"itemId":"i","state":1,"shareCount":"2","data":{"type":"note","content":{}}}]}}}"#,
    );
    assert!(matches!(
        load_export(invalid_share_count.path(), InputLimits::default()),
        Err(AppError::InvalidJson { .. })
    ));
}

#[test]
fn enforces_versions_folder_nested_and_projected_output_limits() {
    let current_version = write_raw(br#"{"version":"5.0.999.999","vaults":{}}"#);
    assert!(load_export(current_version.path(), InputLimits::default()).is_ok());

    let current_content_version = write_raw(
        br#"{"version":"5.0.999.999","vaults":{"v":{"items":[{"itemId":"i","state":1,"contentFormatVersion":7,"data":{"type":"note","content":{}}}]}}}"#,
    );
    assert!(load_export(current_content_version.path(), InputLimits::default()).is_ok());

    let bad_content_version = write_raw(
        br#"{"version":"5.0.999.999","vaults":{"v":{"items":[{"itemId":"i","state":1,"contentFormatVersion":8,"data":{"type":"note","content":{}}}]}}}"#,
    );
    assert!(matches!(
        load_export(bad_content_version.path(), InputLimits::default()),
        Err(AppError::InvalidExport)
    ));

    let folder = write_raw(br#"{"version":"1","vaults":{"v":{"name":"one/two","items":[]}}}"#);
    let folder_limits = InputLimits {
        max_folder_depth: 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(folder.path(), folder_limits),
        Err(AppError::InvalidExport)
    ));

    let nested = write_raw(
        br#"{"version":"1","vaults":{"v":{"items":[{"itemId":"i","state":1,"data":{"type":"login","content":{"urls":["a","b"]}}}]}}}"#,
    );
    let nested_limits = InputLimits {
        max_nested_elements: 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(nested.path(), nested_limits),
        Err(AppError::InputTooLarge)
    ));

    let passkey = serde_json::json!({
        "keyId": "",
        "content": "",
        "domain": "",
        "rpId": "",
        "rpName": "",
        "userName": "",
        "userDisplayName": "",
        "userId": "",
        "note": "",
        "credentialId": "",
        "userHandle": ""
    });
    let projected = write_raw(
        serde_json::to_string(&serde_json::json!({
            "version": "1",
            "vaults": {"v": {"items": [{
                "itemId": "i",
                "state": 1,
                "data": {
                    "type": "login",
                    "content": {
                        "password": "a".repeat(1024),
                        "passkeys": [passkey.clone(), passkey]
                    }
                }
            }]}}
        }))
        .unwrap()
        .as_bytes(),
    );
    let projected_limits = InputLimits {
        max_projected_output_bytes: 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(projected.path(), projected_limits),
        Err(AppError::InputTooLarge)
    ));
}

#[test]
fn rejects_empty_folder_components_without_rejecting_trimmed_leading_slashes() {
    for name in ["one//two".to_owned(), format!("one{}two", "/".repeat(2048))] {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "version": "1",
            "vaults": {"v": {"name": name, "items": []}}
        }))
        .unwrap();
        let input = write_raw(&bytes);
        assert!(matches!(
            load_export(input.path(), InputLimits::default()),
            Err(AppError::InvalidExport)
        ));
    }

    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": "1",
        "vaults": {"v": {"name": "///one/two", "items": []}}
    }))
    .unwrap();
    let input = write_raw(&bytes);
    assert!(load_export(input.path(), InputLimits::default()).is_ok());
}

#[test]
fn accounts_for_each_unique_generated_folder_prefix_in_the_output_budget() {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": "1",
        "vaults": {
            "v1": {"name": "one/two/three", "items": []},
            "v2": {"name": "one/two/four", "items": []}
        }
    }))
    .unwrap();
    let input = write_raw(&bytes);
    let base = (bytes.len() as u64) * 4;
    let generated_folder_bytes = (56 + 3) + (56 + 7) + (56 + 13) + (56 + 12);

    let insufficient = InputLimits {
        max_projected_output_bytes: base + generated_folder_bytes - 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(input.path(), insufficient),
        Err(AppError::InputTooLarge)
    ));

    let exact = InputLimits {
        max_projected_output_bytes: base + generated_folder_bytes,
        ..InputLimits::default()
    };
    assert!(load_export(input.path(), exact).is_ok());
}

#[test]
fn enforces_section_name_byte_limit_at_the_default_boundary() {
    let section_export = |section_name: String| {
        serde_json::to_vec(&serde_json::json!({
            "version": "1",
            "vaults": {"v": {"items": [{
                "itemId": "i",
                "state": 1,
                "data": {
                    "type": "custom",
                    "content": {"sections": [{
                        "sectionName": section_name,
                        "sectionFields": [{
                            "fieldName": "Field",
                            "type": "text",
                            "data": {"content": "value"}
                        }]
                    }]}
                }
            }]}}
        }))
        .unwrap()
    };
    let limit = InputLimits::default().max_section_name_bytes;
    let accepted = write_raw(&section_export("s".repeat(limit)));
    assert!(load_export(accepted.path(), InputLimits::default()).is_ok());

    let rejected = write_raw(&section_export("s".repeat(limit + 1)));
    assert!(matches!(
        load_export(rejected.path(), InputLimits::default()),
        Err(AppError::InputTooLarge)
    ));
}

#[test]
fn accounts_for_repeated_section_prefixes_in_the_output_budget() {
    let section_name = "section-prefix".repeat(16);
    let fields = (0..64)
        .map(|index| {
            serde_json::json!({
                "fieldName": format!("Field {index}"),
                "type": "text",
                "data": {"content": "value"}
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": "1",
        "vaults": {"v": {"items": [{
            "itemId": "i",
            "state": 1,
            "data": {
                "type": "custom",
                "content": {"sections": [{
                    "sectionName": section_name.clone(),
                    "sectionFields": fields
                }]}
            }
        }]}}
    }))
    .unwrap();
    let input = write_raw(&bytes);
    let base = (bytes.len() as u64) * 4 + 4096;
    let generated_section_prefix_bytes = (section_name.len() as u64 + 3) * 64;

    let insufficient = InputLimits {
        max_projected_output_bytes: base + generated_section_prefix_bytes - 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(input.path(), insufficient),
        Err(AppError::InputTooLarge)
    ));

    let exact = InputLimits {
        max_projected_output_bytes: base + generated_section_prefix_bytes,
        ..InputLimits::default()
    };
    assert!(load_export(input.path(), exact).is_ok());
}

#[test]
fn enforces_identifier_byte_limits() {
    let vault_bytes = format!(
        r#"{{"version":"1","vaults":{{"{}":{{"items":[]}}}}}}"#,
        "v".repeat(InputLimits::default().max_vault_id_bytes + 1)
    );
    let vault_id = write_raw(vault_bytes.as_bytes());
    assert!(matches!(
        load_export(vault_id.path(), InputLimits::default()),
        Err(AppError::InputTooLarge)
    ));

    let item = |item_id: &str, share_id: &str, item_uuid: &str| {
        serde_json::to_vec(&serde_json::json!({
            "version": "1",
            "vaults": {"v": {"items": [{
                "itemId": item_id,
                "shareId": share_id,
                "state": 1,
                "data": {
                    "metadata": {"itemUuid": item_uuid},
                    "type": "note",
                    "content": {}
                }
            }]}}
        }))
        .unwrap()
    };

    let item_id_value = "i".repeat(InputLimits::default().max_item_id_bytes + 1);
    let item_id = write_raw(&item(&item_id_value, "", ""));
    assert!(matches!(
        load_export(item_id.path(), InputLimits::default()),
        Err(AppError::InputTooLarge)
    ));

    let share_id_value = "s".repeat(InputLimits::default().max_share_id_bytes + 1);
    let share_id = write_raw(&item("i", &share_id_value, ""));
    assert!(matches!(
        load_export(share_id.path(), InputLimits::default()),
        Err(AppError::InputTooLarge)
    ));

    let item_uuid_value = "u".repeat(InputLimits::default().max_item_uuid_bytes + 1);
    let item_uuid = write_raw(&item("i", "", &item_uuid_value));
    assert!(matches!(
        load_export(item_uuid.path(), InputLimits::default()),
        Err(AppError::InputTooLarge)
    ));
}

#[test]
fn preflights_configured_nested_aggregate_for_unknown_item_content() {
    let bytes = br#"{"version":"1","vaults":{"v":{"items":[{"itemId":"i","state":1,"data":{"type":"futureType","content":{"future":[0,1]}}}]}}}"#;
    let input = write_raw(bytes);
    let insufficient = InputLimits {
        max_nested_elements: 1,
        ..InputLimits::default()
    };
    assert!(matches!(
        load_export(input.path(), insufficient),
        Err(AppError::InputTooLarge)
    ));

    let exact = InputLimits {
        max_nested_elements: 2,
        ..InputLimits::default()
    };
    assert!(load_export(input.path(), exact).is_ok());
}

#[test]
fn rejects_unmodeled_passkey_arrays_in_future_item_types() {
    let input = write_raw(
        br#"{"version":"1","vaults":{"v":{"items":[{"itemId":"i","state":1,"data":{"type":"futureType","content":{"passkeys":[{"content":"synthetic"}]}}}]}}}"#,
    );

    assert!(matches!(
        load_export(input.path(), InputLimits::default()),
        Err(AppError::InvalidExport)
    ));
}

#[cfg(unix)]
#[test]
fn rejects_symlink_and_nonregular_input_endpoints() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.json");
    let link = directory.path().join("link.json");
    fs::write(&target, MINIMAL).unwrap();
    symlink(&target, &link).unwrap();
    assert!(matches!(
        load_export(&link, InputLimits::default()),
        Err(AppError::UnsupportedInput)
    ));

    assert!(matches!(
        load_export(directory.path(), InputLimits::default()),
        Err(AppError::UnsupportedInput)
    ));
}

fn assert_unsafe_archive_with_limits(path: &Path, limits: InputLimits) {
    assert!(matches!(
        load_export(path, limits),
        Err(AppError::UnsafeArchive)
    ));
}
