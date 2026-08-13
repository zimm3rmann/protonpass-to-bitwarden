use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use protonpass_to_bitwarden::bitwarden_export::{BitwardenItem, ConversionResult};
use protonpass_to_bitwarden::convert_export;
use protonpass_to_bitwarden::proton_export::{
    AllowedAndroidApp, AndroidSpecific, AutofillUrl, CreditCardContent, CustomContent,
    EmptyContent, IdentityContent, LoginContent, PlatformSpecific, ProtonExport, ProtonExtraField,
    ProtonExtraFieldData, ProtonItem, ProtonItemData, ProtonItemKind, ProtonMetadata,
    ProtonSection, ProtonVault, SshKeyContent, WifiContent,
};
use protonpass_to_bitwarden::proton_passkey::{ProtonPasskeyCreationData, ProtonPasskeyInput};
use protonpass_to_bitwarden::report::{EntityKind, OutcomeCode, ReasonCode};
use serde::Serialize;

const CREATED: i64 = 1_700_000_000;
const MODIFIED: i64 = 1_700_000_001;
const SSH_PRIVATE_KEY: &str = concat!(
    "-----BEGIN OPENSSH PRI",
    "VATE KEY-----\n",
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n",
    "QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n",
    "XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n",
    "AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n",
    "ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==\n",
    "-----END OPENSSH PRI",
    "VATE KEY-----"
);
const SSH_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com";
const SSH_FINGERPRINT: &str = "SHA256:UCUiLr7Pjs9wFFJMDByLgc3NrtdU344OgUM45wZPcIQ";
const ENCRYPTED_SSH_PRIVATE_KEY: &str = concat!(
    "-----BEGIN OPENSSH PRI",
    "VATE KEY-----\n",
    "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDjNCaEMn\n",
    "B07EZG4Q43IiK/AAAABAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIF0RJIBhPFKfVDgz\n",
    "165sOYs9BsMfEaUxJD0dtFLJSnNgAAAAsFc4Zfp3ePdnnVChKvzVouEojackglL1nKsu2y\n",
    "W7nMCODlbM5cyovazssoO9XMtBD8rXMMTMCqe5VUW4Qnt6NBGEeZ6j6an5B1s4RDx3hTHL\n",
    "b9YV5oYcwOEqoQkls3bhEFxaw33U1xqtDdUmlNqMCO/PRlOOnYjLySZyiyVMUbVovf6Wzm\n",
    "x9HTB6cytwCQevCiLpYIxs98oWKp6u76yOFVNiCLcZ3yAYakbOJnLKrg5B\n",
    "-----END OPENSSH PRI",
    "VATE KEY-----"
);
const ENCRYPTED_SSH_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF0RJIBhPFKfVDgz165sOYs9BsMfEaUxJD0dtFLJSnNg synthetic-encrypted@example.test";
const ENCRYPTED_SSH_CANONICAL_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF0RJIBhPFKfVDgz165sOYs9BsMfEaUxJD0dtFLJSnNg";
const ENCRYPTED_SSH_FINGERPRINT: &str = "SHA256:YivArJMB9rIJVQzK4ciCQb9JhvKEJgPU+Q1rhoBnY0w";
const RSA_SSH_PRIVATE_KEY: &str = concat!(
    "-----BEGIN OPENSSH PRI",
    "VATE KEY-----\n",
    r#"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAyc3o6Vwf51V6B3Y05kpIQu+4FZGbvYKlfVru/sjwR88Sh8mbIa5m
9y5FTylXWHk+9tHrILrHQlVdD70ZuiqN42nlq8BxWsgzN0a2OzqSVyFQKXr9hJJIujmSjQ
QRPo+ArEYzJyFYJgJmfCWPo8QrtUfCel7EEVzeSZ0JZ8M1XJpumX6OWJux2fsQ2iTKmImz
WRaervHFkKzBl4Kw6olEJ/Q1Avt73vMY5zVNehcZvuBBKTlojQ4+Awr5KP43Szsm5DxgSz
QqpuEAv8hSeiFCehXIDhG4fm1seL1jvT5KcZi6W3rtr47P35HoF2GxLQjXgnSaC1tDMHjw
yhAOjwVRzQAAA9ABwEDeAcBA3gAAAAdzc2gtcnNhAAABAQDJzejpXB/nVXoHdjTmSkhC77
gVkZu9gqV9Wu7+yPBHzxKHyZshrmb3LkVPKVdYeT720esgusdCVV0PvRm6Ko3jaeWrwHFa
yDM3RrY7OpJXIVApev2Ekki6OZKNBBE+j4CsRjMnIVgmAmZ8JY+jxCu1R8J6XsQRXN5JnQ
lnwzVcmm6Zfo5Ym7HZ+xDaJMqYibNZFp6u8cWQrMGXgrDqiUQn9DUC+3ve8xjnNU16Fxm+
4EEpOWiNDj4DCvko/jdLOybkPGBLNCqm4QC/yFJ6IUJ6FcgOEbh+bWx4vWO9PkpxmLpbeu
2vjs/fkegXYbEtCNeCdJoLW0MwePDKEA6PBVHNAAAAAwEAAQAAAQAoii5vbrvT/6ZfiF4R
IzwIAlszLgig1fWDzLg1Q82NR2p8D8KTzhLONiPjRrVOxzCgacQ3033C9B4ZUs4vyWuuky
/5xFOhPpWXVaO3G0mZqk4NvzDdqHtmubkYjggezro1IXcWNcsc+5918h+8cOSs6qkFZzMx
H7xiAmOIzjzSiLI2md1eEe7zkPs3LqeFOYJdtlaHafbAzdYaS2w55Mseu9vALSarFINkQc
NxaZ8C14mVzyc6k5Kd31sHsTls9JZ+7jvwz7wVbUmBZpp4cZOlO2i0SrnO1E/9MdlgYCLp
FONaAwTpHc+z5L/EmpKsF+Us4ot8AP2YdZjGlzGuVe7xAAAAgHmlbQ9ogM+b/fQHDz/lKQ
0mMOjMqUmKv5YhVTaPm80Wy0HCQ5Ol7wPDXy8Unz25TZbI+NABgyvvOk9YySXSyErqEDtb
ER520UxT21gSUzAHk1+HdhgvofpEyGBMXk2UDqRqPvtlWLhnQ3KvAoMC5If9cXdz84fXBJ
yhzQAbmw6ZAAAAgQDoL9kkw/Scko8nfneeH95OIdprtryeIrgywtIqQ2PwoVTprRmuNLU5
zDh0yE8BCjNHJz0RSvOG5Fpu67Xhm6LZQTsmxwN4DoiflcJ2aEORe7Aii3+8xIefr4MRNv
XSszb9hjOILeKfRMsGynZBwh+m9SOLPmYqxI4LU8qH0qyKaQAAAIEA3oBbKcifZur2hxw7
EWMdSpJ3S/h64TMVpR8nHAV7T4yDsVeOY2yPMyPy3g7LXV2ty3DG/lA8Hh6uMGdWLVWkqU
8HMlwcdSp8Hs4k71Qza+3+jTg5fP5tqf1QUp4N1hNg9g0gcz3azW6tVhQu1cqCfyRtZDD7
U1SW/1HkGk+od8UAAAAac3ludGhldGljLXJzYUBleGFtcGxlLnRlc3QB
"#,
    "-----END OPENSSH PRI",
    "VATE KEY-----"
);
const RSA_SSH_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJzejpXB/nVXoHdjTmSkhC77gVkZu9gqV9Wu7+yPBHzxKHyZshrmb3LkVPKVdYeT720esgusdCVV0PvRm6Ko3jaeWrwHFayDM3RrY7OpJXIVApev2Ekki6OZKNBBE+j4CsRjMnIVgmAmZ8JY+jxCu1R8J6XsQRXN5JnQlnwzVcmm6Zfo5Ym7HZ+xDaJMqYibNZFp6u8cWQrMGXgrDqiUQn9DUC+3ve8xjnNU16Fxm+4EEpOWiNDj4DCvko/jdLOybkPGBLNCqm4QC/yFJ6IUJ6FcgOEbh+bWx4vWO9PkpxmLpbeu2vjs/fkegXYbEtCNeCdJoLW0MwePDKEA6PBVHN synthetic-rsa@example.test";
const RSA_SSH_FINGERPRINT: &str = "SHA256:qrQx6EOAT6mMRdv6zy2oX3EI9v9CY2FYMRdOoW23dV8";

fn item(kind: ProtonItemKind, name: &str) -> ProtonItem {
    ProtonItem {
        item_id: format!("item-{name}"),
        share_id: "synthetic-vault".into(),
        data: ProtonItemData {
            metadata: ProtonMetadata {
                name: name.into(),
                note: String::new(),
                item_uuid: format!("uuid-{name}"),
            },
            extra_fields: Vec::new(),
            platform_specific: None,
            kind,
        },
        state: 1,
        alias_email: None,
        content_format_version: 6,
        create_time: CREATED,
        modify_time: MODIFIED,
        pinned: false,
        files: Vec::new(),
    }
}

fn export(items: Vec<ProtonItem>) -> ProtonExport {
    ProtonExport {
        version: "synthetic-1".into(),
        user_id: None,
        encrypted: Some(false),
        vaults: BTreeMap::from([(
            "vault-id".into(),
            ProtonVault {
                name: "/Parent\\Child".into(),
                description: String::new(),
                items,
            },
        )]),
    }
}

fn field(name: &str, field_type: &str, content: &str) -> ProtonExtraField {
    ProtonExtraField {
        field_name: name.into(),
        field_type: field_type.into(),
        data: ProtonExtraFieldData {
            content: content.into(),
            ..ProtonExtraFieldData::default()
        },
    }
}

fn find_item<'a>(result: &'a ConversionResult, name: &str) -> &'a BitwardenItem {
    result
        .export
        .items
        .iter()
        .find(|item| item.name == name)
        .unwrap_or_else(|| panic!("missing synthetic item {name}"))
}

#[test]
fn converts_every_supported_item_type() {
    let mut login = item(
        ProtonItemKind::Login(LoginContent {
            item_email: "fallback@example.test".into(),
            password: "synthetic-login-password".into(),
            urls: vec!["example.test/login".into()],
            totp_uri: "otpauth://totp/synthetic".into(),
            ..LoginContent::default()
        }),
        "Login",
    );
    login.pinned = true;
    login.data.metadata.note = "synthetic login note".into();
    login.data.extra_fields = vec![field("Hidden", "hidden", "hidden-value")];

    let mut note = item(ProtonItemKind::Note(EmptyContent {}), "Note");
    note.data.metadata.note = "synthetic note body".into();
    note.data.extra_fields = vec![field("Text", "text", "text-value")];

    let mut alias = item(ProtonItemKind::Alias(EmptyContent {}), "Alias");
    alias.alias_email = Some("alias@example.test".into());

    let card = item(
        ProtonItemKind::CreditCard(CreditCardContent {
            cardholder_name: "Synthetic Holder".into(),
            card_type: 0,
            number: "4111111111111111".into(),
            verification_number: "123".into(),
            expiration_date: "2030-04".into(),
            pin: "9876".into(),
        }),
        "Card",
    );

    let identity = item(
        ProtonItemKind::Identity(Box::new(IdentityContent {
            full_name: "First Middle Last".into(),
            email: "identity@example.test".into(),
            phone_number: "+1-555-0100".into(),
            gender: "Synthetic".into(),
            organization: "Example Org".into(),
            street_address: "1 Test Way".into(),
            floor: "Floor 2".into(),
            county: "Test County".into(),
            city: "Example City".into(),
            state_or_province: "EX".into(),
            zip_or_postal_code: "00000".into(),
            country_or_region: "US".into(),
            company: "Example Company".into(),
            extra_personal_details: vec![field("Identity Hidden", "hidden", "identity-value")],
            extra_sections: vec![ProtonSection {
                section_name: "Identity Section".into(),
                section_fields: vec![field("Reference", "text", "identity-reference")],
            }],
            ..IdentityContent::default()
        })),
        "Identity",
    );

    let ssh = item(
        ProtonItemKind::SshKey(SshKeyContent {
            private_key: SSH_PRIVATE_KEY.into(),
            public_key: SSH_PUBLIC_KEY.into(),
            fingerprint: String::new(),
            sections: vec![ProtonSection {
                section_name: "SSH".into(),
                section_fields: vec![field("Host", "text", "host.example.test")],
            }],
        }),
        "SSH",
    );

    let wifi = item(
        ProtonItemKind::Wifi(WifiContent {
            ssid: "Synthetic Network".into(),
            password: "synthetic-wifi-password".into(),
            security: 3,
            sections: vec![ProtonSection {
                section_name: "Network Details".into(),
                section_fields: vec![field("Channel", "text", "44")],
            }],
        }),
        "WiFi",
    );

    let custom = item(
        ProtonItemKind::Custom(CustomContent {
            sections: vec![ProtonSection {
                section_name: "Custom".into(),
                section_fields: vec![field("Account", "text", "123456")],
            }],
        }),
        "Custom",
    );

    let result = convert_export(
        &export(vec![login, note, alias, card, identity, ssh, wifi, custom]),
        true,
    );

    assert!(!result.export.encrypted);
    assert_eq!(result.export.items.len(), 8);
    assert_eq!(
        result
            .export
            .folders
            .iter()
            .map(|folder| folder.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Parent", "Parent/Child"]
    );
    let child_folder = result
        .export
        .folders
        .iter()
        .find(|folder| folder.name == "Parent/Child")
        .expect("child folder should exist");
    assert!(
        result
            .export
            .items
            .iter()
            .all(|item| item.folder_id.as_deref() == Some(child_folder.id.as_str()))
    );

    let login = find_item(&result, "Login");
    assert_eq!(login.item_type, 1);
    assert!(login.favorite);
    assert_eq!(login.reprompt, 0);
    assert!(login.creation_date.is_some());
    assert!(login.revision_date.is_some());
    let login_data = login.login.as_ref().expect("login data should exist");
    assert_eq!(
        login_data.username.as_deref(),
        Some("fallback@example.test")
    );
    assert_eq!(
        login_data.password.as_deref(),
        Some("synthetic-login-password")
    );
    assert_eq!(login_data.totp.as_deref(), Some("otpauth://totp/synthetic"));
    assert_eq!(login_data.uris[0].uri, "http://example.test/login");
    assert!(
        login
            .fields
            .iter()
            .any(|value| value.name == "Hidden" && value.field_type == 1)
    );

    let note = find_item(&result, "Note");
    assert_eq!(note.item_type, 2);
    assert_eq!(
        note.secure_note
            .as_ref()
            .expect("secure note data should exist")
            .note_type,
        0
    );
    assert_eq!(note.notes.as_deref(), Some("synthetic note body"));
    assert!(note.fields.iter().any(|value| value.name == "Text"));

    let alias = find_item(&result, "Alias");
    assert_eq!(alias.item_type, 1);
    assert_eq!(
        alias
            .login
            .as_ref()
            .expect("alias login data should exist")
            .username
            .as_deref(),
        Some("alias@example.test")
    );

    let card = find_item(&result, "Card");
    assert_eq!(card.item_type, 3);
    let card_data = card.card.as_ref().expect("card data should exist");
    assert_eq!(
        card_data.cardholder_name.as_deref(),
        Some("Synthetic Holder")
    );
    assert_eq!(card_data.brand.as_deref(), Some("Visa"));
    assert_eq!(card_data.number.as_deref(), Some("4111111111111111"));
    assert_eq!(card_data.exp_month.as_deref(), Some("4"));
    assert_eq!(card_data.exp_year.as_deref(), Some("2030"));
    assert_eq!(card_data.code.as_deref(), Some("123"));
    assert!(
        card.fields
            .iter()
            .any(|value| { value.name == "PIN" && value.value == "9876" && value.field_type == 1 })
    );

    let identity = find_item(&result, "Identity");
    assert_eq!(identity.item_type, 4);
    let identity_data = identity
        .identity
        .as_ref()
        .expect("identity data should exist");
    assert_eq!(identity_data.first_name.as_deref(), Some("First"));
    assert_eq!(identity_data.middle_name.as_deref(), Some("Middle"));
    assert_eq!(identity_data.last_name.as_deref(), Some("Last"));
    assert_eq!(identity_data.address1.as_deref(), Some("Example Org"));
    assert_eq!(identity_data.address2.as_deref(), Some("1 Test Way"));
    assert_eq!(
        identity_data.address3.as_deref(),
        Some("Floor 2 Test County")
    );
    assert!(identity.fields.iter().any(|value| value.name == "gender"));
    assert!(
        identity
            .fields
            .iter()
            .any(|value| value.name == "Identity Hidden" && value.field_type == 1)
    );
    assert!(identity.fields.iter().any(|value| {
        value.name == "Identity Section / Reference" && value.value == "identity-reference"
    }));

    let ssh = find_item(&result, "SSH");
    assert_eq!(ssh.item_type, 5);
    let ssh_data = ssh.ssh_key.as_ref().expect("SSH data should exist");
    assert_eq!(ssh_data.private_key.trim_end(), SSH_PRIVATE_KEY);
    assert_eq!(ssh_data.public_key, SSH_PUBLIC_KEY);
    assert_eq!(ssh_data.key_fingerprint, SSH_FINGERPRINT);
    assert!(ssh.fields.iter().any(|value| value.name == "SSH / Host"));

    let wifi = find_item(&result, "WiFi");
    assert_eq!(wifi.item_type, 2);
    assert!(wifi.fields.iter().any(|value| {
        value.name == "Password"
            && value.value == "synthetic-wifi-password"
            && value.field_type == 1
    }));
    assert!(
        wifi.fields
            .iter()
            .any(|value| value.name == "Security" && value.value == "WPA3")
    );
    assert!(
        wifi.fields
            .iter()
            .any(|value| { value.name == "Network Details / Channel" && value.value == "44" })
    );

    let custom = find_item(&result, "Custom");
    assert_eq!(custom.item_type, 2);
    assert!(
        custom
            .fields
            .iter()
            .any(|value| value.name == "Custom / Account" && value.value == "123456")
    );

    assert_eq!(result.report.summary.items_total, 8);
    assert_eq!(result.report.summary.items_converted, 8);
    assert_eq!(result.report.summary.items_skipped, 0);
    assert_eq!(result.report.summary.folders_created, 2);
    assert_eq!(result.report.summary.output_items_created, 8);
    assert_eq!(result.report.summary.strict_failures, 1);
    assert!(
        result
            .report
            .outcomes
            .iter()
            .all(|entry| entry.name.is_none())
    );
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.item_type == "wifi"
            && entry.outcome == OutcomeCode::ConvertedWithFallback
            && entry.reason == ReasonCode::WifiMappedToSecureNote
    }));
}

#[test]
fn preserves_section_context_without_creating_a_strict_failure() {
    let custom = item(
        ProtonItemKind::Custom(CustomContent {
            sections: vec![
                ProtonSection {
                    section_name: "Primary".into(),
                    section_fields: vec![field("Account", "text", "primary-account")],
                },
                ProtonSection {
                    section_name: "Backup".into(),
                    section_fields: vec![field("Account", "text", "backup-account")],
                },
                ProtonSection {
                    section_name: "Primary".into(),
                    section_fields: vec![field("Account", "text", "second-primary-account")],
                },
                ProtonSection {
                    section_name: "   ".into(),
                    section_fields: vec![field("Unscoped", "text", "unscoped-value")],
                },
                ProtonSection {
                    section_name: "Long".into(),
                    section_fields: vec![field("Blob", "text", &"a".repeat(201))],
                },
                ProtonSection {
                    section_name: "Long".into(),
                    section_fields: vec![field("Blob", "text", &"b".repeat(201))],
                },
            ],
        }),
        "Sectioned custom item",
    );

    let result = convert_export(&export(vec![custom]), true);
    let converted = find_item(&result, "Sectioned custom item");
    let fields = converted
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field.value.as_str()))
        .collect::<BTreeSet<_>>();

    assert!(fields.contains(&("Primary / Account", "primary-account")));
    assert!(fields.contains(&("Backup / Account", "backup-account")));
    assert!(fields.contains(&("Primary / Account [2]", "second-primary-account")));
    assert!(fields.contains(&("Unscoped", "unscoped-value")));
    let notes = converted.notes.as_deref().expect("long field notes");
    assert!(notes.contains("Long / Blob: "));
    assert!(notes.contains("Long / Blob [2]: "));
    assert_eq!(result.report.summary.strict_failures, 0);
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Item
            && entry.outcome == OutcomeCode::Converted
            && entry.reason == ReasonCode::None
    }));
}

#[test]
fn preserves_long_ascii_and_multibyte_urls_exactly() {
    let ascii_source = format!("example.test/{}", "a".repeat(1_100));
    let ascii_expected = format!("http://{ascii_source}");
    let multibyte_expected = format!("https://example.test/{}", "界".repeat(400));
    let login = item(
        ProtonItemKind::Login(LoginContent {
            urls: vec![
                format!("  {ascii_source}\n"),
                format!("\t{multibyte_expected}  "),
            ],
            ..LoginContent::default()
        }),
        "Long URLs",
    );

    let result = convert_export(&export(vec![login]), true);
    let login = find_item(&result, "Long URLs")
        .login
        .as_ref()
        .expect("login data should exist");

    assert!(ascii_expected.len() > 1_000);
    assert!(multibyte_expected.len() > 1_000);
    assert_eq!(login.uris[0].uri, ascii_expected);
    assert_eq!(login.uris[1].uri, multibyte_expected);
}

#[test]
fn reports_every_simultaneous_loss_reason_on_one_item() {
    let mut invalid_passkey = valid_passkey(
        1,
        &[1, 2, 3],
        b"multi-loss-handle",
        "multi-loss@example.test",
    );
    invalid_passkey.content = "invalid".into();
    let mut login = item(
        ProtonItemKind::Login(LoginContent {
            autofill_urls: vec![AutofillUrl {
                url: "https://example.test/pattern".into(),
                mode: 4,
            }],
            passkeys: vec![invalid_passkey],
            ..LoginContent::default()
        }),
        "Multiple losses",
    );
    login.data.extra_fields = vec![field("future", "future", "synthetic")];
    login.data.platform_specific = Some(PlatformSpecific {
        android: Some(AndroidSpecific {
            allowed_apps: vec![AllowedAndroidApp {
                package_name: "example.synthetic".into(),
                hashes: Vec::new(),
                app_name: "Synthetic".into(),
            }],
        }),
    });

    let result = convert_export(&export(vec![login]), true);
    let entry = result
        .report
        .outcomes
        .iter()
        .find(|entry| entry.entity == EntityKind::Item)
        .expect("item outcome");

    assert_eq!(entry.outcome, OutcomeCode::ConvertedWithFallback);
    assert_eq!(entry.reason, ReasonCode::UnsupportedAutofillMode);
    assert_eq!(
        entry.additional_reasons,
        vec![
            ReasonCode::UnsupportedPlatformMetadata,
            ReasonCode::OneOrMorePasskeysNotMigrated,
            ReasonCode::UnsupportedExtraField,
        ]
    );
    assert_eq!(result.report.summary.strict_failures, 2);
}

#[test]
fn reports_trashed_unknown_and_attachment_records() {
    let mut attachment = item(ProtonItemKind::Note(EmptyContent {}), "Attachment");
    attachment.files = vec!["SYNTHETIC_ATTACHMENT_PATH_SENTINEL".into()];
    let mut trashed = item(ProtonItemKind::Note(EmptyContent {}), "Trashed");
    trashed.state = 2;
    let unknown = item(ProtonItemKind::Unknown, "Unknown");

    let result = convert_export(&export(vec![attachment, trashed, unknown]), true);

    assert_eq!(result.export.items.len(), 1);
    assert_eq!(result.report.summary.items_total, 3);
    assert_eq!(result.report.summary.items_converted, 1);
    assert_eq!(result.report.summary.items_skipped, 2);
    assert_eq!(result.report.summary.attachment_sets_skipped, 1);
    assert_eq!(result.report.summary.strict_failures, 2);
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Item && entry.outcome == OutcomeCode::SkippedTrashed
    }));
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Item
            && entry.outcome == OutcomeCode::UnsupportedItemType
            && entry.reason == ReasonCode::UnsupportedType
    }));
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Attachment
            && entry.outcome == OutcomeCode::SkippedAttachment
            && entry.reason == ReasonCode::AttachmentsRequireManualMigration
    }));
    assert!(
        !serde_json::to_string(&result.report)
            .expect("report should serialize")
            .contains("SYNTHETIC_ATTACHMENT_PATH_SENTINEL")
    );
}

#[test]
fn report_is_deterministic_when_item_input_order_changes() {
    let first = item(ProtonItemKind::Note(EmptyContent {}), "First");
    let second = item(
        ProtonItemKind::CreditCard(CreditCardContent {
            cardholder_name: "Synthetic Holder".into(),
            card_type: 0,
            number: "4111111111111111".into(),
            verification_number: "123".into(),
            expiration_date: "2030-04".into(),
            pin: "9876".into(),
        }),
        "Second",
    );
    let forward = convert_export(&export(vec![first, second]), true);

    let first = item(ProtonItemKind::Note(EmptyContent {}), "First");
    let second = item(
        ProtonItemKind::CreditCard(CreditCardContent {
            cardholder_name: "Synthetic Holder".into(),
            card_type: 0,
            number: "4111111111111111".into(),
            verification_number: "123".into(),
            expiration_date: "2030-04".into(),
            pin: "9876".into(),
        }),
        "Second",
    );
    let reversed = convert_export(&export(vec![second, first]), true);

    assert_eq!(
        serde_json::to_string(&forward.report).expect("forward report should serialize"),
        serde_json::to_string(&reversed.report).expect("reversed report should serialize")
    );
}

#[test]
fn redacted_report_does_not_leak_unsupported_passkey_card_or_note_sentinels() {
    let mut login_content = LoginContent {
        item_username: "SYNTHETIC_USERNAME_SENTINEL".into(),
        password: "SYNTHETIC_PASSWORD_SENTINEL".into(),
        totp_uri: "SYNTHETIC_TOTP_SENTINEL".into(),
        ..LoginContent::default()
    };
    login_content.passkeys.push(ProtonPasskeyInput {
        key_id: "SYNTHETIC_PASSKEY_KEY_ID_SENTINEL".into(),
        content: "SYNTHETIC_INVALID_PASSKEY_CONTENT_SENTINEL".into(),
        domain: "SYNTHETIC_PASSKEY_DOMAIN_SENTINEL".into(),
        rp_id: "SYNTHETIC_PASSKEY_RP_SENTINEL".into(),
        rp_name: "SYNTHETIC_PASSKEY_RP_NAME_SENTINEL".into(),
        user_name: "SYNTHETIC_PASSKEY_USER_SENTINEL".into(),
        user_display_name: "SYNTHETIC_PASSKEY_DISPLAY_SENTINEL".into(),
        user_id: "SYNTHETIC_PASSKEY_USER_ID_SENTINEL".into(),
        create_time: Some(CREATED),
        note: "SYNTHETIC_PASSKEY_NOTE_SENTINEL".into(),
        credential_id: "SYNTHETIC_PASSKEY_CREDENTIAL_SENTINEL".into(),
        user_handle: "SYNTHETIC_PASSKEY_HANDLE_SENTINEL".into(),
        creation_data: None,
    });
    let mut login = item(
        ProtonItemKind::Login(login_content),
        "SYNTHETIC_LOGIN_NAME_SENTINEL",
    );
    login.data.metadata.note = "SYNTHETIC_LOGIN_NOTE_SENTINEL".into();
    login.data.extra_fields = vec![field(
        "SYNTHETIC_FIELD_NAME_SENTINEL",
        "hidden",
        "SYNTHETIC_FIELD_VALUE_SENTINEL",
    )];

    let card = item(
        ProtonItemKind::CreditCard(CreditCardContent {
            cardholder_name: "SYNTHETIC_CARD_HOLDER_SENTINEL".into(),
            card_type: 0,
            number: "SYNTHETIC_CARD_NUMBER_SENTINEL".into(),
            verification_number: "SYNTHETIC_CARD_CODE_SENTINEL".into(),
            expiration_date: "2030-01".into(),
            pin: "SYNTHETIC_CARD_PIN_SENTINEL".into(),
        }),
        "SYNTHETIC_CARD_NAME_SENTINEL",
    );

    let mut note = item(
        ProtonItemKind::Note(EmptyContent {}),
        "SYNTHETIC_NOTE_NAME_SENTINEL",
    );
    note.data.metadata.note = "SYNTHETIC_NOTE_BODY_SENTINEL".into();
    note.files = vec!["SYNTHETIC_ATTACHMENT_SENTINEL".into()];

    let result = convert_export(&export(vec![login, card, note]), true);
    let report = serde_json::to_string(&result.report).expect("report should serialize");
    let output = serde_json::to_string(&result.export).expect("vault should serialize");

    for sentinel in [
        "SYNTHETIC_USERNAME_SENTINEL",
        "SYNTHETIC_PASSWORD_SENTINEL",
        "SYNTHETIC_TOTP_SENTINEL",
        "SYNTHETIC_INVALID_PASSKEY_CONTENT_SENTINEL",
        "SYNTHETIC_PASSKEY_DOMAIN_SENTINEL",
        "SYNTHETIC_PASSKEY_RP_SENTINEL",
        "SYNTHETIC_PASSKEY_USER_SENTINEL",
        "SYNTHETIC_PASSKEY_NOTE_SENTINEL",
        "SYNTHETIC_PASSKEY_CREDENTIAL_SENTINEL",
        "SYNTHETIC_PASSKEY_HANDLE_SENTINEL",
        "SYNTHETIC_LOGIN_NAME_SENTINEL",
        "SYNTHETIC_LOGIN_NOTE_SENTINEL",
        "SYNTHETIC_FIELD_NAME_SENTINEL",
        "SYNTHETIC_FIELD_VALUE_SENTINEL",
        "SYNTHETIC_CARD_HOLDER_SENTINEL",
        "SYNTHETIC_CARD_NUMBER_SENTINEL",
        "SYNTHETIC_CARD_CODE_SENTINEL",
        "SYNTHETIC_CARD_PIN_SENTINEL",
        "SYNTHETIC_CARD_NAME_SENTINEL",
        "SYNTHETIC_NOTE_NAME_SENTINEL",
        "SYNTHETIC_NOTE_BODY_SENTINEL",
        "SYNTHETIC_ATTACHMENT_SENTINEL",
    ] {
        assert!(!report.contains(sentinel), "report leaked {sentinel}");
    }
    assert!(output.contains("SYNTHETIC_PASSWORD_SENTINEL"));
    assert!(output.contains("SYNTHETIC_CARD_NUMBER_SENTINEL"));
    assert!(output.contains("SYNTHETIC_NOTE_BODY_SENTINEL"));
    assert_eq!(result.report.summary.passkeys_total, 1);
    assert_eq!(result.report.summary.passkeys_unsupported, 1);
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Passkey
            && entry.outcome == OutcomeCode::InvalidKeyMaterial
            && entry.reason == ReasonCode::MalformedPasskeyEncoding
    }));

    let visible = convert_export(
        &export(vec![item(
            ProtonItemKind::Note(EmptyContent {}),
            "VISIBLE_SYNTHETIC_NAME",
        )]),
        false,
    );
    let visible_report =
        serde_json::to_string(&visible.report).expect("visible report should serialize");
    assert!(visible_report.contains("VISIBLE_SYNTHETIC_NAME"));
}

#[test]
fn splits_multiple_compatible_passkeys_and_preserves_login_context() {
    let first = valid_passkey(
        1,
        &[1, 2, 3, 4, 5],
        b"first-user-handle",
        "first@example.test",
    );
    let second = valid_passkey(
        2,
        &[6, 7, 8, 9, 10, 11],
        b"second-user-handle",
        "second@example.test",
    );
    let login = item(
        ProtonItemKind::Login(LoginContent {
            item_username: "shared-login@example.test".into(),
            password: "shared-synthetic-password".into(),
            urls: vec!["https://example.test/login".into()],
            totp_uri: "otpauth://totp/shared-synthetic".into(),
            passkeys: vec![first, second],
            ..LoginContent::default()
        }),
        "Passkey Login",
    );

    let source = export(vec![login]);
    let result = convert_export(&source, true);

    assert_eq!(result.export.items.len(), 2);
    let main = &result.export.items[0];
    let split = &result.export.items[1];
    assert_eq!(main.name, "Passkey Login");
    assert_eq!(split.name, "Passkey Login — Passkey 2");
    assert_ne!(main.id, split.id);
    assert_eq!(main.folder_id, split.folder_id);
    let main_login = main.login.as_ref().expect("main login should exist");
    let split_login = split.login.as_ref().expect("split login should exist");
    assert_eq!(main_login.username, split_login.username);
    assert_eq!(main_login.password, split_login.password);
    assert_eq!(main_login.totp, split_login.totp);
    assert_eq!(main_login.uris[0].uri, split_login.uris[0].uri);
    assert_eq!(main_login.fido2_credentials.len(), 1);
    assert_eq!(split_login.fido2_credentials.len(), 1);
    assert_eq!(main_login.fido2_credentials[0].credential_id, "b64.AQIDBAU");
    assert_eq!(
        split_login.fido2_credentials[0].credential_id,
        "b64.BgcICQoL"
    );
    assert_eq!(main_login.fido2_credentials[0].counter, "7");
    assert_eq!(split_login.fido2_credentials[0].counter, "7");
    assert_eq!(main_login.fido2_credentials[0].discoverable, "true");
    assert_eq!(split_login.fido2_credentials[0].discoverable, "true");

    let fido_json =
        serde_json::to_value(&main_login.fido2_credentials[0]).expect("passkey should serialize");
    assert!(fido_json["counter"].is_string());
    assert!(fido_json["discoverable"].is_string());
    assert!(fido_json["creationDate"].is_string());
    assert_eq!(fido_json["keyType"], "public-key");
    assert_eq!(fido_json["keyAlgorithm"], "ECDSA");
    assert_eq!(fido_json["keyCurve"], "P-256");

    assert_eq!(result.report.summary.items_total, 1);
    assert_eq!(result.report.summary.items_converted, 1);
    assert_eq!(result.report.summary.passkeys_total, 2);
    assert_eq!(result.report.summary.passkeys_converted, 2);
    assert_eq!(result.report.summary.passkeys_unsupported, 0);
    assert_eq!(result.report.summary.additional_logins_created, 1);
    assert_eq!(result.report.summary.strict_failures, 0);
    assert_eq!(
        result
            .report
            .outcomes
            .iter()
            .filter(|entry| entry.outcome == OutcomeCode::SplitAdditionalPasskey)
            .count(),
        1
    );

    let again = convert_export(&source, true);
    assert_eq!(
        serde_json::to_string(&result.export).expect("first vault should serialize"),
        serde_json::to_string(&again.export).expect("second vault should serialize")
    );
    assert_eq!(
        serde_json::to_string(&result.report).expect("first report should serialize"),
        serde_json::to_string(&again.report).expect("second report should serialize")
    );
    let outcome_ids: BTreeSet<_> = result
        .report
        .outcomes
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    assert_eq!(outcome_ids.len(), result.report.outcomes.len());
}

#[test]
fn preserves_each_passkey_note_without_cross_contaminating_split_items_or_reports() {
    let mut first = valid_passkey(1, &[1, 2, 3], b"first-handle", "first@example.test");
    first.note = "FIRST_PASSKEY_NOTE_SENTINEL".into();
    let mut second = valid_passkey(2, &[4, 5, 6], b"second-handle", "second@example.test");
    second.note = "SECOND_PASSKEY_NOTE_SENTINEL".into();
    let mut invalid = valid_passkey(3, &[7, 8, 9], b"third-handle", "third@example.test");
    invalid.content = "invalid".into();
    invalid.note = "INVALID_PASSKEY_NOTE_SENTINEL".into();
    let login = item(
        ProtonItemKind::Login(LoginContent {
            passkeys: vec![first, second, invalid],
            ..LoginContent::default()
        }),
        "Passkey notes",
    );

    let result = convert_export(&export(vec![login]), true);
    let main = find_item(&result, "Passkey notes");
    let split = find_item(&result, "Passkey notes — Passkey 2");
    assert!(main.fields.iter().any(|field| {
        field.name == "Proton passkey note 1" && field.value == "FIRST_PASSKEY_NOTE_SENTINEL"
    }));
    assert!(main.fields.iter().any(|field| {
        field.name == "Proton passkey note 3" && field.value == "INVALID_PASSKEY_NOTE_SENTINEL"
    }));
    assert!(
        !main
            .fields
            .iter()
            .any(|field| field.value == "SECOND_PASSKEY_NOTE_SENTINEL")
    );
    assert!(split.fields.iter().any(|field| {
        field.name == "Proton passkey note 2" && field.value == "SECOND_PASSKEY_NOTE_SENTINEL"
    }));
    assert!(!split.fields.iter().any(|field| {
        matches!(
            field.value.as_str(),
            "FIRST_PASSKEY_NOTE_SENTINEL" | "INVALID_PASSKEY_NOTE_SENTINEL"
        )
    }));
    let report = serde_json::to_string(&result.report).expect("report should serialize");
    for note in [
        "FIRST_PASSKEY_NOTE_SENTINEL",
        "SECOND_PASSKEY_NOTE_SENTINEL",
        "INVALID_PASSKEY_NOTE_SENTINEL",
    ] {
        assert!(!report.contains(note));
    }
    assert_eq!(result.report.summary.passkeys_total, 3);
    assert_eq!(result.report.summary.passkeys_converted, 2);
    assert_eq!(result.report.summary.passkeys_unsupported, 1);
}

#[test]
fn rejects_exact_duplicate_passkeys_across_logins_and_preserves_their_notes() {
    let mut first = valid_passkey(1, &[1, 2, 3], b"shared-handle", "user@example.test");
    first.note = "DUPLICATE_PASSKEY_NOTE_SENTINEL".into();
    let mut second = valid_passkey(1, &[1, 2, 3], b"shared-handle", "user@example.test");
    second.note = "DUPLICATE_PASSKEY_NOTE_SENTINEL".into();
    let first = item(
        ProtonItemKind::Login(LoginContent {
            passkeys: vec![first],
            ..LoginContent::default()
        }),
        "First duplicate",
    );
    let second = item(
        ProtonItemKind::Login(LoginContent {
            passkeys: vec![second],
            ..LoginContent::default()
        }),
        "Second duplicate",
    );

    let result = convert_export(&export(vec![first, second]), true);
    assert!(result.export.items.iter().all(|item| {
        item.login
            .as_ref()
            .is_some_and(|login| login.fido2_credentials.is_empty())
    }));
    assert!(result.export.items.iter().all(|item| {
        item.fields
            .iter()
            .any(|field| field.value == "DUPLICATE_PASSKEY_NOTE_SENTINEL")
    }));
    assert_eq!(
        result
            .report
            .outcomes
            .iter()
            .filter(|entry| {
                entry.entity == EntityKind::Passkey
                    && entry.outcome == OutcomeCode::UnsupportedDuplicatePasskey
                    && entry.reason == ReasonCode::ExactDuplicatePasskey
            })
            .count(),
        2
    );
    assert_eq!(result.report.summary.passkeys_unsupported, 2);
    assert_eq!(result.report.summary.strict_failures, 4);
    assert!(
        !serde_json::to_string(&result.report)
            .expect("report should serialize")
            .contains("DUPLICATE_PASSKEY_NOTE_SENTINEL")
    );
}

#[test]
fn rejects_every_member_of_a_conflicting_duplicate_credential_group() {
    let first = valid_passkey(1, &[1, 2, 3], b"shared-handle", "user@example.test");
    let second = valid_passkey(2, &[1, 2, 3], b"shared-handle", "user@example.test");
    let first = item(
        ProtonItemKind::Login(LoginContent {
            passkeys: vec![first],
            ..LoginContent::default()
        }),
        "First conflict",
    );
    let second = item(
        ProtonItemKind::Login(LoginContent {
            passkeys: vec![second],
            ..LoginContent::default()
        }),
        "Second conflict",
    );

    let result = convert_export(&export(vec![first, second]), true);
    assert!(result.export.items.iter().all(|item| {
        item.login
            .as_ref()
            .is_some_and(|login| login.fido2_credentials.is_empty())
    }));
    assert_eq!(
        result
            .report
            .outcomes
            .iter()
            .filter(|entry| {
                entry.entity == EntityKind::Passkey
                    && entry.outcome == OutcomeCode::UnsupportedDuplicatePasskey
                    && entry.reason == ReasonCode::ConflictingDuplicatePasskey
            })
            .count(),
        2
    );
}

#[test]
fn accepts_distinct_origin_domain_and_reports_all_passkey_fallbacks() {
    let mut subdomain = valid_passkey(1, &[1, 2, 3], b"first-handle", "first@example.test");
    subdomain.domain = "login.example.test".into();
    let subdomain = item(
        ProtonItemKind::Login(LoginContent {
            passkeys: vec![subdomain],
            ..LoginContent::default()
        }),
        "Origin subdomain",
    );
    let subdomain_result = convert_export(&export(vec![subdomain]), true);
    assert_eq!(subdomain_result.report.summary.passkeys_converted, 1);
    assert_eq!(subdomain_result.report.summary.passkeys_unsupported, 0);
    assert!(subdomain_result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Passkey
            && entry.outcome == OutcomeCode::Converted
            && entry.reason == ReasonCode::None
    }));

    let mut with_creation_data =
        valid_passkey(2, &[4, 5, 6], b"second-handle", "second@example.test");
    with_creation_data.creation_data = Some(ProtonPasskeyCreationData {
        os_name: "Synthetic OS".into(),
        os_version: "1".into(),
        device_name: "Synthetic device".into(),
        app_version: "1".into(),
    });
    with_creation_data.create_time = None;
    let with_creation_data = item(
        ProtonItemKind::Login(LoginContent {
            passkeys: vec![with_creation_data],
            ..LoginContent::default()
        }),
        "Creation metadata",
    );
    let creation_result = convert_export(&export(vec![with_creation_data]), true);
    assert_eq!(creation_result.report.summary.passkeys_converted, 1);
    assert_eq!(creation_result.report.summary.strict_failures, 1);
    assert!(creation_result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Passkey
            && entry.outcome == OutcomeCode::ConvertedWithFallback
            && entry.reason == ReasonCode::UnsupportedPlatformMetadata
            && entry.additional_reasons == vec![ReasonCode::PasskeyTimeFallback]
    }));
}

#[test]
fn ledgers_passkeys_and_attachments_inside_trashed_items() {
    let mut trashed = item(
        ProtonItemKind::Login(LoginContent {
            passkeys: vec![valid_passkey(
                1,
                &[1, 2, 3],
                b"trashed-handle",
                "trashed@example.test",
            )],
            ..LoginContent::default()
        }),
        "Trashed login",
    );
    trashed.state = 2;
    trashed.files = vec!["SYNTHETIC_TRASHED_ATTACHMENT".into()];

    let result = convert_export(&export(vec![trashed]), true);
    assert_eq!(result.report.summary.items_total, 1);
    assert_eq!(result.report.summary.passkeys_total, 1);
    assert_eq!(result.report.summary.attachment_sets_skipped, 1);
    assert_eq!(result.report.summary.passkeys_skipped, 1);
    assert_eq!(result.report.summary.passkeys_unsupported, 0);
    assert_eq!(result.report.summary.strict_failures, 0);
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Passkey && entry.outcome == OutcomeCode::SkippedTrashed
    }));
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Attachment && entry.outcome == OutcomeCode::SkippedTrashed
    }));
}

#[test]
fn preserves_encrypted_ssh_private_key_after_validating_its_public_identity() {
    let encrypted = item(
        ProtonItemKind::SshKey(SshKeyContent {
            private_key: ENCRYPTED_SSH_PRIVATE_KEY.into(),
            public_key: ENCRYPTED_SSH_PUBLIC_KEY.into(),
            fingerprint: ENCRYPTED_SSH_FINGERPRINT.into(),
            sections: vec![ProtonSection {
                section_name: "SSH".into(),
                section_fields: vec![field("Host", "text", "encrypted.example.test")],
            }],
        }),
        "Encrypted SSH",
    );

    let result = convert_export(&export(vec![encrypted]), true);
    let converted = find_item(&result, "Encrypted SSH");
    let ssh_key = converted.ssh_key.as_ref().expect("SSH data should exist");

    assert_eq!(converted.item_type, 5);
    assert_eq!(ssh_key.private_key, ENCRYPTED_SSH_PRIVATE_KEY);
    assert_eq!(ssh_key.public_key, ENCRYPTED_SSH_CANONICAL_PUBLIC_KEY);
    assert_eq!(ssh_key.key_fingerprint, ENCRYPTED_SSH_FINGERPRINT);
    assert!(
        converted
            .fields
            .iter()
            .any(|field| { field.name == "SSH / Host" && field.value == "encrypted.example.test" })
    );
    assert_eq!(result.report.summary.items_converted, 1);
    assert_eq!(result.report.summary.strict_failures, 1);
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Item
            && entry.outcome == OutcomeCode::ConvertedWithFallback
            && entry.reason == ReasonCode::EncryptedSshKeyNotFullyVerified
    }));
}

#[test]
fn rejects_encrypted_ssh_keys_with_mismatched_public_identity() {
    let public_mismatch = item(
        ProtonItemKind::SshKey(SshKeyContent {
            private_key: ENCRYPTED_SSH_PRIVATE_KEY.into(),
            public_key: SSH_PUBLIC_KEY.into(),
            fingerprint: ENCRYPTED_SSH_FINGERPRINT.into(),
            sections: Vec::new(),
        }),
        "Encrypted public mismatch",
    );
    let fingerprint_mismatch = item(
        ProtonItemKind::SshKey(SshKeyContent {
            private_key: ENCRYPTED_SSH_PRIVATE_KEY.into(),
            public_key: ENCRYPTED_SSH_PUBLIC_KEY.into(),
            fingerprint: SSH_FINGERPRINT.into(),
            sections: Vec::new(),
        }),
        "Encrypted fingerprint mismatch",
    );

    let result = convert_export(&export(vec![public_mismatch, fingerprint_mismatch]), true);

    assert!(result.export.items.is_empty());
    assert_eq!(result.report.summary.items_skipped, 2);
    assert_eq!(result.report.summary.strict_failures, 2);
    assert_eq!(
        result
            .report
            .outcomes
            .iter()
            .filter(|entry| {
                entry.entity == EntityKind::Item && entry.reason == ReasonCode::SshKeyMismatch
            })
            .count(),
        2
    );
}

#[test]
fn converts_a_real_synthetic_rsa_openssh_key() {
    let rsa = item(
        ProtonItemKind::SshKey(SshKeyContent {
            private_key: RSA_SSH_PRIVATE_KEY.into(),
            public_key: RSA_SSH_PUBLIC_KEY.into(),
            fingerprint: RSA_SSH_FINGERPRINT.into(),
            sections: Vec::new(),
        }),
        "RSA SSH",
    );

    let result = convert_export(&export(vec![rsa]), true);
    let converted = find_item(&result, "RSA SSH");
    let ssh_key = converted.ssh_key.as_ref().expect("SSH data should exist");

    assert_eq!(converted.item_type, 5);
    assert_eq!(ssh_key.private_key.trim_end(), RSA_SSH_PRIVATE_KEY);
    assert_eq!(ssh_key.public_key, RSA_SSH_PUBLIC_KEY);
    assert_eq!(ssh_key.key_fingerprint, RSA_SSH_FINGERPRINT);
    assert_eq!(result.report.summary.items_converted, 1);
    assert_eq!(result.report.summary.strict_failures, 0);
}

#[test]
fn rejects_malformed_and_mismatched_ssh_key_material_with_closed_reasons() {
    let malformed = item(
        ProtonItemKind::SshKey(SshKeyContent {
            private_key: "MALFORMED_PRIVATE_KEY_SENTINEL".into(),
            public_key: SSH_PUBLIC_KEY.into(),
            fingerprint: SSH_FINGERPRINT.into(),
            sections: Vec::new(),
        }),
        "Malformed SSH",
    );
    let mismatched = item(
        ProtonItemKind::SshKey(SshKeyContent {
            private_key: SSH_PRIVATE_KEY.into(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILI+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com".into(),
            fingerprint: SSH_FINGERPRINT.into(),
            sections: Vec::new(),
        }),
        "Mismatched SSH",
    );
    let fingerprint_mismatch = item(
        ProtonItemKind::SshKey(SshKeyContent {
            private_key: SSH_PRIVATE_KEY.into(),
            public_key: SSH_PUBLIC_KEY.into(),
            fingerprint: "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM".into(),
            sections: Vec::new(),
        }),
        "Fingerprint mismatch",
    );

    let result = convert_export(
        &export(vec![malformed, mismatched, fingerprint_mismatch]),
        true,
    );
    assert_eq!(
        result
            .export
            .items
            .iter()
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>(),
        Vec::<&str>::new()
    );
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Item && entry.reason == ReasonCode::SshKeyMalformed
    }));
    assert_eq!(
        result
            .report
            .outcomes
            .iter()
            .filter(|entry| {
                entry.entity == EntityKind::Item && entry.reason == ReasonCode::SshKeyMismatch
            })
            .count(),
        2
    );
    let report = serde_json::to_string(&result.report).expect("report should serialize");
    assert!(!report.contains("MALFORMED_PRIVATE_KEY_SENTINEL"));
    assert!(!report.contains(SSH_PUBLIC_KEY));
    assert!(!report.contains(SSH_FINGERPRINT));
}

#[derive(Serialize)]
struct FixtureOuter {
    #[serde(rename = "c")]
    content: Vec<u8>,
    #[serde(rename = "v")]
    version: u64,
}

#[derive(Serialize)]
struct FixturePasskey {
    key: FixtureKey,
    #[serde(rename = "cid")]
    credential_id: Vec<u8>,
    #[serde(rename = "rid")]
    rp_id: String,
    #[serde(rename = "uhd")]
    user_handle: Option<Vec<u8>>,
    #[serde(rename = "cnt")]
    counter: Option<u32>,
    #[serde(rename = "ext")]
    extensions: FixtureExtensions,
    #[serde(rename = "udn")]
    user_display_name: Option<String>,
    #[serde(rename = "un")]
    username: Option<String>,
}

#[derive(Serialize)]
struct FixtureKey {
    #[serde(rename = "kty")]
    key_type: FixtureTagged,
    #[serde(rename = "kid")]
    key_id: Vec<u8>,
    #[serde(rename = "alg")]
    algorithm: Option<FixtureTagged>,
    #[serde(rename = "kops")]
    key_operations: Vec<FixtureTagged>,
    #[serde(rename = "biv")]
    base_iv: Vec<u8>,
    #[serde(rename = "par")]
    parameters: Vec<(FixtureLabel, FixtureValue)>,
}

#[derive(Serialize)]
struct FixtureTagged {
    #[serde(rename = "t")]
    tag: &'static str,
    #[serde(rename = "c")]
    content: &'static str,
}

#[derive(Serialize)]
#[serde(tag = "t", content = "c")]
enum FixtureLabel {
    #[serde(rename = "int")]
    Integer(i64),
}

#[derive(Serialize)]
#[serde(tag = "t", content = "c")]
enum FixtureValue {
    #[serde(rename = "int")]
    Integer(FixtureInteger),
    #[serde(rename = "bytes")]
    Bytes(Vec<u8>),
}

#[derive(Serialize)]
struct FixtureInteger {
    inner: Vec<u8>,
}

#[derive(Serialize)]
struct FixtureExtensions {
    hmac_secret: Option<FixtureHmacSecret>,
}

#[derive(Serialize)]
struct FixtureHmacSecret {
    cred_with_uv: Vec<u8>,
    cred_without_uv: Option<Vec<u8>>,
}

fn valid_passkey(
    scalar_byte: u8,
    credential_id: &[u8],
    user_handle: &[u8],
    username: &str,
) -> ProtonPasskeyInput {
    let scalar = vec![scalar_byte; 32];
    let secret = p256::SecretKey::from_slice(&scalar).expect("synthetic scalar should be valid");
    let point = secret.public_key().to_encoded_point(false);
    let display_name = format!("Synthetic User {scalar_byte}");
    let inner = FixturePasskey {
        key: FixtureKey {
            key_type: FixtureTagged {
                tag: "assign",
                content: "EC2",
            },
            key_id: Vec::new(),
            algorithm: Some(FixtureTagged {
                tag: "assign",
                content: "ES256",
            }),
            key_operations: Vec::new(),
            base_iv: Vec::new(),
            parameters: vec![
                (
                    FixtureLabel::Integer(-1),
                    FixtureValue::Integer(FixtureInteger {
                        inner: 1_i128.to_le_bytes().to_vec(),
                    }),
                ),
                (
                    FixtureLabel::Integer(-2),
                    FixtureValue::Bytes(point.x().expect("point should have x").to_vec()),
                ),
                (
                    FixtureLabel::Integer(-3),
                    FixtureValue::Bytes(point.y().expect("point should have y").to_vec()),
                ),
                (FixtureLabel::Integer(-4), FixtureValue::Bytes(scalar)),
            ],
        },
        credential_id: credential_id.to_vec(),
        rp_id: "example.test".into(),
        user_handle: Some(user_handle.to_vec()),
        counter: Some(7),
        extensions: FixtureExtensions { hmac_secret: None },
        user_display_name: Some(display_name.clone()),
        username: Some(username.into()),
    };
    let nested = rmp_serde::to_vec_named(&inner).expect("inner fixture should serialize");
    let outer = rmp_serde::to_vec_named(&FixtureOuter {
        content: nested,
        version: 1,
    })
    .expect("outer fixture should serialize");

    ProtonPasskeyInput {
        key_id: URL_SAFE_NO_PAD.encode(credential_id),
        content: STANDARD.encode(outer),
        domain: "example.test".into(),
        rp_id: "example.test".into(),
        rp_name: "Example".into(),
        user_name: username.into(),
        user_display_name: display_name,
        user_id: STANDARD.encode(user_handle),
        create_time: Some(1_767_225_600),
        note: String::new(),
        credential_id: STANDARD.encode(credential_id),
        user_handle: STANDARD.encode(user_handle),
        creation_data: None,
    }
}
