use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use protonpass_to_bitwarden::bitwarden_export::convert_passkeys_only;
use protonpass_to_bitwarden::proton_export::{
    EmptyContent, LoginContent, ProtonExport, ProtonExtraField, ProtonExtraFieldData, ProtonItem,
    ProtonItemData, ProtonItemKind, ProtonMetadata, ProtonVault,
};
use protonpass_to_bitwarden::proton_passkey::{ProtonPasskeyCreationData, ProtonPasskeyInput};
use protonpass_to_bitwarden::report::{EntityKind, MigrationMode, OutcomeCode, ReasonCode};
use serde::Serialize;

const CREATED: i64 = 1_700_000_000;

fn export(items: Vec<ProtonItem>) -> ProtonExport {
    ProtonExport {
        version: "synthetic".into(),
        user_id: None,
        encrypted: Some(false),
        vaults: BTreeMap::from([(
            "vault-id".into(),
            ProtonVault {
                name: "SOURCE_FOLDER_SENTINEL".into(),
                description: "SOURCE_VAULT_DESCRIPTION_SENTINEL".into(),
                items,
            },
        )]),
    }
}

fn login_item(name: &str, passkeys: Vec<ProtonPasskeyInput>) -> ProtonItem {
    ProtonItem {
        item_id: format!("item-{name}"),
        share_id: "share-id".into(),
        data: ProtonItemData {
            metadata: ProtonMetadata {
                name: name.into(),
                note: "SOURCE_ITEM_NOTE_SENTINEL".into(),
                item_uuid: format!("uuid-{name}"),
            },
            extra_fields: vec![ProtonExtraField {
                field_name: "SOURCE_FIELD_NAME_SENTINEL".into(),
                field_type: "hidden".into(),
                data: ProtonExtraFieldData {
                    content: "SOURCE_FIELD_VALUE_SENTINEL".into(),
                    ..ProtonExtraFieldData::default()
                },
            }],
            platform_specific: None,
            kind: ProtonItemKind::Login(LoginContent {
                item_email: "SOURCE_EMAIL_SENTINEL".into(),
                item_username: "SOURCE_USERNAME_SENTINEL".into(),
                username: "SOURCE_LEGACY_USERNAME_SENTINEL".into(),
                password: "SOURCE_PASSWORD_SENTINEL".into(),
                urls: vec!["https://SOURCE_URL_SENTINEL.example".into()],
                autofill_urls: Vec::new(),
                totp_uri: "otpauth://SOURCE_TOTP_SENTINEL".into(),
                passkeys,
            }),
        },
        state: 1,
        alias_email: None,
        content_format_version: 6,
        create_time: CREATED,
        modify_time: CREATED + 1,
        pinned: true,
        files: vec!["SOURCE_ATTACHMENT_SENTINEL".into()],
    }
}

fn note_item(name: &str) -> ProtonItem {
    ProtonItem {
        item_id: format!("item-{name}"),
        share_id: "share-id".into(),
        data: ProtonItemData {
            metadata: ProtonMetadata {
                name: name.into(),
                note: "UNRELATED_NOTE_SECRET_SENTINEL".into(),
                item_uuid: format!("uuid-{name}"),
            },
            extra_fields: Vec::new(),
            platform_specific: None,
            kind: ProtonItemKind::Note(EmptyContent {}),
        },
        state: 1,
        alias_email: None,
        content_format_version: 6,
        create_time: CREATED,
        modify_time: CREATED + 1,
        pinned: false,
        files: vec!["UNRELATED_ATTACHMENT_SENTINEL".into()],
    }
}

#[test]
fn emits_one_minimal_carrier_without_source_login_secrets() {
    let mut passkey = valid_passkey(1, &[1, 2, 3], b"handle-one", "one@example.test");
    passkey.note = "SOURCE_PASSKEY_NOTE_SENTINEL".into();
    let source = export(vec![login_item("Original", vec![passkey])]);

    let result = convert_passkeys_only(&source, true);

    assert!(result.export.folders.is_empty());
    assert_eq!(result.export.items.len(), 1);
    let carrier = &result.export.items[0];
    assert_eq!(carrier.name, "Original — Proton passkey");
    assert_eq!(carrier.item_type, 1);
    assert_eq!(carrier.reprompt, 0);
    assert!(!carrier.favorite);
    assert_eq!(carrier.folder_id, None);
    assert_eq!(carrier.notes, None);
    assert!(carrier.fields.is_empty());
    assert_eq!(carrier.creation_date, None);
    assert_eq!(carrier.revision_date, None);
    assert!(carrier.secure_note.is_none());
    assert!(carrier.card.is_none());
    assert!(carrier.identity.is_none());
    assert!(carrier.ssh_key.is_none());
    let login = carrier.login.as_ref().expect("carrier should be a login");
    assert!(login.uris.is_empty());
    assert_eq!(login.username, None);
    assert_eq!(login.password, None);
    assert_eq!(login.totp, None);
    assert_eq!(login.fido2_credentials.len(), 1);

    let json = serde_json::to_string(&result.export).expect("export should serialize");
    for sentinel in [
        "SOURCE_FOLDER_SENTINEL",
        "SOURCE_VAULT_DESCRIPTION_SENTINEL",
        "SOURCE_ITEM_NOTE_SENTINEL",
        "SOURCE_FIELD_NAME_SENTINEL",
        "SOURCE_FIELD_VALUE_SENTINEL",
        "SOURCE_EMAIL_SENTINEL",
        "SOURCE_USERNAME_SENTINEL",
        "SOURCE_LEGACY_USERNAME_SENTINEL",
        "SOURCE_PASSWORD_SENTINEL",
        "SOURCE_URL_SENTINEL",
        "SOURCE_TOTP_SENTINEL",
        "SOURCE_PASSKEY_NOTE_SENTINEL",
        "SOURCE_ATTACHMENT_SENTINEL",
    ] {
        assert!(!json.contains(sentinel), "leaked {sentinel}");
    }
    assert_eq!(result.report.mode, MigrationMode::PasskeysOnly);
    assert_eq!(result.report.summary.items_filtered, 1);
    assert_eq!(result.report.summary.passkeys_converted, 1);
    assert_eq!(result.report.summary.output_items_created, 1);
    assert_eq!(result.report.summary.strict_failures, 0);
    let passkey_entry = result
        .report
        .outcomes
        .iter()
        .find(|entry| entry.entity == EntityKind::Passkey)
        .expect("passkey outcome should exist");
    assert_eq!(passkey_entry.outcome, OutcomeCode::ConvertedWithFallback);
    assert_eq!(passkey_entry.reason, ReasonCode::PasskeyNoteOmitted);
}

#[test]
fn numbers_all_source_positions_and_preserves_fallback_reasons() {
    let mut first = valid_passkey(1, &[1], b"first-handle", "first@example.test");
    first.create_time = None;
    let mut invalid = valid_passkey(2, &[2], b"second-handle", "second@example.test");
    invalid.content = "invalid".into();
    let mut third = valid_passkey(3, &[3], b"third-handle", "third@example.test");
    third.creation_data = Some(ProtonPasskeyCreationData {
        os_name: "Synthetic OS".into(),
        os_version: "1".into(),
        device_name: "Synthetic device".into(),
        app_version: "1".into(),
    });
    third.note = "omitted third note".into();
    let source = export(vec![login_item("Three", vec![first, invalid, third])]);

    let result = convert_passkeys_only(&source, true);

    assert_eq!(
        result
            .export
            .items
            .iter()
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Three — Proton passkey 1", "Three — Proton passkey 3"]
    );
    assert!(result.export.items.iter().all(|item| {
        item.login
            .as_ref()
            .is_some_and(|login| login.fido2_credentials.len() == 1)
    }));
    assert_eq!(result.report.summary.passkeys_total, 3);
    assert_eq!(result.report.summary.passkeys_converted, 2);
    assert_eq!(result.report.summary.passkeys_unsupported, 1);
    assert_eq!(result.report.summary.output_items_created, 2);
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Passkey
            && entry.outcome == OutcomeCode::ConvertedWithFallback
            && entry.reason == ReasonCode::PasskeyTimeFallback
    }));
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Passkey
            && entry.outcome == OutcomeCode::InvalidKeyMaterial
            && entry.reason == ReasonCode::MalformedPasskeyEncoding
    }));
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Passkey
            && entry.outcome == OutcomeCode::SplitAdditionalPasskey
            && entry.reason == ReasonCode::UnsupportedPlatformMetadata
            && entry
                .additional_reasons
                .contains(&ReasonCode::AdditionalPasskeySplit)
            && entry
                .additional_reasons
                .contains(&ReasonCode::PasskeyNoteOmitted)
    }));
}

#[test]
fn reports_unsupported_trashed_and_filtered_records_without_attachment_failures() {
    let mut invalid = valid_passkey(1, &[1], b"active-handle", "active@example.test");
    invalid.content = "invalid".into();
    let active = login_item("Active", vec![invalid]);
    let mut trashed = login_item(
        "Trashed",
        vec![valid_passkey(
            2,
            &[2],
            b"trashed-handle",
            "trash@example.test",
        )],
    );
    trashed.state = 2;
    let source = export(vec![active, trashed, note_item("Unrelated")]);

    let result = convert_passkeys_only(&source, true);

    assert!(result.export.items.is_empty());
    assert_eq!(result.report.summary.items_total, 3);
    assert_eq!(result.report.summary.items_filtered, 2);
    assert_eq!(result.report.summary.items_skipped, 1);
    assert_eq!(result.report.summary.passkeys_total, 2);
    assert_eq!(result.report.summary.passkeys_skipped, 1);
    assert_eq!(result.report.summary.passkeys_unsupported, 1);
    assert_eq!(result.report.summary.attachment_sets_skipped, 0);
    assert_eq!(result.report.summary.output_items_created, 0);
    assert!(
        result
            .report
            .outcomes
            .iter()
            .all(|entry| entry.entity != EntityKind::Attachment)
    );
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Item
            && entry.outcome == OutcomeCode::FilteredPasskeysOnly
            && entry.reason == ReasonCode::PasskeysOnlyMode
    }));
    assert!(result.report.outcomes.iter().any(|entry| {
        entry.entity == EntityKind::Passkey && entry.outcome == OutcomeCode::SkippedTrashed
    }));
}

#[test]
fn rejects_duplicates_globally_and_is_deterministic() {
    let first = login_item(
        "First",
        vec![valid_passkey(
            1,
            &[7, 8, 9],
            b"shared-handle",
            "shared@example.test",
        )],
    );
    let second = login_item(
        "Second",
        vec![valid_passkey(
            1,
            &[7, 8, 9],
            b"shared-handle",
            "shared@example.test",
        )],
    );
    let source = export(vec![first, second]);

    let first_result = convert_passkeys_only(&source, false);
    let second_result = convert_passkeys_only(&source, false);

    assert!(first_result.export.items.is_empty());
    assert_eq!(first_result.report.summary.passkeys_unsupported, 2);
    assert_eq!(
        first_result
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
    assert_eq!(
        serde_json::to_value(&first_result.export).expect("export should serialize"),
        serde_json::to_value(&second_result.export).expect("export should serialize")
    );
    assert_eq!(first_result.report, second_result.report);
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
