use std::collections::{BTreeMap, BTreeSet};

use num_bigint_dig::BigUint;
use serde::Serialize;
use ssh_key::{
    Fingerprint, HashAlg, LineEnding, Mpint, PrivateKey, PublicKey,
    private::{KeypairData, RsaKeypair},
    public::{Ed25519PublicKey, KeyData},
};
use time::{OffsetDateTime, format_description::well_known::Iso8601};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::proton_export::{
    AutofillUrl, CreditCardContent, IdentityContent, LoginContent, ProtonExport, ProtonExtraField,
    ProtonItem, ProtonItemKind, ProtonSection, SshKeyContent, WifiContent,
};
use crate::proton_passkey::{
    ConvertedPasskey, PasskeyFailure, ProtonPasskeyInput, convert_passkey,
};
use crate::report::{
    EntityKind, MigrationMode, MigrationReport, OutcomeCode, ReasonCode, ReportEntry, stable_id,
};

const FOLDER_NAMESPACE: Uuid = Uuid::from_bytes([
    0xcf, 0x36, 0x65, 0x59, 0x37, 0x1d, 0x52, 0xc0, 0x82, 0xc7, 0x4f, 0x59, 0x2b, 0xbd, 0x63, 0xd1,
]);
const MAX_SSH_PRIVATE_KEY_BYTES: usize = 64 * 1024;
const MAX_SSH_PUBLIC_KEY_BYTES: usize = 16 * 1024;
const MAX_SSH_FINGERPRINT_BYTES: usize = 256;
const MAX_RSA_COMPONENT_BYTES: usize = 512;

impl Zeroize for ConvertedPasskey {
    fn zeroize(&mut self) {
        self.credential_id.zeroize();
        self.key_type.zeroize();
        self.key_algorithm.zeroize();
        self.key_curve.zeroize();
        self.key_value.zeroize();
        self.rp_id.zeroize();
        self.user_handle.zeroize();
        self.user_name.zeroize();
        self.counter.zeroize();
        self.rp_name.zeroize();
        self.user_display_name.zeroize();
        self.discoverable.zeroize();
        self.creation_date.zeroize();
        self.used_item_time_fallback.zeroize();
        self.has_unpreserved_creation_data.zeroize();
        self.credential_id_bytes.zeroize();
    }
}

#[derive(Serialize, Zeroize)]
pub struct BitwardenExport {
    pub encrypted: bool,
    pub folders: Vec<BitwardenFolder>,
    pub items: Vec<BitwardenItem>,
}

#[derive(Clone, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct BitwardenFolder {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenItem {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(rename = "type")]
    pub item_type: u8,
    pub reprompt: u8,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub favorite: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<BitwardenField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<BitwardenLogin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure_note: Option<BitwardenSecureNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<BitwardenCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<BitwardenIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<BitwardenSshKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_date: Option<String>,
}

#[derive(Clone, Serialize, Zeroize)]
pub struct BitwardenField {
    pub name: String,
    pub value: String,
    #[serde(rename = "type")]
    pub field_type: u8,
}

#[derive(Clone, Serialize, Zeroize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenLogin {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uris: Vec<BitwardenUri>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fido2_credentials: Vec<ConvertedPasskey>,
}

#[derive(Clone, Serialize, Zeroize)]
pub struct BitwardenUri {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#match: Option<u8>,
}

#[derive(Clone, Serialize, Zeroize)]
pub struct BitwardenSecureNote {
    #[serde(rename = "type")]
    pub note_type: u8,
}

#[derive(Clone, Serialize, Zeroize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenCard {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardholder_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_month: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp_year: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Clone, Default, Serialize, Zeroize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passport_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_number: Option<String>,
}

#[derive(Clone, Serialize, Zeroize)]
#[serde(rename_all = "camelCase")]
pub struct BitwardenSshKey {
    pub private_key: String,
    pub public_key: String,
    pub key_fingerprint: String,
}

pub struct ConversionResult {
    pub export: BitwardenExport,
    pub report: MigrationReport,
}

struct ItemContext<'a> {
    vault_id: &'a str,
    folder_id: Option<String>,
    item_id: String,
    name: Option<String>,
}

struct BuiltItem {
    item: BitwardenItem,
    item_outcome: OutcomeCode,
    item_reason: ReasonCode,
    additional_reasons: Vec<ReasonCode>,
    additional_items: Vec<BitwardenItem>,
    passkey_entries: Vec<ReportEntry>,
}

struct ConvertedSshKey {
    value: BitwardenSshKey,
    encrypted: bool,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct PasskeyLocation {
    vault_index: usize,
    item_index: usize,
    passkey_index: usize,
}

struct ConvertedPasskeyCandidate {
    converted: ConvertedPasskey,
}

impl Drop for ConvertedPasskeyCandidate {
    fn drop(&mut self) {
        self.converted.zeroize();
    }
}

enum DuplicatePasskey {
    Exact,
    Conflicting,
}

type ConvertedPasskeys = BTreeMap<PasskeyLocation, ConvertedPasskeyCandidate>;
type DuplicatePasskeys = BTreeMap<PasskeyLocation, DuplicatePasskey>;
type PasskeyIdentity = (String, Vec<u8>);
type PasskeyGroupMember<'a> = (
    PasskeyLocation,
    &'a ProtonPasskeyInput,
    ConvertedPasskeyCandidate,
);
type PasskeyGroups<'a> = BTreeMap<PasskeyIdentity, Vec<PasskeyGroupMember<'a>>>;

struct PasskeyConversionState<'a> {
    location: PasskeyLocation,
    converted_passkeys: &'a ConvertedPasskeys,
    duplicate_passkeys: &'a DuplicatePasskeys,
}

fn classify_passkeys(source: &ProtonExport) -> (ConvertedPasskeys, DuplicatePasskeys) {
    let mut groups = PasskeyGroups::new();

    for (vault_index, vault) in source.vaults.values().enumerate() {
        for (item_index, item) in vault.items.iter().enumerate() {
            if item.state == 2 {
                continue;
            }
            let ProtonItemKind::Login(content) = &item.data.kind else {
                continue;
            };
            for (passkey_index, passkey) in content.passkeys.iter().enumerate() {
                if let Ok(converted) = convert_passkey(passkey, item.create_time) {
                    let key = (
                        converted.rp_id.to_ascii_lowercase(),
                        converted.credential_id_bytes.clone(),
                    );
                    groups.entry(key).or_default().push((
                        PasskeyLocation {
                            vault_index,
                            item_index,
                            passkey_index,
                        },
                        passkey,
                        ConvertedPasskeyCandidate { converted },
                    ));
                }
            }
        }
    }

    let mut converted_passkeys = BTreeMap::new();
    let mut duplicate_passkeys = BTreeMap::new();
    for group in groups.into_values() {
        if group.len() == 1 {
            if let Some((location, _, converted)) = group.into_iter().next() {
                converted_passkeys.insert(location, converted);
            }
            continue;
        }

        let first = &group[0];
        let exact = group
            .iter()
            .skip(1)
            .all(|value| value.1 == first.1 && value.2.converted == first.2.converted);
        for (location, _, _) in group {
            duplicate_passkeys.insert(
                location,
                if exact {
                    DuplicatePasskey::Exact
                } else {
                    DuplicatePasskey::Conflicting
                },
            );
        }
    }
    (converted_passkeys, duplicate_passkeys)
}

pub fn convert_export(source: &ProtonExport, names_redacted: bool) -> ConversionResult {
    let mut folders_by_name = BTreeMap::new();
    let mut items = Vec::new();
    let mut report = MigrationReport::new(names_redacted);
    let (converted_passkeys, duplicate_passkeys) = classify_passkeys(source);

    for (vault_index, (vault_id, vault)) in source.vaults.iter().enumerate() {
        let folder_id = create_folders(vault_id, &vault.name, &mut folders_by_name);
        for (item_index, item) in vault.items.iter().enumerate() {
            let item_id = stable_item_id(vault_id, item);
            let item_name = (!names_redacted).then(|| display_name(&item.data.metadata.name));
            let item_type = item.data.kind.label().to_owned();
            let location = PasskeyLocation {
                vault_index,
                item_index,
                passkey_index: 0,
            };

            if item.state == 2 {
                report.push(ReportEntry {
                    entity: EntityKind::Item,
                    id: item_id.clone(),
                    parent_id: None,
                    item_type: item_type.clone(),
                    outcome: OutcomeCode::SkippedTrashed,
                    reason: ReasonCode::None,
                    additional_reasons: Vec::new(),
                    name: item_name.clone(),
                });
                if let ProtonItemKind::Login(content) = &item.data.kind {
                    for (passkey_index, passkey) in content.passkeys.iter().enumerate() {
                        report.push(passkey_report_entry(
                            passkey_id(vault_id, &item_id, passkey_index, passkey),
                            &item_id,
                            item_name.clone(),
                            OutcomeCode::SkippedTrashed,
                            ReasonCode::None,
                        ));
                    }
                }
            } else {
                let context = ItemContext {
                    vault_id,
                    folder_id: folder_id.clone(),
                    item_id: item_id.clone(),
                    name: item_name.clone(),
                };

                match build_item(
                    item,
                    &context,
                    location,
                    &converted_passkeys,
                    &duplicate_passkeys,
                ) {
                    Ok(mut built) => {
                        report.push(ReportEntry {
                            entity: EntityKind::Item,
                            id: item_id.clone(),
                            parent_id: None,
                            item_type: item_type.clone(),
                            outcome: built.item_outcome,
                            reason: built.item_reason,
                            additional_reasons: built.additional_reasons,
                            name: item_name.clone(),
                        });
                        report.outcomes.append(&mut built.passkey_entries);
                        items.push(built.item);
                        items.append(&mut built.additional_items);
                    }
                    Err(reason) => report.push(ReportEntry {
                        entity: EntityKind::Item,
                        id: item_id.clone(),
                        parent_id: None,
                        item_type: item_type.clone(),
                        outcome: OutcomeCode::UnsupportedItemType,
                        reason,
                        additional_reasons: Vec::new(),
                        name: item_name.clone(),
                    }),
                }
            }

            if !item.files.is_empty() {
                report.push(ReportEntry {
                    entity: EntityKind::Attachment,
                    id: stable_id(
                        b"proton-attachment-set-v1",
                        &[vault_id.as_bytes(), item_id.as_bytes()],
                    ),
                    parent_id: Some(item_id),
                    item_type,
                    outcome: if item.state == 2 {
                        OutcomeCode::SkippedTrashed
                    } else {
                        OutcomeCode::SkippedAttachment
                    },
                    reason: if item.state == 2 {
                        ReasonCode::None
                    } else {
                        ReasonCode::AttachmentsRequireManualMigration
                    },
                    additional_reasons: Vec::new(),
                    name: item_name,
                });
            }
        }
    }

    report.finalize();
    report.summary.folders_created = folders_by_name.len();
    report.summary.output_items_created = items.len();
    ConversionResult {
        export: BitwardenExport {
            encrypted: false,
            folders: folders_by_name
                .into_iter()
                .map(|(mut name, folder)| {
                    name.zeroize();
                    folder
                })
                .collect(),
            items,
        },
        report,
    }
}

pub fn convert_passkeys_only(source: &ProtonExport, names_redacted: bool) -> ConversionResult {
    let mut items = Vec::new();
    let mut report = MigrationReport::new_with_mode(names_redacted, MigrationMode::PasskeysOnly);
    let (converted_passkeys, duplicate_passkeys) = classify_passkeys(source);

    for (vault_index, (vault_id, vault)) in source.vaults.iter().enumerate() {
        for (item_index, item) in vault.items.iter().enumerate() {
            let item_id = stable_item_id(vault_id, item);
            let item_name = (!names_redacted).then(|| display_name(&item.data.metadata.name));
            let trashed = item.state == 2;
            report.push(ReportEntry {
                entity: EntityKind::Item,
                id: item_id.clone(),
                parent_id: None,
                item_type: item.data.kind.label().to_owned(),
                outcome: if trashed {
                    OutcomeCode::SkippedTrashed
                } else {
                    OutcomeCode::FilteredPasskeysOnly
                },
                reason: if trashed {
                    ReasonCode::None
                } else {
                    ReasonCode::PasskeysOnlyMode
                },
                additional_reasons: Vec::new(),
                name: item_name.clone(),
            });

            let ProtonItemKind::Login(content) = &item.data.kind else {
                continue;
            };
            let multiple = content.passkeys.len() > 1;
            for (passkey_index, passkey) in content.passkeys.iter().enumerate() {
                let report_id = passkey_id(vault_id, &item_id, passkey_index, passkey);
                if trashed {
                    report.push(passkey_report_entry(
                        report_id,
                        &item_id,
                        item_name.clone(),
                        OutcomeCode::SkippedTrashed,
                        ReasonCode::None,
                    ));
                    continue;
                }

                let location = PasskeyLocation {
                    vault_index,
                    item_index,
                    passkey_index,
                };
                if let Some(duplicate) = duplicate_passkeys.get(&location) {
                    report.push(passkey_report_entry(
                        report_id,
                        &item_id,
                        item_name.clone(),
                        OutcomeCode::UnsupportedDuplicatePasskey,
                        match duplicate {
                            DuplicatePasskey::Exact => ReasonCode::ExactDuplicatePasskey,
                            DuplicatePasskey::Conflicting => {
                                ReasonCode::ConflictingDuplicatePasskey
                            }
                        },
                    ));
                    continue;
                }

                if let Some(candidate) = converted_passkeys.get(&location) {
                    let converted = candidate.converted.clone();
                    let split = passkey_index > 0;
                    let mut reasons = Vec::new();
                    if converted.has_unpreserved_creation_data {
                        reasons.push(ReasonCode::UnsupportedPlatformMetadata);
                    }
                    if converted.used_item_time_fallback {
                        reasons.push(ReasonCode::PasskeyTimeFallback);
                    }
                    if split {
                        reasons.push(ReasonCode::AdditionalPasskeySplit);
                    }
                    if !passkey.note.trim().is_empty() {
                        reasons.push(ReasonCode::PasskeyNoteOmitted);
                    }
                    let outcome = if split {
                        OutcomeCode::SplitAdditionalPasskey
                    } else if reasons.is_empty() {
                        OutcomeCode::Converted
                    } else {
                        OutcomeCode::ConvertedWithFallback
                    };
                    let reason = reasons.first().copied().unwrap_or(ReasonCode::None);
                    report.push(passkey_report_entry_with_reasons(
                        report_id,
                        &item_id,
                        item_name.clone(),
                        outcome,
                        reason,
                        reasons.into_iter().skip(1).collect(),
                    ));
                    items.push(passkey_carrier(
                        vault_id,
                        &item_id,
                        &item.data.metadata.name,
                        passkey_index,
                        multiple,
                        converted,
                    ));
                    continue;
                }

                let failure = convert_passkey(passkey, item.create_time)
                    .err()
                    .unwrap_or(PasskeyFailure::MalformedOrUnknownField);
                let (outcome, reason) = map_passkey_failure(failure);
                report.push(passkey_report_entry(
                    report_id,
                    &item_id,
                    item_name.clone(),
                    outcome,
                    reason,
                ));
            }
        }
    }

    report.finalize();
    report.summary.output_items_created = items.len();
    ConversionResult {
        export: BitwardenExport {
            encrypted: false,
            folders: Vec::new(),
            items,
        },
        report,
    }
}

fn passkey_carrier(
    vault_id: &str,
    item_id: &str,
    original_name: &str,
    passkey_index: usize,
    multiple: bool,
    converted: ConvertedPasskey,
) -> BitwardenItem {
    let name = if multiple {
        format!(
            "{} — Proton passkey {}",
            display_name(original_name),
            passkey_index + 1
        )
    } else {
        format!("{} — Proton passkey", display_name(original_name))
    };
    let mut suffix = b"passkey-only-v1".to_vec();
    suffix.extend_from_slice(&(passkey_index as u64).to_be_bytes());
    BitwardenItem {
        id: item_uuid(vault_id, item_id, &suffix),
        folder_id: None,
        item_type: 1,
        reprompt: 0,
        name,
        notes: None,
        favorite: false,
        fields: Vec::new(),
        login: Some(BitwardenLogin {
            uris: Vec::new(),
            username: None,
            password: None,
            totp: None,
            fido2_credentials: vec![converted],
        }),
        secure_note: None,
        card: None,
        identity: None,
        ssh_key: None,
        creation_date: None,
        revision_date: None,
    }
}

fn build_item(
    item: &ProtonItem,
    context: &ItemContext<'_>,
    location: PasskeyLocation,
    converted_passkeys: &BTreeMap<PasskeyLocation, ConvertedPasskeyCandidate>,
    duplicate_passkeys: &BTreeMap<PasskeyLocation, DuplicatePasskey>,
) -> Result<BuiltItem, ReasonCode> {
    let (creation_date, creation_fallback) = timestamp(item.create_time);
    let (revision_date, revision_fallback) = timestamp(item.modify_time);
    let mut bitwarden = BitwardenItem {
        id: item_uuid(context.vault_id, &context.item_id, b"main"),
        folder_id: context.folder_id.clone(),
        item_type: 1,
        reprompt: 0,
        name: display_name(&item.data.metadata.name),
        notes: nonempty(&item.data.metadata.note),
        favorite: item.pinned,
        fields: Vec::new(),
        login: None,
        secure_note: None,
        card: None,
        identity: None,
        ssh_key: None,
        creation_date,
        revision_date,
    };
    process_extra_fields(&mut bitwarden, &item.data.extra_fields);

    let mut fallback_reasons = Vec::new();
    if creation_fallback || revision_fallback {
        fallback_reasons.push(ReasonCode::ItemTimeInvalid);
    }
    let mut additional_items = Vec::new();
    let mut passkey_entries = Vec::new();

    match &item.data.kind {
        ProtonItemKind::Login(content) => {
            let (login, unsupported_mode) = build_login(content);
            bitwarden.login = Some(login);
            if nonempty(&content.item_username)
                .or_else(|| nonempty(&content.username))
                .is_some()
                && let Some(email) = nonempty(&content.item_email)
            {
                push_field(&mut bitwarden, "email", &email, 0);
            }
            if unsupported_mode {
                push_reason(&mut fallback_reasons, ReasonCode::UnsupportedAutofillMode);
            }
            if has_platform_metadata(item) {
                push_reason(
                    &mut fallback_reasons,
                    ReasonCode::UnsupportedPlatformMetadata,
                );
            }
            convert_login_passkeys(
                content,
                item,
                context,
                &mut bitwarden,
                &mut additional_items,
                &mut passkey_entries,
                PasskeyConversionState {
                    location,
                    converted_passkeys,
                    duplicate_passkeys,
                },
            );
            if passkey_entries.iter().any(|entry| {
                !matches!(
                    entry.outcome,
                    OutcomeCode::Converted
                        | OutcomeCode::ConvertedWithFallback
                        | OutcomeCode::SplitAdditionalPasskey
                )
            }) {
                push_reason(
                    &mut fallback_reasons,
                    ReasonCode::OneOrMorePasskeysNotMigrated,
                );
            }
        }
        ProtonItemKind::Note(_) => {
            bitwarden.item_type = 2;
            bitwarden.secure_note = Some(BitwardenSecureNote { note_type: 0 });
        }
        ProtonItemKind::Alias(_) => {
            bitwarden.login = Some(BitwardenLogin {
                uris: Vec::new(),
                username: item.alias_email.as_deref().and_then(nonempty),
                password: None,
                totp: None,
                fido2_credentials: Vec::new(),
            });
        }
        ProtonItemKind::CreditCard(content) => {
            bitwarden.item_type = 3;
            process_card(&mut bitwarden, content);
        }
        ProtonItemKind::Identity(content) => {
            bitwarden.item_type = 4;
            process_identity(&mut bitwarden, content);
        }
        ProtonItemKind::SshKey(content) => {
            bitwarden.item_type = 5;
            let converted = convert_ssh_key(content)?;
            bitwarden.ssh_key = Some(converted.value);
            process_sections(&mut bitwarden, &content.sections);
            if converted.encrypted {
                push_reason(
                    &mut fallback_reasons,
                    ReasonCode::EncryptedSshKeyNotFullyVerified,
                );
            }
        }
        ProtonItemKind::Wifi(content) => {
            bitwarden.item_type = 2;
            bitwarden.secure_note = Some(BitwardenSecureNote { note_type: 0 });
            process_wifi(&mut bitwarden, content);
            push_reason(&mut fallback_reasons, ReasonCode::WifiMappedToSecureNote);
        }
        ProtonItemKind::Custom(content) => {
            bitwarden.item_type = 2;
            bitwarden.secure_note = Some(BitwardenSecureNote { note_type: 0 });
            process_sections(&mut bitwarden, &content.sections);
        }
        ProtonItemKind::Unknown => return Err(ReasonCode::UnsupportedType),
    }

    if has_unsupported_extra_fields(item) {
        push_reason(&mut fallback_reasons, ReasonCode::UnsupportedExtraField);
    }

    let outcome = if fallback_reasons.is_empty() {
        OutcomeCode::Converted
    } else {
        OutcomeCode::ConvertedWithFallback
    };
    let reason = fallback_reasons
        .first()
        .copied()
        .unwrap_or(ReasonCode::None);
    let additional_reasons = fallback_reasons.into_iter().skip(1).collect();

    Ok(BuiltItem {
        item: bitwarden,
        item_outcome: outcome,
        item_reason: reason,
        additional_reasons,
        additional_items,
        passkey_entries,
    })
}

fn push_reason(reasons: &mut Vec<ReasonCode>, reason: ReasonCode) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn build_login(content: &LoginContent) -> (BitwardenLogin, bool) {
    let mut uris = Vec::new();
    let mut unsupported = false;
    if content.autofill_urls.is_empty() {
        uris.extend(content.urls.iter().filter_map(|url| uri(url, None)));
    } else {
        for value in &content.autofill_urls {
            let (mapped, mode_unsupported) = map_autofill_mode(value);
            unsupported |= mode_unsupported;
            if let Some(value) = uri(&value.url, mapped) {
                uris.push(value);
            }
        }
    }

    let username = nonempty(&content.item_username)
        .or_else(|| nonempty(&content.item_email))
        .or_else(|| nonempty(&content.username));
    (
        BitwardenLogin {
            uris,
            username,
            password: nonempty(&content.password),
            totp: nonempty(&content.totp_uri),
            fido2_credentials: Vec::new(),
        },
        unsupported,
    )
}

fn convert_login_passkeys(
    content: &LoginContent,
    item: &ProtonItem,
    context: &ItemContext<'_>,
    main: &mut BitwardenItem,
    additional: &mut Vec<BitwardenItem>,
    entries: &mut Vec<ReportEntry>,
    state: PasskeyConversionState<'_>,
) {
    let template = main.clone();
    let mut converted_index = 0_usize;
    for (index, passkey) in content.passkeys.iter().enumerate() {
        let passkey_id = passkey_id(context.vault_id, &context.item_id, index, passkey);
        let location = PasskeyLocation {
            passkey_index: index,
            ..state.location
        };
        if let Some(duplicate) = state.duplicate_passkeys.get(&location) {
            preserve_passkey_note(main, index, &passkey.note);
            entries.push(passkey_report_entry(
                passkey_id,
                &context.item_id,
                context.name.clone(),
                OutcomeCode::UnsupportedDuplicatePasskey,
                match duplicate {
                    DuplicatePasskey::Exact => ReasonCode::ExactDuplicatePasskey,
                    DuplicatePasskey::Conflicting => ReasonCode::ConflictingDuplicatePasskey,
                },
            ));
        } else if let Some(candidate) = state.converted_passkeys.get(&location) {
            let converted = candidate.converted.clone();
            let split = converted_index > 0;
            let fallback = converted.used_item_time_fallback;
            let creation_data_fallback = converted.has_unpreserved_creation_data;
            let entry_outcome = if split {
                OutcomeCode::SplitAdditionalPasskey
            } else if fallback || creation_data_fallback {
                OutcomeCode::ConvertedWithFallback
            } else {
                OutcomeCode::Converted
            };
            let mut reasons = Vec::new();
            if creation_data_fallback {
                reasons.push(ReasonCode::UnsupportedPlatformMetadata);
            }
            if fallback {
                reasons.push(ReasonCode::PasskeyTimeFallback);
            }
            if split {
                reasons.push(ReasonCode::AdditionalPasskeySplit);
            }
            let reason = reasons.first().copied().unwrap_or(ReasonCode::None);
            entries.push(passkey_report_entry_with_reasons(
                passkey_id,
                &context.item_id,
                context.name.clone(),
                entry_outcome,
                reason,
                reasons.into_iter().skip(1).collect(),
            ));

            if split {
                let mut clone = template.clone();
                clone.id = item_uuid(
                    context.vault_id,
                    &context.item_id,
                    &(converted_index as u64).to_be_bytes(),
                );
                clone.name = format!("{} — Passkey {}", main.name, converted_index + 1);
                if let Some(login) = &mut clone.login {
                    login.fido2_credentials = vec![converted];
                }
                preserve_passkey_note(&mut clone, index, &passkey.note);
                additional.push(clone);
            } else {
                if let Some(login) = &mut main.login {
                    login.fido2_credentials.push(converted);
                }
                preserve_passkey_note(main, index, &passkey.note);
            }
            converted_index += 1;
        } else {
            let failure = convert_passkey(passkey, item.create_time)
                .err()
                .unwrap_or(PasskeyFailure::MalformedOrUnknownField);
            let (outcome, reason) = map_passkey_failure(failure);
            preserve_passkey_note(main, index, &passkey.note);
            entries.push(passkey_report_entry(
                passkey_id,
                &context.item_id,
                context.name.clone(),
                outcome,
                reason,
            ));
        }
    }
}

fn passkey_id(vault_id: &str, item_id: &str, index: usize, passkey: &ProtonPasskeyInput) -> String {
    stable_id(
        b"proton-passkey-v1",
        &[
            vault_id.as_bytes(),
            item_id.as_bytes(),
            &(index as u64).to_be_bytes(),
            passkey.credential_id.as_bytes(),
        ],
    )
}

fn passkey_report_entry(
    id: String,
    parent_id: &str,
    name: Option<String>,
    outcome: OutcomeCode,
    reason: ReasonCode,
) -> ReportEntry {
    passkey_report_entry_with_reasons(id, parent_id, name, outcome, reason, Vec::new())
}

fn passkey_report_entry_with_reasons(
    id: String,
    parent_id: &str,
    name: Option<String>,
    outcome: OutcomeCode,
    reason: ReasonCode,
    additional_reasons: Vec<ReasonCode>,
) -> ReportEntry {
    ReportEntry {
        entity: EntityKind::Passkey,
        id,
        parent_id: Some(parent_id.to_owned()),
        item_type: "login".into(),
        outcome,
        reason,
        additional_reasons,
        name,
    }
}

fn preserve_passkey_note(item: &mut BitwardenItem, index: usize, note: &str) {
    if let Some(note) = nonempty(note) {
        push_field(
            item,
            &format!("Proton passkey note {}", index + 1),
            &note,
            0,
        );
    }
}

fn process_card(item: &mut BitwardenItem, content: &CreditCardContent) {
    if let Some(pin) = nonempty(&content.pin) {
        push_field(item, "PIN", &pin, 1);
    }
    let mut date = content.expiration_date.split('-');
    let year = date.next().and_then(nonempty);
    let month = date
        .next()
        .and_then(nonempty)
        .map(|value| value.trim_start_matches('0').to_owned())
        .filter(|value| !value.is_empty());
    item.card = Some(BitwardenCard {
        cardholder_name: nonempty(&content.cardholder_name),
        brand: card_brand(&content.number).map(str::to_owned),
        number: nonempty(&content.number),
        exp_month: month,
        exp_year: year,
        code: nonempty(&content.verification_number),
    });
}

fn process_identity(item: &mut BitwardenItem, content: &IdentityContent) {
    let (first, middle, last) = process_names(content);
    let address3 = format!("{} {}", content.floor, content.county)
        .trim()
        .to_owned();
    item.identity = Some(BitwardenIdentity {
        first_name: first,
        middle_name: middle,
        last_name: last,
        address1: nonempty(&content.organization),
        address2: nonempty(&content.street_address),
        address3: nonempty(&address3),
        city: nonempty(&content.city),
        state: nonempty(&content.state_or_province),
        postal_code: nonempty(&content.zip_or_postal_code),
        country: nonempty(&content.country_or_region),
        company: nonempty(&content.company),
        email: nonempty(&content.email),
        phone: nonempty(&content.phone_number),
        ssn: nonempty(&content.social_security_number),
        passport_number: nonempty(&content.passport_number),
        license_number: nonempty(&content.license_number),
    });
    for (name, value) in [
        ("birthdate", &content.birthdate),
        ("gender", &content.gender),
        ("website", &content.website),
        ("xHandle", &content.x_handle),
        ("secondPhoneNumber", &content.second_phone_number),
        ("linkedin", &content.linkedin),
        ("reddit", &content.reddit),
        ("facebook", &content.facebook),
        ("yahoo", &content.yahoo),
        ("instagram", &content.instagram),
        ("jobTitle", &content.job_title),
        ("personalWebsite", &content.personal_website),
        ("workPhoneNumber", &content.work_phone_number),
        ("workEmail", &content.work_email),
    ] {
        if let Some(value) = nonempty(value) {
            push_field(item, name, &value, 0);
        }
    }
    for fields in [
        &content.extra_personal_details,
        &content.extra_address_details,
        &content.extra_contact_details,
        &content.extra_work_details,
    ] {
        process_extra_fields(item, fields);
    }
    process_sections(item, &content.extra_sections);
}

fn convert_ssh_key(content: &SshKeyContent) -> Result<ConvertedSshKey, ReasonCode> {
    let private =
        Zeroizing::new(nonempty(&content.private_key).ok_or(ReasonCode::SshKeyIncomplete)?);
    let public = nonempty(&content.public_key).ok_or(ReasonCode::SshKeyIncomplete)?;
    let fingerprint = nonempty(&content.fingerprint);
    if private.len() > MAX_SSH_PRIVATE_KEY_BYTES
        || public.len() > MAX_SSH_PUBLIC_KEY_BYTES
        || fingerprint
            .as_ref()
            .is_some_and(|value| value.len() > MAX_SSH_FINGERPRINT_BYTES)
    {
        return Err(ReasonCode::SshKeyMalformed);
    }
    let private = private
        .parse::<PrivateKey>()
        .map_err(|_| ReasonCode::SshKeyMalformed)?;
    let supplied_public = public
        .parse::<PublicKey>()
        .map_err(|_| ReasonCode::SshKeyMalformed)?;
    let supplied_fingerprint = fingerprint
        .as_deref()
        .map(str::parse::<Fingerprint>)
        .transpose()
        .map_err(|_| ReasonCode::SshKeyMalformed)?;
    let encrypted = private.is_encrypted();
    let derived_public = if encrypted {
        private.public_key().clone()
    } else {
        derive_ssh_public_key(&private)?
    };
    let derived_fingerprint = derived_public.fingerprint(HashAlg::Sha256);
    if supplied_public.key_data() != derived_public.key_data()
        || supplied_fingerprint.is_some_and(|value| value != derived_fingerprint)
    {
        return Err(ReasonCode::SshKeyMismatch);
    }
    let private_key = if encrypted {
        content.private_key.clone()
    } else {
        private
            .to_openssh(LineEnding::LF)
            .map_err(|_| ReasonCode::SshKeyMalformed)?
            .to_string()
    };
    let public_key = derived_public
        .to_openssh()
        .map_err(|_| ReasonCode::SshKeyMalformed)?;
    Ok(ConvertedSshKey {
        value: BitwardenSshKey {
            private_key,
            public_key,
            key_fingerprint: derived_fingerprint.to_string(),
        },
        encrypted,
    })
}

fn derive_ssh_public_key(private: &PrivateKey) -> Result<PublicKey, ReasonCode> {
    let key_data = match private.key_data() {
        KeypairData::Ed25519(keypair) => {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(keypair.private.as_ref());
            let derived = Ed25519PublicKey(signing_key.verifying_key().to_bytes());
            if derived != keypair.public {
                return Err(ReasonCode::SshKeyMismatch);
            }
            KeyData::from(derived)
        }
        KeypairData::Rsa(keypair) => {
            validate_rsa_keypair(keypair)?;
            KeyData::from(keypair.public.clone())
        }
        _ => return Err(ReasonCode::SshKeyMalformed),
    };
    Ok(PublicKey::new(key_data, private.comment()))
}

fn validate_rsa_keypair(keypair: &RsaKeypair) -> Result<(), ReasonCode> {
    let one = BigUint::from(1_u8);
    let n = positive_biguint(&keypair.public.n)?;
    let e = positive_biguint(&keypair.public.e)?;
    let d = positive_biguint(&keypair.private.d)?;
    let iqmp = positive_biguint(&keypair.private.iqmp)?;
    let p = positive_biguint(&keypair.private.p)?;
    let q = positive_biguint(&keypair.private.q)?;
    if *p <= one || *q <= one || *e <= one || *d <= one || *iqmp >= *p {
        return Err(ReasonCode::SshKeyMalformed);
    }
    if !num_bigint_dig::prime::probably_prime(&p, 64)
        || !num_bigint_dig::prime::probably_prime(&q, 64)
    {
        return Err(ReasonCode::SshKeyMalformed);
    }

    let modulus = Zeroizing::new(&*p * &*q);
    if *modulus != *n {
        return Err(ReasonCode::SshKeyMismatch);
    }

    let p_minus_one = Zeroizing::new(&*p - &one);
    let q_minus_one = Zeroizing::new(&*q - &one);
    let gcd = gcd_zeroizing(&p_minus_one, &q_minus_one);
    let quotient = Zeroizing::new(&*p_minus_one / &*gcd);
    let lambda = Zeroizing::new(&*quotient * &*q_minus_one);
    let de = Zeroizing::new(&*d * &*e);
    let de_mod_lambda = Zeroizing::new(&*de % &*lambda);
    if *de_mod_lambda != one {
        return Err(ReasonCode::SshKeyMismatch);
    }

    let iqmp_q = Zeroizing::new(&*iqmp * &*q);
    let iqmp_q_mod_p = Zeroizing::new(&*iqmp_q % &*p);
    if *iqmp_q_mod_p != one {
        return Err(ReasonCode::SshKeyMismatch);
    }
    Ok(())
}

fn positive_biguint(value: &Mpint) -> Result<Zeroizing<BigUint>, ReasonCode> {
    let bytes = value
        .as_positive_bytes()
        .filter(|bytes| !bytes.is_empty() && bytes.len() <= MAX_RSA_COMPONENT_BYTES)
        .ok_or(ReasonCode::SshKeyMalformed)?;
    Ok(Zeroizing::new(BigUint::from_bytes_be(bytes)))
}

fn gcd_zeroizing(left: &BigUint, right: &BigUint) -> Zeroizing<BigUint> {
    let mut left = Zeroizing::new(left.clone());
    let mut right = Zeroizing::new(right.clone());
    let zero = BigUint::from(0_u8);
    while *right != zero {
        let remainder = Zeroizing::new(&*left % &*right);
        left = right;
        right = remainder;
    }
    left
}

fn process_wifi(item: &mut BitwardenItem, content: &WifiContent) {
    if let Some(ssid) = nonempty(&content.ssid) {
        push_field(item, "SSID", &ssid, 0);
    }
    if let Some(password) = nonempty(&content.password) {
        push_field(item, "Password", &password, 1);
    }
    let security = match content.security {
        1 => "WPA",
        2 => "WPA2",
        3 => "WPA3",
        4 => "WEP",
        _ => "Unspecified",
    };
    push_field(item, "Security", security, 0);
    process_sections(item, &content.sections);
}

fn process_names(content: &IdentityContent) -> (Option<String>, Option<String>, Option<String>) {
    let mut first = nonempty(&content.first_name);
    let mut middle = nonempty(&content.middle_name);
    let mut last = nonempty(&content.last_name);
    let parts: Vec<_> = content.full_name.split_whitespace().collect();
    if !parts.is_empty() {
        first = Some(parts[0].to_owned());
        if parts.len() > 1 {
            last = Some(parts[parts.len() - 1].to_owned());
        }
        if parts.len() > 2 {
            middle = Some(parts[1..parts.len() - 1].join(" "));
        }
    }
    (first, middle, last)
}

fn process_sections(item: &mut BitwardenItem, sections: &[ProtonSection]) {
    let mut names = SectionFieldNames::new(item);
    for section in sections {
        if section.section_name.trim().is_empty() {
            for field in &section.section_fields {
                if extra_field_has_value(field) {
                    process_extra_field(item, field, &field.field_name);
                    names.record(&field.field_name);
                }
            }
            continue;
        }
        for field in &section.section_fields {
            if extra_field_has_value(field) {
                let name = Zeroizing::new(names.unique(&section.section_name, &field.field_name));
                process_extra_field(item, field, &name);
            }
        }
    }
}

fn process_extra_fields(item: &mut BitwardenItem, fields: &[ProtonExtraField]) {
    for field in fields {
        process_extra_field(item, field, &field.field_name);
    }
}

fn process_extra_field(item: &mut BitwardenItem, field: &ProtonExtraField, name: &str) -> bool {
    let (value, field_type) = match field.field_type.as_str() {
        "hidden" => (&field.data.content, 1),
        "totp" => (&field.data.totp_uri, 1),
        "timestamp" => (&field.data.timestamp, 0),
        _ => (&field.data.content, 0),
    };
    if let Some(value) = nonempty(value) {
        push_field(item, name, &value, field_type);
        true
    } else {
        false
    }
}

fn extra_field_has_value(field: &ProtonExtraField) -> bool {
    let value = match field.field_type.as_str() {
        "totp" => &field.data.totp_uri,
        "timestamp" => &field.data.timestamp,
        _ => &field.data.content,
    };
    !value.trim().is_empty()
}

struct SectionFieldNames {
    used: BTreeSet<String>,
    next_suffix: BTreeMap<String, usize>,
}

impl SectionFieldNames {
    fn new(item: &BitwardenItem) -> Self {
        Self {
            used: item.fields.iter().map(|field| field.name.clone()).collect(),
            next_suffix: BTreeMap::new(),
        }
    }

    fn record(&mut self, name: &str) {
        self.used.insert(name.to_owned());
    }

    fn unique(&mut self, section: &str, field: &str) -> String {
        let base = Zeroizing::new(format!("{section} / {field}"));
        if self.used.insert(base.to_string()) {
            return base.to_string();
        }
        let suffix = self.next_suffix.entry(base.to_string()).or_insert(2);
        loop {
            let candidate = Zeroizing::new(format!("{} [{suffix}]", base.as_str()));
            *suffix += 1;
            if self.used.insert(candidate.to_string()) {
                return candidate.to_string();
            }
        }
    }
}

impl Drop for SectionFieldNames {
    fn drop(&mut self) {
        while let Some(mut name) = self.used.pop_first() {
            name.zeroize();
        }
        while let Some((mut name, _)) = self.next_suffix.pop_first() {
            name.zeroize();
        }
    }
}

fn push_field(item: &mut BitwardenItem, name: &str, value: &str, field_type: u8) {
    if value.len() > 200 || value.contains(['\n', '\r']) {
        let notes = item.notes.get_or_insert_default();
        notes.push_str(name);
        notes.push_str(": ");
        notes.push_str(&value.replace("\r\n", "\n").replace('\r', "\n"));
        notes.push('\n');
    } else {
        item.fields.push(BitwardenField {
            name: name.to_owned(),
            value: value.to_owned(),
            field_type,
        });
    }
}

fn create_folders(
    vault_id: &str,
    original_name: &str,
    folders: &mut BTreeMap<String, BitwardenFolder>,
) -> Option<String> {
    let name = original_name.replace('\\', "/");
    let name = name.trim_start_matches('/').trim();
    if name.is_empty() {
        return None;
    }
    let mut folder_name = String::new();
    for part in name.split('/') {
        if !folder_name.is_empty() {
            folder_name.push('/');
        }
        folder_name.push_str(part);
        folders
            .entry(folder_name.clone())
            .or_insert_with(|| BitwardenFolder {
                id: Uuid::new_v5(
                    &FOLDER_NAMESPACE,
                    format!("{vault_id}\0{folder_name}").as_bytes(),
                )
                .to_string(),
                name: folder_name.clone(),
            });
    }
    folders.get(name).map(|folder| folder.id.clone())
}

fn map_autofill_mode(value: &AutofillUrl) -> (Option<u8>, bool) {
    match value.mode {
        0 => (None, false),
        1 | 6 => (Some(3), false),
        2 => (Some(5), false),
        3 => (Some(2), false),
        5 => (Some(4), false),
        _ => (Some(5), true),
    }
}

fn uri(value: &str, match_type: Option<u8>) -> Option<BitwardenUri> {
    let mut value = value.trim().to_owned();
    if value.is_empty() {
        return None;
    }
    if !value.contains("://") && value.contains('.') && match_type != Some(4) {
        value = format!("http://{value}");
    }
    Some(BitwardenUri {
        uri: value,
        r#match: match_type,
    })
}

fn timestamp(epoch: i64) -> (Option<String>, bool) {
    if epoch <= 0 {
        return (None, true);
    }
    match OffsetDateTime::from_unix_timestamp(epoch)
        .ok()
        .and_then(|date| date.format(&Iso8601::DEFAULT).ok())
    {
        Some(value) => (Some(value), false),
        None => (None, true),
    }
}

fn card_brand(number: &str) -> Option<&'static str> {
    let bytes = number.as_bytes();
    let decimal = bytes.iter().all(u8::is_ascii_digit);
    let prefix = |length: usize| {
        bytes
            .get(..length)
            .filter(|value| value.iter().all(u8::is_ascii_digit))
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.parse::<u32>().ok())
    };

    if bytes.first() == Some(&b'4') {
        Some("Visa")
    } else if decimal
        && bytes.len() == 16
        && (prefix(2).is_some_and(|value| (51..=55).contains(&value))
            || prefix(4).is_some_and(|value| (2221..=2720).contains(&value)))
    {
        Some("Mastercard")
    } else if bytes
        .get(..2)
        .is_some_and(|value| matches!(value, b"34" | b"37"))
    {
        Some("Amex")
    } else if number.starts_with("6011")
        || number.starts_with("65")
        || prefix(6).is_some_and(|value| (622_126..=622_925).contains(&value))
        || prefix(3).is_some_and(|value| (644..=649).contains(&value))
    {
        Some("Discover")
    } else if number.starts_with("36")
        || prefix(3).is_some_and(|value| (300..=305).contains(&value))
    {
        Some("Diners Club")
    } else if prefix(4).is_some_and(|value| (3528..=3589).contains(&value)) {
        Some("JCB")
    } else {
        None
    }
}

fn has_unsupported_extra_fields(item: &ProtonItem) -> bool {
    let supported = |field: &ProtonExtraField| {
        matches!(
            field.field_type.as_str(),
            "text" | "hidden" | "totp" | "timestamp"
        )
    };
    let unsupported_fields =
        |fields: &[ProtonExtraField]| fields.iter().any(|field| !supported(field));
    let unsupported_sections = |sections: &[ProtonSection]| {
        sections
            .iter()
            .any(|section| unsupported_fields(&section.section_fields))
    };

    unsupported_fields(&item.data.extra_fields)
        || match &item.data.kind {
            ProtonItemKind::Identity(content) => {
                unsupported_fields(&content.extra_personal_details)
                    || unsupported_fields(&content.extra_address_details)
                    || unsupported_fields(&content.extra_contact_details)
                    || unsupported_fields(&content.extra_work_details)
                    || unsupported_sections(&content.extra_sections)
            }
            ProtonItemKind::SshKey(content) => unsupported_sections(&content.sections),
            ProtonItemKind::Wifi(content) => unsupported_sections(&content.sections),
            ProtonItemKind::Custom(content) => unsupported_sections(&content.sections),
            _ => false,
        }
}

fn has_platform_metadata(item: &ProtonItem) -> bool {
    item.data
        .platform_specific
        .as_ref()
        .and_then(|platform| platform.android.as_ref())
        .is_some_and(|android| !android.allowed_apps.is_empty())
}

fn stable_item_id(vault_id: &str, item: &ProtonItem) -> String {
    stable_id(
        b"proton-item-v1",
        &[
            vault_id.as_bytes(),
            item.item_id.as_bytes(),
            item.data.metadata.item_uuid.as_bytes(),
        ],
    )
}

fn item_uuid(vault_id: &str, item_id: &str, suffix: &[u8]) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(vault_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(item_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(suffix);
    Uuid::new_v5(&FOLDER_NAMESPACE, &bytes).to_string()
}

fn display_name(value: &str) -> String {
    nonempty(value).unwrap_or_else(|| "--".into())
}

fn nonempty(value: &str) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.to_owned())
}

fn map_passkey_failure(failure: PasskeyFailure) -> (OutcomeCode, ReasonCode) {
    match failure {
        PasskeyFailure::UnsupportedVersion => (
            OutcomeCode::UnsupportedPasskeyVersion,
            ReasonCode::UnknownPasskeyVersion,
        ),
        PasskeyFailure::UnsupportedAlgorithm => (
            OutcomeCode::UnsupportedKeyAlgorithm,
            ReasonCode::KeyAlgorithmNotEs256,
        ),
        PasskeyFailure::UnsupportedCurve => (
            OutcomeCode::UnsupportedKeyCurve,
            ReasonCode::KeyCurveNotP256,
        ),
        PasskeyFailure::PrfExtension => (
            OutcomeCode::UnsupportedPrfExtension,
            ReasonCode::PrfDataCannotBePreserved,
        ),
        PasskeyFailure::MetadataMismatch => (
            OutcomeCode::MetadataMismatch,
            ReasonCode::DuplicatedMetadataMismatch,
        ),
        PasskeyFailure::UnsupportedKeyType => (
            OutcomeCode::UnsupportedKeyAlgorithm,
            ReasonCode::KeyTypeNotEc2,
        ),
        PasskeyFailure::UnsupportedKeyMetadata => (
            OutcomeCode::InvalidKeyMaterial,
            ReasonCode::KeyRestrictionsUnsupported,
        ),
        PasskeyFailure::MissingUserHandle => (
            OutcomeCode::MetadataMismatch,
            ReasonCode::DiscoverableUserHandleMissing,
        ),
        PasskeyFailure::InvalidTimestamp => (
            OutcomeCode::MetadataMismatch,
            ReasonCode::PasskeyTimeInvalid,
        ),
        PasskeyFailure::ResourceLimit => (
            OutcomeCode::InvalidKeyMaterial,
            ReasonCode::PasskeyResourceLimit,
        ),
        PasskeyFailure::InvalidBase64
        | PasskeyFailure::MalformedOrUnknownField
        | PasskeyFailure::TrailingMessagePack => (
            OutcomeCode::InvalidKeyMaterial,
            ReasonCode::MalformedPasskeyEncoding,
        ),
        PasskeyFailure::PublicKeyMismatch => (
            OutcomeCode::InvalidKeyMaterial,
            ReasonCode::PublicPrivateKeyMismatch,
        ),
        _ => (
            OutcomeCode::InvalidKeyMaterial,
            ReasonCode::KeyMaterialInvalid,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::proton_export::{EmptyContent, ProtonItemData, ProtonMetadata, ProtonVault};

    fn item(kind: ProtonItemKind, name: &str) -> ProtonItem {
        ProtonItem {
            item_id: name.into(),
            share_id: "vault".into(),
            data: ProtonItemData {
                metadata: ProtonMetadata {
                    name: name.into(),
                    ..ProtonMetadata::default()
                },
                extra_fields: Vec::new(),
                platform_specific: None,
                kind,
            },
            state: 1,
            alias_email: None,
            content_format_version: 6,
            create_time: 1_700_000_000,
            modify_time: 1_700_000_001,
            pinned: false,
            files: Vec::new(),
        }
    }

    #[test]
    fn zeroizes_converted_item_secrets() {
        let export = ProtonExport {
            version: "test".into(),
            user_id: None,
            encrypted: None,
            vaults: BTreeMap::from([(
                "v".into(),
                ProtonVault {
                    name: "Folder".into(),
                    description: String::new(),
                    items: vec![item(
                        ProtonItemKind::Login(LoginContent {
                            password: "synthetic-password".into(),
                            totp_uri: "otpauth://synthetic".into(),
                            ..LoginContent::default()
                        }),
                        "login",
                    )],
                },
            )]),
        };
        let mut result = convert_export(&export, true);
        let item = &mut result.export.items[0];

        item.zeroize();

        assert!(item.id.is_empty());
        assert!(item.name.is_empty());
        assert!(item.login.is_none());
        assert!(item.fields.is_empty());
    }

    #[test]
    fn maps_notes_and_trashed_items_with_explicit_outcomes() {
        let mut trashed = item(ProtonItemKind::Note(EmptyContent {}), "trash");
        trashed.state = 2;
        let export = ProtonExport {
            version: "test".into(),
            user_id: None,
            encrypted: None,
            vaults: BTreeMap::from([(
                "v".into(),
                ProtonVault {
                    name: "Folder".into(),
                    description: String::new(),
                    items: vec![item(ProtonItemKind::Note(EmptyContent {}), "note"), trashed],
                },
            )]),
        };
        let result = convert_export(&export, true);
        assert_eq!(result.export.items.len(), 1);
        assert_eq!(result.export.items[0].item_type, 2);
        assert_eq!(result.report.summary.items_total, 2);
        assert_eq!(result.report.summary.items_skipped, 1);
    }

    #[test]
    fn maps_wifi_without_losing_password() {
        let export = ProtonExport {
            version: "test".into(),
            user_id: None,
            encrypted: None,
            vaults: BTreeMap::from([(
                "v".into(),
                ProtonVault {
                    name: "Folder".into(),
                    description: String::new(),
                    items: vec![item(
                        ProtonItemKind::Wifi(WifiContent {
                            ssid: "network".into(),
                            password: "synthetic-password".into(),
                            security: 3,
                            sections: Vec::new(),
                        }),
                        "wifi",
                    )],
                },
            )]),
        };
        let result = convert_export(&export, true);
        assert_eq!(result.export.items[0].item_type, 2);
        assert!(result.export.items[0].fields.iter().any(|field| {
            field.name == "Password" && field.value == "synthetic-password" && field.field_type == 1
        }));
    }

    #[test]
    fn report_never_contains_vault_secrets() {
        let login = LoginContent {
            password: "SYNTHETIC_PASSWORD_SENTINEL".into(),
            totp_uri: "SYNTHETIC_TOTP_SENTINEL".into(),
            ..LoginContent::default()
        };
        let export = ProtonExport {
            version: "test".into(),
            user_id: None,
            encrypted: None,
            vaults: BTreeMap::from([(
                "v".into(),
                ProtonVault {
                    name: "Folder".into(),
                    description: String::new(),
                    items: vec![item(
                        ProtonItemKind::Login(login),
                        "SYNTHETIC_NAME_SENTINEL",
                    )],
                },
            )]),
        };
        let result = convert_export(&export, true);
        let report = serde_json::to_string(&result.report).unwrap();
        assert!(!report.contains("SYNTHETIC_PASSWORD_SENTINEL"));
        assert!(!report.contains("SYNTHETIC_TOTP_SENTINEL"));
        assert!(!report.contains("SYNTHETIC_NAME_SENTINEL"));
    }

    #[test]
    fn folder_ids_are_deterministic() {
        let mut folders = BTreeMap::new();
        let first = create_folders("v", "a/b", &mut folders).unwrap();
        let mut again = BTreeMap::new();
        let second = create_folders("v", "a/b", &mut again).unwrap();
        assert_eq!(first, second);
        assert_eq!(folders.len(), 2);
    }

    #[test]
    fn identity_full_name_matches_upstream_split_policy() {
        let content = IdentityContent {
            full_name: "First Middle Last".into(),
            ..IdentityContent::default()
        };
        assert_eq!(
            process_names(&content),
            (
                Some("First".into()),
                Some("Middle".into()),
                Some("Last".into())
            )
        );
    }

    #[test]
    fn mapping_declares_supported_item_types() {
        let labels: BTreeSet<_> = [
            ProtonItemKind::Note(EmptyContent {}),
            ProtonItemKind::Alias(EmptyContent {}),
            ProtonItemKind::Unknown,
        ]
        .iter()
        .map(ProtonItemKind::label)
        .collect();
        assert_eq!(labels, BTreeSet::from(["alias", "note", "unknown"]));
    }

    #[test]
    fn validates_rsa_private_components_against_the_public_key() {
        use ssh_key::{private::RsaPrivateKey, public::RsaPublicKey};

        let mpint = |value: u32| Mpint::from_positive_bytes(&value.to_be_bytes()).unwrap();
        let keypair = |n, d, iqmp, p, q| RsaKeypair {
            public: RsaPublicKey {
                n: mpint(n),
                e: mpint(17),
            },
            private: RsaPrivateKey {
                d: mpint(d),
                iqmp: mpint(iqmp),
                p: mpint(p),
                q: mpint(q),
            },
        };

        assert!(validate_rsa_keypair(&keypair(3233, 413, 38, 61, 53)).is_ok());
        assert_eq!(
            validate_rsa_keypair(&keypair(3234, 413, 38, 61, 53)),
            Err(ReasonCode::SshKeyMismatch)
        );
        assert_eq!(
            validate_rsa_keypair(&keypair(3233, 414, 38, 61, 53)),
            Err(ReasonCode::SshKeyMismatch)
        );
        assert_eq!(
            validate_rsa_keypair(&keypair(3233, 413, 39, 61, 53)),
            Err(ReasonCode::SshKeyMismatch)
        );
        assert_eq!(
            validate_rsa_keypair(&keypair(4081, 465, 16, 77, 53)),
            Err(ReasonCode::SshKeyMalformed)
        );

        let oversized = Mpint::from_positive_bytes(&vec![1; MAX_RSA_COMPONENT_BYTES + 1]);
        assert!(oversized.is_ok());
        assert_eq!(
            positive_biguint(&oversized.unwrap()),
            Err(ReasonCode::SshKeyMalformed)
        );
    }

    #[test]
    fn rejects_oversized_ssh_text_before_parsing() {
        let mut converted = item(
            ProtonItemKind::SshKey(SshKeyContent {
                private_key: "x".repeat(MAX_SSH_PRIVATE_KEY_BYTES + 1),
                public_key: "ssh-ed25519 synthetic".into(),
                fingerprint: String::new(),
                sections: Vec::new(),
            }),
            "oversized ssh",
        );
        converted.files.clear();
        let export = ProtonExport {
            version: "test".into(),
            user_id: None,
            encrypted: None,
            vaults: BTreeMap::from([(
                "v".into(),
                ProtonVault {
                    name: "Folder".into(),
                    description: String::new(),
                    items: vec![converted],
                },
            )]),
        };
        let result = convert_export(&export, true);
        assert!(result.export.items.is_empty());
        assert!(result.report.outcomes.iter().any(|entry| {
            entry.entity == EntityKind::Item && entry.reason == ReasonCode::SshKeyMalformed
        }));
    }

    #[test]
    fn unsupported_autofill_modes_are_mapped_to_never() {
        let content = LoginContent {
            autofill_urls: vec![
                AutofillUrl {
                    url: "https://pattern.example".into(),
                    mode: 4,
                },
                AutofillUrl {
                    url: "https://future.example".into(),
                    mode: 99,
                },
            ],
            ..LoginContent::default()
        };
        let (login, unsupported) = build_login(&content);
        assert!(unsupported);
        assert!(login.uris.iter().all(|value| value.r#match == Some(5)));
    }

    #[test]
    fn recognizes_the_card_ranges_supported_by_bitwarden() {
        for (number, brand) in [
            ("4111111111111111", "Visa"),
            ("2221000000000000", "Mastercard"),
            ("2720000000000000", "Mastercard"),
            ("378282246310005", "Amex"),
            ("6221260000000000", "Discover"),
            ("6490000000000000", "Discover"),
            ("30500000000000", "Diners Club"),
            ("36000000000000", "Diners Club"),
            ("3528000000000000", "JCB"),
        ] {
            assert_eq!(card_brand(number), Some(brand));
        }
    }

    #[test]
    fn incomplete_ssh_keys_have_a_specific_report_reason() {
        let export = ProtonExport {
            version: "test".into(),
            user_id: None,
            encrypted: None,
            vaults: BTreeMap::from([(
                "v".into(),
                ProtonVault {
                    name: "Folder".into(),
                    description: String::new(),
                    items: vec![item(
                        ProtonItemKind::SshKey(SshKeyContent::default()),
                        "ssh",
                    )],
                },
            )]),
        };
        let result = convert_export(&export, true);
        assert_eq!(result.export.items.len(), 0);
        assert_eq!(
            result.report.outcomes[0].reason,
            ReasonCode::SshKeyIncomplete
        );
    }
}
