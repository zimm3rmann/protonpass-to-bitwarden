use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Item,
    Passkey,
    Attachment,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationMode {
    FullVault,
    PasskeysOnly,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeCode {
    Converted,
    ConvertedWithFallback,
    SplitAdditionalPasskey,
    SkippedTrashed,
    SkippedAttachment,
    FilteredPasskeysOnly,
    UnsupportedItemType,
    UnsupportedPasskeyVersion,
    UnsupportedKeyAlgorithm,
    UnsupportedKeyCurve,
    UnsupportedPrfExtension,
    UnsupportedDuplicatePasskey,
    InvalidKeyMaterial,
    MetadataMismatch,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    None,
    ItemTimeInvalid,
    PasskeyTimeFallback,
    OneOrMorePasskeysNotMigrated,
    AdditionalPasskeySplit,
    AttachmentsRequireManualMigration,
    PasskeysOnlyMode,
    PasskeyNoteOmitted,
    UnsupportedType,
    UnsupportedAutofillMode,
    UnsupportedPlatformMetadata,
    UnsupportedExtraField,
    WifiMappedToSecureNote,
    SshKeyIncomplete,
    SshKeyMalformed,
    SshKeyMismatch,
    EncryptedSshKeyNotFullyVerified,
    UnknownPasskeyVersion,
    MalformedPasskeyEncoding,
    PasskeyResourceLimit,
    PasskeyTimeInvalid,
    DiscoverableUserHandleMissing,
    KeyTypeNotEc2,
    KeyAlgorithmNotEs256,
    KeyCurveNotP256,
    KeyRestrictionsUnsupported,
    PrfDataCannotBePreserved,
    KeyMaterialInvalid,
    PublicPrivateKeyMismatch,
    DuplicatedMetadataMismatch,
    ExactDuplicatePasskey,
    ConflictingDuplicatePasskey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReportEntry {
    pub entity: EntityKind,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub item_type: String,
    pub outcome: OutcomeCode,
    pub reason: ReasonCode,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_reasons: Vec<ReasonCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Drop for ReportEntry {
    fn drop(&mut self) {
        self.id.zeroize();
        self.parent_id.zeroize();
        self.item_type.zeroize();
        self.name.zeroize();
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ReportSummary {
    pub items_total: usize,
    pub items_converted: usize,
    pub items_skipped: usize,
    pub items_filtered: usize,
    pub passkeys_total: usize,
    pub passkeys_converted: usize,
    pub passkeys_skipped: usize,
    pub passkeys_unsupported: usize,
    pub additional_logins_created: usize,
    pub attachment_sets_skipped: usize,
    pub folders_created: usize,
    pub output_items_created: usize,
    pub strict_failures: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MigrationReport {
    pub format_version: u8,
    pub source_format: &'static str,
    pub destination_format: &'static str,
    pub mode: MigrationMode,
    pub names_redacted: bool,
    pub summary: ReportSummary,
    pub outcomes: Vec<ReportEntry>,
}

impl MigrationReport {
    pub fn new(names_redacted: bool) -> Self {
        Self::new_with_mode(names_redacted, MigrationMode::FullVault)
    }

    pub fn new_with_mode(names_redacted: bool, mode: MigrationMode) -> Self {
        Self {
            format_version: 2,
            source_format: "proton_pass",
            destination_format: "bitwarden_json",
            mode,
            names_redacted,
            summary: ReportSummary::default(),
            outcomes: Vec::new(),
        }
    }

    pub fn push(&mut self, entry: ReportEntry) {
        self.outcomes.push(entry);
    }

    pub fn finalize(&mut self) {
        self.outcomes.sort_by(|a, b| {
            (&a.id, a.entity, &a.parent_id, a.outcome).cmp(&(
                &b.id,
                b.entity,
                &b.parent_id,
                b.outcome,
            ))
        });

        let mut summary = ReportSummary::default();
        for entry in &self.outcomes {
            match entry.entity {
                EntityKind::Item => {
                    summary.items_total += 1;
                    match entry.outcome {
                        OutcomeCode::Converted | OutcomeCode::ConvertedWithFallback => {
                            summary.items_converted += 1;
                        }
                        OutcomeCode::SkippedTrashed | OutcomeCode::UnsupportedItemType => {
                            summary.items_skipped += 1;
                        }
                        OutcomeCode::FilteredPasskeysOnly => summary.items_filtered += 1,
                        _ => {}
                    }
                }
                EntityKind::Passkey => {
                    summary.passkeys_total += 1;
                    match entry.outcome {
                        OutcomeCode::Converted | OutcomeCode::ConvertedWithFallback => {
                            summary.passkeys_converted += 1;
                        }
                        OutcomeCode::SplitAdditionalPasskey => {
                            summary.passkeys_converted += 1;
                            summary.additional_logins_created += 1;
                        }
                        OutcomeCode::SkippedTrashed => summary.passkeys_skipped += 1,
                        _ => summary.passkeys_unsupported += 1,
                    }
                }
                EntityKind::Attachment => summary.attachment_sets_skipped += 1,
            }

            if is_strict_failure(entry) {
                summary.strict_failures += 1;
            }
        }
        self.summary = summary;
    }
}

fn is_strict_failure(entry: &ReportEntry) -> bool {
    match entry.entity {
        EntityKind::Item => matches!(
            entry.outcome,
            OutcomeCode::UnsupportedItemType | OutcomeCode::ConvertedWithFallback
        ),
        EntityKind::Passkey => {
            if entry.outcome == OutcomeCode::SkippedTrashed {
                false
            } else if entry.reason == ReasonCode::UnsupportedPlatformMetadata
                || entry
                    .additional_reasons
                    .contains(&ReasonCode::UnsupportedPlatformMetadata)
            {
                true
            } else {
                !matches!(
                    entry.outcome,
                    OutcomeCode::Converted
                        | OutcomeCode::ConvertedWithFallback
                        | OutcomeCode::SplitAdditionalPasskey
                )
            }
        }
        EntityKind::Attachment => entry.outcome != OutcomeCode::SkippedTrashed,
    }
}

pub fn stable_id(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    let digest = hash.finalize();
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn summary_by_outcome(report: &MigrationReport) -> BTreeMap<OutcomeCode, usize> {
    let mut counts = BTreeMap::new();
    for entry in &report.outcomes {
        *counts.entry(entry.outcome).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_ids_are_domain_separated_and_repeatable() {
        let first = stable_id(b"item", &[b"vault", b"record"]);
        assert_eq!(first, stable_id(b"item", &[b"vault", b"record"]));
        assert_ne!(first, stable_id(b"passkey", &[b"vault", b"record"]));
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn finalization_counts_entities() {
        let mut report = MigrationReport::new(true);
        report.push(ReportEntry {
            entity: EntityKind::Item,
            id: "a".into(),
            parent_id: None,
            item_type: "login".into(),
            outcome: OutcomeCode::Converted,
            reason: ReasonCode::None,
            additional_reasons: Vec::new(),
            name: None,
        });
        report.push(ReportEntry {
            entity: EntityKind::Passkey,
            id: "b".into(),
            parent_id: Some("a".into()),
            item_type: "login".into(),
            outcome: OutcomeCode::UnsupportedPrfExtension,
            reason: ReasonCode::PrfDataCannotBePreserved,
            additional_reasons: Vec::new(),
            name: None,
        });
        report.finalize();
        assert_eq!(report.summary.items_converted, 1);
        assert_eq!(report.summary.passkeys_unsupported, 1);
        assert_eq!(report.summary.strict_failures, 1);
    }
}
