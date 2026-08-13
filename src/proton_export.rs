use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path};

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use zip::CompressionMethod;
use zip::ZipArchive;

use crate::error::AppError;
use crate::proton_passkey::{ProtonPasskeyCreationData, ProtonPasskeyInput};

#[derive(Clone, Copy)]
pub struct InputLimits {
    pub max_archive_bytes: u64,
    pub max_json_bytes: u64,
    pub max_entries: usize,
    pub max_central_directory_bytes: u64,
    pub max_entry_name_bytes: usize,
    pub max_zip_metadata_bytes: u64,
    pub max_vaults: usize,
    pub max_items: usize,
    pub max_passkeys_per_item: usize,
    pub max_nested_elements: usize,
    pub max_vault_id_bytes: usize,
    pub max_item_id_bytes: usize,
    pub max_share_id_bytes: usize,
    pub max_item_uuid_bytes: usize,
    pub max_vault_name_bytes: usize,
    pub max_section_name_bytes: usize,
    pub max_folder_depth: usize,
    pub max_folder_component_bytes: usize,
    pub max_projected_output_bytes: u64,
}

impl Default for InputLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 2 * 1024 * 1024 * 1024,
            max_json_bytes: 64 * 1024 * 1024,
            max_entries: 100_000,
            max_central_directory_bytes: 256 * 1024 * 1024,
            max_entry_name_bytes: 4 * 1024,
            max_zip_metadata_bytes: 128 * 1024 * 1024,
            max_vaults: 10_000,
            max_items: 500_000,
            max_passkeys_per_item: 100,
            max_nested_elements: 1_000_000,
            max_vault_id_bytes: 1024,
            max_item_id_bytes: 1024,
            max_share_id_bytes: 1024,
            max_item_uuid_bytes: 1024,
            max_vault_name_bytes: 4 * 1024,
            max_section_name_bytes: 4 * 1024,
            max_folder_depth: 64,
            max_folder_component_bytes: 255,
            max_projected_output_bytes: 512 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum InputSource {
    RawJson,
    Zip,
}

impl InputSource {
    pub const fn label(self) -> &'static str {
        match self {
            Self::RawJson => "raw_json",
            Self::Zip => "zip",
        }
    }
}

pub struct LoadedExport {
    pub export: ProtonExport,
    pub source: InputSource,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtonExport {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub encrypted: Option<bool>,
    pub vaults: BTreeMap<String, ProtonVault>,
}

impl Zeroize for ProtonExport {
    fn zeroize(&mut self) {
        self.version.zeroize();
        self.user_id.zeroize();
        self.encrypted.zeroize();
        while let Some((mut vault_id, mut vault)) = self.vaults.pop_first() {
            vault_id.zeroize();
            vault.zeroize();
        }
    }
}

impl Drop for ProtonExport {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ProtonExport {}

impl<'de> Deserialize<'de> for ProtonExport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Version,
            UserId,
            Encrypted,
            Vaults,
            Unknown,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl Visitor<'_> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a Proton export field")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        Ok(match value {
                            "version" => Field::Version,
                            "userId" => Field::UserId,
                            "encrypted" => Field::Encrypted,
                            "vaults" => Field::Vaults,
                            _ => Field::Unknown,
                        })
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ExportVisitor;

        impl<'de> Visitor<'de> for ExportVisitor {
            type Value = ProtonExport;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Proton export")
            }

            fn visit_map<A>(self, mut map: A) -> Result<ProtonExport, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut version = None;
                let mut user_id = None;
                let mut encrypted = None;
                let mut vaults = None;
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Version => set_once(&mut version, map.next_value()?, "version")?,
                        Field::UserId => set_once(&mut user_id, map.next_value()?, "userId")?,
                        Field::Encrypted => {
                            set_once(&mut encrypted, map.next_value()?, "encrypted")?
                        }
                        Field::Vaults => set_once(
                            &mut vaults,
                            map.next_value_seed(UniqueMapSeed::<ProtonVault>::new())?,
                            "vaults",
                        )?,
                        Field::Unknown => {
                            map.next_value::<IgnoredAny>()?;
                            return Err(de::Error::custom("unknown Proton export field"));
                        }
                    }
                }
                Ok(ProtonExport {
                    version: version.unwrap_or_default(),
                    user_id: user_id.unwrap_or_default(),
                    encrypted: encrypted.unwrap_or_default(),
                    vaults: vaults.ok_or_else(|| de::Error::missing_field("vaults"))?,
                })
            }
        }

        deserializer.deserialize_map(ExportVisitor)
    }
}

fn set_once<T, E>(slot: &mut Option<T>, value: T, field: &'static str) -> Result<(), E>
where
    E: de::Error,
{
    if slot.replace(value).is_some() {
        Err(E::duplicate_field(field))
    } else {
        Ok(())
    }
}

const HARD_MAX_ITEMS: usize = 500_000;
const HARD_MAX_NESTED_ELEMENTS: usize = 100_000;
const HARD_MAX_PASSKEYS_PER_ITEM: usize = 100;

fn deserialize_bounded_vec<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const MAX: usize>(std::marker::PhantomData<T>);

    impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVecVisitor<T, MAX>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "an array with at most {MAX} elements")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Vec<T>, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(MAX);
            let mut values = Vec::with_capacity(capacity);
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX {
                    return Err(de::Error::custom("array exceeds safety limit"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>(std::marker::PhantomData))
}

fn deserialize_items<'de, D>(deserializer: D) -> Result<Vec<ProtonItem>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, HARD_MAX_ITEMS>(deserializer)
}

fn deserialize_nested_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserialize_bounded_vec::<_, _, HARD_MAX_NESTED_ELEMENTS>(deserializer)
}

fn deserialize_passkeys<'de, D>(deserializer: D) -> Result<Vec<ProtonPasskeyInput>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, HARD_MAX_PASSKEYS_PER_ITEM>(deserializer)
}

struct UniqueMapSeed<T>(std::marker::PhantomData<T>);

impl<T> UniqueMapSeed<T> {
    const fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<'de, T> DeserializeSeed<'de> for UniqueMapSeed<T>
where
    T: Deserialize<'de>,
{
    type Value = BTreeMap<String, T>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueMapVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T> Visitor<'de> for UniqueMapVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = BTreeMap<String, T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map with unique keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate map key"));
                    }
                    if values.len() == 10_000 {
                        return Err(de::Error::custom("map exceeds safety limit"));
                    }
                    let value = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(values)
            }
        }

        deserializer.deserialize_map(UniqueMapVisitor(std::marker::PhantomData))
    }
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct ProtonVault {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub items: Vec<ProtonItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtonVaultInput {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default, deserialize_with = "deserialize_items")]
    items: Vec<ProtonItem>,
    #[serde(rename = "display", default)]
    _display: Option<ProtonVaultDisplay>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtonVaultDisplay {
    #[serde(rename = "icon", default)]
    _icon: Option<i32>,
    #[serde(rename = "color", default)]
    _color: Option<i32>,
}

impl<'de> Deserialize<'de> for ProtonVault {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = ProtonVaultInput::deserialize(deserializer)?;
        Ok(Self {
            name: input.name,
            description: input.description,
            items: input.items,
        })
    }
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct ProtonItem {
    #[serde(default)]
    pub item_id: String,
    #[serde(default)]
    pub share_id: String,
    pub data: ProtonItemData,
    #[serde(default)]
    pub state: u8,
    #[serde(default)]
    pub alias_email: Option<String>,
    #[serde(default)]
    pub content_format_version: u32,
    #[serde(default)]
    pub create_time: i64,
    #[serde(default)]
    pub modify_time: i64,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtonItemInput {
    #[serde(default)]
    item_id: String,
    #[serde(default)]
    share_id: String,
    data: ProtonItemData,
    #[serde(default)]
    state: u8,
    #[serde(default)]
    alias_email: Option<String>,
    #[serde(default)]
    content_format_version: u32,
    #[serde(default)]
    create_time: i64,
    #[serde(default)]
    modify_time: i64,
    #[serde(default)]
    pinned: bool,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    files: Vec<String>,
    #[serde(rename = "shareCount", default)]
    _share_count: Option<u64>,
}

impl<'de> Deserialize<'de> for ProtonItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = ProtonItemInput::deserialize(deserializer)?;
        Ok(Self {
            item_id: input.item_id,
            share_id: input.share_id,
            data: input.data,
            state: input.state,
            alias_email: input.alias_email,
            content_format_version: input.content_format_version,
            create_time: input.create_time,
            modify_time: input.modify_time,
            pinned: input.pinned,
            files: input.files,
        })
    }
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct ProtonItemData {
    #[serde(default)]
    pub metadata: ProtonMetadata,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub extra_fields: Vec<ProtonExtraField>,
    #[serde(default)]
    pub platform_specific: Option<PlatformSpecific>,
    #[serde(flatten)]
    pub kind: ProtonItemKind,
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "type", content = "content")]
pub enum ProtonItemKind {
    #[serde(rename = "login")]
    Login(LoginContent),
    #[serde(rename = "note")]
    Note(EmptyContent),
    #[serde(rename = "alias")]
    Alias(EmptyContent),
    #[serde(rename = "creditCard")]
    CreditCard(CreditCardContent),
    #[serde(rename = "identity")]
    Identity(Box<IdentityContent>),
    #[serde(rename = "sshKey")]
    SshKey(SshKeyContent),
    #[serde(rename = "wifi")]
    Wifi(WifiContent),
    #[serde(rename = "custom")]
    Custom(CustomContent),
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum ProtonItemKindInput {
    #[serde(rename = "login")]
    Login { content: LoginContent },
    #[serde(rename = "note")]
    Note { content: EmptyContent },
    #[serde(rename = "alias")]
    Alias { content: EmptyContent },
    #[serde(rename = "creditCard")]
    CreditCard { content: CreditCardContent },
    #[serde(rename = "identity")]
    Identity { content: Box<IdentityContent> },
    #[serde(rename = "sshKey")]
    SshKey { content: SshKeyContent },
    #[serde(rename = "wifi")]
    Wifi { content: WifiContent },
    #[serde(rename = "custom")]
    Custom { content: CustomContent },
    #[serde(other)]
    Unknown,
}

impl<'de> Deserialize<'de> for ProtonItemKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match ProtonItemKindInput::deserialize(deserializer)? {
            ProtonItemKindInput::Login { content } => Self::Login(content),
            ProtonItemKindInput::Note { content } => Self::Note(content),
            ProtonItemKindInput::Alias { content } => Self::Alias(content),
            ProtonItemKindInput::CreditCard { content } => Self::CreditCard(content),
            ProtonItemKindInput::Identity { content } => Self::Identity(content),
            ProtonItemKindInput::SshKey { content } => Self::SshKey(content),
            ProtonItemKindInput::Wifi { content } => Self::Wifi(content),
            ProtonItemKindInput::Custom { content } => Self::Custom(content),
            ProtonItemKindInput::Unknown => Self::Unknown,
        })
    }
}

impl ProtonItemKind {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Login(_) => "login",
            Self::Note(_) => "note",
            Self::Alias(_) => "alias",
            Self::CreditCard(_) => "credit_card",
            Self::Identity(_) => "identity",
            Self::SshKey(_) => "ssh_key",
            Self::Wifi(_) => "wifi",
            Self::Custom(_) => "custom",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtonMetadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub item_uuid: String,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct EmptyContent {}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginContent {
    #[serde(default)]
    pub item_email: String,
    #[serde(default)]
    pub item_username: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub urls: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub autofill_urls: Vec<AutofillUrl>,
    #[serde(default)]
    pub totp_uri: String,
    #[serde(default, deserialize_with = "deserialize_passkeys")]
    pub passkeys: Vec<ProtonPasskeyInput>,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct AutofillUrl {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub mode: i32,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditCardContent {
    #[serde(default)]
    pub cardholder_name: String,
    #[serde(default)]
    pub card_type: i32,
    #[serde(default)]
    pub number: String,
    #[serde(default)]
    pub verification_number: String,
    #[serde(default)]
    pub expiration_date: String,
    #[serde(default)]
    pub pin: String,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityContent {
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone_number: String,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub middle_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub birthdate: String,
    #[serde(default)]
    pub gender: String,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub extra_personal_details: Vec<ProtonExtraField>,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub street_address: String,
    #[serde(default)]
    pub zip_or_postal_code: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub state_or_province: String,
    #[serde(default)]
    pub country_or_region: String,
    #[serde(default)]
    pub floor: String,
    #[serde(default)]
    pub county: String,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub extra_address_details: Vec<ProtonExtraField>,
    #[serde(default)]
    pub social_security_number: String,
    #[serde(default)]
    pub passport_number: String,
    #[serde(default)]
    pub license_number: String,
    #[serde(default)]
    pub website: String,
    #[serde(default)]
    pub x_handle: String,
    #[serde(default)]
    pub second_phone_number: String,
    #[serde(default)]
    pub linkedin: String,
    #[serde(default)]
    pub reddit: String,
    #[serde(default)]
    pub facebook: String,
    #[serde(default)]
    pub yahoo: String,
    #[serde(default)]
    pub instagram: String,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub extra_contact_details: Vec<ProtonExtraField>,
    #[serde(default)]
    pub company: String,
    #[serde(default)]
    pub job_title: String,
    #[serde(default)]
    pub personal_website: String,
    #[serde(default)]
    pub work_phone_number: String,
    #[serde(default)]
    pub work_email: String,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub extra_work_details: Vec<ProtonExtraField>,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub extra_sections: Vec<ProtonSection>,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SshKeyContent {
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub sections: Vec<ProtonSection>,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct WifiContent {
    #[serde(default)]
    pub ssid: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub security: i32,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub sections: Vec<ProtonSection>,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct CustomContent {
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub sections: Vec<ProtonSection>,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtonSection {
    #[serde(default)]
    pub section_name: String,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub section_fields: Vec<ProtonExtraField>,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtonExtraField {
    #[serde(default)]
    pub field_name: String,
    #[serde(rename = "type", default)]
    pub field_type: String,
    #[serde(default)]
    pub data: ProtonExtraFieldData,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtonExtraFieldData {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub totp_uri: String,
    #[serde(default)]
    pub timestamp: String,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct PlatformSpecific {
    #[serde(default)]
    pub android: Option<AndroidSpecific>,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidSpecific {
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub allowed_apps: Vec<AllowedAndroidApp>,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowedAndroidApp {
    #[serde(default)]
    pub package_name: String,
    #[serde(default, deserialize_with = "deserialize_nested_vec")]
    pub hashes: Vec<String>,
    #[serde(default)]
    pub app_name: String,
}

impl Zeroize for ProtonPasskeyCreationData {
    fn zeroize(&mut self) {
        self.os_name.zeroize();
        self.os_version.zeroize();
        self.device_name.zeroize();
        self.app_version.zeroize();
    }
}

impl Zeroize for ProtonPasskeyInput {
    fn zeroize(&mut self) {
        self.key_id.zeroize();
        self.content.zeroize();
        self.domain.zeroize();
        self.rp_id.zeroize();
        self.rp_name.zeroize();
        self.user_name.zeroize();
        self.user_display_name.zeroize();
        self.user_id.zeroize();
        self.create_time.zeroize();
        self.note.zeroize();
        self.credential_id.zeroize();
        self.user_handle.zeroize();
        self.creation_data.zeroize();
    }
}

#[derive(Clone, Copy)]
enum JsonBudgetContext {
    Root,
    Vaults,
    Vault,
    Items,
    Item,
    ItemData,
    Metadata,
    Passkeys,
    ItemId,
    ShareId,
    ItemUuid,
    Other,
}

struct JsonBudget {
    limits: InputLimits,
    vaults: usize,
    items: usize,
    passkeys: usize,
    nested_elements: usize,
    exceeded: bool,
}

impl JsonBudget {
    fn reject<T, E>(&mut self) -> Result<T, E>
    where
        E: de::Error,
    {
        self.exceeded = true;
        Err(E::custom("configured input limit exceeded"))
    }

    fn increment_vaults<E>(&mut self) -> Result<(), E>
    where
        E: de::Error,
    {
        let Some(vaults) = self.vaults.checked_add(1) else {
            return self.reject();
        };
        if vaults > self.limits.max_vaults {
            return self.reject();
        }
        self.vaults = vaults;
        Ok(())
    }

    fn increment_items<E>(&mut self) -> Result<(), E>
    where
        E: de::Error,
    {
        let Some(items) = self.items.checked_add(1) else {
            return self.reject();
        };
        if items > self.limits.max_items {
            return self.reject();
        }
        self.items = items;
        Ok(())
    }

    fn increment_nested<E>(&mut self) -> Result<(), E>
    where
        E: de::Error,
    {
        let Some(nested_elements) = self.nested_elements.checked_add(1) else {
            return self.reject();
        };
        if nested_elements > self.limits.max_nested_elements {
            return self.reject();
        }
        self.nested_elements = nested_elements;
        Ok(())
    }

    fn check_identifier<E>(&mut self, context: JsonBudgetContext, length: usize) -> Result<(), E>
    where
        E: de::Error,
    {
        let limit = match context {
            JsonBudgetContext::ItemId => self.limits.max_item_id_bytes,
            JsonBudgetContext::ShareId => self.limits.max_share_id_bytes,
            JsonBudgetContext::ItemUuid => self.limits.max_item_uuid_bytes,
            _ => return Ok(()),
        };
        if length > limit {
            return self.reject();
        }
        Ok(())
    }
}

struct JsonBudgetSeed<'a> {
    budget: &'a mut JsonBudget,
    context: JsonBudgetContext,
}

impl<'de> DeserializeSeed<'de> for JsonBudgetSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonBudgetVisitor {
            budget: self.budget,
            context: self.context,
        })
    }
}

struct JsonBudgetVisitor<'a> {
    budget: &'a mut JsonBudget,
    context: JsonBudgetContext,
}

impl<'de> Visitor<'de> for JsonBudgetVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.check_identifier(self.context, value.len())
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let element_context = match self.context {
            JsonBudgetContext::Items => JsonBudgetContext::Item,
            _ => JsonBudgetContext::Other,
        };
        let mut local_elements = 0_usize;
        while sequence
            .next_element_seed(JsonBudgetSeed {
                budget: self.budget,
                context: element_context,
            })?
            .is_some()
        {
            match self.context {
                JsonBudgetContext::Items => self.budget.increment_items()?,
                JsonBudgetContext::Passkeys => {
                    local_elements = local_elements
                        .checked_add(1)
                        .ok_or_else(|| de::Error::custom("configured input limit exceeded"))?;
                    if local_elements > self.budget.limits.max_passkeys_per_item {
                        return self.budget.reject();
                    }
                    self.budget.passkeys = self
                        .budget
                        .passkeys
                        .checked_add(1)
                        .ok_or_else(|| de::Error::custom("configured input limit exceeded"))?;
                    self.budget.increment_nested()?;
                }
                _ => self.budget.increment_nested()?,
            }
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key_seed(JsonKeySeed)? {
            if matches!(self.context, JsonBudgetContext::Vaults) {
                self.budget.increment_vaults()?;
                if key.len() > self.budget.limits.max_vault_id_bytes {
                    return self.budget.reject();
                }
            }
            let context = json_value_context(self.context, &key);
            map.next_value_seed(JsonBudgetSeed {
                budget: self.budget,
                context,
            })?;
        }
        Ok(())
    }
}

struct JsonKeySeed;

impl<'de> DeserializeSeed<'de> for JsonKeySeed {
    type Value = Cow<'de, str>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(JsonKeyVisitor)
    }
}

struct JsonKeyVisitor;

impl<'de> Visitor<'de> for JsonKeyVisitor {
    type Value = Cow<'de, str>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object key")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(Cow::Borrowed(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Cow::Owned(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Cow::Owned(value))
    }
}

fn json_value_context(context: JsonBudgetContext, key: &str) -> JsonBudgetContext {
    match (context, key) {
        (JsonBudgetContext::Root, "vaults") => JsonBudgetContext::Vaults,
        (JsonBudgetContext::Vaults, _) => JsonBudgetContext::Vault,
        (JsonBudgetContext::Vault, "items") => JsonBudgetContext::Items,
        (JsonBudgetContext::Item, "itemId") => JsonBudgetContext::ItemId,
        (JsonBudgetContext::Item, "shareId") => JsonBudgetContext::ShareId,
        (JsonBudgetContext::Item, "data") => JsonBudgetContext::ItemData,
        (JsonBudgetContext::ItemData, "metadata") => JsonBudgetContext::Metadata,
        (JsonBudgetContext::Metadata, "itemUuid") => JsonBudgetContext::ItemUuid,
        (_, "passkeys") => JsonBudgetContext::Passkeys,
        _ => JsonBudgetContext::Other,
    }
}

fn preflight_json(bytes: &[u8], limits: InputLimits) -> Result<usize, AppError> {
    let mut budget = JsonBudget {
        limits,
        vaults: 0,
        items: 0,
        passkeys: 0,
        nested_elements: 0,
        exceeded: false,
    };
    let result = {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        JsonBudgetSeed {
            budget: &mut budget,
            context: JsonBudgetContext::Root,
        }
        .deserialize(&mut deserializer)
        .and_then(|_| deserializer.end())
    };
    match result {
        Ok(()) => Ok(budget.passkeys),
        Err(_) if budget.exceeded => Err(AppError::InputTooLarge),
        Err(error) => Err(AppError::InvalidJson {
            line: error.line(),
            column: error.column(),
        }),
    }
}

pub fn load_export(path: &Path, limits: InputLimits) -> Result<LoadedExport, AppError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| AppError::InputOpen)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(AppError::UnsupportedInput);
    }
    let mut file = File::open(path).map_err(|_| AppError::InputOpen)?;
    let metadata = file.metadata().map_err(|_| AppError::InputOpen)?;
    if !metadata.is_file() {
        return Err(AppError::UnsupportedInput);
    }
    let length = metadata.len();
    if length > limits.max_archive_bytes {
        return Err(AppError::InputTooLarge);
    }

    let mut signature = [0_u8; 4];
    let read = file.read(&mut signature).map_err(|_| AppError::InputOpen)?;
    file.rewind().map_err(|_| AppError::InputOpen)?;

    let (json, source) = if read == 4 && signature == [0x50, 0x4b, 0x03, 0x04] {
        (read_zip_json(file, limits)?, InputSource::Zip)
    } else {
        if length > limits.max_json_bytes {
            return Err(AppError::InputTooLarge);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(length as usize));
        file.take(limits.max_json_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AppError::InputOpen)?;
        if bytes.len() as u64 > limits.max_json_bytes {
            return Err(AppError::InputTooLarge);
        }
        if is_pgp(&bytes) {
            return Err(AppError::EncryptedExport);
        }
        (bytes, InputSource::RawJson)
    };

    let preflight_passkeys = preflight_json(&json, limits)?;
    let export: ProtonExport =
        serde_json::from_slice(&json).map_err(|error| AppError::InvalidJson {
            line: error.line(),
            column: error.column(),
        })?;

    if export.encrypted == Some(true) {
        return Err(AppError::EncryptedExport);
    }
    validate_export(&export, limits, json.len() as u64, preflight_passkeys)?;

    Ok(LoadedExport { export, source })
}

fn read_zip_json(file: File, limits: InputLimits) -> Result<Zeroizing<Vec<u8>>, AppError> {
    let length = file.metadata().map_err(|_| AppError::UnsafeArchive)?.len();
    if length > limits.max_archive_bytes {
        return Err(AppError::InputTooLarge);
    }
    preflight_zip(&file, length, limits)?;
    if file.metadata().map_err(|_| AppError::UnsafeArchive)?.len() != length {
        return Err(AppError::UnsafeArchive);
    }
    let archive = ZipArchive::new(file).map_err(|_| AppError::UnsafeArchive)?;
    let central_directory_start = archive.central_directory_start();
    let parsed_entries = archive.len();
    let mut file = archive.into_inner();
    if file.metadata().map_err(|_| AppError::UnsafeArchive)?.len() != length {
        return Err(AppError::UnsafeArchive);
    }
    validate_central_directory(
        &mut file,
        central_directory_start,
        parsed_entries,
        limits.max_entries,
    )?;
    if file.metadata().map_err(|_| AppError::UnsafeArchive)?.len() != length {
        return Err(AppError::UnsafeArchive);
    }
    file.rewind().map_err(|_| AppError::UnsafeArchive)?;
    let mut archive = ZipArchive::new(file).map_err(|_| AppError::UnsafeArchive)?;
    if archive.len() > limits.max_entries {
        return Err(AppError::UnsafeArchive);
    }
    validate_nonoverlapping_ranges(&mut archive, central_directory_start)?;

    let mut json_index = None;
    let mut pgp_found = false;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|_| AppError::UnsafeArchive)?;
        validate_zip_entry(&entry)?;
        match entry.name() {
            "Proton Pass/data.json" => {
                if json_index.replace(index).is_some() {
                    return Err(AppError::MissingOrAmbiguousData);
                }
            }
            "Proton Pass/data.pgp" => pgp_found = true,
            _ => {}
        }
    }

    if pgp_found {
        return Err(AppError::EncryptedExport);
    }
    let index = json_index.ok_or(AppError::MissingOrAmbiguousData)?;
    let entry = archive
        .by_index(index)
        .map_err(|_| AppError::UnsafeArchive)?;
    if entry.size() > limits.max_json_bytes {
        return Err(AppError::InputTooLarge);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(entry.size() as usize));
    entry
        .take(limits.max_json_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AppError::UnsafeArchive)?;
    if bytes.len() as u64 > limits.max_json_bytes {
        return Err(AppError::InputTooLarge);
    }
    if archive
        .into_inner()
        .metadata()
        .map_err(|_| AppError::UnsafeArchive)?
        .len()
        != length
    {
        return Err(AppError::UnsafeArchive);
    }
    Ok(bytes)
}

fn validate_nonoverlapping_ranges<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    central_directory_start: u64,
) -> Result<(), AppError> {
    let mut ranges = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|_| AppError::UnsafeArchive)?;
        let start = entry.data_start().ok_or(AppError::UnsafeArchive)?;
        let end = start
            .checked_add(entry.compressed_size())
            .ok_or(AppError::UnsafeArchive)?;
        if end > central_directory_start {
            return Err(AppError::UnsafeArchive);
        }
        if start != end {
            ranges.push(start..end);
        }
    }
    ranges.sort_unstable_by_key(|range| range.start);
    if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(AppError::UnsafeArchive);
    }
    Ok(())
}

fn preflight_zip(file: &File, file_length: u64, limits: InputLimits) -> Result<(), AppError> {
    const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const ZIP64_LOCATOR_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
    const ZIP64_EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    const MAX_EOCD_SEARCH: u64 = 22 + u16::MAX as u64;

    if file_length < 22 {
        return Err(AppError::UnsafeArchive);
    }
    let search_start = file_length.saturating_sub(MAX_EOCD_SEARCH);
    let search_length =
        usize::try_from(file_length - search_start).map_err(|_| AppError::UnsafeArchive)?;
    let mut tail = vec![0_u8; search_length];
    let mut reader = file.try_clone().map_err(|_| AppError::UnsafeArchive)?;
    reader
        .seek(SeekFrom::Start(search_start))
        .and_then(|_| reader.read_exact(&mut tail))
        .map_err(|_| AppError::UnsafeArchive)?;

    let eocd_candidates: Vec<_> = tail
        .windows(4)
        .enumerate()
        .filter_map(|(index, signature)| {
            if signature != EOCD_SIGNATURE || index + 22 > tail.len() {
                return None;
            }
            read_u16_at(&tail, index + 20)
                .is_some_and(|length| index + 22 + length as usize == tail.len())
                .then_some(index)
        })
        .collect();
    if eocd_candidates.len() != 1 {
        return Err(AppError::UnsafeArchive);
    }
    let eocd_relative = eocd_candidates[0];
    let eocd = &tail[eocd_relative..];
    let eocd_offset = search_start
        .checked_add(eocd_relative as u64)
        .ok_or(AppError::UnsafeArchive)?;
    let disk_number = read_u16_at(eocd, 4).ok_or(AppError::UnsafeArchive)?;
    let central_disk = read_u16_at(eocd, 6).ok_or(AppError::UnsafeArchive)?;
    let entries_on_disk = read_u16_at(eocd, 8).ok_or(AppError::UnsafeArchive)? as u64;
    let total_entries = read_u16_at(eocd, 10).ok_or(AppError::UnsafeArchive)? as u64;
    let directory_size = read_u32_at(eocd, 12).ok_or(AppError::UnsafeArchive)? as u64;
    let directory_offset = read_u32_at(eocd, 16).ok_or(AppError::UnsafeArchive)? as u64;

    if disk_number != 0 || central_disk != 0 || entries_on_disk != total_entries {
        return Err(AppError::UnsafeArchive);
    }

    let needs_zip64 = total_entries == u16::MAX as u64
        || directory_size == u32::MAX as u64
        || directory_offset == u32::MAX as u64;
    let (total_entries, directory_size, directory_offset, expected_directory_end) = if needs_zip64 {
        if eocd_offset < 20 {
            return Err(AppError::UnsafeArchive);
        }
        let locator_offset = eocd_offset - 20;
        let mut locator = [0_u8; 20];
        reader
            .seek(SeekFrom::Start(locator_offset))
            .and_then(|_| reader.read_exact(&mut locator))
            .map_err(|_| AppError::UnsafeArchive)?;
        if locator[..4] != ZIP64_LOCATOR_SIGNATURE
            || read_u32_at(&locator, 4) != Some(0)
            || read_u32_at(&locator, 16) != Some(1)
        {
            return Err(AppError::UnsafeArchive);
        }
        let zip64_offset = read_u64_at(&locator, 8).ok_or(AppError::UnsafeArchive)?;
        let mut zip64 = [0_u8; 56];
        reader
            .seek(SeekFrom::Start(zip64_offset))
            .and_then(|_| reader.read_exact(&mut zip64))
            .map_err(|_| AppError::UnsafeArchive)?;
        if zip64[..4] != ZIP64_EOCD_SIGNATURE
            || read_u64_at(&zip64, 4).is_none_or(|size| size < 44)
            || read_u32_at(&zip64, 16) != Some(0)
            || read_u32_at(&zip64, 20) != Some(0)
        {
            return Err(AppError::UnsafeArchive);
        }
        let zip64_size = read_u64_at(&zip64, 4).ok_or(AppError::UnsafeArchive)?;
        if zip64_offset
            .checked_add(12)
            .and_then(|value| value.checked_add(zip64_size))
            != Some(locator_offset)
        {
            return Err(AppError::UnsafeArchive);
        }
        let disk_entries = read_u64_at(&zip64, 24).ok_or(AppError::UnsafeArchive)?;
        let entries = read_u64_at(&zip64, 32).ok_or(AppError::UnsafeArchive)?;
        if disk_entries != entries {
            return Err(AppError::UnsafeArchive);
        }
        (
            entries,
            read_u64_at(&zip64, 40).ok_or(AppError::UnsafeArchive)?,
            read_u64_at(&zip64, 48).ok_or(AppError::UnsafeArchive)?,
            zip64_offset,
        )
    } else {
        (total_entries, directory_size, directory_offset, eocd_offset)
    };

    if total_entries > limits.max_entries as u64
        || directory_size > limits.max_central_directory_bytes
    {
        return Err(AppError::UnsafeArchive);
    }
    let directory_end = directory_offset
        .checked_add(directory_size)
        .ok_or(AppError::UnsafeArchive)?;
    if directory_end != expected_directory_end || directory_end > file_length {
        return Err(AppError::UnsafeArchive);
    }
    preflight_central_directory(
        &mut reader,
        directory_offset,
        directory_size,
        total_entries,
        limits,
    )
}

fn preflight_central_directory(
    file: &mut File,
    start: u64,
    size: u64,
    entries: u64,
    limits: InputLimits,
) -> Result<(), AppError> {
    const CENTRAL_HEADER: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    file.seek(SeekFrom::Start(start))
        .map_err(|_| AppError::UnsafeArchive)?;
    let mut consumed = 0_u64;
    let mut metadata_bytes = 0_u64;
    for _ in 0..entries {
        let mut header = [0_u8; 46];
        file.read_exact(&mut header)
            .map_err(|_| AppError::UnsafeArchive)?;
        if header[..4] != CENTRAL_HEADER {
            return Err(AppError::UnsafeArchive);
        }
        if read_u16_at(&header, 34) != Some(0) {
            return Err(AppError::UnsafeArchive);
        }
        let name_length = read_u16_at(&header, 28).ok_or(AppError::UnsafeArchive)? as u64;
        let extra_length = read_u16_at(&header, 30).ok_or(AppError::UnsafeArchive)? as u64;
        let comment_length = read_u16_at(&header, 32).ok_or(AppError::UnsafeArchive)? as u64;
        if name_length > limits.max_entry_name_bytes as u64 {
            return Err(AppError::UnsafeArchive);
        }
        let variable = name_length
            .checked_add(extra_length)
            .and_then(|value| value.checked_add(comment_length))
            .ok_or(AppError::UnsafeArchive)?;
        metadata_bytes = metadata_bytes
            .checked_add(46)
            .and_then(|value| value.checked_add(variable))
            .ok_or(AppError::UnsafeArchive)?;
        consumed = consumed
            .checked_add(46)
            .and_then(|value| value.checked_add(variable))
            .ok_or(AppError::UnsafeArchive)?;
        if consumed > size || metadata_bytes > limits.max_zip_metadata_bytes {
            return Err(AppError::UnsafeArchive);
        }
        file.seek(SeekFrom::Current(
            i64::try_from(variable).map_err(|_| AppError::UnsafeArchive)?,
        ))
        .map_err(|_| AppError::UnsafeArchive)?;
    }
    if consumed != size {
        return Err(AppError::UnsafeArchive);
    }
    Ok(())
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn validate_central_directory(
    file: &mut File,
    start: u64,
    parsed_entries: usize,
    max_entries: usize,
) -> Result<(), AppError> {
    const CENTRAL_HEADER: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const CENTRAL_DIRECTORY_END: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const ZIP64_CENTRAL_DIRECTORY_END: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    const FIXED_HEADER_BYTES: usize = 46;

    file.seek(std::io::SeekFrom::Start(start))
        .map_err(|_| AppError::UnsafeArchive)?;

    let file_length = file.metadata().map_err(|_| AppError::UnsafeArchive)?.len();
    let mut position = start;
    let mut count = 0_usize;
    let mut names = std::collections::BTreeSet::new();

    loop {
        if position
            .checked_add(4)
            .is_none_or(|next| next > file_length)
        {
            return Err(AppError::UnsafeArchive);
        }
        let mut signature = [0_u8; 4];
        file.read_exact(&mut signature)
            .map_err(|_| AppError::UnsafeArchive)?;
        if matches!(
            signature,
            CENTRAL_DIRECTORY_END | ZIP64_CENTRAL_DIRECTORY_END
        ) {
            break;
        }
        if signature != CENTRAL_HEADER {
            return Err(AppError::UnsafeArchive);
        }

        let mut header = [0_u8; FIXED_HEADER_BYTES - 4];
        file.read_exact(&mut header)
            .map_err(|_| AppError::UnsafeArchive)?;

        let name_length = u16::from_le_bytes([header[24], header[25]]) as usize;
        let extra_length = u16::from_le_bytes([header[26], header[27]]) as usize;
        let comment_length = u16::from_le_bytes([header[28], header[29]]) as usize;
        let variable_length = name_length
            .checked_add(extra_length)
            .and_then(|value| value.checked_add(comment_length))
            .ok_or(AppError::UnsafeArchive)?;
        let next = position
            .checked_add(FIXED_HEADER_BYTES as u64)
            .and_then(|value| value.checked_add(variable_length as u64))
            .ok_or(AppError::UnsafeArchive)?;
        if next > file_length {
            return Err(AppError::UnsafeArchive);
        }

        let mut name = vec![0_u8; name_length];
        file.read_exact(&mut name)
            .map_err(|_| AppError::UnsafeArchive)?;
        file.seek(std::io::SeekFrom::Current(
            (extra_length + comment_length) as i64,
        ))
        .map_err(|_| AppError::UnsafeArchive)?;

        count = count.checked_add(1).ok_or(AppError::UnsafeArchive)?;
        if count > max_entries || !names.insert(name) {
            return Err(AppError::UnsafeArchive);
        }
        position = next;
    }

    if count != parsed_entries {
        return Err(AppError::UnsafeArchive);
    }
    Ok(())
}

fn validate_zip_entry<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> Result<(), AppError> {
    if entry.encrypted() {
        return Err(AppError::UnsafeArchive);
    }
    let raw = std::str::from_utf8(entry.name_raw()).map_err(|_| AppError::UnsafeArchive)?;
    if raw.contains('\0') || raw.contains('\\') || raw.starts_with('/') || raw.starts_with("//") {
        return Err(AppError::UnsafeArchive);
    }
    let without_trailing_slash = raw.strip_suffix('/').unwrap_or(raw);
    if without_trailing_slash.is_empty()
        || without_trailing_slash
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(AppError::UnsafeArchive);
    }
    if without_trailing_slash
        .split('/')
        .next()
        .is_some_and(|part| part.as_bytes().get(1) == Some(&b':'))
    {
        return Err(AppError::UnsafeArchive);
    }
    if entry.enclosed_name().is_none()
        || entry.enclosed_name().is_some_and(|path| {
            path.components()
                .any(|part| !matches!(part, Component::Normal(_)))
        })
    {
        return Err(AppError::UnsafeArchive);
    }
    if entry
        .unix_mode()
        .is_some_and(|mode| mode & 0o170000 == 0o120000)
    {
        return Err(AppError::UnsafeArchive);
    }
    if !matches!(
        entry.compression(),
        CompressionMethod::Stored | CompressionMethod::Deflated
    ) {
        return Err(AppError::UnsafeArchive);
    }
    Ok(())
}

fn validate_export(
    export: &ProtonExport,
    limits: InputLimits,
    input_json_bytes: u64,
    preflight_passkeys: usize,
) -> Result<(), AppError> {
    if export.vaults.len() > limits.max_vaults {
        return Err(AppError::InputTooLarge);
    }
    let mut items = 0_usize;
    let mut nested_elements = 0_usize;
    let mut projected_bytes = input_json_bytes;
    let mut modeled_passkeys = 0_usize;
    let mut generated_folder_bytes = 0_u64;
    let mut generated_section_prefix_bytes = 0_u64;
    let mut folder_prefixes = FolderPrefixNode::default();
    for (vault_id, vault) in &export.vaults {
        if vault_id.len() > limits.max_vault_id_bytes {
            return Err(AppError::InputTooLarge);
        }
        if vault_id.is_empty() || vault.name.len() > limits.max_vault_name_bytes {
            return Err(AppError::InvalidExport);
        }
        account_folder_prefixes(
            &vault.name,
            limits,
            &mut folder_prefixes,
            &mut generated_folder_bytes,
        )?;
        ensure_projected_output(
            projected_bytes,
            items,
            generated_folder_bytes,
            generated_section_prefix_bytes,
            limits,
        )?;
        items = items
            .checked_add(vault.items.len())
            .ok_or(AppError::InputTooLarge)?;
        if items > limits.max_items {
            return Err(AppError::InputTooLarge);
        }
        let mut item_ids = std::collections::BTreeSet::new();
        for item in &vault.items {
            if item.item_id.len() > limits.max_item_id_bytes
                || item.share_id.len() > limits.max_share_id_bytes
                || item.data.metadata.item_uuid.len() > limits.max_item_uuid_bytes
            {
                return Err(AppError::InputTooLarge);
            }
            let split_count = if let ProtonItemKind::Login(login) = &item.data.kind {
                if login.passkeys.len() > limits.max_passkeys_per_item {
                    return Err(AppError::InputTooLarge);
                }
                modeled_passkeys = modeled_passkeys
                    .checked_add(login.passkeys.len())
                    .ok_or(AppError::InputTooLarge)?;
                login.passkeys.len().max(1)
            } else {
                1
            };
            if item.item_id.is_empty()
                || !item_ids.insert(item.item_id.as_str())
                || !matches!(item.state, 1 | 2)
                || item.content_format_version > 7
            {
                return Err(AppError::InvalidExport);
            }
            nested_elements = nested_elements
                .checked_add(count_nested_elements(item))
                .ok_or(AppError::InputTooLarge)?;
            if nested_elements > limits.max_nested_elements {
                return Err(AppError::InputTooLarge);
            }
            generated_section_prefix_bytes = generated_section_prefix_bytes
                .checked_add(account_section_prefixes(item, limits)?)
                .ok_or(AppError::InputTooLarge)?;
            if split_count > 1 {
                let item_bytes = serialized_size(item)?;
                let duplicate_bytes = item_bytes
                    .checked_mul((split_count - 1) as u64)
                    .ok_or(AppError::InputTooLarge)?;
                projected_bytes = projected_bytes
                    .checked_add(duplicate_bytes)
                    .ok_or(AppError::InputTooLarge)?;
            }
        }
    }
    if modeled_passkeys != preflight_passkeys {
        return Err(AppError::InvalidExport);
    }
    ensure_projected_output(
        projected_bytes,
        items,
        generated_folder_bytes,
        generated_section_prefix_bytes,
        limits,
    )
}

#[derive(Default)]
struct FolderPrefixNode {
    children: BTreeMap<String, FolderPrefixNode>,
}

fn account_folder_prefixes(
    name: &str,
    limits: InputLimits,
    root: &mut FolderPrefixNode,
    generated_bytes: &mut u64,
) -> Result<(), AppError> {
    const FOLDER_OBJECT_OVERHEAD_BYTES: u64 = 56;

    let normalized = name.replace('\\', "/");
    let normalized = normalized.trim_start_matches('/').trim();
    if normalized.is_empty() {
        return Ok(());
    }

    let mut depth = 0_usize;
    let mut escaped_prefix_bytes = 0_u64;
    let mut node = root;
    for component in normalized.split('/') {
        if component.is_empty() {
            return Err(AppError::InvalidExport);
        }
        depth = depth.checked_add(1).ok_or(AppError::InputTooLarge)?;
        if depth > limits.max_folder_depth || component.len() > limits.max_folder_component_bytes {
            return Err(AppError::InvalidExport);
        }
        if depth > 1 {
            escaped_prefix_bytes = escaped_prefix_bytes
                .checked_add(1)
                .ok_or(AppError::InputTooLarge)?;
        }
        escaped_prefix_bytes = escaped_prefix_bytes
            .checked_add(json_escaped_content_bytes(component)?)
            .ok_or(AppError::InputTooLarge)?;

        use std::collections::btree_map::Entry;
        node = match node.children.entry(component.to_owned()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                *generated_bytes = generated_bytes
                    .checked_add(FOLDER_OBJECT_OVERHEAD_BYTES)
                    .and_then(|value| value.checked_add(escaped_prefix_bytes))
                    .ok_or(AppError::InputTooLarge)?;
                entry.insert(FolderPrefixNode::default())
            }
        };
    }
    Ok(())
}

fn json_escaped_content_bytes(value: &str) -> Result<u64, AppError> {
    value.chars().try_fold(0_u64, |total, character| {
        let bytes = match character {
            '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8() as u64,
        };
        total.checked_add(bytes).ok_or(AppError::InputTooLarge)
    })
}

fn ensure_projected_output(
    source_bytes: u64,
    items: usize,
    generated_folder_bytes: u64,
    generated_section_prefix_bytes: u64,
    limits: InputLimits,
) -> Result<(), AppError> {
    let item_count = u64::try_from(items).map_err(|_| AppError::InputTooLarge)?;
    let projected_bytes = source_bytes
        .checked_mul(4)
        .and_then(|value| {
            item_count
                .checked_mul(4096)
                .and_then(|item_bytes| value.checked_add(item_bytes))
        })
        .and_then(|value| value.checked_add(generated_folder_bytes))
        .and_then(|value| value.checked_add(generated_section_prefix_bytes))
        .ok_or(AppError::InputTooLarge)?;
    if projected_bytes > limits.max_projected_output_bytes {
        return Err(AppError::InputTooLarge);
    }
    Ok(())
}

fn account_section_prefixes(item: &ProtonItem, limits: InputLimits) -> Result<u64, AppError> {
    let sections = match &item.data.kind {
        ProtonItemKind::Identity(content) => content.extra_sections.as_slice(),
        ProtonItemKind::SshKey(content) => content.sections.as_slice(),
        ProtonItemKind::Wifi(content) => content.sections.as_slice(),
        ProtonItemKind::Custom(content) => content.sections.as_slice(),
        ProtonItemKind::Login(_)
        | ProtonItemKind::Note(_)
        | ProtonItemKind::Alias(_)
        | ProtonItemKind::CreditCard(_)
        | ProtonItemKind::Unknown => return Ok(0),
    };
    sections.iter().try_fold(0_u64, |total, section| {
        if section.section_name.len() > limits.max_section_name_bytes {
            return Err(AppError::InputTooLarge);
        }
        if section.section_name.trim().is_empty() {
            return Ok(total);
        }
        let prefix_bytes = json_escaped_content_bytes(&section.section_name)?
            .checked_add(3)
            .ok_or(AppError::InputTooLarge)?;
        let field_count =
            u64::try_from(section.section_fields.len()).map_err(|_| AppError::InputTooLarge)?;
        total
            .checked_add(
                prefix_bytes
                    .checked_mul(field_count)
                    .ok_or(AppError::InputTooLarge)?,
            )
            .ok_or(AppError::InputTooLarge)
    })
}

fn count_nested_elements(item: &ProtonItem) -> usize {
    let mut count = item
        .files
        .len()
        .saturating_add(item.data.extra_fields.len());
    if let Some(android) = item
        .data
        .platform_specific
        .as_ref()
        .and_then(|platform| platform.android.as_ref())
    {
        count = count.saturating_add(android.allowed_apps.len());
        for app in &android.allowed_apps {
            count = count.saturating_add(app.hashes.len());
        }
    }
    match &item.data.kind {
        ProtonItemKind::Login(login) => {
            count = count
                .saturating_add(login.urls.len())
                .saturating_add(login.autofill_urls.len())
                .saturating_add(login.passkeys.len());
        }
        ProtonItemKind::Identity(identity) => {
            count = count
                .saturating_add(identity.extra_personal_details.len())
                .saturating_add(identity.extra_address_details.len())
                .saturating_add(identity.extra_contact_details.len())
                .saturating_add(identity.extra_work_details.len())
                .saturating_add(count_sections(&identity.extra_sections));
        }
        ProtonItemKind::SshKey(content) => {
            count = count.saturating_add(count_sections(&content.sections));
        }
        ProtonItemKind::Wifi(content) => {
            count = count.saturating_add(count_sections(&content.sections));
        }
        ProtonItemKind::Custom(content) => {
            count = count.saturating_add(count_sections(&content.sections));
        }
        ProtonItemKind::Note(_)
        | ProtonItemKind::Alias(_)
        | ProtonItemKind::CreditCard(_)
        | ProtonItemKind::Unknown => {}
    }
    count
}

fn count_sections(sections: &[ProtonSection]) -> usize {
    sections.iter().fold(sections.len(), |total, section| {
        total.saturating_add(section.section_fields.len())
    })
}

fn serialized_size<T: Serialize + ?Sized>(value: &T) -> Result<u64, AppError> {
    struct Counter(u64);

    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("size overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(|_| AppError::InputTooLarge)?;
    Ok(counter.0)
}

fn is_pgp(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .take(27)
        .eq(b"-----BEGIN PGP MESSAGE-----".iter().copied())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;
    use zip::write::SimpleFileOptions;

    use super::*;

    const MINIMAL: &str = r#"{"version":"1","vaults":{}}"#;

    #[test]
    fn zeroizes_parsed_item_secrets() {
        let mut export: ProtonExport = serde_json::from_str(
            r#"{"version":"1","vaults":{"v":{"items":[{"itemId":"i","state":1,"data":{"metadata":{"note":"synthetic-note"},"extraFields":[{"fieldName":"hidden","type":"hidden","data":{"content":"synthetic-hidden"}}],"type":"login","content":{"password":"synthetic-password","totpUri":"otpauth://synthetic"}}}]}}}"#,
        )
        .unwrap();
        let item = &mut export.vaults.get_mut("v").unwrap().items[0];

        item.zeroize();

        assert!(item.item_id.is_empty());
        assert!(item.data.metadata.note.is_empty());
        assert!(item.data.extra_fields.is_empty());
        let ProtonItemKind::Login(login) = &item.data.kind else {
            panic!("login variant should remain selected");
        };
        assert!(login.password.is_empty());
        assert!(login.totp_uri.is_empty());
    }

    #[test]
    fn loads_raw_json_without_historical_encrypted_field() {
        let mut input = NamedTempFile::new().unwrap();
        input.write_all(MINIMAL.as_bytes()).unwrap();
        let loaded = load_export(input.path(), InputLimits::default()).unwrap();
        assert!(matches!(loaded.source, InputSource::RawJson));
    }

    #[test]
    fn rejects_encrypted_json() {
        let mut input = NamedTempFile::new().unwrap();
        input
            .write_all(br#"{"encrypted":true,"version":"1","vaults":{}}"#)
            .unwrap();
        assert!(matches!(
            load_export(input.path(), InputLimits::default()),
            Err(AppError::EncryptedExport)
        ));
    }

    #[test]
    fn reads_exact_zip_entry() {
        let input = NamedTempFile::new().unwrap();
        {
            let mut writer = zip::ZipWriter::new(input.reopen().unwrap());
            writer
                .start_file("Proton Pass/data.json", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(MINIMAL.as_bytes()).unwrap();
            writer.finish().unwrap();
        }
        let loaded = load_export(input.path(), InputLimits::default()).unwrap();
        assert!(matches!(loaded.source, InputSource::Zip));
    }

    #[test]
    fn rejects_pgp_zip() {
        let input = NamedTempFile::new().unwrap();
        {
            let mut writer = zip::ZipWriter::new(input.reopen().unwrap());
            writer
                .start_file("Proton Pass/data.pgp", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"encrypted").unwrap();
            writer.finish().unwrap();
        }
        assert!(matches!(
            load_export(input.path(), InputLimits::default()),
            Err(AppError::EncryptedExport)
        ));
    }

    #[test]
    fn rejects_oversized_raw_json() {
        let mut input = NamedTempFile::new().unwrap();
        input.write_all(MINIMAL.as_bytes()).unwrap();
        let limits = InputLimits {
            max_json_bytes: 4,
            ..InputLimits::default()
        };
        assert!(matches!(
            load_export(input.path(), limits),
            Err(AppError::InputTooLarge)
        ));
    }

    #[test]
    fn preserves_unknown_item_as_an_explicit_unsupported_variant() {
        let mut input = NamedTempFile::new().unwrap();
        input
            .write_all(
                br#"{"version":"1","vaults":{"v":{"items":[{"itemId":"i","state":1,"data":{"type":"futureType","content":{"password":"SYNTHETIC_UNKNOWN_SECRET"}}}]}}}"#,
            )
            .unwrap();
        let loaded = load_export(input.path(), InputLimits::default()).unwrap();
        let item = &loaded.export.vaults["v"].items[0];
        assert!(matches!(item.data.kind, ProtonItemKind::Unknown));
    }
}
