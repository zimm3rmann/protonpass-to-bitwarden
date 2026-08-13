use std::fmt;
use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_SERIALIZED_PASSKEY_BYTES: usize = 64 * 1024;
const MAX_SERIALIZED_PASSKEY_BASE64_BYTES: usize = MAX_SERIALIZED_PASSKEY_BYTES.div_ceil(3) * 4;
const MAX_MESSAGEPACK_DEPTH: usize = 32;
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
const MAX_USER_HANDLE_BYTES: usize = 64;
const MAX_RP_ID_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 4096;

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtonPasskeyCreationData {
    pub os_name: String,
    pub os_version: String,
    pub device_name: String,
    pub app_version: String,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtonPasskeyInput {
    pub key_id: String,
    pub content: String,
    pub domain: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub user_id: String,
    #[serde(default)]
    pub create_time: Option<i64>,
    pub note: String,
    pub credential_id: String,
    pub user_handle: String,
    #[serde(default)]
    pub creation_data: Option<ProtonPasskeyCreationData>,
}

impl Drop for ProtonPasskeyInput {
    fn drop(&mut self) {
        self.key_id.zeroize();
        self.content.zeroize();
        self.domain.zeroize();
        self.rp_id.zeroize();
        self.rp_name.zeroize();
        self.user_name.zeroize();
        self.user_display_name.zeroize();
        self.user_id.zeroize();
        self.note.zeroize();
        self.credential_id.zeroize();
        self.user_handle.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConvertedPasskey {
    pub credential_id: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub key_curve: String,
    pub key_value: String,
    pub rp_id: String,
    pub user_handle: String,
    pub user_name: String,
    pub counter: String,
    pub rp_name: String,
    pub user_display_name: String,
    pub discoverable: String,
    pub creation_date: String,
    #[serde(skip_serializing)]
    pub used_item_time_fallback: bool,
    #[serde(skip_serializing)]
    pub(crate) has_unpreserved_creation_data: bool,
    #[serde(skip_serializing)]
    pub(crate) credential_id_bytes: Vec<u8>,
}

impl Drop for ConvertedPasskey {
    fn drop(&mut self) {
        self.key_value.zeroize();
        self.credential_id_bytes.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasskeyFailure {
    InvalidBase64,
    ResourceLimit,
    MalformedOrUnknownField,
    TrailingMessagePack,
    UnsupportedVersion,
    PrfExtension,
    UnsupportedKeyType,
    UnsupportedAlgorithm,
    UnsupportedKeyMetadata,
    UnknownKeyParameter,
    DuplicateKeyParameter,
    MissingKeyParameter,
    InvalidKeyParameter,
    UnsupportedCurve,
    InvalidPrivateScalar,
    PublicKeyMismatch,
    MetadataMismatch,
    MissingUserHandle,
    InvalidTimestamp,
    PrivateKeyEncoding,
}

impl fmt::Display for PasskeyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBase64 => "passkey metadata contains invalid base64",
            Self::ResourceLimit => "passkey content exceeds a resource limit",
            Self::MalformedOrUnknownField => {
                "passkey content is malformed or contains an unknown field"
            }
            Self::TrailingMessagePack => "passkey content contains trailing MessagePack data",
            Self::UnsupportedVersion => "passkey content uses an unsupported format version",
            Self::PrfExtension => "passkey PRF data cannot be preserved",
            Self::UnsupportedKeyType => "passkey key type is unsupported",
            Self::UnsupportedAlgorithm => "passkey key algorithm is unsupported",
            Self::UnsupportedKeyMetadata => "passkey key restrictions are unsupported",
            Self::UnknownKeyParameter => "passkey contains an unknown key parameter",
            Self::DuplicateKeyParameter => "passkey contains a duplicate key parameter",
            Self::MissingKeyParameter => "passkey is missing a required key parameter",
            Self::InvalidKeyParameter => "passkey contains an invalid key parameter",
            Self::UnsupportedCurve => "passkey key curve is unsupported",
            Self::InvalidPrivateScalar => "passkey private key material is invalid",
            Self::PublicKeyMismatch => "passkey public and private key material do not match",
            Self::MetadataMismatch => "passkey duplicated metadata does not match",
            Self::MissingUserHandle => "passkey has no discoverable user handle",
            Self::InvalidTimestamp => "passkey and item timestamps are invalid",
            Self::PrivateKeyEncoding => "passkey private key encoding failed",
        })
    }
}

impl std::error::Error for PasskeyFailure {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SerializedPassKey {
    #[serde(rename = "c")]
    content: Vec<u8>,
    #[serde(rename = "v")]
    format_version: u64,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct ProtonPassKey {
    #[serde(rename = "key")]
    key: ProtonKey,
    #[serde(rename = "cid")]
    credential_id: Vec<u8>,
    #[serde(rename = "rid")]
    rp_id: String,
    #[serde(rename = "uhd")]
    user_handle: Option<Vec<u8>>,
    #[serde(rename = "cnt")]
    counter: Option<u32>,
    #[serde(rename = "ext", default)]
    extensions: ProtonPassCredentialExtensions,
    #[serde(rename = "udn", default)]
    user_display_name: Option<String>,
    #[serde(rename = "un", default)]
    username: Option<String>,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct ProtonKey {
    #[serde(rename = "kty")]
    key_type: TaggedString,
    #[serde(rename = "kid")]
    key_id: Vec<u8>,
    #[serde(rename = "alg")]
    algorithm: Option<TaggedAlgorithm>,
    #[serde(rename = "kops")]
    key_operations: Vec<TaggedString>,
    #[serde(rename = "biv")]
    base_iv: Vec<u8>,
    #[serde(rename = "par")]
    parameters: Vec<(ProtonLabel, ProtonValue)>,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct TaggedString {
    #[serde(rename = "t")]
    tag: String,
    #[serde(rename = "c")]
    content: String,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct TaggedAlgorithm {
    #[serde(rename = "t")]
    tag: String,
    #[serde(rename = "c")]
    content: TaggedAlgorithmContent,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(untagged)]
enum TaggedAlgorithmContent {
    Text(String),
    Integer(i64),
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(tag = "t", content = "c", deny_unknown_fields)]
enum ProtonLabel {
    #[serde(rename = "int")]
    Integer(i64),
    #[serde(rename = "txt")]
    Text(String),
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(tag = "t", content = "c", deny_unknown_fields)]
enum ProtonValue {
    #[serde(rename = "int")]
    Integer(ProtonInteger),
    #[serde(rename = "bytes")]
    Bytes(Vec<u8>),
    #[serde(rename = "float")]
    Float(f64),
    #[serde(rename = "txt")]
    Text(String),
    #[serde(rename = "bool")]
    Bool(bool),
    #[serde(rename = "null")]
    Null,
    #[serde(rename = "tag")]
    Tag(u64, Box<ProtonValue>),
    #[serde(rename = "array")]
    Array(Vec<ProtonValue>),
    #[serde(rename = "map")]
    Map(Vec<(ProtonValue, ProtonValue)>),
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct ProtonInteger {
    inner: Vec<u8>,
}

#[derive(Default, Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct ProtonPassCredentialExtensions {
    hmac_secret: Option<ProtonPassStoredHmacSecret>,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct ProtonPassStoredHmacSecret {
    cred_with_uv: Vec<u8>,
    cred_without_uv: Option<Vec<u8>>,
}

pub fn convert_passkey(
    input: &ProtonPasskeyInput,
    containing_item_epoch: i64,
) -> Result<ConvertedPasskey, PasskeyFailure> {
    let encoded_content = decode_passkey_content(&input.content)?;
    let serialized: SerializedPassKey = decode_messagepack_exact(&encoded_content)?;
    let nested_content = Zeroizing::new(serialized.content);

    if serialized.format_version != 1 {
        return Err(PasskeyFailure::UnsupportedVersion);
    }

    let passkey: ProtonPassKey = decode_messagepack_exact(&nested_content)?;
    if passkey.extensions.hmac_secret.is_some() {
        return Err(PasskeyFailure::PrfExtension);
    }

    validate_metadata(input, &passkey)?;
    validate_key_header(&passkey.key)?;
    let key_material = extract_key_material(&passkey.key)?;
    let secret_key = p256::SecretKey::from_slice(key_material.private_scalar)
        .map_err(|_| PasskeyFailure::InvalidPrivateScalar)?;
    validate_public_key(&secret_key, key_material.x, key_material.y)?;

    let private_key = secret_key
        .to_pkcs8_der()
        .map_err(|_| PasskeyFailure::PrivateKeyEncoding)?;
    let key_value = URL_SAFE_NO_PAD.encode(private_key.as_bytes());
    let user_handle = passkey
        .user_handle
        .as_deref()
        .ok_or(PasskeyFailure::MissingUserHandle)?;
    let (creation_date, used_item_time_fallback) =
        creation_date(input.create_time, containing_item_epoch)?;

    Ok(ConvertedPasskey {
        credential_id: format!("b64.{}", URL_SAFE_NO_PAD.encode(&passkey.credential_id)),
        key_type: "public-key".into(),
        key_algorithm: "ECDSA".into(),
        key_curve: "P-256".into(),
        key_value,
        rp_id: if input.rp_id.is_empty() {
            passkey.rp_id.clone()
        } else {
            input.rp_id.clone()
        },
        user_handle: URL_SAFE_NO_PAD.encode(user_handle),
        user_name: if input.user_name.is_empty() {
            passkey.username.clone().unwrap_or_default()
        } else {
            input.user_name.clone()
        },
        counter: passkey.counter.unwrap_or(0).to_string(),
        rp_name: input.rp_name.clone(),
        user_display_name: if input.user_display_name.is_empty() {
            passkey.user_display_name.clone().unwrap_or_default()
        } else {
            input.user_display_name.clone()
        },
        discoverable: "true".into(),
        creation_date,
        used_item_time_fallback,
        has_unpreserved_creation_data: input.creation_data.is_some(),
        credential_id_bytes: passkey.credential_id.clone(),
    })
}

fn decode_passkey_content(value: &str) -> Result<Zeroizing<Vec<u8>>, PasskeyFailure> {
    if value.len() > MAX_SERIALIZED_PASSKEY_BASE64_BYTES {
        return Err(PasskeyFailure::ResourceLimit);
    }
    let decoded = decode_standard_base64(value)?;
    if decoded.len() > MAX_SERIALIZED_PASSKEY_BYTES {
        return Err(PasskeyFailure::ResourceLimit);
    }
    Ok(decoded)
}

fn decode_standard_base64(value: &str) -> Result<Zeroizing<Vec<u8>>, PasskeyFailure> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|_| PasskeyFailure::InvalidBase64)?,
    );
    if STANDARD.encode(&decoded) != value {
        return Err(PasskeyFailure::InvalidBase64);
    }
    Ok(decoded)
}

fn decode_url_base64(value: &str) -> Result<Zeroizing<Vec<u8>>, PasskeyFailure> {
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| PasskeyFailure::InvalidBase64)?,
    );
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(PasskeyFailure::InvalidBase64);
    }
    Ok(decoded)
}

fn decode_messagepack_exact<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, PasskeyFailure> {
    let mut cursor = Cursor::new(bytes);
    let value = {
        let mut deserializer = rmp_serde::Deserializer::new(&mut cursor);
        deserializer.set_max_depth(MAX_MESSAGEPACK_DEPTH);
        T::deserialize(&mut deserializer).map_err(|_| PasskeyFailure::MalformedOrUnknownField)?
    };
    if cursor.position() != bytes.len() as u64 {
        return Err(PasskeyFailure::TrailingMessagePack);
    }
    Ok(value)
}

fn validate_metadata(
    input: &ProtonPasskeyInput,
    passkey: &ProtonPassKey,
) -> Result<(), PasskeyFailure> {
    let credential_id = (!input.credential_id.is_empty())
        .then(|| decode_standard_base64(&input.credential_id))
        .transpose()?;
    let key_id = (!input.key_id.is_empty())
        .then(|| decode_url_base64(&input.key_id))
        .transpose()?;
    let outer_user_handle = (!input.user_handle.is_empty())
        .then(|| decode_standard_base64(&input.user_handle))
        .transpose()?;
    let outer_user_id = (!input.user_id.is_empty())
        .then(|| decode_standard_base64(&input.user_id))
        .transpose()?;
    let inner_user_handle = passkey
        .user_handle
        .as_deref()
        .filter(|handle| !handle.is_empty())
        .ok_or(PasskeyFailure::MissingUserHandle)?;
    let user_name = if input.user_name.is_empty() {
        passkey.username.as_deref().unwrap_or_default()
    } else {
        &input.user_name
    };
    let user_display_name = if input.user_display_name.is_empty() {
        passkey.user_display_name.as_deref().unwrap_or_default()
    } else {
        &input.user_display_name
    };

    if passkey.credential_id.is_empty()
        || credential_id
            .as_deref()
            .is_some_and(|value| value.as_slice() != passkey.credential_id.as_slice())
        || key_id
            .as_deref()
            .is_some_and(|value| value.as_slice() != passkey.credential_id.as_slice())
        || outer_user_handle
            .as_deref()
            .is_some_and(|value| value.as_slice() != inner_user_handle)
        || outer_user_id
            .as_deref()
            .is_some_and(|value| value.as_slice() != inner_user_handle)
        || passkey.rp_id.is_empty()
        || input.rp_name.is_empty()
        || (!input.rp_id.is_empty() && input.rp_id != passkey.rp_id)
        || passkey
            .username
            .as_deref()
            .filter(|username| !username.is_empty())
            .is_some_and(|username| !input.user_name.is_empty() && username != input.user_name)
        || passkey
            .user_display_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .is_some_and(|name| {
                !input.user_display_name.is_empty() && name != input.user_display_name
            })
    {
        return Err(PasskeyFailure::MetadataMismatch);
    }
    if passkey.credential_id.len() > MAX_CREDENTIAL_ID_BYTES
        || inner_user_handle.len() > MAX_USER_HANDLE_BYTES
        || passkey.rp_id.len() > MAX_RP_ID_BYTES
        || input.rp_name.len() > MAX_LABEL_BYTES
        || user_name.len() > MAX_LABEL_BYTES
        || user_display_name.len() > MAX_LABEL_BYTES
    {
        return Err(PasskeyFailure::ResourceLimit);
    }
    Ok(())
}

fn validate_key_header(key: &ProtonKey) -> Result<(), PasskeyFailure> {
    if key.key_type.tag != "assign" || key.key_type.content != "EC2" {
        return Err(PasskeyFailure::UnsupportedKeyType);
    }
    let Some(algorithm) = &key.algorithm else {
        return Err(PasskeyFailure::UnsupportedAlgorithm);
    };
    if algorithm.tag != "assign"
        || !matches!(&algorithm.content, TaggedAlgorithmContent::Text(value) if value == "ES256")
    {
        return Err(PasskeyFailure::UnsupportedAlgorithm);
    }
    if !key.key_id.is_empty()
        || !key.base_iv.is_empty()
        || key
            .key_operations
            .iter()
            .any(|operation| operation.tag != "assign" || operation.content != "Sign")
    {
        return Err(PasskeyFailure::UnsupportedKeyMetadata);
    }
    Ok(())
}

struct KeyMaterial<'a> {
    x: &'a [u8],
    y: &'a [u8],
    private_scalar: &'a [u8],
}

fn extract_key_material(key: &ProtonKey) -> Result<KeyMaterial<'_>, PasskeyFailure> {
    let mut curve = None;
    let mut x = None;
    let mut y = None;
    let mut private_scalar = None;

    for (label, value) in &key.parameters {
        let ProtonLabel::Integer(label) = label else {
            return Err(PasskeyFailure::UnknownKeyParameter);
        };
        match *label {
            -1 => set_once(&mut curve, parse_integer(value)?)?,
            -2 => set_once(&mut x, parse_bytes(value)?)?,
            -3 => set_once(&mut y, parse_bytes(value)?)?,
            -4 => set_once(&mut private_scalar, parse_bytes(value)?)?,
            _ => return Err(PasskeyFailure::UnknownKeyParameter),
        }
    }

    let curve = curve.ok_or(PasskeyFailure::MissingKeyParameter)?;
    if curve != 1 {
        return Err(PasskeyFailure::UnsupportedCurve);
    }
    let x = x.ok_or(PasskeyFailure::MissingKeyParameter)?;
    let y = y.ok_or(PasskeyFailure::MissingKeyParameter)?;
    let private_scalar = private_scalar.ok_or(PasskeyFailure::MissingKeyParameter)?;
    if x.len() != 32 || y.len() != 32 || private_scalar.len() != 32 {
        return Err(PasskeyFailure::InvalidKeyParameter);
    }

    Ok(KeyMaterial {
        x,
        y,
        private_scalar,
    })
}

fn set_once<T>(destination: &mut Option<T>, value: T) -> Result<(), PasskeyFailure> {
    if destination.replace(value).is_some() {
        return Err(PasskeyFailure::DuplicateKeyParameter);
    }
    Ok(())
}

fn parse_integer(value: &ProtonValue) -> Result<i128, PasskeyFailure> {
    let ProtonValue::Integer(value) = value else {
        return Err(PasskeyFailure::InvalidKeyParameter);
    };
    let bytes: [u8; 16] = value
        .inner
        .as_slice()
        .try_into()
        .map_err(|_| PasskeyFailure::InvalidKeyParameter)?;
    Ok(i128::from_le_bytes(bytes))
}

fn parse_bytes(value: &ProtonValue) -> Result<&[u8], PasskeyFailure> {
    let ProtonValue::Bytes(value) = value else {
        return Err(PasskeyFailure::InvalidKeyParameter);
    };
    Ok(value)
}

fn validate_public_key(
    secret_key: &p256::SecretKey,
    expected_x: &[u8],
    expected_y: &[u8],
) -> Result<(), PasskeyFailure> {
    let encoded = secret_key.public_key().to_encoded_point(false);
    let Some(x) = encoded.x() else {
        return Err(PasskeyFailure::InvalidKeyParameter);
    };
    let Some(y) = encoded.y() else {
        return Err(PasskeyFailure::InvalidKeyParameter);
    };
    if &x[..] != expected_x || &y[..] != expected_y {
        return Err(PasskeyFailure::PublicKeyMismatch);
    }
    Ok(())
}

fn creation_date(
    passkey_epoch: Option<i64>,
    containing_item_epoch: i64,
) -> Result<(String, bool), PasskeyFailure> {
    if let Some(date) = passkey_epoch.and_then(format_epoch) {
        return Ok((date, false));
    }
    format_epoch(containing_item_epoch)
        .map(|date| (date, true))
        .ok_or(PasskeyFailure::InvalidTimestamp)
}

fn format_epoch(epoch: i64) -> Option<String> {
    if epoch <= 0 {
        return None;
    }
    let date = OffsetDateTime::from_unix_timestamp(epoch).ok()?;
    if !(1..=9999).contains(&date.year()) {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        date.year(),
        u8::from(date.month()),
        date.day(),
        date.hour(),
        date.minute(),
        date.second()
    ))
}

#[cfg(test)]
mod tests {
    use p256::pkcs8::DecodePrivateKey;
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    use super::*;

    const PROTON_WEBCLIENTS_FIXTURE_REPOSITORY: &str = "https://github.com/ProtonMail/WebClients";
    const PROTON_WEBCLIENTS_FIXTURE_COMMIT: &str = "1ee27e1b54a4a3d0462ca1e35051bc58a0c4ac7b";
    const PROTON_WEBCLIENTS_FIXTURE_PATH: &str =
        "packages/pass/lib/import/providers/protonpass/mocks/protonpass.zip:Proton Pass/data.json";
    const PROTON_WEBCLIENTS_FIXTURE_LICENSE: &str = "GPL-3.0-or-later";
    const PROTON_WEBCLIENTS_PASSKEY_CONTENT: &str = "gqFj3AGxzIXMo2tlecyGzKNrdHnMgsyhdMymYXNzaWduzKFjzKNFQzLMo2tpZMyQzKNhbGfMgsyhdMymYXNzaWduzKFjzKVFUzI1Nsyka29wc8yQzKNiaXbMkMyjcGFyzJTMksyCzKF0zKNpbnTMoWPM/8yCzKF0zKNpbnTMoWPMgcylaW5uZXLM3AAQAQAAAAAAAAAAAAAAAAAAAMySzILMoXTMo2ludMyhY8z+zILMoXTMpWJ5dGVzzKFjzNwAIMzMzM/MzMygKMzMzN9rzMzMrszMzPFPzMzM1ArMzMyOdszMzPxfQMzMzILMzMzdzMzMqVjMzMyyzMzM8kAAzMzM6nXMzMzjFczMzLUazMzM51AfzJLMgsyhdMyjaW50zKFjzP3MgsyhdMylYnl0ZXPMoWPM3AAgMXFgzMzM2MzMzLEeZkIAzMzMykVuKVk1zMzMxi/MzMyoaMzMzI/MzMzxzMzM0szMzLHMzMz+zMzM2czMzLIczMzMqMzMzJ/MzMzACF7MksyCzKF0zKNpbnTMoWPM/MyCzKF0zKVieXRlc8yhY8zcACAyF8zMzLfMzMyYzMzM/gjMzMy7HzAnJczMzN4veAQIY8zMzO7MzMyedszMzNNXZ2UeCMzMzJ/MzMzYzMzMwDA0XMyjY2lkzNwAEGEXcszMzIo+zMzM0czMzLLMzMypzMzMnMzMzPBBH8zMzK3MzMyOzMzMrszMzNzMo3JpZMyrd2ViYXV0aG4uaW/Mo3VoZMzcACtqRVdtTE5HVndtYXozdk15YVd6SW16ejFFRWxOUDVvUXhWSnlld3hubjNFzKNjbnTMwKF2AQ==";
    const PROTON_COMMON_SERIALIZED_V1: &str = "gqFj3AF1zIXMo2tlecyGzKNrdHnMgsyhdMymYXNzaWduzKFjzKNFQzLMo2tpZMyTAQIDzKNhbGfMwMyka29wc8yRzILMoXTMo3R4dMyhY8ykc29tZcyjYml2zJMBAgPMo3BhcsyUzJLMgsyhdMyjdHh0zKFjzKVsYWJlbMyCzKF0zKNpbnTMoWPMgcylaW5uZXLM3AAQQMzMzOIBAAAAAAAAAAAAAAAAAMySzILMoXTMo2ludMyhY8zOB1vMzRXMgsyhdMylYXJyYXnMoWPMksyCzKF0zKN0eHTMoWPMp2EgdmFsdWXMgsyhdMylYnl0ZXPMoWPMkwECA8ySzILMoXTMo3R4dMyhY8ysdmFsdWUgaXMgdGFnzILMoXTMo3RhZ8yhY8ySNsyCzKF0zKRib29szKFjzMPMksyCzKF0zKN0eHTMoWPMrHZhbHVlIGlzIG1hcMyCzKF0zKNtYXDMoWPMksySzILMoXTMpWZsb2F0zKFjzMs/zPPMvnbMyMy0OVjMgsyhdMykYm9vbMyhY8zCzJLMgsyhdMyjaW50zKFjzIHMpWlubmVyzNwAEMzMzNsDAAAAAAAAAAAAAAAAAADMgcyhdMykbnVsbMyjY2lkzJUBAgMEBcyjcmlkzKpzb21lX3JwX2lkzKN1aGTMwMyjY250zMChdgE=";
    const PROTON_COMMON_SERIALIZED_V2: &str = "gqFj3AGuzIbMo2tlecyGzKNrdHnMgsyhdMymYXNzaWduzKFjzKNFQzLMo2tpZMyTAQIDzKNhbGfMwMyka29wc8yRzILMoXTMo3R4dMyhY8ykc29tZcyjYml2zJMBAgPMo3BhcsyUzJLMgsyhdMyjdHh0zKFjzKVsYWJlbMyCzKF0zKNpbnTMoWPMgcylaW5uZXLM3AAQQMzMzOIBAAAAAAAAAAAAAAAAAMySzILMoXTMo2ludMyhY8zOB1vMzRXMgsyhdMylYXJyYXnMoWPMksyCzKF0zKN0eHTMoWPMp2EgdmFsdWXMgsyhdMylYnl0ZXPMoWPMkwECA8ySzILMoXTMo3R4dMyhY8ysdmFsdWUgaXMgdGFnzILMoXTMo3RhZ8yhY8ySNsyCzKF0zKRib29szKFjzMPMksyCzKF0zKN0eHTMoWPMrHZhbHVlIGlzIG1hcMyCzKF0zKNtYXDMoWPMksySzILMoXTMpWZsb2F0zKFjzMs/zPPMvnbMyMy0OVjMgsyhdMykYm9vbMyhY8zCzJLMgsyhdMyjaW50zKFjzIHMpWlubmVyzNwAEMzMzNsDAAAAAAAAAAAAAAAAAADMgcyhdMykbnVsbMyjY2lkzJUBAgMEBcyjcmlkzKpzb21lX3JwX2lkzKN1aGTMwMyjY250zMDMo2V4dMyBzKtobWFjX3NlY3JldMyCzKxjcmVkX3dpdGhfdXbMlAECAwTMr2NyZWRfd2l0aG91dF91dsyUBQYHCKF2AQ==";
    const PROTON_COMMON_SERIALIZED_V3: &str = "gqFj3AHQzIjMo2tlecyGzKNrdHnMgsyhdMymYXNzaWduzKFjzKNFQzLMo2tpZMyTAQIDzKNhbGfMwMyka29wc8yRzILMoXTMo3R4dMyhY8ykc29tZcyjYml2zJMBAgPMo3BhcsyUzJLMgsyhdMyjdHh0zKFjzKVsYWJlbMyCzKF0zKNpbnTMoWPMgcylaW5uZXLM3AAQQMzMzOIBAAAAAAAAAAAAAAAAAMySzILMoXTMo2ludMyhY8zOB1vMzRXMgsyhdMylYXJyYXnMoWPMksyCzKF0zKN0eHTMoWPMp2EgdmFsdWXMgsyhdMylYnl0ZXPMoWPMkwECA8ySzILMoXTMo3R4dMyhY8ysdmFsdWUgaXMgdGFnzILMoXTMo3RhZ8yhY8ySNsyCzKF0zKRib29szKFjzMPMksyCzKF0zKN0eHTMoWPMrHZhbHVlIGlzIG1hcMyCzKF0zKNtYXDMoWPMksySzILMoXTMpWZsb2F0zKFjzMs/zPPMvnbMyMy0OVjMgsyhdMykYm9vbMyhY8zCzJLMgsyhdMyjaW50zKFjzIHMpWlubmVyzNwAEMzMzNsDAAAAAAAAAAAAAAAAAADMgcyhdMykbnVsbMyjY2lkzJUBAgMEBcyjcmlkzKpzb21lX3JwX2lkzKN1aGTMwMyjY250zMDMo2V4dMyBzKtobWFjX3NlY3JldMyCzKxjcmVkX3dpdGhfdXbMlAECAwTMr2NyZWRfd2l0aG91dF91dsyUBQYHCMyjdWRuzLF1c2VyX2Rpc3BsYXlfbmFtZcyidW7MqHVzZXJuYW1loXYB";

    struct Fixture {
        input: ProtonPasskeyInput,
        inner: ProtonPassKey,
    }

    fn make_fixture() -> Fixture {
        let scalar = vec![1; 32];
        let secret =
            p256::SecretKey::from_slice(&scalar).expect("synthetic scalar should be valid");
        let point = secret.public_key().to_encoded_point(false);
        let x = point
            .x()
            .expect("uncompressed point should have x")
            .to_vec();
        let y = point
            .y()
            .expect("uncompressed point should have y")
            .to_vec();
        let credential_id = vec![7, 8, 9, 10, 11, 12];
        let user_handle = b"synthetic-user-handle".to_vec();
        let inner = ProtonPassKey {
            key: ProtonKey {
                key_type: TaggedString {
                    tag: "assign".into(),
                    content: "EC2".into(),
                },
                key_id: Vec::new(),
                algorithm: Some(TaggedAlgorithm {
                    tag: "assign".into(),
                    content: TaggedAlgorithmContent::Text("ES256".into()),
                }),
                key_operations: Vec::new(),
                base_iv: Vec::new(),
                parameters: vec![
                    (
                        ProtonLabel::Integer(-1),
                        ProtonValue::Integer(ProtonInteger {
                            inner: 1_i128.to_le_bytes().to_vec(),
                        }),
                    ),
                    (ProtonLabel::Integer(-2), ProtonValue::Bytes(x)),
                    (ProtonLabel::Integer(-3), ProtonValue::Bytes(y)),
                    (ProtonLabel::Integer(-4), ProtonValue::Bytes(scalar)),
                ],
            },
            credential_id: credential_id.clone(),
            rp_id: "example.test".into(),
            user_handle: Some(user_handle.clone()),
            counter: Some(42),
            extensions: ProtonPassCredentialExtensions::default(),
            user_display_name: Some("Synthetic User".into()),
            username: Some("synthetic@example.test".into()),
        };
        let input = input_for(&inner, 1);
        Fixture { input, inner }
    }

    fn input_for(inner: &ProtonPassKey, version: u64) -> ProtonPasskeyInput {
        let nested = rmp_serde::to_vec_named(inner).expect("fixture should serialize");
        let outer = rmp_serde::to_vec_named(&SerializedPassKey {
            content: nested,
            format_version: version,
        })
        .expect("fixture should serialize");
        let credential_id = inner.credential_id.clone();
        let user_handle = inner.user_handle.clone().unwrap_or_default();
        ProtonPasskeyInput {
            key_id: URL_SAFE_NO_PAD.encode(&credential_id),
            content: STANDARD.encode(outer),
            domain: "example.test".into(),
            rp_id: inner.rp_id.clone(),
            rp_name: "Example".into(),
            user_name: inner.username.clone().unwrap_or_default(),
            user_display_name: inner.user_display_name.clone().unwrap_or_default(),
            user_id: STANDARD.encode(&user_handle),
            create_time: Some(1_767_225_600),
            note: String::new(),
            credential_id: STANDARD.encode(&credential_id),
            user_handle: STANDARD.encode(&user_handle),
            creation_data: None,
        }
    }

    fn rebuild_input(fixture: &mut Fixture) {
        fixture.input = input_for(&fixture.inner, 1);
    }

    fn official_proton_webclients_input() -> ProtonPasskeyInput {
        ProtonPasskeyInput {
            key_id: "YRdyij7Rsqmc8EEfrY6u3A".into(),
            content: PROTON_WEBCLIENTS_PASSKEY_CONTENT.into(),
            domain: "webauthn.io".into(),
            rp_id: "webauthn.io".into(),
            rp_name: "webauthn.io".into(),
            user_name: "yo".into(),
            user_display_name: "yo".into(),
            user_id: "akVXbUxOR1Z3bWF6M3ZNeWFXekltenoxRUVsTlA1b1F4Vkp5ZXd4bm4zRQ==".into(),
            create_time: Some(1_714_982_805),
            note: String::new(),
            credential_id: "YRdyij7Rsqmc8EEfrY6u3A==".into(),
            user_handle: "akVXbUxOR1Z3bWF6M3ZNeWFXekltenoxRUVsTlA1b1F4Vkp5ZXd4bm4zRQ==".into(),
            creation_data: None,
        }
    }

    #[test]
    fn official_proton_webclients_gpl_3_or_later_fixture_at_pinned_commit_converts() {
        assert_eq!(
            (
                PROTON_WEBCLIENTS_FIXTURE_REPOSITORY,
                PROTON_WEBCLIENTS_FIXTURE_COMMIT,
                PROTON_WEBCLIENTS_FIXTURE_PATH,
                PROTON_WEBCLIENTS_FIXTURE_LICENSE,
            ),
            (
                "https://github.com/ProtonMail/WebClients",
                "1ee27e1b54a4a3d0462ca1e35051bc58a0c4ac7b",
                "packages/pass/lib/import/providers/protonpass/mocks/protonpass.zip:Proton Pass/data.json",
                "GPL-3.0-or-later",
            )
        );

        let converted = convert_passkey(&official_proton_webclients_input(), 1_714_982_805)
            .expect("official fixture should convert");
        let content = STANDARD
            .decode(PROTON_WEBCLIENTS_PASSKEY_CONTENT)
            .expect("transcribed fixture payload should be base64");
        assert_eq!(
            format!("{:x}", Sha256::digest(content)),
            "cf2c1a886b910fbbb490111334a6babfff6f23fed7b82e3f72ebb21df4e6860e"
        );
        assert_eq!(converted.credential_id, "b64.YRdyij7Rsqmc8EEfrY6u3A");
        assert_eq!(converted.rp_id, "webauthn.io");
        assert_eq!(
            converted.user_handle,
            "akVXbUxOR1Z3bWF6M3ZNeWFXekltenoxRUVsTlA1b1F4Vkp5ZXd4bm4zRQ"
        );
        assert_eq!(converted.user_name, "yo");
        assert_eq!(converted.user_display_name, "yo");
        assert_eq!(converted.counter, "0");
        assert_eq!(converted.creation_date, "2024-05-06T08:06:45.000Z");
        assert!(!converted.used_item_time_fallback);

        let der = URL_SAFE_NO_PAD
            .decode(&converted.key_value)
            .expect("official fixture key should be base64url");
        assert_eq!(
            format!("{:x}", Sha256::digest(der)),
            "b11a2fba5dfff80cdfd9ee13004599393a28b2edcb2ee2986aec73eb33908c9a"
        );
    }

    #[test]
    fn decodes_published_proton_common_v1_v2_v3_regressions() {
        for (encoded, has_extension, username) in [
            (PROTON_COMMON_SERIALIZED_V1, false, None),
            (PROTON_COMMON_SERIALIZED_V2, true, None),
            (PROTON_COMMON_SERIALIZED_V3, true, Some("username")),
        ] {
            let bytes = STANDARD.decode(encoded).expect("published fixture base64");
            let outer: SerializedPassKey =
                decode_messagepack_exact(&bytes).expect("published outer MessagePack");
            assert_eq!(outer.format_version, 1);
            let inner: ProtonPassKey =
                decode_messagepack_exact(&outer.content).expect("published inner MessagePack");
            assert_eq!(inner.credential_id, [1, 2, 3, 4, 5]);
            assert_eq!(inner.rp_id, "some_rp_id");
            assert_eq!(inner.extensions.hmac_secret.is_some(), has_extension);
            assert_eq!(inner.username.as_deref(), username);
        }
    }

    #[test]
    fn converts_es256_key_and_preserves_fields() {
        let fixture = make_fixture();
        let converted =
            convert_passkey(&fixture.input, 1_700_000_000).expect("fixture should convert");
        assert_eq!(converted.credential_id, "b64.BwgJCgsM");
        assert_eq!(converted.key_type, "public-key");
        assert_eq!(converted.key_algorithm, "ECDSA");
        assert_eq!(converted.key_curve, "P-256");
        assert_eq!(converted.rp_id, "example.test");
        assert_eq!(converted.user_handle, "c3ludGhldGljLXVzZXItaGFuZGxl");
        assert_eq!(converted.user_name, "synthetic@example.test");
        assert_eq!(converted.counter, "42");
        assert_eq!(converted.rp_name, "Example");
        assert_eq!(converted.user_display_name, "Synthetic User");
        assert_eq!(converted.discoverable, "true");
        assert_eq!(converted.creation_date, "2026-01-01T00:00:00.000Z");
        assert!(!converted.used_item_time_fallback);

        let der = URL_SAFE_NO_PAD
            .decode(&converted.key_value)
            .expect("generated key should be base64url");
        let decoded =
            p256::SecretKey::from_pkcs8_der(&der).expect("generated key should be PKCS#8");
        assert_eq!(decoded.to_bytes()[..], [1; 32]);
    }

    #[test]
    fn rejects_unknown_outer_version_and_trailing_data() {
        let fixture = make_fixture();
        let input = input_for(&fixture.inner, 2);
        assert_eq!(
            convert_passkey(&input, 1_700_000_000).err(),
            Some(PasskeyFailure::UnsupportedVersion)
        );

        let mut raw = STANDARD
            .decode(&fixture.input.content)
            .expect("fixture base64");
        raw.push(0);
        let mut input = input_for(&fixture.inner, 1);
        input.content = STANDARD.encode(raw);
        assert_eq!(
            convert_passkey(&input, 1_700_000_000).err(),
            Some(PasskeyFailure::TrailingMessagePack)
        );

        let mut nested = rmp_serde::to_vec_named(&fixture.inner).expect("fixture should serialize");
        nested.push(0);
        let outer = rmp_serde::to_vec_named(&SerializedPassKey {
            content: nested,
            format_version: 1,
        })
        .expect("fixture should serialize");
        let mut input = input_for(&fixture.inner, 1);
        input.content = STANDARD.encode(outer);
        assert_eq!(
            convert_passkey(&input, 1_700_000_000).err(),
            Some(PasskeyFailure::TrailingMessagePack)
        );
    }

    #[test]
    fn rejects_unknown_messagepack_fields() {
        #[derive(Serialize)]
        struct OuterWithUnknown {
            #[serde(rename = "c")]
            content: Vec<u8>,
            #[serde(rename = "v")]
            version: u64,
            unknown: u8,
        }

        let fixture = make_fixture();
        let nested = rmp_serde::to_vec_named(&fixture.inner).expect("fixture should serialize");
        let outer = rmp_serde::to_vec_named(&OuterWithUnknown {
            content: nested,
            version: 1,
            unknown: 1,
        })
        .expect("fixture should serialize");
        let mut input = input_for(&fixture.inner, 1);
        input.content = STANDARD.encode(outer);
        assert_eq!(
            convert_passkey(&input, 1_700_000_000).err(),
            Some(PasskeyFailure::MalformedOrUnknownField)
        );
    }

    #[test]
    fn rejects_oversized_and_excessively_nested_content() {
        let fixture = make_fixture();
        let mut input = input_for(&fixture.inner, 1);
        input.content = STANDARD.encode(vec![0; MAX_SERIALIZED_PASSKEY_BYTES + 1]);
        assert_eq!(
            convert_passkey(&input, 1_700_000_000).err(),
            Some(PasskeyFailure::ResourceLimit)
        );

        let mut fixture = make_fixture();
        let mut nested = ProtonValue::Null;
        for _ in 0..=MAX_MESSAGEPACK_DEPTH {
            nested = ProtonValue::Tag(1, Box::new(nested));
        }
        fixture.inner.key.parameters[1].1 = nested;
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::MalformedOrUnknownField)
        );
    }

    #[test]
    fn rejects_hmac_secret() {
        let mut fixture = make_fixture();
        fixture.inner.extensions.hmac_secret = Some(ProtonPassStoredHmacSecret {
            cred_with_uv: vec![3; 32],
            cred_without_uv: None,
        });
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::PrfExtension)
        );
    }

    #[test]
    fn rejects_each_mismatched_duplicate_metadata_field() {
        let mutations: [fn(&mut ProtonPasskeyInput); 7] = [
            |input| input.credential_id = STANDARD.encode([99]),
            |input| input.key_id = URL_SAFE_NO_PAD.encode([99]),
            |input| input.user_handle = STANDARD.encode([99]),
            |input| input.user_id = STANDARD.encode([99]),
            |input| input.user_name = "different-user".into(),
            |input| input.user_display_name = "Different User".into(),
            |input| input.rp_id = "different.test".into(),
        ];

        for mutate in mutations {
            let mut fixture = make_fixture();
            mutate(&mut fixture.input);
            assert_eq!(
                convert_passkey(&fixture.input, 1_700_000_000).err(),
                Some(PasskeyFailure::MetadataMismatch)
            );
        }
    }

    #[test]
    fn accepts_origin_domain_that_is_more_specific_than_rp_id() {
        let mut fixture = make_fixture();
        fixture.input.domain = "login.example.test".into();

        let converted = convert_passkey(&fixture.input, 1_700_000_000)
            .expect("origin host can differ from RP ID");
        assert_eq!(converted.rp_id, "example.test");
    }

    #[test]
    fn rejects_missing_duplicate_and_wrong_sized_parameters() {
        let mut fixture = make_fixture();
        fixture.inner.key.parameters.pop();
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::MissingKeyParameter)
        );

        let mut fixture = make_fixture();
        fixture.inner.key.parameters.push((
            ProtonLabel::Integer(-1),
            ProtonValue::Integer(ProtonInteger {
                inner: 1_i128.to_le_bytes().to_vec(),
            }),
        ));
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::DuplicateKeyParameter)
        );

        let mut fixture = make_fixture();
        fixture.inner.key.parameters[1].1 = ProtonValue::Bytes(vec![1; 31]);
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::InvalidKeyParameter)
        );
    }

    #[test]
    fn rejects_invalid_scalar_public_mismatch_and_missing_handle() {
        let mut fixture = make_fixture();
        fixture.inner.key.parameters[3].1 = ProtonValue::Bytes(vec![0; 32]);
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::InvalidPrivateScalar)
        );

        let mut fixture = make_fixture();
        fixture.inner.key.parameters[1].1 = ProtonValue::Bytes(vec![4; 32]);
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::PublicKeyMismatch)
        );

        let mut fixture = make_fixture();
        fixture.inner.user_handle = None;
        fixture.input = input_for(&fixture.inner, 1);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::MissingUserHandle)
        );
    }

    #[test]
    fn uses_valid_item_time_only_when_passkey_time_is_invalid() {
        let mut fixture = make_fixture();
        fixture.input.create_time = Some(0);
        let converted =
            convert_passkey(&fixture.input, 1_704_067_200).expect("item time should be used");
        assert_eq!(converted.creation_date, "2024-01-01T00:00:00.000Z");
        assert!(converted.used_item_time_fallback);

        fixture.input.create_time = None;
        assert_eq!(
            convert_passkey(&fixture.input, 0).err(),
            Some(PasskeyFailure::InvalidTimestamp)
        );
    }

    #[test]
    fn rejects_unsupported_headers_and_curve() {
        let mut fixture = make_fixture();
        fixture.inner.key.key_id = vec![1];
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::UnsupportedKeyMetadata)
        );

        let mut fixture = make_fixture();
        fixture.inner.key.key_type.content = "RSA".into();
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::UnsupportedKeyType)
        );

        let mut fixture = make_fixture();
        fixture.inner.key.algorithm = Some(TaggedAlgorithm {
            tag: "assign".into(),
            content: TaggedAlgorithmContent::Text("EdDSA".into()),
        });
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::UnsupportedAlgorithm)
        );

        let mut fixture = make_fixture();
        fixture.inner.key.parameters[0].1 = ProtonValue::Integer(ProtonInteger {
            inner: 2_i128.to_le_bytes().to_vec(),
        });
        rebuild_input(&mut fixture);
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::UnsupportedCurve)
        );
    }

    #[test]
    fn deterministic_scalars_round_trip_through_pkcs8() {
        for byte in [1_u8, 2, 7, 19, 63] {
            let mut fixture = make_fixture();
            let scalar = vec![byte; 32];
            let secret =
                p256::SecretKey::from_slice(&scalar).expect("synthetic scalar should be valid");
            let point = secret.public_key().to_encoded_point(false);
            fixture.inner.key.parameters[1].1 =
                ProtonValue::Bytes(point.x().expect("point x").to_vec());
            fixture.inner.key.parameters[2].1 =
                ProtonValue::Bytes(point.y().expect("point y").to_vec());
            fixture.inner.key.parameters[3].1 = ProtonValue::Bytes(scalar.clone());
            rebuild_input(&mut fixture);

            let converted =
                convert_passkey(&fixture.input, 1_700_000_000).expect("fixture should convert");
            let der = URL_SAFE_NO_PAD
                .decode(&converted.key_value)
                .expect("generated key should be base64url");
            let decoded =
                p256::SecretKey::from_pkcs8_der(&der).expect("generated key should be PKCS#8");
            assert_eq!(decoded.to_bytes()[..], scalar[..]);
        }
    }

    #[test]
    fn accepts_absent_outer_metadata_when_inner_values_are_present() {
        let mut fixture = make_fixture();
        fixture.input.key_id.clear();
        fixture.input.credential_id.clear();
        fixture.input.user_handle.clear();
        fixture.input.user_id.clear();
        fixture.input.rp_id.clear();
        fixture.input.user_name.clear();
        fixture.input.user_display_name.clear();

        let converted =
            convert_passkey(&fixture.input, 1_700_000_000).expect("inner metadata should be used");
        assert_eq!(converted.credential_id, "b64.BwgJCgsM");
        assert_eq!(converted.rp_id, "example.test");
        assert_eq!(converted.user_name, "synthetic@example.test");
        assert_eq!(converted.user_display_name, "Synthetic User");
    }

    #[test]
    fn accepts_validator_field_size_boundaries() {
        let mut fixture = make_fixture();
        fixture.inner.credential_id = vec![7; MAX_CREDENTIAL_ID_BYTES];
        fixture.inner.user_handle = Some(vec![8; MAX_USER_HANDLE_BYTES]);
        fixture.inner.rp_id = "r".repeat(MAX_RP_ID_BYTES);
        fixture.inner.username = Some("é".repeat(MAX_LABEL_BYTES / 2));
        fixture.inner.user_display_name = Some("d".repeat(MAX_LABEL_BYTES));
        rebuild_input(&mut fixture);
        fixture.input.rp_name = "n".repeat(MAX_LABEL_BYTES);

        let converted = convert_passkey(&fixture.input, 1_700_000_000)
            .expect("validator field boundaries should convert");
        assert_eq!(converted.credential_id_bytes.len(), MAX_CREDENTIAL_ID_BYTES);
        assert_eq!(converted.rp_id.len(), MAX_RP_ID_BYTES);
        assert_eq!(converted.rp_name.len(), MAX_LABEL_BYTES);
        assert_eq!(converted.user_name.len(), MAX_LABEL_BYTES);
        assert_eq!(converted.user_display_name.len(), MAX_LABEL_BYTES);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&converted.user_handle)
                .expect("converted user handle should be base64url")
                .len(),
            MAX_USER_HANDLE_BYTES
        );
    }

    #[test]
    fn rejects_each_validator_field_above_its_size_boundary() {
        let mutations: [fn(&mut Fixture); 6] = [
            |fixture| {
                fixture.inner.credential_id = vec![7; MAX_CREDENTIAL_ID_BYTES + 1];
                rebuild_input(fixture);
            },
            |fixture| {
                fixture.inner.user_handle = Some(vec![8; MAX_USER_HANDLE_BYTES + 1]);
                rebuild_input(fixture);
            },
            |fixture| {
                fixture.inner.rp_id = "r".repeat(MAX_RP_ID_BYTES + 1);
                rebuild_input(fixture);
            },
            |fixture| fixture.input.rp_name = "n".repeat(MAX_LABEL_BYTES + 1),
            |fixture| {
                fixture.inner.username = Some(format!("{}a", "é".repeat(MAX_LABEL_BYTES / 2)));
                rebuild_input(fixture);
            },
            |fixture| {
                fixture.inner.user_display_name = Some("d".repeat(MAX_LABEL_BYTES + 1));
                rebuild_input(fixture);
            },
        ];

        for mutate in mutations {
            let mut fixture = make_fixture();
            mutate(&mut fixture);
            assert_eq!(
                convert_passkey(&fixture.input, 1_700_000_000).err(),
                Some(PasskeyFailure::ResourceLimit)
            );
        }
    }

    #[test]
    fn rejects_missing_rp_name() {
        let mut fixture = make_fixture();
        fixture.input.rp_name.clear();
        assert_eq!(
            convert_passkey(&fixture.input, 1_700_000_000).err(),
            Some(PasskeyFailure::MetadataMismatch)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_valid_scalars_round_trip(scalar in any::<[u8; 32]>()) {
            let secret = p256::SecretKey::from_slice(&scalar);
            prop_assume!(secret.is_ok());
            let secret = secret.expect("assumption checked");
            let point = secret.public_key().to_encoded_point(false);
            let mut fixture = make_fixture();
            fixture.inner.key.parameters[1].1 =
                ProtonValue::Bytes(point.x().expect("point x").to_vec());
            fixture.inner.key.parameters[2].1 =
                ProtonValue::Bytes(point.y().expect("point y").to_vec());
            fixture.inner.key.parameters[3].1 = ProtonValue::Bytes(scalar.to_vec());
            rebuild_input(&mut fixture);

            let converted = convert_passkey(&fixture.input, 1_700_000_000)
                .expect("valid scalar should convert");
            let der = URL_SAFE_NO_PAD.decode(&converted.key_value)
                .expect("generated key should be base64url");
            let decoded = p256::SecretKey::from_pkcs8_der(&der)
                .expect("generated key should be PKCS#8");
            prop_assert_eq!(&decoded.to_bytes()[..], &scalar);
        }

        #[test]
        fn arbitrary_messagepack_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let mut fixture = make_fixture();
            fixture.input.content = STANDARD.encode(bytes);
            let _ = convert_passkey(&fixture.input, 1_700_000_000);
        }
    }
}
