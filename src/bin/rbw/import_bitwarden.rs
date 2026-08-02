// Parsing for upstream Bitwarden vault exports, as opposed to the
// `rbw export` shape that `commands::import` originally supported.
// Bitwarden's web/desktop/CLI clients offer several export formats:
//
// - "JSON": plain JSON, `{"folders": [...], "collections": [...], "items":
//   [...]}` -- a different schema from `rbw export`'s
//   `{"entries": [...], "collections": [...]}`.
// - "Encrypted JSON" (password protected): the same JSON payload, symmetric-
//   encrypted with a key derived from a password and an embedded KDF
//   config/salt -- unrelated to rbw's own gpg-based `--encrypt`.
// - "zip (with attachments)": a zip archive containing the JSON above plus
//   the decrypted attachment files under `attachments/<item id>/...`.
//
// This module only turns any of those into a `BwVault` (or, for the
// encrypted/zip cases, into the inputs `commands.rs` needs to do so); the
// actual `BwVault` -> `ImportedEntry` conversion stays in `commands.rs`,
// since that's where the (private) `Imported*` types live.

use std::io::{Read as _, Write as _};

use anyhow::Context as _;
use serde::Deserialize as _;

type Result<T> = anyhow::Result<T>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ImportFormat {
    /// Auto-detect between all of the formats below.
    Auto,
    /// The JSON (optionally gpg-encrypted) shape produced by `rbw export`.
    Rbw,
    /// Bitwarden's own plain JSON export.
    BitwardenJson,
    /// Bitwarden's password-protected "Encrypted JSON" export.
    BitwardenEncryptedJson,
    /// Bitwarden's "zip (with attachments)" export.
    BitwardenZip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ExportFormat {
    /// The JSON (optionally gpg-encrypted) shape produced by `rbw export`.
    Rbw,
    /// Bitwarden's own plain JSON export.
    BitwardenJson,
    /// Bitwarden's password-protected "Encrypted JSON" export (--encrypt
    /// supplies the password).
    BitwardenEncryptedJson,
    /// Bitwarden's "zip (with attachments)" export.
    BitwardenZip,
    /// Bitwarden's CSV export. Only Login and `SecureNote` entries are
    /// included -- Bitwarden's own CSV format has no columns for
    /// Card/Identity/SSH key items, confirmed against a real export.
    BitwardenCsv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    Rbw,
    BitwardenJson,
    BitwardenEncryptedJson,
    BitwardenZip,
}

impl std::fmt::Display for DetectedFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Rbw => "rbw",
            Self::BitwardenJson => "bitwarden-json",
            Self::BitwardenEncryptedJson => "bitwarden-encrypted-json",
            Self::BitwardenZip => "bitwarden-zip",
        };
        write!(f, "{s}")
    }
}

// Sniffs `raw` to figure out which format it is, without needing a
// passphrase up front. Zip archives and gpg packets are both binary, so
// those are distinguished by magic bytes; anything that's valid UTF-8 JSON
// is distinguished by which top-level keys it has (rbw's own export always
// has `entries`; Bitwarden's plain export always has `items`; Bitwarden's
// encrypted export always has `encrypted`/`data`).
pub fn detect_format(raw: &[u8]) -> Result<DetectedFormat> {
    if raw.starts_with(b"PK\x03\x04") || raw.starts_with(b"PK\x05\x06") {
        return Ok(DetectedFormat::BitwardenZip);
    }

    if let Ok(text) = std::str::from_utf8(raw) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(obj) = value.as_object() {
                if obj.contains_key("entries") {
                    return Ok(DetectedFormat::Rbw);
                }
                if obj.contains_key("encrypted") && obj.contains_key("data") {
                    return Ok(DetectedFormat::BitwardenEncryptedJson);
                }
                if obj.contains_key("items") || obj.contains_key("folders") {
                    return Ok(DetectedFormat::BitwardenJson);
                }
            }
            anyhow::bail!(
                "couldn't recognize the JSON shape as an rbw or Bitwarden \
                 export"
            );
        }
    }

    // Not JSON and not a zip -- assume it's the gpg-encrypted tar.gz that
    // `rbw export --encrypt` produces. `load_import_json`'s caller reports a
    // clearer error than we could here if that turns out to be wrong (e.g.
    // no passphrase was given).
    Ok(DetectedFormat::Rbw)
}

// Bitwarden's own export writes an empty list field as an explicit JSON
// `null` (e.g. `"collectionIds": null`) rather than omitting the key or
// using `[]` -- confirmed against a real export. `#[serde(default)]` alone
// only covers a missing key, not a present-but-null one, so every `Vec`
// field below also needs this to deserialize real exports at all.
fn null_as_default<'de, D, T>(
    deserializer: D,
) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + serde::Deserialize<'de>,
{
    Ok(Option::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BwFolder {
    pub id: Option<String>,
    pub name: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BwCollection {
    pub id: Option<String>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    pub name: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BwUri {
    pub uri: Option<String>,
    #[serde(rename = "match", default)]
    pub match_type: Option<rbw::api::UriMatchType>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BwLogin {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub uris: Vec<BwUri>,
    #[serde(
        rename = "fido2Credentials",
        default,
        deserialize_with = "null_as_default"
    )]
    pub fido2_credentials: Vec<BwFido2Credential>,
}

// Bitwarden's own JSON export is already fully decrypted client-side, so
// (unlike `db::Fido2Credential`/`api::CipherFido2Credential`) every field
// here is a plain value, not a CipherString -- same as `BwLogin`'s other
// fields.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BwFido2Credential {
    #[serde(rename = "credentialId", default)]
    pub credential_id: Option<String>,
    #[serde(rename = "keyType", default)]
    pub key_type: Option<String>,
    #[serde(rename = "keyAlgorithm", default)]
    pub key_algorithm: Option<String>,
    #[serde(rename = "keyCurve", default)]
    pub key_curve: Option<String>,
    #[serde(rename = "keyValue", default)]
    pub key_value: Option<String>,
    #[serde(rename = "rpId", default)]
    pub rp_id: Option<String>,
    #[serde(rename = "userHandle", default)]
    pub user_handle: Option<String>,
    #[serde(rename = "userName", default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub counter: Option<String>,
    #[serde(rename = "rpName", default)]
    pub rp_name: Option<String>,
    #[serde(rename = "userDisplayName", default)]
    pub user_display_name: Option<String>,
    #[serde(default)]
    pub discoverable: Option<String>,
    #[serde(rename = "creationDate", default)]
    pub creation_date: Option<String>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BwCard {
    #[serde(rename = "cardholderName", default)]
    pub cardholder_name: Option<String>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
    #[serde(rename = "expMonth", default)]
    pub exp_month: Option<String>,
    #[serde(rename = "expYear", default)]
    pub exp_year: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BwIdentity {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(rename = "firstName", default)]
    pub first_name: Option<String>,
    #[serde(rename = "middleName", default)]
    pub middle_name: Option<String>,
    #[serde(rename = "lastName", default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub address1: Option<String>,
    #[serde(default)]
    pub address2: Option<String>,
    #[serde(default)]
    pub address3: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(rename = "postalCode", default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub ssn: Option<String>,
    #[serde(rename = "licenseNumber", default)]
    pub license_number: Option<String>,
    #[serde(rename = "passportNumber", default)]
    pub passport_number: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BwSshKey {
    #[serde(rename = "privateKey", default)]
    pub private_key: Option<String>,
    #[serde(rename = "publicKey", default)]
    pub public_key: Option<String>,
    #[serde(rename = "keyFingerprint", default)]
    pub fingerprint: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BwField {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(rename = "type", default)]
    pub ty: Option<rbw::api::FieldType>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BwPasswordHistory {
    #[serde(rename = "lastUsedDate", default)]
    pub last_used_date: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BwItem {
    pub id: Option<String>,
    #[serde(rename = "organizationId", default)]
    pub organization_id: Option<String>,
    #[serde(rename = "folderId", default)]
    pub folder_id: Option<String>,
    #[serde(
        rename = "archivedDate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub archived_date: Option<String>,
    #[serde(
        rename = "deletedDate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deleted_date: Option<String>,
    #[serde(rename = "type")]
    pub ty: u16,
    pub name: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub login: Option<BwLogin>,
    #[serde(default)]
    pub card: Option<BwCard>,
    #[serde(default)]
    pub identity: Option<BwIdentity>,
    #[serde(rename = "sshKey", default)]
    pub ssh_key: Option<BwSshKey>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub fields: Vec<BwField>,
    #[serde(
        rename = "passwordHistory",
        default,
        deserialize_with = "null_as_default"
    )]
    pub password_history: Vec<BwPasswordHistory>,
    #[serde(
        rename = "collectionIds",
        default,
        deserialize_with = "null_as_default"
    )]
    pub collection_ids: Vec<String>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BwVault {
    #[serde(default, deserialize_with = "null_as_default")]
    pub folders: Vec<BwFolder>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub collections: Vec<BwCollection>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub items: Vec<BwItem>,
}

pub fn parse_bitwarden_json(text: &str) -> Result<BwVault> {
    serde_json::from_str(text).context(
        "failed to parse import data (expected the JSON shape produced by \
         a Bitwarden vault export)",
    )
}

// `rbw::api::KdfType`'s own `Serialize` impl writes a string ("0"/"1"),
// since that's the shape it needs for `db.json` persistence -- Bitwarden's
// own encrypted export instead expects `kdfType` as a bare JSON number, so
// this field gets its own serializer rather than changing that shared impl.
#[allow(clippy::ref_option, clippy::trivially_copy_pass_by_ref)]
fn serialize_kdf_type_numeric<S>(
    ty: &Option<rbw::api::KdfType>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match ty {
        Some(rbw::api::KdfType::Pbkdf2) => serializer.serialize_some(&0_u8),
        Some(rbw::api::KdfType::Argon2id) => serializer.serialize_some(&1_u8),
        None => serializer.serialize_none(),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BwEncryptedEnvelope {
    #[serde(default)]
    encrypted: Option<bool>,
    #[serde(rename = "passwordProtected", default)]
    password_protected: Option<bool>,
    #[serde(default)]
    salt: Option<String>,
    #[serde(
        rename = "kdfType",
        default,
        serialize_with = "serialize_kdf_type_numeric"
    )]
    kdf_type: Option<rbw::api::KdfType>,
    #[serde(rename = "kdfIterations", default)]
    kdf_iterations: Option<u32>,
    #[serde(rename = "kdfMemory", default)]
    kdf_memory: Option<u32>,
    #[serde(rename = "kdfParallelism", default)]
    kdf_parallelism: Option<u32>,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT", default)]
    enc_key_validation: Option<String>,
    data: String,
}

// Derives the enc/mac key pair Bitwarden's password-protected export uses
// from `password` and the export's own embedded salt/KDF config. This
// mirrors `rbw::identity::Identity::new`'s master-key derivation (PBKDF2 or
// Argon2id into a 32 byte key, then HKDF-Expand that key into separate
// "enc"/"mac" halves) but keyed on the export's random salt instead of the
// account email, since an export has no notion of an account to salt with.
fn derive_export_keys(
    password: &[u8],
    salt: &[u8],
    kdf: rbw::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
) -> Result<rbw::locked::Keys> {
    let iterations = std::num::NonZeroU32::new(iterations)
        .context("encrypted export has a zero KDF iteration count")?;

    let mut keys = rbw::locked::Vec::new();
    keys.extend(std::iter::repeat_n(0, 64));

    let enc_key = &mut keys.data_mut()[0..32];
    match kdf {
        rbw::api::KdfType::Pbkdf2 => {
            pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                password,
                salt,
                iterations.get(),
                enc_key,
            )
            .map_err(|_| anyhow::anyhow!("pbkdf2 key derivation failed"))?;
        }
        rbw::api::KdfType::Argon2id => {
            let memory = memory.context(
                "encrypted export uses Argon2id but is missing kdfMemory",
            )?;
            let parallelism = parallelism.context(
                "encrypted export uses Argon2id but is missing \
                 kdfParallelism",
            )?;
            let argon2_config = argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(
                    memory * 1024,
                    iterations.get(),
                    parallelism,
                    Some(32),
                )
                .map_err(|source| {
                    anyhow::anyhow!("invalid argon2 parameters: {source}")
                })?,
            );
            argon2::Argon2::hash_password_into(
                &argon2_config,
                password,
                salt,
                enc_key,
            )
            .map_err(|source| {
                anyhow::anyhow!("argon2 key derivation failed: {source}")
            })?;
        }
    }

    let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(enc_key)
        .map_err(|_| anyhow::anyhow!("hkdf expand failed"))?;
    hkdf.expand(b"enc", enc_key)
        .map_err(|_| anyhow::anyhow!("hkdf expand failed"))?;
    let mac_key = &mut keys.data_mut()[32..64];
    hkdf.expand(b"mac", mac_key)
        .map_err(|_| anyhow::anyhow!("hkdf expand failed"))?;

    Ok(rbw::locked::Keys::new(keys))
}

// Decrypts a Bitwarden "Encrypted JSON" (password protected) export and
// returns the plain JSON text inside it (the same shape `parse_bitwarden_
// json` expects). Unrelated to `rbw export --encrypt`'s gpg-based envelope.
pub fn decrypt_encrypted_json(raw: &[u8], password: &str) -> Result<String> {
    let text = std::str::from_utf8(raw)
        .context("encrypted export is not valid UTF-8")?;
    let envelope: BwEncryptedEnvelope = serde_json::from_str(text)
        .context("failed to parse the encrypted export's JSON envelope")?;

    let salt = envelope.salt.context(
        "encrypted export is missing its `salt` field -- is this really a \
         password-protected export?",
    )?;
    let kdf_type = envelope.kdf_type.unwrap_or(rbw::api::KdfType::Pbkdf2);
    let iterations = envelope.kdf_iterations.unwrap_or(600_000);

    // Bitwarden's own client derives this key using the `salt` field's raw
    // UTF-8 bytes as the PBKDF2/Argon2 salt -- not the bytes it happens to
    // look like when base64-decoded. `salt` is just a client-generated
    // random string rendered into JSON, and that same string is what gets
    // fed into the KDF, unlike the account-login path (where the PBKDF2
    // salt genuinely is meaningful text, the account email). Confirmed
    // against a real `bw export --format encrypted_json` output: decoding
    // the salt first makes every decrypt fail on the MAC check.
    let keys = derive_export_keys(
        password.as_bytes(),
        salt.as_bytes(),
        kdf_type,
        iterations,
        envelope.kdf_memory,
        envelope.kdf_parallelism,
    )?;

    let cipherstring = rbw::cipherstring::CipherString::new(&envelope.data)
        .context(
        "encrypted export's `data` field isn't a valid cipherstring",
    )?;
    let plaintext = cipherstring.decrypt_symmetric(&keys, None).context(
        "failed to decrypt encrypted export (wrong password, or a \
         corrupted file)",
    )?;

    String::from_utf8(plaintext).context(
        "decrypted export data was not valid UTF-8 (wrong password?)",
    )
}

// Builds a Bitwarden password-protected "Encrypted JSON" export from
// `plaintext` (expected to be the same JSON shape `parse_bitwarden_json`
// produces). The inverse of `decrypt_encrypted_json`, using the same
// derivation -- including the same salt-as-raw-string-bytes quirk, so a
// real `bw import --format encrypted_json` can read this back.
pub fn encrypt_encrypted_json(
    plaintext: &str,
    password: &str,
    kdf: rbw::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
) -> Result<String> {
    use rand::RngCore as _;

    let mut salt_bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = rbw::base64::encode(salt_bytes);

    let keys = derive_export_keys(
        password.as_bytes(),
        salt.as_bytes(),
        kdf,
        iterations,
        memory,
        parallelism,
    )?;

    // Bitwarden's own client just encrypts a fresh random value here; all
    // that matters is that it decrypts (the MAC check) with the derived
    // keys, letting a client sanity-check the password before attempting
    // the full `data` decrypt.
    let validation = rbw::cipherstring::CipherString::encrypt_symmetric(
        &keys,
        uuid::Uuid::new_v4().to_string().as_bytes(),
    )?;
    let data = rbw::cipherstring::CipherString::encrypt_symmetric(
        &keys,
        plaintext.as_bytes(),
    )?;

    let envelope = BwEncryptedEnvelope {
        encrypted: Some(true),
        password_protected: Some(true),
        salt: Some(salt),
        kdf_type: Some(kdf),
        kdf_iterations: Some(iterations),
        kdf_memory: memory,
        kdf_parallelism: parallelism,
        enc_key_validation: Some(validation.to_string()),
        data: data.to_string(),
    };

    serde_json::to_string_pretty(&envelope)
        .context("failed to serialize encrypted export envelope")
}

// An attachment extracted from a "zip (with attachments)" export, keyed by
// the *sanitized display name* of the item that owns it (see
// `sanitize_zip_folder_name`) -- confirmed against a real `bw export
// --format zip` that this is the only association available: the
// exported `data.json`'s own per-item `attachments` arrays are always
// empty, even inside a zip export, so there's no id-based mapping
// anywhere in the archive to use instead.
pub struct ZipAttachment {
    pub file_name: String,
    pub data: Vec<u8>,
}

// Mirrors the path-sanitizing Bitwarden's own zip export applies to an
// item's name before using it as a directory name: characters that are
// illegal (or awkward) in a filename on common filesystems become `_`.
// Confirmed against a real export: `Abus Combiflex 2503/120` became
// `attachments/Abus Combiflex 2503_120/...` and `email: p@x.dev` became
// `attachments/email_ p@x.dev/...` (only the illegal character itself is
// replaced -- surrounding text, including a following space, is kept).
pub fn sanitize_zip_folder_name(name: &str) -> String {
    name.chars()
        .map(|c| if "<>:\"/\\|?*".contains(c) { '_' } else { c })
        .collect()
}

// Bitwarden's CLI (`bw export --format zip`) lays a zip export out as the
// plain JSON data file at the root plus one folder per item under
// `attachments/<sanitized item name>/<file name>`.
pub fn parse_zip(
    raw: &[u8],
) -> Result<(
    BwVault,
    std::collections::HashMap<String, Vec<ZipAttachment>>,
)> {
    let cursor = std::io::Cursor::new(raw);
    let mut archive = zip::ZipArchive::new(cursor)
        .context("failed to read the export as a zip archive")?;

    let mut json_text: Option<String> = None;
    let mut attachments: std::collections::HashMap<
        String,
        Vec<ZipAttachment>,
    > = std::collections::HashMap::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .context("failed to read an entry from the zip archive")?;
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_string();

        if let Some(folder_name) = name
            .strip_prefix("attachments/")
            .and_then(|rest| rest.split('/').next())
            .filter(|folder_name| !folder_name.is_empty())
        {
            let Some(file_part) =
                name.rsplit('/').next().filter(|s| !s.is_empty())
            else {
                continue;
            };
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .with_context(|| format!("failed to read {name}"))?;
            attachments
                .entry(folder_name.to_string())
                .or_default()
                .push(ZipAttachment {
                    file_name: file_part.to_string(),
                    data,
                });
            continue;
        }

        let is_json = std::path::Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
        if is_json && json_text.is_none() {
            let mut text = String::new();
            entry
                .read_to_string(&mut text)
                .with_context(|| format!("failed to read {name}"))?;
            json_text = Some(text);
        }
    }

    let json_text = json_text.context(
        "no JSON data file found inside the zip export (expected one at \
         the archive root)",
    )?;
    let vault = parse_bitwarden_json(&json_text)?;
    Ok((vault, attachments))
}

// Builds a "zip (with attachments)" export: `json_text` (the same shape
// `parse_bitwarden_json` reads) as `data.json` at the archive root, plus
// one file per `(item name, file name, bytes)` triple under
// `attachments/<sanitized item name>/<file name>` -- the real layout
// confirmed by `parse_zip`'s doc comment, so a real `bw import --format
// zip` can read this back.
pub fn write_zip(
    json_text: &str,
    attachments: &[(String, String, Vec<u8>)],
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();

        writer
            .start_file("data.json", options)
            .context("failed to start data.json in the zip export")?;
        writer
            .write_all(json_text.as_bytes())
            .context("failed to write data.json in the zip export")?;

        for (item_name, file_name, data) in attachments {
            let folder = sanitize_zip_folder_name(item_name);
            let path = format!("attachments/{folder}/{file_name}");
            writer.start_file(&path, options).with_context(|| {
                format!("failed to start {path} in the zip export")
            })?;
            writer
                .write_all(data)
                .with_context(|| format!("failed to write {path}"))?;
        }

        writer
            .finish()
            .context("failed to finalize the zip export")?;
    }
    Ok(buf)
}

// Builds a Bitwarden CSV export. Confirmed against a real export that
// Bitwarden's CSV format only ever contains Login and SecureNote items
// (Card/Identity/SSH key items are silently absent, even though the
// exporting vault has them) -- other types are skipped here too, with the
// count returned so the caller can warn instead of silently matching that
// silence. `fields` join each custom field as `name: value` lines, the
// established (if informally documented) convention for that column.
pub fn write_csv(vault: &BwVault) -> Result<(String, usize)> {
    let folder_names: std::collections::HashMap<String, String> = vault
        .folders
        .iter()
        .filter_map(|f| f.id.clone().map(|id| (id, f.name.clone())))
        .collect();

    let mut writer = csv::WriterBuilder::new().from_writer(Vec::new());
    writer
        .write_record([
            "folder",
            "favorite",
            "type",
            "name",
            "notes",
            "fields",
            "reprompt",
            "archivedDate",
            "login_uri",
            "login_username",
            "login_password",
            "login_totp",
        ])
        .context("failed to write the CSV header")?;

    let mut skipped = 0_usize;
    for item in &vault.items {
        let ty_str = match item.ty {
            1 => "login",
            2 => "note",
            _ => {
                skipped += 1;
                continue;
            }
        };

        let folder = item
            .folder_id
            .as_deref()
            .and_then(|id| folder_names.get(id))
            .cloned()
            .unwrap_or_default();
        let fields = item
            .fields
            .iter()
            .map(|f| {
                format!(
                    "{}: {}",
                    f.name.as_deref().unwrap_or_default(),
                    f.value.as_deref().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let login = item.login.as_ref();

        writer
            .write_record([
                folder.as_str(),
                "false",
                ty_str,
                item.name.as_str(),
                item.notes.as_deref().unwrap_or_default(),
                fields.as_str(),
                "0",
                item.archived_date.as_deref().unwrap_or_default(),
                login
                    .and_then(|l| l.uris.first())
                    .and_then(|u| u.uri.as_deref())
                    .unwrap_or_default(),
                login
                    .and_then(|l| l.username.as_deref())
                    .unwrap_or_default(),
                login
                    .and_then(|l| l.password.as_deref())
                    .unwrap_or_default(),
                login.and_then(|l| l.totp.as_deref()).unwrap_or_default(),
            ])
            .with_context(|| {
                format!("failed to write row for '{}'", item.name)
            })?;
    }

    let bytes = writer
        .into_inner()
        .context("failed to finalize the CSV export")?;
    let text =
        String::from_utf8(bytes).context("CSV export was not valid UTF-8")?;
    Ok((text, skipped))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_decrypt_encrypted_json_round_trips_with_derived_keys() {
        // The salt is used as its own raw UTF-8 bytes, not base64-decoded
        // first (see the comment on `decrypt_encrypted_json`) -- so the
        // string used here as the JSON `salt` field is exactly what gets
        // fed into the KDF, both when deriving the keys used to encrypt
        // below and when `decrypt_encrypted_json` derives them again.
        let salt = "some-random-salt-string";
        let password = "correct horse battery staple";
        let keys = derive_export_keys(
            password.as_bytes(),
            salt.as_bytes(),
            rbw::api::KdfType::Pbkdf2,
            100_000,
            None,
            None,
        )
        .unwrap();

        let plaintext: &[u8] = br#"{"folders": [], "items": []}"#;
        let cipherstring =
            rbw::cipherstring::CipherString::encrypt_symmetric(
                &keys, plaintext,
            )
            .unwrap();

        let envelope = serde_json::json!({
            "encrypted": true,
            "passwordProtected": true,
            "salt": salt,
            "kdfType": 0,
            "kdfIterations": 100_000,
            "data": cipherstring.to_string(),
        });
        let raw = serde_json::to_vec(&envelope).unwrap();

        let decrypted = decrypt_encrypted_json(&raw, password).unwrap();
        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[test]
    fn test_decrypt_encrypted_json_rejects_wrong_password() {
        let salt = "salt-string";
        let keys = derive_export_keys(
            b"correct password",
            salt.as_bytes(),
            rbw::api::KdfType::Pbkdf2,
            100_000,
            None,
            None,
        )
        .unwrap();
        let cipherstring =
            rbw::cipherstring::CipherString::encrypt_symmetric(&keys, b"{}")
                .unwrap();
        let envelope = serde_json::json!({
            "salt": salt,
            "kdfType": 0,
            "kdfIterations": 100_000,
            "data": cipherstring.to_string(),
        });
        let raw = serde_json::to_vec(&envelope).unwrap();

        assert!(decrypt_encrypted_json(&raw, "wrong password").is_err());
    }

    #[test]
    fn test_parse_zip_extracts_data_json_and_attachments() {
        let mut zip_bytes = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut zip_bytes);
            let mut writer = zip::ZipWriter::new(cursor);
            let options = zip::write::SimpleFileOptions::default();

            writer.start_file("data.json", options).unwrap();
            let data_json = r#"{"items": [{"id": "item1", "type": 2, "name": "a note"}]}"#;
            writer.write_all(data_json.as_bytes()).unwrap();

            // Real exports key the folder by the item's (sanitized) name,
            // not its id -- see `sanitize_zip_folder_name`.
            writer
                .start_file("attachments/a note/photo.png", options)
                .unwrap();
            writer.write_all(b"pngbytes").unwrap();

            writer.finish().unwrap();
        }

        let (bw, attachments) = parse_zip(&zip_bytes).unwrap();
        assert_eq!(bw.items.len(), 1);
        assert_eq!(bw.items[0].name, "a note");

        let files = &attachments["a note"];
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_name, "photo.png");
        assert_eq!(files[0].data, b"pngbytes");
    }

    #[test]
    fn test_sanitize_zip_folder_name_replaces_illegal_characters() {
        assert_eq!(
            sanitize_zip_folder_name("Abus Combiflex 2503/120"),
            "Abus Combiflex 2503_120"
        );
        assert_eq!(
            sanitize_zip_folder_name("email: p@x.dev"),
            "email_ p@x.dev"
        );
        assert_eq!(sanitize_zip_folder_name("plain name"), "plain name");
    }

    #[test]
    fn test_encrypt_encrypted_json_round_trips_through_decrypt() {
        let password = "export-password-123";
        let plaintext = r#"{"folders": [], "items": [{"id": "1", "type": 2, "name": "a note"}]}"#;

        let encrypted = encrypt_encrypted_json(
            plaintext,
            password,
            rbw::api::KdfType::Pbkdf2,
            100_000,
            None,
            None,
        )
        .unwrap();

        // The envelope looks like a real one: bare JSON numbers for
        // kdfType, not the string form `KdfType`'s own `Serialize` impl
        // would produce for `db.json`.
        let value: serde_json::Value =
            serde_json::from_str(&encrypted).unwrap();
        assert_eq!(value["kdfType"], serde_json::json!(0));
        assert_eq!(value["encrypted"], serde_json::json!(true));

        let decrypted =
            decrypt_encrypted_json(encrypted.as_bytes(), password).unwrap();
        assert_eq!(decrypted, plaintext);

        assert!(decrypt_encrypted_json(
            encrypted.as_bytes(),
            "wrong password"
        )
        .is_err());
    }

    #[test]
    fn test_write_zip_round_trips_through_parse_zip() {
        let json_text =
            r#"{"items": [{"id": "1", "type": 2, "name": "a/note"}]}"#;
        let attachments = vec![(
            "a/note".to_string(),
            "photo.png".to_string(),
            b"pngbytes".to_vec(),
        )];

        let zip_bytes = write_zip(json_text, &attachments).unwrap();
        let (bw, parsed_attachments) = parse_zip(&zip_bytes).unwrap();

        assert_eq!(bw.items.len(), 1);
        assert_eq!(bw.items[0].name, "a/note");

        // The folder name is sanitized on write, so it's looked up
        // sanitized too.
        let files = &parsed_attachments["a_note"];
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_name, "photo.png");
        assert_eq!(files[0].data, b"pngbytes");
    }

    #[test]
    fn test_write_csv_includes_only_login_and_note_items() {
        let vault = BwVault {
            folders: vec![],
            collections: vec![],
            items: vec![
                BwItem {
                    id: Some("1".to_string()),
                    organization_id: None,
                    folder_id: None,
                    archived_date: Some(
                        "2026-07-29T12:00:00.000Z".to_string(),
                    ),
                    deleted_date: None,
                    ty: 1,
                    name: "a login".to_string(),
                    notes: None,
                    login: Some(BwLogin {
                        username: Some("user".to_string()),
                        password: Some("pw".to_string()),
                        totp: None,
                        uris: vec![BwUri {
                            uri: Some("https://example.com".to_string()),
                            match_type: None,
                        }],
                        fido2_credentials: vec![],
                    }),
                    card: None,
                    identity: None,
                    ssh_key: None,
                    fields: vec![BwField {
                        name: Some("custom".to_string()),
                        value: Some("val".to_string()),
                        ty: Some(rbw::api::FieldType::Text),
                    }],
                    password_history: vec![],
                    collection_ids: vec![],
                },
                BwItem {
                    id: Some("2".to_string()),
                    organization_id: None,
                    folder_id: None,
                    archived_date: None,
                    deleted_date: None,
                    ty: 5,
                    name: "an ssh key".to_string(),
                    notes: None,
                    login: None,
                    card: None,
                    identity: None,
                    ssh_key: None,
                    fields: vec![],
                    password_history: vec![],
                    collection_ids: vec![],
                },
            ],
        };

        let (csv_text, skipped) = write_csv(&vault).unwrap();
        assert_eq!(skipped, 1);
        assert!(csv_text.contains("a login"));
        assert!(csv_text.contains("https://example.com"));
        assert!(csv_text.contains("custom: val"));
        assert!(csv_text.contains("2026-07-29T12:00:00.000Z"));
        assert!(!csv_text.contains("an ssh key"));

        let mut reader = csv::Reader::from_reader(csv_text.as_bytes());
        let headers = reader.headers().unwrap().clone();
        assert_eq!(headers.get(2), Some("type"));
        assert_eq!(headers.get(8), Some("login_uri"));
        let records: Vec<_> = reader
            .records()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(records.len(), 1);
    }
}
