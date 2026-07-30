// serde_repr generates some as conversions that we can't seem to silence from
// here, unfortunately
#![allow(clippy::as_conversions)]

use crate::prelude::*;

use rand::distr::SampleString as _;
use sha2::Digest as _;
use tokio::io::AsyncReadExt as _;

use crate::json::{
    DeserializeJsonWithPath as _, DeserializeJsonWithPathAsync as _,
};

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

impl std::fmt::Display for UriMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::enum_glob_use)]
        use UriMatchType::*;
        let s = match self {
            Domain => "domain",
            Host => "host",
            StartsWith => "starts_with",
            Exact => "exact",
            RegularExpression => "regular_expression",
            Never => "never",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

impl TwoFactorProviderType {
    pub fn message(&self) -> &str {
        match *self {
            Self::Authenticator => "Enter the 6 digit verification code from your authenticator app.",
            Self::Yubikey => "Insert your Yubikey and push the button.",
            Self::Email => "Enter the PIN you received via email.",
            _ => "Enter the code."
        }
    }

    pub fn header(&self) -> &str {
        match *self {
            Self::Authenticator => "Authenticator App",
            Self::Yubikey => "Yubikey",
            Self::Email => "Email Code",
            _ => "Two Factor Authentication",
        }
    }

    pub fn grab(&self) -> bool {
        !matches!(self, Self::Email)
    }
}

impl<'de> serde::Deserialize<'de> for TwoFactorProviderType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TwoFactorProviderTypeVisitor;
        impl serde::de::Visitor<'_> for TwoFactorProviderTypeVisitor {
            type Value = TwoFactorProviderType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("two factor provider id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(TwoFactorProviderTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for TwoFactorProviderType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::Yubikey),
            4 => Ok(Self::U2f),
            5 => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            7 => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for TwoFactorProviderType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Authenticator),
            "1" => Ok(Self::Email),
            "2" => Ok(Self::Duo),
            "3" => Ok(Self::Yubikey),
            "4" => Ok(Self::U2f),
            "5" => Ok(Self::Remember),
            "6" => Ok(Self::OrganizationDuo),
            "7" => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider { ty: ty.to_string() }),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl<'de> serde::Deserialize<'de> for KdfType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KdfTypeVisitor;
        impl serde::de::Visitor<'_> for KdfTypeVisitor {
            type Value = KdfType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("kdf id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(KdfTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for KdfType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Pbkdf2),
            1 => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for KdfType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Pbkdf2),
            "1" => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType { ty: ty.to_string() }),
        }
    }
}

impl serde::Serialize for KdfType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::Pbkdf2 => "0",
            Self::Argon2id => "1",
        };
        serializer.serialize_str(s)
    }
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum CipherRepromptType {
    None = 0,
    Password = 1,
}

#[derive(serde::Serialize, Debug)]
struct PreloginReq {
    email: String,
}

#[derive(serde::Deserialize, Debug)]
struct PreloginRes {
    #[serde(rename = "Kdf", alias = "kdf")]
    kdf: KdfType,
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: u32,
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    kdf_parallelism: Option<u32>,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenReq {
    grant_type: String,
    scope: String,
    client_id: String,
    #[serde(rename = "deviceType")]
    device_type: u32,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "deviceName")]
    device_name: String,
    #[serde(rename = "devicePushToken")]
    device_push_token: String,
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider")]
    two_factor_provider: Option<u32>,
    #[serde(flatten)]
    auth: ConnectTokenAuth,
}

#[derive(serde::Serialize, Debug)]
#[serde(untagged)]
enum ConnectTokenAuth {
    Password(ConnectTokenPassword),
    AuthCode(ConnectTokenAuthCode),
    ClientCredentials(ConnectTokenClientCredentials),
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenPassword {
    username: String,
    password: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenAuthCode {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenClientCredentials {
    username: String,
    client_secret: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectTokenRes {
    access_token: String,
    refresh_token: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorRes {
    error: String,
    error_description: Option<String>,
    #[serde(rename = "ErrorModel", alias = "errorModel")]
    error_model: Option<ConnectErrorResErrorModel>,
    #[serde(rename = "TwoFactorProviders", alias = "twoFactorProviders")]
    two_factor_providers: Option<Vec<TwoFactorProviderType>>,
    #[serde(
        rename = "SsoEmail2faSessionToken",
        alias = "ssoEmail2faSessionToken"
    )]
    sso_email_2fa_session_token: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorResErrorModel {
    #[serde(rename = "Message", alias = "message")]
    message: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectRefreshTokenReq {
    grant_type: String,
    client_id: String,
    refresh_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectRefreshTokenRes {
    access_token: String,
}

#[derive(serde::Serialize, Debug)]
struct SendEmailLoginReq {
    email: String,
    #[serde(rename = "DeviceIdentifier", alias = "deviceIdentifier")]
    device_identifier: String,
    #[serde(
        rename = "SsoEmail2faSessionToken",
        alias = "ssoEmail2faSessionToken"
    )]
    sso_email_2fa_session_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct SyncRes {
    #[serde(rename = "Ciphers", alias = "ciphers")]
    ciphers: Vec<SyncResCipher>,
    #[serde(rename = "Profile", alias = "profile")]
    profile: SyncResProfile,
    #[serde(rename = "Folders", alias = "folders")]
    folders: Vec<SyncResFolder>,
    #[serde(rename = "Collections", alias = "collections", default)]
    collections: Vec<SyncResCollection>,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct SyncResCollection {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "OrganizationId", alias = "organizationId")]
    organization_id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResCipher {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "FolderId", alias = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "OrganizationId", alias = "organizationId")]
    organization_id: Option<String>,
    #[serde(rename = "Name", alias = "name")]
    name: String,
    #[serde(rename = "Login", alias = "login")]
    login: Option<CipherLogin>,
    #[serde(rename = "Card", alias = "card")]
    card: Option<CipherCard>,
    #[serde(rename = "Identity", alias = "identity")]
    identity: Option<CipherIdentity>,
    #[serde(rename = "SecureNote", alias = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "SshKey", alias = "sshKey")]
    ssh_key: Option<CipherSshKey>,
    #[serde(rename = "Notes", alias = "notes")]
    notes: Option<String>,
    #[serde(rename = "PasswordHistory", alias = "passwordHistory")]
    password_history: Option<Vec<SyncResPasswordHistory>>,
    #[serde(rename = "Fields", alias = "fields")]
    fields: Option<Vec<CipherField>>,
    #[serde(rename = "DeletedDate", alias = "deletedDate")]
    deleted_date: Option<String>,
    #[serde(rename = "ArchivedDate", alias = "archivedDate")]
    archived_date: Option<String>,
    #[serde(rename = "Key", alias = "key")]
    key: Option<String>,
    #[serde(rename = "Reprompt", alias = "reprompt")]
    reprompt: CipherRepromptType,
    #[serde(rename = "CollectionIds", alias = "collectionIds", default)]
    collection_ids: Vec<String>,
    #[serde(
        rename = "Attachments",
        alias = "attachments",
        default,
        deserialize_with = "deserialize_default_on_null"
    )]
    attachments: Vec<CipherAttachment>,
}

fn deserialize_default_on_null<'de, D, T>(
    deserializer: D,
) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    <Option<T> as serde::Deserialize>::deserialize(deserializer)
        .map(Option::unwrap_or_default)
}

impl SyncResCipher {
    fn to_entry(
        &self,
        folders: &[SyncResFolder],
    ) -> Option<crate::db::Entry> {
        let history =
            self.password_history
                .as_ref()
                .map_or_else(Vec::new, |history| {
                    history
                        .iter()
                        .filter_map(|entry| {
                            // Gets rid of entries with a non-existent
                            // password
                            entry.password.clone().map(|p| {
                                crate::db::HistoryEntry {
                                    last_used_date: entry
                                        .last_used_date
                                        .clone(),
                                    password: p,
                                }
                            })
                        })
                        .collect()
                });

        let (folder, folder_id) =
            self.folder_id.as_ref().map_or((None, None), |folder_id| {
                let mut folder_name = None;
                for folder in folders {
                    if &folder.id == folder_id {
                        folder_name = Some(folder.name.clone());
                    }
                }
                (folder_name, Some(folder_id))
            });
        let data = if let Some(login) = &self.login {
            crate::db::EntryData::Login {
                username: login.username.clone(),
                password: login.password.clone(),
                totp: login.totp.clone(),
                uris: login.uris.as_ref().map_or_else(
                    std::vec::Vec::new,
                    |uris| {
                        uris.iter()
                            .filter_map(|uri| {
                                uri.uri.clone().map(|s| crate::db::Uri {
                                    uri: s,
                                    match_type: uri.match_type,
                                })
                            })
                            .collect()
                    },
                ),
                fido2_credentials: login
                    .fido2_credentials
                    .as_ref()
                    .map_or_else(std::vec::Vec::new, |creds| {
                        creds
                            .iter()
                            .map(|c| crate::db::Fido2Credential {
                                credential_id: c.credential_id.clone(),
                                key_type: c.key_type.clone(),
                                key_algorithm: c.key_algorithm.clone(),
                                key_curve: c.key_curve.clone(),
                                key_value: c.key_value.clone(),
                                rp_id: c.rp_id.clone(),
                                user_handle: c.user_handle.clone(),
                                user_name: c.user_name.clone(),
                                counter: c.counter.clone(),
                                rp_name: c.rp_name.clone(),
                                user_display_name: c
                                    .user_display_name
                                    .clone(),
                                discoverable: c.discoverable.clone(),
                                creation_date: c.creation_date.clone(),
                            })
                            .collect()
                    }),
            }
        } else if let Some(card) = &self.card {
            crate::db::EntryData::Card {
                cardholder_name: card.cardholder_name.clone(),
                number: card.number.clone(),
                brand: card.brand.clone(),
                exp_month: card.exp_month.clone(),
                exp_year: card.exp_year.clone(),
                code: card.code.clone(),
            }
        } else if let Some(identity) = &self.identity {
            crate::db::EntryData::Identity {
                title: identity.title.clone(),
                first_name: identity.first_name.clone(),
                middle_name: identity.middle_name.clone(),
                last_name: identity.last_name.clone(),
                address1: identity.address1.clone(),
                address2: identity.address2.clone(),
                address3: identity.address3.clone(),
                city: identity.city.clone(),
                state: identity.state.clone(),
                postal_code: identity.postal_code.clone(),
                country: identity.country.clone(),
                phone: identity.phone.clone(),
                email: identity.email.clone(),
                ssn: identity.ssn.clone(),
                license_number: identity.license_number.clone(),
                passport_number: identity.passport_number.clone(),
                username: identity.username.clone(),
            }
        } else if let Some(_secure_note) = &self.secure_note {
            crate::db::EntryData::SecureNote
        } else if let Some(ssh_key) = &self.ssh_key {
            crate::db::EntryData::SshKey {
                private_key: ssh_key.private_key.clone(),
                public_key: ssh_key.public_key.clone(),
                fingerprint: ssh_key.fingerprint.clone(),
            }
        } else {
            // e.g. an SshKey cipher whose type-specific data the server
            // stored as null; warn instead of hiding it entirely
            log::warn!(
                "ignoring cipher {} with no type-specific data",
                self.id
            );
            return None;
        };
        let fields = self.fields.as_ref().map_or_else(Vec::new, |fields| {
            fields
                .iter()
                .map(|field| crate::db::Field {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect()
        });
        Some(crate::db::Entry {
            id: self.id.clone(),
            org_id: self.organization_id.clone(),
            folder,
            folder_id: folder_id.map(std::string::ToString::to_string),
            name: self.name.clone(),
            data,
            fields,
            notes: self.notes.clone(),
            history,
            key: self.key.clone(),
            master_password_reprompt: self.reprompt,
            archived: self.archived_date.is_some(),
            deleted: self.deleted_date.is_some(),
            collection_ids: self.collection_ids.clone(),
            attachments: self
                .attachments
                .iter()
                .map(|attachment| crate::db::Attachment {
                    id: attachment.id.clone(),
                    url: attachment.url.clone(),
                    file_name: attachment.file_name.clone(),
                    key: attachment.key.clone(),
                    size: attachment.size.clone(),
                    size_name: attachment.size_name.clone(),
                })
                .collect(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherAttachment {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Url", alias = "url")]
    url: Option<String>,
    #[serde(rename = "FileName", alias = "fileName")]
    file_name: Option<String>,
    #[serde(rename = "Key", alias = "key")]
    key: Option<String>,
    #[serde(
        rename = "Size",
        alias = "size",
        default,
        deserialize_with = "deserialize_optional_string"
    )]
    size: Option<String>,
    #[serde(rename = "SizeName", alias = "sizeName")]
    size_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_cipher_treats_null_attachments_as_empty() {
        let cipher: SyncResCipher =
            serde_json::from_value(serde_json::json!({
                "id": "cipher-id",
                "name": "example",
                "secureNote": {},
                "reprompt": 0,
                "attachments": null,
            }))
            .unwrap();

        assert!(cipher.attachments.is_empty());
    }

    fn test_ssh_key() -> CipherSshKey {
        CipherSshKey {
            private_key: Some("private".to_string()),
            public_key: Some("public".to_string()),
            fingerprint: Some("fingerprint".to_string()),
        }
    }

    #[test]
    fn ciphers_post_req_serializes_ssh_key() {
        let req = CiphersPostReq {
            ty: 5,
            folder_id: None,
            name: "server key".to_string(),
            notes: None,
            login: None,
            card: None,
            identity: None,
            fields: Vec::new(),
            secure_note: None,
            ssh_key: Some(test_ssh_key()),
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["type"], 5);
        assert!(json["login"].is_null());
        assert!(json["card"].is_null());
        assert!(json["identity"].is_null());
        assert!(json["secureNote"].is_null());
        // must be camelCase (with fingerprint as keyFingerprint):
        // Vaultwarden silently stores `"sshKey": null` otherwise
        assert_eq!(json["sshKey"]["privateKey"], "private");
        assert_eq!(json["sshKey"]["publicKey"], "public");
        assert_eq!(json["sshKey"]["keyFingerprint"], "fingerprint");
    }

    #[test]
    fn ciphers_put_req_serializes_ssh_key() {
        let req = CiphersPutReq {
            ty: 5,
            folder_id: None,
            organization_id: None,
            name: "server key".to_string(),
            notes: None,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            ssh_key: Some(test_ssh_key()),
            fields: Vec::new(),
            password_history: Vec::new(),
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["type"], 5);
        assert!(json["login"].is_null());
        assert!(json["card"].is_null());
        assert!(json["identity"].is_null());
        assert!(json["secureNote"].is_null());
        // must be camelCase (with fingerprint as keyFingerprint):
        // Vaultwarden silently stores `"sshKey": null` otherwise
        assert_eq!(json["sshKey"]["privateKey"], "private");
        assert_eq!(json["sshKey"]["publicKey"], "public");
        assert_eq!(json["sshKey"]["keyFingerprint"], "fingerprint");
    }

    #[test]
    fn cipher_ssh_key_deserializes_all_fingerprint_spellings() {
        // camelCase `keyFingerprint` is what servers send today;
        // `Fingerprint` is what old rbw versions serialized; the
        // remaining spellings guard against first-char case
        // normalization of stored data.
        for json in [
            serde_json::json!({
                "privateKey": "private",
                "publicKey": "public",
                "keyFingerprint": "fingerprint",
            }),
            serde_json::json!({
                "PrivateKey": "private",
                "PublicKey": "public",
                "KeyFingerprint": "fingerprint",
            }),
            serde_json::json!({
                "PrivateKey": "private",
                "PublicKey": "public",
                "Fingerprint": "fingerprint",
            }),
            serde_json::json!({
                "privateKey": "private",
                "publicKey": "public",
                "fingerprint": "fingerprint",
            }),
        ] {
            let ssh_key: CipherSshKey = serde_json::from_value(json).unwrap();
            assert_eq!(ssh_key.private_key.as_deref(), Some("private"));
            assert_eq!(ssh_key.public_key.as_deref(), Some("public"));
            assert_eq!(ssh_key.fingerprint.as_deref(), Some("fingerprint"));
        }
    }
}

fn deserialize_optional_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value =
        <Option<serde_json::Value> as serde::Deserialize>::deserialize(
            deserializer,
        )?;
    Ok(value.and_then(|value| match value {
        serde_json::Value::String(value) => Some(value),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }))
}

#[derive(serde::Deserialize, Debug)]
struct AttachmentDataRes {
    #[serde(rename = "Url", alias = "url")]
    url: String,
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfile {
    #[serde(rename = "Key", alias = "key")]
    key: String,
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    private_key: String,
    #[serde(rename = "Organizations", alias = "organizations")]
    organizations: Vec<SyncResProfileOrganization>,
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfileOrganization {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct SyncResFolder {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLogin {
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
    #[serde(rename = "Totp", alias = "totp")]
    totp: Option<String>,
    #[serde(rename = "Uris", alias = "uris")]
    uris: Option<Vec<CipherLoginUri>>,
    #[serde(rename = "Fido2Credentials", alias = "fido2Credentials")]
    fido2_credentials: Option<Vec<CipherFido2Credential>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLoginUri {
    #[serde(rename = "Uri", alias = "uri")]
    uri: Option<String>,
    #[serde(rename = "Match", alias = "match")]
    match_type: Option<UriMatchType>,
}

// A synced passkey. Every field except `creation_date` is an individually
// encrypted CipherString, exactly like `password`/`username` above --
// `creation_date` is the one plain (unencrypted) field Bitwarden stores on
// a fido2 credential.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherFido2Credential {
    #[serde(rename = "CredentialId", alias = "credentialId")]
    credential_id: Option<String>,
    #[serde(rename = "KeyType", alias = "keyType")]
    key_type: Option<String>,
    #[serde(rename = "KeyAlgorithm", alias = "keyAlgorithm")]
    key_algorithm: Option<String>,
    #[serde(rename = "KeyCurve", alias = "keyCurve")]
    key_curve: Option<String>,
    #[serde(rename = "KeyValue", alias = "keyValue")]
    key_value: Option<String>,
    #[serde(rename = "RpId", alias = "rpId")]
    rp_id: Option<String>,
    #[serde(rename = "UserHandle", alias = "userHandle")]
    user_handle: Option<String>,
    #[serde(rename = "UserName", alias = "userName")]
    user_name: Option<String>,
    #[serde(rename = "Counter", alias = "counter")]
    counter: Option<String>,
    #[serde(rename = "RpName", alias = "rpName")]
    rp_name: Option<String>,
    #[serde(rename = "UserDisplayName", alias = "userDisplayName")]
    user_display_name: Option<String>,
    #[serde(rename = "Discoverable", alias = "discoverable")]
    discoverable: Option<String>,
    #[serde(rename = "CreationDate", alias = "creationDate")]
    creation_date: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherCard {
    #[serde(rename = "CardholderName", alias = "cardholderName")]
    cardholder_name: Option<String>,
    #[serde(rename = "Number", alias = "number")]
    number: Option<String>,
    #[serde(rename = "Brand", alias = "brand")]
    brand: Option<String>,
    #[serde(rename = "ExpMonth", alias = "expMonth")]
    exp_month: Option<String>,
    #[serde(rename = "ExpYear", alias = "expYear")]
    exp_year: Option<String>,
    #[serde(rename = "Code", alias = "code")]
    code: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherIdentity {
    #[serde(rename = "Title", alias = "title")]
    title: Option<String>,
    #[serde(rename = "FirstName", alias = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "MiddleName", alias = "middleName")]
    middle_name: Option<String>,
    #[serde(rename = "LastName", alias = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "Address1", alias = "address1")]
    address1: Option<String>,
    #[serde(rename = "Address2", alias = "address2")]
    address2: Option<String>,
    #[serde(rename = "Address3", alias = "address3")]
    address3: Option<String>,
    #[serde(rename = "City", alias = "city")]
    city: Option<String>,
    #[serde(rename = "State", alias = "state")]
    state: Option<String>,
    #[serde(rename = "PostalCode", alias = "postalCode")]
    postal_code: Option<String>,
    #[serde(rename = "Country", alias = "country")]
    country: Option<String>,
    #[serde(rename = "Phone", alias = "phone")]
    phone: Option<String>,
    #[serde(rename = "Email", alias = "email")]
    email: Option<String>,
    #[serde(rename = "SSN", alias = "ssn")]
    ssn: Option<String>,
    #[serde(rename = "LicenseNumber", alias = "licenseNumber")]
    license_number: Option<String>,
    #[serde(rename = "PassportNumber", alias = "passportNumber")]
    passport_number: Option<String>,
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
}

// Unlike the other Cipher* structs, this one serializes to camelCase:
// SshKey ciphers postdate the era where the server sent PascalCase, and
// both Bitwarden and Vaultwarden require exactly `privateKey`/`publicKey`/
// `keyFingerprint` when storing. Vaultwarden in particular responds with
// HTTP 200 but silently stores `"sshKey": null` if any of those keys is
// missing, so sending PascalCase destroys the key material. The PascalCase
// (and old-rbw `Fingerprint`) spellings are kept as deserialization
// aliases for compatibility with data already in the wild.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherSshKey {
    #[serde(rename = "privateKey", alias = "PrivateKey")]
    private_key: Option<String>,
    #[serde(rename = "publicKey", alias = "PublicKey")]
    public_key: Option<String>,
    #[serde(
        rename = "keyFingerprint",
        alias = "KeyFingerprint",
        alias = "Fingerprint",
        alias = "fingerprint"
    )]
    fingerprint: Option<String>,
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
#[repr(u16)]
pub enum FieldType {
    Text = 0,
    Hidden = 1,
    Boolean = 2,
    Linked = 3,
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
#[repr(u16)]
pub enum LinkedIdType {
    LoginUsername = 100,
    LoginPassword = 101,
    CardCardholderName = 300,
    CardExpMonth = 301,
    CardExpYear = 302,
    CardCode = 303,
    CardBrand = 304,
    CardNumber = 305,
    IdentityTitle = 400,
    IdentityMiddleName = 401,
    IdentityAddress1 = 402,
    IdentityAddress2 = 403,
    IdentityAddress3 = 404,
    IdentityCity = 405,
    IdentityState = 406,
    IdentityPostalCode = 407,
    IdentityCountry = 408,
    IdentityCompany = 409,
    IdentityEmail = 410,
    IdentityPhone = 411,
    IdentitySsn = 412,
    IdentityUsername = 413,
    IdentityPassportNumber = 414,
    IdentityLicenseNumber = 415,
    IdentityFirstName = 416,
    IdentityLastName = 417,
    IdentityFullName = 418,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherField {
    #[serde(rename = "Type", alias = "type")]
    ty: Option<FieldType>,
    #[serde(rename = "Name", alias = "name")]
    name: Option<String>,
    #[serde(rename = "Value", alias = "value")]
    value: Option<String>,
    #[serde(rename = "LinkedId", alias = "linkedId")]
    linked_id: Option<LinkedIdType>,
}

// this is just a name and some notes, both of which are already on the cipher
// object
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherSecureNote {}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResPasswordHistory {
    #[serde(rename = "LastUsedDate", alias = "lastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
}

// The cipher type code, and the type-specific sub-object, for the wire
// format every cipher-create/edit/import request shares -- factored out of
// `Client::add` (and reused by `Client::import_ciphers`/
// `import_organization_ciphers`) so the five-way match isn't duplicated.
#[allow(clippy::type_complexity)]
fn cipher_type_and_fields(
    data: &crate::db::EntryData,
) -> (
    u32,
    Option<CipherLogin>,
    Option<CipherCard>,
    Option<CipherIdentity>,
    Option<CipherSecureNote>,
    Option<CipherSshKey>,
) {
    let ty = match data {
        crate::db::EntryData::Login { .. } => 1,
        crate::db::EntryData::SecureNote => 2,
        crate::db::EntryData::Card { .. } => 3,
        crate::db::EntryData::Identity { .. } => 4,
        crate::db::EntryData::SshKey { .. } => 5,
    };
    let mut login = None;
    let mut card = None;
    let mut identity = None;
    let mut secure_note = None;
    let mut ssh_key = None;
    match data {
        crate::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        } => {
            let uris = if uris.is_empty() {
                None
            } else {
                Some(
                    uris.iter()
                        .map(|s| CipherLoginUri {
                            uri: Some(s.uri.clone()),
                            match_type: s.match_type,
                        })
                        .collect(),
                )
            };
            let fido2_credentials = if fido2_credentials.is_empty() {
                None
            } else {
                Some(
                    fido2_credentials
                        .iter()
                        .map(|c| CipherFido2Credential {
                            credential_id: c.credential_id.clone(),
                            key_type: c.key_type.clone(),
                            key_algorithm: c.key_algorithm.clone(),
                            key_curve: c.key_curve.clone(),
                            key_value: c.key_value.clone(),
                            rp_id: c.rp_id.clone(),
                            user_handle: c.user_handle.clone(),
                            user_name: c.user_name.clone(),
                            counter: c.counter.clone(),
                            rp_name: c.rp_name.clone(),
                            user_display_name: c.user_display_name.clone(),
                            discoverable: c.discoverable.clone(),
                            creation_date: c.creation_date.clone(),
                        })
                        .collect(),
                )
            };
            login = Some(CipherLogin {
                username: username.clone(),
                password: password.clone(),
                totp: totp.clone(),
                uris,
                fido2_credentials,
            });
        }
        crate::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => {
            card = Some(CipherCard {
                cardholder_name: cardholder_name.clone(),
                number: number.clone(),
                brand: brand.clone(),
                exp_month: exp_month.clone(),
                exp_year: exp_year.clone(),
                code: code.clone(),
            });
        }
        crate::db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => {
            identity = Some(CipherIdentity {
                title: title.clone(),
                first_name: first_name.clone(),
                middle_name: middle_name.clone(),
                last_name: last_name.clone(),
                address1: address1.clone(),
                address2: address2.clone(),
                address3: address3.clone(),
                city: city.clone(),
                state: state.clone(),
                postal_code: postal_code.clone(),
                country: country.clone(),
                phone: phone.clone(),
                email: email.clone(),
                ssn: ssn.clone(),
                license_number: license_number.clone(),
                passport_number: passport_number.clone(),
                username: username.clone(),
            });
        }
        crate::db::EntryData::SecureNote => {
            secure_note = Some(CipherSecureNote {});
        }
        crate::db::EntryData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => {
            ssh_key = Some(CipherSshKey {
                private_key: private_key.clone(),
                public_key: public_key.clone(),
                fingerprint: fingerprint.clone(),
            });
        }
    }
    (ty, login, card, identity, secure_note, ssh_key)
}

#[derive(serde::Serialize, Debug)]
struct CiphersPostReq {
    #[serde(rename = "type")]
    ty: u32, // XXX what are the valid types?
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    name: String,
    notes: Option<String>,
    login: Option<CipherLogin>,
    card: Option<CipherCard>,
    identity: Option<CipherIdentity>,
    fields: Vec<CipherField>,
    #[serde(rename = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "sshKey")]
    ssh_key: Option<CipherSshKey>,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPutReq {
    #[serde(rename = "type")]
    ty: u32, // XXX what are the valid types?
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    name: String,
    notes: Option<String>,
    login: Option<CipherLogin>,
    card: Option<CipherCard>,
    identity: Option<CipherIdentity>,
    fields: Vec<CipherField>,
    #[serde(rename = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "sshKey")]
    ssh_key: Option<CipherSshKey>,
    #[serde(rename = "passwordHistory")]
    password_history: Vec<CiphersPutReqHistory>,
}

#[derive(serde::Serialize, Debug)]
struct CiphersPutReqHistory {
    #[serde(rename = "LastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password")]
    password: String,
}

#[derive(serde::Serialize, Debug)]
struct CiphersCollectionsPutReq {
    #[serde(rename = "collectionIds")]
    collection_ids: Vec<String>,
}

// The wire format for `POST /ciphers/import` and `/ciphers/import-
// organization` shares one per-cipher shape (Vaultwarden/Bitwarden both
// reuse their single-cipher `CipherData` struct for it) -- `organization_id`
// is always `None` for the personal-vault endpoint and always `Some` for
// the org-scoped one, and `folder_id` is the reverse (org imports never
// carry a personal folder).
#[derive(serde::Serialize, Debug)]
struct ImportCipherReq {
    #[serde(rename = "type")]
    ty: u32,
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    name: String,
    notes: Option<String>,
    login: Option<CipherLogin>,
    card: Option<CipherCard>,
    identity: Option<CipherIdentity>,
    fields: Vec<CipherField>,
    #[serde(rename = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "sshKey")]
    ssh_key: Option<CipherSshKey>,
    #[serde(rename = "passwordHistory")]
    password_history: Vec<CiphersPutReqHistory>,
}

// An entry in `ImportCipherReq`/`ImportOrganizationCiphersReq`'s
// `folders`/`collections` array: `id: Some(existing_id)` means "reuse this
// existing one" (its `name`/`groups`/`users` are then ignored server-side),
// `id: None` means "create a new one with this name" -- rbw only ever uses
// the reuse form, since folders/collections are already resolved-or-
// created by the caller before building the bulk request.
#[derive(serde::Serialize, Debug)]
struct ImportFolderReq {
    id: Option<String>,
    name: String,
}

#[derive(serde::Serialize, Debug)]
struct ImportCollectionReq {
    id: Option<String>,
    name: String,
    #[serde(rename = "externalId")]
    external_id: Option<String>,
    // Only consulted when creating a *new* collection (`id: None`); always
    // empty here since rbw always reuses an existing, already-resolved one.
    groups: Vec<serde_json::Value>,
    users: Vec<serde_json::Value>,
}

// One `(cipher index, folder/collection index)` pair, each index into the
// sibling `ciphers`/`folders`-or-`collections` arrays in the same request.
#[derive(serde::Serialize, Debug)]
struct ImportKvpReq {
    key: usize,
    value: usize,
}

#[derive(serde::Serialize, Debug)]
struct ImportCiphersReq {
    ciphers: Vec<ImportCipherReq>,
    folders: Vec<ImportFolderReq>,
    #[serde(rename = "folderRelationships")]
    folder_relationships: Vec<ImportKvpReq>,
}

#[derive(serde::Serialize, Debug)]
struct ImportOrganizationCiphersReq {
    ciphers: Vec<ImportCipherReq>,
    collections: Vec<ImportCollectionReq>,
    #[serde(rename = "collectionRelationships")]
    collection_relationships: Vec<ImportKvpReq>,
}

#[derive(serde::Serialize, Debug)]
struct CipherIdsReq {
    ids: Vec<String>,
}

#[derive(serde::Serialize, Debug)]
struct PurgeReq {
    #[serde(rename = "masterPasswordHash")]
    master_password_hash: String,
}

#[derive(serde::Serialize, Debug)]
struct CollectionPutReq {
    name: String,
    #[serde(rename = "organizationId")]
    organization_id: String,
    #[serde(rename = "externalId")]
    external_id: Option<String>,
    groups: Vec<serde_json::Value>,
    users: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize, Debug)]
struct CollectionCreateRes {
    #[serde(rename = "Id", alias = "id")]
    id: String,
}

#[derive(serde::Deserialize, Debug)]
struct CipherCreateRes {
    #[serde(rename = "Id", alias = "id")]
    id: String,
}

// The body of the first step of the v2 attachment upload (POST
// /ciphers/{id}/attachment/v2): reserve an upload slot for a file of the given
// (encrypted) size.
#[derive(serde::Serialize, Debug)]
struct AttachmentUploadDataReq {
    #[serde(rename = "fileName")]
    file_name: String,
    key: String,
    #[serde(rename = "fileSize")]
    file_size: i64,
}

// The response to the v2 request: where and how to upload the file data.
#[derive(serde::Deserialize, Debug)]
struct AttachmentUploadDataRes {
    #[serde(rename = "attachmentId", alias = "AttachmentId")]
    attachment_id: String,
    #[serde(rename = "url", alias = "Url")]
    url: String,
    // 0 = Direct (POST multipart back to the Bitwarden API), 1 = Azure (PUT the
    // bytes to the returned blob URL).
    #[serde(rename = "fileUploadType", alias = "FileUploadType")]
    file_upload_type: u32,
}

#[derive(Debug, Clone)]
pub struct OrgUser {
    // The OrganizationUser relationship id -- what confirm/remove/etc (all
    // scoped to `/organizations/{orgId}/users/{id}`) expect.
    pub id: String,
    // The account's own (global, not org-scoped) user id -- only this one
    // works for the general `/users/{id}/public-key` lookup `confirm`
    // needs. `None` until the invited email actually has a registered
    // account (confirmed against a real server: confirming too early
    // fails with "User doesn't exist" using the *other* id instead).
    pub user_id: Option<String>,
    pub email: String,
    pub status: i32,
    // Organization role: 0=Owner, 1=Admin, 2=User, 3=Manager.
    pub role: i32,
    pub access_all: bool,
}

#[derive(serde::Serialize, Debug)]
struct OrgUpdateReq {
    name: String,
    #[serde(rename = "billingEmail")]
    billing_email: String,
}

#[derive(serde::Serialize, Debug)]
struct OrgCreateReq {
    name: String,
    #[serde(rename = "billingEmail")]
    billing_email: String,
    #[serde(rename = "planType")]
    plan_type: i32,
    key: String,
    #[serde(rename = "collectionName")]
    collection_name: String,
}

#[derive(serde::Deserialize, Debug)]
struct OrgCreateRes {
    #[serde(rename = "Id", alias = "id")]
    id: String,
}

#[derive(serde::Deserialize, Debug)]
struct UserPublicKeyRes {
    #[serde(rename = "PublicKey", alias = "publicKey")]
    public_key: String,
}

#[derive(serde::Serialize, Debug)]
struct OrgConfirmReq {
    key: String,
}

#[derive(serde::Serialize, Debug)]
struct OrgAcceptReq {
    token: String,
}

#[derive(serde::Serialize, Debug)]
struct OrgInviteReq {
    emails: Vec<String>,
    #[serde(rename = "type")]
    ty: i32,
    #[serde(rename = "accessAll")]
    access_all: bool,
    collections: Vec<serde_json::Value>,
    groups: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize, Debug)]
struct OrgUsersRes {
    #[serde(rename = "Data", alias = "data")]
    data: Vec<OrgUsersResData>,
}

#[derive(serde::Deserialize, Debug)]
struct OrgUsersResData {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "UserId", alias = "userId", default)]
    user_id: Option<String>,
    #[serde(rename = "Email", alias = "email")]
    email: String,
    #[serde(rename = "Status", alias = "status")]
    status: i32,
    #[serde(rename = "Type", alias = "type")]
    role: i32,
    #[serde(rename = "AccessAll", alias = "accessAll", default)]
    access_all: bool,
}

#[derive(Debug, Clone)]
pub struct CollectionUser {
    pub id: String,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

#[derive(Debug, Clone)]
pub struct CollectionDetail {
    pub id: String,
    pub external_id: Option<String>,
    pub groups: Vec<serde_json::Value>,
    pub users: Vec<CollectionUser>,
}

#[derive(serde::Deserialize, Debug)]
struct CollectionUserData {
    #[serde(rename = "id", alias = "Id")]
    id: String,
    #[serde(rename = "readOnly", alias = "ReadOnly", default)]
    read_only: bool,
    #[serde(rename = "hidePasswords", alias = "HidePasswords", default)]
    hide_passwords: bool,
    #[serde(rename = "manage", alias = "Manage", default)]
    manage: bool,
}

#[derive(serde::Deserialize, Debug)]
struct CollectionDetailsRes {
    #[serde(rename = "Data", alias = "data")]
    data: Vec<CollectionDetailsResData>,
}

#[derive(serde::Deserialize, Debug)]
struct CollectionDetailsResData {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "ExternalId", alias = "externalId", default)]
    external_id: Option<String>,
    #[serde(rename = "Groups", alias = "groups", default)]
    groups: Vec<serde_json::Value>,
    #[serde(rename = "Users", alias = "users", default)]
    users: Vec<CollectionUserData>,
}

#[derive(serde::Deserialize, Debug)]
struct FoldersRes {
    #[serde(rename = "Data", alias = "data")]
    data: Vec<FoldersResData>,
}

#[derive(serde::Deserialize, Debug)]
struct FoldersResData {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

#[derive(serde::Serialize, Debug)]
struct FoldersPostReq {
    name: String,
}

// Used for the Bitwarden-Client-Name header. Accepted values:
// https://github.com/bitwarden/server/blob/main/src/Core/Enums/BitwardenClient.cs
const BITWARDEN_CLIENT: &str = "cli";

// DeviceType.LinuxDesktop, as per Bitwarden API device types.
const DEVICE_TYPE: u8 = 8;

// Build an Error from a non-OK, non-401 blocking response, including the body
// when the server sent one.
fn request_failed(
    res: reqwest::blocking::Response,
    status: reqwest::StatusCode,
) -> Error {
    let code = status.as_u16();
    let body = res.text().unwrap_or_default();
    if body.is_empty() {
        Error::RequestFailed { status: code }
    } else {
        Error::RequestFailedWithBody { status: code, body }
    }
}

#[derive(Debug)]
pub struct Client {
    base_url: String,
    identity_url: String,
    ui_url: String,
    client_cert_path: Option<std::path::PathBuf>,
}

impl Client {
    pub fn new(
        base_url: &str,
        identity_url: &str,
        ui_url: &str,
        client_cert_path: Option<&std::path::Path>,
    ) -> Self {
        Self {
            base_url: base_url.to_string(),
            identity_url: identity_url.to_string(),
            ui_url: ui_url.to_string(),
            client_cert_path: client_cert_path
                .map(std::path::Path::to_path_buf),
        }
    }

    async fn reqwest_client(&self) -> Result<reqwest::Client> {
        let mut default_headers = axum::http::HeaderMap::new();
        default_headers.insert(
            "Bitwarden-Client-Name",
            axum::http::HeaderValue::from_static(BITWARDEN_CLIENT),
        );
        default_headers.insert(
            "Bitwarden-Client-Version",
            axum::http::HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        );
        default_headers.append(
            "Device-Type",
            // unwrap is safe here because DEVICE_TYPE is a number and digits
            // are valid ASCII
            axum::http::HeaderValue::from_str(&DEVICE_TYPE.to_string())
                .unwrap(),
        );
        let user_agent = format!(
            "{}/{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        if let Some(client_cert_path) = self.client_cert_path.as_ref() {
            let mut buf = Vec::new();
            let mut f = tokio::fs::File::open(client_cert_path)
                .await
                .map_err(|e| Error::LoadClientCert {
                    source: e,
                    file: client_cert_path.clone(),
                })?;
            f.read_to_end(&mut buf).await.map_err(|e| {
                Error::LoadClientCert {
                    source: e,
                    file: client_cert_path.clone(),
                }
            })?;
            let pem = reqwest::Identity::from_pem(&buf)
                .map_err(|e| Error::CreateReqwestClient { source: e })?;
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .identity(pem)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        } else {
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        }
    }

    pub async fn prelogin(
        &self,
        email: &str,
    ) -> Result<(KdfType, u32, Option<u32>, Option<u32>)> {
        let prelogin = PreloginReq {
            email: email.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/accounts/prelogin"))
            .json(&prelogin)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        let prelogin_res: PreloginRes = res.json_with_path().await?;
        Ok((
            prelogin_res.kdf,
            prelogin_res.kdf_iterations,
            prelogin_res.kdf_memory,
            prelogin_res.kdf_parallelism,
        ))
    }

    pub async fn register(
        &self,
        email: &str,
        device_id: &str,
        apikey: &crate::locked::ApiKey,
    ) -> Result<()> {
        let connect_req = ConnectTokenReq {
            auth: ConnectTokenAuth::ClientCredentials(
                ConnectTokenClientCredentials {
                    username: email.to_string(),
                    client_secret: String::from_utf8(
                        apikey.client_secret().to_vec(),
                    )
                    .unwrap(),
                },
            ),
            grant_type: "client_credentials".to_string(),
            scope: "api".to_string(),
            // XXX unwraps here are not necessarily safe
            client_id: String::from_utf8(apikey.client_id().to_vec())
                .unwrap(),
            device_type: u32::from(DEVICE_TYPE),
            device_identifier: device_id.to_string(),
            device_name: "rbw".to_string(),
            device_push_token: String::new(),
            two_factor_token: None,
            two_factor_provider: None,
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        if res.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let code = res.status().as_u16();
            match res.text().await {
                Ok(body) => match body.clone().json_with_path() {
                    Ok(json) => Err(classify_login_error(&json, code)),
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed { status: code })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed { status: code })
                }
            }
        }
    }

    pub async fn login(
        &self,
        email: &str,
        sso_id: Option<&str>,
        device_id: &str,
        password_hash: &crate::locked::PasswordHash,
        two_factor_token: Option<&str>,
        two_factor_provider: Option<TwoFactorProviderType>,
    ) -> Result<(String, String, String)> {
        let connect_req = match sso_id {
            Some(sso_id) => {
                let (sso_code, sso_code_verifier, callback_url) =
                    self.obtain_sso_code(sso_id).await?;

                ConnectTokenReq {
                    auth: ConnectTokenAuth::AuthCode(ConnectTokenAuthCode {
                        code: sso_code,
                        code_verifier: sso_code_verifier,
                        redirect_uri: callback_url,
                    }),
                    grant_type: "authorization_code".to_string(),
                    scope: "api offline_access".to_string(),
                    client_id: "cli".to_string(),
                    device_type: u32::from(DEVICE_TYPE),
                    device_identifier: device_id.to_string(),
                    device_name: "rbw".to_string(),
                    device_push_token: String::new(),
                    two_factor_token: two_factor_token
                        .map(std::string::ToString::to_string),
                    two_factor_provider: two_factor_provider
                        .map(|ty| ty as u32),
                }
            }
            None => ConnectTokenReq {
                auth: ConnectTokenAuth::Password(ConnectTokenPassword {
                    username: email.to_string(),
                    password: crate::base64::encode(password_hash.hash()),
                }),

                grant_type: "password".to_string(),
                scope: "api offline_access".to_string(),
                client_id: "cli".to_string(),
                device_type: 8,
                device_identifier: device_id.to_string(),
                device_name: "rbw".to_string(),
                device_push_token: String::new(),
                two_factor_token: two_factor_token
                    .map(std::string::ToString::to_string),
                two_factor_provider: two_factor_provider.map(|ty| ty as u32),
            },
        };

        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .header(
                "auth-email",
                crate::base64::encode_url_safe_no_pad(email),
            )
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;

        if res.status() == reqwest::StatusCode::OK {
            let connect_res: ConnectTokenRes = res.json_with_path().await?;
            Ok((
                connect_res.access_token,
                connect_res.refresh_token,
                connect_res.key,
            ))
        } else {
            let code = res.status().as_u16();
            match res.text().await {
                Ok(body) => match body.clone().json_with_path() {
                    Ok(json) => Err(classify_login_error(&json, code)),
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed { status: code })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed { status: code })
                }
            }
        }
    }

    pub async fn send_email_login(
        &self,
        email: &str,
        device_id: &str,
        sso_email_2fa_session_token: &str,
    ) -> Result<()> {
        let send_email_login_req = SendEmailLoginReq {
            email: email.to_string(),
            device_identifier: device_id.to_string(),
            sso_email_2fa_session_token: sso_email_2fa_session_token
                .to_string(),
        };

        let client = self.reqwest_client().await?;
        let res = client
            .post(self.api_url("/two-factor/send-email-login"))
            .json(&send_email_login_req)
            .header(
                "auth-email",
                crate::base64::encode_url_safe_no_pad(email),
            )
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;

        if res.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let code = res.status().as_u16();
            log::warn!("{code}: {:?}", res.text().await);
            Err(Error::RequestFailed { status: code })
        }
    }

    async fn obtain_sso_code(
        &self,
        sso_id: &str,
    ) -> Result<(String, String, String)> {
        let state =
            rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 64);
        let sso_code_verifier =
            rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 64);

        let mut hasher = sha2::Sha256::new();
        hasher.update(sso_code_verifier.clone());
        let code_challenge =
            crate::base64::encode_url_safe_no_pad(hasher.finalize());

        let port = find_free_port(8065, 8070).await?;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| Error::CreateSSOCallbackServer { err: e })?;

        let callback_server =
            start_sso_callback_server(listener, state.as_str());

        let callback_url =
            "http://localhost:".to_string() + port.to_string().as_str();

        open::that(
            self.ui_url.clone()
                + "/#/sso?clientId="
                + "cli"
                + "&redirectUri="
                + urlencoding::encode(callback_url.as_str())
                    .into_owned()
                    .as_str()
                + "&state="
                + state.as_str()
                + "&codeChallenge="
                + code_challenge.as_str()
                + "&identifier="
                + sso_id,
        )
        .map_err(|e| Error::FailedToOpenWebBrowser { err: e })?;
        // TODO: probably it'd be better to display the URL in the console if the automatic
        // open operation fails, instead of failing the whole process? E.g. docker container
        // case

        let sso_code = callback_server.await?;

        Ok((sso_code, sso_code_verifier, callback_url))
    }

    // Creates a new organization (`rbw org create`), owned by whoever's
    // `access_token` this is -- `encrypted_key` must already be their own
    // org key, RSA-encrypted to their own public key, and
    // `encrypted_collection_name` the default collection's name,
    // symmetric-encrypted with that same (not-yet-encrypted-for-transit)
    // org key. Both are prepared agent-side, since deriving the account's
    // RSA key pair needs the retained private key.
    pub async fn create_org(
        &self,
        access_token: &str,
        name: &str,
        billing_email: &str,
        encrypted_key: &str,
        encrypted_collection_name: &str,
    ) -> Result<String> {
        let req = OrgCreateReq {
            name: name.to_string(),
            billing_email: billing_email.to_string(),
            plan_type: 0,
            key: encrypted_key.to_string(),
            collection_name: encrypted_collection_name.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.api_url("/organizations"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let create_res: OrgCreateRes = res.json_with_path().await?;
                Ok(create_res.id)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = res.status().as_u16();
                let body = res.text().await.unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    pub async fn sync(
        &self,
        access_token: &str,
    ) -> Result<(
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
        Vec<crate::db::Collection>,
        Vec<crate::db::Organization>,
    )> {
        let client = self.reqwest_client().await?;
        let res = client
            .get(self.api_url("/sync"))
            .header("Authorization", format!("Bearer {access_token}"))
            // This is necessary for vaultwarden to include the ssh keys in the response
            .header("Bitwarden-Client-Version", "2024.12.0")
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let sync_res: SyncRes = res.json_with_path().await?;
                let folders = sync_res.folders.clone();
                let ciphers = sync_res
                    .ciphers
                    .iter()
                    .filter_map(|cipher| cipher.to_entry(&folders))
                    .collect();
                let org_keys = sync_res
                    .profile
                    .organizations
                    .iter()
                    .map(|org| (org.id.clone(), org.key.clone()))
                    .collect();
                let organizations = sync_res
                    .profile
                    .organizations
                    .iter()
                    .map(|org| crate::db::Organization {
                        id: org.id.clone(),
                        name: org.name.clone(),
                    })
                    .collect();
                let collections = sync_res
                    .collections
                    .iter()
                    .map(|c| crate::db::Collection {
                        id: c.id.clone(),
                        org_id: c.organization_id.clone(),
                        name: c.name.clone(),
                    })
                    .collect();
                Ok((
                    sync_res.profile.key,
                    sync_res.profile.private_key,
                    org_keys,
                    ciphers,
                    collections,
                    organizations,
                ))
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = res.status().as_u16();
                let body = res.text().await.unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    // Permanently deletes every entry in the caller's personal vault in a
    // single server-side call (`rbw purge`), rather than a client-driven
    // loop of individual deletes. `master_password_hash` re-proves
    // knowledge of the master password, matching how `login` re-proves it
    // to authenticate -- both send the same base64-encoded PBKDF2/Argon2
    // hash, never the password itself.
    pub async fn purge_vault(
        &self,
        access_token: &str,
        master_password_hash: &str,
    ) -> Result<()> {
        let req = PurgeReq {
            master_password_hash: master_password_hash.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.api_url("/ciphers/purge"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = res.status().as_u16();
                let body = res.text().await.unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    // Permanently deletes an entire organization (`rbw org delete`),
    // re-proving the master password the same way `purge_vault` does.
    pub async fn delete_org(
        &self,
        access_token: &str,
        org_id: &str,
        master_password_hash: &str,
    ) -> Result<()> {
        let req = PurgeReq {
            master_password_hash: master_password_hash.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.api_url(&format!("/organizations/{org_id}/delete")))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = res.status().as_u16();
                let body = res.text().await.unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    pub fn add(
        &self,
        access_token: &str,
        name: &str,
        data: &crate::db::EntryData,
        fields: &[crate::db::Field],
        notes: Option<&str>,
        folder_id: Option<&str>,
    ) -> Result<String> {
        let (ty, login, card, identity, secure_note, ssh_key) =
            cipher_type_and_fields(data);
        let req = CiphersPostReq {
            ty,
            folder_id: folder_id.map(std::string::ToString::to_string),
            name: name.to_string(),
            notes: notes.map(std::string::ToString::to_string),
            login,
            card,
            identity,
            fields: fields
                .iter()
                .map(|field| CipherField {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect(),
            secure_note,
            ssh_key,
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(self.api_url("/ciphers"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        let status = res.status();
        match status {
            reqwest::StatusCode::OK => {
                let cipher_res: CipherCreateRes = res.json_with_path()?;
                Ok(cipher_res.id)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = status.as_u16();
                let body = res.text().unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    // One cipher's create/edit `/ciphers/{id}` request, minus the id/org/
    // folder placement, into an `ImportCipherReq` -- shared by
    // `import_ciphers`/`import_organization_ciphers` below.
    fn import_cipher_req(
        entry: &crate::actions::ImportCipherEntry,
        organization_id: Option<String>,
        folder_id: Option<String>,
    ) -> ImportCipherReq {
        let (ty, login, card, identity, secure_note, ssh_key) =
            cipher_type_and_fields(&entry.data);
        ImportCipherReq {
            ty,
            folder_id,
            organization_id,
            name: entry.name.clone(),
            notes: entry.notes.clone(),
            login,
            card,
            identity,
            fields: entry
                .fields
                .iter()
                .map(|field| CipherField {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect(),
            secure_note,
            ssh_key,
            password_history: entry
                .history
                .iter()
                .map(|h| CiphersPutReqHistory {
                    last_used_date: h.last_used_date.clone(),
                    password: h.password.clone(),
                })
                .collect(),
        }
    }

    // Bulk-creates every entry in the account's personal vault in a single
    // request -- the same `POST /ciphers/import` the official clients'
    // importer uses (confirmed against both the Bitwarden and Vaultwarden
    // server source). Each entry's (already resolved-or-created)
    // `folder_id` is deduplicated into the shared `folders` array with
    // index-based `folderRelationships`, exactly matching the wire format;
    // entries with no folder simply have no relationship entry.
    pub fn import_ciphers(
        &self,
        access_token: &str,
        entries: &[crate::actions::ImportCipherEntry],
    ) -> Result<()> {
        let mut folder_ids: Vec<String> = Vec::new();
        let mut folder_relationships = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            if let Some(folder_id) = &entry.folder_id {
                let folder_index = folder_ids
                    .iter()
                    .position(|id| id == folder_id)
                    .unwrap_or_else(|| {
                        folder_ids.push(folder_id.clone());
                        folder_ids.len() - 1
                    });
                folder_relationships.push(ImportKvpReq {
                    key: index,
                    value: folder_index,
                });
            }
        }

        let req = ImportCiphersReq {
            ciphers: entries
                .iter()
                .map(|entry| Self::import_cipher_req(entry, None, None))
                .collect(),
            folders: folder_ids
                .into_iter()
                .map(|id| ImportFolderReq {
                    id: Some(id),
                    name: String::new(),
                })
                .collect(),
            folder_relationships,
        };

        self.post_import(access_token, "/ciphers/import", &req)
    }

    // Bulk-creates every entry directly into one organization (optionally
    // across several of its collections at once) in a single request --
    // `POST /ciphers/import-organization`, the org-scoped sibling of
    // `import_ciphers` the official clients' org-level import feature
    // uses. Every `collection_id` an entry names is expected to already
    // exist (resolved by the caller) -- this never asks the server to
    // create a new collection, so it never needs the elevated permissions
    // that path requires.
    pub fn import_organization_ciphers(
        &self,
        access_token: &str,
        org_id: &str,
        entries: &[crate::actions::ImportCipherEntry],
    ) -> Result<()> {
        let mut collection_ids: Vec<String> = Vec::new();
        let mut collection_relationships = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            for collection_id in &entry.collection_ids {
                let collection_index = collection_ids
                    .iter()
                    .position(|id| id == collection_id)
                    .unwrap_or_else(|| {
                        collection_ids.push(collection_id.clone());
                        collection_ids.len() - 1
                    });
                collection_relationships.push(ImportKvpReq {
                    key: index,
                    value: collection_index,
                });
            }
        }

        let req = ImportOrganizationCiphersReq {
            ciphers: entries
                .iter()
                .map(|entry| {
                    Self::import_cipher_req(
                        entry,
                        Some(org_id.to_string()),
                        None,
                    )
                })
                .collect(),
            collections: collection_ids
                .into_iter()
                .map(|id| ImportCollectionReq {
                    id: Some(id),
                    name: String::new(),
                    external_id: None,
                    groups: Vec::new(),
                    users: Vec::new(),
                })
                .collect(),
            collection_relationships,
        };

        self.post_import(
            access_token,
            &format!("/ciphers/import-organization?organizationId={org_id}"),
            &req,
        )
    }

    fn post_import(
        &self,
        access_token: &str,
        path: &str,
        req: &impl serde::Serialize,
    ) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(self.api_url(path))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        let status = res.status();
        match status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = status.as_u16();
                let body = res.text().unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    pub fn edit(
        &self,
        access_token: &str,
        id: &str,
        org_id: Option<&str>,
        name: &str,
        data: &crate::db::EntryData,
        fields: &[crate::db::Field],
        notes: Option<&str>,
        folder_uuid: Option<&str>,
        history: &[crate::db::HistoryEntry],
    ) -> Result<()> {
        let mut req = CiphersPutReq {
            ty: match data {
                crate::db::EntryData::Login { .. } => 1,
                crate::db::EntryData::SecureNote => 2,
                crate::db::EntryData::Card { .. } => 3,
                crate::db::EntryData::Identity { .. } => 4,
                crate::db::EntryData::SshKey { .. } => 5,
            },
            folder_id: folder_uuid.map(std::string::ToString::to_string),
            organization_id: org_id.map(std::string::ToString::to_string),
            name: name.to_string(),
            notes: notes.map(std::string::ToString::to_string),
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            ssh_key: None,
            fields: fields
                .iter()
                .map(|field| CipherField {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect(),
            password_history: history
                .iter()
                .map(|entry| CiphersPutReqHistory {
                    last_used_date: entry.last_used_date.clone(),
                    password: entry.password.clone(),
                })
                .collect(),
        };
        match data {
            crate::db::EntryData::Login {
                username,
                password,
                totp,
                uris,
                fido2_credentials,
            } => {
                let uris = if uris.is_empty() {
                    None
                } else {
                    Some(
                        uris.iter()
                            .map(|s| CipherLoginUri {
                                uri: Some(s.uri.clone()),
                                match_type: s.match_type,
                            })
                            .collect(),
                    )
                };
                let fido2_credentials = if fido2_credentials.is_empty() {
                    None
                } else {
                    Some(
                        fido2_credentials
                            .iter()
                            .map(|c| CipherFido2Credential {
                                credential_id: c.credential_id.clone(),
                                key_type: c.key_type.clone(),
                                key_algorithm: c.key_algorithm.clone(),
                                key_curve: c.key_curve.clone(),
                                key_value: c.key_value.clone(),
                                rp_id: c.rp_id.clone(),
                                user_handle: c.user_handle.clone(),
                                user_name: c.user_name.clone(),
                                counter: c.counter.clone(),
                                rp_name: c.rp_name.clone(),
                                user_display_name: c
                                    .user_display_name
                                    .clone(),
                                discoverable: c.discoverable.clone(),
                                creation_date: c.creation_date.clone(),
                            })
                            .collect(),
                    )
                };
                req.login = Some(CipherLogin {
                    username: username.clone(),
                    password: password.clone(),
                    totp: totp.clone(),
                    uris,
                    fido2_credentials,
                });
            }
            crate::db::EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => {
                req.card = Some(CipherCard {
                    cardholder_name: cardholder_name.clone(),
                    number: number.clone(),
                    brand: brand.clone(),
                    exp_month: exp_month.clone(),
                    exp_year: exp_year.clone(),
                    code: code.clone(),
                });
            }
            crate::db::EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
            } => {
                req.identity = Some(CipherIdentity {
                    title: title.clone(),
                    first_name: first_name.clone(),
                    middle_name: middle_name.clone(),
                    last_name: last_name.clone(),
                    address1: address1.clone(),
                    address2: address2.clone(),
                    address3: address3.clone(),
                    city: city.clone(),
                    state: state.clone(),
                    postal_code: postal_code.clone(),
                    country: country.clone(),
                    phone: phone.clone(),
                    email: email.clone(),
                    ssn: ssn.clone(),
                    license_number: license_number.clone(),
                    passport_number: passport_number.clone(),
                    username: username.clone(),
                });
            }
            crate::db::EntryData::SecureNote => {
                req.secure_note = Some(CipherSecureNote {});
            }
            crate::db::EntryData::SshKey {
                private_key,
                public_key,
                fingerprint,
            } => {
                req.ssh_key = Some(CipherSshKey {
                    private_key: private_key.clone(),
                    public_key: public_key.clone(),
                    fingerprint: fingerprint.clone(),
                });
            }
        }
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!("/ciphers/{id}")))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        let status = res.status();
        match status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = status.as_u16();
                let body = res.text().unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    // Soft delete (move to trash): both official Bitwarden and Vaultwarden
    // treat the bare `DELETE /ciphers/{id}` as a *permanent*, unrecoverable
    // delete -- the trash-recoverable soft delete is this PUT route
    // instead (confirmed against bitwarden/server's CiphersController.cs
    // `PutDelete`/`SoftDeleteAsync` and vaultwarden's `delete_cipher_put`).
    pub fn remove(&self, access_token: &str, id: &str) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!("/ciphers/{id}/delete")))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    // The actual permanent, unrecoverable delete -- bypasses trash
    // entirely (or purges an entry already in it). This is what the bare
    // `DELETE /ciphers/{id}` route really does; see `remove()`'s comment.
    // Only reachable via `rbw remove --force`.
    pub fn delete_permanently(
        &self,
        access_token: &str,
        id: &str,
    ) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .delete(self.api_url(&format!("/ciphers/{id}")))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn archive(&self, access_token: &str, id: &str) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!("/ciphers/{id}/archive")))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn unarchive(&self, access_token: &str, id: &str) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!("/ciphers/{id}/unarchive")))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn archive_multiple(
        &self,
        access_token: &str,
        ids: &[String],
    ) -> Result<()> {
        let req = CipherIdsReq { ids: ids.to_vec() };
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url("/ciphers/archive"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn unarchive_multiple(
        &self,
        access_token: &str,
        ids: &[String],
    ) -> Result<()> {
        let req = CipherIdsReq { ids: ids.to_vec() };
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url("/ciphers/unarchive"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn restore(&self, access_token: &str, id: &str) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!("/ciphers/{id}/restore")))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn restore_multiple(
        &self,
        access_token: &str,
        ids: &[String],
    ) -> Result<()> {
        let req = CipherIdsReq { ids: ids.to_vec() };
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url("/ciphers/restore"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn delete_attachment(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .delete(self.api_url(&format!(
                "/ciphers/{cipher_id}/attachment/{attachment_id}"
            )))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn edit_collections(
        &self,
        access_token: &str,
        id: &str,
        collection_ids: &[String],
    ) -> Result<()> {
        let req = CiphersCollectionsPutReq {
            collection_ids: collection_ids.to_vec(),
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!("/ciphers/{id}/collections")))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn attachment_url(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<String> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(self.api_url(&format!(
                "/ciphers/{cipher_id}/attachment/{attachment_id}"
            )))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let res: AttachmentDataRes = res.json_with_path()?;
                Ok(res.url)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    // Upload a file as an attachment using the two-step v2 flow: first reserve
    // an upload slot (which returns where/how to upload), then send the bytes
    // either to Azure blob storage (bitwarden.com) or back to the API as a
    // multipart POST (self-hosted "direct" uploads). The old single-step
    // /attachment endpoint has been removed from bitwarden.com.
    pub fn create_attachment(
        &self,
        access_token: &str,
        cipher_id: &str,
        encrypted_filename: &str,
        encrypted_key: &str,
        encrypted_data: Vec<u8>,
    ) -> Result<()> {
        let client = reqwest::blocking::Client::new();

        // Step 1: reserve an upload slot.
        let req = AttachmentUploadDataReq {
            file_name: encrypted_filename.to_string(),
            key: encrypted_key.to_string(),
            file_size: i64::try_from(encrypted_data.len())
                .unwrap_or(i64::MAX),
        };
        let res = client
            .post(
                self.api_url(&format!("/ciphers/{cipher_id}/attachment/v2")),
            )
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        let upload: AttachmentUploadDataRes = match res.status() {
            reqwest::StatusCode::OK => res.json_with_path()?,
            reqwest::StatusCode::UNAUTHORIZED => {
                return Err(Error::RequestUnauthorized)
            }
            status => return Err(request_failed(res, status)),
        };

        // Step 2: upload the encrypted bytes where step 1 told us to.
        let res = if upload.file_upload_type == 1 {
            // Azure blob: PUT the bytes to the returned SAS URL.
            client
                .put(&upload.url)
                .header("x-ms-blob-type", "BlockBlob")
                .body(encrypted_data)
                .send()
                .map_err(|source| Error::Reqwest { source })?
        } else {
            // Direct: POST the bytes as multipart back to the API.
            let url = if upload.url.starts_with("http") {
                upload.url
            } else {
                self.api_url(&format!(
                    "/ciphers/{cipher_id}/attachment/{}",
                    upload.attachment_id
                ))
            };
            let form = reqwest::blocking::multipart::Form::new().part(
                "data",
                reqwest::blocking::multipart::Part::bytes(encrypted_data)
                    .file_name("blob")
                    .mime_str("application/octet-stream")
                    .map_err(|source| Error::Reqwest { source })?,
            );
            client
                .post(url)
                .header("Authorization", format!("Bearer {access_token}"))
                .multipart(form)
                .send()
                .map_err(|source| Error::Reqwest { source })?
        };

        match res.status() {
            reqwest::StatusCode::OK | reqwest::StatusCode::CREATED => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            status => Err(request_failed(res, status)),
        }
    }

    pub fn download_attachment(&self, url: &str) -> Result<Vec<u8>> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(url)
            .header("cache", "no-cache")
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => res
                .bytes()
                .map(|bytes| bytes.to_vec())
                .map_err(|source| Error::Reqwest { source }),
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    // Organization names (unlike collection names) are plaintext, not
    // per-org-key-encrypted -- see the `Organization` doc comment in db.rs.
    // billing_email is required by the server on every update even though
    // this command only ever changes the name; callers pass through
    // whatever the org's current billing email already is.
    pub fn rename_org(
        &self,
        access_token: &str,
        org_id: &str,
        name: &str,
        billing_email: &str,
    ) -> Result<()> {
        let req = OrgUpdateReq {
            name: name.to_string(),
            billing_email: billing_email.to_string(),
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!("/organizations/{org_id}")))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn rename_collection(
        &self,
        access_token: &str,
        org_id: &str,
        collection_id: &str,
        encrypted_name: &str,
    ) -> Result<()> {
        let req = CollectionPutReq {
            name: encrypted_name.to_string(),
            organization_id: org_id.to_string(),
            external_id: None,
            groups: vec![],
            users: vec![],
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!(
                "/organizations/{org_id}/collections/{collection_id}"
            )))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn create_collection(
        &self,
        access_token: &str,
        org_id: &str,
        encrypted_name: &str,
    ) -> Result<String> {
        let req = CollectionPutReq {
            name: encrypted_name.to_string(),
            organization_id: org_id.to_string(),
            external_id: None,
            groups: vec![],
            users: vec![],
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(
                self.api_url(&format!("/organizations/{org_id}/collections")),
            )
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let collection_res: CollectionCreateRes =
                    res.json_with_path()?;
                Ok(collection_res.id)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn delete_collection(
        &self,
        access_token: &str,
        org_id: &str,
        collection_id: &str,
    ) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .delete(self.api_url(&format!(
                "/organizations/{org_id}/collections/{collection_id}"
            )))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn org_users(
        &self,
        access_token: &str,
        org_id: &str,
    ) -> Result<Vec<OrgUser>> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(self.api_url(&format!("/organizations/{org_id}/users")))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let users_res: OrgUsersRes = res.json_with_path()?;
                Ok(users_res
                    .data
                    .into_iter()
                    .map(|u| OrgUser {
                        id: u.id,
                        user_id: u.user_id,
                        email: u.email,
                        status: u.status,
                        role: u.role,
                        access_all: u.access_all,
                    })
                    .collect())
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    // Invites a user by email into an org (`rbw org invite`). No key
    // material changes hands here -- the invitee hasn't accepted yet, so
    // there's nothing to encrypt to them until `confirm_org_user`.
    pub fn invite_org_user(
        &self,
        access_token: &str,
        org_id: &str,
        email: &str,
        role: i32,
    ) -> Result<()> {
        let req = OrgInviteReq {
            emails: vec![email.to_string()],
            ty: role,
            access_all: true,
            collections: vec![],
            groups: vec![],
        };
        let client = reqwest::blocking::Client::new();
        let res =
            client
                .post(self.api_url(&format!(
                    "/organizations/{org_id}/users/invite"
                )))
                .header("Authorization", format!("Bearer {access_token}"))
                .json(&req)
                .send()
                .map_err(|source| Error::Reqwest { source })?;
        let status = res.status();
        match status {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = status.as_u16();
                let body = res.text().unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    pub fn remove_org_user(
        &self,
        access_token: &str,
        org_id: &str,
        user_id: &str,
    ) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let res =
            client
                .delete(self.api_url(&format!(
                    "/organizations/{org_id}/users/{user_id}"
                )))
                .header("Authorization", format!("Bearer {access_token}"))
                .send()
                .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    // Accepts an org invite (`rbw org accept`), called by the invitee
    // using their own token -- `org_id`/`user_id`/`token` all come
    // straight from the invite link/email (`organizationId`,
    // `organizationUserId`, and `token` query params respectively), since
    // an invited-but-not-yet-accepted user generally can't look any of
    // that up for themselves. No key material is involved; that only
    // happens once the *inviter* confirms them afterward.
    pub fn accept_org_invite(
        &self,
        access_token: &str,
        org_id: &str,
        user_id: &str,
        token: &str,
    ) -> Result<()> {
        let req = OrgAcceptReq {
            token: token.to_string(),
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(self.api_url(&format!(
                "/organizations/{org_id}/users/{user_id}/accept"
            )))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = res.status().as_u16();
                let body = res.text().unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    // Fetches a user's RSA public key (raw DER, base64-encoded), needed to
    // encrypt the org key to them in `confirm_org_user`. Deliberately not
    // org-scoped in the API itself -- it's a general user lookup.
    pub fn user_public_key(
        &self,
        access_token: &str,
        user_id: &str,
    ) -> Result<String> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(self.api_url(&format!("/users/{user_id}/public-key")))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let key_res: UserPublicKeyRes = res.json_with_path()?;
                Ok(key_res.public_key)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = res.status().as_u16();
                let body = res.text().unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    // Confirms a member who has accepted their invite (`rbw org confirm`),
    // re-encrypting the org's key to their now-known public key.
    // `encrypted_key` must already be prepared that way -- done
    // agent-side, since it needs the org key already cached from unlock.
    pub async fn confirm_org_user(
        &self,
        access_token: &str,
        org_id: &str,
        user_id: &str,
        encrypted_key: &str,
    ) -> Result<()> {
        let req = OrgConfirmReq {
            key: encrypted_key.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.api_url(&format!(
                "/organizations/{org_id}/users/{user_id}/confirm"
            )))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => {
                let code = res.status().as_u16();
                let body = res.text().await.unwrap_or_default();
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    pub fn collections_details(
        &self,
        access_token: &str,
        org_id: &str,
    ) -> Result<Vec<CollectionDetail>> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(self.api_url(&format!(
                "/organizations/{org_id}/collections/details"
            )))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let details_res: CollectionDetailsRes =
                    res.json_with_path()?;
                Ok(details_res
                    .data
                    .into_iter()
                    .map(|c| CollectionDetail {
                        id: c.id,
                        external_id: c.external_id,
                        groups: c.groups,
                        users: c
                            .users
                            .into_iter()
                            .map(|u| CollectionUser {
                                id: u.id,
                                read_only: u.read_only,
                                hide_passwords: u.hide_passwords,
                                manage: u.manage,
                            })
                            .collect(),
                    })
                    .collect())
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn set_collection_users(
        &self,
        access_token: &str,
        org_id: &str,
        collection_id: &str,
        encrypted_name: &str,
        external_id: Option<&str>,
        groups: &[serde_json::Value],
        users: &[CollectionUser],
    ) -> Result<()> {
        let users: Vec<serde_json::Value> = users
            .iter()
            .map(|u| {
                serde_json::json!({
                    "id": u.id,
                    "readOnly": u.read_only,
                    "hidePasswords": u.hide_passwords,
                    "manage": u.manage,
                })
            })
            .collect();
        let req = CollectionPutReq {
            name: encrypted_name.to_string(),
            organization_id: org_id.to_string(),
            external_id: external_id.map(std::string::ToString::to_string),
            groups: groups.to_vec(),
            users,
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .put(self.api_url(&format!(
                "/organizations/{org_id}/collections/{collection_id}"
            )))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn folders(
        &self,
        access_token: &str,
    ) -> Result<Vec<(String, String)>> {
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(self.api_url("/folders"))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let folders_res: FoldersRes = res.json_with_path()?;
                Ok(folders_res
                    .data
                    .iter()
                    .map(|folder| (folder.id.clone(), folder.name.clone()))
                    .collect())
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn create_folder(
        &self,
        access_token: &str,
        name: &str,
    ) -> Result<String> {
        let req = FoldersPostReq {
            name: name.to_string(),
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(self.api_url("/folders"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let folders_res: FoldersResData = res.json_with_path()?;
                Ok(folders_res.id)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn exchange_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<String> {
        let connect_req = ConnectRefreshTokenReq {
            grant_type: "refresh_token".to_string(),
            client_id: "cli".to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let client = reqwest::blocking::Client::new();
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let connect_res: ConnectRefreshTokenRes =
                    res.json_with_path()?;
                Ok(connect_res.access_token)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            s => {
                let code = s.as_u16();
                let body = res.text().unwrap_or_default();
                log::warn!("refresh token exchange failed ({code}): {body}");
                if let Ok(error_res) =
                    serde_json::from_str::<ConnectErrorRes>(&body)
                {
                    if error_res.error == "invalid_grant" {
                        return Err(Error::SessionExpired);
                    }
                }
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    pub async fn exchange_refresh_token_async(
        &self,
        refresh_token: &str,
    ) -> Result<String> {
        let connect_req = ConnectRefreshTokenReq {
            grant_type: "refresh_token".to_string(),
            client_id: "cli".to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let connect_res: ConnectRefreshTokenRes =
                    res.json_with_path().await?;
                Ok(connect_res.access_token)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            s => {
                let code = s.as_u16();
                let body = res.text().await.unwrap_or_default();
                log::warn!("refresh token exchange failed ({code}): {body}");
                if let Ok(error_res) =
                    serde_json::from_str::<ConnectErrorRes>(&body)
                {
                    if error_res.error == "invalid_grant" {
                        return Err(Error::SessionExpired);
                    }
                }
                if body.is_empty() {
                    Err(Error::RequestFailed { status: code })
                } else {
                    Err(Error::RequestFailedWithBody { status: code, body })
                }
            }
        }
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn identity_url(&self, path: &str) -> String {
        format!("{}{}", self.identity_url, path)
    }
}

async fn find_free_port(bottom: u16, top: u16) -> Result<u16> {
    for port in bottom..top {
        if tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(port);
        }
    }

    Err(Error::FailedToFindFreePort {
        range: format!("({bottom}..{top})"),
    })
}

#[derive(Clone)]
struct SSOHandlerState {
    state: String,
    sender: tokio::sync::mpsc::Sender<Result<String>>,
}

async fn start_sso_callback_server(
    listener: tokio::net::TcpListener,
    state: &str,
) -> Result<String> {
    let (shut_sender, shut_receiver) = tokio::sync::mpsc::channel(1);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

    let sso_handler_state = std::sync::Arc::new(SSOHandlerState {
        state: state.to_string(),
        sender: shut_sender,
    });

    let app = axum::Router::new()
        .route("/", axum::routing::get(handle_sso_callback))
        .with_state(sso_handler_state);

    axum::serve(listener, app)
        .with_graceful_shutdown(sso_server_graceful_shutdown(
            sender,
            shut_receiver,
        ))
        .await
        .map_err(|e| Error::FailedToProcessSSOCallback {
            msg: e.to_string(),
        })?;

    receiver.recv().await.unwrap()
}

async fn sso_server_graceful_shutdown(
    sender: tokio::sync::mpsc::Sender<Result<String>>,
    mut receiver: tokio::sync::mpsc::Receiver<Result<String>>,
) {
    sender.send(receiver.recv().await.unwrap()).await.unwrap();
}

async fn handle_sso_callback(
    axum::extract::State(state): axum::extract::State<
        std::sync::Arc<SSOHandlerState>,
    >,
    axum::extract::Query(params): axum::extract::Query<
        std::collections::HashMap<String, String>,
    >,
) -> axum::http::Response<String> {
    match sso_query_code(&params, state.state.as_str()) {
        Ok(sso_code) => {
            state.sender.send(Ok(sso_code)).await.unwrap();

            axum::http::Response::builder().status(axum::http::StatusCode::OK).
            body(
                "<html><head><title>Success | rbw</title></head><body> \
                  <h1>Successfully authenticated with rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>".to_string()).unwrap()
        }
        Err(e) => {
            state.sender.send(Err(e)).await.unwrap();

            axum::http::Response::builder().status(axum::http::StatusCode::BAD_REQUEST).
            body(
                "<html><head><title>Failed | rbw</title></head><body> \
                  <h1>Something went wrong logging into the rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>".to_string()).unwrap()
        }
    }
}

fn sso_query_code(
    params: &std::collections::HashMap<String, String>,
    state: &str,
) -> Result<String> {
    let sso_code =
        params
            .get("code")
            .ok_or(Error::FailedToProcessSSOCallback {
                msg: "Could not obtain code from the URL".to_string(),
            })?;

    let received_state =
        params
            .get("state")
            .ok_or(Error::FailedToProcessSSOCallback {
                msg: "Could not obtain state from the URL".to_string(),
            })?;

    if received_state.split("_identifier=").next().unwrap() != state {
        return Err(Error::FailedToProcessSSOCallback {
            msg: format!("SSO callback states do not match, sent: {state}, received: {received_state}"),
        });
    }

    Ok(sso_code.clone())
}

fn classify_login_error(error_res: &ConnectErrorRes, code: u16) -> Error {
    let error_desc = error_res.error_description.clone();
    let error_desc = error_desc.as_deref();
    match error_res.error.as_str() {
        "invalid_grant" => match error_desc {
            Some("invalid_username_or_password") => {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    return Error::IncorrectPassword { message };
                }
            }
            Some("Two factor required.") => {
                if let Some(providers) =
                    error_res.two_factor_providers.as_ref()
                {
                    return Error::TwoFactorRequired {
                        providers: providers.clone(),
                        sso_email_2fa_session_token: error_res
                            .sso_email_2fa_session_token
                            .clone(),
                    };
                }
            }
            Some("Captcha required.") => {
                return Error::RegistrationRequired;
            }
            _ => {}
        },
        "invalid_client" => {
            return Error::IncorrectApiKey;
        }
        ""
            // bitwarden_rs returns an empty error and error_description for
            // this case, for some reason
            if (error_desc.is_none() || error_desc == Some("")) => {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    match message.as_str() {
                        "Username or password is incorrect. Try again"
                        | "TOTP code is not a number" => {
                            return Error::IncorrectPassword { message };
                        }
                        s => {
                            if s.starts_with(
                                "Invalid TOTP code! Server time: ",
                            ) {
                                return Error::IncorrectPassword { message };
                            }
                        }
                    }
                }
            }
        _ => {}
    }

    log::warn!("unexpected error received during login: {error_res:?}");
    Error::RequestFailed { status: code }
}
