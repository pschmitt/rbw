#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type")]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum DecryptedData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Option<Vec<DecryptedUri>>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fido2_credentials: Vec<DecryptedFido2Credential>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        public_key: Option<String>,
        fingerprint: Option<String>,
        private_key: Option<String>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedField {
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(serialize_with = "serialize_field_type", rename = "type")]
    pub ty: Option<rbw::api::FieldType>,
    /// The item field a linked field stands for (100 login username, 101 login
    /// password, ...), as the number Bitwarden uses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_id: Option<rbw::api::LinkedIdType>,
}

#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
pub(super) fn serialize_field_type<S>(
    ty: &Option<rbw::api::FieldType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match ty {
        Some(ty) => {
            let s = match ty {
                rbw::api::FieldType::Text => "text",
                rbw::api::FieldType::Hidden => "hidden",
                rbw::api::FieldType::Boolean => "boolean",
                rbw::api::FieldType::Linked => "linked",
            };
            serializer.serialize_some(&Some(s))
        }
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedHistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedUri {
    pub uri: String,
    pub match_type: Option<rbw::api::UriMatchType>,
}

// A decrypted passkey. `creation_date` is never encrypted to begin with
// (see `rbw::db::Fido2Credential`); every other field was decrypted the
// same way `password`/`username` are.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedFido2Credential {
    pub credential_id: Option<String>,
    pub key_type: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_curve: Option<String>,
    pub key_value: Option<String>,
    pub rp_id: Option<String>,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: Option<String>,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: Option<String>,
    pub creation_date: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EditableCipher {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub data: EditableData,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<EditableCustomField>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EditableData {
    Login {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        uris: Vec<EditableUri>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        totp: Option<String>,
        // Round-trips unchanged if left untouched in the editor -- not
        // meant to be hand-edited (it's opaque key material), just carried
        // through so editing an entry can never destroy its passkey the
        // way an absent field on the outgoing request would (Vaultwarden
        // stores the whole `login` object wholesale, no per-field merge).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fido2_credentials: Vec<EditableFido2Credential>,
    },
    Card {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cardholder_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brand: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exp_month: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exp_year: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    Identity {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        first_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        middle_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address1: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address2: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address3: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        city: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        postal_code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        country: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        phone: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ssn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        license_number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passport_number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        private_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fingerprint: Option<String>,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EditableUri {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct EditableFido2Credential {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_curve: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discoverable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EditableCustomField {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(
        rename = "type",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ty: Option<String>,
}

// The configured `defaultUriMatch`, read once per process (the CLI is
// short-lived; the browser host reads its config per request instead).
pub fn configured_uri_match() -> rbw::config::UriMatchDefault {
    static DEFAULT: std::sync::OnceLock<rbw::config::UriMatchDefault> =
        std::sync::OnceLock::new();
    *DEFAULT.get_or_init(|| {
        rbw::config::Config::load()
            .map(|config| config.default_uri_match)
            .unwrap_or_default()
    })
}

pub use rbw::uri_match::{matches_url, skip_insecure_uri};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ListField {
    Id,
    Name,
    User,
    Password,
    Folder,
    Uri,
    EntryType,
    Collections,
    Modified,
    Account,
    Attachments,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum TableColumnStyle {
    Id,
    Name,
    User,
    Password,
    Folder,
    EntryType,
    Collections,
    Attachments,
    Size,
    Account,
    Status,
    Default,
}

pub(super) struct TableColumn<'a> {
    pub(super) header: &'a str,
    pub(super) style: TableColumnStyle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Default,
    Name,
    Json,
    Yaml,
}

impl std::convert::TryFrom<&String> for ListField {
    type Error = anyhow::Error;

    fn try_from(s: &String) -> anyhow::Result<Self> {
        Ok(match s.as_str() {
            "name" => Self::Name,
            "id" | "uid" => Self::Id,
            "user" => Self::User,
            "password" => Self::Password,
            "folder" => Self::Folder,
            "type" => Self::EntryType,
            "collections" => Self::Collections,
            "modified" | "revision" => Self::Modified,
            "account" => Self::Account,
            "attachments" => Self::Attachments,
            _ => return Err(anyhow::anyhow!("unknown field {s}")),
        })
    }
}

/// Parses `--fields`. Without it the listing shows id, name and user, plus
/// the account and attachments columns where they apply. An explicit list is
/// shown as given; the flag says which of the two it was.
pub(super) fn parse_list_fields(
    fields: &[String],
) -> anyhow::Result<(Vec<ListField>, bool)> {
    if fields.is_empty() {
        return Ok((
            vec![ListField::Id, ListField::Name, ListField::User],
            false,
        ));
    }
    let fields = fields
        .iter()
        .map(std::convert::TryFrom::try_from)
        .collect::<anyhow::Result<_>>()?;
    Ok((fields, true))
}

pub const CONFIG_KEYS: &[&str] = &[
    "email",
    "ssoId",
    "baseUrl",
    "identityUrl",
    "uiUrl",
    "notificationsUrl",
    "clientCertPath",
    "primaryAccount",
    "agent.syncInterval",
    "agent.lockTimeout",
    "unlockUi",
    "unlockNoEcho",
    "unlockFingerprint",
    "unlockHideFingerprintNotice",
    "passkeyCounter",
    "upgrade.autoRestart",
    "pinentry.command",
    "pinentry.timeout",
    "termux.keyAlias",
    "fzf.enabled",
    "fzf.options",
    "tui.lockTimeout",
    "hide.archived",
    "hide.trashed",
    "passwordGen.length",
    "passwordGen.noSymbols",
    "passwordGen.onlyNumbers",
    "passwordGen.nonconfusables",
    "passwordGen.diceware",
    "clipboard",
    "defaultUriMatch",
    "redact",
    "browser.clients",
    "browser.fingerprintAutoStart",
];
