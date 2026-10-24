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

// A stored URI's scheme (when it has one) and its URL; scheme-less values such
// as "example.com" or "localhost:3000" are read as hosts.
pub(super) fn stored_url(url: &str) -> Option<(Option<String>, url::Url)> {
    if let Ok(parsed) = url::Url::parse(url) {
        if parsed.host_str().is_some() {
            return Some((Some(parsed.scheme().to_string()), parsed));
        }
    }
    url::Url::parse(&format!("https://{url}"))
        .ok()
        .filter(|parsed| parsed.host_str().is_some())
        .map(|parsed| (None, parsed))
}

// Bitwarden's "Base domain": both hosts share a registrable domain (eTLD+1
// per the public suffix list). Hosts without one (IP addresses, localhost,
// single labels, bare public suffixes) must match exactly, including port.
pub(super) fn registrable_domain(url: &url::Url) -> Option<&str> {
    match url.host() {
        Some(url::Host::Domain(host)) => psl::domain_str(host),
        _ => None,
    }
}

pub(super) fn same_base_domain(stored: &url::Url, given: &url::Url) -> bool {
    match (registrable_domain(stored), registrable_domain(given)) {
        (Some(stored), Some(given)) => stored.eq_ignore_ascii_case(given),
        (None, None) => host_port(stored) == host_port(given),
        _ => false,
    }
}

// rbw's own default: the stored host (with port) or any of its subdomains.
pub(super) fn matches_host_or_subdomain(
    url: &str,
    given_url: &url::Url,
) -> bool {
    let Some(given_host_port) = host_port(given_url) else {
        return false;
    };
    if let Ok(self_url) = url::Url::parse(url) {
        if let Some(self_host_port) = host_port(&self_url) {
            if self_url.scheme() == given_url.scheme()
                && (self_host_port == given_host_port
                    || given_host_port
                        .ends_with(&format!(".{self_host_port}")))
            {
                return true;
            }
        }
    }
    url == given_host_port || given_host_port.ends_with(&format!(".{url}"))
}

/// On a plain-HTTP page (other than loopback) only URIs that are explicitly
/// `http:` may match; `https:` and scheme-less values are skipped, so a
/// credential saved for HTTPS never goes to an HTTP page.
pub fn skip_insecure_uri(url: &url::Url, value: &str) -> bool {
    url.scheme() == "http"
        && !matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        )
        && !value.trim_start().to_ascii_lowercase().starts_with("http:")
}

pub fn matches_url(
    url: &str,
    match_type: Option<rbw::api::UriMatchType>,
    given_url: &url::Url,
    default: rbw::config::UriMatchDefault,
) -> bool {
    let Some(match_type) = match_type.or_else(|| default.match_type()) else {
        return matches_host_or_subdomain(url, given_url);
    };
    match match_type {
        rbw::api::UriMatchType::Domain => {
            let Some((scheme, stored)) = stored_url(url) else {
                return false;
            };
            scheme.is_none_or(|scheme| scheme == given_url.scheme())
                && same_base_domain(&stored, given_url)
        }
        rbw::api::UriMatchType::Host => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && self_host_port == given_host_port
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
        }
        rbw::api::UriMatchType::StartsWith => {
            // Compare against the normalized stored URL so that an origin
            // like "https://example.com" cannot match
            // "https://example.com.evil.net/".
            match url::Url::parse(url) {
                Ok(stored) if stored.host_str().is_some() => {
                    stored.origin() == given_url.origin()
                        && given_url.as_str().starts_with(stored.as_str())
                }
                _ => given_url.to_string().starts_with(url),
            }
        }
        rbw::api::UriMatchType::Exact => {
            if given_url.path() == "/" {
                given_url.to_string().trim_end_matches('/')
                    == url.trim_end_matches('/')
            } else {
                given_url.to_string() == url
            }
        }
        rbw::api::UriMatchType::RegularExpression => {
            let Ok(rx) = regex::Regex::new(url) else {
                return false;
            };
            rx.is_match(given_url.as_ref())
        }
        rbw::api::UriMatchType::Never => false,
    }
}

pub(super) fn host_port(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        url.port().map_or_else(
            || host.to_string(),
            |port| format!("{host}:{port}"),
        ),
    )
}

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
            _ => return Err(anyhow::anyhow!("unknown field {s}")),
        })
    }
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
    "passkeyCounter",
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
    "browser.clients",
    "browser.fingerprintAutoStart",
];
