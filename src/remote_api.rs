//! Types shared by rbw's authenticated remote field API and its clients.

use anyhow::Context as _;
use std::io::Write as _;
use std::str::FromStr;

/// A single field a remote client may request from one vault item.
///
/// Custom fields are identified by their decrypted name. Duplicate custom
/// field names are rejected by the server because they cannot be selected
/// unambiguously.
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
#[serde(try_from = "String", into = "String")]
pub enum FieldRef {
    Name,
    Username,
    Password,
    Totp,
    Uri(usize),
    Notes,
    Custom(String),
    CardholderName,
    CardNumber,
    CardBrand,
    CardExpMonth,
    CardExpYear,
    CardCode,
    Identity(String),
    SshPrivateKey,
    SshPublicKey,
    SshFingerprint,
}

impl From<FieldRef> for String {
    fn from(field: FieldRef) -> Self {
        field.path_token()
    }
}

impl TryFrom<String> for FieldRef {
    type Error = String;

    fn try_from(token: String) -> Result<Self, Self::Error> {
        token.parse().map_err(|_| "invalid field token".to_owned())
    }
}

impl FieldRef {
    /// Whether the field contains a secret by default.
    pub const fn is_sensitive(&self) -> bool {
        matches!(
            self,
            Self::Password
                | Self::Totp
                | Self::Notes
                | Self::CardNumber
                | Self::CardCode
                | Self::Identity(_)
                | Self::SshPrivateKey
        )
    }

    /// The field token used in the HTTP path.
    pub fn path_token(&self) -> String {
        match self {
            Self::Name => "name".to_owned(),
            Self::Username => "username".to_owned(),
            Self::Password => "password".to_owned(),
            Self::Totp => "totp".to_owned(),
            Self::Uri(index) => format!("uri/{index}"),
            Self::Notes => "notes".to_owned(),
            Self::Custom(name) => format!("custom/{name}"),
            Self::CardholderName => "cardholder_name".to_owned(),
            Self::CardNumber => "card_number".to_owned(),
            Self::CardBrand => "card_brand".to_owned(),
            Self::CardExpMonth => "card_exp_month".to_owned(),
            Self::CardExpYear => "card_exp_year".to_owned(),
            Self::CardCode => "card_code".to_owned(),
            Self::Identity(name) => format!("identity/{name}"),
            Self::SshPrivateKey => "ssh_private_key".to_owned(),
            Self::SshPublicKey => "ssh_public_key".to_owned(),
            Self::SshFingerprint => "ssh_fingerprint".to_owned(),
        }
    }
}

impl FromStr for FieldRef {
    type Err = ApiError;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let invalid = || ApiError::new(ErrorCode::InvalidRequest);
        Ok(match token {
            "name" => Self::Name,
            "username" => Self::Username,
            "password" => Self::Password,
            "totp" => Self::Totp,
            "notes" => Self::Notes,
            "cardholder_name" => Self::CardholderName,
            "card_number" => Self::CardNumber,
            "card_brand" => Self::CardBrand,
            "card_exp_month" => Self::CardExpMonth,
            "card_exp_year" => Self::CardExpYear,
            "card_code" => Self::CardCode,
            "ssh_private_key" => Self::SshPrivateKey,
            "ssh_public_key" => Self::SshPublicKey,
            "ssh_fingerprint" => Self::SshFingerprint,
            _ if token.starts_with("uri/") => {
                Self::Uri(token[4..].parse().map_err(|_| invalid())?)
            }
            _ if token.starts_with("custom/") => {
                let name = &token[7..];
                if name.is_empty() {
                    return Err(invalid());
                }
                Self::Custom(name.to_owned())
            }
            _ if token.starts_with("identity/") => {
                let name = &token[9..];
                if name.is_empty() {
                    return Err(invalid());
                }
                Self::Identity(name.to_owned())
            }
            _ => return Err(invalid()),
        })
    }
}

/// Request to read one field from one item.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldReadRequest {
    pub item_id: String,
    pub field: FieldRef,
}

/// Result of a permitted field read. A TOTP read contains the current code,
/// never the stored TOTP seed.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldReadResponse {
    pub field: FieldRef,
    pub value: Option<String>,
    pub sensitive: bool,
}

/// A stable, non-secret API failure.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl ApiError {
    pub fn new(code: ErrorCode) -> Self {
        let (message, retryable) = code.details();
        Self {
            code,
            message: message.to_owned(),
            retryable,
        }
    }
}

/// Stable error codes returned by the remote API.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    VaultLocked,
    ReauthenticationRequired,
    Unavailable,
}

/// On-disk authorization state for remote API clients.
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct PolicyStore {
    #[serde(default)]
    pub clients: std::collections::BTreeMap<String, ClientPolicy>,
}

/// One rbw-managed mTLS client and the fields it may read.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientPolicy {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub items: std::collections::BTreeMap<String, Vec<FieldRef>>,
}

/// Current state of the remote listener, for the local CLI only.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerStatus {
    pub enabled: bool,
    pub listening: bool,
    pub listen: String,
    pub hostname: String,
    pub pid: u32,
    pub error: Option<String>,
}

/// Read the current API listener state written by rbw-agent.
pub fn load_listener_status() -> anyhow::Result<Option<ListenerStatus>> {
    let path = listener_status_path();
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(anyhow::Error::from)
            .context("failed to parse remote API listener status"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(error) => {
            Err(error).context("failed to read remote API listener status")
        }
    }
}

/// Atomically write local-only listener state with private permissions.
pub fn save_listener_status(status: &ListenerStatus) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = ensure_private_dir()?;
    let tmp = dir.join(format!("listener.{}.tmp", std::process::id()));
    let path = listener_status_path();
    let bytes = serde_json::to_vec(status)?;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.context("failed to write remote API listener status")
}

fn listener_status_path() -> std::path::PathBuf {
    crate::dirs::remote_api_dir().join("listener.json")
}

/// Load the current authorization store. It is read for every API request so
/// a CLI revocation applies to requests on existing TLS connections too.
pub fn load_policy_store() -> anyhow::Result<PolicyStore> {
    let path = policy_store_path();
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(anyhow::Error::from)
            .context("failed to parse remote API policy store"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(PolicyStore::default())
        }
        Err(error) => {
            Err(error).context("failed to read remote API policy store")
        }
    }
}

/// Mutate authorization state under an interprocess lock. Readers see either
/// the old or the new complete store; revocations cannot be overwritten by a
/// concurrent grant based on an earlier snapshot.
pub fn update_policy_store(
    update: impl FnOnce(&mut PolicyStore) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    use fs2::FileExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = crate::dirs::remote_api_dir();
    crate::dirs::create_dir_all_with_permissions(&dir, 0o700)?;
    let lock_path = dir.join("clients.lock");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .context("failed to open remote API policy lock")?;
    lock.lock_exclusive()
        .context("failed to lock remote API policy store")?;
    let mut store = load_policy_store()?;
    update(&mut store)?;
    save_policy_store_unlocked(&store)
}

/// Save authorization state with private file permissions and an atomic rename.
fn save_policy_store_unlocked(store: &PolicyStore) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = crate::dirs::remote_api_dir();
    let path = policy_store_path();
    let tmp = dir.join(format!("clients.{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(store)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .context("failed to create remote API policy file")?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        Ok::<_, std::io::Error>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.context("failed to save remote API policy store")
}

fn policy_store_path() -> std::path::PathBuf {
    crate::dirs::remote_api_dir().join("clients.json")
}

/// Ensure the private API-data directory exists with restrictive permissions.
pub fn ensure_private_dir() -> anyhow::Result<std::path::PathBuf> {
    let dir = crate::dirs::remote_api_dir();
    crate::dirs::create_dir_all_with_permissions(&dir, 0o700)?;
    Ok(dir)
}

/// Persist secret PEM material without following or overwriting an existing path.
pub fn write_private_file(
    path: &std::path::Path,
    contents: &[u8],
) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| {
            format!("failed to create private file {}", path.display())
        })?;
    let result = file.write_all(contents).and_then(|()| file.sync_all());
    if let Err(error) = result {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error)
            .context("failed to persist private credential file");
    }
    Ok(())
}

/// Compute the stable certificate fingerprint used to map mTLS identities to
/// rbw-managed policies.
pub fn certificate_fingerprint(certificate_der: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(certificate_der);
    digest.iter().fold(
        String::with_capacity(digest.len() * 2),
        |mut fingerprint, byte| {
            use std::fmt::Write as _;
            let _ = write!(fingerprint, "{byte:02x}");
            fingerprint
        },
    )
}

/// Ensure rbw-owned CA and HTTPS server certificates exist. A hostname change
/// rotates only the server certificate; client certificates keep their trust.
pub fn ensure_tls_material(hostname: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    anyhow::ensure!(!hostname.trim().is_empty(), "API hostname is empty");
    let api_dir = ensure_private_dir()?;
    let pki_dir = api_dir.join("pki");
    if !pki_dir.exists() {
        let tmp = api_dir.join(format!("pki.{}.tmp", std::process::id()));
        std::fs::create_dir(&tmp)
            .context("failed to create remote API PKI directory")?;
        std::fs::set_permissions(
            &tmp,
            std::fs::Permissions::from_mode(0o700),
        )?;
        let result = create_pki(&tmp, hostname);
        if let Err(error) = result {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(error);
        }
        std::fs::rename(&tmp, &pki_dir)
            .context("failed to install remote API certificates")?;
        return Ok(());
    }

    for name in ["ca.pem", "ca-key.pem", "server.pem", "server-key.pem"] {
        anyhow::ensure!(
            pki_dir.join(name).is_file(),
            "remote API certificate material is incomplete; inspect {}",
            pki_dir.display()
        );
    }
    let current_hostname = std::fs::read_to_string(pki_dir.join("hostname"))
        .context("failed to read remote API certificate hostname")?;
    if current_hostname != hostname {
        rotate_server_certificate(&pki_dir, hostname)?;
    }
    Ok(())
}

fn create_pki(dir: &std::path::Path, hostname: &str) -> anyhow::Result<()> {
    use rcgen::{CertificateParams, IsCa, KeyPair};

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rbw remote API CA");
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    write_private_file(&dir.join("ca.pem"), ca_cert.pem().as_bytes())?;
    write_private_file(
        &dir.join("ca-key.pem"),
        ca_key.serialize_pem().as_bytes(),
    )?;

    write_server_certificate(dir, hostname, &ca_params, &ca_key)?;
    write_private_file(&dir.join("hostname"), hostname.as_bytes())?;
    Ok(())
}

fn rotate_server_certificate(
    pki_dir: &std::path::Path,
    hostname: &str,
) -> anyhow::Result<()> {
    let ca_pem = std::fs::read_to_string(pki_dir.join("ca.pem"))?;
    let ca_key_pem = std::fs::read_to_string(pki_dir.join("ca-key.pem"))?;
    let ca_key = rcgen::KeyPair::from_pem(&ca_key_pem)?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_pem, ca_key)?;
    let server_key = rcgen::KeyPair::generate()?;
    let mut params =
        rcgen::CertificateParams::new(vec![hostname.to_owned()])?;
    params.extended_key_usages =
        vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&server_key, &issuer)?;
    replace_private_file(pki_dir, "server.pem", cert.pem().as_bytes())?;
    replace_private_file(
        pki_dir,
        "server-key.pem",
        server_key.serialize_pem().as_bytes(),
    )?;
    replace_private_file(pki_dir, "hostname", hostname.as_bytes())?;
    Ok(())
}

fn write_server_certificate(
    dir: &std::path::Path,
    hostname: &str,
    ca_params: &rcgen::CertificateParams,
    ca_key: &rcgen::KeyPair,
) -> anyhow::Result<()> {
    use rcgen::ExtendedKeyUsagePurpose;
    let issuer = rcgen::Issuer::from_params(ca_params, ca_key);
    let server_key = rcgen::KeyPair::generate()?;
    let mut params =
        rcgen::CertificateParams::new(vec![hostname.to_owned()])?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&server_key, &issuer)?;
    write_private_file(&dir.join("server.pem"), cert.pem().as_bytes())?;
    write_private_file(
        &dir.join("server-key.pem"),
        server_key.serialize_pem().as_bytes(),
    )?;
    Ok(())
}

fn replace_private_file(
    dir: &std::path::Path,
    name: &str,
    contents: &[u8],
) -> anyhow::Result<()> {
    let tmp = dir.join(format!("{name}.{}.tmp", std::process::id()));
    write_private_file(&tmp, contents)?;
    std::fs::rename(tmp, dir.join(name))?;
    Ok(())
}

/// Issue one mTLS client certificate and return its SHA-256 certificate
/// fingerprint. The private key is written with mode 0600.
pub fn issue_client_certificate(
    id: &str,
) -> anyhow::Result<(String, std::path::PathBuf, std::path::PathBuf)> {
    use rcgen::ExtendedKeyUsagePurpose;
    let pki_dir = crate::dirs::remote_api_dir().join("pki");
    let ca_pem = std::fs::read_to_string(pki_dir.join("ca.pem"))?;
    let ca_key_pem = std::fs::read_to_string(pki_dir.join("ca-key.pem"))?;
    let ca_key = rcgen::KeyPair::from_pem(&ca_key_pem)?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_pem, ca_key)?;
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("rbw-client-{id}"));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key, &issuer)?;
    let cert_path = pki_dir.join(format!("client-{id}.pem"));
    let key_path = pki_dir.join(format!("client-{id}-key.pem"));
    write_private_file(&cert_path, cert.pem().as_bytes())?;
    if let Err(error) =
        write_private_file(&key_path, key.serialize_pem().as_bytes())
    {
        let _ = std::fs::remove_file(&cert_path);
        return Err(error);
    }
    Ok((certificate_fingerprint(cert.der()), cert_path, key_path))
}

/// Remove a client's locally stored keypair after the authorization entry is
/// revoked. A copied client certificate is rejected by the policy lookup.
pub fn remove_client_certificate(id: &str) -> anyhow::Result<()> {
    let pki_dir = crate::dirs::remote_api_dir().join("pki");
    for name in [format!("client-{id}.pem"), format!("client-{id}-key.pem")] {
        match std::fs::remove_file(pki_dir.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Paths to the public CA certificate and per-client credentials.
pub fn client_export_paths(
    id: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let pki_dir = crate::dirs::remote_api_dir().join("pki");
    (
        pki_dir.join("ca.pem"),
        pki_dir.join(format!("client-{id}.pem")),
        pki_dir.join(format!("client-{id}-key.pem")),
    )
}

/// Create a new client identity with no grants. This is intentionally
/// separate from policy grants so credentials start with no data access.
pub fn create_client(name: &str) -> anyhow::Result<ClientPolicy> {
    anyhow::ensure!(!name.trim().is_empty(), "client name must not be empty");
    let config = crate::config::Config::load()?;
    ensure_tls_material(&config.api.hostname)?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let (fingerprint, _, _) = issue_client_certificate(&id)?;
    let policy = ClientPolicy {
        id: id.clone(),
        name: name.to_owned(),
        fingerprint,
        account: None,
        items: std::collections::BTreeMap::new(),
    };
    if let Err(error) = update_policy_store(|store| {
        store.clients.insert(id.clone(), policy.clone());
        Ok(())
    }) {
        let _ = remove_client_certificate(&id);
        return Err(error);
    }
    Ok(policy)
}

/// Grant a client access to specific fields on one item of one account.
pub fn grant_fields(
    client_id: &str,
    account: &str,
    item_id: &str,
    fields: &[FieldRef],
) -> anyhow::Result<()> {
    anyhow::ensure!(!fields.is_empty(), "at least one field is required");
    crate::config::Config::load()?.account(Some(account))?;
    update_policy_store(|store| {
        let client = store
            .clients
            .get_mut(client_id)
            .context("remote API client was not found")?;
        if let Some(existing) = &client.account {
            anyhow::ensure!(existing == account, "a client can be scoped to one account; revoke and recreate it to change accounts");
        }
        client.account = Some(account.to_owned());
        let allowed = client.items.entry(item_id.to_owned()).or_default();
        for field in fields {
            if !allowed.contains(field) {
                allowed.push(field.clone());
            }
        }
        Ok(())
    })
}

/// Remove fields from an item grant, deleting the item grant when no fields
/// remain. An empty `fields` slice removes the whole item's grant.
pub fn revoke_fields(
    client_id: &str,
    item_id: &str,
    fields: &[FieldRef],
) -> anyhow::Result<()> {
    update_policy_store(|store| {
        let client = store
            .clients
            .get_mut(client_id)
            .context("remote API client was not found")?;
        if fields.is_empty() {
            anyhow::ensure!(
                client.items.remove(item_id).is_some(),
                "item grant was not found"
            );
        } else {
            let empty = {
                let allowed = client
                    .items
                    .get_mut(item_id)
                    .context("item grant was not found")?;
                allowed.retain(|field| !fields.contains(field));
                allowed.is_empty()
            };
            if empty {
                client.items.remove(item_id);
            }
        }
        if client.items.is_empty() {
            client.account = None;
        }
        Ok(())
    })
}

/// Revoke a client immediately by removing its fingerprint from the policy
/// store, then delete the local credential files.
pub fn revoke_client(client_id: &str) -> anyhow::Result<()> {
    update_policy_store(|store| {
        anyhow::ensure!(
            store.clients.remove(client_id).is_some(),
            "remote API client was not found"
        );
        Ok(())
    })?;
    remove_client_certificate(client_id)
}

impl ErrorCode {
    pub const fn status(self) -> axum::http::StatusCode {
        match self {
            Self::InvalidRequest => axum::http::StatusCode::BAD_REQUEST,
            Self::Unauthorized => axum::http::StatusCode::UNAUTHORIZED,
            Self::Forbidden => axum::http::StatusCode::FORBIDDEN,
            Self::NotFound => axum::http::StatusCode::NOT_FOUND,
            Self::VaultLocked | Self::ReauthenticationRequired => {
                axum::http::StatusCode::LOCKED
            }
            Self::Unavailable => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    const fn details(self) -> (&'static str, bool) {
        match self {
            Self::InvalidRequest => ("Invalid request", false),
            Self::Unauthorized => {
                ("Client certificate is not authorized", false)
            }
            Self::Forbidden => {
                ("Client policy does not allow this field", false)
            }
            Self::NotFound => ("Item or field was not found", false),
            Self::VaultLocked => ("Vault is locked", true),
            Self::ReauthenticationRequired => (
                "Item requires interactive master password verification",
                false,
            ),
            Self::Unavailable => ("API is temporarily unavailable", true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_tokens_round_trip_as_strings() {
        for (token, field) in [
            ("name", FieldRef::Name),
            ("password", FieldRef::Password),
            ("totp", FieldRef::Totp),
            ("uri/2", FieldRef::Uri(2)),
            (
                "custom/Recovery code",
                FieldRef::Custom("Recovery code".into()),
            ),
            (
                "identity/first_name",
                FieldRef::Identity("first_name".into()),
            ),
        ] {
            assert_eq!(token.parse::<FieldRef>().unwrap(), field);
            assert_eq!(
                serde_json::to_string(&field).unwrap(),
                format!("\"{token}\"")
            );
            assert_eq!(
                serde_json::from_str::<FieldRef>(&format!("\"{token}\""))
                    .unwrap(),
                field
            );
        }
    }

    #[test]
    fn field_response_matches_http_json_contract() {
        let response = FieldReadResponse {
            field: FieldRef::Totp,
            value: Some("123456".into()),
            sensitive: true,
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "field": "totp",
                "value": "123456",
                "sensitive": true
            })
        );
    }

    #[test]
    fn api_errors_have_stable_statuses_and_retryability() {
        let locked = ApiError::new(ErrorCode::VaultLocked);
        assert_eq!(locked.code.status(), axum::http::StatusCode::LOCKED);
        assert!(locked.retryable);

        let denied = ApiError::new(ErrorCode::Forbidden);
        assert_eq!(denied.code.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(!denied.retryable);

        let reauthentication =
            ApiError::new(ErrorCode::ReauthenticationRequired);
        assert_eq!(
            reauthentication.code.status(),
            axum::http::StatusCode::LOCKED
        );
        assert!(!reauthentication.retryable);
    }
}
