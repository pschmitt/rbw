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

/// Request body for unlocking an explicitly authorized vault account.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnlockRequest {
    #[serde(default)]
    pub account: Option<String>,
    pub password: String,
}

/// Result of a remote vault unlock operation.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnlockResponse {
    pub account: String,
    pub state: VaultLockState,
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
    InvalidPassword,
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

/// One rbw-managed mTLS client and its explicitly granted capabilities.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientPolicy {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    #[serde(default)]
    pub account: Option<String>,
    /// Whether this client may read non-secret, scoped vault status.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub status: bool,
    /// Account names this client may inspect through the status endpoint.
    /// `status` plus the legacy `account` field remains readable for policy
    /// files created before per-account status grants were introduced.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_accounts: Vec<String>,
    #[serde(default)]
    pub items: std::collections::BTreeMap<String, Vec<FieldRef>>,
}

/// Account lock state visible to a status-authorized client.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum VaultLockState {
    /// The client has no configured account scope or its scope no longer exists.
    Unconfigured,
    /// The configured account does not have usable keys in the agent.
    Locked,
    /// The configured account has usable keys in the agent.
    Unlocked,
}

/// Non-secret remote agent and explicitly scoped vault status.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusResponse {
    pub api_version: u32,
    pub agent_version: String,
    pub accounts: Vec<AccountStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<crate::audit::Event>,
}

/// The status of an account explicitly granted to the requesting client.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountStatus {
    pub account: String,
    pub state: VaultLockState,
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
    with_tls_material(hostname, |_| Ok(()))
}

/// Ensure the HTTPS identity is complete, then use its files while holding the
/// interprocess PKI lock so certificate and private-key reads cannot interleave
/// with a rotation.
pub fn with_tls_material<T>(
    hostname: &str,
    use_material: impl FnOnce(&std::path::Path) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let api_dir = ensure_private_dir()?;
    with_tls_material_at(&api_dir, hostname, use_material)
}

fn with_tls_material_at<T>(
    api_dir: &std::path::Path,
    hostname: &str,
    use_material: impl FnOnce(&std::path::Path) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    use fs2::FileExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    anyhow::ensure!(!hostname.trim().is_empty(), "API hostname is empty");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(api_dir.join("pki.lock"))
        .context("failed to open remote API PKI lock")?;
    lock.lock_exclusive()
        .context("failed to lock remote API certificate material")?;

    ensure_tls_material_unlocked(hostname, api_dir)?;
    use_material(&api_dir.join("pki"))
}

fn ensure_tls_material_unlocked(
    hostname: &str,
    api_dir: &std::path::Path,
) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
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
    ensure_server_certificate(&pki_dir, hostname)
}

fn ensure_server_certificate(
    pki_dir: &std::path::Path,
    hostname: &str,
) -> anyhow::Result<()> {
    let current_hostname = std::fs::read_to_string(pki_dir.join("hostname"))
        .context("failed to read remote API certificate hostname")?;
    if current_hostname != hostname
        || server_certificate_needs_rotation(pki_dir)?
    {
        rotate_server_certificate(pki_dir, hostname)?;
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
    params.use_authority_key_identifier_extension = true;
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
    params.use_authority_key_identifier_extension = true;
    let cert = params.signed_by(&server_key, &issuer)?;
    write_private_file(&dir.join("server.pem"), cert.pem().as_bytes())?;
    write_private_file(
        &dir.join("server-key.pem"),
        server_key.serialize_pem().as_bytes(),
    )?;
    Ok(())
}

/// Detect server certificates that strict TLS clients reject because they lack
/// the RFC 5280 Authority Key Identifier extension.
fn server_certificate_needs_rotation(
    pki_dir: &std::path::Path,
) -> anyhow::Result<bool> {
    use rcgen::PublicKeyData as _;
    use x509_parser::extensions::ParsedExtension;

    let ca_pem = std::fs::read(pki_dir.join("ca.pem"))
        .context("failed to read remote API CA certificate")?;
    let (_, ca_pem) =
        x509_parser::pem::parse_x509_pem(&ca_pem).map_err(|error| {
            anyhow::anyhow!(
                "failed to parse remote API CA certificate: {error}"
            )
        })?;
    let (_, ca) = x509_parser::parse_x509_certificate(&ca_pem.contents)
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to parse remote API CA certificate: {error}"
            )
        })?;
    let ca_key_identifier = ca.extensions().iter().find_map(|extension| {
        if let ParsedExtension::SubjectKeyIdentifier(identifier) =
            extension.parsed_extension()
        {
            Some(identifier.0)
        } else {
            None
        }
    });
    let Some(ca_key_identifier) = ca_key_identifier else {
        anyhow::bail!(
            "remote API CA certificate has no subject key identifier"
        );
    };

    let server_pem = std::fs::read(pki_dir.join("server.pem"))
        .context("failed to read remote API server certificate")?;
    let (_, server_pem) = x509_parser::pem::parse_x509_pem(&server_pem)
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to parse remote API server certificate: {error}"
            )
        })?;
    let (_, server) = x509_parser::parse_x509_certificate(
        &server_pem.contents,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "failed to parse remote API server certificate: {error}"
        )
    })?;
    let server_key_identifier =
        server.extensions().iter().find_map(|extension| {
            if let ParsedExtension::AuthorityKeyIdentifier(identifier) =
                extension.parsed_extension()
            {
                identifier
                    .key_identifier
                    .as_ref()
                    .map(|key_identifier| key_identifier.0)
            } else {
                None
            }
        });
    let server_key = std::fs::read_to_string(pki_dir.join("server-key.pem"))
        .context("failed to read remote API server private key")?;
    let server_key = rcgen::KeyPair::from_pem(&server_key)
        .context("failed to parse remote API server private key")?;
    Ok(server_key_identifier != Some(ca_key_identifier)
        || server_key.subject_public_key_info() != server.public_key().raw)
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
        status: false,
        status_accounts: Vec::new(),
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
        grant_fields_policy(client, account, item_id, fields)
    })
}

fn grant_fields_policy(
    client: &mut ClientPolicy,
    account: &str,
    item_id: &str,
    fields: &[FieldRef],
) -> anyhow::Result<()> {
    anyhow::ensure!(!fields.is_empty(), "at least one field is required");
    if let Some(existing) = &client.account {
        anyhow::ensure!(
            existing == account,
            "a client can be scoped to one account; revoke and recreate it to change accounts"
        );
    }
    client.account = Some(account.to_owned());
    let allowed = client.items.entry(item_id.to_owned()).or_default();
    for field in fields {
        if !allowed.contains(field) {
            allowed.push(field.clone());
        }
    }
    Ok(())
}

/// Grant a client access to non-secret status for configured accounts.
/// This does not grant access to any item fields.
pub fn grant_status(
    client_id: &str,
    accounts: &[String],
) -> anyhow::Result<()> {
    anyhow::ensure!(!accounts.is_empty(), "at least one account is required");
    let config = crate::config::Config::load()?;
    for account in accounts {
        config.account(Some(account))?;
    }
    update_policy_store(|store| {
        let client = store
            .clients
            .get_mut(client_id)
            .context("remote API client was not found")?;
        for account in accounts {
            grant_status_policy(client, account);
        }
        Ok(())
    })
}

pub fn granted_status_accounts(client: &ClientPolicy) -> Vec<String> {
    if !client.status {
        return Vec::new();
    }
    let mut accounts = client.status_accounts.clone();
    // Older policy files represented status permission with a boolean and
    // reused the item grant's account. Continue honoring that exact grant.
    if client.status && accounts.is_empty() {
        if let Some(account) = &client.account {
            accounts.push(account.clone());
        }
    }
    accounts.sort();
    accounts.dedup();
    accounts
}

fn grant_status_policy(client: &mut ClientPolicy, account: &str) {
    let accounts = granted_status_accounts(client);
    client.status_accounts = accounts;
    if client.items.is_empty() {
        // A pre-statusAccounts policy used `account` only as its status
        // scope. Once migrated, leave the item grant scope independent.
        client.account = None;
    }
    if !client.status_accounts.iter().any(|name| name == account) {
        client.status_accounts.push(account.to_owned());
        client.status_accounts.sort();
    }
    client.status = true;
}

/// Revoke one account's status grant, or all status grants when `account` is
/// `None`, without changing item grants.
pub fn revoke_status(
    client_id: &str,
    account: Option<&str>,
) -> anyhow::Result<()> {
    update_policy_store(|store| {
        let client = store
            .clients
            .get_mut(client_id)
            .context("remote API client was not found")?;
        revoke_status_policy(client, account);
        Ok(())
    })
}

fn revoke_status_policy(client: &mut ClientPolicy, account: Option<&str>) {
    client.status_accounts = granted_status_accounts(client);
    if let Some(account) = account {
        client.status_accounts.retain(|name| name != account);
    } else {
        client.status_accounts.clear();
    }
    client.status = !client.status_accounts.is_empty();
    if !client.status && client.items.is_empty() {
        client.account = None;
    }
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
        revoke_fields_policy(client, item_id, fields)
    })
}

fn revoke_fields_policy(
    client: &mut ClientPolicy,
    item_id: &str,
    fields: &[FieldRef],
) -> anyhow::Result<()> {
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
    if client.items.is_empty() && !client.status {
        client.account = None;
    }
    Ok(())
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
            Self::InvalidPassword => {
                axum::http::StatusCode::UNPROCESSABLE_ENTITY
            }
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
                ("Client policy does not allow this request", false)
            }
            Self::InvalidPassword => ("Invalid master password", false),
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

    fn write_legacy_server_certificate(dir: &std::path::Path) {
        let ca_pem = std::fs::read_to_string(dir.join("ca.pem")).unwrap();
        let ca_key = std::fs::read_to_string(dir.join("ca-key.pem")).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(
            &ca_pem,
            rcgen::KeyPair::from_pem(&ca_key).unwrap(),
        )
        .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages =
            vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        // Deliberately model the pre-fix profile, which omitted the AKI.
        let certificate = params.signed_by(&key, &issuer).unwrap();
        std::fs::write(dir.join("server.pem"), certificate.pem()).unwrap();
        std::fs::write(dir.join("server-key.pem"), key.serialize_pem())
            .unwrap();
    }

    fn certificate_has_aki(path: &std::path::Path) -> bool {
        let pem = std::fs::read(path).unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(&pem).unwrap();
        let (_, certificate) =
            x509_parser::parse_x509_certificate(&pem.contents).unwrap();
        certificate.extensions().iter().any(|extension| {
            matches!(
                extension.parsed_extension(),
                x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(identifier)
                    if identifier.key_identifier.is_some()
            )
        })
    }

    fn write_test_client_identity(dir: &std::path::Path) {
        let ca_pem = std::fs::read_to_string(dir.join("ca.pem")).unwrap();
        let ca_key = std::fs::read_to_string(dir.join("ca-key.pem")).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(
            &ca_pem,
            rcgen::KeyPair::from_pem(&ca_key).unwrap(),
        )
        .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.extended_key_usages =
            vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;
        let certificate = params.signed_by(&key, &issuer).unwrap();
        std::fs::write(dir.join("client.pem"), certificate.pem()).unwrap();
        std::fs::write(dir.join("client-key.pem"), key.serialize_pem())
            .unwrap();
    }

    fn python_verifies_server_certificate(dir: &std::path::Path) -> bool {
        let script = r#"
import socket, ssl, sys, threading
ca, server_cert, server_key, client_cert, client_key = sys.argv[1:]
server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_context.load_cert_chain(server_cert, server_key)
server_context.verify_mode = ssl.CERT_REQUIRED
server_context.load_verify_locations(cafile=ca)
client_context = ssl.create_default_context(cafile=ca)
client_context.verify_flags |= ssl.VERIFY_X509_STRICT
client_context.load_cert_chain(client_cert, client_key)
left, right = socket.socketpair()
errors = []
def serve():
    try:
        with server_context.wrap_socket(left, server_side=True) as conn:
            conn.recv(1)
    except Exception as error:
        errors.append(type(error).__name__)
thread = threading.Thread(target=serve)
thread.start()
with client_context.wrap_socket(right, server_hostname="localhost") as conn:
    conn.send(b"x")
thread.join()
if errors:
    raise SystemExit("TLS server handshake failed: " + ",".join(errors))
"#;
        let output = std::process::Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(dir.join("ca.pem"))
            .arg(dir.join("server.pem"))
            .arg(dir.join("server-key.pem"))
            .arg(dir.join("client.pem"))
            .arg(dir.join("client-key.pem"))
            .output()
            .expect("Python 3 is required for the strict TLS certificate regression test");
        output.status.success()
    }

    #[test]
    fn server_certificate_has_aki_and_strict_python_tls_accepts_it() {
        let dir = tempfile::tempdir().unwrap();
        create_pki(dir.path(), "localhost").unwrap();
        write_test_client_identity(dir.path());

        assert!(certificate_has_aki(&dir.path().join("server.pem")));
        assert!(python_verifies_server_certificate(dir.path()));
    }

    #[test]
    fn existing_server_certificate_is_rotated_without_replacing_ca_or_clients(
    ) {
        let dir = tempfile::tempdir().unwrap();
        create_pki(dir.path(), "localhost").unwrap();
        let ca_before = std::fs::read(dir.path().join("ca.pem")).unwrap();
        let ca_key_before =
            std::fs::read(dir.path().join("ca-key.pem")).unwrap();
        write_test_client_identity(dir.path());
        let client_before =
            std::fs::read(dir.path().join("client.pem")).unwrap();
        write_legacy_server_certificate(dir.path());

        assert!(!certificate_has_aki(&dir.path().join("server.pem")));
        assert!(!python_verifies_server_certificate(dir.path()));
        ensure_server_certificate(dir.path(), "localhost").unwrap();

        assert!(certificate_has_aki(&dir.path().join("server.pem")));
        assert_eq!(
            std::fs::read(dir.path().join("ca.pem")).unwrap(),
            ca_before
        );
        assert_eq!(
            std::fs::read(dir.path().join("ca-key.pem")).unwrap(),
            ca_key_before
        );
        assert_eq!(
            std::fs::read(dir.path().join("client.pem")).unwrap(),
            client_before
        );
        let server_before =
            std::fs::read(dir.path().join("server.pem")).unwrap();
        let key_before =
            std::fs::read(dir.path().join("server-key.pem")).unwrap();
        ensure_server_certificate(dir.path(), "localhost").unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("server.pem")).unwrap(),
            server_before
        );
        assert_eq!(
            std::fs::read(dir.path().join("server-key.pem")).unwrap(),
            key_before
        );
        assert!(python_verifies_server_certificate(dir.path()));
    }

    #[test]
    fn mismatched_server_key_is_rotated_even_when_certificate_aki_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        create_pki(dir.path(), "localhost").unwrap();
        write_test_client_identity(dir.path());
        let client_key_before =
            std::fs::read(dir.path().join("client-key.pem")).unwrap();
        std::fs::copy(
            dir.path().join("client-key.pem"),
            dir.path().join("server-key.pem"),
        )
        .unwrap();

        assert!(certificate_has_aki(&dir.path().join("server.pem")));
        ensure_server_certificate(dir.path(), "localhost").unwrap();

        assert!(python_verifies_server_certificate(dir.path()));
        assert_eq!(
            std::fs::read(dir.path().join("client-key.pem")).unwrap(),
            client_key_before
        );
    }

    #[test]
    fn tls_material_rotation_and_read_are_serialized_across_callers() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Barrier, Mutex,
        };

        let api_dir = tempfile::tempdir().unwrap();
        with_tls_material_at(api_dir.path(), "localhost", |_| Ok(()))
            .unwrap();
        let pki_dir = api_dir.path().join("pki");
        write_test_client_identity(&pki_dir);
        std::fs::copy(
            pki_dir.join("client-key.pem"),
            pki_dir.join("server-key.pem"),
        )
        .unwrap();

        let first_entered = Arc::new(Barrier::new(2));
        let release_first = Arc::new(Barrier::new(2));
        let second_started = Arc::new(AtomicBool::new(false));
        let order = Arc::new(Mutex::new(Vec::new()));

        let first_dir = api_dir.path().to_path_buf();
        let first_entered_thread = Arc::clone(&first_entered);
        let release_first_thread = Arc::clone(&release_first);
        let first_order = Arc::clone(&order);
        let first = std::thread::spawn(move || {
            with_tls_material_at(&first_dir, "localhost", |pki_dir| {
                anyhow::ensure!(!server_certificate_needs_rotation(pki_dir)?);
                first_order.lock().unwrap().push("first");
                first_entered_thread.wait();
                release_first_thread.wait();
                Ok(())
            })
        });

        first_entered.wait();
        let second_dir = api_dir.path().to_path_buf();
        let second_started_thread = Arc::clone(&second_started);
        let second_order = Arc::clone(&order);
        let second = std::thread::spawn(move || {
            second_started_thread.store(true, Ordering::SeqCst);
            with_tls_material_at(&second_dir, "localhost", |pki_dir| {
                anyhow::ensure!(!server_certificate_needs_rotation(pki_dir)?);
                second_order.lock().unwrap().push("second");
                Ok(())
            })
        });
        while !second_started.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(*order.lock().unwrap(), ["first"]);

        release_first.wait();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
        assert_eq!(*order.lock().unwrap(), ["first", "second"]);
    }

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
    fn status_response_matches_http_json_contract() {
        let response = StatusResponse {
            api_version: 1,
            agent_version: "2.40.0".to_owned(),
            accounts: vec![AccountStatus {
                account: "personal".to_owned(),
                state: VaultLockState::Locked,
            }],
            events: Vec::new(),
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "apiVersion": 1,
                "agentVersion": "2.40.0",
                "accounts": [{ "account": "personal", "state": "locked" }]
            })
        );
    }

    #[test]
    fn old_client_policy_deserializes_with_status_denied() {
        let policy: ClientPolicy =
            serde_json::from_value(serde_json::json!({
                "id": "client-1",
                "name": "old client",
                "fingerprint": "fingerprint",
                "account": "personal",
                "items": {}
            }))
            .unwrap();
        assert!(!policy.status);
        assert_eq!(policy.status_accounts, Vec::<String>::new());
        assert!(serde_json::to_value(policy)
            .unwrap()
            .get("status")
            .is_none());
    }

    #[test]
    fn legacy_status_policy_keeps_its_existing_single_account_grant() {
        let policy: ClientPolicy =
            serde_json::from_value(serde_json::json!({
                "id": "client-1",
                "name": "legacy status client",
                "fingerprint": "fingerprint",
                "account": "personal",
                "status": true,
                "items": {}
            }))
            .unwrap();
        assert_eq!(granted_status_accounts(&policy), ["personal"]);
        assert_eq!(policy.status_accounts, Vec::<String>::new());

        let mut migrated = policy;
        grant_status_policy(&mut migrated, "work");
        assert_eq!(migrated.account, None);
        assert_eq!(granted_status_accounts(&migrated), ["personal", "work"]);
        grant_fields_policy(
            &mut migrated,
            "work",
            "item-1",
            &[FieldRef::Username],
        )
        .unwrap();
        assert_eq!(migrated.account.as_deref(), Some("work"));
        assert_eq!(granted_status_accounts(&migrated), ["personal", "work"]);
    }

    #[test]
    fn status_grants_do_not_add_item_fields_and_revoke_keeps_item_scope() {
        let mut client = ClientPolicy {
            id: "client-1".to_owned(),
            name: "status client".to_owned(),
            fingerprint: "fingerprint".to_owned(),
            account: None,
            status: false,
            status_accounts: Vec::new(),
            items: std::collections::BTreeMap::new(),
        };

        grant_status_policy(&mut client, "personal");
        assert_eq!(client.account, None);
        assert!(client.status);
        assert_eq!(client.status_accounts, ["personal"]);
        assert!(client.items.is_empty());
        grant_status_policy(&mut client, "work");
        assert_eq!(client.status_accounts, ["personal", "work"]);

        revoke_status_policy(&mut client, Some("personal"));
        assert_eq!(client.status_accounts, ["work"]);
        assert_eq!(granted_status_accounts(&client), ["work"]);
        assert!(client.status);
        revoke_status_policy(&mut client, None);
        assert_eq!(client.account, None);
        assert!(!client.status);
        assert_eq!(client.status_accounts, Vec::<String>::new());

        grant_status_policy(&mut client, "personal");
        client.account = Some("personal".to_owned());
        client
            .items
            .insert("item-1".to_owned(), vec![FieldRef::Username]);
        revoke_status_policy(&mut client, None);
        assert_eq!(client.account.as_deref(), Some("personal"));
        assert!(!client.status);
        assert_eq!(client.items["item-1"], [FieldRef::Username]);
    }

    #[test]
    fn status_accounts_remain_independent_from_item_account_scope() {
        let mut client = ClientPolicy {
            id: "client-1".to_owned(),
            name: "status client".to_owned(),
            fingerprint: "fingerprint".to_owned(),
            account: Some("personal".to_owned()),
            status: true,
            status_accounts: Vec::new(),
            items: std::collections::BTreeMap::from([(
                "item-1".to_owned(),
                vec![FieldRef::Username],
            )]),
        };

        revoke_fields_policy(&mut client, "item-1", &[]).unwrap();
        assert!(client.items.is_empty());
        assert_eq!(client.account.as_deref(), Some("personal"));
        assert!(client.status);
        grant_status_policy(&mut client, "work");
        assert_eq!(client.status_accounts, ["personal", "work"]);
        assert_eq!(client.account, None);
        grant_fields_policy(
            &mut client,
            "work",
            "item-2",
            &[FieldRef::Username],
        )
        .unwrap();
        assert_eq!(client.account.as_deref(), Some("work"));
        assert_eq!(client.items["item-2"], [FieldRef::Username]);
        assert_eq!(granted_status_accounts(&client), ["personal", "work"]);

        revoke_status_policy(&mut client, None);
        assert_eq!(client.account.as_deref(), Some("work"));
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
