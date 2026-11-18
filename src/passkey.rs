//! Shared `WebAuthn` assertion primitives for rbw clients and the agent.

use anyhow::Context as _;
use base64::Engine as _;
use serde_json::json;

pub fn decode(value: &str) -> anyhow::Result<Vec<u8>> {
    let mut normalized = zeroize::Zeroizing::new(String::with_capacity(
        value.len().saturating_add(3),
    ));
    normalized.extend(value.chars().map(|character| match character {
        '-' => '+',
        '_' => '/',
        other => other,
    }));
    let padding = (4 - normalized.len() % 4) % 4;
    normalized.extend(std::iter::repeat_n('=', padding));
    let mut bytes =
        zeroize::Zeroizing::new(vec![0; normalized.len() / 4 * 3]);
    let len = base64::engine::general_purpose::STANDARD
        .decode_slice(normalized.as_bytes(), &mut bytes)
        .context("invalid passkey encoding")?;
    bytes.truncate(len);
    Ok(std::mem::take(&mut *bytes))
}

pub fn credential_id_bytes(value: &str) -> anyhow::Result<Vec<u8>> {
    uuid::Uuid::parse_str(value).map_or_else(
        |_| decode(value.strip_prefix("b64.").unwrap_or(value)),
        |id| Ok(id.as_bytes().to_vec()),
    )
}

pub fn next_counter(current: u32) -> anyhow::Result<u32> {
    current.checked_add(1).context("passkey counter exhausted")
}

/// The page's origin, if it may use a passkey of `rp` (its host is the relying
/// party or a subdomain of it; https, or http on localhost).
pub fn checked_origin(origin: &str, rp: &str) -> anyhow::Result<String> {
    let page = url::Url::parse(origin)
        .map_err(|_| anyhow::anyhow!("invalid --origin"))?;
    let host = page.host_str().context("--origin has no host")?;
    anyhow::ensure!(
        page.scheme() == "https"
            || (page.scheme() == "http" && host == "localhost"),
        "passkeys need an https origin"
    );
    anyhow::ensure!(
        host == rp || host.ends_with(&format!(".{rp}")),
        "{host} may not use a passkey for {rp}"
    );
    Ok(page.origin().ascii_serialization())
}

/// `clientDataJSON`, `authenticatorData` and the DER signature over both, as a
/// passkey provider produces them for a `get()` request.
pub fn sign_assertion_with_verification(
    key: &p256::ecdsa::SigningKey,
    rp: &str,
    origin: &str,
    challenge: &str,
    counter: u32,
    verified: bool,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use p256::ecdsa::signature::Signer as _;
    use sha2::Digest as _;
    let client_data = serde_json::to_vec(&json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    }))?;
    // Flags: user present, user verified, backup eligible, backed up (synced).
    let mut auth_data = sha2::Sha256::digest(rp.as_bytes()).to_vec();
    auth_data.push(0x01 | 0x08 | 0x10 | if verified { 0x04 } else { 0 });
    auth_data.extend_from_slice(&counter.to_be_bytes());
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha2::Sha256::digest(&client_data));
    let signature: p256::ecdsa::Signature = key.sign(&signed);
    Ok((
        client_data,
        auth_data,
        signature.to_der().as_bytes().to_vec(),
    ))
}
