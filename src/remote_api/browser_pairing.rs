//! Proof of possession for browser clients.

use anyhow::Context as _;
use p256::ecdsa::signature::Verifier as _;
use rand::Rng as _;
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DOMAIN: &[u8] = b"rbw browser api v1\0";
const CHALLENGE_TTL: Duration = Duration::from_secs(45);
const MAX_CHALLENGES: usize = 1024;

#[derive(Clone)]
pub struct BrowserKey {
    key: p256::ecdsa::VerifyingKey,
    id: String,
}

impl BrowserKey {
    /// Accept the 65-byte uncompressed P-256 point exported by Web Crypto.
    pub fn parse(encoded: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(encoded.len() == 87, "invalid browser public key");
        let bytes = crate::base64::decode_url_safe_no_pad(encoded)?;
        anyhow::ensure!(
            bytes.len() == 65 && bytes[0] == 4,
            "invalid browser public key"
        );
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
            .context("invalid browser public key")?;
        let id = crate::base64::encode_url_safe_no_pad(sha2::Sha256::digest(
            bytes,
        ));
        Ok(Self { key, id })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    fn verify(&self, payload: &[u8], signature: &str) -> anyhow::Result<()> {
        anyhow::ensure!(signature.len() == 86, "invalid browser signature");
        let bytes = crate::base64::decode_url_safe_no_pad(signature)?;
        let signature = p256::ecdsa::Signature::from_slice(&bytes)
            .context("invalid browser signature")?;
        let mut message = Vec::with_capacity(DOMAIN.len() + payload.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(payload);
        self.key
            .verify(&message, &signature)
            .context("invalid browser signature")
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRequest {
    pub origin: String,
    pub challenge: String,
    pub operation: String,
    pub payload: serde_json::Value,
}

#[derive(Default)]
pub struct Challenges {
    entries: Mutex<HashMap<String, (String, Instant)>>,
}

impl Challenges {
    pub fn issue(&self, key: &BrowserKey) -> anyhow::Result<String> {
        let mut entries = self.entries.lock().expect("challenge lock");
        let now = Instant::now();
        entries.retain(|_, (_, expiry)| *expiry > now);
        anyhow::ensure!(
            entries.len() < MAX_CHALLENGES,
            "browser challenge capacity exhausted"
        );
        let mut nonce = [0_u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        let challenge = crate::base64::encode_url_safe_no_pad(nonce);
        entries.insert(
            challenge.clone(),
            (key.id().to_owned(), now + CHALLENGE_TTL),
        );
        Ok(challenge)
    }

    /// Verify the original request bytes, then consume the challenge exactly
    /// once across concurrent requests. Neither restart nor a new listener
    /// preserves any outstanding challenge.
    pub fn authenticate(
        &self,
        key: &BrowserKey,
        origin: &str,
        request: &[u8],
        signature: &str,
    ) -> anyhow::Result<BrowserRequest> {
        key.verify(request, signature)?;
        let request: BrowserRequest = serde_json::from_slice(request)?;
        anyhow::ensure!(request.origin == origin, "wrong browser API origin");
        let mut entries = self.entries.lock().expect("challenge lock");
        let valid =
            entries.get(&request.challenge).is_some_and(|(id, expiry)| {
                id == key.id() && *expiry > Instant::now()
            });
        anyhow::ensure!(valid, "invalid or expired browser challenge");
        entries.remove(&request.challenge);
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;

    #[test]
    fn request_is_bound_to_payload_origin_and_one_use() {
        let signing_key =
            p256::ecdsa::SigningKey::from_slice(&[7_u8; 32]).unwrap();
        let public = signing_key.verifying_key().to_sec1_point(false);
        let key = BrowserKey::parse(&crate::base64::encode_url_safe_no_pad(
            public.as_bytes(),
        ))
        .unwrap();
        let challenges = Challenges::default();
        let challenge = challenges.issue(&key).unwrap();
        let origin = "https://rbw.example";
        let request = serde_json::to_vec(&serde_json::json!({
            "origin": origin,
            "challenge": challenge,
            "operation": "status",
            "payload": {"account": "test"}
        }))
        .unwrap();
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&request);
        let signature: p256::ecdsa::Signature = signing_key.sign(&message);
        let signature =
            crate::base64::encode_url_safe_no_pad(signature.to_bytes());

        let mut tampered = request.clone();
        tampered.push(b' ');
        assert!(challenges
            .authenticate(&key, origin, &tampered, &signature)
            .is_err());
        assert!(challenges
            .authenticate(&key, "https://other.example", &request, &signature)
            .is_err());
        assert_eq!(
            challenges
                .authenticate(&key, origin, &request, &signature)
                .unwrap()
                .operation,
            "status"
        );
        assert!(challenges
            .authenticate(&key, origin, &request, &signature)
            .is_err());
    }
}
