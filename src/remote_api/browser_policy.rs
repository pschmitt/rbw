//! Shared authorization policies and enrollment state for signed browsers.

use super::{browser_pairing::BrowserKey, update_policy_store};
use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_PENDING: usize = 32;
const PAIRING_TTL_SECONDS: u64 = 300;

pub fn pairing_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(
    clap::ValueEnum, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Read,
    Unlock,
    Passkeys,
}

impl Capability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Unlock => "unlock",
            Self::Passkeys => "passkeys",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserPolicies {
    #[serde(default)]
    pub named: BTreeMap<String, Vec<Capability>>,
    #[serde(default)]
    pub clients: BTreeMap<String, BrowserClient>,
    #[serde(default)]
    pub pending: BTreeMap<String, PairingRequest>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserClient {
    pub name: String,
    pub account: String,
    pub policy: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRequest {
    pub name: String,
    pub code: String,
    pub expires: u64,
    pub denied: bool,
}

impl BrowserPolicies {
    pub fn is_empty(&self) -> bool {
        self.named.is_empty()
            && self.clients.is_empty()
            && self.pending.is_empty()
    }

    pub fn capabilities(&self, policy: &str) -> Option<&[Capability]> {
        use Capability::{Passkeys, Read, Unlock};
        match policy {
            "admin" => Some(&[Read, Unlock, Passkeys]),
            "read-only" => Some(&[Read]),
            name => self.named.get(name).map(Vec::as_slice),
        }
    }

    pub fn allows(
        &self,
        client: &BrowserClient,
        capability: Capability,
    ) -> bool {
        self.capabilities(&client.policy)
            .is_some_and(|caps| caps.contains(&capability))
    }

    pub fn request_pairing(
        &mut self,
        key: &BrowserKey,
        name: &str,
        now: u64,
    ) -> anyhow::Result<PairingRequest> {
        let name = name.trim();
        anyhow::ensure!(
            !name.is_empty()
                && name.len() <= 80
                && !name.chars().any(char::is_control),
            "invalid browser client name"
        );
        anyhow::ensure!(
            !self.clients.contains_key(key.id()),
            "browser already approved"
        );
        self.pending.retain(|_, request| request.expires > now);
        if let Some(request) = self.pending.get(key.id()) {
            return Ok(request.clone());
        }
        anyhow::ensure!(
            self.pending.len() < MAX_PENDING,
            "too many pending browser requests"
        );

        // A short representation of the exact key lets the enrolling user
        // compare the two displays, independently of the untrusted name.
        let request = PairingRequest {
            name: name.to_owned(),
            code: key.id()[..12].to_owned(),
            expires: now.saturating_add(PAIRING_TTL_SECONDS),
            denied: false,
        };
        self.pending.insert(key.id().to_owned(), request.clone());
        Ok(request)
    }

    pub fn pending_request(
        &self,
        id: &str,
        now: u64,
    ) -> anyhow::Result<&PairingRequest> {
        self.pending
            .get(id)
            .filter(|request| request.expires > now)
            .context("browser pairing request has expired or was not found")
    }
}

pub fn approve(id: &str, account: &str, policy: &str) -> anyhow::Result<()> {
    crate::config::Config::load()?.account(Some(account))?;
    update_policy_store(|store| {
        let browser = &mut store.browser;
        anyhow::ensure!(
            browser.capabilities(policy).is_some(),
            "browser policy was not found"
        );
        let request = browser.pending_request(id, pairing_time())?;
        anyhow::ensure!(
            !request.denied,
            "browser pairing request was denied"
        );
        let client = BrowserClient {
            name: request.name.clone(),
            account: account.to_owned(),
            policy: policy.to_owned(),
        };
        browser.pending.remove(id);
        browser.clients.insert(id.to_owned(), client);
        Ok(())
    })
}

pub fn deny(id: &str) -> anyhow::Result<()> {
    update_policy_store(|store| {
        let browser = &mut store.browser;
        browser.pending_request(id, pairing_time())?;
        browser.pending.get_mut(id).expect("checked request").denied = true;
        Ok(())
    })
}

pub fn set_policy(
    name: &str,
    capabilities: Vec<Capability>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 48
            && name.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'-'),
        "policy names must use lowercase letters, digits or hyphens"
    );
    anyhow::ensure!(
        !matches!(name, "admin" | "read-only"),
        "built-in policies cannot be edited"
    );
    update_policy_store(|store| {
        store.browser.named.insert(name.to_owned(), capabilities);
        Ok(())
    })
}

pub fn assign_policy(client_id: &str, policy: &str) -> anyhow::Result<()> {
    update_policy_store(|store| {
        let browser = &mut store.browser;
        anyhow::ensure!(
            browser.capabilities(policy).is_some(),
            "browser policy was not found"
        );
        let client = browser
            .clients
            .get_mut(client_id)
            .context("browser client was not found")?;
        policy.clone_into(&mut client.policy);
        Ok(())
    })
}
