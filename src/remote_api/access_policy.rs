//! Account-scoped grants shared by certificate clients.

use super::{
    update_policy_store, ApiError, ClientPolicy, ErrorCode, FieldRef,
};
use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountGrants {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_items: Vec<FieldRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub items: BTreeMap<String, Vec<FieldRef>>,
    #[serde(default)]
    pub status: bool,
    #[serde(default)]
    pub unlock: bool,
}

impl AccountGrants {
    pub fn has_items(&self) -> bool {
        !self.all_items.is_empty()
            || self.items.values().any(|fields| !fields.is_empty())
    }
}

pub type AccountPolicy = BTreeMap<String, AccountGrants>;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessPolicies {
    #[serde(default)]
    pub named: BTreeMap<String, AccountPolicy>,
    #[serde(default)]
    pub assignments: BTreeMap<String, String>,
    #[serde(default)]
    pub source_allowlists: BTreeMap<String, Vec<String>>,
}

impl AccessPolicies {
    pub fn is_empty(&self) -> bool {
        self.named.is_empty()
            && self.assignments.is_empty()
            && self.source_allowlists.is_empty()
    }

    pub fn accounts(
        &self,
        client: &ClientPolicy,
    ) -> Result<Vec<String>, ApiError> {
        let Some(name) = self.assignments.get(&client.id) else {
            return Ok(client.account.iter().cloned().collect());
        };
        let policy = self
            .named
            .get(name)
            .ok_or_else(|| ApiError::new(ErrorCode::Forbidden))?;
        Ok(policy
            .iter()
            .filter(|(_, grants)| grants.has_items())
            .map(|(name, _)| name.clone())
            .collect())
    }

    /// Resolve one account for item operations. Policy-backed certificates
    /// get their status and unlock grants from the same policy snapshot.
    pub fn apply(
        &self,
        client: &mut ClientPolicy,
        requested: Option<&str>,
        item_operation: bool,
    ) -> Result<(), ApiError> {
        let forbidden = || ApiError::new(ErrorCode::Forbidden);
        let Some(name) = self.assignments.get(&client.id) else {
            if item_operation
                && requested.is_some()
                && requested != client.account.as_deref()
            {
                return Err(forbidden());
            }
            return Ok(());
        };
        let policy = self.named.get(name).ok_or_else(forbidden)?;
        let accounts = self.accounts(client)?;
        let account = requested
            .or_else(|| (accounts.len() == 1).then(|| accounts[0].as_str()));
        if item_operation && account.is_none() && accounts.len() > 1 {
            return Err(ApiError::new(ErrorCode::InvalidRequest));
        }
        let grants = account
            .and_then(|name| policy.get(name))
            .filter(|grants| grants.has_items());
        if item_operation && requested.is_some() && grants.is_none() {
            return Err(forbidden());
        }

        client.account =
            account.filter(|_| grants.is_some()).map(str::to_owned);
        client.all_items =
            grants.map(|g| g.all_items.clone()).unwrap_or_default();
        client.items = grants
            .into_iter()
            .flat_map(|g| &g.items)
            .filter(|(_, fields)| !fields.is_empty())
            .map(|(item, fields)| (item.clone(), fields.clone()))
            .collect();
        client.status_accounts = policy
            .iter()
            .filter(|(_, grants)| grants.status)
            .map(|(account, _)| account.clone())
            .collect();
        client.status = !client.status_accounts.is_empty();
        client.unlock_accounts = policy
            .iter()
            .filter(|(_, grants)| grants.unlock)
            .map(|(account, _)| account.clone())
            .collect();
        Ok(())
    }

    pub fn permits_source(
        &self,
        id: &str,
        peer: Option<std::net::IpAddr>,
    ) -> bool {
        self.source_allowlists.get(id).is_none_or(|allowed| {
            peer.is_some_and(|peer| {
                let peer = match peer {
                    std::net::IpAddr::V6(ip) => {
                        ip.to_ipv4_mapped().map_or(peer, std::net::IpAddr::V4)
                    }
                    peer @ std::net::IpAddr::V4(_) => peer,
                };
                allowed.iter().any(|entry| {
                    parse_network(entry)
                        .is_ok_and(|network| network.contains(&peer))
                })
            })
        })
    }
}

fn parse_network(entry: &str) -> anyhow::Result<ipnet::IpNet> {
    if let Ok(address) = entry.parse::<std::net::IpAddr>() {
        return Ok(ipnet::IpNet::from(address));
    }
    entry
        .parse::<ipnet::IpNet>()
        .with_context(|| format!("invalid source IP or CIDR {entry:?}"))
}

pub fn set_sources(
    client_id: &str,
    entries: &[String],
) -> anyhow::Result<()> {
    let entries = entries
        .iter()
        .map(|entry| parse_network(entry).map(|net| net.trunc().to_string()))
        .collect::<anyhow::Result<Vec<_>>>()?;
    update_policy_store(|store| {
        anyhow::ensure!(
            store.clients.contains_key(client_id),
            "mTLS client was not found"
        );
        if entries.is_empty() {
            store.access.source_allowlists.remove(client_id);
        } else {
            store
                .access
                .source_allowlists
                .insert(client_id.to_owned(), entries);
        }
        Ok(())
    })
}

pub fn set_policy(name: &str, policy: AccountPolicy) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 48
            && name.bytes().all(|ch| ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || ch == b'-'),
        "policy names must use lowercase letters, digits or hyphens"
    );
    let config = crate::config::Config::load()?;
    for (account, grants) in &policy {
        config.account(Some(account))?;
        for (item, fields) in &grants.items {
            anyhow::ensure!(
                !item.trim().is_empty() && item != "@all" && !fields.is_empty(),
                "item grants in account {account:?} need an item ID and at least one field; use allItems for account-wide grants"
            );
        }
    }
    update_policy_store(|store| {
        anyhow::ensure!(
            store.browser.capabilities(name).is_none(),
            "name is already used by a signed browser policy"
        );
        store.access.named.insert(name.to_owned(), policy);
        Ok(())
    })
}

pub fn assign(client_id: &str, policy: &str) -> anyhow::Result<()> {
    update_policy_store(|store| {
        if store.clients.contains_key(client_id) {
            anyhow::ensure!(
                store.access.named.contains_key(policy),
                "account-scoped policy was not found"
            );
            store
                .access
                .assignments
                .insert(client_id.to_owned(), policy.to_owned());
        } else {
            anyhow::ensure!(
                store.browser.capabilities(policy).is_some(),
                "browser policy was not found"
            );
            let client = store
                .browser
                .clients
                .get_mut(client_id)
                .context("remote API client was not found")?;
            policy.clone_into(&mut client.policy);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_explicit_and_source_rules_match_networks() {
        let mut client: ClientPolicy =
            serde_json::from_value(serde_json::json!({
                "id": "client", "name": "test", "fingerprint": "unused",
                "account": "old", "status": true,
                "allItems": ["password"], "unlockAccounts": ["old"]
            }))
            .unwrap();
        let policy = AccessPolicies {
            named: BTreeMap::from([(
                "mixed".into(),
                BTreeMap::from([
                    (
                        "personal".into(),
                        AccountGrants {
                            all_items: vec![FieldRef::Username],
                            status: true,
                            ..AccountGrants::default()
                        },
                    ),
                    (
                        "work".into(),
                        AccountGrants {
                            items: BTreeMap::from([(
                                "item".into(),
                                vec![FieldRef::Totp],
                            )]),
                            unlock: true,
                            ..AccountGrants::default()
                        },
                    ),
                ]),
            )]),
            assignments: BTreeMap::from([("client".into(), "mixed".into())]),
            source_allowlists: BTreeMap::from([(
                "client".into(),
                vec!["100.64.0.0/10".into()],
            )]),
        };
        assert!(policy.apply(&mut client, None, true).is_err());
        assert!(policy.apply(&mut client, Some("old"), true).is_err());
        policy.apply(&mut client, Some("work"), true).unwrap();
        assert!(client.permits("item", &FieldRef::Totp));
        assert!(!client.permits("other", &FieldRef::Totp));
        assert!(!client.permits("item", &FieldRef::Password));
        assert_eq!(client.status_accounts, ["personal"]);
        assert_eq!(client.unlock_accounts, ["work"]);
        policy.apply(&mut client, Some("personal"), true).unwrap();
        assert!(client.permits("other", &FieldRef::Username));
        assert!(!client.permits("item", &FieldRef::Totp));
        assert!(policy
            .permits_source("client", Some("100.64.1.5".parse().unwrap())));
        assert!(!policy
            .permits_source("client", Some("100.128.1.5".parse().unwrap())));
        assert!(!policy.permits_source("client", None));
    }
}
