use sha2::Digest as _;

// Decrypted key material for a single unlocked account. Present in
// `State::accounts` only while that account is unlocked.
#[derive(Default)]
pub struct AccountKeys {
    pub priv_key: Option<rbw::locked::Keys>,
    pub org_keys:
        Option<std::collections::HashMap<String, rbw::locked::Keys>>,
    pub master_password_reprompt: std::collections::HashSet<[u8; 32]>,
    pub master_password_reprompt_initialized: bool,
}

impl AccountKeys {
    fn key(&self, org_id: Option<&str>) -> Option<&rbw::locked::Keys> {
        org_id.map_or(self.priv_key.as_ref(), |id| {
            self.org_keys.as_ref().and_then(|h| h.get(id))
        })
    }

    fn needs_unlock(&self) -> bool {
        self.priv_key.is_none() || self.org_keys.is_none()
    }
}

pub struct State {
    // Per-account key material, keyed by account name. A single global timeout
    // (below) locks all of them at once.
    pub accounts: std::collections::HashMap<String, AccountKeys>,
    pub timeout: crate::timeout::Timeout,
    pub timeout_duration: std::time::Duration,
    pub sync_timeout: crate::timeout::Timeout,
    pub sync_timeout_duration: std::time::Duration,
    pub notifications_handler: crate::notifications::Handler,

    // this is stored here specifically for the use of the ssh agent, because
    // requests made to the ssh agent don't include an environment, and so we
    // can't properly initialize the pinentry process. we work around this by
    // just reusing the last environment we saw being sent to the main agent
    // (there should be at least one in most cases because you need to start
    // the rbw agent in order to make it start serving on the ssh agent
    // socket, and that initial request should come with an environment).
    //
    // we should not use this for any requests on the main agent, those
    // should all send their own environment over.
    pub last_environment: rbw::protocol::Environment,

    #[cfg(feature = "clipboard")]
    pub clipboard: Option<arboard::Clipboard>,
}

impl State {
    pub fn account(&self, account: &str) -> Option<&AccountKeys> {
        self.accounts.get(account)
    }

    // Get (creating if absent) the mutable key slot for an account.
    pub fn account_mut(&mut self, account: &str) -> &mut AccountKeys {
        self.accounts.entry(account.to_string()).or_default()
    }

    pub fn key(
        &self,
        account: &str,
        org_id: Option<&str>,
    ) -> Option<&rbw::locked::Keys> {
        self.accounts.get(account).and_then(|a| a.key(org_id))
    }

    pub fn needs_unlock(&self, account: &str) -> bool {
        self.accounts
            .get(account)
            .is_none_or(AccountKeys::needs_unlock)
    }

    // True if at least one account is currently unlocked.
    // Not called yet: needed by the in-flight multi-account branch.
    #[allow(dead_code)]
    pub fn any_unlocked(&self) -> bool {
        self.accounts.values().any(|a| !a.needs_unlock())
    }

    pub fn set_unlocked(
        &mut self,
        account: &str,
        keys: rbw::locked::Keys,
        org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
    ) {
        let acct = self.account_mut(account);
        acct.priv_key = Some(keys);
        acct.org_keys = Some(org_keys);
    }

    pub fn set_timeout(&self) {
        self.timeout.set(self.timeout_duration);
    }

    // Lock every account (the single global timeout clears them all at once).
    pub fn clear(&mut self) {
        self.accounts.clear();
        self.timeout.clear();
    }

    // Lock a single account (the others stay unlocked, so the global
    // timeout is left running for them).
    pub fn clear_account(&mut self, account: &str) {
        self.accounts.remove(account);
    }

    pub fn set_sync_timeout(&self) {
        self.sync_timeout.set(self.sync_timeout_duration);
    }

    // the way we structure the client/agent split in rbw makes the master
    // password reprompt feature a bit complicated to implement - it would be
    // a lot easier to just have the client do the prompting, but that would
    // leave it open to someone reading the cipherstring from the local
    // database and passing it to the agent directly, bypassing the client.
    // the agent is the thing that holds the unlocked secrets, so it also
    // needs to be the thing guarding access to master password reprompt
    // entries. we only pass individual cipherstrings to the agent though, so
    // the agent needs to be able to recognize the cipherstrings that need
    // reprompting, without the additional context of the entry they came
    // from. in addition, because the reprompt state is stored in the sync db
    // in plaintext, we can't just read it from the db directly, because
    // someone could just edit the file on disk before making the request.
    //
    // therefore, the solution we choose here is to keep an in-memory set of
    // cipherstrings that we know correspond to entries with master password
    // reprompt enabled. this set is only updated when the agent itself does
    // a sync, so it can't be bypassed by editing the on-disk file directly.
    // if the agent gets a request for any of those cipherstrings that it saw
    // marked as master password reprompt during the most recent sync, it
    // forces a reprompt. this is tracked per account.
    pub fn set_master_password_reprompt(
        &mut self,
        account: &str,
        entries: &[rbw::db::Entry],
    ) {
        let mut set = std::collections::HashSet::new();

        let mut hasher = sha2::Sha256::new();
        let mut insert = |s: Option<&str>| {
            if let Some(s) = s {
                if !s.is_empty() {
                    hasher.update(s);
                    set.insert(hasher.finalize_reset().into());
                }
            }
        };

        for entry in entries {
            if !entry.master_password_reprompt() {
                continue;
            }

            match &entry.data {
                rbw::db::EntryData::Login { password, totp, .. } => {
                    insert(password.as_deref());
                    insert(totp.as_deref());
                }
                rbw::db::EntryData::Card { number, code, .. } => {
                    insert(number.as_deref());
                    insert(code.as_deref());
                }
                rbw::db::EntryData::Identity {
                    ssn,
                    passport_number,
                    ..
                } => {
                    insert(ssn.as_deref());
                    insert(passport_number.as_deref());
                }
                rbw::db::EntryData::SecureNote => {}
                rbw::db::EntryData::SshKey { private_key, .. } => {
                    insert(private_key.as_deref());
                }
            }

            for field in &entry.fields {
                if field.ty == Some(rbw::api::FieldType::Hidden) {
                    insert(field.value.as_deref());
                }
            }
        }

        let acct = self.account_mut(account);
        acct.master_password_reprompt = set;
        acct.master_password_reprompt_initialized = true;
    }

    pub fn master_password_reprompt_initialized(
        &self,
        account: &str,
    ) -> bool {
        self.account(account)
            .is_some_and(|a| a.master_password_reprompt_initialized)
    }

    pub fn master_password_reprompt_contains(
        &self,
        account: &str,
        hash: &[u8; 32],
    ) -> bool {
        self.account(account)
            .is_some_and(|a| a.master_password_reprompt.contains(hash))
    }

    pub fn last_environment(&self) -> &rbw::protocol::Environment {
        &self.last_environment
    }

    pub fn set_last_environment(
        &mut self,
        environment: rbw::protocol::Environment,
    ) {
        self.last_environment = environment;
    }
}
