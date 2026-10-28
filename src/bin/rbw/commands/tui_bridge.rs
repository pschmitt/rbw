use super::*;

// Unlock the vault and return the local db together with a lightweight,
// batch-decrypted search index (one agent round-trip for the whole vault). The
// index is parallel to `db.entries` and drives list rendering and filtering;
// full per-entry detail is decrypted lazily via `decrypt_cipher`.
// A single unlocked account's loaded vault for the TUI.
pub struct TuiVault {
    pub account: String,
    pub db: rbw::db::Db,
    pub search: Vec<DecryptedSearchCipher>,
}

#[derive(Debug, Clone, Default)]
pub struct TuiEntryScope {
    pub organization: Option<String>,
    pub collections: Vec<String>,
}

pub fn tui_entry_scope(
    db: &rbw::db::Db,
    entry: &rbw::db::Entry,
) -> TuiEntryScope {
    let organization = entry.org_id.as_deref().map(|id| {
        db.organizations
            .iter()
            .find(|org| org.id == id)
            .map_or_else(|| id.to_string(), |org| org.name.clone())
    });
    let collections = entry
        .collection_ids
        .iter()
        .map(|id| {
            db.collections
                .iter()
                .find(|collection| collection.id == *id)
                .map_or_else(
                    || id.clone(),
                    |collection| {
                        // Unlike organization names, collection names are
                        // encrypted with the org key in the sync response
                        // (see the comment on `Collection` in db.rs) --
                        // fall back to the raw (still-encrypted) name
                        // rather than hiding the collection entirely if a
                        // stale/missing org key ever makes this fail.
                        crate::actions::decrypt(
                            &collection.name,
                            None,
                            Some(&collection.org_id),
                        )
                        .unwrap_or_else(|_| collection.name.clone())
                    },
                )
        })
        .collect();
    TuiEntryScope {
        organization,
        collections,
    }
}

// The initial state handed to the TUI: the vaults of every currently-unlocked
// account, the names of configured-but-locked accounts (offered for lazy
// unlock in the accounts panel), and whether more than one account exists (so
// the UI can hide account badges in the common single-account case).
pub struct TuiOpen {
    pub vaults: Vec<TuiVault>,
    pub locked: Vec<String>,
    pub multi: bool,
}

// The synthetic single vault behind `rbw tui --from-file`: like `TuiVault`,
// but `decrypted`/`attachment_data` carry what would otherwise be decrypted
// lazily via the agent -- there's no agent in this mode, since the export
// format is already plaintext.
pub struct TuiFileVault {
    pub label: String,
    pub db: rbw::db::Db,
    pub search: Vec<DecryptedSearchCipher>,
    pub decrypted: std::collections::HashMap<String, DecryptedCipher>,
    pub attachment_data: std::collections::HashMap<String, Vec<u8>>,
    pub entry_extra: std::collections::HashMap<String, FileEntryExtra>,
    pub collections: Vec<ExportedCollection>,
    pub passphrase: Option<String>,
    pub path: std::path::PathBuf,
    pub write: bool,
}

// Loads `path` (see `load_from_file`) into a `TuiFileVault`: a placeholder
// `rbw::db::Entry` per real entry (only `id` is real, used for indexing --
// nothing will ever decrypt these through `decrypt_cipher`) plus the real
// search index and full detail built directly from the already-decrypted
// entries. `write` (`rbw tui --from-file FILE --write`) takes a `.bak`
// snapshot of the file right away, before any edit can happen.
pub fn tui_vault_from_file(
    path: &std::path::Path,
    write: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<TuiFileVault> {
    let vault = load_from_file(path, passphrase)?;
    if write {
        backup_file(path)?;
    }
    let label = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .map_or_else(
            || "export".to_string(),
            |name| format!("export: {name}"),
        );

    let mut db = rbw::db::Db::new();
    db.entries = vault
        .entries
        .iter()
        .map(|entry| placeholder_entry(entry.id.clone()))
        .collect();
    let search = vault
        .entries
        .iter()
        .map(decrypted_cipher_to_search)
        .collect();
    let decrypted = vault
        .entries
        .into_iter()
        .map(|entry| (entry.id.clone(), entry))
        .collect();

    Ok(TuiFileVault {
        label,
        db,
        search,
        decrypted,
        attachment_data: vault.attachment_data,
        entry_extra: vault.entry_extra,
        collections: vault.collections,
        passphrase: vault.passphrase,
        path: path.to_path_buf(),
        write,
    })
}

// Rebuilds the placeholder `db.entries`/search index pair from a
// `--from-file` vault's `decrypted` map -- the same construction
// `tui_vault_from_file` does for the initial load, reused after every
// `--write` mutation so the TUI's list/filtering stays in sync with
// entries added, edited, or removed in memory.
pub fn rebuild_file_vault_indices(
    decrypted: &std::collections::HashMap<String, DecryptedCipher>,
) -> (Vec<rbw::db::Entry>, Vec<DecryptedSearchCipher>) {
    let entries = decrypted
        .values()
        .map(|entry| placeholder_entry(entry.id.clone()))
        .collect();
    let search = decrypted.values().map(decrypted_cipher_to_search).collect();
    (entries, search)
}

// Everything a writable (`--write`) `--from-file` TUI vault needs to save
// itself back to disk, alongside the `decrypted`/`attachment_data` maps
// already on `AccountVault`.
pub struct FileSaveTarget {
    pub path: std::path::PathBuf,
    pub passphrase: Option<String>,
    pub collections: Vec<ExportedCollection>,
    pub entry_extra: std::collections::HashMap<String, FileEntryExtra>,
}

pub fn tui_file_entry_scope(
    target: &FileSaveTarget,
    entry_id: &str,
) -> TuiEntryScope {
    let Some(extra) = target.entry_extra.get(entry_id) else {
        return TuiEntryScope::default();
    };
    let collections = extra
        .collection_ids
        .iter()
        .map(|id| {
            target
                .collections
                .iter()
                .find(|collection| collection.id == *id)
                .map_or_else(
                    || id.clone(),
                    |collection| collection.name.clone(),
                )
        })
        .collect();
    TuiEntryScope {
        // The export format carries collection organization IDs, but not the
        // organization names. Keep the ID visible/searchable rather than
        // dropping the organization association from the preview.
        organization: extra.org_id.clone(),
        collections,
    }
}

// Writes `decrypted`/`attachment_data` back to `target.path`, in whatever
// format it was loaded in. Called after every `--write` TUI mutation.
pub(super) fn save_file_vault(
    decrypted: &std::collections::HashMap<String, DecryptedCipher>,
    attachment_data: &std::collections::HashMap<String, Vec<u8>>,
    target: &FileSaveTarget,
) -> anyhow::Result<()> {
    let exported = decrypted
        .values()
        .map(|e| to_exported_entry(e, attachment_data, &target.entry_extra))
        .collect();
    save_to_file(
        &target.path,
        exported,
        target.collections.clone(),
        target.passphrase.as_deref(),
    )
}

// `rbw tui --from-file FILE --write`'s counterpart to `tui_save_edit`/
// `tui_save_add`: applies an `EditableCipher` (a new entry if `entry_id`
// is `None`, matching `tui_save_add`'s contract) directly to the in-memory
// vault and saves back to the file, instead of encrypting and pushing to
// the server. Existing attachments/history are preserved when editing;
// history additionally gets the outgoing password inserted, same as
// `tui_save_edit`.
pub fn tui_save_edit_to_file(
    decrypted: &mut std::collections::HashMap<String, DecryptedCipher>,
    attachment_data: &std::collections::HashMap<String, Vec<u8>>,
    target: &FileSaveTarget,
    entry_id: Option<&str>,
    updated: &EditableCipher,
) -> anyhow::Result<()> {
    if updated.name.trim().is_empty() {
        anyhow::bail!("name cannot be empty");
    }

    let existing = entry_id.and_then(|id| decrypted.get(id));
    let (data, fields, notes) = editable_to_decrypted(updated);

    let mut history = existing.map(|e| e.history.clone()).unwrap_or_default();
    if let Some(existing) = existing {
        if let (
            DecryptedData::Login {
                password: Some(old_pw),
                ..
            },
            DecryptedData::Login {
                password: new_pw, ..
            },
        ) = (&existing.data, &data)
        {
            if Some(old_pw) != new_pw.as_ref() {
                history.insert(
                    0,
                    DecryptedHistoryEntry {
                        last_used_date: format!(
                            "{}",
                            humantime::format_rfc3339(
                                std::time::SystemTime::now()
                            )
                        ),
                        password: old_pw.clone(),
                    },
                );
            }
        }
    }
    let attachments =
        existing.map(|e| e.attachments.clone()).unwrap_or_default();
    let archived = existing.is_some_and(|e| e.archived);
    let deleted = existing.is_some_and(|e| e.deleted);
    let id = entry_id.map_or_else(
        || uuid::Uuid::new_v4().to_string(),
        std::string::ToString::to_string,
    );

    decrypted.insert(
        id.clone(),
        DecryptedCipher {
            attachment_metadata: AttachmentMetadata::new(
                &id,
                attachments.len(),
            ),
            id,
            folder: updated.folder.clone(),
            name: updated.name.clone(),
            data,
            fields,
            notes,
            history,
            attachments,
            archived,
            deleted,
            account: None,
            revision_date: None,
        },
    );

    save_file_vault(decrypted, attachment_data, target)
}

// `--write` TUI's counterpart to `tui_delete`.
pub fn tui_delete_from_file(
    decrypted: &mut std::collections::HashMap<String, DecryptedCipher>,
    attachment_data: &std::collections::HashMap<String, Vec<u8>>,
    target: &FileSaveTarget,
    entry_id: &str,
) -> anyhow::Result<()> {
    decrypted.remove(entry_id);
    save_file_vault(decrypted, attachment_data, target)
}

// `--write` TUI's counterpart to `tui_attachment_create`: reads `file`
// straight into the vault's attachment side table (there's no server to
// encrypt-and-upload to) and assigns it a fresh id.
pub fn tui_attachment_create_to_file(
    decrypted: &mut std::collections::HashMap<String, DecryptedCipher>,
    attachment_data: &mut std::collections::HashMap<String, Vec<u8>>,
    target: &FileSaveTarget,
    entry_id: &str,
    file: &std::path::Path,
) -> anyhow::Result<()> {
    let Some(entry) = decrypted.get_mut(entry_id) else {
        anyhow::bail!("entry no longer exists");
    };
    let filename = file
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?
        .to_string();
    let data = std::fs::read(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    let id = uuid::Uuid::new_v4().to_string();
    entry.attachments.push(DecryptedAttachment {
        id: id.clone(),
        file_name: Some(filename),
        size: None,
        size_name: None,
    });
    entry.attachment_metadata =
        AttachmentMetadata::new(&entry.id, entry.attachments.len());
    attachment_data.insert(id, data);

    save_file_vault(decrypted, attachment_data, target)
}

// `--write` TUI's counterpart to `tui_attachment_delete`.
pub fn tui_attachment_delete_from_file(
    decrypted: &mut std::collections::HashMap<String, DecryptedCipher>,
    attachment_data: &mut std::collections::HashMap<String, Vec<u8>>,
    target: &FileSaveTarget,
    entry_id: &str,
    attachment_id: &str,
) -> anyhow::Result<()> {
    let Some(entry) = decrypted.get_mut(entry_id) else {
        anyhow::bail!("entry no longer exists");
    };
    entry.attachments.retain(|a| a.id != attachment_id);
    entry.attachment_metadata =
        AttachmentMetadata::new(&entry.id, entry.attachments.len());
    attachment_data.remove(attachment_id);

    save_file_vault(decrypted, attachment_data, target)
}

// A stand-in `rbw::db::Entry` carrying just enough (a real `id`) to satisfy
// the TUI's `db.entries`/`search`/`slot` indexing for a `--from-file` vault.
// Every other field is unused: `ensure_detail` reads full detail from
// `AccountVault::decrypted` instead of ever calling `decrypt_cipher` on
// this.
pub(super) fn placeholder_entry(id: String) -> rbw::db::Entry {
    rbw::db::Entry {
        id,
        org_id: None,
        folder: None,
        folder_id: None,
        name: String::new(),
        data: rbw::db::EntryData::Login {
            username: None,
            password: None,
            totp: None,
            uris: Vec::new(),
            fido2_credentials: Vec::new(),
        },
        fields: Vec::new(),
        notes: None,
        history: Vec::new(),
        key: None,
        master_password_reprompt: rbw::api::CipherRepromptType::None,
        archived_date: None,
        favorite: false,
        archived: false,
        deleted: false,
        collection_ids: Vec::new(),
        attachments: Vec::new(),
        revision_date: None,
    }
}

// Status of one configured account, for the accounts panel.
pub struct TuiAccount {
    pub name: String,
    pub email: Option<String>,
    pub server: String,
    pub unlocked: bool,
    pub primary: bool,
    // `(source account, optional source item)` from
    // `Account::credential_source`, if this account's master password is
    // linked to another account's vault.
    pub credential_source: Option<(String, Option<String>)>,
}

// True if the currently-active account is unlocked in the agent.
pub(super) fn active_account_unlocked() -> bool {
    crate::actions::unlocked().is_ok()
}

// True if the named configured account is currently unlocked in the agent.
// Used by the TUI's periodic lock-detection poll (`App::poll_agent_lock`) to
// notice when an account it already loaded gets locked out from under it —
// by another process running `rbw lock`/`rbw stop-agent`, or a `lock_timeout`
// expiry — independently of the TUI's own lifetime. Like every other
// per-account tui_* helper, this leaves `crate::actions`' active-account
// pointer set to `name`; that's harmless for a passive check since the next
// real operation always re-points it before doing anything.
pub fn tui_account_unlocked(name: &str) -> anyhow::Result<bool> {
    crate::actions::set_active_account(Some(name.to_string()))?;
    Ok(active_account_unlocked())
}

// Whether an account should be proactively unlocked (prompting as needed)
// for a multi-account merge: `Always` unconditionally, `Never` not even with
// `all`, and the default `OnDemand` only when `all` is set. Shared by
// `list_target_accounts` and `tui_open_with_progress` so the two can't drift
// apart the way they used to -- `tui_open_with_progress` independently
// re-implemented this as `all && account.unlock != Never`, which silently
// dropped the "unconditionally" half of `Always`: an account configured
// `unlock: always` only actually got unlocked by `rbw tui` if `--all` was
// also passed on that invocation, unlike every other command honoring the
// same policy.
pub(super) fn should_unlock_for_merge(
    policy: rbw::config::UnlockPolicy,
    all: bool,
) -> bool {
    match policy {
        rbw::config::UnlockPolicy::Always => true,
        rbw::config::UnlockPolicy::Never => false,
        rbw::config::UnlockPolicy::OnDemand => all,
    }
}

// One configured account as the browser extension sees it in its merged
// ("All accounts") view: whether `exclude_from` keeps it out of `ctx`, its
// unlock policy, and whether the agent has it unlocked right now.
pub struct AccountState {
    pub name: String,
    pub primary: bool,
    pub unlocked: bool,
    pub excluded: bool,
    pub policy: rbw::config::UnlockPolicy,
}

// Like `list_target_accounts`' account selection, but passive: it never
// unlocks anything, so a browser search or autofill can't pop up a
// password prompt. Leaves the active account unset (the primary).
pub fn account_states(
    ctx: rbw::config::ExcludeContext,
) -> anyhow::Result<Vec<AccountState>> {
    let config = rbw::config::Config::load()?;
    let primary = config.primary_account_name();
    let mut out = Vec::new();
    for account in config.accounts() {
        crate::actions::set_active_account(Some(account.name.clone()))?;
        out.push(AccountState {
            primary: account.name == primary,
            unlocked: active_account_unlocked(),
            excluded: account.excluded_from(ctx),
            policy: account.unlock.policy,
            name: account.name.clone(),
        });
    }
    crate::actions::set_active_account(None)?;
    Ok(out)
}

// Which accounts `list`/`search`/`get` should query. An explicit --account/
// RBW_ACCOUNT always wins and scopes to just that one account. Otherwise every
// configured account is a candidate, filtered per-account by
// `Account::excluded_from(ctx)` and `Account::unlock` (see
// `should_unlock_for_merge`); an account that isn't proactively unlocked
// still makes it into the merge if it happens to already be unlocked. `ctx`
// identifies the calling subcommand (e.g. `List`, `Search`, `Get`) so each can
// be excluded independently via `exclude_from`. `unlock_single_account`
// preserves the normal single-account behavior for commands that need vault
// data, while allowing login-only commands such as `sync` to stay locked.
pub(super) fn list_target_accounts(
    all: bool,
    ctx: rbw::config::ExcludeContext,
    unlock_single_account: bool,
) -> anyhow::Result<Vec<String>> {
    if let Some(name) = crate::actions::current_account() {
        if unlock_single_account {
            unlock(None, None)?;
        }
        return Ok(vec![name]);
    }

    crate::actions::set_active_account(None)?;

    let config = rbw::config::Config::load()?;
    let accounts = config.accounts();
    let primary = config.primary_account_name();
    if accounts.len() <= 1 {
        if unlock_single_account {
            unlock(None, None)?;
        }
        return Ok(vec![config.primary_account_name()]);
    }

    let mut out = Vec::new();
    for account in &accounts {
        if account.excluded_from(ctx) {
            continue;
        }
        crate::actions::set_active_account(Some(account.name.clone()))?;
        if should_unlock_for_merge(account.unlock.policy, all) {
            match unlock(None, None) {
                Ok(()) => out.push(account.name.clone()),
                Err(e) if account.name == primary => return Err(e),
                Err(e) => {
                    log::warn!(
                        "failed to auto-unlock account '{}': {e:#}; \
                         continuing without its entries",
                        account.name
                    );
                }
            }
        } else if active_account_unlocked() {
            out.push(account.name.clone());
        }
    }
    Ok(out)
}

// Open the multi-account TUI. Unlocks the target account (--account /
// RBW_ACCOUNT, else primary) up front — pinentry runs here, on the real
// terminal, before the UI takes over the screen; the target is always
// loaded regardless of `exclude_from`, since it was asked for explicitly.
// Every other configured account not excluded from `Tui` is then unlocked
// per `should_unlock_for_merge` (so `unlock: always` accounts always come
// up, `--all` additionally brings in the `on-demand` ones, and `never`
// accounts are only loaded if already unlocked); the rest are reported as
// locked for lazy unlock from the accounts panel. An account excluded from
// `Tui` is skipped entirely -- it won't appear locked in the accounts panel
// either, unless it's the target.
pub fn tui_open_with_progress<F>(
    all: bool,
    target_unlocked: bool,
    mut progress: F,
) -> anyhow::Result<TuiOpen>
where
    F: FnMut(&str),
{
    let config = rbw::config::Config::load()?;
    let accounts = config.accounts();
    let target = crate::actions::current_account()
        .unwrap_or_else(|| config.primary_account_name());

    if !target_unlocked {
        crate::actions::set_active_account(Some(target.clone()))?;
        unlock(None, None)?;
    }

    let mut vaults = Vec::new();
    let mut locked = Vec::new();
    for account in &accounts {
        if account.name != target
            && account.excluded_from(rbw::config::ExcludeContext::Tui)
        {
            continue;
        }
        crate::actions::set_active_account(Some(account.name.clone()))?;
        let should_unlock =
            should_unlock_for_merge(account.unlock.policy, all);
        if should_unlock && !active_account_unlocked() {
            let msg = format!("unlocking '{}'...", account.name);
            progress(&msg);
            if let Err(e) = unlock(None, None) {
                if account.name == target {
                    return Err(e);
                }
                log::warn!(
                    "failed to auto-unlock account '{}': {e:#}; \
                     leaving it locked",
                    account.name
                );
                locked.push(account.name.clone());
                continue;
            }
        }
        if active_account_unlocked() {
            let msg = format!("syncing '{}'...", account.name);
            progress(&msg);
            let (db, search) = tui_reload()?;
            vaults.push(TuiVault {
                account: account.name.clone(),
                db,
                search,
            });
        } else {
            locked.push(account.name.clone());
        }
    }

    Ok(TuiOpen {
        multi: accounts.len() > 1,
        vaults,
        locked,
    })
}

pub fn tui_unlock_target() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let target = crate::actions::current_account()
        .unwrap_or_else(|| config.primary_account_name());
    crate::actions::set_active_account(Some(target))?;
    unlock(None, None)?;
    Ok(())
}

// Lazily unlock one account and load its vault. pinentry runs here, so the
// caller must have restored the real terminal first (like the $EDITOR path).
pub fn tui_unlock_account(name: &str) -> anyhow::Result<TuiVault> {
    crate::actions::set_active_account(Some(name.to_string()))?;
    unlock(None, None)?;
    let (db, search) = tui_reload()?;
    Ok(TuiVault {
        account: name.to_string(),
        db,
        search,
    })
}

// Sync one account from the server and reload its vault.
pub fn tui_account_sync(name: &str) -> anyhow::Result<TuiVault> {
    crate::actions::set_active_account(Some(name.to_string()))?;
    let (db, search) = tui_sync()?;
    Ok(TuiVault {
        account: name.to_string(),
        db,
        search,
    })
}

// A `base_url` for display in the accounts panel: the bare hostname (no
// `https://`/`http://` scheme or trailing slash), or "bitwarden.com" for the
// official server (an unset `base_url`).
pub(super) fn tui_account_server(base_url: Option<&str>) -> String {
    base_url.map_or_else(
        || "bitwarden.com".to_string(),
        |url| {
            url.strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))
                .unwrap_or(url)
                .trim_end_matches('/')
                .to_string()
        },
    )
}

// The status of every configured account, for the accounts panel.
pub fn tui_accounts() -> anyhow::Result<Vec<TuiAccount>> {
    let config = rbw::config::Config::load()?;
    let primary = config.primary_account_name();
    let accounts = config.accounts();
    let mut out = Vec::with_capacity(accounts.len());
    for account in accounts {
        if account.excluded_from(rbw::config::ExcludeContext::Tui) {
            continue;
        }
        crate::actions::set_active_account(Some(account.name.clone()))?;
        // Best-effort: an unreadable secret file (e.g. not yet decrypted)
        // shows as unset rather than failing the whole accounts panel.
        let base_url =
            account.base_url.as_ref().and_then(|v| v.resolve().ok());
        let email = account.email.as_ref().and_then(|v| v.resolve().ok());
        out.push(TuiAccount {
            unlocked: active_account_unlocked(),
            primary: account.name == primary,
            server: tui_account_server(base_url.as_deref()),
            email,
            credential_source: account
                .unlock
                .credentials
                .as_ref()
                .map(|cs| (cs.account.clone(), cs.item.clone())),
            name: account.name,
        });
    }
    Ok(out)
}

// Upload a file as an attachment on an already-loaded, already-unlocked entry
// (the TUI equivalent of `attachment_create`, which finds+unlocks itself).
pub fn tui_attachment_create(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    file: &std::path::Path,
) -> anyhow::Result<()> {
    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    let filename = file
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?;
    let data = std::fs::read(file)
        .with_context(|| format!("failed to read {}", file.display()))?;

    let (encrypted_data, encrypted_key, encrypted_filename) =
        crate::actions::encrypt_attachment(
            data,
            filename,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?;

    if let (Some(tokens), ()) = rbw::actions::create_attachment(
        &access_token,
        &refresh_token,
        &entry.id,
        &encrypted_filename,
        &encrypted_key,
        &encrypted_data,
    )? {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

// Delete an attachment from an entry and sync.
pub fn tui_attachment_delete(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    attachment_id: &str,
) -> anyhow::Result<()> {
    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    if let (Some(tokens), ()) = rbw::actions::delete_attachment(
        &access_token,
        &refresh_token,
        &entry.id,
        attachment_id,
    )? {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

// Add a new account to the config from the TUI accounts panel. Mirrors
// `account_add` but without printing or tearing down the agent (per-account
// keysets make that unnecessary). The account starts locked; unlocking it from
// the panel runs the login/unlock flow.
pub fn tui_account_add(
    name: &str,
    email: Option<String>,
    base_url: Option<String>,
) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("account name cannot be empty");
    }
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    if config.accounts.iter().any(|a| a.name == name) {
        anyhow::bail!("account '{name}' already exists");
    }
    let first = config.accounts.is_empty();
    config.accounts.push(rbw::config::Account {
        name: name.to_string(),
        email: email.map(Into::into),
        sso_id: None,
        base_url: base_url.map(Into::into),
        identity_url: None,
        ui_url: None,
        notifications_url: None,
        client_cert_path: None,
        unlock: rbw::config::UnlockConfig::default(),
        exclude_from: Vec::new(),
        color: None,
    });
    if first {
        config.primary_account = Some(name.to_string());
    }
    config.save()?;
    Ok(())
}

// Set the primary account without tearing down the agent: under per-account
// keysets (see the agent's State) the other accounts' keys stay valid, so
// there is no need to lock everything the way the CLI `account primary` does.
pub fn tui_set_primary(name: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()?;
    config.migrate_legacy();
    if !config.accounts.iter().any(|a| a.name == name) {
        anyhow::bail!("account '{name}' not found");
    }
    config.primary_account = Some(name.to_string());
    config.save()?;
    Ok(())
}

// The configured default password-generation policy, for the TUI's settings
// view. Never fails: a missing/unreadable config just means "no overrides
// yet" (mirrors `App::new`'s handling of the keymap config).
pub fn tui_password_gen_policy() -> rbw::config::PasswordGenPolicy {
    rbw::config::Config::load()
        .map(|c| c.password_gen)
        .unwrap_or_default()
}

// Persist an updated password-generation policy from the TUI's settings view.
pub fn tui_save_password_gen_policy(
    policy: rbw::config::PasswordGenPolicy,
) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    config.password_gen = policy;
    config.save()?;
    Ok(())
}

// Link (or edit) an account's `credential_source` from the TUI accounts
// panel. Mirrors `account_set`'s credential_source handling but without
// printing, per the other tui_* wrappers (see `tui_account_add`).
pub fn tui_account_set_credential_source(
    name: &str,
    source_account: &str,
    source_item: Option<&str>,
) -> anyhow::Result<()> {
    if source_account.trim().is_empty() {
        anyhow::bail!("source account is required");
    }

    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    let Some(account) = config.accounts.iter_mut().find(|a| a.name == name)
    else {
        anyhow::bail!("account '{name}' not found");
    };
    account.unlock.credentials = Some(rbw::config::CredentialSource {
        account: source_account.to_string(),
        item: source_item
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToString::to_string),
    });

    // Reject a self-reference or a cycle before persisting, same guard as
    // the CLI's `account_set`.
    config.credential_source_chain(name)?;

    config.save()?;
    Ok(())
}

// Clear an account's `credential_source` link from the TUI accounts panel.
pub fn tui_account_clear_credential_source(name: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    let Some(account) = config.accounts.iter_mut().find(|a| a.name == name)
    else {
        anyhow::bail!("account '{name}' not found");
    };
    account.unlock.credentials = None;
    config.save()?;
    Ok(())
}

// Re-read the (already unlocked) vault from disk and rebuild the search index.
// Used after an edit/add/remove has synced changes back to the local db.
pub fn tui_reload(
) -> anyhow::Result<(rbw::db::Db, Vec<DecryptedSearchCipher>)> {
    let db = load_db()?;
    let mut requests = BatchRequests::new();
    let plans: Vec<SearchCipherPlan> = db
        .entries
        .iter()
        .map(|entry| SearchCipherPlan::build(entry, &mut requests))
        .collect();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };
    let search = plans
        .into_iter()
        .filter_map(|plan| match plan.resolve(&results) {
            Ok(entry) => Some(entry),
            Err(e) => {
                log::warn!("failed to decrypt entry: {e}");
                None
            }
        })
        .collect();
    Ok((db, search))
}

// Pull remote changes from the server (via the agent), then rebuild the local
// view. Used by the TUI's manual sync shortcut.
pub fn tui_sync() -> anyhow::Result<(rbw::db::Db, Vec<DecryptedSearchCipher>)>
{
    crate::actions::sync()?;
    tui_reload()
}

// Blank empty/whitespace-only folder names to `None` so clearing the folder
// field doesn't create a folder literally named "".
pub(super) fn folder_arg(folder: Option<&str>) -> Option<&str> {
    folder.map(str::trim).filter(|s| !s.is_empty())
}

// Persist an edited entry: encrypt the changed fields, preserve password
// history, resolve/create the folder, push to the server, and sync.
pub fn tui_save_edit(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    updated: &EditableCipher,
) -> anyhow::Result<()> {
    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    let (data, fields, notes) = editable_to_encrypted(
        updated,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let encrypted_name = crate::actions::encrypt(
        &updated.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| {
            crate::actions::encrypt(
                n,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose()?;

    let mut history = entry.history.clone();
    if let (
        rbw::db::EntryData::Login {
            password: Some(old_pw),
            ..
        },
        EditableData::Login {
            password: new_pw, ..
        },
    ) = (&entry.data, &updated.data)
    {
        // Compare the plaintexts: re-encrypting an unchanged password gives
        // a different ciphertext, which would add a bogus history entry.
        let old_plain = crate::actions::decrypt(
            old_pw,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?;
        if Some(&old_plain) != new_pw.as_ref() {
            history.insert(
                0,
                rbw::db::HistoryEntry {
                    last_used_date: format!(
                        "{}",
                        humantime::format_rfc3339(
                            std::time::SystemTime::now()
                        )
                    ),
                    password: old_pw.clone(),
                },
            );
        }
    }

    let folder_id =
        if let Some(folder_name) = folder_arg(updated.folder.as_deref()) {
            resolve_folder_id(db, &access_token, &refresh_token, folder_name)?
        } else {
            entry.folder_id.clone()
        };

    let (tokens, ()) = rbw::actions::edit(
        &access_token,
        &refresh_token,
        &entry.id,
        entry.org_id.as_deref(),
        entry.key.as_deref(),
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
        &history,
        &entry.cipher_write_meta(),
    )?;

    after_server_write(db, tokens)?;
    Ok(())
}

// Create a new entry from a filled-in template.
pub fn tui_save_add(
    db: &mut rbw::db::Db,
    cipher: &EditableCipher,
) -> anyhow::Result<()> {
    if cipher.name.trim().is_empty() {
        anyhow::bail!("name cannot be empty");
    }

    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    let (data, fields, notes) = editable_to_encrypted(cipher, None, None)?;
    let encrypted_name = crate::actions::encrypt(&cipher.name, None, None)?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, None, None))
        .transpose()?;

    let folder_id =
        if let Some(folder_name) = folder_arg(cipher.folder.as_deref()) {
            resolve_folder_id(db, &access_token, &refresh_token, folder_name)?
        } else {
            None
        };

    let (tokens, _) = rbw::actions::add(
        &access_token,
        &refresh_token,
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
    )?;

    after_server_write(db, tokens)?;
    Ok(())
}

// Delete an entry and sync.
pub fn tui_delete(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
) -> anyhow::Result<()> {
    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    if let (Some(tokens), ()) =
        rbw::actions::remove(&access_token, &refresh_token, &entry.id)?
    {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

// `TuiAction::ToggleArchived`'s implementation: archives the entry if it
// isn't archived, unarchives it if it is. Otherwise identical to
// `tui_delete` -- same token handling, same trailing sync.
pub fn tui_toggle_archived(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
) -> anyhow::Result<()> {
    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    let rotated = if entry.archived {
        rbw::actions::unarchive(&access_token, &refresh_token, &entry.id)?
    } else {
        rbw::actions::archive(&access_token, &refresh_token, &entry.id)?
    };
    if let (Some(tokens), ()) = rotated {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

// Open the full entry as YAML in `$EDITOR` for structured editing of every
// field (including entry-type-specific fields the inline form omits). Returns
// `true` if the entry was changed and saved. The caller is responsible for
// suspending/restoring the terminal around this call.
pub fn tui_edit_in_editor(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    decrypted: &DecryptedCipher,
) -> anyhow::Result<bool> {
    let editable = decrypted_to_editable(decrypted);
    let serialized = serde_yaml::to_string(&editable)?;
    let help = "# Edit the YAML below. Lines starting with # are ignored.";

    let interactive = std::io::stdin().is_terminal();
    let contents = rbw::edit::edit(&serialized, help, "yaml")?;
    let result = (|| {
        let contents_trimmed = contents
            .lines()
            .filter(|l| !l.starts_with('#'))
            .fold(String::new(), |mut s, l| {
                s.push_str(l);
                s.push('\n');
                s
            });

        if contents_trimmed.trim() == serialized.trim() {
            return Ok(false);
        }

        let updated: EditableCipher = serde_yaml::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?;
        tui_save_edit(db, entry, &updated)?;
        Ok(true)
    })();
    after_editor(&contents, interactive, result)
}

// Download and decrypt a single attachment (identified by id) into `dest_dir`,
// returning the path written. Mirrors `attachment_get` but operates on an
// already-loaded, already-unlocked db so the TUI can call it inline.
pub fn tui_attachment_get(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    decrypted: &DecryptedCipher,
    attachment_id: &str,
    dest_dir: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    let (attachment, decrypted_attachment) =
        find_attachment(entry, decrypted, attachment_id)?;

    let access_token = db
        .access_token
        .as_ref()
        .context("failed to find access token in db")?
        .clone();
    let refresh_token = db
        .refresh_token
        .as_ref()
        .context("failed to find refresh token in db")?
        .clone();
    let url = match rbw::actions::attachment_url(
        &access_token,
        &refresh_token,
        &entry.id,
        &attachment.id,
    ) {
        Ok((tokens, url)) => {
            if let Some(tokens) = tokens {
                db.access_token = Some(tokens.access_token);
                if let Some(refresh_token) = tokens.refresh_token {
                    db.refresh_token = Some(refresh_token);
                }
                save_db(db)?;
            }
            url
        }
        Err(e) => attachment.url.clone().ok_or(e)?,
    };
    let encrypted = rbw::actions::download_attachment(&url)
        .context("failed to download attachment")?;
    let bytes = crate::actions::decrypt_attachment(
        encrypted,
        attachment.key.as_deref(),
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;

    let file_name = decrypted_attachment
        .file_name
        .as_deref()
        .and_then(|name| std::path::Path::new(name).file_name())
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("BitwardenAttachment");
    let path = dest_dir.join(file_name);
    std::fs::write(&path, bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}
