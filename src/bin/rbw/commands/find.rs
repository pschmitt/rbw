use super::*;

pub fn find_entry(
    db: &rbw::db::Db,
    mut needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    let (collection_id, org_id) = resolve_entry_scope(db, collection, org)?;
    let in_scope = |entry: &rbw::db::Entry| {
        entry_in_collection_org_scope(
            entry,
            collection_id.as_deref(),
            org_id.as_deref(),
        )
    };

    // Fast-path: exactly one UUID needle — try exact match first. Trashed
    // entries are never a candidate for ordinary name/UUID resolution
    // (restoring one is the one exception -- see
    // `find_deleted_entry`/`find_deleted_entries_all`, `rbw restore`'s
    // dedicated trashed-only counterpart).
    if needles.len() == 1 {
        if let Needle::Uuid(uuid, s) = &needles[0] {
            let uuid = *uuid;
            for cipher in &db.entries {
                if !cipher.deleted
                    && uuid::Uuid::parse_str(&cipher.id) == Ok(uuid)
                    && in_scope(cipher)
                {
                    return Ok((cipher.clone(), decrypt_cipher(cipher)?));
                }
            }
            // UUID not found by exact match; fall through to name search
            needles = vec![Needle::Name(s.clone())];
        }
    }

    let mut requests = BatchRequests::new();
    let plans: Vec<SearchCipherPlan> = db
        .entries
        .iter()
        .filter(|entry| in_scope(entry))
        .map(|entry| SearchCipherPlan::build(entry, &mut requests))
        .collect();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };
    let mut ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .filter(|entry| in_scope(entry))
        .zip(plans)
        // A corrupt, unrelated entry elsewhere in the vault must not
        // block finding this one by name -- skip it and warn instead.
        .filter_map(|(entry, plan)| match plan.resolve(&results) {
            Ok(decrypted) => Some((entry.clone(), decrypted)),
            Err(e) => {
                log::warn!("failed to decrypt entry: {e}");
                None
            }
        })
        .collect();
    ciphers.retain(|(entry, _)| !entry.deleted);
    let (entry, _) = find_entry_raw(
        &ciphers,
        &needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )?;
    let decrypted_entry = decrypt_cipher(&entry)?;
    Ok((entry, decrypted_entry))
}

// Like `find_entry`, but resolves against every account in `target_accounts`
// (see `list_target_accounts`) instead of a single db. With one target
// account this is exactly `find_entry`. With several, every account's
// entries are pooled into one list and scored together by the same
// `find_entry_raw` logic used within a single vault — a name match in one
// account beats a weaker match in another exactly as it would within one
// vault, and genuine ties across accounts are reported as ambiguous. Returns
// the name of the account that owns the winning entry alongside it, since the
// caller needs to route the follow-up detail decrypt to the right account.
pub(super) fn find_entry_multi(
    target_accounts: &[String],
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
) -> anyhow::Result<(String, rbw::db::Entry, DecryptedCipher)> {
    let [account] = target_accounts else {
        let mut pool: Vec<(rbw::db::Entry, DecryptedSearchCipher)> =
            Vec::new();
        let mut owner: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for account in target_accounts {
            crate::actions::set_active_account(Some(account.clone()))?;
            let db = load_db()?;
            // A `--collection`/`--org` needle that doesn't resolve in this
            // particular account (name not found here, or ambiguous here)
            // just means this account contributes nothing -- it doesn't
            // abort the search across the other accounts in `--all`.
            let Ok((collection_id, org_id)) =
                resolve_entry_scope(&db, collection, org)
            else {
                continue;
            };
            let in_scope = |entry: &rbw::db::Entry| {
                entry_in_collection_org_scope(
                    entry,
                    collection_id.as_deref(),
                    org_id.as_deref(),
                )
            };
            let mut requests = BatchRequests::new();
            let plans: Vec<SearchCipherPlan> = db
                .entries
                .iter()
                .filter(|entry| in_scope(entry))
                .map(|entry| SearchCipherPlan::build(entry, &mut requests))
                .collect();
            let results = if requests.is_empty() {
                Vec::new()
            } else {
                crate::actions::decrypt_batch(requests.into_vec())?
            };
            for (entry, plan) in
                db.entries.iter().filter(|entry| in_scope(entry)).zip(plans)
            {
                // A corrupt entry in one account must not block finding
                // a different entry across the rest of `--all`'s
                // accounts -- skip it and warn instead.
                match plan.resolve(&results) {
                    Ok(decrypted) => {
                        owner.insert(entry.id.clone(), account.clone());
                        pool.push((entry.clone(), decrypted));
                    }
                    Err(e) => {
                        log::warn!("failed to decrypt entry: {e}");
                    }
                }
            }
        }
        // Trashed entries are never a candidate for ordinary name/UUID
        // resolution -- see `find_entry`'s matching exclusion.
        pool.retain(|(entry, _)| !entry.deleted);

        // Fast-path a single UUID needle, same as `find_entry`.
        let mut needles = needles;
        if let [Needle::Uuid(uuid, s)] = needles.as_slice() {
            let uuid = *uuid;
            if let Some((entry, _)) = pool
                .iter()
                .find(|(e, _)| uuid::Uuid::parse_str(&e.id) == Ok(uuid))
            {
                let entry = entry.clone();
                let account = owner[&entry.id].clone();
                crate::actions::set_active_account(Some(account.clone()))?;
                let decrypted = decrypt_cipher(&entry)?;
                return Ok((account, entry, decrypted));
            }
            needles = vec![Needle::Name(s.clone())];
        }

        // The active account is whichever was loaded last, so tell the fzf
        // preview which account owns each pooled candidate.
        set_fzf_entry_accounts(owner.clone());
        let found = find_entry_raw(
            &pool,
            &needles,
            username,
            folder,
            ignore_case,
            force_exact,
        );
        set_fzf_entry_accounts(std::collections::HashMap::new());
        let (entry, _) = found?;
        let account = owner[&entry.id].clone();
        crate::actions::set_active_account(Some(account.clone()))?;
        let decrypted = decrypt_cipher(&entry)?;
        return Ok((account, entry, decrypted));
    };

    crate::actions::set_active_account(Some(account.clone()))?;
    let db = load_db()?;
    let (entry, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )?;
    Ok((account.clone(), entry, decrypted))
}

// Resolve which attachment a command should operate on: the one matching
// `needle` when given, else the entry's only attachment. No needle with
// several attachments is an error listing what's available.
pub(super) fn resolve_attachment<'a>(
    entry: &'a rbw::db::Entry,
    decrypted: &'a DecryptedCipher,
    needle: Option<&str>,
) -> anyhow::Result<(&'a rbw::db::Attachment, &'a DecryptedAttachment)> {
    needle
        .map_or_else(
            || match entry.attachments.as_slice() {
                [] => Err(anyhow::anyhow!(
                    "no attachments available for this item"
                )),
                [attachment] => decrypted
                    .attachments
                    .first()
                    .map(|decrypted| (attachment, decrypted))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "failed to decrypt attachment metadata"
                        )
                    }),
                _ => Err(anyhow::anyhow!(
                    "attachment id or filename is required"
                )),
            },
            |needle| find_attachment(entry, decrypted, needle),
        )
        .map_err(|err| {
            available_attachments_error(
                &decrypted.name,
                &decrypted.attachments,
                &err.to_string(),
            )
        })
}

pub(super) fn find_attachment<'a>(
    entry: &'a rbw::db::Entry,
    decrypted: &'a DecryptedCipher,
    needle: &str,
) -> anyhow::Result<(&'a rbw::db::Attachment, &'a DecryptedAttachment)> {
    if entry.attachments.is_empty() {
        return Err(anyhow::anyhow!(
            "no attachments available for this item"
        ));
    }

    let needle = needle.to_lowercase();
    let mut matches: Vec<_> = entry
        .attachments
        .iter()
        .zip(&decrypted.attachments)
        .filter(|(attachment, decrypted)| {
            attachment.id.to_lowercase() == needle
                || decrypted.file_name.as_ref().is_some_and(|file_name| {
                    file_name.to_lowercase().contains(&needle)
                })
        })
        .collect();

    let exact_matches: Vec<_> = matches
        .iter()
        .copied()
        .filter(|(_, decrypted)| {
            decrypted
                .file_name
                .as_ref()
                .is_some_and(|file_name| file_name.to_lowercase() == needle)
        })
        .collect();
    if exact_matches.len() == 1 {
        matches = exact_matches;
    }

    match matches.as_slice() {
        [] => Err(anyhow::anyhow!("attachment '{needle}' was not found")),
        [(attachment, decrypted)] => Ok((*attachment, *decrypted)),
        _ => Err(anyhow::anyhow!(
            "multiple attachments found: {}",
            matches
                .iter()
                .map(|(attachment, _)| attachment.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

// `resolve_attachment`'s from-file counterpart: same only-attachment
// fallback and needle matching, but against a `DecryptedCipher`'s own
// `attachments` list (no separate `rbw::db::Entry` exists for
// `--from-file`, and none of the matching logic needs one).
pub(super) fn resolve_attachment_in_file<'a>(
    decrypted: &'a DecryptedCipher,
    needle: Option<&str>,
) -> anyhow::Result<&'a DecryptedAttachment> {
    needle
        .map_or_else(
            || match decrypted.attachments.as_slice() {
                [] => Err(anyhow::anyhow!(
                    "no attachments available for this item"
                )),
                [attachment] => Ok(attachment),
                _ => Err(anyhow::anyhow!(
                    "attachment id or filename is required"
                )),
            },
            |needle| find_attachment_in_file(decrypted, needle),
        )
        .map_err(|err| {
            available_attachments_error(
                &decrypted.name,
                &decrypted.attachments,
                &err.to_string(),
            )
        })
}

pub(super) fn find_attachment_in_file<'a>(
    decrypted: &'a DecryptedCipher,
    needle: &str,
) -> anyhow::Result<&'a DecryptedAttachment> {
    if decrypted.attachments.is_empty() {
        return Err(anyhow::anyhow!(
            "no attachments available for this item"
        ));
    }

    let needle = needle.to_lowercase();
    let mut matches: Vec<_> = decrypted
        .attachments
        .iter()
        .filter(|attachment| {
            attachment.id.to_lowercase() == needle
                || attachment.file_name.as_ref().is_some_and(|file_name| {
                    file_name.to_lowercase().contains(&needle)
                })
        })
        .collect();

    let exact_matches: Vec<_> = matches
        .iter()
        .copied()
        .filter(|attachment| {
            attachment
                .file_name
                .as_ref()
                .is_some_and(|file_name| file_name.to_lowercase() == needle)
        })
        .collect();
    if exact_matches.len() == 1 {
        matches = exact_matches;
    }

    match matches.as_slice() {
        [] => Err(anyhow::anyhow!("attachment '{needle}' was not found")),
        [attachment] => Ok(attachment),
        _ => Err(anyhow::anyhow!(
            "multiple attachments found: {}",
            matches
                .iter()
                .map(|attachment| attachment.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub(super) fn find_entry_raw(
    entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
    if needles.is_empty() {
        return Err(anyhow::anyhow!("no entry found"));
    }

    let joined = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");

    // Total relevance score for an entry, or None if it isn't a candidate
    // (fails the user/folder filter, or some needle matches nowhere). Every
    // needle must match somewhere; the score reflects the best location each
    // matched, so name hits dominate hits in hidden fields.
    let score = |d: &DecryptedSearchCipher,
                 strict_username: bool,
                 strict_folder: bool|
     -> Option<u32> {
        if !d.passes_user_folder(
            username,
            folder,
            ignore_case,
            force_exact,
            strict_username,
            strict_folder,
        ) {
            return None;
        }
        let mut total: u32 = 0;
        for needle in needles {
            total = total.saturating_add(d.match_score(
                needle,
                ignore_case,
                force_exact,
            )?);
        }
        // The whole needle string equalling the name (e.g.
        // `get private gpg key` -> "Private GPG Key") is the strongest signal.
        let name_eq_joined = if ignore_case {
            d.name.to_lowercase() == joined.to_lowercase()
        } else {
            d.name == joined
        };
        if name_eq_joined {
            total = total.saturating_add(SCORE_FULL_NAME_BONUS);
        }
        Some(total)
    };

    let mut scored: Vec<(&(rbw::db::Entry, DecryptedSearchCipher), u32)> =
        entries
            .iter()
            .filter_map(|entry| {
                score(&entry.1, false, false).map(|s| (entry, s))
            })
            .collect();

    if scored.is_empty() {
        return Err(anyhow::anyhow!("no entry found"));
    }

    let max_score = scored.iter().map(|(_, s)| *s).max().unwrap_or(0);
    scored.retain(|(_, s)| *s == max_score);

    if scored.len() == 1 {
        return Ok(scored[0].0.clone());
    }

    // Several candidates tied at the top score. If they share a name they're
    // the "same" entry across folders/users, so try to disambiguate with the
    // strict user/folder filter; differently-named ties are a real ambiguity.
    let first_name = scored[0].0 .1.name.as_str();
    if scored.iter().all(|(entry, _)| entry.1.name == first_name) {
        let narrow = |strict_username: bool, strict_folder: bool| {
            scored
                .iter()
                .filter(|(entry, _)| {
                    score(&entry.1, strict_username, strict_folder).is_some()
                })
                .map(|(entry, _)| *entry)
                .collect::<Vec<_>>()
        };

        let strict_both = narrow(true, true);
        if strict_both.len() == 1 {
            return Ok(strict_both[0].clone());
        }
        // Pick a winner only when exactly one of the stricter filters
        // resolves to a single candidate; if both do (a folder match *and* a
        // user match), it's genuinely ambiguous.
        let strict_folder = narrow(false, true);
        let strict_username = narrow(true, false);
        if strict_folder.len() == 1 && strict_username.len() != 1 {
            return Ok(strict_folder[0].clone());
        } else if strict_folder.len() != 1 && strict_username.len() == 1 {
            return Ok(strict_username[0].clone());
        }
    }

    if FZF_SELECT.load(std::sync::atomic::Ordering::Relaxed) {
        let candidates: Vec<&DecryptedSearchCipher> =
            scored.iter().map(|(entry, _)| &entry.1).collect();
        let id = fzf_select(&candidates)?;
        if let Some((entry, _)) =
            scored.iter().find(|(entry, _)| entry.1.id == id)
        {
            return Ok((*entry).clone());
        }
        anyhow::bail!("fzf returned an unknown entry {id:?}");
    }

    // This error is printed to stderr (wrapped in red by `style_error`), so
    // colour based on stderr. The leading reset stops the outer red from
    // bleeding into the per-field styling of the entry list.
    let c = stderr_supports_color();
    let reset = if c { "\x1b[0m" } else { "" };
    let entries_str: Vec<String> = scored
        .iter()
        .map(|(entry, _)| format_ambiguous_entry(&entry.1, c))
        .collect();
    let hint = format!(
        "Try `rbw list {joined}` to inspect the matches, or add --user/--folder to disambiguate."
    );
    Err(anyhow::anyhow!(
        "multiple entries found:{reset}\n{}\n\n{}",
        entries_str.join("\n"),
        style::dim(&hint, c),
    ))
}

// `--fzf` on the find-family commands (or `fzf.enabled`): when a lookup is
// ambiguous, pick the entry with fzf instead of failing. Set once from the
// parsed command line, see `set_fzf_select`.
pub(super) static FZF_SELECT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_fzf_select(enabled: bool) {
    FZF_SELECT.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

// Entry id -> owning account for candidates pooled from several accounts
// (`find_entry_multi`), so each fzf preview targets the right account rather
// than the active one. Empty outside such a lookup.
pub(super) static FZF_ENTRY_ACCOUNTS: std::sync::Mutex<
    Option<std::collections::HashMap<String, String>>,
> = std::sync::Mutex::new(None);

pub(super) fn set_fzf_entry_accounts(
    accounts: std::collections::HashMap<String, String>,
) {
    *FZF_ENTRY_ACCOUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(accounts).filter(|accounts| !accounts.is_empty());
}

// The account the fzf preview should look `id` up in: its owner when
// pooled from several accounts, else the active account.
pub(super) fn fzf_entry_account(id: &str) -> Option<String> {
    FZF_ENTRY_ACCOUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|accounts| accounts.get(id).cloned())
        .or_else(crate::actions::current_account)
}

// One tab-separated fzf line per candidate: the id (hidden, used for the
// preview and to read the selection back), the owning account (hidden, for
// the preview), then what's shown.
pub(super) fn fzf_candidate_line(
    entry: &DecryptedSearchCipher,
    account: Option<&str>,
) -> String {
    let clean = |s: &str| s.replace(['\t', '\n', '\r'], " ");
    [
        clean(&entry.id),
        clean(account.unwrap_or("")),
        clean(&entry.name),
        clean(entry.user.as_deref().unwrap_or("")),
        clean(entry.folder.as_deref().unwrap_or("")),
    ]
    .join("\t")
}

// Single-quotes `s` for a POSIX shell (fzf runs the preview through one,
// and parses FZF_DEFAULT_OPTS with the same quoting rules).
pub(super) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

// FZF_DEFAULT_OPTS for the picker: the user's own defaults, then rbw's
// (overridable) ones, then RBW_FZF_OPTS or `fzf.options`. fzf applies them
// in order, so later options win.
pub(super) fn fzf_default_opts(
    existing: Option<&str>,
    custom: Option<&str>,
) -> String {
    [
        existing.unwrap_or(""),
        "--select-1 --header='Multiple entries match; pick one'",
        custom.unwrap_or(""),
    ]
    .iter()
    .filter(|part| !part.trim().is_empty())
    .copied()
    .collect::<Vec<_>>()
    .join(" ")
}

pub(super) fn fzf_custom_opts() -> Option<String> {
    std::env::var("RBW_FZF_OPTS").ok().or_else(|| {
        rbw::config::Config::load()
            .ok()
            .and_then(|config| config.fzf.options)
    })
}

pub(super) fn fzf_select(
    candidates: &[&DecryptedSearchCipher],
) -> anyhow::Result<String> {
    use std::io::Write as _;

    let exe = std::env::current_exe()
        .context("failed to find the rbw executable for the fzf preview")?;
    let accounts: Vec<Option<String>> = candidates
        .iter()
        .map(|entry| fzf_entry_account(&entry.id))
        .collect();
    let mut preview = format!(
        "CLICOLOR_FORCE=1 {}",
        shell_quote(&exe.display().to_string())
    );
    if accounts.iter().any(Option::is_some) {
        preview.push_str(" -a {2}");
    }
    preview.push_str(" show --mask {1}");

    let default_opts = fzf_default_opts(
        std::env::var("FZF_DEFAULT_OPTS").ok().as_deref(),
        fzf_custom_opts().as_deref(),
    );
    let mut child = std::process::Command::new("fzf")
        .args(["--delimiter=\t", "--with-nth=3..", "--preview", &preview])
        .env("FZF_DEFAULT_OPTS", default_opts)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("--fzf needs fzf, which isn't in PATH")
            } else {
                anyhow::Error::from(e).context("failed to start fzf")
            }
        })?;
    {
        let mut stdin = child.stdin.take().context("fzf has no stdin")?;
        for (entry, account) in candidates.iter().zip(&accounts) {
            writeln!(
                stdin,
                "{}",
                fzf_candidate_line(entry, account.as_deref())
            )
            .context("failed to write to fzf")?;
        }
    }
    let output =
        child.wait_with_output().context("failed to wait for fzf")?;
    match output.status.code() {
        Some(0) => {}
        Some(1) => anyhow::bail!("no entry selected in fzf"),
        Some(130) => anyhow::bail!("fzf selection cancelled"),
        _ => anyhow::bail!(
            "fzf failed ({}); --fzf needs a terminal",
            output.status
        ),
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .and_then(|line| line.split('\t').next())
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .context("fzf returned no selection")
}

// `find_entry`'s `--from-file` counterpart: same matching
// (`find_entry_raw`), against a `--from-file` vault's already-decrypted
// entries instead of a live account's cipherstring `Db`. Builds the same
// `(rbw::db::Entry, DecryptedSearchCipher)` pairs `find_entry` builds via
// the agent (`placeholder_entry`/`decrypted_cipher_to_search` -- no agent
// involved here, both are already in memory), then looks the winning id
// back up in `entries` for the real (non-placeholder) result.
pub(super) fn find_entry_in_file(
    entries: &[DecryptedCipher],
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
) -> anyhow::Result<DecryptedCipher> {
    let pairs: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = entries
        .iter()
        .map(|entry| {
            (
                placeholder_entry(entry.id.clone()),
                decrypted_cipher_to_search(entry),
            )
        })
        .collect();
    let (matched, _) = find_entry_raw(
        &pairs,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )?;
    entries
        .iter()
        .find(|entry| entry.id == matched.id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("entry no longer exists"))
}

pub(super) fn decrypt_field(
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> Option<String> {
    decrypt_field_with_attachment_key(name, field, entry_key, org_id, None)
}

// Like `decrypt_field`, but for a field wrapped in an attachment's own key
// (e.g. an attachment file name) rather than directly in the entry's key.
pub(super) fn decrypt_field_with_attachment_key(
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    attachment_key: Option<&str>,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| {
            crate::actions::decrypt_with_attachment_key(
                field,
                entry_key,
                org_id,
                attachment_key,
            )
        })
        .transpose();
    match field {
        Ok(field) => field,
        Err(e) => {
            log::warn!("failed to decrypt {name}: {e}");
            None
        }
    }
}
