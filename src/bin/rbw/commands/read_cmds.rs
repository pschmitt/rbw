use super::*;

// `list --from-file`: no term to filter by (a term routes through
// `search_from_file` instead -- see `Opt::List`'s dispatch in main.rs), so
// the only filtering here is `with_attachments`.
pub(super) fn list_from_file(
    path: &std::path::Path,
    fields: &[String],
    with_attachments: bool,
    insecure: bool,
    output: OutputMode,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;
    let mut entries = vault.entries;
    if with_attachments {
        entries.retain(|entry| entry.attachment_metadata.has_attachments());
    }

    if output_is_structured(output) {
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        return write_serialized_pretty(
            &entries,
            output,
            "failed to write entries to stdout",
        );
    }

    let mut fields: Vec<ListField> = fields
        .iter()
        .map(std::convert::TryFrom::try_from)
        .collect::<anyhow::Result<_>>()?;
    if insecure && !fields.contains(&ListField::Password) {
        let insert_pos = fields
            .iter()
            .position(|f| matches!(f, ListField::User))
            .map_or(fields.len(), |i| i + 1);
        fields.insert(insert_pos, ListField::Password);
    }

    let mut entries: Vec<DecryptedListCipher> = entries
        .iter()
        .map(decrypted_cipher_to_search)
        .map(std::convert::Into::into)
        .collect();
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, output, "")?;

    Ok(())
}

// Bitwarden/Vaultwarden send .NET-style RFC 3339 timestamps (up to 7
// fractional digits, `Z` suffix), which humantime's weak parser accepts.
pub(super) fn parse_revision_date(
    date: &str,
) -> anyhow::Result<std::time::SystemTime> {
    humantime::parse_rfc3339_weak(date.trim_end_matches('Z'))
        .with_context(|| format!("invalid revision date '{date}'"))
}

// `rbw list --fields modified`: just the (UTC) day; the full timestamp is
// in the structured output.
pub(super) fn format_revision_date(date: &str) -> String {
    date.get(..10).unwrap_or(date).to_string()
}

pub(super) fn warn_undated_entries(undated: usize) {
    if undated > 0 {
        eprintln!(
            "note: skipped {undated} {} without a revision date (synced by an \
             older rbw); run `rbw sync` to fetch them",
            if undated == 1 { "entry" } else { "entries" }
        );
    }
}

pub fn list(
    fields: &[String],
    with_attachments: bool,
    insecure: bool,
    collection: Option<&str>,
    org: Option<&str>,
    output: OutputMode,
    all: bool,
    archived_filter: ArchivedFilter,
    trash_filter: TrashFilter,
    older_than: Option<std::time::Duration>,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let cutoff = older_than
        .map(|age| {
            std::time::SystemTime::now()
                .checked_sub(age)
                .ok_or_else(|| anyhow::anyhow!("--older-than is too large"))
        })
        .transpose()?;
    let mut undated = 0_usize;
    let mut modified_before = |entry: &rbw::db::Entry| {
        let Some(cutoff) = cutoff else {
            return true;
        };
        match entry.revision_date.as_deref().map(parse_revision_date) {
            Some(Ok(modified)) => modified < cutoff,
            Some(Err(e)) => {
                log::warn!("unparseable revision date on {}: {e}", entry.id);
                false
            }
            None => {
                undated += 1;
                false
            }
        }
    };

    if let Some(path) = from_file {
        return list_from_file(
            path,
            fields,
            with_attachments,
            insecure,
            output,
            from_file_passphrase,
        );
    }

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::List, true)?;
    let tag_account = target_accounts.len() > 1;

    // Structured output (`--json`/`--yaml`) always emits the *full* decrypted
    // entry — same shape as `rbw get --json`: password, custom fields with
    // values, notes, totp, uris, etc. This lets consumers retrieve everything
    // in a single call instead of following up with `rbw get`.
    if output_is_structured(output) {
        let mut entries: Vec<DecryptedCipher> = Vec::new();
        for account in &target_accounts {
            crate::actions::set_active_account(Some(account.clone()))?;
            let db = load_db()?;
            // Same as `find_entry_multi`'s `--all` loop: a `--collection`/
            // `--org` needle that doesn't resolve in this particular
            // account just means it contributes nothing.
            let Ok((collection_id, org_id)) =
                resolve_entry_scope(&db, collection, org)
            else {
                continue;
            };
            let mut account_entries: Vec<DecryptedCipher> = db
                .entries
                .iter()
                .filter(|entry| {
                    entry_in_collection_org_scope(
                        entry,
                        collection_id.as_deref(),
                        org_id.as_deref(),
                    )
                })
                .filter(|entry| modified_before(entry))
                // One corrupt entry must not fail listing the rest of the
                // vault -- skip it and warn instead.
                .filter_map(|entry| match decrypt_cipher(entry) {
                    Ok(decrypted) => Some(decrypted),
                    Err(e) => {
                        log::warn!("failed to decrypt entry: {e}");
                        None
                    }
                })
                .collect();
            if tag_account {
                for entry in &mut account_entries {
                    entry.account = Some(account.clone());
                }
            }
            entries.extend(account_entries);
        }
        if with_attachments {
            entries
                .retain(|entry| entry.attachment_metadata.has_attachments());
        }
        entries.retain(|entry| archived_filter.matches(entry.archived));
        entries.retain(|entry| trash_filter.matches(entry.deleted));
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        warn_undated_entries(undated);
        return write_serialized_pretty(
            &entries,
            output,
            "failed to write entries to stdout",
        );
    }

    let mut fields: Vec<ListField> = fields
        .iter()
        .map(std::convert::TryFrom::try_from)
        .collect::<anyhow::Result<_>>()?;
    if insecure && !fields.contains(&ListField::Password) {
        // Insert password after user (or at position 2 if user column present)
        let insert_pos = fields
            .iter()
            .position(|f| matches!(f, ListField::User))
            .map_or(fields.len(), |i| i + 1);
        fields.insert(insert_pos, ListField::Password);
    }

    let mut entries: Vec<DecryptedListCipher> = Vec::new();
    for account in &target_accounts {
        crate::actions::set_active_account(Some(account.clone()))?;
        let db = load_db()?;
        let Ok((collection_id, org_id)) =
            resolve_entry_scope(&db, collection, org)
        else {
            continue;
        };

        // Gather every cipherstring that needs decrypting across all entries,
        // then decrypt them in a single batch request to the agent. This
        // avoids a separate socket round-trip per field per entry, which
        // dominates the runtime of `list` on large vaults.
        let mut requests = BatchRequests::new();
        let plans: Vec<ListCipherPlan> = db
            .entries
            .iter()
            .filter(|entry| {
                entry_in_collection_org_scope(
                    entry,
                    collection_id.as_deref(),
                    org_id.as_deref(),
                )
            })
            .filter(|entry| modified_before(entry))
            .map(|entry| ListCipherPlan::build(entry, &fields, &mut requests))
            .collect();

        let results = if requests.is_empty() {
            Vec::new()
        } else {
            crate::actions::decrypt_batch(requests.into_vec())?
        };

        let mut account_entries: Vec<DecryptedListCipher> = plans
            .into_iter()
            .filter_map(|plan| match plan.resolve(&results) {
                Ok(entry) => Some(entry),
                Err(e) => {
                    log::warn!("failed to decrypt entry: {e}");
                    None
                }
            })
            .collect();
        if tag_account {
            for entry in &mut account_entries {
                entry.account = Some(account.clone());
            }
        }
        entries.extend(account_entries);
    }
    if with_attachments {
        entries.retain(|entry| entry.attachment_metadata.has_attachments());
    }
    entries.retain(|entry| archived_filter.matches(entry.archived));
    entries.retain(|entry| trash_filter.matches(entry.deleted));
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    warn_undated_entries(undated);
    print_entry_list(&entries, &fields, output, "")?;

    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
#[allow(clippy::too_many_arguments)]
// `get --from-file`: same needle matching/display shape as the
// live-account path below (`DecryptedCipher` carries the same display
// methods either way), against an already-decrypted in-memory vault
// instead of an unlocked agent/account.
pub(super) fn get_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    field: Option<&str>,
    output: OutputMode,
    clipboard: bool,
    ignore_case: bool,
    list_fields: bool,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if list_fields {
        decrypted.display_fields_list();
    } else if output_is_structured(output) {
        decrypted.display_structured(&desc, output)?;
    } else if output == OutputMode::Name {
        println!("{}", decrypted.name);
    } else if let Some(field) = field {
        decrypted.display_field(&desc, field, clipboard);
    } else {
        decrypted.display_short(&desc, clipboard);
    }

    Ok(())
}

// Resolve a bare `rbw get NAME` against a configured item alias (see
// `rbw::config::ItemAlias`). Only fires when there's exactly one needle and
// none of --user/--folder/--collection/--org are already set -- any of
// those being present means the caller is doing an explicit search, not
// invoking a shortcut, so the alias is left alone. Returns the alias name
// alongside its config when `needles` matches one; `None` otherwise (no
// alias by that name, or the trigger conditions aren't met).
pub(super) fn resolve_get_alias<'a>(
    config: &'a rbw::config::Config,
    needles: &[Needle],
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
) -> Option<(&'a str, &'a rbw::config::ItemAlias)> {
    let [Needle::Name(name)] = needles else {
        return None;
    };
    if user.is_some()
        || folder.is_some()
        || collection.is_some()
        || org.is_some()
    {
        return None;
    }
    let alias = config.find_alias(name)?;
    // `find_alias` only returns an entry whose `alias` list contains `name`,
    // so this is always present; borrowing it from `alias` (rather than
    // `name`, which only lives as long as `needles`) is what lets the
    // returned tuple satisfy the `'a` lifetime.
    let matched_name = alias
        .alias
        .iter()
        .find(|n| n.as_str() == name)
        .expect("find_alias guarantees a matching name")
        .as_str();
    Some((matched_name, alias))
}

#[allow(clippy::too_many_arguments)]
pub fn get(
    mut needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    field: Option<&str>,
    output: OutputMode,
    clipboard: bool,
    ignore_case: bool,
    list_fields: bool,
    verbose: bool,
    force_exact: bool,
    all: bool,
    no_alias: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return get_from_file(
            path,
            &needles,
            user,
            folder,
            field,
            output,
            clipboard,
            ignore_case,
            list_fields,
            force_exact,
            from_file_passphrase,
        );
    }

    let mut collection = collection.map(str::to_string);
    let mut org = org.map(str::to_string);
    let mut field = field.map(str::to_string);

    if !no_alias {
        let config = rbw::config::Config::load()?;
        if let Some((alias_name, alias)) = resolve_get_alias(
            &config,
            &needles,
            user,
            folder,
            collection.as_deref(),
            org.as_deref(),
        ) {
            let account = crate::actions::current_account()
                .unwrap_or_else(|| alias.account_name(&config));
            if verbose {
                let c = std::io::stderr().is_terminal()
                    && std::env::var_os("NO_COLOR").is_none();
                let field_suffix = alias
                    .field
                    .as_deref()
                    .map(|f| format!(", field '{f}'"))
                    .unwrap_or_default();
                eprintln!(
                    "{}",
                    style::dim(
                        &format!(
                            "Resolved alias '{alias_name}' -> account \
                            '{account}', item '{}'{field_suffix}",
                            alias.item,
                        ),
                        c,
                    )
                );
            }
            if crate::actions::current_account().is_none() {
                crate::actions::set_account(Some(account));
            }
            needles = vec![parse_needle(&alias.item).unwrap()];
            collection = alias.collection.clone();
            org = alias.org.clone();
            if field.is_none() {
                field.clone_from(&alias.field);
            }
        }
    }

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Get, true)?;
    let tag_account = target_accounts.len() > 1;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (account, _, decrypted) = find_entry_multi(
        &target_accounts,
        needles,
        user,
        folder,
        collection.as_deref(),
        org.as_deref(),
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if verbose {
        let c = std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        // Note which field the value is coming from — useful now that a plain
        // `get` may fall back to a passphrase field, notes, etc.
        let source = if list_fields || output_is_structured(output) {
            None
        } else if let Some(field) = &field {
            Some(format!("field '{field}'"))
        } else {
            decrypted.default_secret().map(|(_, src)| src.label())
        };
        let account_suffix = if tag_account {
            format!(" [{account}]")
        } else {
            String::new()
        };
        let suffix = source
            .map(|s| format!(" {}", style::dim(&format!("({s})"), c)))
            .unwrap_or_default();
        eprintln!(
            "Matched item: {}{account_suffix}{suffix}",
            style::name(&decrypted.name, c),
        );
    }

    if list_fields {
        decrypted.display_fields_list();
    } else if output_is_structured(output) {
        decrypted.display_structured(&desc, output)?;
    } else if output == OutputMode::Name {
        println!("{}", decrypted.name);
    } else if let Some(field) = &field {
        decrypted.display_field(&desc, field, clipboard);
    } else {
        decrypted.display_short(&desc, clipboard);
    }

    Ok(())
}

// `show --from-file`: mirrors `get_from_file` but always uses
// `display_show`/`display_structured` (no field/clipboard support, matching
// the live-account `show` command's own limited output shape).
pub(super) fn show_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
    force_exact: bool,
    passphrase: Option<&str>,
    mask: bool,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if output_is_structured(output) {
        decrypted.display_structured(&desc, output)?;
    } else if output == OutputMode::Name {
        println!("{}", decrypted.name);
    } else {
        decrypted.display_show(mask);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn show(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
    force_exact: bool,
    all: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
    mask: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !mask || !output_is_structured(output),
        "--mask only applies to the default text output"
    );
    if let Some(path) = from_file {
        return show_from_file(
            path,
            &needles,
            user,
            folder,
            ignore_case,
            output,
            force_exact,
            from_file_passphrase,
            mask,
        );
    }

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Show, true)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );
    let (_, _, decrypted) = find_entry_multi(
        &target_accounts,
        needles,
        user,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    if output_is_structured(output) {
        decrypted.display_structured(&desc, output)?;
    } else if output == OutputMode::Name {
        println!("{}", decrypted.name);
    } else {
        decrypted.display_show(mask);
    }
    Ok(())
}
