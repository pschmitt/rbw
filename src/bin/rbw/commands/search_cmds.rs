use super::*;

pub(super) fn print_entry_list(
    entries: &[DecryptedListCipher],
    fields: &[ListField],
    output: OutputMode,
    term: &str,
) -> anyhow::Result<()> {
    if output_is_structured(output) {
        write_serialized_pretty(
            &entries,
            output,
            "failed to write entries to stdout",
        )?;
    } else if output == OutputMode::Name {
        for entry in entries {
            println!("{}", entry.name.clone().unwrap_or_default());
        }
    } else {
        let mut columns = fields
            .iter()
            .map(|field| match field {
                ListField::Id => TableColumn {
                    header: "uid",
                    style: TableColumnStyle::Id,
                },
                ListField::Name => TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
                ListField::User => TableColumn {
                    header: "user",
                    style: TableColumnStyle::User,
                },
                ListField::Folder => TableColumn {
                    header: "folder",
                    style: TableColumnStyle::Folder,
                },
                ListField::Uri => TableColumn {
                    header: "uri",
                    style: TableColumnStyle::Default,
                },
                ListField::EntryType => TableColumn {
                    header: "type",
                    style: TableColumnStyle::EntryType,
                },
                ListField::Collections => TableColumn {
                    header: "collections",
                    style: TableColumnStyle::Collections,
                },
                ListField::Modified => TableColumn {
                    header: "modified",
                    style: TableColumnStyle::Default,
                },
                ListField::Password => TableColumn {
                    header: "password",
                    style: TableColumnStyle::Password,
                },
            })
            .collect::<Vec<_>>();
        let show_account = entries.iter().any(|e| e.account.is_some());
        if show_account {
            columns.push(TableColumn {
                header: "account",
                style: TableColumnStyle::Account,
            });
        }
        let show_attachments = entries
            .iter()
            .any(|e| e.attachment_metadata.has_attachments());
        if show_attachments {
            columns.push(TableColumn {
                header: "attachments",
                style: TableColumnStyle::Attachments,
            });
        }

        let rows = entries
            .iter()
            .map(|entry| {
                let mut values = fields
                    .iter()
                    .map(|field| match field {
                        ListField::Id => entry.id.clone(),
                        ListField::Name => entry.name.as_ref().map_or_else(
                            String::new,
                            std::string::ToString::to_string,
                        ),
                        ListField::User => entry.user.as_ref().map_or_else(
                            || "N/A".to_string(),
                            std::string::ToString::to_string,
                        ),
                        ListField::Folder => {
                            entry.folder.as_ref().map_or_else(
                                String::new,
                                std::string::ToString::to_string,
                            )
                        }
                        ListField::Uri => unreachable!(),
                        ListField::EntryType => {
                            entry.entry_type.as_ref().map_or_else(
                                String::new,
                                std::string::ToString::to_string,
                            )
                        }
                        ListField::Collections => entry
                            .collection_ids
                            .as_ref()
                            .map_or_else(String::new, |ids| ids.join(",")),
                        ListField::Modified => entry
                            .revision_date
                            .as_deref()
                            .map_or_else(String::new, format_revision_date),
                        ListField::Password => {
                            entry.password.as_ref().map_or_else(
                                String::new,
                                std::string::ToString::to_string,
                            )
                        }
                    })
                    .collect::<Vec<_>>();
                if show_account {
                    values.push(entry.account.clone().unwrap_or_default());
                }
                if show_attachments {
                    values.push(attachments_cell(
                        entry.attachment_metadata.attachment_count,
                    ));
                }
                values
            })
            .collect::<Vec<_>>();

        print_table(&columns, &rows, term)?;
    }

    Ok(())
}

// `search --from-file`: same matching/output shape as the live-account
// path below, just sourced from an already-decrypted in-memory vault.
pub(super) fn search_from_file(
    path: &std::path::Path,
    term: &str,
    fields: &[String],
    folder: Option<&str>,
    with_attachments: bool,
    insecure: bool,
    output: OutputMode,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;
    let scope_target = FileSaveTarget {
        path: path.to_path_buf(),
        passphrase: vault.passphrase.clone(),
        collections: vault.collections.clone(),
        entry_extra: vault.entry_extra.clone(),
    };

    if output_is_structured(output) {
        let mut entries: Vec<DecryptedCipher> = vault
            .entries
            .into_iter()
            .filter(|entry| {
                let scope = tui_file_entry_scope(&scope_target, &entry.id);
                decrypted_cipher_to_search(entry).search_match_with_scope(
                    term,
                    folder,
                    with_attachments,
                    Some(&scope),
                )
            })
            .collect();
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        if entries.is_empty() {
            let c = std::io::stderr().is_terminal()
                && std::env::var_os("NO_COLOR").is_none();
            let msg = format!("no entries found matching '{term}'");
            eprintln!("{}", style::warning(&msg, c));
            std::process::exit(1);
        }
        if redact_enabled() {
            entries = entries.iter().map(DecryptedCipher::redacted).collect();
        }
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
    if insecure {
        deny_if_redacted("`--insecure`")?;
    }
    if insecure && !fields.contains(&ListField::Password) {
        let insert_pos = fields
            .iter()
            .position(|f| matches!(f, ListField::User))
            .map_or(fields.len(), |i| i + 1);
        fields.insert(insert_pos, ListField::Password);
    }

    let mut entries: Vec<DecryptedListCipher> = vault
        .entries
        .iter()
        .filter_map(|entry| {
            let scope = tui_file_entry_scope(&scope_target, &entry.id);
            let searchable = decrypted_cipher_to_search(entry);
            searchable
                .search_match_with_scope(
                    term,
                    folder,
                    with_attachments,
                    Some(&scope),
                )
                .then_some(searchable)
        })
        .map(std::convert::Into::into)
        .collect();
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    if entries.is_empty() {
        let c = std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        let msg = format!("no entries found matching '{term}'");
        eprintln!("{}", style::warning(&msg, c));
        std::process::exit(1);
    }

    print_entry_list(&entries, &fields, output, term)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn search(
    term: &str,
    fields: &[String],
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    with_attachments: bool,
    insecure: bool,
    output: OutputMode,
    all: bool,
    archived_filter: ArchivedFilter,
    trash_filter: TrashFilter,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return search_from_file(
            path,
            term,
            fields,
            folder,
            with_attachments,
            insecure,
            output,
            from_file_passphrase,
        );
    }

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Search, true)?;
    let tag_account = target_accounts.len() > 1;

    // Structured output (`--json`/`--yaml`) emits the *full* decrypted entry
    // (same shape as `rbw get --json`) for every match, so consumers get
    // everything in one call. Matching still uses the lightweight searchable
    // view; only the matching entries are fully decrypted.
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
                .filter_map(|entry| match decrypt_search_cipher(entry) {
                    Ok(searchable) => {
                        let scope = tui_entry_scope(&db, entry);
                        (searchable.search_match_with_scope(
                            term,
                            folder,
                            with_attachments,
                            Some(&scope),
                        ) && archived_filter.matches(searchable.archived)
                            && trash_filter.matches(searchable.deleted))
                        .then(|| decrypt_cipher(entry).ok())
                        .flatten()
                    }
                    Err(_) => None,
                })
                .collect();
            if tag_account {
                for entry in &mut account_entries {
                    entry.account = Some(account.clone());
                }
            }
            entries.extend(account_entries);
        }
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        if entries.is_empty() {
            let c = std::io::stderr().is_terminal()
                && std::env::var_os("NO_COLOR").is_none();
            let msg = format!("no entries found matching '{term}'");
            eprintln!("{}", style::warning(&msg, c));
            std::process::exit(1);
        }
        if redact_enabled() {
            entries = entries.iter().map(DecryptedCipher::redacted).collect();
        }
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
    if insecure {
        deny_if_redacted("`--insecure`")?;
    }
    if insecure && !fields.contains(&ListField::Password) {
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

        // As in `list`, decrypt every entry's searchable fields in a single
        // batch request rather than one socket round-trip per field per
        // entry.
        let mut requests = BatchRequests::new();
        let plans: Vec<(TuiEntryScope, SearchCipherPlan)> = db
            .entries
            .iter()
            .filter(|entry| {
                entry_in_collection_org_scope(
                    entry,
                    collection_id.as_deref(),
                    org_id.as_deref(),
                )
            })
            .map(|entry| {
                (
                    tui_entry_scope(&db, entry),
                    SearchCipherPlan::build(entry, &mut requests),
                )
            })
            .collect();

        let results = if requests.is_empty() {
            Vec::new()
        } else {
            crate::actions::decrypt_batch(requests.into_vec())?
        };

        let mut account_entries: Vec<DecryptedListCipher> = plans
            .into_iter()
            .filter_map(|(scope, plan)| match plan.resolve(&results) {
                Ok(entry) => {
                    let matches = entry.search_match_with_scope(
                        term,
                        folder,
                        with_attachments,
                        Some(&scope),
                    ) && archived_filter
                        .matches(entry.archived)
                        && trash_filter.matches(entry.deleted);
                    matches.then(|| entry.into())
                }
                // One entry's ciphertext being corrupt (individually-keyed
                // entries edited by the now-fixed `set`/`edit` bug, or
                // any other bad data) must not take the rest of the vault
                // down with it -- skip it and keep searching.
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
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    if entries.is_empty() {
        let c = std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        let msg = format!("no entries found matching '{term}'");
        eprintln!("{}", style::warning(&msg, c));
        std::process::exit(1);
    }

    print_entry_list(&entries, &fields, output, term)?;

    Ok(())
}

// `code --from-file`: same TOTP-generation logic as the live-account path,
// against a `DecryptedCipher` found in-memory instead of via an unlocked
// account.
pub(super) fn code_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    clipboard: bool,
    ignore_case: bool,
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

    if let DecryptedData::Login { totp, .. } = decrypted.data {
        if let Some(totp) = totp {
            val_display_or_store(clipboard, &generate_totp(&totp)?);
        } else {
            return Err(anyhow::anyhow!(
                "entry does not contain a totp secret"
            ));
        }
    } else {
        return Err(anyhow::anyhow!("not a login entry"));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn code(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    clipboard: bool,
    ignore_case: bool,
    force_exact: bool,
    all: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return code_from_file(
            path,
            &needles,
            user,
            folder,
            clipboard,
            ignore_case,
            force_exact,
            from_file_passphrase,
        );
    }

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Code, true)?;

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

    if let DecryptedData::Login { totp, .. } = decrypted.data {
        if let Some(totp) = totp {
            val_display_or_store(clipboard, &generate_totp(&totp)?);
        } else {
            return Err(anyhow::anyhow!(
                "entry does not contain a totp secret"
            ));
        }
    } else {
        return Err(anyhow::anyhow!("not a login entry"));
    }

    Ok(())
}

/// One login found by `search --url`: what it is, never a secret.
#[derive(Debug, serde::Serialize)]
struct UrlMatch {
    id: String,
    name: String,
    user: Option<String>,
    folder: Option<String>,
    uris: Vec<String>,
    /// Saved for the URL, by rbw's URI matching.
    site: bool,
    has_password: bool,
    has_totp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<String>,
}

/// `search --url`: the logins saved for `url`, by rbw's URI matching (the
/// browser extension's), or with a `term` every login whose name, user,
/// folder or URIs contain each of its words, those for `url` first. Like the
/// extension's search it never looks at notes, custom fields or secrets, and
/// its structured output carries metadata only (URIs, and whether there is a
/// password or a TOTP), so it can answer a web page's search box.
pub fn search_url(
    term: &str,
    url: &str,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    output: OutputMode,
    all: bool,
    archived_filter: ArchivedFilter,
    trash_filter: TrashFilter,
) -> anyhow::Result<()> {
    let url = url::Url::parse(url).context("invalid --url")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "--url must be an http or https URL"
    );
    let default = rbw::config::Config::load()
        .map(|config| config.default_uri_match)
        .unwrap_or_default();
    let words: Vec<String> = term
        .to_lowercase()
        .split_whitespace()
        .map(str::to_owned)
        .collect();

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Search, true)?;
    let tag_account = target_accounts.len() > 1;
    let mut found: Vec<UrlMatch> = Vec::new();
    for account in &target_accounts {
        crate::actions::set_active_account(Some(account.clone()))?;
        let db = load_db()?;
        let Ok((collection_id, org_id)) =
            resolve_entry_scope(&db, collection, org)
        else {
            continue;
        };
        // One batch for the whole vault: names, users, folders and URIs.
        let mut requests = BatchRequests::new();
        let plans: Vec<_> = db
            .entries
            .iter()
            .filter(|entry| {
                archived_filter.matches(entry.archived)
                    && trash_filter.matches(entry.deleted)
                    && entry_in_collection_org_scope(
                        entry,
                        collection_id.as_deref(),
                        org_id.as_deref(),
                    )
            })
            .filter_map(|entry| {
                let rbw::db::EntryData::Login { username, uris, .. } =
                    &entry.data
                else {
                    return None;
                };
                let key = entry.key.as_deref();
                let org = entry.org_id.as_deref();
                Some((
                    entry,
                    requests.push(&entry.name, key, org),
                    username.as_ref().map(|u| requests.push(u, key, org)),
                    // Folders are the user's own: decrypted with the local key.
                    entry
                        .folder
                        .as_ref()
                        .map(|f| requests.push(f, None, None)),
                    uris.iter()
                        .map(|u| {
                            (requests.push(&u.uri, key, org), u.match_type)
                        })
                        .collect::<Vec<_>>(),
                ))
            })
            .collect();
        let results = if requests.is_empty() {
            Vec::new()
        } else {
            crate::actions::decrypt_batch(requests.into_vec())?
        };
        for (entry, name, user, folder_index, uris) in plans {
            let Ok(name) = strict_result(&results[name]) else {
                log::warn!("failed to decrypt entry {}", entry.id);
                continue;
            };
            let user = user
                .and_then(|i| lenient_result(&results[i], Field::Username));
            let entry_folder = folder_index
                .map(|i| strict_result(&results[i]))
                .transpose()
                .ok()
                .flatten();
            if folder.is_some_and(|f| entry_folder.as_deref() != Some(f)) {
                continue;
            }
            let uris: Vec<(String, Option<rbw::api::UriMatchType>)> = uris
                .into_iter()
                .filter_map(|(i, match_type)| {
                    Some((
                        lenient_result(&results[i], Field::Uris)?,
                        match_type,
                    ))
                })
                .collect();
            let site = uris.iter().any(|(value, match_type)| {
                !skip_insecure_uri(&url, value)
                    && matches_url(value, *match_type, &url, default)
            });
            let wanted = if words.is_empty() {
                site
            } else {
                let haystack = [
                    name.as_str(),
                    user.as_deref().unwrap_or_default(),
                    entry_folder.as_deref().unwrap_or_default(),
                ]
                .into_iter()
                .chain(uris.iter().map(|(value, _)| value.as_str()))
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
                words.iter().all(|word| haystack.contains(word.as_str()))
            };
            if !wanted {
                continue;
            }
            let rbw::db::EntryData::Login { password, totp, .. } =
                &entry.data
            else {
                continue;
            };
            found.push(UrlMatch {
                id: entry.id.clone(),
                name,
                user,
                folder: entry_folder,
                uris: uris.into_iter().map(|(value, _)| value).collect(),
                site,
                has_password: password.is_some(),
                has_totp: totp.is_some(),
                account: tag_account.then(|| account.clone()),
            });
        }
    }
    found.sort_by_cached_key(|m| (!m.site, m.name.to_lowercase()));

    if found.is_empty() {
        let c = std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        let msg = if term.trim().is_empty() {
            format!("no entries found for '{url}'")
        } else {
            format!("no entries found matching '{term}'")
        };
        eprintln!("{}", style::warning(&msg, c));
        std::process::exit(1);
    }
    if output_is_structured(output) {
        return write_serialized_pretty(
            &found,
            output,
            "failed to write entries to stdout",
        );
    }
    for m in &found {
        if output == OutputMode::Name {
            println!("{}", m.name);
        } else {
            println!(
                "{}\t{}\t{}\t{}",
                m.id,
                m.name,
                m.user.as_deref().unwrap_or_default(),
                if m.site { "site" } else { "" }
            );
        }
    }
    Ok(())
}
