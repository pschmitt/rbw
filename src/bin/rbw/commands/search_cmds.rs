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
