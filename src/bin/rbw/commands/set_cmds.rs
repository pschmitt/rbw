use super::*;

pub(super) fn edit_structured(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    json: bool,
    patch: bool,
    force_exact: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    crate::actions::sync()?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

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

    let (entry, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let editable = decrypted_to_editable(&decrypted);
    let json = json || patch;

    let serialized = if json {
        serde_json::to_string_pretty(&editable)?
    } else {
        serde_yaml::to_string(&editable)?
    };

    let (help, ext) = if json {
        (
            "# Edit the JSON below. Lines starting with # are ignored.",
            "json",
        )
    } else {
        (
            "# Edit the YAML below. Lines starting with # are ignored.",
            "yaml",
        )
    };

    let interactive = !patch && std::io::stdin().is_terminal();
    let contents = if patch {
        let patch = std::io::read_to_string(std::io::stdin())
            .map_err(|e| anyhow::anyhow!("failed to read stdin: {e}"))?;
        apply_editable_patch(&editable, &patch)?
    } else {
        rbw::edit::edit(&serialized, help, ext)?
    };
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
            eprintln!("{}", paint_no_changes());
            return Ok(());
        }

        let updated: EditableCipher = if json {
            serde_json::from_str(&contents_trimmed)
                .map_err(|e| anyhow::anyhow!("failed to parse JSON: {e}"))?
        } else {
            serde_yaml::from_str(&contents_trimmed)
                .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?
        };

        let (data, fields, notes) = editable_to_encrypted(
            &updated,
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
        // Compare the plaintexts: re-encrypting an unchanged password gives
        // a different ciphertext, which would add a bogus history entry.
        let password_changed = matches!(
            (&decrypted.data, &updated.data),
            (
                DecryptedData::Login { password: Some(old), .. },
                EditableData::Login { password: new, .. },
            ) if Some(old) != new.as_ref()
        );
        if let rbw::db::EntryData::Login {
            password: Some(old_pw),
            ..
        } = &entry.data
        {
            if password_changed {
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

        let folder_id = if let Some(folder_name) = updated.folder.as_deref() {
            resolve_folder_id(
                &mut db,
                &access_token,
                &refresh_token,
                folder_name,
            )?
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

        after_server_write(&mut db, tokens)?;
        Ok(())
    })();
    after_editor(&contents, interactive, result)
}

pub(super) fn add_structured(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    json: bool,
    generated_password: Option<&str>,
    secure_note: bool,
) -> anyhow::Result<()> {
    let template = new_entry_template(
        name,
        username,
        uris,
        folder,
        generated_password,
        secure_note,
    );
    let Some((cipher, editor_buffer)) =
        edit_new_entry(template, json, generated_password.is_some())?
    else {
        return Ok(());
    };

    let result = (|| {
        unlock(None, None)?;

        let mut db = load_db()?;
        let access_token = db.access_token.as_ref().unwrap().clone();
        let refresh_token = db.refresh_token.as_ref().unwrap().clone();

        let (data, fields, notes) =
            editable_to_encrypted(&cipher, None, None)?;

        let encrypted_name =
            crate::actions::encrypt(&cipher.name, None, None)?;
        let encrypted_notes = notes
            .as_deref()
            .map(|n| crate::actions::encrypt(n, None, None))
            .transpose()?;

        let folder_id = if let Some(folder_name) = cipher.folder.as_deref() {
            resolve_folder_id(
                &mut db,
                &access_token,
                &refresh_token,
                folder_name,
            )?
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

        after_server_write(&mut db, tokens)?;
        print_created(&cipher.name);
        Ok(())
    })();
    after_editor(
        editor_buffer.as_deref().unwrap_or(""),
        editor_buffer.is_some(),
        result,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn set(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    new_fields: &[(String, String)],
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    if_revision: Option<&str>,
    bulk: bool,
    yes: bool,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    struct BulkPending {
        entry: rbw::db::Entry,
        entry_name: String,
        changes: Vec<(&'static str, String, String)>,
    }

    if let Some(path) = from_file {
        if bulk {
            return set_from_file_bulk(
                path,
                &needles,
                username,
                folder,
                ignore_case,
                new_name,
                new_username,
                new_password,
                new_notes,
                new_uris,
                new_totp,
                new_fields,
                diff,
                new_attachments,
                yes,
                from_file_passphrase,
            );
        }
        return set_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            new_name,
            new_username,
            new_password,
            new_notes,
            new_uris,
            new_totp,
            new_fields,
            diff,
            new_attachments,
            yes,
            force_exact,
            from_file_passphrase,
        );
    }

    if bulk {
        unlock(None, None)?;
        crate::actions::sync()?;
        let mut db = load_db()?;
        let mut any_err = false;
        let mut committed = false;

        let mut pending: Vec<BulkPending> = Vec::new();

        for needle in &needles {
            match find_entries_all(
                &db,
                needle,
                username,
                folder,
                collection,
                org,
                ignore_case,
            ) {
                Err(e) => {
                    eprintln!("{needle}: {e:#}");
                    any_err = true;
                }
                Ok(entries) => {
                    for (entry, decrypted) in entries {
                        let entry_name = decrypted.name.clone();
                        match compute_entry_changes(
                            &decrypted,
                            new_name,
                            new_username,
                            new_password,
                            new_notes,
                            new_uris,
                            new_totp,
                            new_fields,
                        ) {
                            Err(e) => {
                                eprintln!("{entry_name}: {e:#}");
                                any_err = true;
                            }
                            Ok(changes)
                                if changes.is_empty()
                                    && new_attachments.is_empty() =>
                            {
                                let c = stdout_supports_color();
                                eprintln!(
                                    "{} {}",
                                    style::name(&entry_name, c),
                                    style::dim("(no changes)", c)
                                );
                            }
                            Ok(changes) => {
                                pending.push(BulkPending {
                                    entry,
                                    entry_name,
                                    changes,
                                });
                            }
                        }
                    }
                }
            }
        }

        if !pending.is_empty() && !yes {
            let c = stdout_supports_color();
            let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
            eprintln!(
                "About to update {} {}:",
                style::name(&format!("{}", pending.len()), c),
                if pending.len() == 1 {
                    "entry"
                } else {
                    "entries"
                }
            );
            for pu in &pending {
                eprintln!();
                eprintln!("{}:", style::name(&pu.entry_name, c));
                for (field, old, new) in &pu.changes {
                    // The diff shows the values themselves; hide the secret
                    // ones (a custom field may be hidden, so it counts).
                    let secret = matches!(
                        *field,
                        "notes" | "password" | "totp" | "field"
                    );
                    let (old, new) = if redact_enabled() && secret {
                        (MASKED_SECRET, MASKED_SECRET)
                    } else {
                        (old.as_str(), new.as_str())
                    };
                    eprintln!(
                        "  {} {} {} {}",
                        lbl(field),
                        style::old_val(old, c),
                        style::dim("→", c),
                        style::new_val(new, c),
                    );
                }
                for file in new_attachments {
                    eprintln!("  {} {}", lbl("attach"), file.display());
                }
            }
            eprintln!();
            eprint!("Apply all ({})? [y/N] ", pending.len());
            let _ = std::io::stderr().flush();
            let mut answer = String::new();
            read_set_confirmation(&mut answer)?;
            if !matches!(answer.trim(), "y" | "Y") {
                eprintln!("Aborted.");
                return Ok(());
            }
        }

        let c = stdout_supports_color();
        let pb = item_progress_bar(
            u64::try_from(pending.len()).unwrap_or(u64::MAX),
        );
        for pu in pending {
            pb.set_message(fit_to_width(&pu.entry_name, PROGRESS_MSG_WIDTH));

            let result = apply_entry_update(
                &mut db,
                &pu.entry,
                new_name,
                new_username,
                new_password,
                new_notes,
                new_uris,
                new_totp,
                new_fields,
                !pu.changes.is_empty(),
                new_attachments,
            );
            // `apply_entry_update`'s existing output is a mix of println!
            // (stdout) and eprintln! (stderr) -- suspend the bar around it
            // rather than routing through `pb.println` (which always
            // targets the bar's own stream), so neither stream's output
            // changes.
            pb.suspend(|| {
                if let Err(e) = &result {
                    eprintln!("{}: {e:#}", pu.entry_name);
                } else {
                    println!(
                        "Item {} was updated",
                        style::name(&pu.entry_name, c)
                    );
                    if diff {
                        print_entry_diff(&pu.changes);
                    }
                }
            });
            match result {
                Ok(()) => committed = true,
                Err(e) if e.is::<WriteCommitted>() => return Err(e),
                Err(_) => any_err = true,
            }
            pb.inc(1);
        }
        pb.finish_and_clear();
        return if any_err {
            Err(if committed {
                anyhow::anyhow!("one or more entries failed to update")
                    .context(WriteCommitted)
            } else {
                anyhow::anyhow!("one or more entries failed to update")
            })
        } else {
            Ok(())
        };
    }
    set_one(
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
        new_fields,
        diff,
        new_attachments,
        if_revision,
        yes,
        force_exact,
    )
}

pub(super) fn find_entries_all(
    db: &rbw::db::Db,
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<Vec<(rbw::db::Entry, DecryptedCipher)>> {
    let (collection_id, org_id) = resolve_entry_scope(db, collection, org)?;
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
    let ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .zip(plans)
        // One corrupt entry must not block a `--bulk` operation from
        // finding/matching every other entry -- skip it and warn instead.
        .filter_map(|(entry, plan)| match plan.resolve(&results) {
            Ok(d) => Some((entry.clone(), d)),
            Err(e) => {
                log::warn!("failed to decrypt entry: {e}");
                None
            }
        })
        .collect();

    let matches: Vec<_> = ciphers
        .iter()
        // Trashed entries are never a `--bulk` candidate (matches
        // `find_entry_raw`'s exclusion, and Bitwarden's own precondition
        // that a trashed item can't be re-edited/re-archived) -- see
        // `find_deleted_entries_all` for `rbw restore --bulk`'s dedicated
        // trashed-only counterpart.
        .filter(|(_, d)| !d.deleted)
        .filter(|(entry, _)| {
            entry_in_collection_org_scope(
                entry,
                collection_id.as_deref(),
                org_id.as_deref(),
            )
        })
        .filter(|(_, d)| {
            d.matches(
                needle,
                username,
                folder,
                ignore_case,
                false,
                false,
                false,
            )
        })
        .collect();

    if matches.is_empty() {
        return Err(anyhow::anyhow!("no entry found for '{needle}'"));
    }

    Ok(matches
        .iter()
        // A needle matching several entries shouldn't have one corrupt
        // entry cost it every other match -- skip it and warn instead.
        .filter_map(|(entry, _)| match decrypt_cipher(entry) {
            Ok(d) => Some(((*entry).clone(), d)),
            Err(e) => {
                log::warn!("failed to decrypt entry: {e}");
                None
            }
        })
        .collect())
}

// `find_entries_all`'s `--from-file` counterpart: same matching
// (`DecryptedSearchCipher::matches`) against the already-decrypted vault,
// no agent/batch-decrypt involved -- can't fail the way a live decrypt
// can, so this returns the plain `Vec` rather than a `Result`.
pub(super) fn find_entries_all_in_file(
    entries: &[DecryptedCipher],
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> Vec<DecryptedCipher> {
    entries
        .iter()
        .filter(|entry| {
            decrypted_cipher_to_search(entry).matches(
                needle,
                username,
                folder,
                ignore_case,
                false,
                false,
                false,
            )
        })
        .cloned()
        .collect()
}

// `set --bulk --from-file`: same per-needle "find every match, compute
// changes, confirm once, apply all" flow as the live `bulk` branch above,
// but against the in-memory vault -- `apply_entry_update_decrypted`
// instead of `apply_entry_update`, and a single `save_to_file` at the end
// instead of a `rbw::actions::edit` + `sync` per entry.
#[allow(clippy::too_many_arguments)]
pub(super) fn set_from_file_bulk(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    new_fields: &[(String, String)],
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    yes: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    struct BulkPending {
        decrypted: DecryptedCipher,
        entry_name: String,
        changes: Vec<(&'static str, String, String)>,
    }

    let mut vault = load_from_file(path, passphrase)?;
    let mut any_err = false;
    let mut pending: Vec<BulkPending> = Vec::new();

    for needle in needles {
        let matches = find_entries_all_in_file(
            &vault.entries,
            needle,
            username,
            folder,
            ignore_case,
        );
        if matches.is_empty() {
            eprintln!("{needle}: no entry found");
            any_err = true;
            continue;
        }
        for decrypted in matches {
            let entry_name = decrypted.name.clone();
            match compute_entry_changes(
                &decrypted,
                new_name,
                new_username,
                new_password,
                new_notes,
                new_uris,
                new_totp,
                new_fields,
            ) {
                Err(e) => {
                    eprintln!("{entry_name}: {e:#}");
                    any_err = true;
                }
                Ok(changes)
                    if changes.is_empty() && new_attachments.is_empty() =>
                {
                    let c = stdout_supports_color();
                    eprintln!(
                        "{} {}",
                        style::name(&entry_name, c),
                        style::dim("(no changes)", c)
                    );
                }
                Ok(changes) => {
                    pending.push(BulkPending {
                        decrypted,
                        entry_name,
                        changes,
                    });
                }
            }
        }
    }

    if !pending.is_empty() && !yes {
        let c = stdout_supports_color();
        let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
        eprintln!(
            "About to update {} {}:",
            style::name(&format!("{}", pending.len()), c),
            if pending.len() == 1 {
                "entry"
            } else {
                "entries"
            }
        );
        for pu in &pending {
            eprintln!();
            eprintln!("{}:", style::name(&pu.entry_name, c));
            for (field, old, new) in &pu.changes {
                eprintln!(
                    "  {} {} {} {}",
                    lbl(field),
                    style::old_val(old, c),
                    style::dim("→", c),
                    style::new_val(new, c),
                );
            }
            for file in new_attachments {
                eprintln!("  {} {}", lbl("attach"), file.display());
            }
        }
        eprintln!();
        eprint!("Apply all ({})? [y/N] ", pending.len());
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        read_set_confirmation(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    if pending.is_empty() {
        return if any_err {
            Err(anyhow::anyhow!("one or more needles matched no entry"))
        } else {
            Ok(())
        };
    }

    let c = stdout_supports_color();
    for pu in pending {
        match apply_entry_update_decrypted(
            &pu.decrypted,
            new_name,
            new_password,
            new_username,
            new_notes,
            new_uris,
            new_totp,
            new_fields,
            new_attachments,
        ) {
            Ok((updated, new_attachment_bytes)) => {
                for (id, bytes) in new_attachment_bytes {
                    vault.attachment_data.insert(id, bytes);
                }
                if let Some(pos) =
                    vault.entries.iter().position(|e| e.id == updated.id)
                {
                    vault.entries[pos] = updated;
                }
                println!(
                    "Item {} was updated",
                    style::name(&pu.entry_name, c)
                );
                if diff {
                    print_entry_diff(&pu.changes);
                }
            }
            Err(e) => {
                eprintln!("{}: {e:#}", pu.entry_name);
                any_err = true;
            }
        }
    }

    backup_file(path)?;
    let exported = vault
        .entries
        .iter()
        .map(|e| {
            to_exported_entry(e, &vault.attachment_data, &vault.entry_extra)
        })
        .collect();
    save_to_file(
        path,
        exported,
        vault.collections,
        vault.passphrase.as_deref(),
    )?;

    if any_err {
        Err(anyhow::anyhow!("one or more entries failed to update"))
    } else {
        Ok(())
    }
}

// `rbw set --if-revision`: refuses the update when the entry changed since
// the caller looked at it. Timestamps are compared as points in time, so a
// differently formatted but equal date still matches.
pub(super) fn check_revision(
    entry_name: &str,
    actual: Option<&str>,
    expected: &str,
) -> anyhow::Result<()> {
    let Some(actual) = actual else {
        return Err(anyhow::anyhow!(
            "{entry_name} has no revision date to compare against"
        ));
    };
    let same = actual == expected
        || matches!(
            (parse_revision_date(actual), parse_revision_date(expected)),
            (Ok(a), Ok(b)) if a == b
        );
    if same {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{entry_name} was modified since revision {expected} (now \
             {actual}); not updating"
        ))
    }
}

pub(super) fn set_one(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    new_fields: &[(String, String)],
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    if_revision: Option<&str>,
    yes: bool,
    force_exact: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    crate::actions::sync()?;

    let mut db = load_db()?;

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

    let (entry, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let Some(expected) = if_revision {
        check_revision(
            &decrypted.name,
            entry.revision_date.as_deref(),
            expected,
        )?;
    }

    set_entry(
        &mut db,
        &entry,
        &decrypted,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
        new_fields,
        diff,
        new_attachments,
        yes,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compute_entry_changes(
    decrypted: &DecryptedCipher,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    new_fields: &[(String, String)],
) -> anyhow::Result<Vec<(&'static str, String, String)>> {
    let login_fields_requested = new_username.is_some()
        || new_password.is_some()
        || !new_uris.is_empty()
        || new_totp.is_some();
    if login_fields_requested
        && !matches!(decrypted.data, DecryptedData::Login { .. })
    {
        return Err(anyhow::anyhow!(
            "username/password/uri/totp are only supported for Login entries"
        ));
    }

    let mut changes: Vec<(&'static str, String, String)> = Vec::new();

    if let Some(n) = new_name {
        if n != decrypted.name.as_str() {
            changes.push(("name", decrypted.name.clone(), n.to_string()));
        }
    }
    if let Some(n) = new_notes {
        let cur = decrypted.notes.as_deref().unwrap_or("");
        if n != cur {
            let old_d = if cur.is_empty() {
                "(none)".to_string()
            } else {
                "(set)".to_string()
            };
            let new_d = if n.is_empty() {
                "(cleared)".to_string()
            } else {
                "(set)".to_string()
            };
            changes.push(("notes", old_d, new_d));
        }
    }
    if let DecryptedData::Login {
        username: cur_user,
        password: cur_pw,
        uris: cur_uris,
        totp: cur_totp,
        ..
    } = &decrypted.data
    {
        if let Some(u) = new_username {
            if Some(u) != cur_user.as_deref() {
                let old = cur_user.as_deref().map_or_else(
                    || "(none)".to_string(),
                    std::string::ToString::to_string,
                );
                changes.push(("username", old, u.to_string()));
            }
        }
        if let Some(p) = new_password {
            if Some(p) != cur_pw.as_deref() {
                let old = cur_pw.as_deref().map_or_else(
                    || "(none)".to_string(),
                    |s| format!("\"{}\"", censor(s)),
                );
                changes.push(("password", old, format!("\"{}\"", censor(p))));
            }
        }
        if !new_uris.is_empty() {
            let cur_strs: Vec<&str> = cur_uris
                .as_ref()
                .map(|v| v.iter().map(|u| u.uri.as_str()).collect())
                .unwrap_or_default();
            let new_strs: Vec<&str> =
                new_uris.iter().map(String::as_str).collect();
            if new_strs != cur_strs {
                let fmt_uris = |v: &[&str]| match v {
                    [] => "(none)".to_string(),
                    [u] => (*u).to_string(),
                    _ => format!("[{} uris]", v.len()),
                };
                changes.push((
                    "uri",
                    fmt_uris(&cur_strs),
                    fmt_uris(&new_strs),
                ));
            }
        }
        if let Some(t) = new_totp {
            if Some(t) != cur_totp.as_deref() {
                let old = cur_totp.as_deref().map_or_else(
                    || "(none)".to_string(),
                    |s| format!("\"{}\"", censor(s)),
                );
                changes.push(("totp", old, format!("\"{}\"", censor(t))));
            }
        }
    }
    for (name, value) in new_fields {
        let current = decrypted
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some(name.as_str()));
        if current.is_some_and(|f| f.ty == Some(rbw::api::FieldType::Linked))
        {
            return Err(anyhow::anyhow!(
                "field '{name}' is a linked field and has no value to set"
            ));
        }
        let cur_value = current.and_then(|f| f.value.as_deref());
        if current.is_some() && cur_value == Some(value.as_str()) {
            continue;
        }
        let old = match (current, cur_value) {
            (None, _) => format!("{name} (none)"),
            (Some(_), None) => format!("{name} (empty)"),
            (Some(_), Some(v)) => format!("{name}=\"{}\"", censor(v)),
        };
        changes.push(("field", old, format!("{name}=\"{}\"", censor(value))));
    }
    Ok(changes)
}

// `rbw set --field NAME=VALUE`: replaces the value of the first existing
// custom field named NAME (keeping its type), or appends a new hidden
// field if there is none. Field names are matched on their decrypted
// value, so this needs the entry's key just like the value encryption.
pub(super) fn apply_field_updates_encrypted(
    fields: &[rbw::db::Field],
    new_fields: &[(String, String)],
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<Vec<rbw::db::Field>> {
    let mut fields = fields.to_vec();
    if new_fields.is_empty() {
        return Ok(fields);
    }
    let mut names = fields
        .iter()
        .map(|f| {
            f.name
                .as_deref()
                .map(|n| crate::actions::decrypt(n, entry_key, org_id))
                .transpose()
        })
        .collect::<anyhow::Result<Vec<Option<String>>>>()?;
    for (name, value) in new_fields {
        let enc_value = crate::actions::encrypt(value, entry_key, org_id)?;
        if let Some(pos) = names
            .iter()
            .position(|n| n.as_deref() == Some(name.as_str()))
        {
            fields[pos].value = Some(enc_value);
        } else {
            fields.push(rbw::db::Field {
                ty: Some(rbw::api::FieldType::Hidden),
                name: Some(crate::actions::encrypt(name, entry_key, org_id)?),
                value: Some(enc_value),
                linked_id: None,
            });
            names.push(Some(name.clone()));
        }
    }
    Ok(fields)
}

// `--from-file` counterpart of `apply_field_updates_encrypted`.
pub(super) fn apply_field_updates_decrypted(
    fields: &mut Vec<DecryptedField>,
    new_fields: &[(String, String)],
) {
    for (name, value) in new_fields {
        if let Some(field) = fields
            .iter_mut()
            .find(|f| f.name.as_deref() == Some(name.as_str()))
        {
            field.value = Some(value.clone());
        } else {
            fields.push(DecryptedField {
                name: Some(name.clone()),
                value: Some(value.clone()),
                ty: Some(rbw::api::FieldType::Hidden),
                linked_id: None,
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_entry_update(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    new_fields: &[(String, String)],
    has_field_changes: bool,
    new_attachments: &[std::path::PathBuf],
) -> anyhow::Result<()> {
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();
    let org_id = entry.org_id.as_deref();
    // Every field re-encrypted below must use the entry's own individual
    // key when it has one, exactly like `decrypt_cipher` does when reading
    // it back -- otherwise the fields this edit leaves untouched (still
    // ciphertext under the entry's key) end up alongside a freshly
    // touched field encrypted under the wrong (account/org) key, and
    // whichever ciphertext doesn't match the key actually in effect
    // becomes permanently undecryptable.
    let entry_key = entry.key.as_deref();

    let encrypted_name = if let Some(n) = new_name {
        crate::actions::encrypt(n, entry_key, org_id)?
    } else {
        entry.name.clone()
    };

    let encrypted_notes = if let Some(n) = new_notes {
        if n.is_empty() {
            None
        } else {
            Some(crate::actions::encrypt(n, entry_key, org_id)?)
        }
    } else {
        entry.notes.clone()
    };

    let mut history = entry.history.clone();

    let data = match &entry.data {
        rbw::db::EntryData::Login {
            username: entry_username,
            password: entry_password,
            uris: entry_uris,
            totp: entry_totp,
            fido2_credentials: entry_fido2_credentials,
        } => {
            let enc_user = if new_username.is_some() {
                new_username
                    .map(|u| crate::actions::encrypt(u, entry_key, org_id))
                    .transpose()?
            } else {
                entry_username.clone()
            };
            let enc_pw = if let Some(pw) = new_password {
                if let Some(prev) = entry_password.clone() {
                    history.insert(
                        0,
                        rbw::db::HistoryEntry {
                            last_used_date: format!(
                                "{}",
                                humantime::format_rfc3339(
                                    std::time::SystemTime::now()
                                )
                            ),
                            password: prev,
                        },
                    );
                }
                Some(crate::actions::encrypt(pw, entry_key, org_id)?)
            } else {
                entry_password.clone()
            };
            let enc_uris = if new_uris.is_empty() {
                entry_uris.clone()
            } else {
                new_uris
                    .iter()
                    .map(|u| {
                        Ok(rbw::db::Uri {
                            uri: crate::actions::encrypt(
                                u, entry_key, org_id,
                            )?,
                            match_type: None,
                        })
                    })
                    .collect::<anyhow::Result<_>>()?
            };
            let enc_totp = if new_totp.is_some() {
                new_totp
                    .map(|t| crate::actions::encrypt(t, entry_key, org_id))
                    .transpose()?
            } else {
                entry_totp.clone()
            };
            rbw::db::EntryData::Login {
                username: enc_user,
                password: enc_pw,
                uris: enc_uris,
                totp: enc_totp,
                // `rbw set` never touches passkeys -- always carried over
                // unchanged from the entry being updated, exactly like
                // `password_history` above, so this can never destroy a
                // fido2 credential the way an absent field on the outgoing
                // request would (Vaultwarden stores the whole `login`
                // object wholesale, no per-field merge).
                fido2_credentials: entry_fido2_credentials.clone(),
            }
        }
        other => other.clone(),
    };

    if has_field_changes {
        let fields = apply_field_updates_encrypted(
            &entry.fields,
            new_fields,
            entry_key,
            org_id,
        )?;
        let (tokens, ()) = rbw::actions::edit(
            &access_token,
            &refresh_token,
            &entry.id,
            org_id,
            entry_key,
            &encrypted_name,
            &data,
            &fields,
            encrypted_notes.as_deref(),
            entry.folder_id.as_deref(),
            &history,
            &entry.cipher_write_meta(),
        )?;
        after_server_write(db, tokens)?;
    }

    let mut committed = has_field_changes;
    let follow_up = (|| {
        for file in new_attachments {
            let filename = file
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .ok_or_else(|| {
                    anyhow::anyhow!("invalid filename: {}", file.display())
                })?;
            let file_data = std::fs::read(file).with_context(|| {
                format!("failed to read {}", file.display())
            })?;
            let access_token = db.access_token.as_ref().unwrap().clone();
            let refresh_token = db.refresh_token.as_ref().unwrap().clone();
            let (encrypted_data, encrypted_key, encrypted_filename) =
                crate::actions::encrypt_attachment(
                    file_data,
                    filename,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )?;
            let (tokens, ()) = rbw::actions::create_attachment(
                &access_token,
                &refresh_token,
                &entry.id,
                &encrypted_filename,
                &encrypted_key,
                &encrypted_data,
            )?;
            committed = true;
            if let Some(tokens) = tokens {
                db.access_token = Some(tokens.access_token);
                if let Some(refresh_token) = tokens.refresh_token {
                    db.refresh_token = Some(refresh_token);
                }
                save_db(db)?;
            }
        }

        // Nothing after this call in any caller depends on a freshly-synced
        // `db` -- only skip when there were no attachments uploaded above,
        // since that's the one thing here the local cache doesn't already
        // reflect (same reasoning as `import_create_entry`'s sync-skip).
        if !new_attachments.is_empty() {
            crate::actions::sync()?;
        }
        Ok(())
    })();
    if committed {
        follow_up.context(WriteCommitted)
    } else {
        follow_up
    }
}

// Shared by `set_entry` (live account) and `set_from_file`: prints the
// pending changes and asks to confirm, unless `yes`. `Ok(false)` means the
// caller should abort without applying anything.
// Reads a `[y/N]` answer for `rbw set`. When stdin is already drained
// (it carried the new value, as in `rbw set --field NAME ENTRY <<< value`
// or `--password-stdin`), asks on the terminal instead of reading EOF as
// "no".
pub(super) fn read_set_confirmation(
    answer: &mut String,
) -> anyhow::Result<()> {
    use std::io::BufRead as _;

    let n = std::io::stdin()
        .read_line(answer)
        .context("failed to read confirmation")?;
    if n == 0 {
        let tty = std::fs::File::open("/dev/tty").map_err(|_| {
            anyhow::anyhow!(
                "no confirmation on stdin and no terminal to ask on; \
                pass --yes"
            )
        })?;
        std::io::BufReader::new(tty)
            .read_line(answer)
            .context("failed to read confirmation")?;
    }
    Ok(())
}

pub(super) fn confirm_entry_update(
    entry_name: &str,
    changes: &[(&'static str, String, String)],
    new_attachments: &[std::path::PathBuf],
    yes: bool,
) -> anyhow::Result<bool> {
    use std::io::Write as _;

    if yes {
        return Ok(true);
    }

    let c = stdout_supports_color();
    let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
    eprintln!("About to update {}:", style::name(entry_name, c));
    eprintln!();
    for (field, old, new) in changes {
        eprintln!(
            "{} {} {} {}",
            lbl(field),
            style::old_val(old, c),
            style::dim("→", c),
            style::new_val(new, c),
        );
    }
    for file in new_attachments {
        eprintln!("{} {}", lbl("attach"), file.display());
    }
    eprintln!();
    eprint!("Apply? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    read_set_confirmation(&mut answer)?;
    if matches!(answer.trim(), "y" | "Y") {
        Ok(true)
    } else {
        eprintln!("Aborted.");
        Ok(false)
    }
}

// `set --from-file`'s counterpart to `apply_entry_update`: same field
// updates (including inserting the outgoing password into history -- pure
// data, no crypto involved) but on a `DecryptedCipher` directly instead of
// encrypting and pushing to the server. New attachments (`--attach`) are
// read from disk and handed back with their raw bytes for the caller to
// fold into the vault's attachment side table -- there's no server here to
// assign them an id, so a fresh one is generated.
pub(super) fn apply_entry_update_decrypted(
    decrypted: &DecryptedCipher,
    new_name: Option<&str>,
    new_password: Option<&str>,
    new_username: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    new_fields: &[(String, String)],
    new_attachments: &[std::path::PathBuf],
) -> anyhow::Result<(DecryptedCipher, Vec<(String, Vec<u8>)>)> {
    let mut updated = decrypted.clone();

    if let Some(n) = new_name {
        updated.name = n.to_string();
    }
    if let Some(n) = new_notes {
        updated.notes = (!n.is_empty()).then(|| n.to_string());
    }

    if let DecryptedData::Login {
        username,
        password,
        uris,
        totp,
        ..
    } = &mut updated.data
    {
        if new_username.is_some() {
            *username = new_username.map(str::to_string);
        }
        if let Some(pw) = new_password {
            if let Some(prev) = password.clone() {
                updated.history.insert(
                    0,
                    DecryptedHistoryEntry {
                        last_used_date: format!(
                            "{}",
                            humantime::format_rfc3339(
                                std::time::SystemTime::now()
                            )
                        ),
                        password: prev,
                    },
                );
            }
            *password = Some(pw.to_string());
        }
        if !new_uris.is_empty() {
            *uris = Some(
                new_uris
                    .iter()
                    .map(|u| DecryptedUri {
                        uri: u.clone(),
                        match_type: None,
                    })
                    .collect(),
            );
        }
        if new_totp.is_some() {
            *totp = new_totp.map(str::to_string);
        }
    }
    apply_field_updates_decrypted(&mut updated.fields, new_fields);

    let mut new_attachment_bytes = Vec::new();
    for file in new_attachments {
        let filename = file
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| {
                anyhow::anyhow!("invalid filename: {}", file.display())
            })?
            .to_string();
        let data = std::fs::read(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let id = uuid::Uuid::new_v4().to_string();
        updated.attachments.push(DecryptedAttachment {
            id: id.clone(),
            file_name: Some(filename),
            size: None,
            size_name: None,
        });
        new_attachment_bytes.push((id, data));
    }
    updated.attachment_metadata =
        AttachmentMetadata::new(&updated.id, updated.attachments.len());

    Ok((updated, new_attachment_bytes))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn set_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    new_fields: &[(String, String)],
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    yes: bool,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let mut vault = load_from_file(path, passphrase)?;

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

    let entry_name = decrypted.name.clone();
    let changes = compute_entry_changes(
        &decrypted,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
        new_fields,
    )?;

    if changes.is_empty() && new_attachments.is_empty() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    if !confirm_entry_update(&entry_name, &changes, new_attachments, yes)? {
        return Ok(());
    }

    let (updated, new_attachment_bytes) = apply_entry_update_decrypted(
        &decrypted,
        new_name,
        new_password,
        new_username,
        new_notes,
        new_uris,
        new_totp,
        new_fields,
        new_attachments,
    )?;
    for (id, bytes) in new_attachment_bytes {
        vault.attachment_data.insert(id, bytes);
    }
    if let Some(pos) = vault.entries.iter().position(|e| e.id == decrypted.id)
    {
        vault.entries[pos] = updated;
    }

    backup_file(path)?;
    let exported = vault
        .entries
        .iter()
        .map(|e| {
            to_exported_entry(e, &vault.attachment_data, &vault.entry_extra)
        })
        .collect();
    save_to_file(
        path,
        exported,
        vault.collections,
        vault.passphrase.as_deref(),
    )?;

    let c = stdout_supports_color();
    println!("Item {} was updated", style::name(&entry_name, c));
    if diff {
        print_entry_diff(&changes);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn set_entry(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    decrypted: &DecryptedCipher,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    new_fields: &[(String, String)],
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    yes: bool,
) -> anyhow::Result<()> {
    let entry_name = decrypted.name.clone();

    let changes = compute_entry_changes(
        decrypted,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
        new_fields,
    )?;

    if changes.is_empty() && new_attachments.is_empty() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    if !confirm_entry_update(&entry_name, &changes, new_attachments, yes)? {
        return Ok(());
    }

    apply_entry_update(
        db,
        entry,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
        new_fields,
        !changes.is_empty(),
        new_attachments,
    )?;
    // Refresh the local cache (`apply_entry_update` already did if it
    // uploaded attachments), so a follow-up `rbw set` doesn't build its
    // full-object update from the pre-edit copy.

    let c = stdout_supports_color();
    println!("Item {} was updated", style::name(&entry_name, c));
    if diff {
        print_entry_diff(&changes);
    }
    Ok(())
}

pub(super) fn resolve_folder_id(
    db: &mut rbw::db::Db,
    access_token: &str,
    refresh_token: &str,
    folder_name: &str,
) -> anyhow::Result<Option<String>> {
    let (tokens, folders) =
        rbw::actions::list_folders(access_token, refresh_token)?;
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(db)?;
    }
    let access_token = db.access_token.as_deref().unwrap();
    let refresh_token_str = db.refresh_token.as_deref().unwrap();

    let folders: Vec<(String, String)> = folders
        .iter()
        .cloned()
        .map(|(id, name)| {
            Ok((id, crate::actions::decrypt(&name, None, None)?))
        })
        .collect::<anyhow::Result<_>>()?;

    for (id, name) in &folders {
        if name == folder_name {
            return Ok(Some(id.clone()));
        }
    }

    let (tokens, id) = rbw::actions::create_folder(
        access_token,
        refresh_token_str,
        &crate::actions::encrypt(folder_name, None, None)?,
    )?;
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(db)?;
    }
    Ok(Some(id))
}

pub(super) fn censor(s: &str) -> String {
    // A partial value is still secret material.
    if redact_enabled() {
        return MASKED_SECRET.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    if len <= 4 {
        return "****".to_string();
    }
    let prefix = len.div_ceil(3).min(8);
    let suffix = len.div_ceil(4).min(5);
    if prefix + suffix >= len {
        return "****".to_string();
    }
    format!(
        "{}…{}",
        chars[..prefix].iter().collect::<String>(),
        chars[len - suffix..].iter().collect::<String>()
    )
}

// Exposed for main.rs error rendering — keeps all ANSI codes in one place.
pub fn style_error(msg: &str, color: bool) -> String {
    style::paint_raw(msg, "1;31", color)
}

pub(super) fn paint_no_changes() -> String {
    style::dim("No changes.", stdout_supports_color())
}

pub(super) fn print_created(entry_name: &str) {
    let c = stdout_supports_color();
    eprintln!(
        "{} {}",
        style::success("Created", c),
        style::name(entry_name, c)
    );
}

pub(super) fn print_entry_diff(changes: &[(&str, String, String)]) {
    let c = stdout_supports_color();
    let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
    for (field, old, new) in changes {
        println!(
            "  {} {} {} {}",
            lbl(field),
            style::old_val(old, c),
            style::dim("→", c),
            style::new_val(new, c),
        );
    }
}

// `rbw edit --patch`: applies an RFC 7396 JSON merge patch (objects merge,
// `null` removes a key, anything else replaces it) to the entry as `rbw edit
// --json` would show it, so a script can change one field of any entry type
// without ever reading the secrets it leaves alone. A masked value
// (`MASKED_SECRET`, what `--redact` output shows) is refused, so a redacted
// entry can't be written back over the real one.
pub(super) fn apply_editable_patch(
    editable: &EditableCipher,
    patch: &str,
) -> anyhow::Result<String> {
    let patch: serde_json::Value = serde_json::from_str(patch)
        .map_err(|e| anyhow::anyhow!("failed to parse JSON patch: {e}"))?;
    anyhow::ensure!(
        patch.is_object(),
        "the JSON patch must be an object (RFC 7396 merge patch)"
    );
    anyhow::ensure!(
        !contains_masked_secret(&patch),
        "the JSON patch contains the redaction mask {MASKED_SECRET:?}; \
         leave masked fields out of the patch instead"
    );
    let mut value = serde_json::to_value(editable)?;
    merge_patch(&mut value, &patch);
    Ok(serde_json::to_string_pretty(&value)?)
}

fn merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    let serde_json::Value::Object(patch) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = serde_json::Value::Object(serde_json::Map::new());
    }
    let target = target.as_object_mut().unwrap();
    for (key, value) in patch {
        if value.is_null() {
            target.remove(key);
        } else {
            merge_patch(
                target.entry(key.clone()).or_insert(serde_json::Value::Null),
                value,
            );
        }
    }
}

fn contains_masked_secret(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => s == MASKED_SECRET,
        serde_json::Value::Array(values) => {
            values.iter().any(contains_masked_secret)
        }
        serde_json::Value::Object(map) => {
            map.values().any(contains_masked_secret)
        }
        _ => false,
    }
}
