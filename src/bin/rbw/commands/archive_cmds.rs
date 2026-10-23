use super::*;

#[allow(clippy::too_many_arguments)]
pub fn archive(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return archive_or_unarchive_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            force_exact,
            bulk,
            yes,
            true,
            from_file_passphrase,
        );
    }
    archive_or_unarchive(
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
        bulk,
        yes,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn unarchive(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return archive_or_unarchive_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            force_exact,
            bulk,
            yes,
            false,
            from_file_passphrase,
        );
    }
    archive_or_unarchive(
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
        bulk,
        yes,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn archive_or_unarchive_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    archive: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    let mut vault = load_from_file(path, passphrase)?;
    let verb = if archive { "archive" } else { "unarchive" };
    let mut ids = Vec::new();
    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if bulk {
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
                continue;
            }
            for entry in matches {
                if entry.archived == archive || !seen.insert(entry.id.clone())
                {
                    continue;
                }
                ids.push(entry.id);
                names.push(entry.name);
            }
        }
    } else {
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
        let entry = find_entry_in_file(
            &vault.entries,
            needles,
            username,
            folder,
            ignore_case,
            force_exact,
        )
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
        if entry.archived == archive {
            println!(
                "{} is already {}",
                style::name(&entry.name, stdout_supports_color()),
                if archive { "archived" } else { "unarchived" }
            );
            return Ok(());
        }
        ids.push(entry.id);
        names.push(entry.name);
    }

    if ids.is_empty() {
        anyhow::bail!("no entries to {verb}");
    }

    if bulk && !yes {
        let c = stdout_supports_color();
        eprintln!(
            "About to {verb} {} {}:",
            style::name(&ids.len().to_string(), c),
            if ids.len() == 1 { "entry" } else { "entries" }
        );
        for name in &names {
            eprintln!("  {}", style::name(name, c));
        }
        eprintln!();
        eprint!("Apply to all ({})? [y/N] ", ids.len());
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("failed to read confirmation")?;
        if !matches!(answer.trim(), "y" | "Y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    for entry in &mut vault.entries {
        if ids.iter().any(|id| id == &entry.id) {
            entry.archived = archive;
        }
    }
    save_loaded_file_vault(path, &vault)?;

    let c = stdout_supports_color();
    for name in names {
        println!("Item {} was {verb}d", style::name(&name, c));
    }
    Ok(())
}

pub(super) fn save_loaded_file_vault(
    path: &std::path::Path,
    vault: &FileVault,
) -> anyhow::Result<()> {
    backup_file(path)?;
    let entries = vault
        .entries
        .iter()
        .map(|entry| {
            to_exported_entry(
                entry,
                &vault.attachment_data,
                &vault.entry_extra,
            )
        })
        .collect();
    save_to_file(
        path,
        entries,
        vault.collections.clone(),
        vault.passphrase.as_deref(),
    )
}

// Shared implementation for `rbw archive`/`rbw unarchive`: unlike `remove`,
// this is fully reversible, so neither path confirms by default -- only the
// bulk path prints a preview and confirms (unless `-y`), same as `set
// --bulk`, since it can silently touch many entries at once.
#[allow(clippy::too_many_arguments)]
pub(super) fn archive_or_unarchive(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    archive: bool,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    let verb = if archive { "archive" } else { "unarchive" };

    if bulk {
        unlock(None, None)?;
        let mut db = load_db()?;
        let mut any_err = false;

        let mut pending: Vec<(rbw::db::Entry, String)> = Vec::new();
        let c = stdout_supports_color();

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
                        if entry.archived == archive {
                            eprintln!(
                                "{} {}",
                                style::name(&decrypted.name, c),
                                style::dim(
                                    if archive {
                                        "(already archived)"
                                    } else {
                                        "(not archived)"
                                    },
                                    c
                                )
                            );
                            continue;
                        }
                        pending.push((entry, decrypted.name.clone()));
                    }
                }
            }
        }

        if pending.is_empty() {
            return if any_err {
                Err(anyhow::anyhow!("one or more entries failed to resolve"))
            } else {
                Ok(())
            };
        }

        if !yes {
            eprintln!(
                "About to {verb} {} {}:",
                style::name(&format!("{}", pending.len()), c),
                if pending.len() == 1 {
                    "entry"
                } else {
                    "entries"
                }
            );
            for (_, name) in &pending {
                eprintln!("  {}", style::name(name, c));
            }
            eprintln!();
            eprint!("Apply to all ({})? [y/N] ", pending.len());
            let _ = std::io::stderr().flush();
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .context("failed to read confirmation")?;
            if !matches!(answer.trim(), "y" | "Y") {
                eprintln!("Aborted.");
                return Ok(());
            }
        }

        let access_token = db.access_token.as_ref().unwrap();
        let refresh_token = db.refresh_token.as_ref().unwrap();
        let ids: Vec<String> =
            pending.iter().map(|(entry, _)| entry.id.clone()).collect();

        let rotated = if archive {
            rbw::actions::archive_multiple(access_token, refresh_token, &ids)?
        } else {
            rbw::actions::unarchive_multiple(
                access_token,
                refresh_token,
                &ids,
            )?
        };
        if let (Some(tokens), ()) = rotated {
            db.access_token = Some(tokens.access_token);
            if let Some(refresh_token) = tokens.refresh_token {
                db.refresh_token = Some(refresh_token);
            }
            save_db(&db)?;
        }

        crate::actions::sync()?;

        for (_, name) in &pending {
            println!("Item {} was {verb}d", style::name(name, c));
        }

        return if any_err {
            Err(anyhow::anyhow!("one or more entries failed to resolve"))
        } else {
            Ok(())
        };
    }

    unlock(None, None)?;

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

    let c = stdout_supports_color();
    if entry.archived == archive {
        println!(
            "{} {}",
            style::name(&decrypted.name, c),
            if archive {
                "is already archived"
            } else {
                "is not archived"
            }
        );
        return Ok(());
    }

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let rotated = if archive {
        rbw::actions::archive(access_token, refresh_token, &entry.id)?
    } else {
        rbw::actions::unarchive(access_token, refresh_token, &entry.id)?
    };
    if let (Some(tokens), ()) = rotated {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    crate::actions::sync()?;

    println!("Item {} was {verb}d", style::name(&decrypted.name, c));

    Ok(())
}

// `find_entry`'s counterpart for `rbw restore`: only matches entries that
// *are* trashed (the exact opposite of `find_entry`'s exclusion, kept as a
// separate function rather than a shared parameter so the exclusion in
// `find_entry`/`find_entry_multi` can stay an unconditional invariant
// everywhere else).
pub(super) fn find_deleted_entry(
    db: &rbw::db::Db,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
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
    let mut ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .zip(plans)
        // One corrupt entry must not block finding a different, perfectly
        // fine one -- skip it and warn instead.
        .filter_map(|(entry, plan)| match plan.resolve(&results) {
            Ok(decrypted) => Some((entry.clone(), decrypted)),
            Err(e) => {
                log::warn!("failed to decrypt entry: {e}");
                None
            }
        })
        .collect();
    ciphers.retain(|(entry, _)| entry.deleted);
    ciphers.retain(|(entry, _)| {
        entry_in_collection_org_scope(
            entry,
            collection_id.as_deref(),
            org_id.as_deref(),
        )
    });
    let (entry, _) = find_entry_raw(
        &ciphers,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )?;
    let decrypted_entry = decrypt_cipher(&entry)?;
    Ok((entry, decrypted_entry))
}

// `find_entries_all`'s counterpart for `rbw restore --bulk`: same idea as
// `find_deleted_entry` above, but for the bulk path.
pub(super) fn find_deleted_entries_all(
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
        .filter(|(entry, _)| entry.deleted)
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
        return Err(anyhow::anyhow!("no trashed entry found for '{needle}'"));
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

// `rbw restore`: undoes `rbw remove`/`rbw delete` -- restores an entry out
// of the trash. Unlike `archive`/`unarchive`, this only ever goes one
// direction, so there's no toggle to share between two public entry
// points; otherwise modeled directly on `archive_or_unarchive` (same
// single/`--bulk` shape, same non-destructive no-confirm-unless-`--bulk`
// policy, since restoring is itself the "undo" and needs no undo of its
// own).
#[allow(clippy::too_many_arguments)]
pub fn restore(
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    if let Some(path) = from_file {
        return restore_from_file(
            path,
            needles,
            username,
            folder,
            ignore_case,
            force_exact,
            bulk,
            yes,
            from_file_passphrase,
        );
    }
    if bulk {
        unlock(None, None)?;
        let mut db = load_db()?;
        let mut any_err = false;

        let mut pending: Vec<(rbw::db::Entry, String)> = Vec::new();
        let c = stdout_supports_color();

        for needle in needles {
            match find_deleted_entries_all(
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
                        pending.push((entry, decrypted.name.clone()));
                    }
                }
            }
        }

        if pending.is_empty() {
            return if any_err {
                Err(anyhow::anyhow!("one or more entries failed to resolve"))
            } else {
                Ok(())
            };
        }

        if !yes {
            eprintln!(
                "About to restore {} {}:",
                style::name(&format!("{}", pending.len()), c),
                if pending.len() == 1 {
                    "entry"
                } else {
                    "entries"
                }
            );
            for (_, name) in &pending {
                eprintln!("  {}", style::name(name, c));
            }
            eprintln!();
            eprint!("Apply to all ({})? [y/N] ", pending.len());
            let _ = std::io::stderr().flush();
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .context("failed to read confirmation")?;
            if !matches!(answer.trim(), "y" | "Y") {
                eprintln!("Aborted.");
                return Ok(());
            }
        }

        let access_token = db.access_token.as_ref().unwrap();
        let refresh_token = db.refresh_token.as_ref().unwrap();
        let ids: Vec<String> =
            pending.iter().map(|(entry, _)| entry.id.clone()).collect();

        if let (Some(tokens), ()) =
            rbw::actions::restore_multiple(access_token, refresh_token, &ids)?
        {
            db.access_token = Some(tokens.access_token);
            if let Some(refresh_token) = tokens.refresh_token {
                db.refresh_token = Some(refresh_token);
            }
            save_db(&db)?;
        }

        crate::actions::sync()?;

        for (_, name) in &pending {
            println!("Item {} was restored", style::name(name, c));
        }

        return if any_err {
            Err(anyhow::anyhow!("one or more entries failed to resolve"))
        } else {
            Ok(())
        };
    }

    unlock(None, None)?;

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

    let (entry, decrypted) = find_deleted_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find a trashed entry for '{desc}'"))?;

    let c = stdout_supports_color();

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    if let (Some(tokens), ()) =
        rbw::actions::restore(access_token, refresh_token, &entry.id)?
    {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    crate::actions::sync()?;

    println!("Item {} was restored", style::name(&decrypted.name, c));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn restore_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    let mut vault = load_from_file(path, passphrase)?;
    let mut ids = Vec::new();
    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if bulk {
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
                continue;
            }
            for entry in matches {
                if !entry.deleted || !seen.insert(entry.id.clone()) {
                    continue;
                }
                ids.push(entry.id);
                names.push(entry.name);
            }
        }
    } else {
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
        let entry = find_entry_in_file(
            &vault.entries,
            needles,
            username,
            folder,
            ignore_case,
            force_exact,
        )
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
        if !entry.deleted {
            anyhow::bail!("entry '{}' is not in the trash", entry.name);
        }
        ids.push(entry.id);
        names.push(entry.name);
    }

    if ids.is_empty() {
        anyhow::bail!("no trashed entries to restore");
    }

    if bulk && !yes {
        let c = stdout_supports_color();
        eprintln!(
            "About to restore {} {}:",
            style::name(&ids.len().to_string(), c),
            if ids.len() == 1 { "entry" } else { "entries" }
        );
        for name in &names {
            eprintln!("  {}", style::name(name, c));
        }
        eprintln!();
        eprint!("Apply to all ({})? [y/N] ", ids.len());
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("failed to read confirmation")?;
        if !matches!(answer.trim(), "y" | "Y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    for entry in &mut vault.entries {
        if ids.iter().any(|id| id == &entry.id) {
            entry.deleted = false;
        }
    }
    save_loaded_file_vault(path, &vault)?;

    let c = stdout_supports_color();
    for name in names {
        println!("Item {} was restored", style::name(&name, c));
    }
    Ok(())
}
