use super::*;

// Uploads any embedded attachments on an imported entry to `entry` (the
// entry's current, post-creation-or-update state). `skip_names` are
// filenames already present on the entry (used by the `--overwrite` path so
// re-running an import doesn't pile up duplicate attachments). Returns
// (restored, failed) counts; a failure to restore one attachment is a
// warning, not a fatal error for the whole import.
pub(super) fn upload_imported_attachments(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    entry: &rbw::db::Entry,
    attachments: &[serde_json::Value],
    skip_names: &std::collections::HashSet<String>,
) -> anyhow::Result<(usize, usize)> {
    if attachments.is_empty() {
        return Ok((0, 0));
    }

    let c = stdout_supports_color();
    let mut restored = 0usize;
    let mut failed = 0usize;

    for raw in attachments {
        let parsed: ImportedAttachment =
            match serde_json::from_value(raw.clone()) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "{} couldn't parse an attachment on '{}': {e}",
                        style::warning("Warning:", c),
                        entry.name,
                    );
                    failed += 1;
                    continue;
                }
            };

        let (Some(file_name), Some(data_base64)) =
            (parsed.file_name.as_deref(), parsed.data_base64.as_deref())
        else {
            eprintln!(
                "{} an attachment on '{}' is missing file_name/data_base64; \
                 skipped",
                style::warning("Warning:", c),
                entry.name,
            );
            failed += 1;
            continue;
        };

        if skip_names.contains(file_name) {
            continue;
        }

        let data = match rbw::base64::decode(data_base64) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "{} couldn't decode attachment '{file_name}' on '{}': \
                     {e}",
                    style::warning("Warning:", c),
                    entry.name,
                );
                failed += 1;
                continue;
            }
        };

        let encrypted = crate::actions::encrypt_attachment(
            data,
            file_name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        );
        let (encrypted_data, encrypted_key, encrypted_filename) =
            match encrypted {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "{} couldn't encrypt attachment '{file_name}' on \
                         '{}': {e}",
                        style::warning("Warning:", c),
                        entry.name,
                    );
                    failed += 1;
                    continue;
                }
            };

        match rbw::actions::create_attachment(
            access_token,
            refresh_token,
            &entry.id,
            &encrypted_filename,
            &encrypted_key,
            &encrypted_data,
        ) {
            Ok((tokens, ())) => {
                if let Some(tokens) = tokens {
                    access_token.clone_from(&tokens.access_token);
                    db.access_token = Some(tokens.access_token);
                    if let Some(new_refresh_token) = tokens.refresh_token {
                        refresh_token.clone_from(&new_refresh_token);
                        db.refresh_token = Some(new_refresh_token);
                    }
                    save_db(db)?;
                }
                restored += 1;
            }
            Err(e) => {
                eprintln!(
                    "{} failed to upload attachment '{file_name}' to '{}': \
                     {e}",
                    style::warning("Warning:", c),
                    entry.name,
                );
                failed += 1;
            }
        }
    }

    if restored > 0 {
        crate::actions::sync()?;
    }

    Ok((restored, failed))
}

// Applies the status flags carried by an rbw export after the entry's data
// has been created or updated. The server's import endpoints don't accept
// archive/trash state, and a trashed entry generally needs to be restored
// temporarily before its archive state can be changed.
pub(super) fn apply_imported_status(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    id: &str,
    mut archived: bool,
    mut deleted: bool,
    target_archived: bool,
    target_deleted: bool,
) -> anyhow::Result<()> {
    if deleted && (!target_deleted || archived != target_archived) {
        let (tokens, ()) =
            rbw::actions::restore(access_token, refresh_token, id)?;
        if let Some(tokens) = tokens {
            access_token.clone_from(&tokens.access_token);
            db.access_token = Some(tokens.access_token);
            if let Some(new_refresh_token) = tokens.refresh_token {
                refresh_token.clone_from(&new_refresh_token);
                db.refresh_token = Some(new_refresh_token);
            }
            save_db(db)?;
        }
        deleted = false;
    }

    if archived != target_archived {
        let (tokens, ()) = if target_archived {
            rbw::actions::archive(access_token, refresh_token, id)?
        } else {
            rbw::actions::unarchive(access_token, refresh_token, id)?
        };
        if let Some(tokens) = tokens {
            access_token.clone_from(&tokens.access_token);
            db.access_token = Some(tokens.access_token);
            if let Some(new_refresh_token) = tokens.refresh_token {
                refresh_token.clone_from(&new_refresh_token);
                db.refresh_token = Some(new_refresh_token);
            }
            save_db(db)?;
        }
        archived = target_archived;
    }

    if deleted != target_deleted {
        let (tokens, ()) =
            rbw::actions::remove(access_token, refresh_token, id)?;
        if let Some(tokens) = tokens {
            access_token.clone_from(&tokens.access_token);
            db.access_token = Some(tokens.access_token);
            if let Some(new_refresh_token) = tokens.refresh_token {
                refresh_token.clone_from(&new_refresh_token);
                db.refresh_token = Some(new_refresh_token);
            }
            save_db(db)?;
        }
        deleted = true;
    }

    if let Some(entry) = db.entries.iter_mut().find(|entry| entry.id == id) {
        entry.archived = archived;
        entry.deleted = deleted;
    }
    save_db(db)?;

    Ok(())
}

// Creates a brand-new entry for `imported`. Always creates it in the
// personal vault first (`rbw::actions::add` has no organization parameter),
// then -- only if we're a member of the entry's original organization
// locally -- moves it into that organization and assigns the collections we
// were able to map, mirroring what a human would do by hand. Entries whose
// source organization isn't available locally are left as personal-vault
// entries (a `Warning:` line is not printed for this case to avoid being
// noisy on large multi-org imports; see the final summary's "collections
// skipped" count instead).
pub(super) fn import_create_entry(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    collection_id_map: &std::collections::HashMap<String, String>,
    imported: &ImportedEntry,
) -> anyhow::Result<(usize, usize)> {
    let editable = imported_to_editable(imported);

    let (data, fields, notes) = editable_to_encrypted(&editable, None, None)?;
    let encrypted_name = crate::actions::encrypt(&imported.name, None, None)?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, None, None))
        .transpose()?;

    let folder_id = if let Some(folder_name) = imported.folder.as_deref() {
        resolve_folder_id(db, access_token, refresh_token, folder_name)?
    } else {
        None
    };

    let (tokens, new_entry_id) = rbw::actions::add(
        access_token,
        refresh_token,
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
    )?;
    if let Some(tokens) = tokens {
        access_token.clone_from(&tokens.access_token);
        db.access_token = Some(tokens.access_token);
        if let Some(new_refresh_token) = tokens.refresh_token {
            refresh_token.clone_from(&new_refresh_token);
            db.refresh_token = Some(new_refresh_token);
        }
        save_db(db)?;
    }

    let target_org = imported
        .org_id
        .as_deref()
        .filter(|org_id| db.protected_org_keys.contains_key(*org_id));

    let has_fields_or_history =
        !imported.fields.is_empty() || !imported.history.is_empty();

    if target_org.is_some() || has_fields_or_history {
        let org_id = target_org;
        let (org_data, org_fields, org_notes) =
            editable_to_encrypted(&editable, None, org_id)?;
        let org_encrypted_name =
            crate::actions::encrypt(&imported.name, None, org_id)?;
        let org_encrypted_notes = org_notes
            .as_deref()
            .map(|n| crate::actions::encrypt(n, None, org_id))
            .transpose()?;
        let history =
            imported_history_to_encrypted(&imported.history, None, org_id)?;

        if let (Some(tokens), ()) = rbw::actions::edit(
            access_token,
            refresh_token,
            &new_entry_id,
            org_id,
            None,
            &org_encrypted_name,
            &org_data,
            &org_fields,
            org_encrypted_notes.as_deref(),
            folder_id.as_deref(),
            &history,
            &rbw::db::CipherWriteMeta {
                reprompt: rbw::api::CipherRepromptType::None,
                favorite: false,
                archived_date: None,
                last_known_revision_date: None,
            },
        )? {
            access_token.clone_from(&tokens.access_token);
            db.access_token = Some(tokens.access_token);
            if let Some(new_refresh_token) = tokens.refresh_token {
                refresh_token.clone_from(&new_refresh_token);
                db.refresh_token = Some(new_refresh_token);
            }
            save_db(db)?;
        }
    }

    if target_org.is_some() {
        let resolved_collections: Vec<String> = imported
            .collection_ids
            .iter()
            .filter_map(|id| collection_id_map.get(id).cloned())
            .collect();
        if !resolved_collections.is_empty() {
            if let (Some(tokens), ()) = rbw::actions::edit_collections(
                access_token,
                refresh_token,
                &new_entry_id,
                &resolved_collections,
            )? {
                access_token.clone_from(&tokens.access_token);
                db.access_token = Some(tokens.access_token);
                if let Some(new_refresh_token) = tokens.refresh_token {
                    refresh_token.clone_from(&new_refresh_token);
                    db.refresh_token = Some(new_refresh_token);
                }
                save_db(db)?;
            }
        }
    }

    let attachment_result = if imported.attachments.is_empty() {
        Ok((0, 0))
    } else {
        crate::actions::sync()?;
        *db = load_db()?;
        *access_token = db.access_token.as_ref().unwrap().clone();
        *refresh_token = db.refresh_token.as_ref().unwrap().clone();

        let Some(final_entry) =
            db.entries.iter().find(|e| e.id == new_entry_id).cloned()
        else {
            anyhow::bail!("entry disappeared from the vault after import");
        };

        upload_imported_attachments(
            db,
            access_token,
            refresh_token,
            &final_entry,
            &imported.attachments,
            &std::collections::HashSet::new(),
        )
    }?;

    apply_imported_status(
        db,
        access_token,
        refresh_token,
        &new_entry_id,
        false,
        false,
        imported.archived,
        imported.deleted,
    )?;

    Ok(attachment_result)
}

// Updates an already-existing entry (`--overwrite`) in place: data, fields,
// notes and history are replaced, but the entry keeps its current id,
// organization, and folder (unless `imported` names a different folder) --
// import never moves an existing entry between organizations, to keep
// `--overwrite` predictable.
pub(super) fn import_overwrite_entry(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    existing: &rbw::db::Entry,
    imported: &ImportedEntry,
) -> anyhow::Result<(usize, usize)> {
    // The edit endpoint may reject trashed entries. Restore one temporarily;
    // `apply_imported_status` below reapplies the source flags afterward.
    if existing.deleted {
        apply_imported_status(
            db,
            access_token,
            refresh_token,
            &existing.id,
            existing.archived,
            true,
            existing.archived,
            false,
        )?;
    }

    let editable = imported_to_editable(imported);

    let org_id = existing.org_id.as_deref();
    let entry_key = existing.key.as_deref();
    let (data, fields, notes) =
        editable_to_encrypted(&editable, entry_key, org_id)?;
    let encrypted_name =
        crate::actions::encrypt(&imported.name, entry_key, org_id)?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, entry_key, org_id))
        .transpose()?;
    let history =
        imported_history_to_encrypted(&imported.history, entry_key, org_id)?;

    let folder_id = if let Some(folder_name) = imported.folder.as_deref() {
        resolve_folder_id(db, access_token, refresh_token, folder_name)?
    } else {
        existing.folder_id.clone()
    };

    if let (Some(tokens), ()) = rbw::actions::edit(
        access_token,
        refresh_token,
        &existing.id,
        org_id,
        entry_key,
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
        &history,
        &existing.cipher_write_meta(),
    )? {
        access_token.clone_from(&tokens.access_token);
        db.access_token = Some(tokens.access_token);
        if let Some(new_refresh_token) = tokens.refresh_token {
            refresh_token.clone_from(&new_refresh_token);
            db.refresh_token = Some(new_refresh_token);
        }
        save_db(db)?;
    }

    let attachment_result = if imported.attachments.is_empty() {
        Ok((0, 0))
    } else {
        crate::actions::sync()?;
        *db = load_db()?;
        *access_token = db.access_token.as_ref().unwrap().clone();
        *refresh_token = db.refresh_token.as_ref().unwrap().clone();

        let Some(refreshed) =
            db.entries.iter().find(|e| e.id == existing.id).cloned()
        else {
            anyhow::bail!("entry disappeared from the vault after update");
        };

        let already_attached: std::collections::HashSet<String> =
            decrypt_cipher(&refreshed).map_or_else(
                |_| std::collections::HashSet::new(),
                |d| {
                    d.attachments
                        .into_iter()
                        .filter_map(|a| a.file_name)
                        .collect()
                },
            );

        upload_imported_attachments(
            db,
            access_token,
            refresh_token,
            &refreshed,
            &imported.attachments,
            &already_attached,
        )
    }?;

    apply_imported_status(
        db,
        access_token,
        refresh_token,
        &existing.id,
        existing.archived,
        false,
        imported.archived,
        imported.deleted,
    )?;

    Ok(attachment_result)
}

// The same (name, username) key `import_vault`'s `existing_index` and the
// bulk-import path's post-creation matching both use to identify an entry
// -- factored out so the two stay in sync.
pub(super) fn imported_entry_key(
    imported: &ImportedEntry,
) -> (String, Option<String>) {
    let username = match &imported.data {
        ImportedData::Login { username, .. } => username.clone(),
        _ => None,
    };
    (imported.name.clone(), username)
}

// The pre-bulk-import creation path, one entry at a time via
// `import_create_entry` -- used directly for entries that can't safely go
// through bulk import (two entries in the same batch sharing a (name,
// username) key, which the bulk endpoints' lack of per-cipher ids can't
// disambiguate afterward), and as the fallback for a batch whose bulk call
// itself failed, or for individual entries the post-bulk verification
// couldn't find.
pub(super) fn create_entries_individually(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    collection_id_map: &std::collections::HashMap<String, String>,
    entries: &[&ImportedEntry],
    // Appended to each success line (e.g. " (recovered from a dropped bulk-
    // import entry -- already counted, not additional)") -- empty for
    // callers where an individually-created entry isn't otherwise
    // surprising, non-empty for the post-bulk-import retry, where it isn't
    // obvious without this that the entry was already part of the batch
    // total rather than an extra one.
    note: &str,
) -> (usize, Vec<(String, String)>, usize, usize) {
    if entries.is_empty() {
        return (0, Vec::new(), 0, 0);
    }

    let c = stdout_supports_color();
    let mut created = 0usize;
    let mut failed_names = Vec::new();
    let mut attachments_restored = 0usize;
    let mut attachments_failed = 0usize;

    let pb =
        item_progress_bar(u64::try_from(entries.len()).unwrap_or(u64::MAX));
    for imported in entries {
        pb.set_message(fit_to_width(&imported.name, PROGRESS_MSG_WIDTH));
        match import_create_entry(
            db,
            access_token,
            refresh_token,
            collection_id_map,
            imported,
        ) {
            Ok((restored, failed)) => {
                created += 1;
                attachments_restored += restored;
                attachments_failed += failed;
                pb_println(
                    &pb,
                    format!(
                        "{} '{}'{note}",
                        style::success("Created", c),
                        imported.name,
                    ),
                );
            }
            Err(e) => {
                pb_println(
                    &pb,
                    format!(
                        "{} failed to import '{}': {e:#}",
                        style_error("Error:", c),
                        imported.name,
                    ),
                );
                failed_names.push((imported.name.clone(), format!("{e:#}")));
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    (
        created,
        failed_names,
        attachments_restored,
        attachments_failed,
    )
}

// Bulk-creates every entry in `entries` (all destined for the same place --
// the personal vault if `org_id` is `None`, otherwise that one
// organization) via a single `/ciphers/import`(-organization) request,
// falling back to `create_entries_individually` wherever bulk import can't
// safely or actually cover an entry. Mirrors `import_create_entry`'s
// behavior exactly (same encryption, same collection/folder resolution,
// same attachment restoration) -- just batched.
//
// Two things force a per-entry fallback despite the bulk call:
// 1. Two entries in this same batch sharing a (name, username) key: the
//    bulk endpoints don't return per-cipher ids, so recovering them
//    afterward means matching newly-appeared entries back to their
//    intended import entry by that same key -- which is ambiguous if two
//    entries in the batch share one. Routed to individual creation before
//    the bulk call is even made.
// 2. An entry intended for the batch that isn't found among the newly-
//    appeared entries after syncing post-bulk-call: either the whole bulk
//    call failed outright, or the server silently dropped that one cipher
//    (Vaultwarden's import handler validates the whole batch up front, but
//    swallows a per-cipher failure during the actual creation loop).
//    Either way, retried individually rather than silently reported as
//    missing.
pub(super) fn bulk_create_batch(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    collection_id_map: &std::collections::HashMap<String, String>,
    org_id: Option<&str>,
    entries: &[&ImportedEntry],
) -> anyhow::Result<(usize, Vec<(String, String)>, usize, usize)> {
    if entries.is_empty() {
        return Ok((0, Vec::new(), 0, 0));
    }

    let c = stdout_supports_color();

    // Split off same-batch (name, username) collisions up front -- see
    // point 1 above. `dedup_seen`/`dedup_dupes` are built in one pass so a
    // key appearing 3+ times still routes every occurrence (not just the
    // 2nd-and-later) to the individual path.
    let mut dedup_seen = std::collections::HashSet::new();
    let mut dedup_dupes = std::collections::HashSet::new();
    for imported in entries {
        if !dedup_seen.insert(imported_entry_key(imported)) {
            dedup_dupes.insert(imported_entry_key(imported));
        }
    }
    let (bulk_entries, individual_entries): (Vec<_>, Vec<_>) =
        entries.iter().copied().partition(|imported| {
            !dedup_dupes.contains(&imported_entry_key(imported))
        });

    let mut created = 0usize;
    let mut failed_names = Vec::new();
    let mut attachments_restored = 0usize;
    let mut attachments_failed = 0usize;

    if !individual_entries.is_empty() {
        eprintln!(
            "{} {} entr{} share a name/username with another entry in this \
             batch -- creating {} individually to avoid ambiguity",
            style::warning("Note:", c),
            individual_entries.len(),
            if individual_entries.len() == 1 {
                "y"
            } else {
                "ies"
            },
            if individual_entries.len() == 1 {
                "it"
            } else {
                "them"
            },
        );
        let (c2, f2, ar2, af2) = create_entries_individually(
            db,
            access_token,
            refresh_token,
            collection_id_map,
            &individual_entries,
            "",
        );
        created += c2;
        failed_names.extend(f2);
        attachments_restored += ar2;
        attachments_failed += af2;
    }

    if bulk_entries.is_empty() {
        return Ok((
            created,
            failed_names,
            attachments_restored,
            attachments_failed,
        ));
    }

    // Resolve (or create) every distinct folder name referenced, once --
    // personal-vault entries only; org-owned entries never get a personal
    // folder (Vaultwarden's org-import handler clears it unconditionally).
    let mut folder_ids: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    if org_id.is_none() {
        for imported in &bulk_entries {
            if let Some(folder_name) = imported.folder.as_deref() {
                if !folder_ids.contains_key(folder_name) {
                    let id = resolve_folder_id(
                        db,
                        access_token,
                        refresh_token,
                        folder_name,
                    )?;
                    folder_ids.insert(folder_name.to_string(), id);
                }
            }
        }
    }

    let pb = item_progress_bar(
        u64::try_from(bulk_entries.len()).unwrap_or(u64::MAX),
    );
    let mut cipher_entries = Vec::with_capacity(bulk_entries.len());
    // Indices into `bulk_entries`, not `ImportedEntry` values -- `ImportedEntry`
    // doesn't derive `PartialEq`, and index identity is exact anyway.
    let mut encrypt_failed: std::collections::HashSet<usize> =
        std::collections::HashSet::new();
    for (index, imported) in bulk_entries.iter().enumerate() {
        pb.set_message(fit_to_width(&imported.name, PROGRESS_MSG_WIDTH));

        let result =
            (|| -> anyhow::Result<rbw::actions::ImportCipherEntry> {
                let editable = imported_to_editable(imported);
                let (data, fields, notes) =
                    editable_to_encrypted(&editable, None, org_id)?;
                let encrypted_name =
                    crate::actions::encrypt(&imported.name, None, org_id)?;
                let encrypted_notes = notes
                    .as_deref()
                    .map(|n| crate::actions::encrypt(n, None, org_id))
                    .transpose()?;
                let history = imported_history_to_encrypted(
                    &imported.history,
                    None,
                    org_id,
                )?;
                let folder_id = imported
                    .folder
                    .as_deref()
                    .and_then(|name| folder_ids.get(name).cloned().flatten());
                let collection_ids: Vec<String> = imported
                    .collection_ids
                    .iter()
                    .filter_map(|id| collection_id_map.get(id).cloned())
                    .collect();
                Ok(rbw::actions::ImportCipherEntry {
                    name: encrypted_name,
                    data,
                    fields,
                    notes: encrypted_notes,
                    history,
                    folder_id,
                    collection_ids,
                })
            })();

        match result {
            Ok(cipher_entry) => cipher_entries.push(cipher_entry),
            Err(e) => {
                pb_println(
                    &pb,
                    format!(
                        "{} failed to prepare '{}': {e:#}",
                        style_error("Error:", c),
                        imported.name,
                    ),
                );
                failed_names.push((imported.name.clone(), format!("{e:#}")));
                encrypt_failed.insert(index);
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    // Entries that failed to even encrypt aren't sent to the server at
    // all, and can't usefully be retried (the same encryption call would
    // just fail again) -- already recorded as failed above. `cipher_entries`
    // was built skipping the same indices, in the same relative order, so
    // it still lines up 1:1 with the filtered `bulk_entries` below.
    let bulk_entries: Vec<&ImportedEntry> = bulk_entries
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !encrypt_failed.contains(index))
        .map(|(_, imported)| imported)
        .collect();
    if bulk_entries.is_empty() {
        return Ok((
            created,
            failed_names,
            attachments_restored,
            attachments_failed,
        ));
    }

    let batch_desc = org_id.map_or_else(
        || "the personal vault".to_string(),
        |oid| format!("organization '{oid}'"),
    );
    eprintln!(
        "{} bulk-creating {} entr{} in {batch_desc}...",
        style::section("Importing:", c),
        bulk_entries.len(),
        if bulk_entries.len() == 1 { "y" } else { "ies" }
    );

    let bulk_result = org_id.map_or_else(
        || {
            rbw::actions::import_ciphers(
                access_token,
                refresh_token,
                &cipher_entries,
            )
        },
        |oid| {
            rbw::actions::import_organization_ciphers(
                access_token,
                refresh_token,
                oid,
                &cipher_entries,
            )
        },
    );

    match bulk_result {
        Err(e) => {
            // The batch call itself failed outright (network error, or the
            // server rejected the whole batch during its up-front
            // validation pass) -- fall back to individual creation for
            // every entry in it, rather than losing the batch.
            eprintln!(
                "{} bulk import failed ({e:#}); falling back to one-by-one \
                 creation for this batch",
                style_error("Warning:", c),
            );
            let (c2, f2, ar2, af2) = create_entries_individually(
                db,
                access_token,
                refresh_token,
                collection_id_map,
                &bulk_entries,
                "",
            );
            return Ok((
                created + c2,
                {
                    failed_names.extend(f2);
                    failed_names
                },
                attachments_restored + ar2,
                attachments_failed + af2,
            ));
        }
        Ok((tokens, ())) => {
            if let Some(tokens) = tokens {
                access_token.clone_from(&tokens.access_token);
                db.access_token = Some(tokens.access_token);
                if let Some(new_refresh_token) = tokens.refresh_token {
                    refresh_token.clone_from(&new_refresh_token);
                    db.refresh_token = Some(new_refresh_token);
                }
                save_db(db)?;
            }
        }
    }

    // The bulk endpoints return no per-cipher ids (and don't even
    // guarantee every cipher in the batch was actually created --
    // Vaultwarden silently drops one that fails during its per-cipher
    // creation loop after the batch-level pre-check passes), and
    // attachments need the new cipher's id regardless -- so always resync
    // and match every intended entry back to its real id by (name,
    // username), same key `existing_index` uses.
    let before_ids: std::collections::HashSet<String> =
        db.entries.iter().map(|e| e.id.clone()).collect();
    crate::actions::sync()?;
    *db = load_db()?;
    *access_token = db.access_token.as_ref().unwrap().clone();
    *refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let new_entries: Vec<rbw::db::Entry> = db
        .entries
        .iter()
        .filter(|e| !before_ids.contains(&e.id))
        .cloned()
        .collect();

    let new_index: std::collections::HashMap<
        (String, Option<String>),
        rbw::db::Entry,
    > = {
        let mut requests = BatchRequests::new();
        let plans: Vec<SearchCipherPlan> = new_entries
            .iter()
            .map(|entry| SearchCipherPlan::build(entry, &mut requests))
            .collect();
        let results = if requests.is_empty() {
            Vec::new()
        } else {
            crate::actions::decrypt_batch(requests.into_vec())?
        };
        let mut index = std::collections::HashMap::new();
        for (entry, plan) in new_entries.iter().zip(plans) {
            if let Ok(decrypted) = plan.resolve(&results) {
                index.insert((decrypted.name, decrypted.user), entry.clone());
            }
        }
        index
    };

    let mut retry: Vec<&ImportedEntry> = Vec::new();
    let pb = item_progress_bar(
        u64::try_from(bulk_entries.len()).unwrap_or(u64::MAX),
    );
    for imported in &bulk_entries {
        pb.set_message(fit_to_width(&imported.name, PROGRESS_MSG_WIDTH));

        let Some(new_entry) =
            new_index.get(&imported_entry_key(imported)).cloned()
        else {
            retry.push(imported);
            pb.inc(1);
            continue;
        };

        if !imported.attachments.is_empty() {
            match upload_imported_attachments(
                db,
                access_token,
                refresh_token,
                &new_entry,
                &imported.attachments,
                &std::collections::HashSet::new(),
            ) {
                Ok((restored, failed)) => {
                    attachments_restored += restored;
                    attachments_failed += failed;
                }
                Err(e) => {
                    pb_println(
                        &pb,
                        format!(
                        "{} failed to restore attachments for '{}': {e:#}",
                        style_error("Error:", c),
                        imported.name,
                    ),
                    );
                    attachments_failed += imported.attachments.len();
                }
            }
        }

        match apply_imported_status(
            db,
            access_token,
            refresh_token,
            &new_entry.id,
            new_entry.archived,
            new_entry.deleted,
            imported.archived,
            imported.deleted,
        ) {
            Ok(()) => {
                created += 1;
                pb_println(
                    &pb,
                    format!(
                        "{} '{}'",
                        style::success("Created", c),
                        imported.name,
                    ),
                );
            }
            Err(e) => {
                pb_println(
                    &pb,
                    format!(
                        "{} failed to restore status for '{}': {e:#}",
                        style_error("Error:", c),
                        imported.name,
                    ),
                );
                failed_names.push((imported.name.clone(), format!("{e:#}")));
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    if !retry.is_empty() {
        eprintln!(
            "{} {} of the {} entr{} above weren't found after the bulk \
             import -- retrying {} individually (already counted in the \
             total, not additional)",
            style::warning("Note:", c),
            retry.len(),
            bulk_entries.len(),
            if bulk_entries.len() == 1 { "y" } else { "ies" },
            if retry.len() == 1 { "it" } else { "them" },
        );
        let (c2, f2, ar2, af2) = create_entries_individually(
            db,
            access_token,
            refresh_token,
            collection_id_map,
            &retry,
            " (recovered)",
        );
        created += c2;
        failed_names.extend(f2);
        attachments_restored += ar2;
        attachments_failed += af2;
    }

    Ok((
        created,
        failed_names,
        attachments_restored,
        attachments_failed,
    ))
}

pub fn import(
    file: Option<&std::path::Path>,
    format: crate::import_bitwarden::ImportFormat,
    decrypt: bool,
    decrypt_passphrase: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    overwrite: bool,
) -> anyhow::Result<()> {
    // Resolve the passphrase up front so `--decrypt`'s prompt happens
    // before any input is read (the prompt goes to /dev/tty, so this works
    // even when the archive itself arrives on stdin).
    let decrypt_passphrase =
        resolve_import_passphrase(decrypt, decrypt_passphrase)?;
    let raw = read_import_input(file)?;

    let detected = match format {
        crate::import_bitwarden::ImportFormat::Auto => {
            crate::import_bitwarden::detect_format(&raw)?
        }
        crate::import_bitwarden::ImportFormat::Rbw => {
            crate::import_bitwarden::DetectedFormat::Rbw
        }
        crate::import_bitwarden::ImportFormat::BitwardenJson => {
            crate::import_bitwarden::DetectedFormat::BitwardenJson
        }
        crate::import_bitwarden::ImportFormat::BitwardenEncryptedJson => {
            crate::import_bitwarden::DetectedFormat::BitwardenEncryptedJson
        }
        crate::import_bitwarden::ImportFormat::BitwardenZip => {
            crate::import_bitwarden::DetectedFormat::BitwardenZip
        }
    };

    let vault: ImportedVault = match detected {
        crate::import_bitwarden::DetectedFormat::Rbw => {
            let decrypt_passphrase = prompt_for_encrypted_export_if_needed(
                &raw,
                decrypt_passphrase,
            );
            let json_text =
                load_import_json(&raw, decrypt_passphrase.as_deref())?;
            serde_json::from_str(&json_text).context(
                "failed to parse import data (expected the JSON shape \
                 produced by `rbw export`)",
            )?
        }
        crate::import_bitwarden::DetectedFormat::BitwardenJson => {
            let text = std::str::from_utf8(&raw)
                .context("Bitwarden JSON export is not valid UTF-8")?;
            let bw = crate::import_bitwarden::parse_bitwarden_json(text)?;
            bw_vault_to_imported(bw, None)
        }
        crate::import_bitwarden::DetectedFormat::BitwardenEncryptedJson => {
            let passphrase = decrypt_passphrase.as_deref().context(
                "this looks like a Bitwarden \"Encrypted JSON\" export; \
                 pass --decrypt or --decrypt-passphrase",
            )?;
            let text = crate::import_bitwarden::decrypt_encrypted_json(
                &raw, passphrase,
            )?;
            let bw = crate::import_bitwarden::parse_bitwarden_json(&text)?;
            bw_vault_to_imported(bw, None)
        }
        crate::import_bitwarden::DetectedFormat::BitwardenZip => {
            let (bw, attachments) = crate::import_bitwarden::parse_zip(&raw)?;
            bw_vault_to_imported(bw, Some(attachments))
        }
    };

    import_vault(vault, collection, org, overwrite)
}

// Creates/updates entries and collections in the currently active account
// from an already-parsed `ImportedVault` -- the part of `import` that
// doesn't care which export format the data originally came from. Also
// reused by `mirror_vault`, which builds an `ImportedVault` in memory (via
// `exported_vault_to_bw` + `bw_vault_to_imported`) from a *source account's*
// vault rather than parsing it from a file, but otherwise wants the exact
// same create-or-skip-or-overwrite/collection-creation/attachment-upload
// behavior and summary output.
pub(super) fn import_vault(
    mut vault: ImportedVault,
    collection: Option<&str>,
    dest_org: Option<&str>,
    overwrite: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    // Case-insensitive by name so the created/updated/skipped log (and the
    // progress bar below) reads in a human-sensible order instead of
    // whatever order the source vault happened to return entries in.
    vault.entries.sort_by_cached_key(|e| e.name.to_lowercase());

    let mut db = load_db()?;
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let c = stdout_supports_color();

    // `--dest-org` only disambiguates a `--collection` name that matches
    // more than one collection across different orgs (mirroring how
    // `resolve_collection`'s own `org_id` scoping already works elsewhere);
    // it never restricts anything on its own.
    let dest_org_id = dest_org
        .map(|needle| {
            resolve_organization(&db.organizations, needle)
                .map(|org| org.id.clone())
        })
        .transpose()?;

    // `--collection` redirects every entry into one existing collection,
    // ignoring whatever organization/collection/folder metadata the export
    // carries -- so none of the export's own collections need to be
    // created, and every entry's destination is the same fixed org/
    // collection pair.
    let dest_collection = if let Some(needle) = collection {
        let decrypted = decrypt_collections(&db)?;
        let found =
            resolve_collection(&decrypted, needle, dest_org_id.as_deref())?;
        Some((found.id.clone(), found.org_id.clone()))
    } else {
        None
    };
    if let Some((dest_id, dest_org_id)) = &dest_collection {
        vault.collections.clear();
        for entry in &mut vault.entries {
            entry.org_id = Some(dest_org_id.clone());
            entry.collection_ids = vec![dest_id.clone()];
        }
    }

    let mut collections_created = 0usize;
    let mut collections_reused = 0usize;
    let mut collections_unavailable = 0usize;

    // Existing collections, decrypted once up front: (collection, plaintext
    // name).
    let mut existing_collections: Vec<(rbw::db::Collection, String)> = db
        .collections
        .iter()
        .cloned()
        .map(|col| {
            let name =
                crate::actions::decrypt(&col.name, None, Some(&col.org_id))?;
            Ok((col, name))
        })
        .collect::<anyhow::Result<_>>()?;

    // Maps an imported collection id to the id it has (or now has) in this
    // vault.
    let mut collection_id_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // `vault.collections` is empty when `--collection` was given (nothing
    // to create/reuse), so seed the map directly with the one destination
    // collection every entry now points at.
    if let Some((dest_id, _)) = &dest_collection {
        collection_id_map.insert(dest_id.clone(), dest_id.clone());
    }

    for imported_col in &vault.collections {
        if !db.protected_org_keys.contains_key(&imported_col.org_id) {
            // We're not a member of this organization locally, so we can't
            // create (or assign entries to) its collections.
            collections_unavailable += 1;
            continue;
        }

        if let Some((existing, _)) =
            existing_collections.iter().find(|(col, name)| {
                col.org_id == imported_col.org_id
                    && *name == imported_col.name
            })
        {
            if let Some(orig_id) = &imported_col.id {
                collection_id_map
                    .insert(orig_id.clone(), existing.id.clone());
            }
            collections_reused += 1;
            continue;
        }

        let encrypted_name = crate::actions::encrypt(
            &imported_col.name,
            None,
            Some(&imported_col.org_id),
        )?;
        match rbw::actions::create_collection(
            &access_token,
            &refresh_token,
            &imported_col.org_id,
            &encrypted_name,
        ) {
            Ok((tokens, new_id)) => {
                if let Some(tokens) = tokens {
                    access_token.clone_from(&tokens.access_token);
                    db.access_token = Some(tokens.access_token);
                    if let Some(new_refresh_token) = tokens.refresh_token {
                        refresh_token.clone_from(&new_refresh_token);
                        db.refresh_token = Some(new_refresh_token);
                    }
                    save_db(&db)?;
                }
                if let Some(orig_id) = &imported_col.id {
                    collection_id_map.insert(orig_id.clone(), new_id.clone());
                }
                existing_collections.push((
                    rbw::db::Collection {
                        id: new_id,
                        org_id: imported_col.org_id.clone(),
                        name: encrypted_name,
                    },
                    imported_col.name.clone(),
                ));
                collections_created += 1;
            }
            Err(e) => {
                eprintln!(
                    "{} failed to create collection '{}': {e:#}",
                    style::warning("Warning:", c),
                    imported_col.name,
                );
            }
        }
    }

    if collections_created > 0 {
        crate::actions::sync()?;
        db = load_db()?;
        access_token = db.access_token.as_ref().unwrap().clone();
        refresh_token = db.refresh_token.as_ref().unwrap().clone();
    }

    // Index existing entries by (name, username) so already-imported
    // entries can be detected without recreating them. Login-typed entries
    // are additionally keyed on their username, so two different logins
    // that happen to share a name don't collide with each other. When
    // `--collection`/`--dest-collection` names one destination collection,
    // this is scoped to just that collection's own members -- otherwise an
    // unrelated entry with the same name/username sitting in some other
    // collection (or the personal vault) would count as "already there"
    // and get skipped, leaving the target collection missing it entirely.
    let existing_index = {
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
        let mut index: std::collections::HashMap<
            (String, Option<String>),
            rbw::db::Entry,
        > = std::collections::HashMap::new();
        for (entry, plan) in db.entries.iter().zip(plans) {
            if let Some((dest_id, _)) = &dest_collection {
                if !entry.collection_ids.contains(dest_id) {
                    continue;
                }
            }
            if let Ok(decrypted) = plan.resolve(&results) {
                index.insert((decrypted.name, decrypted.user), entry.clone());
            }
        }
        index
    };

    let mut entries_created = 0usize;
    let mut entries_updated = 0usize;
    let mut entries_skipped = 0usize;
    let mut entries_failed = 0usize;
    let mut attachments_restored = 0usize;
    let mut attachments_failed = 0usize;
    let mut skipped_names: Vec<String> = Vec::new();
    let mut failed_names: Vec<(String, String)> = Vec::new();

    // Classify every entry up front: already-exists (skip, or overwrite --
    // handled immediately below, one at a time, same as ever, since there's
    // no bulk *update* endpoint) vs new (grouped by destination -- the
    // personal vault, or one bucket per target organization -- so each
    // group can go through a single `/ciphers/import`(-organization) bulk
    // request in `bulk_create_batch` below instead of one create call per
    // entry).
    let mut to_overwrite: Vec<(&ImportedEntry, rbw::db::Entry)> = Vec::new();
    let mut personal_batch: Vec<&ImportedEntry> = Vec::new();
    let mut org_batches: std::collections::HashMap<
        String,
        Vec<&ImportedEntry>,
    > = std::collections::HashMap::new();

    for imported in &vault.entries {
        let key = imported_entry_key(imported);

        if let Some(existing) = existing_index.get(&key) {
            if overwrite {
                to_overwrite.push((imported, existing.clone()));
            } else {
                eprintln!(
                    "{} '{}' (already exists; use --overwrite to replace)",
                    style::warning("Skipped", c),
                    imported.name,
                );
                entries_skipped += 1;
                skipped_names.push(imported.name.clone());
            }
            continue;
        }

        let target_org = imported
            .org_id
            .as_deref()
            .filter(|org_id| db.protected_org_keys.contains_key(*org_id));
        match target_org {
            Some(org_id) => {
                org_batches
                    .entry(org_id.to_string())
                    .or_default()
                    .push(imported);
            }
            None => personal_batch.push(imported),
        }
    }

    if !to_overwrite.is_empty() {
        let pb = item_progress_bar(
            u64::try_from(to_overwrite.len()).unwrap_or(u64::MAX),
        );
        for (imported, existing) in &to_overwrite {
            pb.set_message(fit_to_width(&imported.name, PROGRESS_MSG_WIDTH));
            match import_overwrite_entry(
                &mut db,
                &mut access_token,
                &mut refresh_token,
                existing,
                imported,
            ) {
                Ok((restored, failed)) => {
                    attachments_restored += restored;
                    attachments_failed += failed;
                    entries_updated += 1;
                    pb_println(
                        &pb,
                        format!(
                            "{} '{}'",
                            style::success("Updated", c),
                            imported.name,
                        ),
                    );
                }
                Err(e) => {
                    pb_println(
                        &pb,
                        format!(
                            "{} failed to import '{}': {e:#}",
                            style_error("Error:", c),
                            imported.name,
                        ),
                    );
                    entries_failed += 1;
                    failed_names
                        .push((imported.name.clone(), format!("{e:#}")));
                }
            }
            pb.inc(1);
        }
        pb.finish_and_clear();
    }

    if !personal_batch.is_empty() {
        let (created, failed, restored, att_failed) = bulk_create_batch(
            &mut db,
            &mut access_token,
            &mut refresh_token,
            &collection_id_map,
            None,
            &personal_batch,
        )?;
        entries_created += created;
        entries_failed += failed.len();
        failed_names.extend(failed);
        attachments_restored += restored;
        attachments_failed += att_failed;
    }

    for (org_id, batch) in &org_batches {
        let (created, failed, restored, att_failed) = bulk_create_batch(
            &mut db,
            &mut access_token,
            &mut refresh_token,
            &collection_id_map,
            Some(org_id.as_str()),
            batch,
        )?;
        entries_created += created;
        entries_failed += failed.len();
        failed_names.extend(failed);
        attachments_restored += restored;
        attachments_failed += att_failed;
    }

    eprintln!();
    eprintln!("{}", style::section("Import summary:", c));
    eprintln!(
        "  entries created:      {}",
        style::success(&entries_created.to_string(), c)
    );
    if entries_updated > 0 {
        eprintln!(
            "  entries updated:      {}",
            style::success(&entries_updated.to_string(), c)
        );
    }
    if entries_skipped > 0 {
        eprintln!(
            "  entries skipped:      {}",
            style::warning(&entries_skipped.to_string(), c)
        );
    }
    if entries_failed > 0 {
        eprintln!(
            "  entries failed:       {}",
            style_error(&entries_failed.to_string(), c)
        );
    }
    if attachments_restored > 0 {
        eprintln!(
            "  attachments restored: {}",
            style::success(&attachments_restored.to_string(), c)
        );
    }
    if attachments_failed > 0 {
        eprintln!(
            "  attachments failed:   {}",
            style_error(&attachments_failed.to_string(), c)
        );
    }
    if collections_created > 0 || collections_reused > 0 {
        eprintln!(
            "  collections created:  {collections_created} (reused \
             {collections_reused})"
        );
    }
    if collections_unavailable > 0 {
        eprintln!(
            "  collections skipped:  {} (organization not available \
             locally)",
            style::warning(&collections_unavailable.to_string(), c)
        );
    }

    if !skipped_names.is_empty() {
        eprintln!();
        eprintln!("{}", style::section("Skipped entries:", c));
        for name in &skipped_names {
            eprintln!("  {}", style::warning(name, c));
        }
    }
    if !failed_names.is_empty() {
        eprintln!();
        eprintln!("{}", style::section("Failed entries:", c));
        for (name, err) in &failed_names {
            eprintln!("  {}: {err}", style_error(name, c));
        }
    }

    if entries_failed > 0 {
        anyhow::bail!(
            "{entries_failed} entr{} failed to import",
            if entries_failed == 1 { "y" } else { "ies" }
        );
    }

    Ok(())
}
