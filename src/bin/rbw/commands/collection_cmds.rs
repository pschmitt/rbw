use super::*;

// The scoped counterpart to `purge_vault` for `mirror --purge-dest
// --dest-collection`: permanently deletes every entry currently assigned to
// `needle` (name or ID) in the active account, via the same per-cipher
// `delete_permanently` primitive `rbw remove --force` uses -- not the
// server's whole-vault purge endpoint, which explicitly skips org/
// collection-owned ciphers and so can't do this. Entries outside this
// collection, and the collection itself, are left untouched.
pub(super) fn purge_collection_entries(
    needle: &str,
    dest_org: Option<&str>,
) -> anyhow::Result<()> {
    let mut db = load_db()?;
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let dest_org_id = dest_org
        .map(|needle| {
            resolve_organization(&db.organizations, needle)
                .map(|org| org.id.clone())
        })
        .transpose()?;

    let decrypted_collections = decrypt_collections(&db)?;
    let collection = resolve_collection(
        &decrypted_collections,
        needle,
        dest_org_id.as_deref(),
    )?;
    let collection_id = collection.id.clone();
    let collection_name = collection.name.clone();

    let targets: Vec<rbw::db::Entry> = db
        .entries
        .iter()
        .filter(|e| e.collection_ids.contains(&collection_id))
        .cloned()
        .collect();

    let c = stdout_supports_color();
    if targets.is_empty() {
        eprintln!(
            "{} no entries currently in '{collection_name}' -- nothing to \
             purge",
            style::warning("Note:", c)
        );
        return Ok(());
    }

    eprintln!(
        "{} permanently deleting {} entr{} from '{collection_name}'...",
        style_error("Purging:", c),
        targets.len(),
        if targets.len() == 1 { "y" } else { "ies" }
    );

    let mut failed = 0usize;
    let pb =
        item_progress_bar(u64::try_from(targets.len()).unwrap_or(u64::MAX));
    for entry in &targets {
        match rbw::actions::delete_permanently(
            &access_token,
            &refresh_token,
            &entry.id,
        ) {
            Ok((Some(tokens), ())) => {
                access_token.clone_from(&tokens.access_token);
                db.access_token = Some(tokens.access_token);
                if let Some(new_refresh_token) = tokens.refresh_token {
                    refresh_token.clone_from(&new_refresh_token);
                    db.refresh_token = Some(new_refresh_token);
                }
                save_db(&db)?;
            }
            Ok((None, ())) => {}
            Err(e) => {
                pb_println(
                    &pb,
                    format!(
                    "{} failed to delete an entry in '{collection_name}': \
                     {e:#}",
                    style_error("Error:", c)
                ),
                );
                failed += 1;
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    crate::actions::sync()?;

    if failed > 0 {
        anyhow::bail!(
            "{failed} entr{} in '{collection_name}' failed to purge; \
             destination may be in a mixed state",
            if failed == 1 { "y" } else { "ies" }
        );
    }

    Ok(())
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct MirrorConfig {
    pub(super) mirrors: Vec<MirrorConfigEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct MirrorConfigEntry {
    pub(super) from: String,
    pub(super) to: String,
    #[serde(default)]
    pub(super) collection: Option<String>,
    #[serde(default)]
    pub(super) org_id: Option<String>,
    #[serde(default)]
    pub(super) dest_collection: Option<String>,
    #[serde(default)]
    pub(super) dest_org: Option<String>,
    #[serde(default)]
    pub(super) attachments: bool,
    #[serde(default)]
    pub(super) overwrite: bool,
    #[serde(default)]
    pub(super) purge_dest: bool,
    // When true, a missing source collection means "mirror the whole source
    // vault" instead. This lets callers describe a destination collection
    // that is either a same-named source collection or a full-vault copy.
    #[serde(default)]
    pub(super) fallback_to_whole_vault: bool,
}

pub(super) fn load_mirror_config(
    path: &std::path::Path,
) -> anyhow::Result<MirrorConfig> {
    let contents = std::fs::read_to_string(path).with_context(|| {
        format!("failed to read mirror config {}", path.display())
    })?;
    let config = if matches!(
        path.extension().and_then(std::ffi::OsStr::to_str),
        Some("yaml" | "yml")
    ) {
        serde_yaml::from_str(&contents).with_context(|| {
            format!("failed to parse mirror config {}", path.display())
        })?
    } else {
        serde_json::from_str(&contents).with_context(|| {
            format!("failed to parse mirror config {}", path.display())
        })?
    };
    Ok(config)
}

pub fn mirror_vault_config(
    path: &std::path::Path,
    yes: bool,
    password: Option<&str>,
    dry_run: bool,
) -> anyhow::Result<()> {
    let config = load_mirror_config(path)?;
    if config.mirrors.is_empty() {
        anyhow::bail!("mirror config {} contains no mirrors", path.display());
    }

    for (index, mirror) in config.mirrors.iter().enumerate() {
        mirror_vault_config_entry(
            mirror,
            yes,
            password.map(std::string::ToString::to_string),
            dry_run,
        )
        .with_context(|| {
            format!("mirror config entry {} failed", index + 1)
        })?;
    }

    Ok(())
}

pub(super) fn mirror_vault_config_entry(
    mirror: &MirrorConfigEntry,
    yes: bool,
    password: Option<String>,
    dry_run: bool,
) -> anyhow::Result<()> {
    let (collection, purge_dest) =
        if mirror.fallback_to_whole_vault && mirror.collection.is_some() {
            crate::actions::set_active_account(Some(mirror.from.clone()))?;
            unlock(None, None)?;
            if source_collection_is_present(
                mirror.collection.as_deref().unwrap(),
                mirror.org_id.as_deref(),
            )? {
                (mirror.collection.as_deref(), false)
            } else {
                (None, mirror.purge_dest)
            }
        } else {
            (mirror.collection.as_deref(), mirror.purge_dest)
        };

    mirror_vault_with_options(
        &mirror.from,
        &mirror.to,
        collection,
        mirror.org_id.as_deref(),
        mirror.dest_collection.as_deref(),
        mirror.dest_org.as_deref(),
        mirror.attachments,
        mirror.overwrite,
        purge_dest,
        yes,
        password,
        dry_run,
        true,
    )
}

// `rbw move`: moves one entry to another configured account. The entry is
// recreated in the destination through the same export -> import pipeline
// `rbw mirror` uses (attachments included unless disabled), then the
// original goes to the source account's trash, where `rbw restore` can
// bring it back. The original is only trashed once the destination
// verifiably gained a new entry with the same name: `import_vault` skips
// entries whose name/username already exist there, and a skipped copy
// must never cost the original.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MoveSource {
    // The original goes to its account's trash (restorable).
    Trash,
    // The original is deleted permanently.
    Delete,
    // The original stays: a copy to another account.
    Keep,
}

#[allow(clippy::too_many_arguments)]
pub fn move_entry(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    to: &str,
    attachments: bool,
    source: MoveSource,
    yes: bool,
) -> anyhow::Result<()> {
    let target_accounts =
        list_target_accounts(false, rbw::config::ExcludeContext::Get, true)?;
    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let (from, entry, decrypted) = find_entry_multi(
        &target_accounts,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{needle_str}'"))?;
    move_entry_by_id(
        &from,
        &entry.id,
        &decrypted.name,
        to,
        attachments,
        source,
        yes,
    )
}

pub fn move_entry_by_id(
    from: &str,
    id: &str,
    name: &str,
    to: &str,
    attachments: bool,
    source: MoveSource,
    yes: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(from != to, "the entry is already in account '{to}'");
    let config = rbw::config::Config::load()?;
    config.account(Some(to))?;
    let c = stdout_supports_color();
    let fate = match source {
        MoveSource::Trash => "The original goes to the trash",
        MoveSource::Delete => "The original is deleted permanently",
        MoveSource::Keep => "The original is kept",
    };
    if !yes
        && !confirm(&format!(
            "{} {} from '{from}' to '{to}'? {fate}.",
            if source == MoveSource::Keep {
                "Copy"
            } else {
                "Move"
            },
            style::name(name, c)
        ))?
    {
        return Ok(());
    }

    crate::actions::set_active_account(Some(from.to_string()))?;
    unlock(None, None)?;
    let vault = build_exported_vault_matching(
        attachments,
        None,
        None,
        true,
        false,
        Some(id),
    )?;
    anyhow::ensure!(
        vault.entries.len() == 1,
        "entry {id} is not a live entry of account '{from}'"
    );

    crate::actions::set_active_account(Some(to.to_string()))?;
    unlock(None, None)?;
    let before: std::collections::HashSet<String> =
        load_db()?.entries.into_iter().map(|e| e.id).collect();
    let (bw, attachments_flat) = exported_vault_to_bw(&vault);
    let attachments_map = attachments.then(|| {
        let mut map: std::collections::HashMap<
            String,
            Vec<crate::import_bitwarden::ZipAttachment>,
        > = std::collections::HashMap::new();
        for (name, file_name, data) in attachments_flat {
            map.entry(crate::import_bitwarden::sanitize_zip_folder_name(
                &name,
            ))
            .or_default()
            .push(crate::import_bitwarden::ZipAttachment { file_name, data });
        }
        map
    });
    import_vault(
        bw_vault_to_imported(bw, attachments_map),
        None,
        None,
        false,
    )?;
    crate::actions::sync()?;
    let created = load_db()?.entries.into_iter().any(|e| {
        !before.contains(&e.id)
            && crate::actions::decrypt(
                &e.name,
                e.key.as_deref(),
                e.org_id.as_deref(),
            )
            .is_ok_and(|n| n == name)
    });
    anyhow::ensure!(
        created,
        "'{name}' was not created in '{to}' (an entry with the same name \
         and username may already be there); the original was left \
         untouched in '{from}'"
    );

    if source == MoveSource::Keep {
        eprintln!(
            "{} Copied {} to '{to}'; the original is still in '{from}'.",
            style::success("✓", c),
            style::name(name, c)
        );
        return Ok(());
    }
    crate::actions::set_active_account(Some(from.to_string()))?;
    let mut db = load_db()?;
    let (access_token, refresh_token) = (
        db.access_token.clone().unwrap(),
        db.refresh_token.clone().unwrap(),
    );
    let rotated = if source == MoveSource::Delete {
        rbw::actions::delete_permanently(&access_token, &refresh_token, id)?
    } else {
        rbw::actions::remove(&access_token, &refresh_token, id)?
    };
    if let (Some(tokens), ()) = rotated {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }
    crate::actions::sync()?;
    eprintln!(
        "{} Moved {} to '{to}'; the original was {}.",
        style::success("✓", c),
        style::name(name, c),
        if source == MoveSource::Delete {
            format!("deleted from '{from}'")
        } else {
            format!("moved to '{from}''s trash")
        }
    );
    Ok(())
}

// `rbw mirror --from A --to B`: copies vault contents from one already-
// configured local account to another, reusing the same export/import
// conversion machinery `rbw export`/`rbw import` are built on, rather than
// reimplementing the separate-CLI-logins-plus-temp-files pipeline the
// standalone `bw-sync.sh` migration script this replaces used. Named
// `mirror` rather than `sync` -- `rbw sync` already means "pull the latest
// vault from the server for the active account", unrelated to copying
// between two accounts.
//
// Builds an `ExportedVault` from the source account entirely in memory
// (`build_exported_vault`, optionally scoped to a single `--collection`
// and/or `--org-id`), converts it through the same `exported_vault_to_bw`
// -> `bw_vault_to_imported` pipeline `rbw export --format bitwarden-json`
// and `rbw import` already use, then feeds the result through the same
// `import_vault` entry-creation logic `rbw import` uses -- so behavior
// (skip-vs-overwrite matching, collection creation/reuse, personal-vault
// fallback for organizations the destination isn't a member of, the
// per-entry summary) is identical to importing an export file, without a
// file ever touching disk.
//
// `--purge-dest` wipes the destination first. For a whole-vault mirror (no
// `--collection`/`--org-id`) it goes through the same `purge_vault`/
// `Action::PurgeVault` path `rbw purge-vault` uses; combined with
// `--dest-collection` it instead permanently deletes only the entries
// currently assigned to that one destination collection (`purge_vault`'s
// own server-side endpoint explicitly skips org/collection-owned ciphers,
// so it can't do this), leaving the rest of the destination untouched.
#[allow(clippy::too_many_arguments)]
pub fn mirror_vault(
    from: &str,
    to: &str,
    collection: Option<&str>,
    org_id: Option<&str>,
    dest_collection: Option<&str>,
    dest_org: Option<&str>,
    attachments: bool,
    overwrite: bool,
    purge_dest: bool,
    yes: bool,
    password: Option<String>,
    dry_run: bool,
) -> anyhow::Result<()> {
    mirror_vault_with_options(
        from,
        to,
        collection,
        org_id,
        dest_collection,
        dest_org,
        attachments,
        overwrite,
        purge_dest,
        yes,
        password,
        dry_run,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn mirror_vault_with_options(
    from: &str,
    to: &str,
    collection: Option<&str>,
    org_id: Option<&str>,
    dest_collection: Option<&str>,
    dest_org: Option<&str>,
    attachments: bool,
    overwrite: bool,
    purge_dest: bool,
    yes: bool,
    password: Option<String>,
    dry_run: bool,
    create_destination_collection: bool,
) -> anyhow::Result<()> {
    if from == to {
        anyhow::bail!("--from and --to must name different accounts");
    }

    if purge_dest && (collection.is_some() || org_id.is_some()) {
        anyhow::bail!(
            "--purge-dest only supports a whole-vault mirror right now; \
             it can't be combined with --collection/--org-id (there's no \
             scoped-purge implementation yet). Run without --purge-dest, \
             or without --collection/--org-id."
        );
    }

    let config = rbw::config::Config::load()?;
    let from_account = config.account(Some(from))?;
    let to_account = config.account(Some(to))?;

    let c = stdout_supports_color();

    // Gather the source vault before asking for confirmation, so the
    // preview shows real counts instead of vague "everything" language.
    crate::actions::set_active_account(Some(from.to_string()))?;
    unlock(None, None)?;
    let vault =
        build_exported_vault(attachments, collection, org_id, true, false)?;

    let entry_count = vault.entries.len();
    let collection_count = vault.collections.len();
    let plural = if entry_count == 1 { "y" } else { "ies" };

    eprintln!("{}", style::section("Mirror plan:", c));
    eprintln!(
        "  from: {} ({})",
        style::name(from, c),
        from_account
            .email
            .as_ref()
            .and_then(|v| v.resolve().ok())
            .unwrap_or_else(|| "no email set".to_string())
    );
    eprintln!(
        "  to:   {} ({})",
        style::name(to, c),
        to_account
            .email
            .as_ref()
            .and_then(|v| v.resolve().ok())
            .unwrap_or_else(|| "no email set".to_string())
    );
    if let Some(needle) = collection {
        eprintln!("  scope: collection '{needle}'");
    } else if let Some(org) = org_id {
        eprintln!("  scope: organization '{org}'");
    } else {
        eprintln!("  scope: entire vault");
    }
    if let Some(needle) = dest_org {
        eprintln!("  destination organization: '{needle}'");
    }
    if let Some(needle) = dest_collection {
        eprintln!("  destination collection: '{needle}'");
    }
    eprintln!(
        "  entries to copy: {entry_count} ({collection_count} \
         collection(s))"
    );
    if attachments {
        eprintln!("  attachments: included");
    }
    eprintln!(
        "  existing entries at destination: {}",
        if overwrite {
            "will be overwritten"
        } else {
            "will be skipped"
        }
    );
    if purge_dest {
        if let Some(needle) = dest_collection {
            eprintln!(
                "  {} destination collection '{needle}' (rest of the \
                 destination untouched)",
                style_error("Purge:", c)
            );
        } else {
            eprintln!(
                "  {} destination's entire personal vault",
                style_error("Purge:", c)
            );
        }
    }

    if dry_run {
        eprintln!(
            "\n{} no changes made; the destination account was never \
             touched.",
            style::success("Dry run:", c)
        );
        return Ok(());
    }

    if !yes {
        let prompt = if purge_dest {
            let purge_desc = dest_collection.map_or_else(
                || format!("purge '{to}'"),
                |needle| format!("purge collection '{needle}' in '{to}'"),
            );
            format!(
                "{} this will {purge_desc} and then copy {entry_count} \
                 entr{plural} from '{from}'. This cannot be undone! \
                 Continue?",
                style_error("DANGER:", c),
            )
        } else {
            format!(
                "Copy {entry_count} entr{plural} from '{from}' to '{to}'?"
            )
        };
        if !confirm(&prompt)? {
            return Ok(());
        }
    }

    crate::actions::set_active_account(Some(to.to_string()))?;
    unlock(None, None)?;

    if create_destination_collection {
        if let Some(destination_collection) = dest_collection {
            ensure_destination_collection(destination_collection, dest_org)?;
        }
    }

    if purge_dest {
        if let Some(needle) = dest_collection {
            // Scoped purge: no master-password re-proof needed here (unlike
            // the whole-vault path below) since it's just a loop of ordinary
            // per-cipher permanent deletes, the same primitive `rbw remove
            // --force` uses.
            purge_collection_entries(needle, dest_org)?;
        } else {
            // Already confirmed above (the whole-mirror confirmation covers
            // it), so pass `yes: true` to skip `purge_vault`'s own prompt --
            // but it still requires the master-password re-proof, exactly
            // like a standalone `rbw purge-vault` (`--stdin`-suppliable the
            // same way).
            purge_vault(true, password)?;
        }
    }

    let (bw, attachments_flat) = exported_vault_to_bw(&vault);

    let attachments_map = if attachments {
        let mut map: std::collections::HashMap<
            String,
            Vec<crate::import_bitwarden::ZipAttachment>,
        > = std::collections::HashMap::new();
        for (name, file_name, data) in attachments_flat {
            map.entry(crate::import_bitwarden::sanitize_zip_folder_name(
                &name,
            ))
            .or_default()
            .push(crate::import_bitwarden::ZipAttachment { file_name, data });
        }
        Some(map)
    } else {
        None
    };

    let imported = bw_vault_to_imported(bw, attachments_map);

    import_vault(imported, dest_collection, dest_org, overwrite)
}

// Resolve or create the destination organization/collection named by a
// mirror spec. Keeping this here makes a config-file mirror self-contained;
// callers no longer need a shell preflight that separately runs `org list`,
// `org create`, and `collection create`.
pub(super) fn ensure_destination_collection(
    collection: &str,
    org: Option<&str>,
) -> anyhow::Result<()> {
    let mut db = load_db()?;
    let org_id = match org {
        Some(needle) => match resolve_organization(&db.organizations, needle)
        {
            Ok(found) => found.id.clone(),
            Err(error)
                if error.to_string().starts_with("no organization found")
                    && uuid::Uuid::parse_str(needle).is_err() =>
            {
                let id = crate::actions::create_org(needle)?;
                crate::actions::sync()?;
                id
            }
            Err(error) => return Err(error),
        },
        None => resolve_org(&db, None)?,
    };

    db = load_db()?;
    let existing = decrypt_collections(&db)?;
    if existing.iter().any(|candidate| {
        candidate.org_id == org_id && candidate.name == collection
    }) {
        return Ok(());
    }

    let encrypted_name =
        crate::actions::encrypt(collection, None, Some(&org_id))?;
    let access_token = db
        .access_token
        .as_ref()
        .context("destination account has no access token")?;
    let refresh_token = db
        .refresh_token
        .as_ref()
        .context("destination account has no refresh token")?;
    let (tokens, _) = rbw::actions::create_collection(
        access_token,
        refresh_token,
        &org_id,
        &encrypted_name,
    )?;
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }
    crate::actions::sync()?;
    Ok(())
}

// A collection from the synced database, with its name decrypted.
#[derive(Debug, serde::Serialize)]
pub(super) struct DecryptedCollection {
    pub(super) id: String,
    pub(super) org_id: String,
    pub(super) name: String,
}

pub(super) fn decrypt_collections(
    db: &rbw::db::Db,
) -> anyhow::Result<Vec<DecryptedCollection>> {
    db.collections
        .iter()
        .map(|c| {
            let name =
                crate::actions::decrypt(&c.name, None, Some(&c.org_id))
                    .with_context(|| {
                        format!(
                            "failed to decrypt collection name for {}",
                            c.id
                        )
                    })?;
            Ok(DecryptedCollection {
                id: c.id.clone(),
                org_id: c.org_id.clone(),
                name,
            })
        })
        .collect()
}

// Resolve a collection given by name or ID against the synced collection
// list (restricted to `org_id` when given). Mirrors entry lookup: exact ID
// first, then exact name, then a case-insensitive substring fallback, and
// errors listing the candidates when a name is ambiguous.
pub(super) fn resolve_collection<'a>(
    collections: &'a [DecryptedCollection],
    needle: &str,
    org_id: Option<&str>,
) -> anyhow::Result<&'a DecryptedCollection> {
    let in_org =
        |c: &&DecryptedCollection| org_id.is_none_or(|o| c.org_id == o);

    if let Some(collection) = collections
        .iter()
        .filter(in_org)
        .find(|c| c.id.eq_ignore_ascii_case(needle))
    {
        return Ok(collection);
    }

    let mut matches: Vec<&DecryptedCollection> = collections
        .iter()
        .filter(in_org)
        .filter(|c| c.name == needle)
        .collect();
    if matches.is_empty() {
        let needle_lower = needle.to_lowercase();
        matches = collections
            .iter()
            .filter(in_org)
            .filter(|c| c.name.to_lowercase().contains(&needle_lower))
            .collect();
    }

    match matches[..] {
        [] => Err(anyhow::anyhow!("no collection found for '{needle}'")),
        [collection] => Ok(collection),
        _ => {
            let candidates = matches
                .iter()
                .map(|c| format!("{} ({})", c.name, c.id))
                .collect::<Vec<_>>()
                .join(", ");
            Err(anyhow::anyhow!(
                "multiple collections found for '{needle}': {candidates}; \
                use the collection ID instead"
            ))
        }
    }
}

pub fn list_collections(output: OutputMode) -> anyhow::Result<()> {
    unlock(None, None)?;

    let db = load_db()?;

    let mut collections = decrypt_collections(&db)?;
    collections.sort_by(|a, b| a.name.cmp(&b.name));

    if output_is_structured(output) {
        write_serialized_pretty(
            &collections,
            output,
            "failed to write collections to stdout",
        )?;
    } else if output == OutputMode::Name {
        for collection in &collections {
            println!("{}", collection.name);
        }
    } else {
        let rows = collections
            .iter()
            .map(|c| vec![c.id.clone(), c.name.clone()])
            .collect::<Vec<_>>();
        print_table(
            &[
                TableColumn {
                    header: "id",
                    style: TableColumnStyle::Id,
                },
                TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
            ],
            &rows,
            "",
        )?;
    }

    Ok(())
}

// Unlike `list_collections`, there's no decrypt step here -- organization
// names are plaintext in the sync response (see `db::Organization`'s doc
// comment), so `db.organizations` is already display-ready.
pub fn list_organizations(output: OutputMode) -> anyhow::Result<()> {
    unlock(None, None)?;

    let db = load_db()?;

    let mut organizations = db.organizations;
    organizations.sort_by(|a, b| a.name.cmp(&b.name));

    if output_is_structured(output) {
        write_serialized_pretty(
            &organizations,
            output,
            "failed to write organizations to stdout",
        )?;
    } else if output == OutputMode::Name {
        for org in &organizations {
            println!("{}", org.name);
        }
    } else {
        let rows = organizations
            .iter()
            .map(|o| vec![o.id.clone(), o.name.clone()])
            .collect::<Vec<_>>();
        print_table(
            &[
                TableColumn {
                    header: "id",
                    style: TableColumnStyle::Id,
                },
                TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
            ],
            &rows,
            "",
        )?;
    }

    Ok(())
}

// Moves an org-owned entry back into the personal vault. Bitwarden/
// Vaultwarden's server rejects clearing `organizationId` via a plain
// `PUT /ciphers/{id}` edit ("Organization mismatch. Please resync the
// client before updating the cipher" -- confirmed live against
// bw.brkn.lol), so unlike `import_create_entry`'s personal-to-org move
// (which the server does accept via a plain edit), this direction has to
// go through the same create-then-delete dance the official Bitwarden
// clients use for "clone to individual vault": re-encrypt the entry with
// the personal key, create it as a brand-new personal entry (`add` has no
// org parameter -- it's always personal), copy over history with a
// follow-up edit (safe now, since both sides are personal), and only then
// permanently delete the original org-owned entry. Creating before
// deleting means a failure here leaves a duplicate rather than losing the
// entry. Does not touch attachments (callers must refuse entries that
// have any, since their encryption keys aren't re-wrapped here).
pub(super) fn move_entry_to_personal(
    entry: &rbw::db::Entry,
    decrypted: &DecryptedCipher,
    access_token: &mut String,
    refresh_token: &mut String,
    db: &mut rbw::db::Db,
) -> anyhow::Result<()> {
    let editable = decrypted_to_editable(decrypted);

    let (data, fields, notes) = editable_to_encrypted(&editable, None, None)?;
    let encrypted_name = crate::actions::encrypt(&editable.name, None, None)?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, None, None))
        .transpose()?;

    let (tokens, new_entry_id) = rbw::actions::add(
        access_token,
        refresh_token,
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        entry.folder_id.as_deref(),
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

    if !decrypted.history.is_empty() {
        let history = decrypted
            .history
            .iter()
            .map(|h| {
                Ok(rbw::db::HistoryEntry {
                    last_used_date: h.last_used_date.clone(),
                    password: crate::actions::encrypt(
                        &h.password,
                        None,
                        None,
                    )?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        if let (Some(tokens), ()) = rbw::actions::edit(
            access_token,
            refresh_token,
            &new_entry_id,
            None,
            None,
            &encrypted_name,
            &data,
            &fields,
            encrypted_notes.as_deref(),
            entry.folder_id.as_deref(),
            &history,
            &rbw::db::CipherWriteMeta {
                last_known_revision_date: None,
                ..entry.cipher_write_meta()
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

    if let (Some(tokens), ()) = rbw::actions::delete_permanently(
        access_token,
        refresh_token,
        &entry.id,
    )? {
        access_token.clone_from(&tokens.access_token);
        db.access_token = Some(tokens.access_token);
        if let Some(new_refresh_token) = tokens.refresh_token {
            refresh_token.clone_from(&new_refresh_token);
            db.refresh_token = Some(new_refresh_token);
        }
        save_db(db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

// Set the collections one or more entries belong to, addressing entries by
// needle(s) and the collections by name or ID (resolved per entry's own
// organization, since different matched entries could belong to different
// orgs under `--bulk`). Without `--bulk`, exactly one needle must resolve
// to exactly one entry, same as `find_entry` elsewhere; with `--bulk`,
// every needle is matched against every entry it fits (`find_entries_all`),
// previewed, and confirmed once (unless `-y`) before any are touched --
// same convention as `archive --bulk`/`set --bulk`.
//
// `personal: true` (`--personal`) takes a different path entirely: instead
// of a `PUT /ciphers/{id}/collections` call, it fully re-encrypts the
// entry's name/data/fields/notes/history with the account's personal key
// and clears `organizationId` server-side via a normal `edit`, moving the
// entry out of the organization and back into the personal vault --
// mirroring `import_create_entry`'s personal-vault-to-org move, just in
// the opposite direction. Entries with attachments are refused for now:
// attachment encryption keys aren't re-wrapped by this move, so they'd be
// left undecryptable under the new ownership.
#[allow(clippy::too_many_arguments)]
pub fn assign_collections(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    collections: &[String],
    personal: bool,
    bulk: bool,
    yes: bool,
) -> anyhow::Result<()> {
    if !personal && collections.is_empty() {
        anyhow::bail!(
            "either --collection (repeatable) or --personal must be given"
        );
    }

    unlock(None, None)?;

    let mut db = load_db()?;
    let c = stdout_supports_color();

    let targets: Vec<(rbw::db::Entry, DecryptedCipher)> = if bulk {
        let mut any_err = false;
        let mut pending: Vec<(rbw::db::Entry, DecryptedCipher)> = Vec::new();
        for needle in &needles {
            match find_entries_all(
                &db,
                needle,
                user,
                folder,
                None,
                None,
                ignore_case,
            ) {
                Err(e) => {
                    eprintln!("{needle}: {e:#}");
                    any_err = true;
                }
                Ok(entries) => pending.extend(entries),
            }
        }

        let mut seen = std::collections::HashSet::new();
        pending.retain(|(entry, _)| seen.insert(entry.id.clone()));

        if pending.is_empty() {
            if any_err {
                anyhow::bail!("no entries found");
            }
            eprintln!("No matching entries.");
            return Ok(());
        }

        eprintln!(
            "{}",
            style::section(
                if personal {
                    "The following entries will be moved to your personal \
                     vault:"
                } else {
                    "The following entries will be assigned to collections:"
                },
                c
            )
        );
        for (_, decrypted) in &pending {
            eprintln!("  {}", style::name(&decrypted.name, c));
        }
        if !yes && !confirm("Continue?")? {
            return Ok(());
        }
        pending
    } else {
        let [needle] =
            <[Needle; 1]>::try_from(needles).map_err(|needles| {
                anyhow::anyhow!(
                    "expected exactly one needle without --bulk, got {}",
                    needles.len()
                )
            })?;
        let desc = format!(
            "{}{}",
            user.map_or_else(String::new, |s| format!("{s}@")),
            needle
        );
        let entry = find_entry(
            &db,
            vec![needle],
            user,
            folder,
            None,
            None,
            ignore_case,
            force_exact,
        )
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
        vec![entry]
    };

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();
    let all_collections = decrypt_collections(&db)?;

    let mut failed = 0_usize;
    let pb =
        item_progress_bar(u64::try_from(targets.len()).unwrap_or(u64::MAX));
    for (entry, decrypted) in &targets {
        pb.set_message(fit_to_width(&decrypted.name, PROGRESS_MSG_WIDTH));

        if entry.org_id.is_none() {
            pb_println(
                &pb,
                format!(
                    "{} '{}' is {}",
                    style_error("Error:", c),
                    decrypted.name,
                    if personal {
                        "already in your personal vault"
                    } else {
                        "not owned by an organization, so it cannot be \
                     assigned to collections"
                    },
                ),
            );
            failed += 1;
            pb.inc(1);
            continue;
        }

        if personal {
            if !entry.attachments.is_empty() {
                pb_println(
                    &pb,
                    format!(
                        "{} '{}' has attachments, which aren't re-keyed by \
                     this move yet -- refusing to move it to the personal \
                     vault",
                        style_error("Error:", c),
                        decrypted.name,
                    ),
                );
                failed += 1;
                pb.inc(1);
                continue;
            }

            match move_entry_to_personal(
                entry,
                decrypted,
                &mut access_token,
                &mut refresh_token,
                &mut db,
            ) {
                Ok(()) => {
                    pb_println(
                        &pb,
                        format!(
                            "{} {} to your personal vault",
                            style::success("Moved", c),
                            style::name(&decrypted.name, c),
                        ),
                    );
                }
                Err(e) => {
                    pb_println(
                        &pb,
                        format!(
                            "{} failed to move '{}': {e:#}",
                            style_error("Error:", c),
                            decrypted.name,
                        ),
                    );
                    failed += 1;
                }
            }
            pb.inc(1);
            continue;
        }

        let org_id = entry.org_id.as_deref().unwrap();
        let mut collection_ids = Vec::new();
        let mut collection_names = Vec::new();
        let mut resolve_failed = false;
        for needle in collections {
            match resolve_collection(&all_collections, needle, Some(org_id)) {
                Ok(collection) => {
                    if !collection_ids.contains(&collection.id) {
                        collection_ids.push(collection.id.clone());
                        collection_names.push(collection.name.clone());
                    }
                }
                Err(e) => {
                    pb_println(
                        &pb,
                        format!(
                            "{} '{}': {e:#}",
                            style_error("Error:", c),
                            decrypted.name,
                        ),
                    );
                    resolve_failed = true;
                    break;
                }
            }
        }
        if resolve_failed {
            failed += 1;
            pb.inc(1);
            continue;
        }

        match rbw::actions::edit_collections(
            &access_token,
            &refresh_token,
            &entry.id,
            &collection_ids,
        ) {
            Ok((tokens, ())) => {
                if let Some(tokens) = tokens {
                    access_token.clone_from(&tokens.access_token);
                    db.access_token = Some(tokens.access_token);
                    if let Some(new_refresh_token) = tokens.refresh_token {
                        refresh_token.clone_from(&new_refresh_token);
                        db.refresh_token = Some(new_refresh_token);
                    }
                    save_db(&db)?;
                }
                pb_println(
                    &pb,
                    format!(
                        "{} {} to {}",
                        style::success("Assigned", c),
                        style::name(&decrypted.name, c),
                        collection_names
                            .iter()
                            .map(|name| style::name(name, c))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                );
            }
            Err(e) => {
                pb_println(
                    &pb,
                    format!(
                        "{} failed to assign '{}': {e:#}",
                        style_error("Error:", c),
                        decrypted.name,
                    ),
                );
                failed += 1;
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    crate::actions::sync()?;

    if failed > 0 {
        anyhow::bail!(
            "{failed} entr{} failed to be assigned",
            if failed == 1 { "y" } else { "ies" }
        );
    }

    Ok(())
}

// The complement to `assign_collections`: removes the given collections
// (by name or ID, resolved per entry's own organization) from an entry
// that stays in the organization, rather than replacing its whole
// collection list. With no `--collection` given at all, removes every
// collection the entry currently belongs to, leaving it org-owned but
// unassigned to any collection -- distinct from `assign --personal`, which
// actually moves the entry out of the organization entirely. Same
// `--bulk`/preview/confirm convention as `assign_collections`.
#[allow(clippy::too_many_arguments)]
pub fn unassign_collections(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    collections: &[String],
    bulk: bool,
    yes: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let c = stdout_supports_color();

    let targets: Vec<(rbw::db::Entry, DecryptedCipher)> = if bulk {
        let mut any_err = false;
        let mut pending: Vec<(rbw::db::Entry, DecryptedCipher)> = Vec::new();
        for needle in &needles {
            match find_entries_all(
                &db,
                needle,
                user,
                folder,
                None,
                None,
                ignore_case,
            ) {
                Err(e) => {
                    eprintln!("{needle}: {e:#}");
                    any_err = true;
                }
                Ok(entries) => pending.extend(entries),
            }
        }

        let mut seen = std::collections::HashSet::new();
        pending.retain(|(entry, _)| seen.insert(entry.id.clone()));

        if pending.is_empty() {
            if any_err {
                anyhow::bail!("no entries found");
            }
            eprintln!("No matching entries.");
            return Ok(());
        }

        eprintln!(
            "{}",
            style::section(
                if collections.is_empty() {
                    "The following entries will be removed from all their \
                     collections:"
                } else {
                    "The following entries will be removed from the given \
                     collections:"
                },
                c
            )
        );
        for (_, decrypted) in &pending {
            eprintln!("  {}", style::name(&decrypted.name, c));
        }
        if !yes && !confirm("Continue?")? {
            return Ok(());
        }
        pending
    } else {
        let [needle] =
            <[Needle; 1]>::try_from(needles).map_err(|needles| {
                anyhow::anyhow!(
                    "expected exactly one needle without --bulk, got {}",
                    needles.len()
                )
            })?;
        let desc = format!(
            "{}{}",
            user.map_or_else(String::new, |s| format!("{s}@")),
            needle
        );
        let entry = find_entry(
            &db,
            vec![needle],
            user,
            folder,
            None,
            None,
            ignore_case,
            force_exact,
        )
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
        vec![entry]
    };

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();
    let all_collections = decrypt_collections(&db)?;

    let mut failed = 0_usize;
    let pb =
        item_progress_bar(u64::try_from(targets.len()).unwrap_or(u64::MAX));
    for (entry, decrypted) in &targets {
        pb.set_message(fit_to_width(&decrypted.name, PROGRESS_MSG_WIDTH));

        let Some(org_id) = entry.org_id.as_deref() else {
            pb_println(
                &pb,
                format!(
                    "{} '{}' is not owned by an organization, so it has no \
                 collections to remove",
                    style_error("Error:", c),
                    decrypted.name,
                ),
            );
            failed += 1;
            pb.inc(1);
            continue;
        };

        let new_ids: Vec<String> = if collections.is_empty() {
            Vec::new()
        } else {
            let mut remove_ids = Vec::new();
            let mut resolve_failed = false;
            for needle in collections {
                match resolve_collection(
                    &all_collections,
                    needle,
                    Some(org_id),
                ) {
                    Ok(collection) => remove_ids.push(collection.id.clone()),
                    Err(e) => {
                        pb_println(
                            &pb,
                            format!(
                                "{} '{}': {e:#}",
                                style_error("Error:", c),
                                decrypted.name,
                            ),
                        );
                        resolve_failed = true;
                        break;
                    }
                }
            }
            if resolve_failed {
                failed += 1;
                pb.inc(1);
                continue;
            }
            entry
                .collection_ids
                .iter()
                .filter(|id| !remove_ids.contains(id))
                .cloned()
                .collect()
        };

        match rbw::actions::edit_collections(
            &access_token,
            &refresh_token,
            &entry.id,
            &new_ids,
        ) {
            Ok((tokens, ())) => {
                if let Some(tokens) = tokens {
                    access_token.clone_from(&tokens.access_token);
                    db.access_token = Some(tokens.access_token);
                    if let Some(new_refresh_token) = tokens.refresh_token {
                        refresh_token.clone_from(&new_refresh_token);
                        db.refresh_token = Some(new_refresh_token);
                    }
                    save_db(&db)?;
                }
                pb_println(
                    &pb,
                    format!(
                        "{} {} from {}",
                        style::success("Removed", c),
                        style::name(&decrypted.name, c),
                        if collections.is_empty() {
                            "all collections".to_string()
                        } else {
                            collections.join(", ")
                        },
                    ),
                );
            }
            Err(e) => {
                pb_println(
                    &pb,
                    format!(
                        "{} failed to unassign '{}': {e:#}",
                        style_error("Error:", c),
                        decrypted.name,
                    ),
                );
                failed += 1;
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    crate::actions::sync()?;

    if failed > 0 {
        anyhow::bail!(
            "{failed} entr{} failed to be unassigned",
            if failed == 1 { "y" } else { "ies" }
        );
    }

    Ok(())
}

pub fn create_collection(
    name: &str,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let encrypted_name = crate::actions::encrypt(name, None, Some(&org_id))?;

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let (tokens, id) = rbw::actions::create_collection(
        access_token,
        refresh_token,
        &org_id,
        &encrypted_name,
    )?;
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    crate::actions::sync()?;

    println!("{id}");

    Ok(())
}

pub fn delete_collection(
    collection: &str,
    org_id: Option<&str>,
    yes: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;
    let all_collections = decrypt_collections(&db)?;
    let collection =
        resolve_collection(&all_collections, collection, Some(&org_id))?;

    if !yes
        && !confirm(&format!(
            "Delete collection {}?",
            style::name(&collection.name, stdout_supports_color())
        ))?
    {
        return Ok(());
    }

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    if let (Some(tokens), ()) = rbw::actions::delete_collection(
        access_token,
        refresh_token,
        &org_id,
        &collection.id,
    )? {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

// Permanently deletes every entry in a collection, leaving the (now empty)
// collection itself and everything outside it untouched -- the standalone,
// user-facing counterpart to `purge_collection_entries` (which `mirror
// --purge-dest --dest-collection` already calls, under its own whole-
// mirror confirmation). Confirms here instead, matching `purge-vault`/
// `collection delete`'s gating convention, since this has no other prompt
// covering it.
pub fn purge_collection(
    collection: &str,
    org_id: Option<&str>,
    yes: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;
    let all_collections = decrypt_collections(&db)?;
    let resolved =
        resolve_collection(&all_collections, collection, Some(&org_id))?;
    let collection_id = resolved.id.clone();
    let collection_name = resolved.name.clone();

    let count = db
        .entries
        .iter()
        .filter(|e| e.collection_ids.contains(&collection_id))
        .count();

    let c = stdout_supports_color();
    if count == 0 {
        eprintln!(
            "{} no entries currently in '{collection_name}' -- nothing to \
             purge",
            style::warning("Note:", c)
        );
        return Ok(());
    }

    if !yes {
        let prompt = format!(
            "{} this will permanently delete {count} entr{} from \
             collection '{collection_name}'. This cannot be undone! \
             Continue?",
            style_error("DANGER:", c),
            if count == 1 { "y" } else { "ies" }
        );
        if !confirm(&prompt)? {
            return Ok(());
        }
    }

    purge_collection_entries(&collection_id, None)
}

// Organization names are plaintext (unlike collection names, which are
// encrypted with the org key -- see the `Organization` doc comment in
// db.rs), so no `crate::actions::encrypt` call is needed here. The server
// requires billing_email on every update even though this only ever
// changes the name; there's nowhere to read the org's *current* billing
// email back from (the locally-cached `Organization` only has id/name), so
// this just passes through the active account's own email -- fine for the
// common case of a self-hosted instance where the account owns the org it's
// renaming.
pub fn rename_org(org_id: Option<&str>, name: &str) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let config = rbw::config::Config::load()?;
    let account =
        config.account(crate::actions::current_account().as_deref())?;
    let billing_email = account_email(&account)?;

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    if let (Some(tokens), ()) = rbw::actions::rename_org(
        access_token,
        refresh_token,
        &org_id,
        name,
        &billing_email,
    )? {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn rename_collection(
    collection: &str,
    org_id: Option<&str>,
    name: &str,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;
    let all_collections = decrypt_collections(&db)?;
    let collection =
        resolve_collection(&all_collections, collection, Some(&org_id))?;

    let encrypted_name = crate::actions::encrypt(name, None, Some(&org_id))?;

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    if let (Some(tokens), ()) = rbw::actions::rename_collection(
        access_token,
        refresh_token,
        &org_id,
        &collection.id,
        &encrypted_name,
    )? {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub(super) const EDIT: rbw::api::CollectionUser = rbw::api::CollectionUser {
    id: String::new(),
    read_only: false,
    hide_passwords: false,
    manage: false,
};

pub(super) const MANAGE: rbw::api::CollectionUser =
    rbw::api::CollectionUser {
        id: String::new(),
        read_only: false,
        hide_passwords: false,
        manage: true,
    };

pub(super) fn perm_rank(u: &rbw::api::CollectionUser) -> u8 {
    if u.manage {
        return 4;
    }
    match (u.read_only, u.hide_passwords) {
        (false, false) => 3,
        (false, true) => 2,
        (true, false) => 1,
        (true, true) => 0,
    }
}

pub(super) fn perm_level_name(u: &rbw::api::CollectionUser) -> &'static str {
    match perm_rank(u) {
        4 => "manage",
        3 => "edit",
        2 => "edit-no-pw",
        1 => "view",
        _ => "view-no-pw",
    }
}

pub(super) fn same_flags(
    a: &rbw::api::CollectionUser,
    b: &rbw::api::CollectionUser,
) -> bool {
    a.read_only == b.read_only
        && a.hide_passwords == b.hide_passwords
        && a.manage == b.manage
}

pub(super) fn normalize_collection_name(
    name: &str,
) -> anyhow::Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('/')
        || trimmed.ends_with('/')
    {
        anyhow::bail!("collection name is empty or has a leading/trailing slash: {name:?}");
    }
    Ok(trimmed.to_string())
}

// Resolve an organization given by name or ID against the account's
// organization list (`db.organizations`, already plaintext -- see the
// comment on that field). Mirrors `resolve_collection`: exact ID first,
// then exact name, then a case-insensitive substring fallback, erroring
// when a name is ambiguous.
pub(super) fn resolve_organization<'a>(
    organizations: &'a [rbw::db::Organization],
    needle: &str,
) -> anyhow::Result<&'a rbw::db::Organization> {
    if let Some(org) = organizations
        .iter()
        .find(|o| o.id.eq_ignore_ascii_case(needle))
    {
        return Ok(org);
    }

    let mut matches: Vec<&rbw::db::Organization> =
        organizations.iter().filter(|o| o.name == needle).collect();
    if matches.is_empty() {
        let needle_lower = needle.to_lowercase();
        matches = organizations
            .iter()
            .filter(|o| o.name.to_lowercase().contains(&needle_lower))
            .collect();
    }

    match matches[..] {
        [] => Err(anyhow::anyhow!("no organization found for '{needle}'")),
        [org] => Ok(org),
        _ => {
            let candidates = matches
                .iter()
                .map(|o| format!("{} ({})", o.name, o.id))
                .collect::<Vec<_>>()
                .join(", ");
            Err(anyhow::anyhow!(
                "multiple organizations found for '{needle}': {candidates}; \
                use the organization ID instead"
            ))
        }
    }
}

// Resolve `--collection`/`--org` (name or ID) from the `find`-family
// commands (get/show/edit/... and list/search) into concrete IDs for
// `entry_in_collection_org_scope`. `--org` alone scopes by organization;
// `--collection` (optionally combined with `--org` to disambiguate a name
// shared across orgs, same as `resolve_collection`'s own `org_id` scoping)
// resolves to one specific collection -- its own org is returned instead of
// the raw `--org` needle in that case, since the collection already pins it
// down more precisely.
pub(super) fn resolve_entry_scope(
    db: &rbw::db::Db,
    collection: Option<&str>,
    org: Option<&str>,
) -> anyhow::Result<(Option<String>, Option<String>)> {
    let org_id = org
        .map(|needle| {
            resolve_organization(&db.organizations, needle)
                .map(|found| found.id.clone())
        })
        .transpose()?;

    if let Some(needle) = collection {
        let decrypted = decrypt_collections(db)?;
        let found =
            resolve_collection(&decrypted, needle, org_id.as_deref())?;
        Ok((Some(found.id.clone()), Some(found.org_id.clone())))
    } else {
        Ok((None, org_id))
    }
}

pub(super) fn source_collection_is_present(
    collection: &str,
    org: Option<&str>,
) -> anyhow::Result<bool> {
    let db = load_db()?;
    match resolve_entry_scope(&db, Some(collection), org) {
        Ok((Some(_), _)) => Ok(true),
        Err(error)
            if error.to_string().starts_with("no collection found") =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
        Ok((None, _)) => Ok(false),
    }
}

// Resolve the target organization: the given `--org-id` (validated), or
// auto-detected when the vault belongs to exactly one org. The org universe
// is every org key delivered by sync, plus any org referenced by a synced
// collection (for older local dbs that predate the org key list).
pub(super) fn resolve_org(
    db: &rbw::db::Db,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut org_ids: std::collections::BTreeSet<&str> =
        db.protected_org_keys.keys().map(String::as_str).collect();
    org_ids.extend(db.collections.iter().map(|c| c.org_id.as_str()));
    org_id.map_or_else(
        || match org_ids.len() {
            0 => Err(anyhow::anyhow!("no organization found in vault")),
            1 => Ok((*org_ids.iter().next().unwrap()).to_string()),
            _ => Err(anyhow::anyhow!(
                "multiple organizations found ({}); pass --org-id",
                org_ids.iter().copied().collect::<Vec<_>>().join(", ")
            )),
        },
        |o| {
            if org_ids.contains(o) {
                Ok(o.to_string())
            } else {
                Err(anyhow::anyhow!("org {o} not found in this vault"))
            }
        },
    )
}

pub(super) fn parse_org_role(role: &str) -> anyhow::Result<i32> {
    match role.to_lowercase().as_str() {
        "owner" => Ok(0),
        "admin" => Ok(1),
        "user" => Ok(2),
        "manager" => Ok(3),
        _ => anyhow::bail!(
            "invalid role '{role}' (expected owner, admin, user, or manager)"
        ),
    }
}

// Invites a user by email into an org. No key material changes hands here
// Pulls organizationId/organizationUserId/token out of a pasted invite
// link, tolerating the `#/accept-organization/?...` fragment-based query
// string the web vault uses (a plain URL parse would treat everything
// after `#` as an opaque fragment and miss the query params inside it).
pub(super) fn parse_accept_org_url(
    url: &str,
) -> anyhow::Result<(String, String, String)> {
    let query = url.rsplit_once('?').map(|(_, q)| q).ok_or_else(|| {
        anyhow::anyhow!("couldn't find a query string in the invite URL")
    })?;

    let mut org_id = None;
    let mut user_id = None;
    let mut token = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "organizationId" => org_id = Some(value.into_owned()),
            "organizationUserId" => user_id = Some(value.into_owned()),
            "token" => token = Some(value.into_owned()),
            _ => {}
        }
    }

    Ok((
        org_id.context("invite URL is missing organizationId")?,
        user_id.context("invite URL is missing organizationUserId")?,
        token.context("invite URL is missing token")?,
    ))
}

// Accepts an org invite, called by the invitee using either the whole
// invite link or the org id/user id/token from it individually -- not
// `resolve_org`, since an invited-but-unaccepted account generally has no
// other way to know any of that (it isn't a member yet, so it doesn't
// show up in `rbw org list`/db.protected_org_keys locally).
pub fn accept_org_invite(
    url: Option<&str>,
    org_id: Option<&str>,
    user_id: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let (org_id, user_id, token) = if let Some(url) = url {
        parse_accept_org_url(url)?
    } else {
        (
            org_id
                .context("--org-id is required without --url")?
                .to_string(),
            user_id
                .context("--user-id is required without --url")?
                .to_string(),
            token
                .context("--token is required without --url")?
                .to_string(),
        )
    };

    unlock(None, None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let (tokens, ()) = rbw::actions::accept_org_invite(
        access_token,
        refresh_token,
        &org_id,
        &user_id,
        &token,
    )?;
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    eprintln!(
        "{}",
        style::success(
            "Accepted the organization invite.",
            stdout_supports_color(),
        ),
    );

    Ok(())
}

// Creates a new organization with the current account as its (initial,
// and at creation time only) owner. Agent-mediated -- see
// `create_org`'s comment in `rbw-agent/actions.rs` for why.
pub fn create_org(name: &str) -> anyhow::Result<()> {
    unlock(None, None)?;

    let id = crate::actions::create_org(name)?;

    eprintln!(
        "{} organization '{name}' ({id})",
        style::success("Created", stdout_supports_color()),
    );

    Ok(())
}

// Permanently deletes an entire organization -- same danger class as
// `purge_vault`, so it's gated the same way: a strong confirmation
// (`-y`/`--yes` to skip) plus the master-password re-entry itself
// (`--stdin` to skip that too).
pub fn delete_org(
    org_id: Option<&str>,
    yes: bool,
    password: Option<String>,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let c = stdout_supports_color();
    let prompt = format!(
        "{} this will permanently delete the organization {} and \
         everything in it. This cannot be undone! Continue?",
        style_error("DANGER:", c),
        style::name(&org_id, c),
    );
    if !yes && !confirm(&prompt)? {
        return Ok(());
    }

    crate::actions::delete_org(&org_id, password)?;

    eprintln!("{}", style::success("Organization deleted.", c));

    Ok(())
}

pub fn invite_org_user(
    org_id: Option<&str>,
    email: &str,
    role: &str,
) -> anyhow::Result<()> {
    let role = parse_org_role(role)?;

    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let (tokens, ()) = rbw::actions::invite_org_user(
        access_token,
        refresh_token,
        &org_id,
        email,
        role,
    )?;
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    eprintln!(
        "{} '{email}' to the organization",
        style::success("Invited", stdout_supports_color()),
    );

    Ok(())
}

pub fn remove_org_user(
    org_id: Option<&str>,
    user: &str,
    yes: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (tokens, users) =
        rbw::actions::org_users(&access_token, &refresh_token, &org_id)?;
    if let Some(tokens) = tokens {
        access_token.clone_from(&tokens.access_token);
        db.access_token = Some(tokens.access_token);
        if let Some(new_refresh_token) = tokens.refresh_token {
            refresh_token.clone_from(&new_refresh_token);
            db.refresh_token = Some(new_refresh_token);
        }
        save_db(&db)?;
    }

    let target = users
        .iter()
        .find(|u| u.id == user)
        .or_else(|| users.iter().find(|u| u.email.eq_ignore_ascii_case(user)))
        .ok_or_else(|| {
            anyhow::anyhow!("no organization member found for '{user}'")
        })?;

    let c = stdout_supports_color();
    let prompt = format!(
        "Remove {} from the organization?",
        style::name(&target.email, c),
    );
    if !yes && !confirm(&prompt)? {
        return Ok(());
    }

    let (tokens, ()) = rbw::actions::remove_org_user(
        &access_token,
        &refresh_token,
        &org_id,
        &target.id,
    )?;
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    eprintln!(
        "{} '{}' from the organization",
        style::success("Removed", c),
        target.email,
    );

    Ok(())
}

// Confirms a member who has accepted their invite -- required before they
// can decrypt anything in the org, since that's what actually re-encrypts
// the org key to their now-known public key. Resolving the member and
// fetching their public key are both plain lookups done here; only the
// re-encryption itself is agent-mediated (needs the org key already
// cached from unlock).
pub fn confirm_org_user(
    org_id: Option<&str>,
    user: &str,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (tokens, users) =
        rbw::actions::org_users(&access_token, &refresh_token, &org_id)?;
    if let Some(tokens) = tokens {
        access_token.clone_from(&tokens.access_token);
        db.access_token = Some(tokens.access_token);
        if let Some(new_refresh_token) = tokens.refresh_token {
            refresh_token.clone_from(&new_refresh_token);
            db.refresh_token = Some(new_refresh_token);
        }
        save_db(&db)?;
    }

    let target = users
        .iter()
        .find(|u| u.id == user)
        .or_else(|| users.iter().find(|u| u.email.eq_ignore_ascii_case(user)))
        .ok_or_else(|| {
            anyhow::anyhow!("no organization member found for '{user}'")
        })?;
    // The public-key lookup needs the account's own (global) user id --
    // a different id than the OrganizationUser relationship id `confirm`
    // itself uses. Only unset if they haven't registered an account for
    // that email yet.
    let target_user_id = target.user_id.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "'{}' hasn't registered an account for this email yet -- \
             they need to do that before they can be confirmed",
            target.email,
        )
    })?;

    let (tokens, public_key_der_b64) = rbw::actions::user_public_key(
        &access_token,
        &refresh_token,
        target_user_id,
    )?;
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    crate::actions::confirm_org_user(
        &org_id,
        &target.id,
        &public_key_der_b64,
    )?;

    eprintln!(
        "{} '{}'",
        style::success("Confirmed", stdout_supports_color()),
        target.email,
    );

    Ok(())
}

// Sets one member's permissions on one collection directly, without any
// of `propagate_collection_permissions`'s hierarchy-inference policy
// (topmost held -> edit, descendants -> manage). That command bakes in a
// specific naming-convention-driven policy that doesn't fit every org;
// this is the generic primitive underneath it, for anyone who just wants
// to set a permission on a (collection, member) pair directly.
pub fn grant_collection_access(
    collection: &str,
    user: &str,
    org_id: Option<&str>,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    crate::actions::sync()?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let all_collections = decrypt_collections(&db)?;
    let resolved =
        resolve_collection(&all_collections, collection, Some(&org_id))?;
    let collection_id = resolved.id.clone();
    let collection_name = resolved.name.clone();

    // The still-encrypted name, needed to re-submit the PUT below --
    // reusing it directly avoids any risk of a decrypt/re-encrypt
    // mismatch changing it.
    let encrypted_name = db
        .collections
        .iter()
        .find(|c| c.id == collection_id)
        .map(|c| c.name.clone())
        .context("collection disappeared from the local db")?;

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (tokens, members) =
        rbw::actions::org_users(&access_token, &refresh_token, &org_id)?;
    if let Some(tokens) = tokens {
        access_token.clone_from(&tokens.access_token);
        db.access_token = Some(tokens.access_token);
        if let Some(new_refresh_token) = tokens.refresh_token {
            refresh_token.clone_from(&new_refresh_token);
            db.refresh_token = Some(new_refresh_token);
        }
        save_db(&db)?;
    }

    let target = members
        .iter()
        .find(|m| m.id == user)
        .or_else(|| {
            members.iter().find(|m| m.email.eq_ignore_ascii_case(user))
        })
        .ok_or_else(|| {
            anyhow::anyhow!("no organization member found for '{user}'")
        })?;

    let (tokens, details) = rbw::actions::collections_details(
        &access_token,
        &refresh_token,
        &org_id,
    )?;
    if let Some(tokens) = tokens {
        access_token.clone_from(&tokens.access_token);
        db.access_token = Some(tokens.access_token);
        if let Some(new_refresh_token) = tokens.refresh_token {
            refresh_token.clone_from(&new_refresh_token);
            db.refresh_token = Some(new_refresh_token);
        }
        save_db(&db)?;
    }

    let detail =
        details
            .iter()
            .find(|d| d.id == collection_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "collection '{collection_name}' has no per-user \
                 permission data from the API (accessAll members aren't \
                 listed there)"
                )
            })?;

    let mut users: Vec<rbw::api::CollectionUser> = detail
        .users
        .iter()
        .filter(|u| u.id != target.id)
        .cloned()
        .collect();
    users.push(rbw::api::CollectionUser {
        id: target.id.clone(),
        read_only,
        hide_passwords,
        manage,
    });

    let (tokens, ()) = rbw::actions::set_collection_users(
        &access_token,
        &refresh_token,
        &org_id,
        &collection_id,
        &encrypted_name,
        detail.external_id.as_deref(),
        &detail.groups,
        &users,
    )?;
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    eprintln!(
        "{} permissions for '{}' on collection '{collection_name}'",
        style::success("Set", stdout_supports_color()),
        target.email,
    );

    Ok(())
}

pub fn propagate_collection_permissions(
    org_id: Option<&str>,
    apply: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    crate::actions::sync()?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let mut id2name: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for c in &db.collections {
        if c.org_id != org_id {
            continue;
        }
        let name = crate::actions::decrypt(&c.name, None, Some(&c.org_id))
            .with_context(|| {
                format!("failed to decrypt collection name for {}", c.id)
            })?;
        let name = normalize_collection_name(&name)?;
        id2name.insert(c.id.clone(), name);
    }

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (tokens, members) =
        rbw::actions::org_users(&access_token, &refresh_token, &org_id)?;
    if let Some(tokens) = tokens {
        access_token.clone_from(&tokens.access_token);
        db.access_token = Some(tokens.access_token);
        if let Some(new_refresh_token) = tokens.refresh_token {
            refresh_token.clone_from(&new_refresh_token);
            db.refresh_token = Some(new_refresh_token);
        }
        save_db(&db)?;
    }

    let (tokens, details) = rbw::actions::collections_details(
        &access_token,
        &refresh_token,
        &org_id,
    )?;
    if let Some(tokens) = tokens {
        access_token.clone_from(&tokens.access_token);
        db.access_token = Some(tokens.access_token);
        if let Some(new_refresh_token) = tokens.refresh_token {
            refresh_token.clone_from(&new_refresh_token);
            db.refresh_token = Some(new_refresh_token);
        }
        save_db(&db)?;
    }

    // Exclude Owners (role 0) and Admins (role 1); only Users (2) and
    // Managers (3) get permission propagation. confirmed (status==2) and
    // non-access-all members only.
    let eligible: std::collections::HashMap<String, String> = members
        .iter()
        .filter(|m| m.status == 2 && !m.access_all && m.role >= 2)
        .map(|m| (m.id.clone(), m.email.clone()))
        .collect();

    let details_by_id: std::collections::HashMap<
        &str,
        &rbw::api::CollectionDetail,
    > = details.iter().map(|d| (d.id.as_str(), d)).collect();
    for d in &details {
        if !id2name.contains_key(&d.id) {
            anyhow::bail!(
                "collection {} returned by the API is missing or undecryptable in the local db; aborting",
                d.id
            );
        }
    }
    for id in id2name.keys() {
        if !details_by_id.contains_key(id.as_str()) {
            anyhow::bail!(
                "collection {} ({}) is in the local db but absent from the live API response; aborting",
                id,
                id2name[id]
            );
        }
    }

    let mut held: std::collections::HashMap<
        String,
        std::collections::HashMap<String, rbw::api::CollectionUser>,
    > = std::collections::HashMap::new();
    for d in &details {
        for u in &d.users {
            if eligible.contains_key(&u.id) {
                held.entry(u.id.clone())
                    .or_default()
                    .insert(d.id.clone(), u.clone());
            }
        }
    }

    let mut desired: std::collections::HashMap<
        (String, String),
        rbw::api::CollectionUser,
    > = std::collections::HashMap::new();
    for member_id in held.keys() {
        let held_ids = &held[member_id];
        let held_names: Vec<&str> =
            held_ids.keys().map(|id| id2name[id].as_str()).collect();
        let topmost: Vec<&str> = held_names
            .iter()
            .copied()
            .filter(|n| {
                !held_names
                    .iter()
                    .any(|h| *h != *n && n.starts_with(&format!("{h}/")))
            })
            .collect();
        for (id, name) in &id2name {
            if topmost.iter().any(|t| name.starts_with(&format!("{t}/"))) {
                desired.insert((member_id.clone(), id.clone()), MANAGE);
            }
        }
        for (id, name) in &id2name {
            if topmost.contains(&name.as_str()) {
                desired.insert((member_id.clone(), id.clone()), EDIT);
            }
        }
    }

    let mut changes: std::collections::BTreeMap<
        String,
        Vec<(String, rbw::api::CollectionUser)>,
    > = std::collections::BTreeMap::new();
    for ((member_id, coll_id), target) in &desired {
        let current = held.get(member_id).and_then(|h| h.get(coll_id));
        let needs_change = current.is_none_or(|c| !same_flags(c, target));
        if needs_change {
            changes
                .entry(coll_id.clone())
                .or_default()
                .push((member_id.clone(), target.clone()));
        }
    }
    for member_targets in changes.values_mut() {
        member_targets.sort_by(|a, b| a.0.cmp(&b.0));
    }

    for coll_id in changes.keys() {
        if !details_by_id[coll_id.as_str()].groups.is_empty() {
            anyhow::bail!(
                "collection {} ({}) has groups assigned; groups passthrough on PUT is unverified, aborting (see docs/collection-permissions-spec.md §4.3)",
                coll_id,
                id2name[coll_id]
            );
        }
    }

    let mut changed_members: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut grants = 0usize;
    for (coll_id, member_targets) in &changes {
        let name = &id2name[coll_id];
        for (member_id, target) in member_targets {
            let email = &eligible[member_id];
            let level = if target.manage { "MANAGE" } else { "EDIT" };
            let current = held.get(member_id).and_then(|h| h.get(coll_id));
            let downgrade =
                current.is_some_and(|c| perm_rank(target) < perm_rank(c));
            let prefix = if apply { "" } else { "WOULD " };
            if downgrade {
                let cur_level = perm_level_name(current.unwrap());
                let tgt_level = perm_level_name(target);
                println!(
                    "{prefix}DOWNGRADE {email} {cur_level}->{tgt_level} on {name}"
                );
            } else {
                println!("{prefix}SET {email} -> {level} on {name}");
            }
            changed_members.insert(member_id.clone());
            grants += 1;
        }
    }

    if verbose {
        eprintln!(
            "{} eligible members, {} collections in org, {} collections to change",
            eligible.len(),
            id2name.len(),
            changes.len()
        );
    }

    if apply {
        let mut applied: Vec<String> = Vec::new();
        for (coll_id, member_targets) in &changes {
            let detail = details_by_id[coll_id.as_str()];
            let mut new_users = detail.users.clone();
            for (member_id, target) in member_targets {
                let entry = new_users.iter_mut().find(|u| &u.id == member_id);
                if let Some(u) = entry {
                    u.read_only = target.read_only;
                    u.hide_passwords = target.hide_passwords;
                    u.manage = target.manage;
                } else {
                    new_users.push(rbw::api::CollectionUser {
                        id: member_id.clone(),
                        read_only: target.read_only,
                        hide_passwords: target.hide_passwords,
                        manage: target.manage,
                    });
                }
            }
            let enc_name = db
                .collections
                .iter()
                .find(|c| &c.id == coll_id)
                .map(|c| c.name.clone())
                .unwrap();
            let res = rbw::actions::set_collection_users(
                &access_token,
                &refresh_token,
                &org_id,
                coll_id,
                &enc_name,
                detail.external_id.as_deref(),
                &detail.groups,
                &new_users,
            );
            match res {
                Ok((tokens, ())) => {
                    if let Some(tokens) = tokens {
                        access_token.clone_from(&tokens.access_token);
                        db.access_token = Some(tokens.access_token);
                        if let Some(new_refresh_token) = tokens.refresh_token
                        {
                            refresh_token.clone_from(&new_refresh_token);
                            db.refresh_token = Some(new_refresh_token);
                        }
                        save_db(&db)?;
                    }
                    applied.push(coll_id.clone());
                }
                Err(e) => {
                    eprintln!(
                        "PUT failed on collection {} ({}); already applied to: {:?}",
                        coll_id, id2name[coll_id], applied
                    );
                    return Err(e.into());
                }
            }
        }
        crate::actions::sync()?;
    }

    let mode = if apply { "applied" } else { "dry-run" };
    println!(
        "Done: {} members, {} collections changed, {} grants set ({})",
        changed_members.len(),
        changes.len(),
        grants,
        mode
    );

    Ok(())
}
