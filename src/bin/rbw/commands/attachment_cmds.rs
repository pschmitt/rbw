use super::*;

// `attachment list --from-file`: same output shape as the live-account
// path, listing `decrypted.attachments` off an in-memory `DecryptedCipher`.
pub(super) fn attachment_list_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
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

    if output_is_structured(output) {
        write_serialized_pretty(
            &decrypted.attachments,
            output,
            "failed to write attachments to stdout",
        )?;
    } else if output == OutputMode::Name {
        for attachment in &decrypted.attachments {
            println!(
                "{}",
                attachment
                    .file_name
                    .clone()
                    .unwrap_or_else(|| attachment.id.clone())
            );
        }
    } else {
        let rows = decrypted
            .attachments
            .iter()
            .map(|attachment| {
                vec![
                    attachment.id.clone(),
                    attachment.file_name.clone().unwrap_or_default(),
                    attachment
                        .size_name
                        .clone()
                        .or_else(|| attachment.size.clone())
                        .unwrap_or_default(),
                ]
            })
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
                TableColumn {
                    header: "size",
                    style: TableColumnStyle::Size,
                },
            ],
            &rows,
            "",
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn attachment_list(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return attachment_list_from_file(
            path,
            &needles,
            user,
            folder,
            ignore_case,
            output,
            force_exact,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;
    let db = load_db()?;
    let (_, decrypted) = find_entry(
        &db,
        needles,
        user,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )?;

    if output_is_structured(output) {
        write_serialized_pretty(
            &decrypted.attachments,
            output,
            "failed to write attachments to stdout",
        )?;
    } else if output == OutputMode::Name {
        for attachment in &decrypted.attachments {
            println!(
                "{}",
                attachment
                    .file_name
                    .clone()
                    .unwrap_or_else(|| attachment.id.clone())
            );
        }
    } else {
        let rows = decrypted
            .attachments
            .iter()
            .map(|attachment| {
                vec![
                    attachment.id.clone(),
                    attachment.file_name.clone().unwrap_or_default(),
                    attachment
                        .size_name
                        .clone()
                        .or_else(|| attachment.size.clone())
                        .unwrap_or_default(),
                ]
            })
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
                TableColumn {
                    header: "size",
                    style: TableColumnStyle::Size,
                },
            ],
            &rows,
            "",
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
// `attachment get --from-file`: reads the attachment bytes directly from
// `vault.attachment_data` (populated by `rbw export --attachments`/`add
// --attachment`, keyed by attachment id) instead of downloading and
// decrypting them over the network.
pub(super) fn attachment_get_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
    output: Option<&std::path::Path>,
    raw: bool,
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
    let decrypted_attachment =
        resolve_attachment_in_file(&decrypted, attachment)?;

    let data = vault
        .attachment_data
        .get(&decrypted_attachment.id)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "attachment data for '{}' is not present in {}",
                decrypted_attachment.id,
                path.display()
            )
        })?;

    let output_to_stdout = raw
        || output.is_some_and(|output| output == std::path::Path::new("-"));

    if output_to_stdout {
        std::io::stdout()
            .write_all(&data)
            .context("failed to write attachment to stdout")?;
        return Ok(());
    }

    let file_name = decrypted_attachment
        .file_name
        .as_deref()
        .and_then(|name| std::path::Path::new(name).file_name())
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("BitwardenAttachment");
    let out_path = output.map_or_else(
        || std::path::PathBuf::from(file_name),
        |output| {
            if output.is_dir() {
                output.join(file_name)
            } else {
                output.to_path_buf()
            }
        },
    );
    std::fs::write(&out_path, data)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    println!("{}", out_path.display());

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn attachment_get(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
    output: Option<&std::path::Path>,
    raw: bool,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return attachment_get_from_file(
            path,
            &needles,
            user,
            folder,
            ignore_case,
            attachment,
            output,
            raw,
            force_exact,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;
    let mut db = load_db()?;
    let (entry, decrypted) = find_entry(
        &db,
        needles,
        user,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )?;
    let (attachment, decrypted_attachment) =
        resolve_attachment(&entry, &decrypted, attachment)?;

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
                save_db(&db)?;
            }
            url
        }
        Err(e) => attachment.url.clone().ok_or(e)?,
    };
    let encrypted = rbw::actions::download_attachment(&url)
        .context("failed to download attachment")?;
    let decrypted = crate::actions::decrypt_attachment(
        encrypted,
        attachment.key.as_deref(),
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;

    let output_to_stdout = raw
        || output.is_some_and(|output| output == std::path::Path::new("-"));

    if output_to_stdout {
        std::io::stdout()
            .write_all(&decrypted)
            .context("failed to write attachment to stdout")?;
        return Ok(());
    }

    let file_name = decrypted_attachment
        .file_name
        .as_deref()
        .and_then(|name| std::path::Path::new(name).file_name())
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("BitwardenAttachment");
    let path = output.map_or_else(
        || std::path::PathBuf::from(file_name),
        |output| {
            if output.is_dir() {
                output.join(file_name)
            } else {
                output.to_path_buf()
            }
        },
    );
    std::fs::write(&path, decrypted)
        .with_context(|| format!("failed to write {}", path.display()))?;
    println!("{}", path.display());

    Ok(())
}

// `attachment create --from-file`: mirrors `set --attachment --from-file`'s
// attachment-adding logic (new random id, raw bytes into
// `vault.attachment_data`), but for the dedicated `attachment create`
// command instead of as a side effect of `set`.
pub(super) fn attachment_create_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    file: &std::path::Path,
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

    let mut decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let filename = file
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?
        .to_string();
    let data = std::fs::read(file)
        .with_context(|| format!("failed to read {}", file.display()))?;

    let id = uuid::Uuid::new_v4().to_string();
    decrypted.attachments.push(DecryptedAttachment {
        id: id.clone(),
        file_name: Some(filename.clone()),
        size: None,
        size_name: None,
    });
    decrypted.attachment_metadata =
        AttachmentMetadata::new(&decrypted.id, decrypted.attachments.len());
    vault.attachment_data.insert(id, data);

    let entry_name = decrypted.name.clone();
    if let Some(pos) = vault.entries.iter().position(|e| e.id == decrypted.id)
    {
        vault.entries[pos] = decrypted;
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
    eprintln!(
        "{} {} \u{2192} {}",
        style::success("Attached", c),
        style::name(&filename, c),
        style::name(&entry_name, c),
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn attachment_create(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    file: &std::path::Path,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return attachment_create_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            file,
            force_exact,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;
    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (entry, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        None,
        None,
        ignore_case,
        force_exact,
    )?;

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
        save_db(&db)?;
    }

    crate::actions::sync()?;

    let c = stdout_supports_color();
    eprintln!(
        "{} {} \u{2192} {}",
        style::success("Attached", c),
        style::name(filename, c),
        style::name(&decrypted.name, c),
    );

    Ok(())
}

// `attachment rm --from-file`: same resolution/confirmation shape as the
// live-account path, then drops the attachment (and its raw bytes) from
// the in-memory vault and writes back.
#[allow(clippy::too_many_arguments)]
pub(super) fn attachment_rm_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
    force_exact: bool,
    yes: bool,
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

    let mut decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    let decrypted_attachment =
        resolve_attachment_in_file(&decrypted, attachment)?;

    let attachment_id = decrypted_attachment.id.clone();
    let file_name = decrypted_attachment
        .file_name
        .clone()
        .unwrap_or_else(|| attachment_id.clone());

    if !yes {
        let c = stdout_supports_color();
        if !confirm(&format!(
            "Delete attachment {} from {}?",
            style::name(&file_name, c),
            style::name(&decrypted.name, c)
        ))? {
            return Ok(());
        }
    }

    decrypted.attachments.retain(|a| a.id != attachment_id);
    decrypted.attachment_metadata =
        AttachmentMetadata::new(&decrypted.id, decrypted.attachments.len());
    vault.attachment_data.remove(&attachment_id);

    let entry_name = decrypted.name.clone();
    if let Some(pos) = vault.entries.iter().position(|e| e.id == decrypted.id)
    {
        vault.entries[pos] = decrypted;
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
    eprintln!(
        "{} {} from {}",
        style::success("Deleted", c),
        style::name(&file_name, c),
        style::name(&entry_name, c),
    );

    Ok(())
}

// Delete an attachment from an entry and sync. Shares the entry/attachment
// resolution behavior of `attachment_get`, including the only-attachment
// fallback when --attachment is omitted.
#[allow(clippy::too_many_arguments)]
pub fn attachment_rm(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
    force_exact: bool,
    yes: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return attachment_rm_from_file(
            path,
            &needles,
            user,
            folder,
            ignore_case,
            attachment,
            force_exact,
            yes,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;
    let mut db = load_db()?;
    let (entry, decrypted) = find_entry(
        &db,
        needles,
        user,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )?;
    let (attachment, decrypted_attachment) =
        resolve_attachment(&entry, &decrypted, attachment)?;

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

    let attachment_id = attachment.id.clone();
    let file_name = decrypted_attachment
        .file_name
        .clone()
        .unwrap_or_else(|| attachment_id.clone());

    if !yes {
        let c = stdout_supports_color();
        if !confirm(&format!(
            "Delete attachment {} from {}?",
            style::name(&file_name, c),
            style::name(&decrypted.name, c)
        ))? {
            return Ok(());
        }
    }

    if let (Some(tokens), ()) = rbw::actions::delete_attachment(
        &access_token,
        &refresh_token,
        &entry.id,
        &attachment_id,
    )? {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    crate::actions::sync()?;

    let c = stdout_supports_color();
    eprintln!(
        "{} {} from {}",
        style::success("Deleted", c),
        style::name(&file_name, c),
        style::name(&decrypted.name, c),
    );

    Ok(())
}
