use super::*;

#[allow(clippy::too_many_arguments)]
pub fn add(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    json: bool,
    _yaml: bool,
    generate: bool,
    gen_len: usize,
    gen_ty: rbw::pwgen::Type,
    secure_note: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if secure_note && generate {
        // clap only rejects an explicit `-g`; the pwgen flags that imply
        // it (`-l`, `--diceware`, ...) end up here.
        anyhow::bail!(
            "--secure-note cannot be combined with password generation"
        );
    }
    if secure_note && name.is_none() && !std::io::stdin().is_terminal() {
        anyhow::bail!("--secure-note with a piped note requires a NAME");
    }
    if generate && !std::io::stdin().is_terminal() {
        // The editor ignores its template entirely and reads the entry
        // straight from stdin when it isn't a tty (see `rbw::edit::edit`),
        // so a generated password would be silently discarded anyway --
        // treat the combination as a user error rather than a silent no-op.
        anyhow::bail!(
            "--generate cannot be combined with a piped entry; provide the \
             password via generation or stdin, not both"
        );
    }
    let generated = generate.then(|| rbw::pwgen::pwgen(gen_ty, gen_len));
    if let Some(path) = from_file {
        return add_from_file(
            path,
            name,
            username,
            uris,
            folder,
            json,
            generated.as_deref(),
            secure_note,
            from_file_passphrase,
        );
    }
    add_structured(
        name,
        username,
        uris,
        folder,
        json,
        generated.as_deref(),
        secure_note,
    )
}

// Initial `EditableCipher` shown in the editor by `rbw add`: a login
// prefilled from the CLI args, or an empty secure note with
// `--secure-note`.
pub(super) fn new_entry_template(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    generated_password: Option<&str>,
    secure_note: bool,
) -> EditableCipher {
    let data = if secure_note {
        EditableData::SecureNote
    } else {
        let editable_uris: Vec<EditableUri> = if uris.is_empty() {
            vec![EditableUri {
                uri: String::new(),
                match_type: None,
            }]
        } else {
            uris.iter()
                .map(|(uri, mt)| EditableUri {
                    uri: uri.clone(),
                    match_type: mt.map(|m| uri_match_type_str(m).to_string()),
                })
                .collect()
        };
        EditableData::Login {
            username: Some(username.unwrap_or("").to_string()),
            password: Some(
                generated_password.unwrap_or_default().to_string(),
            ),
            uris: editable_uris,
            totp: None,
            fido2_credentials: Vec::new(),
        }
    };
    EditableCipher {
        name: name.unwrap_or("").to_string(),
        folder: folder.map(std::string::ToString::to_string),
        // Serialized as `notes: ''` so the field is visible in the
        // editor -- it's the whole point of a secure note.
        notes: secure_note.then(String::new),
        data,
        fields: Vec::new(),
    }
}

// Runs the `rbw add` template through `$EDITOR` (or stdin) and parses the
// result. `Ok(None)` means the buffer came back unchanged and the add
// should be cancelled.
pub(super) fn edit_new_entry(
    template: EditableCipher,
    json: bool,
    prefilled: bool,
) -> anyhow::Result<Option<(EditableCipher, Option<String>)>> {
    if matches!(template.data, EditableData::SecureNote)
        && !std::io::stdin().is_terminal()
    {
        // `echo ... | rbw add --secure-note NAME`: the piped text is the
        // note itself, not a YAML/JSON entry.
        let notes = std::io::read_to_string(std::io::stdin())?;
        if notes.is_empty() {
            anyhow::bail!("no note content on stdin");
        }
        return Ok(Some((
            EditableCipher {
                notes: Some(notes),
                ..template
            },
            None,
        )));
    }

    let serialized = if json {
        serde_json::to_string_pretty(&template)?
    } else {
        serde_yaml::to_string(&template)?
    };

    let (help, ext) = if json {
        (
            "# Fill in the JSON below. Lines starting with # are ignored.",
            "json",
        )
    } else {
        (
            "# Fill in the YAML below. Lines starting with # are ignored.",
            "yaml",
        )
    };

    let interactive = std::io::stdin().is_terminal();
    let contents = rbw::edit::edit(&serialized, help, ext)?;
    let result = (|| {
        let contents_trimmed = contents
            .lines()
            .filter(|l| !l.starts_with('#'))
            .fold(String::new(), |mut s, l| {
                s.push_str(l);
                s.push('\n');
                s
            });

        // With `--generate`, the template already has a real (generated)
        // password filled in, so leaving the editor untouched means "accept the
        // generated entry as shown", not "I opened this by accident" -- only
        // treat an unmodified buffer as a no-op cancel when there's nothing
        // pre-filled worth keeping.
        if !prefilled && contents_trimmed.trim() == serialized.trim() {
            eprintln!("{}", paint_no_changes());
            return Ok(None);
        }

        let cipher: EditableCipher = if json {
            serde_json::from_str(&contents_trimmed)
                .map_err(|e| anyhow::anyhow!("failed to parse JSON: {e}"))?
        } else {
            serde_yaml::from_str(&contents_trimmed)
                .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?
        };

        if cipher.name.is_empty() {
            return Err(anyhow::anyhow!("name cannot be empty"));
        }

        Ok(Some(cipher))
    })();
    after_editor(&contents, interactive, result).map(|cipher| {
        cipher.map(|cipher| (cipher, interactive.then_some(contents)))
    })
}

// `add --from-file`'s counterpart to `add_structured`: same
// template/`$EDITOR`/reparse flow, but `editable_to_decrypted` into a
// fresh `DecryptedCipher` (a locally-generated id -- there's no server
// here to assign one) instead of encrypting and pushing to the server.
#[allow(clippy::too_many_arguments)]
pub(super) fn add_from_file(
    path: &std::path::Path,
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    json: bool,
    generated_password: Option<&str>,
    secure_note: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let mut vault = load_from_file(path, passphrase)?;

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
        let (data, fields, notes) = editable_to_decrypted(&cipher);
        let id = uuid::Uuid::new_v4().to_string();
        vault.entries.push(DecryptedCipher {
            attachment_metadata: AttachmentMetadata::new(&id, 0),
            id,
            folder: cipher.folder.clone(),
            name: cipher.name.clone(),
            data,
            fields,
            notes,
            history: Vec::new(),
            attachments: Vec::new(),
            archived: false,
            deleted: false,
            account: None,
            revision_date: None,
        });

        backup_file(path)?;
        let exported = vault
            .entries
            .iter()
            .map(|e| {
                to_exported_entry(
                    e,
                    &vault.attachment_data,
                    &vault.entry_extra,
                )
            })
            .collect();
        save_to_file(
            path,
            exported,
            vault.collections,
            vault.passphrase.as_deref(),
        )?;

        print_created(&cipher.name);
        Ok(())
    })();
    after_editor(
        editor_buffer.as_deref().unwrap_or(""),
        editor_buffer.is_some(),
        result,
    )
}

pub fn generate(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let password = rbw::pwgen::pwgen(ty, len);
    println!("{password}");

    if let Some(name) = name {
        unlock(None, None)?;

        let mut db = load_db()?;
        // unwrap is safe here because the call to unlock above is guaranteed
        // to populate these or error
        let mut access_token = db.access_token.as_ref().unwrap().clone();
        let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();

        let name = crate::actions::encrypt(name, None, None)?;
        let username = username
            .map(|username| crate::actions::encrypt(username, None, None))
            .transpose()?;
        let password = crate::actions::encrypt(&password, None, None)?;
        let uris: Vec<_> = uris
            .iter()
            .map(|uri| {
                Ok(rbw::db::Uri {
                    uri: crate::actions::encrypt(&uri.0, None, None)?,
                    match_type: uri.1,
                })
            })
            .collect::<anyhow::Result<_>>()?;

        let mut folder_id = None;
        if let Some(folder_name) = folder {
            let (tokens, folders) =
                rbw::actions::list_folders(&access_token, &refresh_token)?;
            if let Some(tokens) = tokens {
                access_token = tokens.access_token;
                db.access_token = Some(access_token.clone());
                if let Some(new_refresh_token) = tokens.refresh_token {
                    refresh_token = new_refresh_token;
                    db.refresh_token = Some(refresh_token.clone());
                }
                save_db(&db)?;
            }

            let folders: Vec<(String, String)> = folders
                .iter()
                .cloned()
                .map(|(id, name)| {
                    Ok((id, crate::actions::decrypt(&name, None, None)?))
                })
                .collect::<anyhow::Result<_>>()?;

            for (id, name) in folders {
                if name == folder_name {
                    folder_id = Some(id);
                }
            }
            if folder_id.is_none() {
                let (tokens, id) = rbw::actions::create_folder(
                    &access_token,
                    &refresh_token,
                    &crate::actions::encrypt(folder_name, None, None)?,
                )?;
                if let Some(tokens) = tokens {
                    access_token = tokens.access_token;
                    db.access_token = Some(access_token.clone());
                    if let Some(new_refresh_token) = tokens.refresh_token {
                        refresh_token = new_refresh_token;
                        db.refresh_token = Some(refresh_token.clone());
                    }
                    save_db(&db)?;
                }
                folder_id = Some(id);
            }
        }

        let (tokens, _) = rbw::actions::add(
            &access_token,
            &refresh_token,
            &name,
            &rbw::db::EntryData::Login {
                username,
                password: Some(password),
                uris,
                totp: None,
                fido2_credentials: Vec::new(),
            },
            &[],
            None,
            folder_id.as_deref(),
        )?;

        after_server_write(&mut db, tokens)?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn edit(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    json: bool,
    _yaml: bool,
    patch: bool,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return edit_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            json,
            force_exact,
            from_file_passphrase,
        );
    }
    edit_structured(
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        json,
        patch,
        force_exact,
    )
}

// What `rbw edit --field NAME` writes to, resolved against the entry.
pub(super) enum EditFieldTarget {
    Name,
    Notes,
    Username,
    Password,
    Totp,
    Uris,
    Custom(String),
}

impl EditFieldTarget {
    pub(super) fn resolve(
        decrypted: &DecryptedCipher,
        field: &str,
    ) -> anyhow::Result<Self> {
        // Built-in fields win, as in `rbw get --field`.
        let is_login = matches!(decrypted.data, DecryptedData::Login { .. });
        let builtin = field.parse::<Field>().ok();
        match builtin {
            Some(Field::Name) => return Ok(Self::Name),
            Some(Field::Notes) => return Ok(Self::Notes),
            Some(Field::Username) if is_login => return Ok(Self::Username),
            Some(Field::Password) if is_login => return Ok(Self::Password),
            Some(Field::Totp) if is_login => return Ok(Self::Totp),
            Some(Field::Uris) if is_login => return Ok(Self::Uris),
            _ => {}
        }
        // Then an existing custom field, matched exactly, then ignoring
        // case (keeping its stored spelling, since `set` matches custom
        // field names exactly).
        let names =
            || decrypted.fields.iter().filter_map(|f| f.name.as_deref());
        if let Some(name) = names()
            .find(|n| *n == field)
            .or_else(|| names().find(|n| n.eq_ignore_ascii_case(field)))
        {
            return Ok(Self::Custom(name.to_string()));
        }
        if builtin.is_some() {
            return Err(anyhow::anyhow!(
                "field '{field}' can't be edited with --field on this \
                entry; use `rbw edit --yaml`"
            ));
        }
        Ok(Self::Custom(field.to_string()))
    }

    pub(super) fn current(&self, decrypted: &DecryptedCipher) -> String {
        let login = |f: fn(&DecryptedData) -> Option<String>| {
            f(&decrypted.data).unwrap_or_default()
        };
        match self {
            Self::Name => decrypted.name.clone(),
            Self::Notes => decrypted.notes.clone().unwrap_or_default(),
            Self::Username => login(|d| match d {
                DecryptedData::Login { username, .. } => username.clone(),
                _ => None,
            }),
            Self::Password => login(|d| match d {
                DecryptedData::Login { password, .. } => password.clone(),
                _ => None,
            }),
            Self::Totp => login(|d| match d {
                DecryptedData::Login { totp, .. } => totp.clone(),
                _ => None,
            }),
            Self::Uris => login(|d| match d {
                DecryptedData::Login { uris, .. } => uris.as_ref().map(|u| {
                    u.iter()
                        .map(|u| u.uri.as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                }),
                _ => None,
            }),
            Self::Custom(name) => decrypted
                .fields
                .iter()
                .find(|f| f.name.as_deref() == Some(name.as_str()))
                .and_then(|f| f.value.clone())
                .unwrap_or_default(),
        }
    }
}

// `rbw edit --field NAME`: reads one field's new value (piped stdin, or
// `$EDITOR` prefilled with the current value) and hands it to `rbw set`, so
// keyed entries, password history and revision checks behave exactly as
// they do there.
#[allow(clippy::too_many_arguments)]
pub fn edit_field(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    field: &str,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    crate::actions::sync()?;

    let db = load_db()?;
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
    let (_, decrypted) = find_entry(
        &db,
        needles.clone(),
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let target = EditFieldTarget::resolve(&decrypted, field)?;
    let current = target.current(&decrypted);
    let contents = rbw::edit::edit(&current, "", "")?;
    // Editors and `<<<` both append a final newline the value never had.
    let value = contents
        .strip_suffix('\n')
        .map_or(contents.as_str(), |v| v.strip_suffix('\r').unwrap_or(v));
    if value == current {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    let mut new_name = None;
    let mut new_notes = None;
    let mut new_username = None;
    let mut new_password = None;
    let mut new_totp = None;
    let mut new_uris = Vec::new();
    let mut new_fields = Vec::new();
    match &target {
        EditFieldTarget::Notes => new_notes = Some(value),
        EditFieldTarget::Custom(name) => {
            new_fields.push((name.clone(), value.to_string()));
        }
        _ if value.trim().is_empty() => {
            return Err(anyhow::anyhow!(
                "refusing to set an empty {field}; use `rbw edit --yaml` \
                to clear it"
            ))
        }
        EditFieldTarget::Name => new_name = Some(value),
        EditFieldTarget::Username => new_username = Some(value),
        EditFieldTarget::Password => new_password = Some(value),
        EditFieldTarget::Totp => new_totp = Some(value),
        EditFieldTarget::Uris => {
            new_uris = value
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
        }
    }

    set(
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
        &new_uris,
        new_totp,
        &new_fields,
        false,
        &[],
        None,
        false,
        true,
        force_exact,
        None,
        None,
    )
}

// `edit --from-file`'s counterpart to `edit_structured`: same
// `decrypted_to_editable` → `$EDITOR` → reparse flow (including no-op
// detection on an untouched buffer and password-history tracking), but
// `editable_to_decrypted` (plain data, no crypto) instead of
// `editable_to_encrypted`, and saved back to `path` instead of pushed to
// the server.
pub(super) fn edit_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    json: bool,
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

    let editable = decrypted_to_editable(&decrypted);

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

    let interactive = std::io::stdin().is_terminal();
    let contents = rbw::edit::edit(&serialized, help, ext)?;
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

        let (data, fields, notes) = editable_to_decrypted(&updated);

        let mut new_entry = decrypted.clone();
        new_entry.name = updated.name;
        new_entry.folder = updated.folder;
        new_entry.data = data;
        new_entry.fields = fields;
        new_entry.notes = notes;

        if let (
            DecryptedData::Login {
                password: Some(old_pw),
                ..
            },
            DecryptedData::Login {
                password: new_pw, ..
            },
        ) = (&decrypted.data, &new_entry.data)
        {
            if Some(old_pw) != new_pw.as_ref() {
                new_entry.history.insert(
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

        if let Some(pos) =
            vault.entries.iter().position(|e| e.id == decrypted.id)
        {
            vault.entries[pos] = new_entry;
        }

        backup_file(path)?;
        let exported = vault
            .entries
            .iter()
            .map(|e| {
                to_exported_entry(
                    e,
                    &vault.attachment_data,
                    &vault.entry_extra,
                )
            })
            .collect();
        save_to_file(
            path,
            exported,
            vault.collections,
            vault.passphrase.as_deref(),
        )
    })();
    after_editor(&contents, interactive, result)
}

// `remove --from-file`: same needle matching and confirmation prompt as
// the live-account path, but drops the entry from an in-memory vault and
// saves it back to `path` instead of calling `rbw::actions::remove`.
pub(super) fn remove_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
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

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if !yes
        && !confirm(&format!(
            "Delete entry {}?",
            style::name(&decrypted.name, stdout_supports_color())
        ))?
    {
        return Ok(());
    }

    vault.entries.retain(|e| e.id != decrypted.id);

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
    )
}

#[allow(clippy::too_many_arguments)]
pub fn remove(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    force: bool,
    yes: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return remove_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            force_exact,
            yes,
            from_file_passphrase,
        );
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

    // Plain `remove` only ever targets a live (non-trashed) entry -- moving
    // it to trash. `--force` additionally falls back to a trashed entry (to
    // permanently purge something already there) if no live match exists.
    let (entry, decrypted) = if force {
        find_entry(
            &db,
            needles.clone(),
            username,
            folder,
            collection,
            org,
            ignore_case,
            force_exact,
        )
        .or_else(|_| {
            find_deleted_entry(
                &db,
                &needles,
                username,
                folder,
                collection,
                org,
                ignore_case,
                force_exact,
            )
        })
        .with_context(|| format!("couldn't find entry for '{desc}'"))?
    } else {
        find_entry(
            &db,
            needles,
            username,
            folder,
            collection,
            org,
            ignore_case,
            force_exact,
        )
        .with_context(|| format!("couldn't find entry for '{desc}'"))?
    };

    let prompt = if force {
        format!(
            "Permanently delete entry {}? This cannot be undone!",
            style::name(&decrypted.name, stdout_supports_color())
        )
    } else {
        format!(
            "Delete entry {}?",
            style::name(&decrypted.name, stdout_supports_color())
        )
    };
    if !yes && !confirm(&prompt)? {
        return Ok(());
    }

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let rotated = if force {
        rbw::actions::delete_permanently(
            access_token,
            refresh_token,
            &entry.id,
        )?
    } else {
        rbw::actions::remove(access_token, refresh_token, &entry.id)?
    };
    if let (Some(tokens), ()) = rotated {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}
