use super::*;

// A vault loaded from an export file for `--from-file` (`list`/`search`/
// `tui`): entries are already decrypted, since that's what the export
// format is. Attachment bytes are kept in a side table keyed by attachment
// id, since `DecryptedAttachment` itself only carries metadata.
pub struct FileVault {
    pub entries: Vec<DecryptedCipher>,
    pub attachment_data: std::collections::HashMap<String, Vec<u8>>,
    // `org_id`/`collection_ids` per entry, keyed by id: `DecryptedCipher`
    // (shared with the live-account paths, where these are tracked on
    // `rbw::db::Entry` instead) has no room for them, but a save still
    // needs to round-trip them for any entry that isn't the one being
    // edited -- otherwise editing one entry would silently drop another's
    // org association.
    pub entry_extra: std::collections::HashMap<String, FileEntryExtra>,
    // Collections aren't editable through `--from-file` (nothing here
    // creates/renames one), but are carried through so a `save_to_file`
    // after editing entries doesn't silently drop them.
    pub collections: Vec<ExportedCollection>,
    // `Some` when the file was gpg-encrypted -- `save_to_file` re-encrypts
    // with the same passphrase instead of re-prompting.
    pub passphrase: Option<String>,
}

#[derive(Clone, Default)]
pub struct FileEntryExtra {
    pub org_id: Option<String>,
    pub collection_ids: Vec<String>,
}

// Loads an export file as a one-off, in-memory, read-only vault: no config,
// no agent, no account touched at all. This deliberately shares the format
// detection and upstream Bitwarden conversion used by `import`, so every
// command accepting `--from-file` understands rbw JSON/gpg archives as well
// as Bitwarden JSON, encrypted JSON, and zip exports.
//
// `passphrase` is the explicit, non-interactive override from `--passphrase`
// (with the old `--from-file-passphrase` spelling retained as an alias); when
// `None`, the passphrase falls back to `$RBW_EXPORT_PASSPHRASE`, then an
// interactive `/dev/tty` prompt.
pub fn load_from_file(
    path: &std::path::Path,
    passphrase: Option<&str>,
) -> anyhow::Result<FileVault> {
    let raw = read_import_input(Some(path))?;
    let mut passphrase = passphrase.map(std::string::ToString::to_string);

    let detected = crate::import_bitwarden::detect_format(&raw)?;
    let vault = match detected {
        crate::import_bitwarden::DetectedFormat::Rbw => {
            let json_text = if std::str::from_utf8(&raw).is_ok_and(|text| {
                serde_json::from_str::<serde_json::Value>(text).is_ok()
            }) {
                String::from_utf8(raw).unwrap()
            } else {
                let resolved = match &passphrase {
                    Some(p) if !p.is_empty() => p.clone(),
                    _ => resolve_env_or_prompted_passphrase(false)?,
                };
                let text = decrypt_import_archive(&raw, &resolved)?;
                passphrase = Some(resolved);
                text
            };
            let vault: ImportedVault = serde_json::from_str(&json_text)
                .context(
                    "failed to parse import data (expected the JSON shape \
                     produced by `rbw export`)",
                )?;
            vault
        }
        crate::import_bitwarden::DetectedFormat::BitwardenJson => {
            let text = std::str::from_utf8(&raw)
                .context("Bitwarden JSON export is not valid UTF-8")?;
            let bw = crate::import_bitwarden::parse_bitwarden_json(text)?;
            bw_vault_to_imported(bw, None)
        }
        crate::import_bitwarden::DetectedFormat::BitwardenEncryptedJson => {
            let resolved = match &passphrase {
                Some(p) if !p.is_empty() => p.clone(),
                _ => resolve_env_or_prompted_passphrase(false)?,
            };
            let text = crate::import_bitwarden::decrypt_encrypted_json(
                &raw, &resolved,
            )?;
            let bw = crate::import_bitwarden::parse_bitwarden_json(&text)?;
            passphrase = Some(resolved);
            bw_vault_to_imported(bw, None)
        }
        crate::import_bitwarden::DetectedFormat::BitwardenZip => {
            let (bw, attachments) = crate::import_bitwarden::parse_zip(&raw)?;
            bw_vault_to_imported(bw, Some(attachments))
        }
    };

    Ok(file_vault_from_imported(&vault, passphrase))
}

pub(super) fn file_vault_from_imported(
    vault: &ImportedVault,
    passphrase: Option<String>,
) -> FileVault {
    let mut attachment_data = std::collections::HashMap::new();
    let mut entry_extra = std::collections::HashMap::new();
    let entries = vault
        .entries
        .iter()
        .enumerate()
        .map(|(i, imported)| {
            let attachments = imported
                .attachments
                .iter()
                .filter_map(|raw_attachment| {
                    match parse_file_attachment(raw_attachment) {
                        Ok((attachment, data)) => {
                            attachment_data
                                .insert(attachment.id.clone(), data);
                            Some(attachment)
                        }
                        Err(e) => {
                            log::warn!(
                                "couldn't parse an attachment on '{}': {e:#}",
                                imported.name
                            );
                            None
                        }
                    }
                })
                .collect::<Vec<_>>();
            let id = imported
                .id
                .clone()
                .unwrap_or_else(|| format!("from-file-{i}"));
            entry_extra.insert(
                id.clone(),
                FileEntryExtra {
                    org_id: imported.org_id.clone(),
                    collection_ids: imported.collection_ids.clone(),
                },
            );
            DecryptedCipher {
                attachment_metadata: AttachmentMetadata::new(
                    &id,
                    attachments.len(),
                ),
                id,
                folder: imported.folder.clone(),
                name: imported.name.clone(),
                data: imported_data_to_decrypted(&imported.data),
                fields: imported
                    .fields
                    .iter()
                    .map(|f| DecryptedField {
                        name: f.name.clone(),
                        value: f.value.clone(),
                        ty: f.ty.as_deref().and_then(|ty| {
                            parse_field_type(ty)
                                .inspect_err(|e| {
                                    log::warn!(
                                        "skipping an unrecognized field \
                                        type on '{}': {e:#}",
                                        imported.name
                                    );
                                })
                                .ok()
                        }),
                        linked_id: None,
                    })
                    .collect(),
                notes: imported.notes.clone(),
                history: imported
                    .history
                    .iter()
                    .map(|h| DecryptedHistoryEntry {
                        last_used_date: h.last_used_date.clone(),
                        password: h.password.clone(),
                    })
                    .collect(),
                attachments,
                archived: imported.archived,
                deleted: imported.deleted,
                account: None,
                revision_date: None,
            }
        })
        .collect();

    let collections = vault
        .collections
        .iter()
        .enumerate()
        .map(|(i, imported)| ExportedCollection {
            id: imported
                .id
                .clone()
                .unwrap_or_else(|| format!("from-file-collection-{i}")),
            org_id: imported.org_id.clone(),
            name: imported.name.clone(),
        })
        .collect();

    FileVault {
        entries,
        attachment_data,
        entry_extra,
        collections,
        passphrase,
    }
}

// Parses one raw attachment JSON value (see `ImportedAttachment`) into a
// `DecryptedAttachment` plus its decoded bytes. A missing id gets a
// synthetic one (stable within this one load, which is all `--from-file`
// needs it for) rather than failing the whole attachment.
pub(super) fn parse_file_attachment(
    raw: &serde_json::Value,
) -> anyhow::Result<(DecryptedAttachment, Vec<u8>)> {
    let parsed: ImportedAttachment = serde_json::from_value(raw.clone())
        .context("unrecognized attachment shape")?;
    let data_base64 = parsed
        .data_base64
        .context("attachment is missing data_base64")?;
    let data = rbw::base64::decode(&data_base64)
        .context("failed to decode attachment data")?;
    let id = parsed.id.unwrap_or_else(|| {
        format!(
            "from-file-attachment-{}",
            &data_base64[..data_base64.len().min(16)]
        )
    });
    Ok((
        DecryptedAttachment {
            id,
            file_name: parsed.file_name,
            size: None,
            size_name: None,
        },
        data,
    ))
}

// Writes `entries`/`collections` back to `path` in whatever format they
// were loaded in (`format` is `FileVault::format`, and `passphrase` is
// `FileVault::passphrase`/
// `TuiFileVault::passphrase` -- `Some` round-trips back through gpg with
// the same passphrase, `None` writes plain JSON), via the exact same
// tar.gz/gpg/atomic-write pipeline `export()` uses. Attachment bytes
// aren't re-embedded here -- callers that add/keep an attachment already
// have its `ExportedAttachment` (with `data_base64`) to put on the entry
// before calling this.
pub(super) fn save_to_file(
    path: &std::path::Path,
    entries: Vec<ExportedEntry>,
    collections: Vec<ExportedCollection>,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    // Read the existing file before replacing it. This keeps all existing
    // writeback call sites format-preserving, including TUI edits, without
    // trusting a caller to remember to thread the detected format through.
    let format = crate::import_bitwarden::detect_format(&read_import_input(
        Some(path),
    )?)?;
    let vault = ExportedVault {
        entries,
        collections,
    };
    match format {
        crate::import_bitwarden::DetectedFormat::Rbw => {
            if let Some(passphrase) = passphrase {
                let archive = build_export_tar_gz(&vault)?;
                let encrypted = gpg_symmetric_encrypt(passphrase, &archive)?;
                write_secure_output_file(path, &encrypted)
            } else {
                let mut json = serde_json::to_vec_pretty(&vault)
                    .context("failed to serialize vault to JSON")?;
                json.push(b'\n');
                write_secure_output_file(path, &json)
            }
        }
        crate::import_bitwarden::DetectedFormat::BitwardenJson => {
            let (bw, _) = exported_vault_to_bw(&vault);
            let mut json = serde_json::to_vec_pretty(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            json.push(b'\n');
            write_secure_output_file(path, &json)
        }
        crate::import_bitwarden::DetectedFormat::BitwardenEncryptedJson => {
            let passphrase = passphrase.context(
                "cannot write an encrypted Bitwarden export without a \
                 passphrase",
            )?;
            let (bw, _) = exported_vault_to_bw(&vault);
            let json = serde_json::to_string(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            let encrypted = crate::import_bitwarden::encrypt_encrypted_json(
                &json,
                passphrase,
                rbw::api::KdfType::Pbkdf2,
                600_000,
                None,
                None,
            )?;
            write_secure_output_file(path, encrypted.as_bytes())
        }
        crate::import_bitwarden::DetectedFormat::BitwardenZip => {
            let (bw, attachments) = exported_vault_to_bw(&vault);
            let json = serde_json::to_string_pretty(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            let zip =
                crate::import_bitwarden::write_zip(&json, &attachments)?;
            write_secure_output_file(path, &zip)
        }
    }
}

// Snapshots `path` to a sibling `.bak` file before the first write of a
// `--from-file` writeback session, so there's always a copy of the
// pre-edit content sitting next to it regardless of how the edits that
// follow turn out.
pub(super) fn backup_file(path: &std::path::Path) -> anyhow::Result<()> {
    let mut backup = path.as_os_str().to_os_string();
    backup.push(".bak");
    std::fs::copy(path, &backup).with_context(|| {
        format!(
            "failed to back up {} to {}",
            path.display(),
            std::path::Path::new(&backup).display()
        )
    })?;
    Ok(())
}

// The inverse of `load_from_file`'s per-entry mapping: re-attaches
// `org_id`/`collection_ids` (not on `DecryptedCipher` at all -- see
// `FileEntryExtra`) and re-embeds attachment bytes from the side table
// (not on `DecryptedAttachment`, which only carries metadata) so a saved
// entry round-trips through `load_from_file` unchanged if untouched.
pub(super) fn to_exported_entry(
    decrypted: &DecryptedCipher,
    attachment_data: &std::collections::HashMap<String, Vec<u8>>,
    entry_extra: &std::collections::HashMap<String, FileEntryExtra>,
) -> ExportedEntry {
    let extra = entry_extra.get(&decrypted.id).cloned().unwrap_or_default();
    ExportedEntry {
        id: decrypted.id.clone(),
        org_id: extra.org_id,
        folder: decrypted.folder.clone(),
        name: decrypted.name.clone(),
        data: decrypted.data.clone(),
        fields: decrypted.fields.clone(),
        notes: decrypted.notes.clone(),
        history: decrypted.history.clone(),
        collection_ids: extra.collection_ids,
        archived: decrypted.archived,
        deleted: decrypted.deleted,
        attachments: decrypted
            .attachments
            .iter()
            .map(|a| ExportedAttachment {
                id: a.id.clone(),
                file_name: a
                    .file_name
                    .clone()
                    .unwrap_or_else(|| a.id.clone()),
                data_base64: attachment_data
                    .get(&a.id)
                    .map(rbw::base64::encode)
                    .unwrap_or_default(),
            })
            .collect(),
    }
}
