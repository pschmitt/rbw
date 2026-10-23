use super::*;

#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub(super) struct ExportedAttachment {
    pub(super) id: String,
    pub(super) file_name: String,
    // decrypted attachment contents, base64-encoded so the export
    // round-trips cleanly through JSON
    pub(super) data_base64: String,
}

#[derive(serde::Serialize)]
pub(super) struct ExportedEntry {
    pub(super) id: String,
    pub(super) org_id: Option<String>,
    pub(super) folder: Option<String>,
    pub(super) name: String,
    #[serde(flatten)]
    pub(super) data: DecryptedData,
    pub(super) fields: Vec<DecryptedField>,
    pub(super) notes: Option<String>,
    pub(super) history: Vec<DecryptedHistoryEntry>,
    pub(super) collection_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(super) archived: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(super) deleted: bool,
    // empty unless `--attachments` was passed, so exports produced
    // without that flag are byte-for-byte identical to before it
    // existed
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) attachments: Vec<ExportedAttachment>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportedCollection {
    pub id: String,
    pub org_id: String,
    pub name: String,
}

#[derive(serde::Serialize)]
pub(super) struct ExportedVault {
    pub(super) entries: Vec<ExportedEntry>,
    pub(super) collections: Vec<ExportedCollection>,
}

// Downloads and decrypts every attachment on `entry`, using the
// already-decrypted `decrypted_attachments` (from `decrypt_cipher`)
// for filenames. This mirrors `attachment_get`'s handling of the
// legacy quirk where an attachment's filename may still be
// entry-key-encrypted even though its data is attachment-key-encrypted:
// `decrypt_cipher` already resolved that via
// `decrypt_field_with_attachment_key`, so we just reuse its result
// here rather than re-deriving it.
pub(super) fn export_attachments(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    decrypted_attachments: &[DecryptedAttachment],
) -> anyhow::Result<Vec<ExportedAttachment>> {
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

    let mut out = Vec::with_capacity(entry.attachments.len());
    for (attachment, decrypted_attachment) in
        entry.attachments.iter().zip(decrypted_attachments)
    {
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
                    save_db(db)?;
                }
                url
            }
            Err(e) => attachment.url.clone().ok_or(e)?,
        };
        let encrypted = rbw::actions::download_attachment(&url)
            .with_context(|| {
                format!("failed to download attachment {}", attachment.id)
            })?;
        let decrypted_bytes = crate::actions::decrypt_attachment(
            encrypted,
            attachment.key.as_deref(),
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?;
        let file_name = decrypted_attachment
            .file_name
            .clone()
            .unwrap_or_else(|| attachment.id.clone());
        out.push(ExportedAttachment {
            id: attachment.id.clone(),
            file_name,
            data_base64: rbw::base64::encode(&decrypted_bytes),
        });
    }
    Ok(out)
}

// Whether an entry belongs in `export`/`mirror`'s output, within the given
// collection/org scope, if any. Trashed entries are deliberately not
// filtered here: native rbw exports carry their `deleted` flag, and the
// export command is a backup of the whole vault. `mirror` applies its own
// live-entry filter because the upstream Bitwarden-shaped conversion
// cannot represent trash status.
pub(super) fn export_entry_in_scope(
    entry: &rbw::db::Entry,
    scope_collection_id: Option<&str>,
    scope_org_id: Option<&str>,
) -> bool {
    entry_in_collection_org_scope(entry, scope_collection_id, scope_org_id)
}

pub(super) fn export_entry_status_allowed(
    entry: &rbw::db::Entry,
    skip_trash: bool,
    skip_archived: bool,
) -> bool {
    !(skip_trash && entry.deleted || skip_archived && entry.archived)
}

// Whether `entry` belongs to the given collection/org scope (either or both
// `None` matches everything regardless of the entry's own collection/org).
// `collection_ids`/`org_id` are plain IDs on every synced entry, never
// encrypted, so this needs no decryption -- shared by the mirror/export
// scope above and by `--collection`/`--org` filtering on
// `find_entry`/`list`/`search`.
pub(super) fn entry_in_collection_org_scope(
    entry: &rbw::db::Entry,
    collection_id: Option<&str>,
    org_id: Option<&str>,
) -> bool {
    if let Some(cid) = collection_id {
        if !entry.collection_ids.iter().any(|c| c == cid) {
            return false;
        }
    }
    if let Some(oid) = org_id {
        if entry.org_id.as_deref() != Some(oid) {
            return false;
        }
    }
    true
}

// Builds rbw's own decrypted `ExportedVault` shape from the currently
// active account (see `crate::actions::set_active_account`) -- shared by
// `export` and `mirror_vault`, both of which can additionally scope to a
// single `--collection` and/or `--org`, since neither an export nor a
// cross-account copy should have to mean "the entire vault". Assumes the
// account is already unlocked.
pub(super) fn build_exported_vault(
    attachments: bool,
    collection: Option<&str>,
    org: Option<&str>,
    skip_trash: bool,
    skip_archived: bool,
) -> anyhow::Result<ExportedVault> {
    build_exported_vault_matching(
        attachments,
        collection,
        org,
        skip_trash,
        skip_archived,
        None,
    )
}

// `build_exported_vault`, optionally limited to the single entry `only_id`
// (and the collections it belongs to), so `rbw move` doesn't decrypt -- or
// download the attachments of -- the whole vault.
pub(super) fn build_exported_vault_matching(
    attachments: bool,
    collection: Option<&str>,
    org: Option<&str>,
    skip_trash: bool,
    skip_archived: bool,
    only_id: Option<&str>,
) -> anyhow::Result<ExportedVault> {
    let mut db = load_db()?;

    // Same name-or-ID `--collection`/`--org` resolution the find-family
    // commands (get/show/list/search/...) use: `--org` alone filters by
    // organization directly, `--collection` (optionally combined with
    // `--org` to disambiguate a name shared across orgs) resolves to one
    // specific collection.
    let (scope_collection_id, scope_org_id) =
        resolve_entry_scope(&db, collection, org)?;

    let entries_snapshot: Vec<rbw::db::Entry> = db
        .entries
        .iter()
        .filter(|entry| {
            export_entry_status_allowed(entry, skip_trash, skip_archived)
        })
        .filter(|entry| only_id.is_none_or(|id| entry.id == id))
        .filter(|entry| {
            export_entry_in_scope(
                entry,
                scope_collection_id.as_deref(),
                scope_org_id.as_deref(),
            )
        })
        .cloned()
        .collect();

    let mut entries: Vec<ExportedEntry> = Vec::new();
    let pb = item_progress_bar(
        u64::try_from(entries_snapshot.len()).unwrap_or(u64::MAX),
    );
    for entry in &entries_snapshot {
        let decrypted = decrypt_cipher(entry)?;
        pb.set_message(fit_to_width(&decrypted.name, PROGRESS_MSG_WIDTH));

        let exported_attachments =
            if attachments && !entry.attachments.is_empty() {
                export_attachments(&mut db, entry, &decrypted.attachments)?
            } else {
                Vec::new()
            };

        entries.push(ExportedEntry {
            id: decrypted.id,
            org_id: entry.org_id.clone(),
            folder: decrypted.folder,
            name: decrypted.name,
            data: decrypted.data,
            fields: decrypted.fields,
            notes: decrypted.notes,
            history: decrypted.history,
            collection_ids: entry.collection_ids.clone(),
            archived: entry.archived,
            deleted: entry.deleted,
            attachments: exported_attachments,
        });
        pb.inc(1);
    }
    pb.finish_and_clear();

    let mut collections: Vec<ExportedCollection> = db
        .collections
        .iter()
        .filter(|c| scope_org_id.as_deref().is_none_or(|oid| c.org_id == oid))
        .filter(|c| {
            only_id.is_none()
                || entries.iter().any(|e| e.collection_ids.contains(&c.id))
        })
        .map(|c| {
            let name =
                crate::actions::decrypt(&c.name, None, Some(&c.org_id))?;
            Ok(ExportedCollection {
                id: c.id.clone(),
                org_id: c.org_id.clone(),
                name,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    collections.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ExportedVault {
        entries,
        collections,
    })
}

pub fn export(
    format: crate::import_bitwarden::ExportFormat,
    attachments: bool,
    skip_trash: bool,
    skip_archived: bool,
    encrypt: Option<&str>,
    output: Option<&std::path::Path>,
    collection: Option<&str>,
    org: Option<&str>,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use crate::import_bitwarden::ExportFormat;

    // Resolve the passphrase up front (from $RBW_EXPORT_PASSPHRASE or an
    // interactive prompt when `--encrypt` was given without a value), so a
    // mistyped confirmation fails before any decryption work happens.
    // `--encrypt` means two different things depending on `--format`: rbw's
    // own gpg passphrase for the default format, or the Bitwarden
    // "Encrypted JSON" export's password for `bitwarden-encrypted-json`.
    // That format always needs *some* password, so unlike rbw's own
    // (optionally encrypted) format, choosing it prompts on its own even
    // without `--encrypt` -- `--encrypt` only still matters there to
    // supply the password inline and skip the prompt.
    let passphrase = resolve_export_passphrase(encrypt)?;
    let passphrase = if matches!(format, ExportFormat::BitwardenEncryptedJson)
        && passphrase.is_none()
    {
        Some(resolve_env_or_prompted_passphrase(true)?)
    } else {
        passphrase
    };

    if let Some(path) = from_file {
        let file_vault = load_from_file(path, from_file_passphrase)?;
        let vault = exported_vault_from_file(
            &file_vault,
            collection,
            org,
            skip_trash,
            skip_archived,
        )?;
        return write_exported_vault(
            format, passphrase, output, &vault, None,
        );
    }

    unlock(None, None)?;

    let vault = build_exported_vault(
        attachments,
        collection,
        org,
        skip_trash,
        skip_archived,
    )?;
    // Reloaded (rather than threaded through `build_exported_vault`) purely
    // for the KDF settings the `BitwardenEncryptedJson` branch below needs;
    // cheap, since it's just the local db.json cache, and none of those
    // fields change as a side effect of building the vault.
    let db = load_db()?;

    write_exported_vault(format, passphrase, output, &vault, Some(&db))
}

pub(super) fn exported_vault_from_file(
    file_vault: &FileVault,
    collection: Option<&str>,
    org: Option<&str>,
    skip_trash: bool,
    skip_archived: bool,
) -> anyhow::Result<ExportedVault> {
    let collection_id = collection
        .map(|wanted| {
            file_vault
                .collections
                .iter()
                .find(|c| {
                    (c.id == wanted || c.name == wanted)
                        && org.is_none_or(|org_id| c.org_id == org_id)
                })
                .map(|c| c.id.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "collection '{wanted}' not found in export"
                    )
                })
        })
        .transpose()?;

    let entries = file_vault
        .entries
        .iter()
        .filter(|entry| {
            !(skip_trash && entry.deleted || skip_archived && entry.archived)
        })
        .filter(|entry| {
            let extra = file_vault.entry_extra.get(&entry.id);
            org.is_none_or(|org_id| {
                extra.and_then(|extra| extra.org_id.as_deref())
                    == Some(org_id)
            })
        })
        .filter(|entry| {
            collection_id.as_deref().is_none_or(|collection_id| {
                file_vault.entry_extra.get(&entry.id).is_some_and(|extra| {
                    extra.collection_ids.iter().any(|id| id == collection_id)
                })
            })
        })
        .map(|entry| {
            to_exported_entry(
                entry,
                &file_vault.attachment_data,
                &file_vault.entry_extra,
            )
        })
        .collect();

    let collections = file_vault
        .collections
        .iter()
        .filter(|collection| {
            org.is_none_or(|org_id| collection.org_id == org_id)
        })
        .filter(|collection| {
            collection_id
                .as_deref()
                .is_none_or(|collection_id| collection.id == collection_id)
        })
        .cloned()
        .collect();

    Ok(ExportedVault {
        entries,
        collections,
    })
}

pub(super) fn write_exported_vault(
    format: crate::import_bitwarden::ExportFormat,
    passphrase: Option<String>,
    output: Option<&std::path::Path>,
    vault: &ExportedVault,
    db: Option<&rbw::db::Db>,
) -> anyhow::Result<()> {
    use crate::import_bitwarden::ExportFormat;

    match format {
        ExportFormat::Rbw => {
            if let Some(passphrase) = passphrase {
                let archive = build_export_tar_gz(vault)?;
                let encrypted = gpg_symmetric_encrypt(&passphrase, &archive)?;
                write_export_bytes(
                    output,
                    &encrypted,
                    "failed to write encrypted export",
                )
            } else if let Some(path) = output {
                let mut json = serde_json::to_vec_pretty(vault)
                    .context("failed to serialize export to JSON")?;
                json.push(b'\n');
                write_export_bytes(
                    Some(path),
                    &json,
                    "failed to write export JSON",
                )
            } else {
                write_json_pretty(vault, "failed to write export to stdout")
            }
        }
        ExportFormat::BitwardenJson => {
            let (bw, _attachments) = exported_vault_to_bw(vault);
            let mut json = serde_json::to_vec_pretty(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            json.push(b'\n');
            write_export_bytes(
                output,
                &json,
                "failed to write Bitwarden JSON export",
            )
        }
        ExportFormat::BitwardenEncryptedJson => {
            let (bw, _attachments) = exported_vault_to_bw(vault);
            let json_text = serde_json::to_string(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            let passphrase = passphrase
                .context("Bitwarden encrypted JSON requires a passphrase")?;
            let (kdf, iterations, memory, parallelism) = db.map_or(
                (rbw::api::KdfType::Pbkdf2, 600_000, None, None),
                |db| {
                    (
                        db.kdf.unwrap_or(rbw::api::KdfType::Pbkdf2),
                        db.iterations.unwrap_or(600_000),
                        db.memory,
                        db.parallelism,
                    )
                },
            );
            let encrypted = crate::import_bitwarden::encrypt_encrypted_json(
                &json_text,
                &passphrase,
                kdf,
                iterations,
                memory,
                parallelism,
            )?;
            write_export_bytes(
                output,
                encrypted.as_bytes(),
                "failed to write encrypted Bitwarden export",
            )
        }
        ExportFormat::BitwardenZip => {
            let (bw, zip_attachments) = exported_vault_to_bw(vault);
            let json_text = serde_json::to_string_pretty(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            let zip_bytes = crate::import_bitwarden::write_zip(
                &json_text,
                &zip_attachments,
            )?;
            write_export_bytes(
                output,
                &zip_bytes,
                "failed to write zip export",
            )
        }
        ExportFormat::BitwardenCsv => {
            let (bw, _attachments) = exported_vault_to_bw(vault);
            let (csv_text, skipped) =
                crate::import_bitwarden::write_csv(&bw)?;
            if skipped > 0 {
                eprintln!(
                    "{} {skipped} entr{} of a type Bitwarden's CSV export \
                     doesn't support (Card/Identity/SSH key) were skipped",
                    style::warning("Warning:", stdout_supports_color()),
                    if skipped == 1 { "y" } else { "ies" },
                );
            }
            write_export_bytes(
                output,
                csv_text.as_bytes(),
                "failed to write CSV export",
            )
        }
    }
}

pub(super) fn resolve_export_passphrase(
    encrypt: Option<&str>,
) -> anyhow::Result<Option<String>> {
    match encrypt {
        None => Ok(None),
        Some(passphrase) if !passphrase.is_empty() => {
            Ok(Some(passphrase.to_string()))
        }
        Some(_) => resolve_env_or_prompted_passphrase(true).map(Some),
    }
}

pub fn resolve_import_passphrase(
    decrypt: bool,
    decrypt_passphrase: Option<&str>,
) -> anyhow::Result<Option<String>> {
    if let Some(passphrase) = decrypt_passphrase {
        return Ok(Some(passphrase.to_string()));
    }
    if decrypt {
        return resolve_env_or_prompted_passphrase(false).map(Some);
    }
    Ok(None)
}

pub(super) fn resolve_env_or_prompted_passphrase(
    confirm: bool,
) -> anyhow::Result<String> {
    if let Ok(passphrase) = std::env::var(EXPORT_PASSPHRASE_ENV) {
        if !passphrase.is_empty() {
            return Ok(passphrase);
        }
    }

    if confirm {
        prompt_new_passphrase()
    } else {
        prompt_existing_passphrase()
    }
}

pub(super) fn prompt_new_passphrase() -> anyhow::Result<String> {
    let first = prompt_hidden_tty("Export passphrase: ")?;
    if first.is_empty() {
        anyhow::bail!("passphrase must not be empty");
    }
    let second = prompt_hidden_tty("Confirm export passphrase: ")?;
    if first != second {
        anyhow::bail!("passphrases did not match");
    }
    Ok(first)
}

pub(super) fn prompt_existing_passphrase() -> anyhow::Result<String> {
    prompt_hidden_tty("Import passphrase: ")
}

pub(super) fn prompt_hidden_tty(prompt: &str) -> anyhow::Result<String> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("failed to open /dev/tty for passphrase prompt")?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&tty);
    let original = tcgetattr(fd)?;
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    tcsetattr(fd, &hidden)
        .context("failed to disable terminal echo for passphrase prompt")?;

    let _restore = RestoreEcho { fd, original };

    tty.write_all(prompt.as_bytes())
        .context("failed to write passphrase prompt")?;
    tty.flush().context("failed to flush passphrase prompt")?;

    let mut input = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(&mut tty),
        &mut input,
    )
    .context("failed to read passphrase from /dev/tty")?;
    tty.write_all(b"\n")
        .context("failed to finish passphrase prompt")?;
    tty.flush().context("failed to flush passphrase prompt")?;

    Ok(input.trim_end_matches(['\r', '\n']).to_string())
}

pub(super) fn tcgetattr(
    fd: std::os::fd::RawFd,
) -> std::io::Result<libc::termios> {
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `termios` points to valid uninitialized memory, and `fd` is an
    // open tty fd when this helper is called.
    let rc = unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: successful `tcgetattr` initialized `termios`.
        Ok(unsafe { termios.assume_init() })
    }
}

pub(super) fn tcsetattr(
    fd: std::os::fd::RawFd,
    termios: &libc::termios,
) -> std::io::Result<()> {
    // SAFETY: `termios` points to a valid termios struct and `fd` is an open
    // tty fd when this helper is called.
    let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, termios) };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn write_export_bytes(
    output: Option<&std::path::Path>,
    bytes: &[u8],
    stdout_context: &'static str,
) -> anyhow::Result<()> {
    output.map_or_else(
        || std::io::stdout().write_all(bytes).context(stdout_context),
        |path| write_secure_output_file(path, bytes),
    )
}

pub(super) fn write_secure_output_file(
    path: &std::path::Path,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => std::path::Path::new("."),
    };
    let mut file = tempfile::Builder::new()
        .prefix(".rbw-export.")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "failed to open temporary export output near {}",
                path.display()
            )
        })?;
    file.as_file_mut()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| {
            format!("failed to set secure permissions on {}", path.display())
        })?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.as_file_mut()
        .sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    file.persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("failed to persist {}", path.display()))?;
    std::fs::File::open(parent)
        .with_context(|| {
            format!(
                "failed to sync export output directory {}",
                parent.display()
            )
        })?
        .sync_all()
        .with_context(|| {
            format!(
                "failed to sync export output directory {}",
                parent.display()
            )
        })?;
    Ok(())
}

// Packages `value` as pretty-printed JSON named `vault.json` inside an
// in-memory tar.gz archive, returning the compressed bytes.
pub(super) fn build_export_tar_gz<T: serde::Serialize>(
    value: &T,
) -> anyhow::Result<Vec<u8>> {
    let json = serde_json::to_vec_pretty(value)
        .context("failed to serialize export to JSON")?;

    let mut header = tar::Header::new_gnu();
    header.set_size(u64::try_from(json.len()).unwrap_or(u64::MAX));
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();

    let encoder = flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    );
    let mut builder = tar::Builder::new(encoder);
    builder
        .append_data(&mut header, "vault.json", json.as_slice())
        .context("failed to write vault.json into tar archive")?;
    let encoder = builder
        .into_inner()
        .context("failed to finalize tar archive")?;
    encoder.finish().context("failed to finalize gzip stream")
}

// Symmetrically encrypts `plaintext` with `gpg`, passing the passphrase over
// an inherited pipe fd and streaming the plaintext over stdin so neither the
// passphrase nor the decrypted archive ever hit argv or the filesystem.
pub(super) fn gpg_symmetric_encrypt(
    passphrase: &str,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let output = run_gpg_with_passphrase(
        [
            "--batch",
            "--yes",
            "--passphrase-fd",
            "3",
            "--symmetric",
            "--cipher-algo",
            "AES256",
            "-o",
            "-",
        ],
        passphrase,
        plaintext.to_vec(),
        "gpg not found on PATH; install GnuPG to use `rbw export --encrypt`",
    )?;

    if !output.status.success() {
        anyhow::bail!(
            "gpg failed to encrypt export: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(output.stdout)
}

pub(super) fn run_gpg_with_passphrase<const N: usize>(
    args: [&str; N],
    passphrase: &str,
    stdin_data: Vec<u8>,
    not_found_message: &'static str,
) -> anyhow::Result<std::process::Output> {
    let (read_fd, write_fd) =
        rustix::pipe::pipe().context("failed to create passphrase pipe")?;
    let passphrase_fd = std::os::fd::AsRawFd::as_raw_fd(&read_fd);

    {
        let mut writer = std::fs::File::from(write_fd);
        writer
            .write_all(passphrase.as_bytes())
            .and_then(|()| writer.write_all(b"\n"))
            .context("failed to write passphrase to gpg pipe")?;
    }

    let mut child = {
        let mut command = std::process::Command::new("gpg");
        command
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // SAFETY: this runs in the child between fork and exec. It only calls
        // async-signal-safe libc functions (`dup2`/`close`) to map the pipe's
        // read end to fd 3 for gpg's `--passphrase-fd 3`.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(passphrase_fd, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if passphrase_fd != 3 && libc::close(passphrase_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        command.spawn().map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(not_found_message)
            } else {
                anyhow::Error::from(source).context("failed to spawn gpg")
            }
        })?
    };

    drop(read_fd);

    let stdin = child.stdin.take().context("failed to open gpg's stdin")?;
    let stdin_writer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut stdin = stdin;
        stdin.write_all(&stdin_data)
    });

    let output = child
        .wait_with_output()
        .context("failed to wait for gpg to finish")?;
    stdin_writer
        .join()
        .map_err(|_| anyhow::anyhow!("gpg stdin writer thread panicked"))?
        .context("failed to write payload to gpg")?;

    Ok(output)
}

// ===========================================================================
// Import
//
// Reads the JSON produced by `rbw export` (optionally wrapped in a
// gpg-encrypted tar.gz, as produced by `rbw export --encrypt`) and recreates
// its entries and collections in the active account's vault (the active
// account is whatever the global `--account`/`-a` flag or $RBW_ACCOUNT
// resolved to, same as every other command). Deliberately reuses the same
// add/edit/create-collection/create-attachment protocol calls the rest of
// this file already uses instead of hand-rolling anything new.
// ===========================================================================
