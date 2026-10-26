use super::*;

// `history --from-file`: same output shape as the live-account path,
// reading `decrypted.history` from an in-memory `DecryptedCipher`.
pub(super) fn history_from_file(
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

    let decrypted = if redact_enabled() {
        decrypted.redacted()
    } else {
        decrypted
    };
    if output_is_structured(output) {
        write_serialized_pretty(
            &decrypted.history,
            output,
            "failed to write history to stdout",
        )?;
    } else if output == OutputMode::Name {
        for history in decrypted.history {
            println!("{}", history.password);
        }
    } else {
        for history in decrypted.history {
            println!("{}: {}", history.last_used_date, history.password);
        }
    }

    Ok(())
}

#[derive(serde::Serialize)]
pub(super) struct AuditFinding {
    pub(super) id: String,
    pub(super) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) revision_date: Option<String>,
    pub(super) issues: Vec<crate::audit::Issue>,
}

// `rbw audit`: weak, reused and (with `hibp`) breached passwords across
// the active account's live Login entries. Only entry references are
// reported, never passwords. With `hibp`, just the first 5 hex characters
// of each password's SHA-1 leave the machine (HIBP's k-anonymity API).
pub fn audit(
    min_bits: u32,
    hibp: bool,
    output: OutputMode,
    fail: bool,
) -> anyhow::Result<()> {
    struct Login {
        cipher: DecryptedCipher,
        user: Option<String>,
        password: String,
    }

    unlock(None, None)?;
    let db = load_db()?;
    let logins: Vec<Login> = db
        .entries
        .iter()
        .filter(|entry| !entry.deleted && !entry.archived)
        .filter(|entry| {
            matches!(entry.data, rbw::db::EntryData::Login { .. })
        })
        .filter_map(|entry| match decrypt_cipher(entry) {
            Ok(cipher) => Some(cipher),
            Err(e) => {
                log::warn!("failed to decrypt entry: {e}");
                None
            }
        })
        .filter_map(|cipher| {
            let DecryptedData::Login {
                username, password, ..
            } = &cipher.data
            else {
                return None;
            };
            let password = password.clone().filter(|p| !p.is_empty())?;
            let user = username.clone();
            Some(Login {
                cipher,
                user,
                password,
            })
        })
        .collect();

    let mut issues: Vec<Vec<crate::audit::Issue>> =
        vec![Vec::new(); logins.len()];
    for (login, issues) in logins.iter().zip(issues.iter_mut()) {
        let bits = crate::audit::estimate_bits(&login.password);
        if bits < min_bits {
            issues.push(crate::audit::Issue::Weak {
                estimated_bits: bits,
            });
        }
    }
    for group in crate::audit::reused_groups(
        logins.iter().map(|login| login.password.as_str()),
    ) {
        for &index in &group {
            let with = group
                .iter()
                .filter(|&&other| other != index)
                .map(|&other| logins[other].cipher.name.clone())
                .collect();
            issues[index].push(crate::audit::Issue::Reused { with });
        }
    }
    if hibp {
        let client = reqwest::blocking::Client::new();
        let mut ranges: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let pb = item_progress_bar(
            u64::try_from(logins.len()).unwrap_or(u64::MAX),
        );
        for (login, issues) in logins.iter().zip(issues.iter_mut()) {
            let (prefix, suffix) = crate::audit::hibp_hash(&login.password);
            if !ranges.contains_key(&prefix) {
                let body = crate::audit::hibp_range(&client, &prefix)
                    .context("Have I Been Pwned range lookup failed")?;
                ranges.insert(prefix.clone(), body);
            }
            let count = crate::audit::hibp_count(&ranges[&prefix], &suffix);
            if count > 0 {
                issues.push(crate::audit::Issue::Breached { count });
            }
            pb.inc(1);
        }
        pb.finish_and_clear();
    }

    let total = logins.len();
    let mut findings: Vec<AuditFinding> = logins
        .into_iter()
        .zip(issues)
        .filter(|(_, issues)| !issues.is_empty())
        .map(|(login, issues)| AuditFinding {
            id: login.cipher.id,
            name: login.cipher.name,
            user: login.user,
            revision_date: login.cipher.revision_date,
            issues,
        })
        .collect();
    findings.sort_by(|a, b| a.name.cmp(&b.name));

    if output_is_structured(output) {
        write_serialized_pretty(
            &findings,
            output,
            "failed to write audit findings to stdout",
        )?;
    } else {
        let columns = [
            TableColumn {
                header: "id",
                style: TableColumnStyle::Id,
            },
            TableColumn {
                header: "name",
                style: TableColumnStyle::Name,
            },
            TableColumn {
                header: "user",
                style: TableColumnStyle::User,
            },
            TableColumn {
                header: "issues",
                style: TableColumnStyle::Default,
            },
        ];
        let rows: Vec<Vec<String>> = findings
            .iter()
            .map(|finding| {
                vec![
                    finding.id.clone(),
                    finding.name.clone(),
                    finding.user.clone().unwrap_or_default(),
                    finding
                        .issues
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                ]
            })
            .collect();
        if !rows.is_empty() {
            print_table(&columns, &rows, "")?;
        }
    }
    eprintln!(
        "{} of {total} logins have issues{}",
        findings.len(),
        if hibp {
            ""
        } else {
            " (breach check skipped; use --hibp)"
        }
    );

    if fail && !findings.is_empty() {
        return Err(anyhow::anyhow!("audit found issues"));
    }
    Ok(())
}

// `rbw history --restore[=N]`: re-applies a previous password through the
// regular `rbw set` path, so the current one lands in the history and the
// confirmation shows the (censored) change.
#[allow(clippy::too_many_arguments)]
pub fn history_restore(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    n: usize,
    yes: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    let mut db = load_db()?;
    let (entry, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )?;
    let previous = restore_candidate(&decrypted, n)?.to_string();
    set_entry(
        &mut db,
        &entry,
        &decrypted,
        None,
        None,
        Some(&previous),
        None,
        &[],
        None,
        &[],
        false,
        &[],
        yes,
    )
}

pub(super) fn restore_candidate(
    decrypted: &DecryptedCipher,
    n: usize,
) -> anyhow::Result<&str> {
    if !matches!(decrypted.data, DecryptedData::Login { .. }) {
        return Err(anyhow::anyhow!(
            "{} is not a Login entry and has no password to restore",
            decrypted.name
        ));
    }
    decrypted
        .history
        .get(n.saturating_sub(1))
        .map(|h| h.password.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} has only {} previous password(s), can't restore #{n}",
                decrypted.name,
                decrypted.history.len()
            )
        })
}

#[allow(clippy::too_many_arguments)]
pub fn history(
    needles: Vec<Needle>,
    username: Option<&str>,
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
        return history_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            output,
            force_exact,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;

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
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    let decrypted = if redact_enabled() {
        decrypted.redacted()
    } else {
        decrypted
    };
    if output_is_structured(output) {
        write_serialized_pretty(
            &decrypted.history,
            output,
            "failed to write history to stdout",
        )?;
    } else if output == OutputMode::Name {
        // There is no "name" for a history item; print just the previous
        // passwords (the primary value), one per line.
        for history in decrypted.history {
            println!("{}", history.password);
        }
    } else {
        for history in decrypted.history {
            println!("{}: {}", history.last_used_date, history.password);
        }
    }

    Ok(())
}
