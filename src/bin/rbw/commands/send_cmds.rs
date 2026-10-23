use super::*;

pub fn send_list(output: OutputMode) -> anyhow::Result<()> {
    unlock(None, None)?;
    let mut db = load_db()?;
    let items = crate::sends::list_sends(&mut db)?;

    if output_is_structured(output) {
        return write_serialized_pretty(
            &items,
            output,
            "failed to serialize sends",
        );
    }

    if output == OutputMode::Name {
        for item in &items {
            println!("{}", item.name);
        }
        return Ok(());
    }

    if items.is_empty() {
        if std::io::stdout().is_terminal() {
            eprintln!("No Sends found.");
        }
        return Ok(());
    }

    let columns = [
        TableColumn {
            header: "NAME",
            style: TableColumnStyle::Name,
        },
        TableColumn {
            header: "ID",
            style: TableColumnStyle::Id,
        },
        TableColumn {
            header: "TYPE",
            style: TableColumnStyle::EntryType,
        },
        TableColumn {
            header: "ACCESS",
            style: TableColumnStyle::Default,
        },
        TableColumn {
            header: "EXPIRATION",
            style: TableColumnStyle::Default,
        },
        TableColumn {
            header: "DELETION",
            style: TableColumnStyle::Default,
        },
        TableColumn {
            header: "STATUS",
            style: TableColumnStyle::Status,
        },
    ];

    let rows = items
        .iter()
        .map(|item| {
            let max_acc = item
                .max_access_count
                .map_or_else(|| "∞".to_string(), |m| m.to_string());
            let access = format!("{}/{}", item.access_count, max_acc);
            let expiration = item.expiration_date.as_deref().unwrap_or("-");
            vec![
                item.name.clone(),
                item.id.clone(),
                item.send_type.to_string(),
                access,
                expiration.to_string(),
                item.deletion_date.clone(),
                item.status_label().to_string(),
            ]
        })
        .collect::<Vec<_>>();

    print_table(&columns, &rows, "")
}

pub fn send_view(
    needle: &str,
    text_only: bool,
    output: OutputMode,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    let mut db = load_db()?;
    let (_raw, item) = crate::sends::find_send(&mut db, needle)?;

    if text_only {
        match item.send_type {
            crate::sends::SendType::Text => {
                let text = item.text.unwrap_or_default();
                if std::io::stdout().is_terminal() && !text.ends_with('\n') {
                    println!("{text}");
                } else {
                    print!("{text}");
                }
                return Ok(());
            }
            crate::sends::SendType::File => {
                anyhow::bail!(
                    "Send '{}' is a file ({})",
                    item.name,
                    item.file_name.as_deref().unwrap_or("unknown")
                );
            }
        }
    }

    if output_is_structured(output) {
        return write_serialized_pretty(
            &item,
            output,
            "failed to serialize send",
        );
    }

    let c = stdout_supports_color();
    println!(
        "{}:          {}",
        style::dim("Name", c),
        style::name(&item.name, c)
    );
    println!(
        "{}:            {}",
        style::dim("ID", c),
        style::uid(&item.id, c)
    );
    println!("{}:    {}", style::dim("Access URL", c), item.url);
    let type_desc = match item.send_type {
        crate::sends::SendType::Text => "Text".to_string(),
        crate::sends::SendType::File => format!(
            "File ({}, {} bytes)",
            item.file_name.as_deref().unwrap_or("unknown"),
            item.file_size.unwrap_or(0)
        ),
    };
    println!("{}:          {}", style::dim("Type", c), type_desc);
    println!(
        "{}:        {}",
        style::dim("Status", c),
        item.status_label()
    );
    let max_acc = item
        .max_access_count
        .map_or_else(|| "unlimited".to_string(), |m| m.to_string());
    println!(
        "{}:  {} / {}",
        style::dim("Access count", c),
        item.access_count,
        max_acc
    );
    if let Some(exp) = &item.expiration_date {
        println!("{}:    {}", style::dim("Expiration", c), exp);
    }
    println!("{}: {}", style::dim("Deletion date", c), item.deletion_date);
    println!(
        "{}:      {}",
        style::dim("Password", c),
        if item.has_password { "Yes" } else { "No" }
    );
    println!(
        "{}:    {}",
        style::dim("Hide email", c),
        if item.hide_email { "Yes" } else { "No" }
    );
    if let Some(notes) = &item.notes {
        if !notes.is_empty() {
            println!("{}:\n{notes}", style::dim("Notes", c));
        }
    }
    if let Some(text) = &item.text {
        let text_label = if item.hidden {
            "Text (hidden by default)"
        } else {
            "Text"
        };
        println!("{}:\n{text}", style::dim(text_label, c));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn send_create(
    name: Option<&str>,
    text: Option<&str>,
    file: Option<&std::path::Path>,
    stdin: bool,
    notes: Option<&str>,
    password: Option<&str>,
    hidden: bool,
    days: u64,
    expire_in: Option<u64>,
    deletion_date: Option<&str>,
    expiration_date: Option<&str>,
    max_access_count: Option<u64>,
    hide_email: bool,
    copy: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    let mut db = load_db()?;

    let (send_name, content) = if let Some(path) = file {
        anyhow::ensure!(path.is_file(), "file not found: {}", path.display());
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .context("invalid file name")?
            .to_string();
        let send_name = name.unwrap_or(&file_name).to_string();
        let bytes = std::fs::read(path).with_context(|| {
            format!("failed to read file: {}", path.display())
        })?;
        (
            send_name,
            crate::sends::SendContent::File { bytes, file_name },
        )
    } else {
        let send_name = name
            .context("Send name is required for text sends")?
            .to_string();
        let content_text = if stdin || text == Some("-") {
            std::io::read_to_string(std::io::stdin())
                .context("failed to read text from stdin")?
        } else if let Some(t) = text {
            t.to_string()
        } else if !std::io::stdin().is_terminal() {
            std::io::read_to_string(std::io::stdin())
                .context("failed to read text from stdin")?
        } else {
            anyhow::bail!("Send text must be provided via -t/--text, --file, or piped via stdin");
        };
        (send_name, crate::sends::SendContent::Text(content_text))
    };

    let expiration_date = expiration_date.map(str::to_string).or_else(|| {
        expire_in.map(|exp_days| {
            humantime::format_rfc3339(
                std::time::SystemTime::now()
                    + std::time::Duration::from_secs(exp_days * 86400),
            )
            .to_string()
        })
    });

    let params = crate::sends::CreateParams {
        name: send_name,
        content,
        notes: notes.map(str::to_string),
        password: password.map(str::to_string),
        hidden,
        days,
        deletion_date: deletion_date.map(str::to_string),
        expiration_date,
        max_access_count,
        hide_email,
    };

    let item = crate::sends::create_send(&mut db, params)?;

    let c = stdout_supports_color();
    eprintln!(
        "{} Send '{}' ({})",
        style::success("Created", c),
        style::name(&item.name, c),
        style::uid(&item.id, c)
    );
    println!("{}", item.url);

    if copy {
        crate::actions::system_clipboard_store(&item.url)?;
        eprintln!("{}", style::dim("Copied link to clipboard.", c));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn send_edit(
    needle: &str,
    name: Option<&str>,
    text: Option<&str>,
    notes: Option<&str>,
    password: Option<&str>,
    remove_password: bool,
    hidden: Option<bool>,
    disabled: Option<bool>,
    hide_email: Option<bool>,
    days: Option<u64>,
    deletion_date: Option<&str>,
    expire_in: Option<u64>,
    expiration_date: Option<&str>,
    clear_expiration: bool,
    max_access_count: Option<u64>,
    clear_max_access: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    let mut db = load_db()?;
    let (existing, _info) = crate::sends::find_send(&mut db, needle)?;

    let exp_opt = if clear_expiration {
        Some(None)
    } else if let Some(exp) = expiration_date {
        Some(Some(exp.to_string()))
    } else {
        expire_in.map(|exp_days| {
            Some(
                humantime::format_rfc3339(
                    std::time::SystemTime::now()
                        + std::time::Duration::from_secs(exp_days * 86400),
                )
                .to_string(),
            )
        })
    };

    let max_acc_opt = if clear_max_access {
        Some(None)
    } else {
        max_access_count.map(Some)
    };

    let params = crate::sends::UpdateParams {
        name: name.map(str::to_string),
        notes: notes.map(str::to_string),
        text: text.map(str::to_string),
        hidden,
        password: password.map(str::to_string),
        remove_password,
        days,
        deletion_date: deletion_date.map(str::to_string),
        expiration_date: exp_opt,
        max_access_count: max_acc_opt,
        disabled,
        hide_email,
    };

    let updated = crate::sends::update_send(&mut db, existing, params)?;

    let c = stdout_supports_color();
    eprintln!(
        "{} Send '{}' ({})",
        style::success("Updated", c),
        style::name(&updated.name, c),
        style::uid(&updated.id, c)
    );
    println!("{}", updated.url);

    Ok(())
}

pub fn send_remove(needle: &str, yes: bool) -> anyhow::Result<()> {
    unlock(None, None)?;
    let mut db = load_db()?;
    let (_existing, info) = crate::sends::find_send(&mut db, needle)?;

    if !yes {
        let c = stdout_supports_color();
        if !confirm(&format!(
            "Delete Send '{}' ({})?",
            style::name(&info.name, c),
            style::uid(&info.id, c)
        ))? {
            return Ok(());
        }
    }

    crate::sends::delete_send(&mut db, &info.id)?;

    let c = stdout_supports_color();
    eprintln!(
        "{} Send '{}' ({})",
        style::success("Deleted", c),
        style::name(&info.name, c),
        style::uid(&info.id, c)
    );

    Ok(())
}

pub fn send_link(needle: &str, copy: bool) -> anyhow::Result<()> {
    unlock(None, None)?;
    let mut db = load_db()?;
    let (_existing, info) = crate::sends::find_send(&mut db, needle)?;

    println!("{}", info.url);

    if copy {
        crate::actions::system_clipboard_store(&info.url)?;
        let c = stdout_supports_color();
        eprintln!("{}", style::dim("Copied link to clipboard.", c));
    }

    Ok(())
}
