use super::*;

fn write_api_output(
    value: &serde_json::Value,
    output: OutputMode,
) -> anyhow::Result<()> {
    write_serialized_pretty(value, output, "failed to write API output")
}

fn write_api_policy(
    value: &serde_json::Value,
    output: OutputMode,
) -> anyhow::Result<()> {
    let output = if output == OutputMode::Default {
        OutputMode::Yaml
    } else {
        output
    };
    write_api_output(value, output)
}

pub fn api_enable(
    listen: Vec<String>,
    hostname: Option<&str>,
    hostname_aliases: Vec<String>,
    output: OutputMode,
) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()?;
    let previous = config.api.clone();
    match listen.as_slice() {
        [] => {}
        [address] => {
            config.api.listen = rbw::config::ApiListen::One(address.clone());
        }
        _ => config.api.listen = rbw::config::ApiListen::Many(listen),
    }
    rbw::remote_api::primary_listen_port(&config.api.listen)?;
    if let Some(hostname) = hostname {
        hostname.clone_into(&mut config.api.hostname);
    }
    if !hostname_aliases.is_empty() {
        config.api.hostname_aliases = hostname_aliases;
    }
    rbw::remote_api::ensure_tls_material(&config.api)?;
    config.api.enabled = true;
    config.save()?;
    let enable_result =
        ensure_agent().and_then(|()| wait_for_listener(&config.api));
    if let Err(error) = enable_result {
        config.api = previous;
        config.save()?;
        let rollback = if config.api.enabled {
            wait_for_listener(&config.api)
        } else {
            wait_for_listener_stopped()
        };
        if let Err(rollback_error) = rollback {
            return Err(error.context(format!(
                "API enable failed; configuration was rolled back, but restoring listener state also failed: {rollback_error:#}"
            )));
        }
        return Err(error);
    }
    if output_is_structured(output) || stdout_is_terminal() {
        return api_status(output);
    }
    println!("Remote API enabled at {}", api_server_url(&config)?);
    println!(
        "Server CA certificate: {}",
        rbw::dirs::remote_api_dir().join("pki/ca.pem").display()
    );
    Ok(())
}

pub fn api_disable(output: OutputMode) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()?;
    config.api.enabled = false;
    config.save()?;
    wait_for_listener_stopped()?;
    if output_is_structured(output) || stdout_is_terminal() {
        return api_status(output);
    }
    println!("Remote API disabled");
    Ok(())
}

pub fn api_status(output: OutputMode) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let status = rbw::remote_api::load_listener_status()?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({
                "enabled": config.api.enabled,
                "bind": config.api.listen,
                "serverUrl": api_server_url(&config)?,
                "listener": status,
            }),
            output,
        );
    }
    let listener = status.as_ref().map_or_else(
        || "not running".to_owned(),
        |status| {
            status.error.as_ref().map_or_else(
                || {
                    if status.listening {
                        "listening".to_owned()
                    } else {
                        "stopped".to_owned()
                    }
                },
                |error| format!("failed: {error}"),
            )
        },
    );
    if stdout_is_terminal() {
        let mut fields = vec![
            (
                "Configuration",
                if config.api.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
                .to_owned(),
            ),
            ("Listener", listener),
            ("Bind", config.api.listen.to_string()),
            ("Server URL", api_server_url(&config)?),
        ];
        if let Some(status) = status.filter(|status| status.listening) {
            fields.extend(
                status
                    .addresses
                    .iter()
                    .map(|address| ("Listening on", address.to_string())),
            );
        }
        if config.api.enabled {
            fields.push((
                "CA certificate",
                rbw::dirs::remote_api_dir()
                    .join("pki/ca.pem")
                    .display()
                    .to_string(),
            ));
        }
        if let Some(browser) = &config.api.browser {
            fields.push(("Browser origin", browser.origin.clone()));
            fields.push((
                "Browser upstream",
                format!("127.0.0.1:{}", browser.port),
            ));
        }
        return print_fields(&fields);
    }
    println!("configured={} listener={listener}", config.api.enabled);
    println!(
        "bind={} server={}",
        config.api.listen,
        api_server_url(&config)?
    );
    if let Some(status) = status.filter(|status| status.listening) {
        for address in status.addresses {
            println!("listening={address}");
        }
    }
    Ok(())
}

pub fn api_client_create(
    name: &str,
    output: OutputMode,
) -> anyhow::Result<()> {
    let client = rbw::remote_api::create_client(name)?;
    let (ca, cert, key) = rbw::remote_api::client_export_paths(&client.id);
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({
                "name": client.name, "id": client.id, "auth": "mTLS",
                "caCertificate": ca, "clientCertificate": cert, "privateKeyFile": key,
                "serverUrl": api_server_url(&rbw::config::Config::load()?)?,
            }),
            output,
        );
    }
    if stdout_is_terminal() {
        return print_fields(&[
            ("Client", client.name),
            ("Client ID", client.id),
            ("Authentication", "mTLS".to_owned()),
            ("Access", "No grants".to_owned()),
            ("CA certificate", ca.display().to_string()),
            ("Client certificate", cert.display().to_string()),
            ("Private key file", key.display().to_string()),
            ("Server URL", api_server_url(&rbw::config::Config::load()?)?),
        ]);
    }
    println!(
        "Created client {} ({}) with no grants",
        client.name, client.id
    );
    println!("CA certificate: {}", ca.display());
    println!("Client certificate: {}", cert.display());
    println!("Client private key: {}", key.display());
    println!(
        "Server URL: {}",
        api_server_url(&rbw::config::Config::load()?)?
    );
    Ok(())
}

pub fn api_client_list(output: OutputMode) -> anyhow::Result<()> {
    let store = rbw::remote_api::load_policy_store()?;
    if output_is_structured(output) {
        let clients = store.clients.values().map(|client| {
            let policy = store.access.assignments.get(&client.id);
            let accounts = policy.and_then(|name| store.access.named.get(name))
                .map_or_else(|| client.account.iter().collect::<Vec<_>>(),
                    |grants| grants.keys().collect());
            serde_json::json!({
                "id": client.id, "name": client.name, "auth": "mTLS",
                "policy": policy, "accounts": accounts,
                "sourceAllowlist": store.access.source_allowlists.get(&client.id),
            })
        }).chain(store.browser.clients.iter().map(|(id, client)| {
            serde_json::json!({
                "id": id, "name": client.name, "auth": "browser",
                "policy": client.policy, "accounts": [client.account],
            })
        })).collect::<Vec<_>>();
        return write_api_output(
            &serde_json::json!({"clients": clients}),
            output,
        );
    }
    if store.clients.is_empty() && store.browser.clients.is_empty() {
        println!("No remote API clients");
        return Ok(());
    }
    if stdout_is_terminal() {
        let columns = [
            TableColumn {
                header: "name",
                style: TableColumnStyle::Name,
            },
            TableColumn {
                header: "client id",
                style: TableColumnStyle::Id,
            },
            TableColumn {
                header: "auth",
                style: TableColumnStyle::EntryType,
            },
            TableColumn {
                header: "account",
                style: TableColumnStyle::Account,
            },
            TableColumn {
                header: "policy",
                style: TableColumnStyle::Default,
            },
            TableColumn {
                header: "grants",
                style: TableColumnStyle::Default,
            },
        ];
        let mut rows: Vec<_> = store.clients.values().map(|client| {
            if let Some(policy) = store.access.assignments.get(&client.id) {
                let accounts = store.access.named.get(policy).into_iter().flat_map(|rules| rules.keys())
                    .cloned().collect::<Vec<_>>().join(", ");
                return vec![client.name.clone(), client.id.clone(), "mTLS".to_owned(), accounts, policy.clone(), "—".to_owned()];
            }
            let fields = client.items.values().map(Vec::len).sum::<usize>();
            let status = rbw::remote_api::granted_status_accounts(client).len();
            vec![
                client.name.clone(),
                client.id.clone(),
                "mTLS".to_owned(),
                client.account.clone().unwrap_or_else(|| "—".to_owned()),
                "direct".to_owned(),
                format!("{} items / {fields} fields / {} global / {status} status / {} unlock",
                    client.items.len(), client.all_items.len(), client.unlock_accounts.len()),
            ]
        }).collect();
        rows.extend(store.browser.clients.iter().map(|(id, client)| {
            vec![
                client.name.clone(),
                id.clone(),
                "browser".to_owned(),
                client.account.clone(),
                client.policy.clone(),
                "—".to_owned(),
            ]
        }));
        rows.sort_by(|a, b| a[0].cmp(&b[0]).then_with(|| a[1].cmp(&b[1])));
        return print_table(&columns, &rows, "");
    }
    for client in store.clients.values() {
        if let Some(policy) = store.access.assignments.get(&client.id) {
            let accounts = store
                .access
                .named
                .get(policy)
                .into_iter()
                .flat_map(|rules| rules.keys())
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "{}\t{}\t{accounts}\tpolicy {policy}",
                client.id, client.name
            );
            continue;
        }
        let fields: usize = client.items.values().map(Vec::len).sum();
        println!(
            "{}\t{}\t{}\t{} item(s), {fields} field grant(s), account-wide fields [{}], status [{}], unlock [{}]",
            client.id,
            client.name,
            client.account.as_deref().unwrap_or("unscoped"),
            client.items.len(),
            client.all_items.iter().map(rbw::remote_api::FieldRef::path_token).collect::<Vec<_>>().join(", "),
            rbw::remote_api::granted_status_accounts(client).join(", "),
            client.unlock_accounts.join(", "),
        );
    }
    for (id, client) in &store.browser.clients {
        println!(
            "{id}\t{:?}\t{:?}\tpolicy {}",
            client.name, client.account, client.policy
        );
    }
    Ok(())
}

pub fn api_status_grant(
    client_id: &str,
    accounts: &[String],
    all_configured: bool,
    output: OutputMode,
) -> anyhow::Result<()> {
    let accounts = if all_configured {
        rbw::config::Config::load()?
            .accounts()
            .into_iter()
            .map(|account| account.name)
            .collect::<Vec<_>>()
    } else {
        accounts.to_vec()
    };
    anyhow::ensure!(!accounts.is_empty(), "at least one account is required");
    rbw::remote_api::grant_status(client_id, &accounts)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "granted", "clientId": client_id, "permission": "status", "accounts": accounts}),
            output,
        );
    }
    if stdout_is_terminal() {
        return print_access_result(
            "granted",
            client_id,
            &format!("status · {}", accounts.join(", ")),
        );
    }
    println!(
        "Granted non-secret status for {} account(s) to client {client_id}; no item fields were granted",
        accounts.len()
    );
    for account in accounts {
        println!("  {account}");
    }
    Ok(())
}

pub fn api_status_revoke(
    client_id: &str,
    account: Option<&str>,
    output: OutputMode,
) -> anyhow::Result<()> {
    rbw::remote_api::revoke_status(client_id, account)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "revoked", "clientId": client_id, "permission": "status", "account": account}),
            output,
        );
    }
    if stdout_is_terminal() {
        return print_access_result(
            "revoked",
            client_id,
            &format!("status · {}", account.unwrap_or("all accounts")),
        );
    }
    if let Some(account) = account {
        println!(
            "Revoked status for account {account} from client {client_id}"
        );
    } else {
        println!("Revoked all status grants for client {client_id}");
    }
    Ok(())
}

pub fn api_unlock_grant(
    client_id: &str,
    account: &str,
    output: OutputMode,
) -> anyhow::Result<()> {
    rbw::remote_api::grant_unlock(client_id, account)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "granted", "clientId": client_id, "permission": "unlock", "account": account}),
            output,
        );
    }
    if stdout_is_terminal() {
        return print_access_result(
            "granted",
            client_id,
            &format!("unlock · {account}"),
        );
    }
    println!("Granted unlock for account {account} to client {client_id}; no status or item fields were granted");
    Ok(())
}

pub fn api_unlock_revoke(
    client_id: &str,
    account: Option<&str>,
    output: OutputMode,
) -> anyhow::Result<()> {
    rbw::remote_api::revoke_unlock(client_id, account)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "revoked", "clientId": client_id, "permission": "unlock", "account": account}),
            output,
        );
    }
    if stdout_is_terminal() {
        return print_access_result(
            "revoked",
            client_id,
            &format!("unlock · {}", account.unwrap_or("all accounts")),
        );
    }
    println!("Revoked unlock grants for client {client_id}");
    Ok(())
}

pub fn api_client_revoke(id: &str, output: OutputMode) -> anyhow::Result<()> {
    rbw::remote_api::revoke_client(id)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "revoked", "clientId": id}),
            output,
        );
    }
    if stdout_is_terminal() {
        return print_access_result("revoked", id, "all API access");
    }
    println!("Revoked remote API client {id}");
    Ok(())
}

pub fn api_grant(
    client_id: &str,
    account: &str,
    item_id: &str,
    field_tokens: &[String],
    output: OutputMode,
) -> anyhow::Result<()> {
    let fields = field_tokens
        .iter()
        .map(|token| {
            token.parse::<rbw::remote_api::FieldRef>().map_err(|_| {
                anyhow::anyhow!("unsupported field token '{token}'")
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    rbw::remote_api::grant_fields(client_id, account, item_id, &fields)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "granted", "clientId": client_id, "account": account, "itemId": item_id, "fields": fields}),
            output,
        );
    }
    if stdout_is_terminal() {
        return print_access_result(
            "granted",
            client_id,
            &format!("{account} / {item_id} · {}", field_tokens.join(", ")),
        );
    }
    println!(
        "Granted {} field(s) on item {item_id} to client {client_id}",
        fields.len()
    );
    Ok(())
}

pub fn api_revoke(
    client_id: &str,
    item_id: &str,
    field_tokens: &[String],
    output: OutputMode,
) -> anyhow::Result<()> {
    let fields = field_tokens
        .iter()
        .map(|token| {
            token.parse::<rbw::remote_api::FieldRef>().map_err(|_| {
                anyhow::anyhow!("unsupported field token '{token}'")
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    rbw::remote_api::revoke_fields(client_id, item_id, &fields)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "revoked", "clientId": client_id, "itemId": item_id, "fields": fields}),
            output,
        );
    }
    if stdout_is_terminal() {
        let fields = if field_tokens.is_empty() {
            "all fields".to_owned()
        } else {
            field_tokens.join(", ")
        };
        return print_access_result(
            "revoked",
            client_id,
            &format!("{item_id} · {fields}"),
        );
    }
    println!("Revoked item field grants for client {client_id}");
    Ok(())
}

fn api_server_url(config: &rbw::config::Config) -> anyhow::Result<String> {
    let port = rbw::remote_api::primary_listen_port(&config.api.listen)?;
    let hostname =
        if config.api.hostname.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", config.api.hostname)
        } else {
            config.api.hostname.clone()
        };
    Ok(format!("https://{hostname}:{port}"))
}

fn wait_for_listener(config: &rbw::config::ApiConfig) -> anyhow::Result<()> {
    let listen = config.listen.to_string();
    for _ in 0..50 {
        if let Some(status) = rbw::remote_api::load_listener_status()? {
            if status.enabled
                && status.listen == listen
                && status.hostname == config.hostname
                && status.hostname_aliases == config.hostname_aliases
            {
                if status.listening {
                    return Ok(());
                }
                if let Some(error) = status.error {
                    anyhow::bail!("remote API listener failed: {error}");
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    anyhow::bail!(
        "remote API listener did not become ready; run `rbw api status` for details"
    )
}

fn wait_for_listener_stopped() -> anyhow::Result<()> {
    for _ in 0..50 {
        match rbw::remote_api::load_listener_status()? {
            Some(status) if status.enabled && status.listening => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            _ => return Ok(()),
        }
    }
    anyhow::bail!(
        "API access is disabled, but the listener did not stop; run `rbw api status`"
    )
}

pub fn api_policy_list(output: OutputMode) -> anyhow::Result<()> {
    let store = rbw::remote_api::load_policy_store()?;
    let browser = &store.browser;
    if output_is_structured(output) {
        let policies = ["admin", "read-only"]
            .into_iter()
            .chain(browser.named.keys().map(String::as_str))
            .map(|name| {
                serde_json::json!({
                    "policy": name,
                    "capabilities": browser.capabilities(name),
                    "clientIds": browser.clients.iter()
                        .filter(|(_, client)| client.policy == name)
                        .map(|(id, _)| id).collect::<Vec<_>>(),
                })
            })
            .chain(store.access.named.iter().map(|(name, accounts)| {
                serde_json::json!({
                    "policy": name,
                    "accounts": accounts,
                    "clientIds": store.access.assignments.iter()
                        .filter(|(_, policy)| *policy == name)
                        .map(|(id, _)| id).collect::<Vec<_>>(),
                })
            }))
            .chain(
                store
                    .clients
                    .values()
                    .filter(|client| {
                        !store.access.assignments.contains_key(&client.id)
                    })
                    .map(|client| direct_policy(&store, client)),
            )
            .collect::<Vec<_>>();
        return write_api_output(
            &serde_json::json!({"policies": policies}),
            output,
        );
    }
    let terminal = stdout_is_terminal();
    let columns = [
        TableColumn {
            header: "policy",
            style: TableColumnStyle::Name,
        },
        TableColumn {
            header: "client id",
            style: TableColumnStyle::Id,
        },
        TableColumn {
            header: "scope",
            style: TableColumnStyle::Default,
        },
    ];
    let mut rows = ["admin", "read-only"]
        .into_iter()
        .chain(browser.named.keys().map(String::as_str))
        .map(|name| {
            let capabilities =
                browser.capabilities(name).expect("listed policy exists");
            let clients = browser
                .clients
                .iter()
                .filter(|(_, client)| client.policy == name)
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let capabilities = if terminal {
                "named policy".to_owned()
            } else {
                serde_json::to_string(capabilities)?
            };
            Ok(vec![name.to_owned(), capabilities, clients])
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    for (name, accounts) in &store.access.named {
        let clients = store
            .access
            .assignments
            .iter()
            .filter(|(_, policy)| *policy == name)
            .map(|(id, _)| id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let scope = if terminal {
            accounts.keys().cloned().collect::<Vec<_>>().join(", ")
        } else {
            serde_json::to_string(accounts)?
        };
        rows.push(vec![name.clone(), scope, clients]);
    }
    for client in store
        .clients
        .values()
        .filter(|client| !store.access.assignments.contains_key(&client.id))
    {
        let status = rbw::remote_api::granted_status_accounts(client);
        let scope = client.account.as_deref().unwrap_or("unscoped");
        let grants = if terminal {
            format!(
                "{scope} · {} item grants · {} global fields · {} status · {} unlock",
                client.items.len(),
                client.all_items.len(),
                status.len(),
                client.unlock_accounts.len()
            )
        } else {
            serde_json::to_string(&serde_json::json!({
                "name": client.name,
                "account": client.account,
                "allItems": client.all_items,
                "items": client.items,
                "statusAccounts": status,
                "unlockAccounts": client.unlock_accounts,
            }))?
        };
        let name = if terminal {
            format!("direct ({})", client.name)
        } else {
            "direct".to_owned()
        };
        rows.push(vec![name, grants, client.id.clone()]);
    }
    if terminal {
        // Keep the legacy field order when print_table emits TSV.
        for row in &mut rows {
            row.swap(1, 2);
        }
    }
    print_table(&columns, &rows, "")
}

fn show_account_policy(
    store: &rbw::remote_api::PolicyStore,
    policy: &str,
    accounts: &rbw::remote_api::access_policy::AccountPolicy,
    output: OutputMode,
) -> anyhow::Result<()> {
    let clients = store.access.assignments.iter()
            .filter(|(_, assigned)| *assigned == policy)
            .filter_map(|(id, _)| store.clients.get(id))
            .map(|client| serde_json::json!({
                "id": client.id, "name": client.name,
                "sourceAllowlist": store.access.source_allowlists.get(&client.id),
            }))
            .collect::<Vec<_>>();
    write_api_policy(
        &serde_json::json!({
            "policy": policy, "accounts": accounts, "clients": clients,
        }),
        output,
    )
}

pub fn api_policy_show(
    policy: &str,
    output: OutputMode,
) -> anyhow::Result<()> {
    let store = rbw::remote_api::load_policy_store()?;
    if let Some(accounts) = store.access.named.get(policy) {
        return show_account_policy(&store, policy, accounts, output);
    }
    if let Some(capabilities) = store.browser.capabilities(policy) {
        let clients = store
            .browser
            .clients
            .iter()
            .filter(|(_, client)| client.policy == policy)
            .map(|(id, client)| {
                serde_json::json!({
                    "id": id, "name": client.name, "account": client.account,
                })
            })
            .collect::<Vec<_>>();
        return write_api_policy(
            &serde_json::json!({
                "policy": policy, "capabilities": capabilities, "clients": clients,
            }),
            output,
        );
    }

    let client = if let Some(client) = store.clients.get(policy) {
        client
    } else {
        let mut matches = store
            .clients
            .values()
            .filter(|client| client.name == policy);
        let client = matches
            .next()
            .context("API policy or client was not found")?;
        anyhow::ensure!(
            matches.next().is_none(),
            "ambiguous client name; use its client ID"
        );
        client
    };
    if let Some(assigned) = store.access.assignments.get(&client.id) {
        let accounts = store
            .access
            .named
            .get(assigned)
            .context("assigned policy was not found")?;
        return show_account_policy(&store, assigned, accounts, output);
    }
    write_api_policy(&direct_policy(&store, client), output)
}

fn direct_policy(
    store: &rbw::remote_api::PolicyStore,
    client: &rbw::remote_api::ClientPolicy,
) -> serde_json::Value {
    serde_json::json!({
        "sourceAllowlist": store.access.source_allowlists.get(&client.id),
        "policy": "direct",
        "clientId": client.id,
        "name": client.name,
        "account": client.account,
        "allItems": client.all_items,
        "items": client.items,
        "statusAccounts": rbw::remote_api::granted_status_accounts(client),
        "unlockAccounts": client.unlock_accounts,
    })
}

pub fn api_pairing_list(output: OutputMode) -> anyhow::Result<()> {
    let browser = rbw::remote_api::load_policy_store()?.browser;
    let now = rbw::remote_api::browser_policy::pairing_time();
    if output_is_structured(output) {
        let requests = browser
            .pending
            .iter()
            .filter(|(_, request)| request.expires > now)
            .map(|(id, request)| {
                serde_json::json!({
                    "id": id, "code": request.code, "name": request.name,
                    "expires": request.expires, "denied": request.denied,
                })
            })
            .collect::<Vec<_>>();
        return write_api_output(
            &serde_json::json!({"requests": requests}),
            output,
        );
    }
    let terminal = stdout_is_terminal();
    let columns = [
        TableColumn {
            header: "request id",
            style: TableColumnStyle::Id,
        },
        TableColumn {
            header: "code",
            style: TableColumnStyle::Name,
        },
        TableColumn {
            header: "status",
            style: TableColumnStyle::Status,
        },
        TableColumn {
            header: "name",
            style: TableColumnStyle::Name,
        },
    ];
    let rows = browser
        .pending
        .iter()
        .filter(|(_, request)| request.expires > now)
        .map(|(id, request)| {
            let state = if request.denied { "denied" } else { "pending" };
            vec![
                id.clone(),
                request.code.clone(),
                state.to_owned(),
                if terminal {
                    request.name.clone()
                } else {
                    format!("{:?}", request.name)
                },
            ]
        })
        .collect::<Vec<_>>();
    if rows.is_empty() && terminal {
        println!("No browser pairing requests");
        return Ok(());
    }
    print_table(&columns, &rows, "")
}

pub fn api_policy_import(
    name: &str,
    file: &std::path::Path,
    output: OutputMode,
) -> anyhow::Result<()> {
    let reader = std::fs::File::open(file)
        .context("failed to open API policy file")?;
    let rules = serde_yaml::from_reader(reader)
        .context("invalid account-scoped API policy")?;
    rbw::remote_api::access_policy::set_policy(name, rules)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "updated", "policy": name}),
            output,
        );
    }
    if stdout_is_terminal() {
        print_access_result("updated", name, "account-scoped API policy")?;
    }
    Ok(())
}

pub fn api_client_allow_source(
    client_id: &str,
    sources: &[String],
    output: OutputMode,
) -> anyhow::Result<()> {
    rbw::remote_api::access_policy::set_sources(client_id, sources)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "updated", "clientId": client_id, "sources": sources}),
            output,
        );
    }
    if stdout_is_terminal() {
        let scope = if sources.is_empty() {
            "any source".to_owned()
        } else {
            sources.join(", ")
        };
        print_access_result("updated", client_id, &scope)?;
    }
    Ok(())
}

pub fn api_policy_set(
    name: &str,
    capabilities: Vec<rbw::remote_api::browser_policy::Capability>,
    output: OutputMode,
) -> anyhow::Result<()> {
    rbw::remote_api::browser_policy::set_policy(name, capabilities)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "updated", "policy": name}),
            output,
        );
    }
    if stdout_is_terminal() {
        print_access_result("updated", name, "browser policy")?;
    }
    Ok(())
}

pub fn api_policy_assign(
    client_id: &str,
    policy: &str,
    output: OutputMode,
) -> anyhow::Result<()> {
    rbw::remote_api::access_policy::assign(client_id, policy)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "assigned", "clientId": client_id, "policy": policy}),
            output,
        );
    }
    if stdout_is_terminal() {
        print_access_result("assigned", client_id, policy)?;
    }
    Ok(())
}

pub fn api_pairing_approve(
    request: &str,
    account: &str,
    policy: &str,
    output: OutputMode,
) -> anyhow::Result<()> {
    rbw::remote_api::browser_policy::approve(request, account, policy)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "approved", "requestId": request, "account": account, "policy": policy}),
            output,
        );
    }
    if stdout_is_terminal() {
        print_access_result(
            "approved",
            request,
            &format!("{account} · {policy}"),
        )?;
    }
    Ok(())
}

pub fn api_pairing_deny(
    request: &str,
    output: OutputMode,
) -> anyhow::Result<()> {
    rbw::remote_api::browser_policy::deny(request)?;
    if output_is_structured(output) {
        return write_api_output(
            &serde_json::json!({"action": "denied", "requestId": request}),
            output,
        );
    }
    if stdout_is_terminal() {
        print_access_result("denied", request, "browser pairing")?;
    }
    Ok(())
}
