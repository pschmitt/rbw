use super::*;

pub fn api_enable(
    listen: Option<&str>,
    hostname: Option<&str>,
) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()?;
    if let Some(listen) = listen {
        listen
            .parse::<std::net::SocketAddr>()
            .context("API listen address must be a socket address")?;
        listen.clone_into(&mut config.api.listen);
    }
    if let Some(hostname) = hostname {
        anyhow::ensure!(
            !hostname.trim().is_empty(),
            "API hostname must not be empty"
        );
        hostname.clone_into(&mut config.api.hostname);
    }
    rbw::remote_api::ensure_tls_material(&config.api.hostname)?;
    config.api.enabled = true;
    config.save()?;
    let enable_result =
        ensure_agent().and_then(|()| wait_for_listener(&config.api));
    if let Err(error) = enable_result {
        config.api.enabled = false;
        config.save()?;
        let shutdown = wait_for_listener_stopped();
        if let Err(shutdown_error) = shutdown {
            return Err(error.context(format!(
                "API enable failed; configuration was rolled back, but listener shutdown also failed: {shutdown_error:#}"
            )));
        }
        return Err(error);
    }
    println!("Remote API enabled at {}", api_server_url(&config)?);
    println!(
        "Server CA certificate: {}",
        rbw::dirs::remote_api_dir().join("pki/ca.pem").display()
    );
    Ok(())
}

pub fn api_disable() -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()?;
    config.api.enabled = false;
    config.save()?;
    wait_for_listener_stopped()?;
    println!("Remote API disabled");
    Ok(())
}

pub fn api_status() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let status = rbw::remote_api::load_listener_status()?;
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
    println!("configured={} listener={listener}", config.api.enabled);
    println!(
        "bind={} server={}",
        config.api.listen,
        api_server_url(&config)?
    );
    Ok(())
}

pub fn api_client_create(name: &str) -> anyhow::Result<()> {
    let client = rbw::remote_api::create_client(name)?;
    let (ca, cert, key) = rbw::remote_api::client_export_paths(&client.id);
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

pub fn api_client_list() -> anyhow::Result<()> {
    let store = rbw::remote_api::load_policy_store()?;
    if store.clients.is_empty() {
        println!("No remote API clients");
        return Ok(());
    }
    for client in store.clients.values() {
        let fields: usize = client.items.values().map(Vec::len).sum();
        println!(
            "{}\t{}\t{}\t{} item(s), {fields} field grant(s), status {}",
            client.id,
            client.name,
            client.account.as_deref().unwrap_or("unscoped"),
            client.items.len(),
            if client.status {
                "granted"
            } else {
                "not granted"
            },
        );
    }
    Ok(())
}

pub fn api_status_grant(
    client_id: &str,
    account: &str,
) -> anyhow::Result<()> {
    rbw::remote_api::grant_status(client_id, account)?;
    println!(
        "Granted non-secret status for account {account} to client {client_id}; no item fields were granted"
    );
    Ok(())
}

pub fn api_status_revoke(client_id: &str) -> anyhow::Result<()> {
    rbw::remote_api::revoke_status(client_id)?;
    println!("Revoked non-secret status permission for client {client_id}");
    Ok(())
}

pub fn api_client_revoke(id: &str) -> anyhow::Result<()> {
    rbw::remote_api::revoke_client(id)?;
    println!("Revoked remote API client {id}");
    Ok(())
}

pub fn api_grant(
    client_id: &str,
    account: &str,
    item_id: &str,
    field_tokens: &[String],
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
    println!("Revoked item field grants for client {client_id}");
    Ok(())
}

fn api_server_url(config: &rbw::config::Config) -> anyhow::Result<String> {
    let listen: std::net::SocketAddr = config
        .api
        .listen
        .parse()
        .context("invalid remote API listen address")?;
    let hostname =
        if config.api.hostname.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", config.api.hostname)
        } else {
            config.api.hostname.clone()
        };
    Ok(format!("https://{hostname}:{}", listen.port()))
}

fn wait_for_listener(config: &rbw::config::ApiConfig) -> anyhow::Result<()> {
    for _ in 0..50 {
        if let Some(status) = rbw::remote_api::load_listener_status()? {
            if status.enabled
                && status.listen == config.listen
                && status.hostname == config.hostname
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
