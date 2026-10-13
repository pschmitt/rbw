//! Passkey automation keeps private keys inside rbw and the browser CDP socket.
//! Reserve the next counter before injection so an interrupted browser cannot
//! leave the vault behind an assertion already accepted by the relying party.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::Context as _;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;

use super::{actions, commands, FindArgs};

struct Selected {
    entry: rbw::db::Entry,
    credential: commands::DecryptedFido2Credential,
    index: usize,
}

fn select(args: &FindArgs, rp_id: Option<&str>) -> anyhow::Result<Selected> {
    actions::sync()?;
    let db = commands::load_db()?;
    let (entry, decrypted) = if args.needles.is_empty() {
        let rp = rp_id.context("name an entry or give --rp-id")?;
        find_by_rp_id(&db, rp)?
    } else {
        commands::find_entry(
            &db,
            args.needles.clone(),
            args.user.as_deref(),
            args.folder.as_deref(),
            args.collection.as_deref(),
            args.org.as_deref(),
            args.ignorecase,
            args.exact,
        )?
    };
    let commands::DecryptedData::Login {
        fido2_credentials, ..
    } = decrypted.data
    else {
        anyhow::bail!("passkeys require a login item");
    };
    let mut matches =
        fido2_credentials.into_iter().enumerate().filter(|(_, c)| {
            rp_id.is_none_or(|rp| c.rp_id.as_deref() == Some(rp))
        });
    let (index, credential) =
        matches.next().context("no matching passkey")?;
    anyhow::ensure!(
        matches.next().is_none(),
        "ambiguous passkey; select a unique --rp-id"
    );
    Ok(Selected {
        entry,
        credential,
        index,
    })
}

/// The one live login holding a passkey for `rp_id`. Only entries that carry
/// passkeys at all are decrypted.
fn find_by_rp_id(
    db: &rbw::db::Db,
    rp_id: &str,
) -> anyhow::Result<(rbw::db::Entry, commands::DecryptedCipher)> {
    let mut found = Vec::new();
    for entry in &db.entries {
        let has_passkeys = matches!(
            &entry.data,
            rbw::db::EntryData::Login { fido2_credentials, .. }
                if !fido2_credentials.is_empty()
        );
        if entry.deleted || entry.archived || !has_passkeys {
            continue;
        }
        let decrypted = commands::decrypt_cipher(entry)?;
        if let commands::DecryptedData::Login {
            fido2_credentials, ..
        } = &decrypted.data
        {
            if fido2_credentials
                .iter()
                .any(|c| c.rp_id.as_deref() == Some(rp_id))
            {
                found.push((entry.clone(), decrypted));
            }
        }
    }
    anyhow::ensure!(
        found.len() < 2,
        "several entries hold a passkey for {rp_id}; name one"
    );
    found
        .pop()
        .with_context(|| format!("no passkey for {rp_id} in the vault"))
}

fn stored_counter(
    credential: &commands::DecryptedFido2Credential,
) -> anyhow::Result<u32> {
    // An absent field may mean decryption failed. Never reset it to zero.
    credential
        .counter
        .as_deref()
        .context("missing passkey counter")?
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid passkey counter"))
}

fn advance(selected: &Selected, counter: u32) -> anyhow::Result<()> {
    let old = stored_counter(&selected.credential)?;
    anyhow::ensure!(
        counter >= old,
        "refusing to decrease the passkey counter"
    );
    if counter == old {
        return Ok(());
    }
    anyhow::ensure!(
        selected.entry.revision_date.is_some(),
        "missing server revision; refusing an unguarded vault update"
    );
    let mut entry = selected.entry.clone();
    let rbw::db::EntryData::Login {
        fido2_credentials, ..
    } = &mut entry.data
    else {
        anyhow::bail!("passkeys require a login item");
    };
    fido2_credentials[selected.index].counter = Some(actions::encrypt(
        &counter.to_string(),
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?);
    let mut db = commands::load_db()?;
    let access =
        db.access_token.as_deref().context("missing access token")?;
    let refresh = db
        .refresh_token
        .as_deref()
        .context("missing refresh token")?;
    let (tokens, ()) = rbw::actions::edit(
        access,
        refresh,
        &entry.id,
        entry.org_id.as_deref(),
        entry.key.as_deref(),
        &entry.name,
        &entry.data,
        &entry.fields,
        entry.notes.as_deref(),
        entry.folder_id.as_deref(),
        &entry.history,
        &entry.cipher_write_meta(),
    )?;
    commands::after_server_write(&mut db, tokens)
}

pub fn counter(
    args: &FindArgs,
    rp_id: Option<&str>,
    set: Option<u32>,
) -> anyhow::Result<()> {
    commands::unlock(None, None)?;
    let selected = select(args, rp_id)?;
    if let Some(value) = set {
        advance(&selected, value)?;
        warn_counter_enabled(stored_counter(&selected.credential)?, value);
        println!("{value}");
    } else {
        println!("{}", stored_counter(&selected.credential)?);
    }
    Ok(())
}

fn warn_counter_enabled(previous: u32, current: u32) {
    if previous == 0 && current > 0 {
        eprintln!("Warning: passkey counter tracking has been enabled. Sync every Bitwarden client before using this passkey there; a client still holding counter zero may skip syncing and trigger a clone warning.");
    }
}

fn normalize_base64(value: &str) -> anyhow::Result<String> {
    let normalized = value.replace('-', "+").replace('_', "/");
    let padded =
        format!("{normalized}{}", "=".repeat((4 - normalized.len() % 4) % 4));
    let bytes = rbw::base64::decode(padded)
        .map_err(|_| anyhow::anyhow!("invalid passkey encoding"))?;
    Ok(rbw::base64::encode(bytes))
}

fn credential_id(value: &str) -> anyhow::Result<String> {
    uuid::Uuid::parse_str(value).map_or_else(
        |_| normalize_base64(value),
        |id| Ok(rbw::base64::encode(id.as_bytes())),
    )
}

fn next_counter(current: u32) -> anyhow::Result<u32> {
    // Enable counter tracking for Bitwarden credentials created with counter 0.
    current.checked_add(1).context("passkey counter exhausted")
}

fn cdp_credential(
    selected: &Selected,
    reserved: u32,
) -> anyhow::Result<Value> {
    let c = &selected.credential;
    anyhow::ensure!(
        c.key_type.as_deref() == Some("public-key")
            && c.key_algorithm.as_deref() == Some("ECDSA")
            && c.key_curve.as_deref() == Some("P-256"),
        "unsupported passkey key type"
    );
    Ok(json!({
        "credentialId": credential_id(c.credential_id.as_deref().context("missing credential ID")?)?,
        "rpId": c.rp_id.as_deref().context("missing relying party")?,
        "privateKey": normalize_base64(c.key_value.as_deref().context("missing passkey key")?)?,
        "userHandle": normalize_base64(c.user_handle.as_deref().context("missing user handle")?)?,
        "isResidentCredential": c.discoverable.as_deref() == Some("true"),
        "signCount": reserved - 1,
        "backupEligibility": true,
        "backupState": true,
    }))
}

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

struct Cdp {
    socket: Socket,
    sequence: u64,
    events: std::collections::VecDeque<Value>,
}

impl Cdp {
    async fn final_counter(
        &mut self,
        authenticator: &str,
        credential: &str,
        asserted: u32,
    ) -> anyhow::Result<u32> {
        self.send(
            "WebAuthn.setAutomaticPresenceSimulation",
            json!({
                "authenticatorId": authenticator, "enabled": false,
            }),
        )
        .await?;
        // Another assertion may have completed before presence was disabled.
        // Read the credential after the disable acknowledgement rather than
        // trusting the first event. The response includes key material: never
        // include it in errors or logs.
        let result = self.send("WebAuthn.getCredential", json!({
            "authenticatorId": authenticator, "credentialId": credential,
        })).await?;
        anyhow::ensure!(
            result["credential"]["credentialId"].as_str() == Some(credential),
            "browser returned a different passkey"
        );
        let count = result["credential"]["signCount"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .context("missing final browser counter")?;
        anyhow::ensure!(
            count >= asserted,
            "final browser counter is behind its assertion"
        );
        Ok(count)
    }

    async fn receive(&mut self) -> anyhow::Result<Value> {
        if let Some(event) = self.events.pop_front() {
            return Ok(event);
        }
        self.receive_wire().await
    }

    async fn receive_wire(&mut self) -> anyhow::Result<Value> {
        loop {
            let message = self
                .socket
                .next()
                .await
                .context("browser disconnected")?
                .map_err(|_| anyhow::anyhow!("CDP connection failed"))?;
            match message {
                Message::Text(text) => {
                    return serde_json::from_str(&text)
                        .map_err(|_| anyhow::anyhow!("invalid CDP response"))
                }
                Message::Close(_) => anyhow::bail!("browser disconnected"),
                _ => {}
            }
        }
    }

    async fn send(
        &mut self,
        method: &str,
        params: Value,
    ) -> anyhow::Result<Value> {
        self.sequence += 1;
        self.socket
            .send(Message::Text(
                json!({
                    "id": self.sequence, "method": method, "params": params,
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|_| anyhow::anyhow!("CDP send failed"))?;
        loop {
            let response = self.receive_wire().await?;
            if response["id"].as_u64() == Some(self.sequence) {
                // CDP errors can echo parameters; never print their content.
                anyhow::ensure!(
                    response.get("error").is_none(),
                    "CDP command failed: {method}"
                );
                return Ok(response["result"].clone());
            }
            if response.get("method").is_some() {
                self.events.push_back(response);
            }
        }
    }
}

pub fn inject(
    args: &FindArgs,
    rp_id: Option<&str>,
    cdp_url: &str,
    page_id: &str,
    timeout: u64,
) -> anyhow::Result<()> {
    // Websocket trace logging can contain private key frames.
    log::set_max_level(log::LevelFilter::Off);
    commands::unlock(None, None)?;
    let selected = select(args, rp_id)?;
    // One injection per item on this machine. Across machines, the server's
    // lastKnownRevisionDate rejects competing counter reservations.
    rbw::dirs::make_all()?;
    let lock_path = rbw::dirs::pid_file()
        .with_file_name(format!("passkey-{}.lock", selected.entry.id));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(lock_path)?;
    lock.try_lock().map_err(|_| {
        anyhow::anyhow!("another passkey injection is active for this item")
    })?;
    // Refresh under the lock to avoid using a selection made before a prior
    // session finished its writeback.
    let selected = select(args, rp_id)?;
    let previous = stored_counter(&selected.credential)?;
    let reserved = next_counter(previous)?;
    let credential = cdp_credential(&selected, reserved)?;
    let injected_id = credential["credentialId"]
        .as_str()
        .context("missing injected credential ID")?
        .to_string();

    // Fetch target metadata without logging websocket URLs or query tokens.
    let endpoint = url::Url::parse(cdp_url)
        .map_err(|_| anyhow::anyhow!("invalid --cdp-url"))?;
    anyhow::ensure!(
        matches!(endpoint.scheme(), "http" | "https")
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none(),
        "--cdp-url must be an HTTP endpoint without credentials"
    );
    let targets: Vec<Value> = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?
        .get(endpoint.join("/json/list")?)
        .send()
        .map_err(|_| anyhow::anyhow!("cannot fetch browser targets"))?
        .error_for_status()
        .map_err(|_| {
            anyhow::anyhow!("browser target endpoint rejected the request")
        })?
        .json()
        .map_err(|_| anyhow::anyhow!("invalid browser target list"))?;
    let target = targets
        .iter()
        .find(|t| t["id"].as_str() == Some(page_id) && t["type"] == "page")
        .context("no matching browser page; use an exact page ID")?;
    let mut websocket = endpoint
        .join(
            target["webSocketDebuggerUrl"]
                .as_str()
                .context("page has no debugging websocket")?,
        )
        .map_err(|_| anyhow::anyhow!("invalid browser websocket"))?;
    // Browserless may advertise its container-internal hostname. Connect
    // through the trusted endpoint supplied by the caller instead.
    websocket
        .set_scheme(if endpoint.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|()| anyhow::anyhow!("invalid websocket scheme"))?;
    websocket
        .set_host(endpoint.host_str())
        .map_err(|_| anyhow::anyhow!("invalid websocket host"))?;
    websocket
        .set_port(endpoint.port())
        .map_err(|()| anyhow::anyhow!("invalid websocket port"))?;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let (socket, _) = tokio::time::timeout(std::time::Duration::from_secs(10),
            tokio_tungstenite::connect_async(websocket.as_str())).await
            .context("CDP connection timed out")?
            .map_err(|_| anyhow::anyhow!("cannot connect to browser CDP"))?;
        let mut cdp = Cdp { socket, sequence: 0, events: std::collections::VecDeque::new() };
        cdp.send("WebAuthn.enable", json!({})).await?;
        // Disable presence until the counter reservation has reached the vault.
        let result = cdp.send("WebAuthn.addVirtualAuthenticator", json!({"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": true,
            "hasUserVerification": true, "isUserVerified": true,
            "automaticPresenceSimulation": false,
            "defaultBackupEligibility": true, "defaultBackupState": true,
        }})).await?;
        let authenticator = result["authenticatorId"].as_str().context("missing authenticator ID")?.to_string();
        let mut removed = false;
        let operation = async {
            cdp.send("WebAuthn.addCredential", json!({"authenticatorId": authenticator, "credential": credential})).await?;
            // The blocking vault API cannot run on an async runtime thread.
            tokio::task::block_in_place(|| advance(&selected, reserved))?;
            warn_counter_enabled(previous, reserved);
            cdp.send("WebAuthn.setAutomaticPresenceSimulation", json!({"authenticatorId": authenticator, "enabled": true})).await?;
            println!("Passkey ready; reserved counter {reserved}. Waiting for one browser assertion.");
            std::io::stdout().flush()?;
            loop {
                let event = cdp.receive().await?;
                if event["method"] == "WebAuthn.credentialAsserted"
                    && event["params"]["authenticatorId"] == authenticator {
                    let count = event["params"]["credential"]["signCount"].as_u64()
                        .and_then(|n| u32::try_from(n).ok()).context("missing assertion counter")?;
                    anyhow::ensure!(count >= reserved, "browser counter is behind its reservation");
                    let count = cdp.final_counter(&authenticator, &injected_id, count).await?;
                    // Remove the authenticator before the vault writeback so
                    // it cannot assert again while that update is in flight.
                    let removal = cdp.send("WebAuthn.removeVirtualAuthenticator", json!({"authenticatorId": authenticator})).await;
                    removed = removal.is_ok();
                    tokio::task::block_in_place(|| {
                        let current = select(args, rp_id)?;
                        anyhow::ensure!(current.entry.id == selected.entry.id
                            && current.credential.credential_id == selected.credential.credential_id,
                            "passkey changed during the browser session");
                        advance(&current, count.max(stored_counter(&current.credential)?))
                    }).with_context(|| format!("failed to synchronize final browser counter {count}; reconcile the vault before another login"))?;
                    // Even if removal fails, preserve the counter we already
                    // observed before reporting that cleanup needs attention.
                    removal.context("vault counter synchronized but authenticator removal failed; close the browser page")?;
                    println!("Final browser counter {count}; vault synchronized. Check the page to confirm the site accepted the login.");
                    return Ok::<(), anyhow::Error>(());
                }
            }
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(timeout), operation)
            .await.map_err(|_| anyhow::anyhow!("no assertion before timeout; reserved counter retained"))
            .and_then(std::convert::identity);
        if !removed {
            let cleanup = tokio::time::timeout(std::time::Duration::from_secs(5),
                cdp.send("WebAuthn.removeVirtualAuthenticator", json!({"authenticatorId": authenticator}))).await;
            if !matches!(cleanup, Ok(Ok(_))) {
                eprintln!("Could not remove virtual authenticator; close the browser page.");
            }
        }
        outcome
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_enables_tracking_and_rejects_exhaustion() {
        assert_eq!(next_counter(0).unwrap(), 1);
        assert_eq!(next_counter(u32::MAX - 1).unwrap(), u32::MAX);
        assert!(next_counter(u32::MAX).is_err());
        let missing = commands::DecryptedFido2Credential::default();
        assert!(stored_counter(&missing).is_err());
        let malformed = commands::DecryptedFido2Credential {
            counter: Some("4294967296".to_string()),
            ..Default::default()
        };
        assert!(stored_counter(&malformed).is_err());
    }

    #[tokio::test]
    async fn final_counter_captures_racing_assertions_and_rejects_bad_state()
    {
        for (credential_id, final_count, expected) in [
            ("AQID", json!(7), Some(7)),
            ("AQID", json!(8), Some(8)),
            ("AQID", json!(6), None),
            ("AQID", Value::Null, None),
            ("AQID", json!(4_294_967_296_u64), None),
            ("different", json!(8), None),
        ] {
            let listener =
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut ws =
                    tokio_tungstenite::accept_async(stream).await.unwrap();
                let request: Value = serde_json::from_str(
                    ws.next().await.unwrap().unwrap().to_text().unwrap(),
                )
                .unwrap();
                assert_eq!(
                    request["method"],
                    "WebAuthn.setAutomaticPresenceSimulation"
                );
                assert_eq!(
                    request["params"],
                    json!({"authenticatorId": "test", "enabled": false})
                );
                // The first event reported 7. A second assertion completes
                // before the disable acknowledgement and raises the count to 8.
                ws.send(Message::Text(json!({
                    "method": "WebAuthn.credentialAsserted",
                    "params": {"authenticatorId": "test", "credential": {"signCount": 8}},
                }).to_string().into())).await.unwrap();
                ws.send(Message::Text(
                    json!({"id": request["id"], "result": {}})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
                let request: Value = serde_json::from_str(
                    ws.next().await.unwrap().unwrap().to_text().unwrap(),
                )
                .unwrap();
                assert_eq!(request["method"], "WebAuthn.getCredential");
                assert_eq!(
                    request["params"],
                    json!({"authenticatorId": "test", "credentialId": "AQID"})
                );
                ws.send(Message::Text(json!({
                    "id": request["id"], "result": {"credential": {
                        "credentialId": credential_id, "signCount": final_count,
                        "privateKey": "DO-NOT-ECHO",
                    }},
                }).to_string().into())).await.unwrap();
            });
            let (socket, _) =
                tokio_tungstenite::connect_async(format!("ws://{address}"))
                    .await
                    .unwrap();
            let mut cdp = Cdp {
                socket,
                sequence: 0,
                events: std::collections::VecDeque::default(),
            };
            let result = cdp.final_counter("test", "AQID", 7).await;
            if let Some(expected) = expected {
                assert_eq!(result.unwrap(), expected);
            } else {
                let error = result.unwrap_err().to_string();
                assert!(!error.contains("DO-NOT-ECHO"));
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn cdp_preserves_early_assertions_and_does_not_echo_error_parameters(
    ) {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws =
                tokio_tungstenite::accept_async(stream).await.unwrap();
            let first = ws.next().await.unwrap().unwrap();
            let request: Value =
                serde_json::from_str(first.to_text().unwrap()).unwrap();
            // A pending browser get() can assert immediately when presence is
            // enabled, before CDP acknowledges setAutomaticPresenceSimulation.
            ws.send(Message::Text(json!({
                "method": "WebAuthn.credentialAsserted",
                "params": {"authenticatorId": "test", "credential": {"signCount": 7}},
            }).to_string().into())).await.unwrap();
            ws.send(Message::Text(
                json!({"id": request["id"], "result": {}})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
            let second = ws.next().await.unwrap().unwrap();
            let request: Value =
                serde_json::from_str(second.to_text().unwrap()).unwrap();
            ws.send(Message::Text(json!({
                "id": request["id"], "error": {"message": "privateKey=DO-NOT-ECHO"},
            }).to_string().into())).await.unwrap();
        });
        let (socket, _) =
            tokio_tungstenite::connect_async(format!("ws://{address}"))
                .await
                .unwrap();
        let mut cdp = Cdp {
            socket,
            sequence: 0,
            events: std::collections::VecDeque::default(),
        };
        cdp.send("WebAuthn.setAutomaticPresenceSimulation", json!({}))
            .await
            .unwrap();
        let event = cdp.receive().await.unwrap();
        assert_eq!(event["params"]["credential"]["signCount"], 7);
        let error = cdp
            .send("WebAuthn.addCredential", json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "CDP command failed: WebAuthn.addCredential"
        );
        server.await.unwrap();
    }
}
