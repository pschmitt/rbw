//! Browser frontend for the agent API. The reverse proxy terminates HTTPS.

use super::{api_response, ApiState};
use axum::{extract::State, response::Response, routing::post, Json, Router};
use rbw::remote_api::{
    browser_pairing::{BrowserKey, BrowserRequest, Challenges},
    browser_policy::{BrowserClient, Capability},
    ApiError, ClientPolicy, ErrorCode, FieldReadRequest, FieldRef,
};
use std::sync::Arc;

#[derive(Clone)]
struct BrowserState {
    agent: ApiState,
    origin: String,
    challenges: Arc<Challenges>,
}

pub(super) fn router(agent: ApiState, origin: String) -> Router {
    Router::new()
        .route("/v1/browser/challenge", post(challenge))
        .route("/v1/browser/request", post(request))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(BrowserState {
            agent,
            origin,
            challenges: Arc::default(),
        })
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengeInput {
    public_key: String,
}

async fn challenge(
    State(state): State<BrowserState>,
    Json(input): Json<ChallengeInput>,
) -> Response {
    api_response(
        async {
            let key = parse_key(&input.public_key)?;
            let challenge =
                state.challenges.issue(&key).map_err(|_| failed())?;
            Ok(serde_json::json!({ "challenge": challenge }))
        }
        .await,
    )
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedInput {
    public_key: String,
    request: String,
    signature: String,
}

async fn request(
    State(state): State<BrowserState>,
    Json(input): Json<SignedInput>,
) -> Response {
    api_response(
        async {
            let key = parse_key(&input.public_key)?;
            let request = state
                .challenges
                .authenticate(
                    &key,
                    &state.origin,
                    input.request.as_bytes(),
                    &input.signature,
                )
                .map_err(|_| ApiError::new(ErrorCode::Unauthorized))?;
            handle_request(&state.agent, &key, request).await
        }
        .await,
    )
}

fn parse_key(encoded: &str) -> Result<BrowserKey, ApiError> {
    BrowserKey::parse(encoded).map_err(|_| invalid())
}

fn invalid() -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest)
}
fn failed() -> ApiError {
    ApiError::new(ErrorCode::Unavailable)
}
fn forbidden() -> ApiError {
    ApiError::new(ErrorCode::Forbidden)
}

fn payload<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, ApiError> {
    serde_json::from_value(value).map_err(|_| invalid())
}

fn json<T: serde::Serialize>(
    value: T,
) -> Result<serde_json::Value, ApiError> {
    serde_json::to_value(value).map_err(|_| failed())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PairInput {
    name: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SearchInput {
    url: Option<String>,
    query: String,
    site_only: bool,
}

async fn handle_request(
    state: &ApiState,
    key: &BrowserKey,
    request: BrowserRequest,
) -> Result<serde_json::Value, ApiError> {
    let (enabled, store) = (state.policy)().await?;
    if !enabled {
        return Err(ApiError::new(ErrorCode::Unauthorized));
    }
    let browser = store.browser;
    let now = rbw::remote_api::browser_policy::pairing_time();
    match request.operation.as_str() {
        "pair" => {
            let input: PairInput = payload(request.payload)?;
            let mut request = None;
            rbw::remote_api::update_policy_store(|store| {
                request = Some(store.browser.request_pairing(
                    key,
                    &input.name,
                    now,
                )?);
                Ok(())
            })
            .map_err(|_| invalid())?;
            return json(request);
        }
        "pairing_status" => {
            if let Some(client) = browser.clients.get(key.id()) {
                return Ok(serde_json::json!({
                    "state": "approved",
                    "policy": client.policy,
                }));
            }
            return Ok(serde_json::json!({
                "state": match browser.pending_request(key.id(), now) {
                    Ok(request) if request.denied => "denied",
                    Ok(_) => "pending",
                    Err(_) => "expired",
                }
            }));
        }
        _ => {}
    }

    let client = browser.clients.get(key.id()).ok_or_else(forbidden)?;
    let capability = match request.operation.as_str() {
        "status" | "search" | "list" | "read" => Capability::Read,
        "unlock" => Capability::Unlock,
        "passkeys" | "assert" => Capability::Passkeys,
        _ => return Err(invalid()),
    };
    if !browser.allows(client, capability) {
        return Err(forbidden());
    }

    let capabilities =
        browser.capabilities(&client.policy).ok_or_else(forbidden)?;
    let actor = client.name.clone();
    let operation = request.operation;
    let result = dispatch(state, client, &operation, request.payload)
        .await
        .map(|mut value| {
            if operation == "status" {
                value["capabilities"] = serde_json::json!(capabilities);
            }
            value
        });
    super::record_api_event(
        actor,
        match operation.as_str() {
            "status" => "api.status_read",
            "search" => "api.items_searched",
            "list" => "api.items_listed",
            "read" => "api.field_read",
            "unlock" => "api.unlock",
            "passkeys" => "api.passkeys_listed",
            "assert" => "api.passkey_asserted",
            _ => unreachable!(),
        },
        super::ApiAuditMeta {
            account: Some(client.account.clone()),
            client: Some(key.id().to_owned()),
            ..Default::default()
        },
        super::api_audit_outcome(&result),
    )
    .await;
    result
}

async fn dispatch(
    state: &ApiState,
    client: &BrowserClient,
    operation: &str,
    value: serde_json::Value,
) -> Result<serde_json::Value, ApiError> {
    let agent = || state.agent.as_ref().ok_or_else(failed);
    let account = client.account.clone();
    match operation {
        "status" => json((state.status_reader)(account).await?),
        "list" => json((state.names_reader)(Vec::new(), account).await?),
        "search" => {
            let input: SearchInput = payload(value)?;
            let url = input
                .url
                .as_deref()
                .map(url::Url::parse)
                .transpose()
                .map_err(|_| invalid())?;
            if url.as_ref().is_some_and(|url| {
                !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
            }) {
                return Err(invalid());
            }
            let scope = action_scope(
                client,
                vec![
                    FieldRef::Name,
                    FieldRef::Username,
                    FieldRef::Password,
                    FieldRef::Totp,
                    FieldRef::UriAll,
                ],
            );
            json(
                crate::actions::browser::search(
                    agent()?,
                    &scope,
                    url.as_ref(),
                    &input.query,
                    input.site_only,
                )
                .await?,
            )
        }
        "read" => {
            let input: FieldReadRequest = payload(value)?;
            // Passkeys are usable only via the assertion operation.
            if matches!(input.field, FieldRef::Passkey) {
                return Err(forbidden());
            }
            json((state.reader)(input, account).await?.0)
        }
        "unlock" => {
            let mut input: rbw::remote_api::UnlockRequest = payload(value)?;
            if input.account.as_ref().is_some_and(|name| name != &account) {
                return Err(forbidden());
            }
            json(
                (state.unlocker)(
                    account,
                    std::mem::take(&mut input.password),
                )
                .await?,
            )
        }
        "passkeys" => {
            let rp_id: String = payload(value)?;
            let scope = action_scope(client, vec![FieldRef::Passkey]);
            json(
                crate::actions::browser::find_passkeys(
                    agent()?,
                    &scope,
                    &rp_id,
                )
                .await?,
            )
        }
        "assert" => {
            let request: rbw::remote_api::PasskeyAssertionRequest =
                payload(value)?;
            if request.user_verified {
                return Err(forbidden());
            }
            let agent = agent()?.clone();
            let scope = action_scope(client, vec![FieldRef::Passkey]);
            json(
                tokio::spawn(async move {
                    crate::actions::browser::assert_passkey(
                        agent, &scope, &request,
                    )
                    .await
                })
                .await
                .map_err(|_| failed())??,
            )
        }
        _ => Err(invalid()),
    }
}

fn action_scope(
    client: &BrowserClient,
    all_items: Vec<FieldRef>,
) -> ClientPolicy {
    ClientPolicy {
        id: String::new(),
        name: client.name.clone(),
        fingerprint: String::new(),
        account: Some(client.account.clone()),
        status: false,
        status_accounts: Vec::new(),
        unlock_accounts: Vec::new(),
        items: std::collections::BTreeMap::new(),
        all_items,
    }
}
