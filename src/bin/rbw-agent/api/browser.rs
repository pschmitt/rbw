use super::{
    api_audit_outcome, api_response, audit_actor, extract_consumer,
    record_api_event, ApiAuditMeta, ApiState,
};
use axum::{
    extract::{Extension, Query, State},
    response::Response,
    Json,
};
use axum_server::tls::TlsInfo;
use rbw::remote_api::{ApiError, ErrorCode};
use rbw::remote_api::{
    ClientPolicy, PasskeyAssertionRequest, PasskeyListResponse,
    SearchResponse,
};
use std::sync::Arc;

#[derive(serde::Deserialize)]
pub(super) struct ItemQuery {
    pub url: Option<String>,
    q: Option<String>,
}

#[derive(serde::Deserialize)]
pub(super) struct PasskeyQuery {
    rp_id: String,
}

async fn client(
    state: &ApiState,
    certificate: Option<&[u8]>,
) -> Result<ClientPolicy, ApiError> {
    let (enabled, store) = (state.policy)().await?;
    let certificate = certificate
        .filter(|_| enabled)
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized))?;
    let fingerprint = rbw::remote_api::certificate_fingerprint(certificate);
    store
        .clients
        .into_values()
        .find(|client| client.fingerprint == fingerprint)
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized))
}

pub(super) async fn search(
    state: &ApiState,
    certificate: Option<&[u8]>,
    query: ItemQuery,
) -> Result<SearchResponse, ApiError> {
    let client = client(state, certificate).await?;
    let agent = state
        .agent
        .as_ref()
        .ok_or_else(|| ApiError::new(ErrorCode::Unavailable))?;
    let url = query
        .url
        .as_deref()
        .and_then(|url| url::Url::parse(url).ok())
        .filter(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
        })
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest))?;
    crate::actions::browser::search(
        agent,
        &client,
        &url,
        query.q.as_deref().unwrap_or_default(),
    )
    .await
}

pub(super) async fn find_passkeys(
    State(state): State<ApiState>,
    Extension(tls): Extension<Arc<TlsInfo>>,
    headers: axum::http::HeaderMap,
    Query(query): Query<PasskeyQuery>,
) -> Response {
    let certificate = tls.peer_certificates.first().map(Vec::as_slice);
    let actor = audit_actor(&state, certificate).await;
    let result: Result<PasskeyListResponse, ApiError> = async {
        let client = client(&state, certificate).await?;
        let agent = state
            .agent
            .as_ref()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable))?;
        crate::actions::browser::find_passkeys(agent, &client, &query.rp_id)
            .await
    }
    .await;
    let outcome = api_audit_outcome(&result);
    record_api_event(
        actor,
        "api.passkeys_listed",
        ApiAuditMeta {
            client: extract_consumer(&headers),
            ..ApiAuditMeta::default()
        },
        outcome,
    )
    .await;
    api_response(result)
}

pub(super) async fn assert_passkey(
    State(state): State<ApiState>,
    Extension(tls): Extension<Arc<TlsInfo>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<PasskeyAssertionRequest>,
) -> Response {
    let certificate = tls.peer_certificates.first().map(Vec::as_slice);
    let actor = audit_actor(&state, certificate).await;
    let item_id = request.item_id.clone();
    let result = async {
        let client = client(&state, certificate).await?;
        let agent = state
            .agent
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable))?;
        // Complete a counter reservation even if the HTTP caller disconnects.
        tokio::spawn(async move {
            crate::actions::browser::assert_passkey(agent, &client, &request)
                .await
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Unavailable))?
    }
    .await;
    let outcome = api_audit_outcome(&result);
    record_api_event(
        actor,
        "api.passkey_asserted",
        ApiAuditMeta {
            item_id,
            field: Some("passkey".to_owned()),
            client: extract_consumer(&headers),
            ..ApiAuditMeta::default()
        },
        outcome,
    )
    .await;
    api_response(result)
}
