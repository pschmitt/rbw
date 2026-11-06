use anyhow::Context as _;
use axum::{
    extract::{Extension, Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures::future::BoxFuture;
use rustls::pki_types::CertificateDer;
use std::{future::Future, io, pin::Pin};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;

#[derive(Clone, Debug, Default)]
struct PeerCertificates(Vec<CertificateDer<'static>>);

impl PeerCertificates {
    fn leaf(&self) -> Option<&CertificateDer<'static>> {
        self.0.first()
    }
}

#[derive(Clone, Debug)]
struct PeerCertAcceptor<A = axum_server::accept::DefaultAcceptor> {
    inner: axum_server::tls_rustls::RustlsAcceptor<A>,
}

impl PeerCertAcceptor {
    fn new(inner: axum_server::tls_rustls::RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S, A> axum_server::accept::Accept<I, S> for PeerCertAcceptor<A>
where
    A: axum_server::accept::Accept<I, S> + Clone + Send + 'static,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send,
    A::Service: Send,
    A::Future: Send,
    I: Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<A::Stream>;
    type Service = PeerCertService<A::Service>;
    type Future = Pin<
        Box<
            dyn Future<Output = io::Result<(Self::Stream, Self::Service)>>
                + Send,
        >,
    >;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (tls_stream, service) = inner.accept(stream, service).await?;
            let (_, connection) = tls_stream.get_ref();
            let certs = connection
                .peer_certificates()
                .unwrap_or_default()
                .iter()
                .map(|cert| cert.clone().into_owned())
                .collect();
            Ok((
                tls_stream,
                PeerCertService {
                    inner: service,
                    certs: PeerCertificates(certs),
                },
            ))
        })
    }
}

#[derive(Clone, Debug)]
struct PeerCertService<S> {
    inner: S,
    certs: PeerCertificates,
}

impl<S, B> tower_service::Service<axum::http::Request<B>>
    for PeerCertService<S>
where
    S: tower_service::Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: axum::http::Request<B>) -> Self::Future {
        request.extensions_mut().insert(self.certs.clone());
        self.inner.call(request)
    }
}

use rbw::remote_api::{
    AccountStatus, ApiError, ErrorCode, FieldReadResponse, StatusResponse,
    UnlockRequest, UnlockResponse, VaultLockState,
};

type PolicyFuture = BoxFuture<
    'static,
    Result<(bool, rbw::remote_api::PolicyStore), ApiError>,
>;
type ReaderFuture =
    BoxFuture<'static, Result<(FieldReadResponse, Option<String>), ApiError>>;
type StatusFuture = BoxFuture<'static, Result<AccountStatus, ApiError>>;
type EventsFuture = BoxFuture<'static, Vec<rbw::audit::Event>>;
type UnlockFuture = BoxFuture<'static, Result<UnlockResponse, ApiError>>;

#[derive(Clone)]
struct ApiState {
    policy: std::sync::Arc<dyn Fn() -> PolicyFuture + Send + Sync>,
    reader: std::sync::Arc<
        dyn Fn(rbw::remote_api::FieldReadRequest, String) -> ReaderFuture
            + Send
            + Sync,
    >,
    status_reader:
        std::sync::Arc<dyn Fn(String) -> StatusFuture + Send + Sync>,
    events_reader: std::sync::Arc<
        dyn Fn(
                Vec<String>,
                std::collections::BTreeMap<String, String>,
            ) -> EventsFuture
            + Send
            + Sync,
    >,
    unlocker:
        std::sync::Arc<dyn Fn(String, String) -> UnlockFuture + Send + Sync>,
}

impl ApiState {
    fn production(
        agent: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> Self {
        let policy: std::sync::Arc<dyn Fn() -> PolicyFuture + Send + Sync> =
            std::sync::Arc::new(|| {
                Box::pin(async {
                    let config = rbw::config::Config::load_async()
                        .await
                        .map_err(|_| ApiError::new(ErrorCode::Unavailable))?;
                    let store = rbw::remote_api::load_policy_store()
                        .map_err(|_| ApiError::new(ErrorCode::Unavailable))?;
                    Ok((config.api.enabled, store))
                })
            });
        let reader_agent = agent.clone();
        let reader: std::sync::Arc<
            dyn Fn(rbw::remote_api::FieldReadRequest, String) -> ReaderFuture
                + Send
                + Sync,
        > = std::sync::Arc::new(move |request, account: String| {
            let agent = reader_agent.clone();
            Box::pin(async move {
                let environment = rbw::protocol::Environment::default();
                crate::actions::read_remote_field(
                    agent,
                    request,
                    &account,
                    &environment,
                )
                .await
            })
        });
        let status_agent = agent.clone();
        let status_reader: std::sync::Arc<
            dyn Fn(String) -> StatusFuture + Send + Sync,
        > = std::sync::Arc::new(move |account| {
            let agent = status_agent.clone();
            Box::pin(async move {
                let config = rbw::config::Config::load_async()
                    .await
                    .map_err(|_| ApiError::new(ErrorCode::Unavailable))?;
                if config.account(Some(&account)).is_err() {
                    return Ok(AccountStatus {
                        account,
                        state: VaultLockState::Unconfigured,
                    });
                }
                let locked = agent.lock().await.needs_unlock(&account);
                Ok(AccountStatus {
                    account,
                    state: if locked {
                        VaultLockState::Locked
                    } else {
                        VaultLockState::Unlocked
                    },
                })
            })
        });
        let events_reader: std::sync::Arc<
            dyn Fn(
                    Vec<String>,
                    std::collections::BTreeMap<String, String>,
                ) -> EventsFuture
                + Send
                + Sync,
        > = std::sync::Arc::new(move |accounts, client_names| {
            Box::pin(async move {
                tokio::task::spawn_blocking(move || {
                    rbw::audit::recent_events(50, &accounts, &client_names)
                })
                .await
                .unwrap_or_default()
            })
        });
        let unlocker: std::sync::Arc<
            dyn Fn(String, String) -> UnlockFuture + Send + Sync,
        > = std::sync::Arc::new(move |account, password| {
            let agent = agent.clone();
            Box::pin(async move {
                crate::actions::unlock_remote_account(
                    agent, &account, password,
                )
                .await
            })
        });
        Self {
            policy,
            reader,
            status_reader,
            events_reader,
            unlocker,
        }
    }
}

struct RunningListener {
    listen: String,
    hostname: String,
    cancel: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

pub async fn supervise(
    agent: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) {
    let mut interval =
        tokio::time::interval(std::time::Duration::from_millis(500));
    let mut running: Option<RunningListener> = None;
    let mut last_status: Option<rbw::remote_api::ListenerStatus> = None;
    loop {
        interval.tick().await;
        let config = match rbw::config::Config::load_async().await {
            Ok(config) => config,
            Err(error) => {
                log::warn!("remote API config reload failed: {error:#}");
                continue;
            }
        };
        let desired_listen = config.api.listen.clone();
        let desired_hostname = config.api.hostname.clone();
        let same_config = running.as_ref().is_some_and(|listener| {
            listener.listen == desired_listen
                && listener.hostname == desired_hostname
                && !listener.task.is_finished()
        });

        if !config.api.enabled {
            if let Some(listener) = running.take() {
                stop_listener(listener).await;
            }
            save_status_if_changed(
                &mut last_status,
                rbw::remote_api::ListenerStatus {
                    enabled: false,
                    listening: false,
                    listen: desired_listen,
                    hostname: desired_hostname,
                    pid: std::process::id(),
                    error: None,
                },
            );
            continue;
        }

        if same_config {
            continue;
        }
        if let Some(listener) = running.take() {
            stop_listener(listener).await;
        }

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let cancel = tokio_util::sync::CancellationToken::new();
        let listener_config = config.api.clone();
        let listener_cancel = cancel.clone();
        let listener_agent = agent.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = run(
                listener_agent,
                listener_config,
                ready_tx,
                listener_cancel,
            )
            .await
            {
                log::error!("remote API stopped: {error:#}");
            }
        });

        match ready_rx.await {
            Ok(Ok(())) => {
                save_status_if_changed(
                    &mut last_status,
                    rbw::remote_api::ListenerStatus {
                        enabled: true,
                        listening: true,
                        listen: desired_listen.clone(),
                        hostname: desired_hostname.clone(),
                        pid: std::process::id(),
                        error: None,
                    },
                );
                running = Some(RunningListener {
                    listen: desired_listen,
                    hostname: desired_hostname,
                    cancel,
                    task,
                });
            }
            Ok(Err(error)) => {
                log::error!("remote API did not start: {error}");
                save_status_if_changed(
                    &mut last_status,
                    rbw::remote_api::ListenerStatus {
                        enabled: true,
                        listening: false,
                        listen: desired_listen,
                        hostname: desired_hostname,
                        pid: std::process::id(),
                        error: Some(error),
                    },
                );
                let _ = task.await;
            }
            Err(_) => {
                log::error!("remote API did not report startup");
                let _ = task.await;
            }
        }
    }
}

fn save_status_if_changed(
    last_status: &mut Option<rbw::remote_api::ListenerStatus>,
    status: rbw::remote_api::ListenerStatus,
) {
    let changed = last_status.as_ref().is_none_or(|previous| {
        previous.enabled != status.enabled
            || previous.listening != status.listening
            || previous.listen != status.listen
            || previous.hostname != status.hostname
            || previous.error != status.error
    });
    if changed {
        if let Err(error) = rbw::remote_api::save_listener_status(&status) {
            log::warn!(
                "failed to save remote API listener status: {error:#}"
            );
        }
        *last_status = Some(status);
    }
}

async fn stop_listener(listener: RunningListener) {
    listener.cancel.cancel();
    if tokio::time::timeout(std::time::Duration::from_secs(2), listener.task)
        .await
        .is_err()
    {
        log::warn!("remote API listener did not stop promptly");
    }
}

async fn run(
    agent: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    config: rbw::config::ApiConfig,
    ready: tokio::sync::oneshot::Sender<Result<(), String>>,
    cancel: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    let prepared = prepare(agent, &config).await;
    let server = match prepared {
        Ok(server) => server,
        Err(error) => {
            let _ = ready.send(Err(format!("{error:#}")));
            return Err(error);
        }
    };
    let _ = ready.send(Ok(()));
    tokio::select! {
        () = cancel.cancelled() => Ok(()),
        result = server => result.context("remote API listener failed"),
    }
}

async fn prepare(
    agent: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    config: &rbw::config::ApiConfig,
) -> anyhow::Result<
    impl std::future::Future<Output = anyhow::Result<()>> + Send,
> {
    let listen: std::net::SocketAddr = config
        .listen
        .parse()
        .context("invalid remote API listen address")?;
    let tls =
        rbw::remote_api::with_tls_material(&config.hostname, tls_config_at)?;
    let router = router(ApiState::production(agent));
    let acceptor = PeerCertAcceptor::new(
        axum_server::tls_rustls::RustlsAcceptor::new(tls),
    );

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .context("failed to bind remote API listener")?;
    let listener = listener
        .into_std()
        .context("failed to prepare remote API listener")?;
    let server = axum_server::from_tcp(listener)?.acceptor(acceptor);
    log::info!("rbw remote field API listening on {listen}");
    Ok(async move {
        server
            .serve(router.into_make_service())
            .await
            .context("remote API listener failed")
    })
}

fn tls_config_at(
    pki_dir: &std::path::Path,
) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        server::WebPkiClientVerifier,
        RootCertStore,
    };

    let ca = CertificateDer::from_pem_file(pki_dir.join("ca.pem"))
        .context("remote API CA certificate is missing")?;
    let mut roots = RootCertStore::empty();
    roots.add(ca).context("invalid remote API CA certificate")?;
    let verifier = WebPkiClientVerifier::builder(std::sync::Arc::new(roots))
        .build()
        .context("failed to configure required mTLS client verification")?;

    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(pki_dir.join("server.pem"))?
            .collect::<Result<_, _>>()?;
    let key: PrivateKeyDer<'static> =
        PrivateKeyDer::from_pem_file(pki_dir.join("server-key.pem"))
            .context("remote API server key is missing")?;
    let mut server = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .context("failed to configure remote API TLS identity")?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        std::sync::Arc::new(server),
    ))
}

fn router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/items/{item_id}/fields/{*field}", get(read_field))
        .route("/v1/status", get(read_status))
        .route("/v1/unlock", axum::routing::post(unlock_account))
        .with_state(state)
}

#[derive(Default)]
struct ApiAuditMeta {
    item_id: Option<String>,
    item_name: Option<String>,
    account: Option<String>,
    field: Option<String>,
    client: Option<String>,
}

fn extract_consumer(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers.get("x-rbw-consumer")?.to_str().ok()?.trim();
    let cleaned = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._+-/:".contains(*c))
        .take(64)
        .collect::<String>();
    (!cleaned.is_empty()).then_some(cleaned)
}

async fn read_field(
    State(state): State<ApiState>,
    Extension(certificates): Extension<PeerCertificates>,
    headers: axum::http::HeaderMap,
    Path((item_id, field_token)): Path<(String, String)>,
) -> Response {
    let cert_der = certificates.leaf().map(std::convert::AsRef::as_ref);
    let actor = audit_actor(&state, cert_der).await;
    let consumer = extract_consumer(&headers);
    let (result, mut meta) =
        read_field_inner(&state, cert_der, &item_id, &field_token).await;
    meta.item_id = Some(item_id);
    meta.field = Some(field_token);
    meta.client = consumer;
    let outcome = api_audit_outcome(&result);
    record_api_event(actor, "api.field_read", meta, outcome).await;
    api_response(result)
}

async fn read_status(
    State(state): State<ApiState>,
    Extension(certificates): Extension<PeerCertificates>,
) -> Response {
    let cert_der = certificates.leaf().map(std::convert::AsRef::as_ref);
    let actor = audit_actor(&state, cert_der).await;
    let result = read_status_inner(&state, cert_der).await;
    let outcome = api_audit_outcome(&result);
    record_api_event(
        actor,
        "api.status_read",
        ApiAuditMeta::default(),
        outcome,
    )
    .await;
    api_response(result)
}

async fn unlock_account(
    State(state): State<ApiState>,
    Extension(certificates): Extension<PeerCertificates>,
    headers: axum::http::HeaderMap,
    Json(mut request): Json<UnlockRequest>,
) -> Response {
    let cert_der = certificates.leaf().map(std::convert::AsRef::as_ref);
    let actor = audit_actor(&state, cert_der).await;
    let consumer = extract_consumer(&headers);
    let password = std::mem::take(&mut request.password);
    let (result, account) = unlock_account_inner(
        &state,
        cert_der,
        request.account.as_deref(),
        password,
    )
    .await;
    let outcome = api_audit_outcome(&result);
    record_api_event(
        actor,
        "api.unlock",
        ApiAuditMeta {
            account,
            client: consumer,
            ..ApiAuditMeta::default()
        },
        outcome,
    )
    .await;
    api_response(result)
}

async fn audit_actor(
    state: &ApiState,
    certificate_der: Option<&[u8]>,
) -> String {
    let Some(certificate_der) = certificate_der else {
        return "unauthenticated".to_owned();
    };
    let fingerprint =
        rbw::remote_api::certificate_fingerprint(certificate_der);
    if let Ok((_, store)) = (state.policy)().await {
        if let Some(client) = store
            .clients
            .values()
            .find(|client| client.fingerprint == fingerprint)
        {
            return if client.name.trim().is_empty() {
                client.id.clone()
            } else {
                client.name.clone()
            };
        }
    }
    let fallback = fingerprint.clone();
    tokio::task::spawn_blocking(move || {
        rbw::remote_api::load_policy_store()
            .ok()
            .and_then(|store| {
                store
                    .clients
                    .values()
                    .find(|client| client.fingerprint == fingerprint)
                    .map(|client| {
                        if client.name.trim().is_empty() {
                            client.id.clone()
                        } else {
                            client.name.clone()
                        }
                    })
            })
            .unwrap_or(fallback)
    })
    .await
    .unwrap_or_else(|_| "unknown-client".to_owned())
}

fn api_audit_outcome<T>(result: &Result<T, ApiError>) -> &'static str {
    result.as_ref().map_or_else(
        |error| match error.code {
            ErrorCode::InvalidRequest => "failure.invalid_request",
            ErrorCode::Unauthorized => "failure.unauthorized",
            ErrorCode::Forbidden => "failure.forbidden",
            ErrorCode::InvalidPassword => "failure.invalid_password",
            ErrorCode::NotFound => "failure.not_found",
            ErrorCode::VaultLocked => "failure.vault_locked",
            ErrorCode::ReauthenticationRequired => {
                "failure.reauthentication_required"
            }
            ErrorCode::Unavailable => "failure.unavailable",
        },
        |_| "success",
    )
}

async fn record_api_event(
    actor: String,
    operation: &'static str,
    meta: ApiAuditMeta,
    outcome: &'static str,
) {
    let Ok(config) = rbw::config::Config::load_async().await else {
        log::warn!("audit event could not read rbw configuration");
        return;
    };
    let config = config.audit;
    let mut event = rbw::audit::Event::new(actor, operation, outcome);
    if let Some(item_id) = meta.item_id.as_deref() {
        event = event.with_item_id(item_id);
    }
    if let Some(item_name) = meta.item_name.as_deref() {
        event = event.with_item_name(item_name);
    }
    if let Some(account) = meta.account.as_deref() {
        event = event.with_account(account);
    }
    if let Some(field) = meta.field.as_deref() {
        event = event.with_field(field);
    }
    if let Some(client) = meta.client.as_deref() {
        event = event.with_client(client);
    }
    rbw::audit::record_async_best_effort(config, event).await;
}

fn api_response<T: serde::Serialize>(
    result: Result<T, ApiError>,
) -> Response {
    let mut response = match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => {
            let status = error.code.status();
            let retryable = error.retryable;
            let mut response = (status, Json(error)).into_response();
            if retryable {
                response.headers_mut().insert(
                    header::RETRY_AFTER,
                    HeaderValue::from_static("5"),
                );
            }
            response
        }
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn read_status_inner(
    state: &ApiState,
    certificate_der: Option<&[u8]>,
) -> Result<StatusResponse, ApiError> {
    let (enabled, store) = (state.policy)().await?;
    let accounts =
        authorized_status_accounts(enabled, &store, certificate_der)?;
    let mut statuses = Vec::with_capacity(accounts.len());
    for account in &accounts {
        statuses.push((state.status_reader)(account.clone()).await?);
    }
    let client_names = store
        .clients
        .values()
        .map(|client| (client.id.clone(), client.name.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let events = (state.events_reader)(accounts, client_names).await;
    Ok(StatusResponse {
        api_version: 1,
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        accounts: statuses,
        events,
    })
}

async fn read_field_inner(
    state: &ApiState,
    certificate_der: Option<&[u8]>,
    item_id: &str,
    field_token: &str,
) -> (Result<FieldReadResponse, ApiError>, ApiAuditMeta) {
    use rbw::remote_api::{FieldReadRequest, FieldRef};

    let mut meta = ApiAuditMeta::default();
    let (enabled, store) = match (state.policy)().await {
        Ok(value) => value,
        Err(err) => return (Err(err), meta),
    };
    if let Some(cert) = certificate_der {
        let fp = rbw::remote_api::certificate_fingerprint(cert);
        meta.account = store
            .clients
            .values()
            .find(|c| c.fingerprint == fp)
            .and_then(|c| c.account.clone());
    }
    let Ok(field) = field_token.parse::<FieldRef>() else {
        return (Err(ApiError::new(ErrorCode::InvalidRequest)), meta);
    };
    let account = match authorized_account(
        enabled,
        &store,
        certificate_der,
        item_id,
        &field,
    ) {
        Ok(account) => account,
        Err(err) => return (Err(err), meta),
    };
    meta.account = Some(account.clone());

    match (state.reader)(
        FieldReadRequest {
            item_id: item_id.to_owned(),
            field,
        },
        account,
    )
    .await
    {
        Ok((response, item_name)) => {
            meta.item_name = item_name;
            (Ok(response), meta)
        }
        Err(err) => (Err(err), meta),
    }
}

async fn unlock_account_inner(
    state: &ApiState,
    certificate_der: Option<&[u8]>,
    requested_account: Option<&str>,
    mut password: String,
) -> (Result<UnlockResponse, ApiError>, Option<String>) {
    let (enabled, store) = match (state.policy)().await {
        Ok(value) => value,
        Err(err) => {
            zeroize::Zeroize::zeroize(&mut password);
            return (Err(err), None);
        }
    };
    let account = match authorized_unlock_account(
        enabled,
        &store,
        certificate_der,
        requested_account,
    ) {
        Ok(account) => account,
        Err(err) => {
            zeroize::Zeroize::zeroize(&mut password);
            return (Err(err), requested_account.map(str::to_owned));
        }
    };
    let result = (state.unlocker)(account.clone(), password).await;
    (result, Some(account))
}

fn authorized_unlock_account(
    enabled: bool,
    store: &rbw::remote_api::PolicyStore,
    certificate_der: Option<&[u8]>,
    requested_account: Option<&str>,
) -> Result<String, ApiError> {
    if !enabled {
        return Err(ApiError::new(ErrorCode::Unauthorized));
    }
    let certificate_der = certificate_der
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized))?;
    let fingerprint =
        rbw::remote_api::certificate_fingerprint(certificate_der);
    let client = store
        .clients
        .values()
        .find(|client| client.fingerprint == fingerprint)
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized))?;
    let target = requested_account
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| client.account.clone())
        .unwrap_or_else(|| "default".to_owned());
    let allowed_via_default =
        client.account.as_deref() == Some(target.as_str());
    let allowed_via_status = client.status
        && rbw::remote_api::granted_status_accounts(client)
            .iter()
            .any(|account| account == &target);
    if !allowed_via_default && !allowed_via_status {
        return Err(ApiError::new(ErrorCode::Forbidden));
    }
    Ok(target)
}

fn authorized_account(
    enabled: bool,
    store: &rbw::remote_api::PolicyStore,
    certificate_der: Option<&[u8]>,
    item_id: &str,
    field: &rbw::remote_api::FieldRef,
) -> Result<String, ApiError> {
    if !enabled {
        return Err(ApiError::new(ErrorCode::Unauthorized));
    }
    let certificate_der = certificate_der
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized))?;
    let fingerprint =
        rbw::remote_api::certificate_fingerprint(certificate_der);
    let client = store
        .clients
        .values()
        .find(|client| client.fingerprint == fingerprint)
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized))?;
    let account = client
        .account
        .clone()
        .ok_or_else(|| ApiError::new(ErrorCode::Forbidden))?;
    let allowed_fields = client
        .items
        .get(item_id)
        .ok_or_else(|| ApiError::new(ErrorCode::Forbidden))?;
    if !allowed_fields.contains(field) {
        return Err(ApiError::new(ErrorCode::Forbidden));
    }
    Ok(account)
}

fn authorized_status_accounts(
    enabled: bool,
    store: &rbw::remote_api::PolicyStore,
    certificate_der: Option<&[u8]>,
) -> Result<Vec<String>, ApiError> {
    if !enabled {
        return Err(ApiError::new(ErrorCode::Unauthorized));
    }
    let certificate_der = certificate_der
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized))?;
    let fingerprint =
        rbw::remote_api::certificate_fingerprint(certificate_der);
    let client = store
        .clients
        .values()
        .find(|client| client.fingerprint == fingerprint)
        .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized))?;
    if !client.status {
        return Err(ApiError::new(ErrorCode::Forbidden));
    }
    let accounts = rbw::remote_api::granted_status_accounts(client);
    if accounts.is_empty()
        || accounts.iter().any(|account| account.trim().is_empty())
    {
        return Err(ApiError::new(ErrorCode::Unavailable));
    }
    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbw::remote_api::{ClientPolicy, FieldRef, PolicyStore};
    use rcgen::{
        CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    use std::sync::Arc;

    struct TlsFixture {
        pki_dir: tempfile::TempDir,
        ca_pem: String,
        client_identity: Vec<u8>,
        client_cert_der: Vec<u8>,
    }

    fn tls_fixture() -> TlsFixture {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let mut server_params =
            CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        server_params.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_issuer = Issuer::from_ca_cert_pem(
            &ca_cert.pem(),
            KeyPair::from_pem(&ca_key.serialize_pem()).unwrap(),
        )
        .unwrap();
        let server_cert = server_params
            .signed_by(&server_key, &server_issuer)
            .unwrap();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::default();
        client_params.extended_key_usages =
            vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_issuer = Issuer::from_ca_cert_pem(
            &ca_cert.pem(),
            KeyPair::from_pem(&ca_key.serialize_pem()).unwrap(),
        )
        .unwrap();
        let client_cert = client_params
            .signed_by(&client_key, &client_issuer)
            .unwrap();
        let pki_dir = tempfile::tempdir().unwrap();
        std::fs::write(pki_dir.path().join("ca.pem"), ca_cert.pem()).unwrap();
        std::fs::write(pki_dir.path().join("server.pem"), server_cert.pem())
            .unwrap();
        std::fs::write(
            pki_dir.path().join("server-key.pem"),
            server_key.serialize_pem(),
        )
        .unwrap();
        let mut identity = client_cert.pem().into_bytes();
        identity.extend_from_slice(client_key.serialize_pem().as_bytes());
        TlsFixture {
            pki_dir,
            ca_pem: ca_cert.pem(),
            client_identity: identity,
            client_cert_der: client_cert.der().to_vec(),
        }
    }

    fn test_state(
        certificate_der: &[u8],
        enabled: bool,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    ) -> (
        ApiState,
        Arc<tokio::sync::RwLock<(bool, PolicyStore)>>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::Ordering;

        let fingerprint =
            rbw::remote_api::certificate_fingerprint(certificate_der);
        let client = ClientPolicy {
            id: "client-1".to_owned(),
            name: "synthetic client".to_owned(),
            fingerprint,
            account: Some("personal".to_owned()),
            status: true,
            status_accounts: vec!["personal".to_owned()],
            items: std::collections::BTreeMap::from([(
                "item-1".to_owned(),
                vec![FieldRef::Password],
            )]),
        };
        let state_value = Arc::new(tokio::sync::RwLock::new((
            enabled,
            PolicyStore {
                clients: std::collections::BTreeMap::from([(
                    client.id.clone(),
                    client,
                )]),
            },
        )));
        let policy_source = state_value.clone();
        let policy: Arc<dyn Fn() -> PolicyFuture + Send + Sync> =
            Arc::new(move || {
                let source = policy_source.clone();
                Box::pin(async move {
                    let (enabled, store) = source.read().await.clone();
                    Ok((enabled, store))
                })
            });
        let reader: Arc<
            dyn Fn(rbw::remote_api::FieldReadRequest, String) -> ReaderFuture
                + Send
                + Sync,
        > = Arc::new(
            move |request: rbw::remote_api::FieldReadRequest,
                  _account: String| {
                let calls = calls.clone();
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok((
                        FieldReadResponse {
                            field: request.field,
                            value: Some("synthetic-secret-value".to_owned()),
                            sensitive: true,
                        },
                        Some("Synthetic Item".to_owned()),
                    ))
                })
            },
        );
        let status_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let status_reader: Arc<dyn Fn(String) -> StatusFuture + Send + Sync> =
            Arc::new({
                let status_calls = status_calls.clone();
                move |account| {
                    let status_calls = status_calls.clone();
                    Box::pin(async move {
                        status_calls.fetch_add(1, Ordering::SeqCst);
                        match account.as_str() {
                            "personal" => Ok(AccountStatus {
                                account,
                                state: VaultLockState::Locked,
                            }),
                            "work" => Ok(AccountStatus {
                                account,
                                state: VaultLockState::Unlocked,
                            }),
                            "unavailable" => {
                                Err(ApiError::new(ErrorCode::Unavailable))
                            }
                            _ => Ok(AccountStatus {
                                account,
                                state: VaultLockState::Unconfigured,
                            }),
                        }
                    })
                }
            });
        let events_reader: Arc<
            dyn Fn(
                    Vec<String>,
                    std::collections::BTreeMap<String, String>,
                ) -> EventsFuture
                + Send
                + Sync,
        > = Arc::new(|_, _| Box::pin(async { Vec::new() }));
        let unlocker: Arc<
            dyn Fn(String, String) -> UnlockFuture + Send + Sync,
        > = Arc::new(|account, password| {
            Box::pin(async move {
                if password == "correct-password" {
                    Ok(UnlockResponse {
                        account,
                        state: VaultLockState::Unlocked,
                    })
                } else {
                    Err(ApiError::new(ErrorCode::InvalidPassword))
                }
            })
        });
        (
            ApiState {
                policy,
                reader,
                status_reader,
                events_reader,
                unlocker,
            },
            state_value,
            status_calls,
        )
    }

    async fn https_request(
        url: String,
        ca_pem: String,
        client_identity: Option<Vec<u8>>,
        path: &'static str,
    ) -> anyhow::Result<(
        reqwest::StatusCode,
        Option<String>,
        String,
        Option<String>,
    )> {
        tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;
            let mut builder =
                reqwest::blocking::Client::builder().add_root_certificate(ca);
            if let Some(identity) = client_identity {
                builder =
                    builder.identity(reqwest::Identity::from_pem(&identity)?);
            }
            let response =
                builder.build()?.get(format!("{url}{path}")).send()?;
            let status = response.status();
            let cache_control = response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let retry_after = response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let body = response.text()?;
            Ok((status, cache_control, body, retry_after))
        })
        .await
        .unwrap()
    }

    async fn https_post(
        url: String,
        ca_pem: String,
        client_identity: Option<Vec<u8>>,
        path: &'static str,
        payload: serde_json::Value,
    ) -> anyhow::Result<(reqwest::StatusCode, String)> {
        tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;
            let mut builder =
                reqwest::blocking::Client::builder().add_root_certificate(ca);
            if let Some(identity) = client_identity {
                builder =
                    builder.identity(reqwest::Identity::from_pem(&identity)?);
            }
            let response = builder
                .build()?
                .post(format!("{url}{path}"))
                .json(&payload)
                .send()?;
            let status = response.status();
            let body = response.text()?;
            Ok((status, body))
        })
        .await
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn https_handler_enforces_grants_revocation_and_disabled_state() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let fixture = tls_fixture();
        let tls = tls_config_at(fixture.pki_dir.path()).unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (state, policy, status_calls) =
            test_state(&fixture.client_cert_der, true, calls.clone());
        let app = router(state);
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let listener = listener.into_std().unwrap();
        let acceptor = PeerCertAcceptor::new(
            axum_server::tls_rustls::RustlsAcceptor::new(tls),
        );
        let server =
            axum_server::from_tcp(listener).unwrap().acceptor(acceptor);
        let server_task = tokio::spawn(async move {
            server.serve(app.into_make_service()).await
        });
        let url = format!("https://localhost:{}", address.port());

        assert!(https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            None,
            "/v1/items/item-1/fields/password",
        )
        .await
        .is_err());

        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/items/item-1/fields/password",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1.as_deref(), Some("no-store"));
        let payload: FieldReadResponse =
            serde_json::from_str(&response.2).unwrap();
        assert_eq!(payload.value.as_deref(), Some("synthetic-secret-value"));

        // Status permission is distinct from item fields and reveals only
        // account names explicitly granted to this client.
        policy
            .write()
            .await
            .1
            .clients
            .get_mut("client-1")
            .unwrap()
            .items
            .clear();
        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/status",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1.as_deref(), Some("no-store"));
        let payload: StatusResponse =
            serde_json::from_str(&response.2).unwrap();
        assert_eq!(payload.api_version, 1);
        assert_eq!(payload.agent_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(payload.accounts.len(), 1);
        assert_eq!(payload.accounts[0].account, "personal");
        assert_eq!(payload.accounts[0].state, VaultLockState::Locked);
        assert!(!response.2.contains("work"));
        assert!(!response.2.contains("client-1"));

        // Unlocking a granted account succeeds with valid password and rejects
        // an invalid password or an ungranted account.
        let unlock_ok = https_post(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/unlock",
            serde_json::json!({ "account": "personal", "password": "correct-password" }),
        )
        .await
        .unwrap();
        assert_eq!(unlock_ok.0, StatusCode::OK);
        let unlocked: UnlockResponse =
            serde_json::from_str(&unlock_ok.1).unwrap();
        assert_eq!(unlocked.account, "personal");
        assert_eq!(unlocked.state, VaultLockState::Unlocked);

        let unlock_bad_pw = https_post(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/unlock",
            serde_json::json!({ "account": "personal", "password": "wrong" }),
        )
        .await
        .unwrap();
        assert_eq!(unlock_bad_pw.0, StatusCode::UNPROCESSABLE_ENTITY);

        let unlock_forbidden = https_post(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/unlock",
            serde_json::json!({ "account": "ungranted", "password": "correct-password" }),
        )
        .await
        .unwrap();
        assert_eq!(unlock_forbidden.0, StatusCode::FORBIDDEN);

        // Multiple explicit grants return each account's state.
        policy
            .write()
            .await
            .1
            .clients
            .get_mut("client-1")
            .unwrap()
            .status_accounts = vec!["personal".to_owned(), "work".to_owned()];
        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/status",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::OK);
        let payload: StatusResponse =
            serde_json::from_str(&response.2).unwrap();
        assert_eq!(payload.accounts.len(), 2);
        assert_eq!(payload.accounts[0].account, "personal");
        assert_eq!(payload.accounts[0].state, VaultLockState::Locked);
        assert_eq!(payload.accounts[1].account, "work");
        assert_eq!(payload.accounts[1].state, VaultLockState::Unlocked);
        assert!(!response.2.contains("unavailable"));

        // Revoking one account removes its name and state immediately.
        policy
            .write()
            .await
            .1
            .clients
            .get_mut("client-1")
            .unwrap()
            .status_accounts = vec!["personal".to_owned()];
        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/status",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::OK);
        let payload: StatusResponse =
            serde_json::from_str(&response.2).unwrap();
        assert_eq!(payload.accounts.len(), 1);
        assert_eq!(payload.accounts[0].account, "personal");
        assert!(!response.2.contains("work"));

        // A deleted account remains visible only because it was granted.
        policy
            .write()
            .await
            .1
            .clients
            .get_mut("client-1")
            .unwrap()
            .status_accounts = vec!["deleted-account".to_owned()];
        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/status",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::OK);
        let payload: StatusResponse =
            serde_json::from_str(&response.2).unwrap();
        assert_eq!(payload.accounts.len(), 1);
        assert_eq!(payload.accounts[0].account, "deleted-account");
        assert_eq!(payload.accounts[0].state, VaultLockState::Unconfigured);
        assert!(!response.2.contains("personal"));

        // Temporary config failures use the shared retryable error contract.
        policy
            .write()
            .await
            .1
            .clients
            .get_mut("client-1")
            .unwrap()
            .status_accounts = vec!["unavailable".to_owned()];
        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/status",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.3.as_deref(), Some("5"));
        let error: ApiError = serde_json::from_str(&response.2).unwrap();
        assert!(matches!(error.code, ErrorCode::Unavailable));
        assert!(error.retryable);

        // A malformed policy that enables status without an account scope is
        // a repairable server error, not an empty successful response.
        {
            let mut state = policy.write().await;
            let client = state.1.clients.get_mut("client-1").unwrap();
            client.status_accounts.clear();
            client.account = None;
        }
        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/status",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::SERVICE_UNAVAILABLE);
        let error: ApiError = serde_json::from_str(&response.2).unwrap();
        assert!(matches!(error.code, ErrorCode::Unavailable));

        // Status authorization defaults to deny, independently of mTLS.
        policy
            .write()
            .await
            .1
            .clients
            .get_mut("client-1")
            .unwrap()
            .status = false;
        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/status",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::FORBIDDEN);
        assert_eq!(response.1.as_deref(), Some("no-store"));

        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/items/item-1/fields/username",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::FORBIDDEN);

        // Removing the client from the current policy denies a subsequent
        // request using the same established client identity.
        policy.write().await.1 = PolicyStore::default();
        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/items/item-1/fields/password",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::UNAUTHORIZED);

        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/status",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::UNAUTHORIZED);

        policy.write().await.0 = false;
        let response = https_request(
            url.clone(),
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/items/item-1/fields/password",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::UNAUTHORIZED);

        let response = https_request(
            url,
            fixture.ca_pem.clone(),
            Some(fixture.client_identity.clone()),
            "/v1/status",
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(status_calls.load(std::sync::atomic::Ordering::SeqCst), 6);

        server_task.abort();
    }
}
