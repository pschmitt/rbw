//! Run under a private session bus, never the real system fingerprint service.
use super::native::fingerprint_on_connection;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zbus::object_server::SignalEmitter;
use zbus::OwnedObjectPath;

const SERVICE: &str = "net.reactivated.Fprint";
const DEVICE_PATH: &str = "/net/reactivated/Fprint/Device/0";

struct Manager {
    path: &'static str,
}

#[zbus::interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    fn get_default_device(&self) -> OwnedObjectPath {
        OwnedObjectPath::try_from(self.path).unwrap()
    }
}

#[derive(Default)]
struct State {
    events: Mutex<Vec<&'static str>>,
    results: Mutex<VecDeque<(&'static str, bool)>>,
    started: tokio::sync::Notify,
    refuse_claim: bool,
    fail_stop: bool,
}

struct Device(Arc<State>);

#[zbus::interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    fn claim(&self, username: &str) -> zbus::fdo::Result<()> {
        assert_eq!(username, "");
        self.0.events.lock().unwrap().push("claim");
        if self.0.refuse_claim {
            return Err(zbus::fdo::Error::AccessDenied("test denial".into()));
        }
        Ok(())
    }

    async fn verify_start(
        &self,
        finger: &str,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        assert_eq!(finger, "any");
        self.0.events.lock().unwrap().push("start");
        self.0.started.notify_one();
        let result = self.0.results.lock().unwrap().pop_front();
        if let Some((status, done)) = result {
            // Emit before returning the method reply to exercise the race.
            Self::verify_status(&emitter, status, done).await.map_err(
                |error| zbus::fdo::Error::Failed(error.to_string()),
            )?;
        }
        Ok(())
    }

    fn verify_stop(&self) -> zbus::fdo::Result<()> {
        self.0.events.lock().unwrap().push("stop");
        if self.0.fail_stop {
            return Err(zbus::fdo::Error::Failed("test stop failure".into()));
        }
        Ok(())
    }

    fn release(&self) {
        self.0.events.lock().unwrap().push("release");
    }

    #[zbus(signal)]
    async fn verify_status(
        emitter: &SignalEmitter<'_>,
        result: &str,
        done: bool,
    ) -> zbus::Result<()>;
}

#[test]
#[ignore = "requires RBW_TEST_PRIVATE_DBUS=1 and dbus-run-session"]
fn fingerprint_protocol_and_cleanup() {
    assert_eq!(std::env::var("RBW_TEST_PRIVATE_DBUS").as_deref(), Ok("1"));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            for (
                label,
                results,
                success,
                cancel,
                refuse_claim,
                fail_stop,
                expected,
            ) in [
                (
                    "immediate match",
                    vec![("verify-match", true)],
                    true,
                    false,
                    false,
                    false,
                    vec!["claim", "start", "stop", "release"],
                ),
                (
                    "retry",
                    vec![("verify-no-match", true), ("verify-match", true)],
                    true,
                    false,
                    false,
                    false,
                    vec![
                        "claim", "start", "stop", "start", "stop", "release",
                    ],
                ),
                (
                    "three mismatches",
                    vec![("verify-no-match", true); 3],
                    false,
                    false,
                    false,
                    false,
                    vec![
                        "claim", "start", "stop", "start", "stop", "start",
                        "stop", "release",
                    ],
                ),
                (
                    "incomplete match",
                    vec![("verify-match", false)],
                    false,
                    false,
                    false,
                    false,
                    vec!["claim", "start", "stop", "release"],
                ),
                (
                    "timeout",
                    vec![],
                    false,
                    false,
                    false,
                    false,
                    vec!["claim", "start", "stop", "release"],
                ),
                (
                    "cancellation",
                    vec![],
                    false,
                    true,
                    false,
                    false,
                    vec!["claim", "start", "stop", "release"],
                ),
                (
                    "stop failure",
                    vec![("verify-match", true)],
                    false,
                    false,
                    false,
                    true,
                    vec!["claim", "start", "stop", "release"],
                ),
                (
                    "claim denial",
                    vec![],
                    false,
                    false,
                    true,
                    false,
                    vec!["claim"],
                ),
            ] {
                let state = Arc::new(State {
                    results: Mutex::new(results.into()),
                    refuse_claim,
                    fail_stop,
                    ..State::default()
                });
                let server = zbus::connection::Builder::session()
                    .name(SERVICE)
                    .serve_at(
                        "/net/reactivated/Fprint/Manager",
                        Manager { path: DEVICE_PATH },
                    )
                    .serve_at(DEVICE_PATH, Device(state.clone()))
                    .build()
                    .await
                    .unwrap();
                let client = zbus::Connection::session().await.unwrap();
                let cancelled = async {
                    if cancel {
                        state.started.notified().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                let result = fingerprint_on_connection(
                    client,
                    Duration::from_secs(1),
                    false,
                    cancelled,
                    false,
                )
                .await;
                assert_eq!(result.is_ok(), success, "{label}: {result:?}");
                assert_eq!(
                    *state.events.lock().unwrap(),
                    expected,
                    "{label}"
                );
                server.release_name(SERVICE).await.unwrap();
            }
        });
}
