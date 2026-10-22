use super::native::first_success;
use std::future::{pending, ready};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::oneshot;

#[tokio::test]
async fn password_winner_waits_for_reader_cleanup() {
    let cleaned = AtomicBool::new(false);
    let (stop_pin, _pin_cancel) = oneshot::channel();
    let (stop_bio, bio_cancel) = oneshot::channel();
    let bio = async {
        let _ = bio_cancel.await;
        cleaned.store(true, Ordering::SeqCst);
        anyhow::bail!("reader released");
    };
    let result = first_success(
        ready(Ok("test-password".into())),
        bio,
        stop_pin,
        stop_bio,
        pending(),
    )
    .await;
    assert!(result.is_ok());
    assert!(cleaned.load(Ordering::SeqCst));
}

#[tokio::test]
async fn fingerprint_winner_waits_for_pinentry_cleanup() {
    let cleaned = AtomicBool::new(false);
    let (stop_pin, pin_cancel) = oneshot::channel();
    let (stop_bio, _bio_cancel) = oneshot::channel();
    let pin = async {
        let _ = pin_cancel.await;
        cleaned.store(true, Ordering::SeqCst);
        anyhow::bail!("prompt reaped");
    };
    let result = first_success(
        pin,
        ready(Ok("test-password".into())),
        stop_pin,
        stop_bio,
        pending(),
    )
    .await;
    assert!(result.is_ok());
    assert!(cleaned.load(Ordering::SeqCst));
}

#[tokio::test]
async fn failed_fingerprint_keeps_password_available() {
    let (stop_pin, _pin_cancel) = oneshot::channel();
    let (stop_bio, _bio_cancel) = oneshot::channel();
    let pin = async {
        tokio::task::yield_now().await;
        Ok("test-password".into())
    };
    assert!(first_success(
        pin,
        ready(Err(anyhow::anyhow!("no match or stale credential"))),
        stop_pin,
        stop_bio,
        pending()
    )
    .await
    .is_ok());
}

#[tokio::test]
async fn closed_prompt_keeps_fingerprint_available() {
    let (stop_pin, _pin_cancel) = oneshot::channel();
    let (stop_bio, _bio_cancel) = oneshot::channel();
    let bio = async {
        tokio::task::yield_now().await;
        Ok("test-password".into())
    };
    assert!(first_success(
        ready(Err(anyhow::anyhow!("prompt cancelled"))),
        bio,
        stop_pin,
        stop_bio,
        pending()
    )
    .await
    .is_ok());
}

#[tokio::test]
async fn both_failed_methods_return_an_error() {
    let (stop_pin, _pin_cancel) = oneshot::channel();
    let (stop_bio, _bio_cancel) = oneshot::channel();
    assert!(first_success(
        ready(Err(anyhow::anyhow!("prompt cancelled"))),
        ready(Err(anyhow::anyhow!("no match"))),
        stop_pin,
        stop_bio,
        pending()
    )
    .await
    .is_err());
}

#[tokio::test]
async fn cancellation_cleans_up_both_methods() {
    let pin_cleaned = AtomicBool::new(false);
    let bio_cleaned = AtomicBool::new(false);
    let (stop_pin, pin_cancel) = oneshot::channel();
    let (stop_bio, bio_cancel) = oneshot::channel();
    let pin = async {
        let _ = pin_cancel.await;
        pin_cleaned.store(true, Ordering::SeqCst);
        anyhow::bail!("prompt reaped");
    };
    let bio = async {
        let _ = bio_cancel.await;
        bio_cleaned.store(true, Ordering::SeqCst);
        anyhow::bail!("reader released");
    };
    assert!(first_success(pin, bio, stop_pin, stop_bio, ready(()))
        .await
        .is_err());
    assert!(pin_cleaned.load(Ordering::SeqCst));
    assert!(bio_cleaned.load(Ordering::SeqCst));
}
