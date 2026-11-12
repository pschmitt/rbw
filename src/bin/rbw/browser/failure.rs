//! What the browser is told when a request fails.
//!
//! The extension used to get one catch-all sentence for nearly everything.
//! Now every failure we know gets its own user-safe `message`, and the whole
//! error chain goes along as a sanitized `detail` the extension shows behind
//! a "Details" disclosure. Backend errors can contain vault data, so the
//! detail is only ever the chain's own messages with long opaque tokens
//! redacted and the length capped; secrets (passwords, keys, decrypted
//! fields) are never put into error messages in the first place.
use crate::commands;

/// What went wrong, as the extension shows it.
#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    pub message: String,
    pub detail: String,
}

/// What the request was doing, for the wording of the generic cases.
#[derive(Clone, Copy, Default)]
pub struct Context {
    pub moving: bool,
    pub fingerprint: bool,
    pub unlocking: bool,
}

/// The wording for a failure that nothing else explains.
pub const FALLBACK: &str = "rbw could not complete this request. The cause is not one rbw recognizes; open \"Details\" for the technical reason.";

const MAX_DETAIL: usize = 1200;

pub fn describe(error: &anyhow::Error, context: Context) -> Failure {
    Failure {
        message: message(error, context),
        detail: detail(error),
    }
}

fn message(error: &anyhow::Error, context: Context) -> String {
    let chain = format!("{error:#}");
    if commands::exit_status(error) == 2 {
        return "The server write succeeded, but synchronization failed. Sync and inspect your vault before retrying to avoid duplicates.".into();
    }
    if let Some(known) = error
        .chain()
        .find_map(|e| e.downcast_ref::<super::passkeys::PasskeyError>())
    {
        return known.to_string();
    }
    if context.moving {
        return "Could not move the item; it was not deleted. Both accounts must be unlocked, and the other account must not already have an item with the same name and username.".into();
    }
    if context.fingerprint {
        return "Fingerprint unlock failed. Scan again, or unlock with your master password.".into();
    }
    if chain.contains("site mismatch") {
        return "This item has no URI matching this page. Use Autofill from the item's menu to fill it anyway.".into();
    }
    if context.unlocking {
        return if chain.contains("Password is incorrect") {
            "The master password is incorrect.".into()
        } else {
            "Could not unlock this account. Check your master password and account configuration.".into()
        };
    }
    if let Some(api) = error
        .chain()
        .find_map(|e| e.downcast_ref::<rbw::error::Error>())
        .and_then(api_message)
    {
        return api;
    }
    if chain.contains("agent is locked") {
        return "This account is locked. Unlock it, then try again.".into();
    }
    if chain.contains("failed to connect to rbw-agent") {
        return "The rbw agent is not reachable. Start it (or run rbw unlock) and try again.".into();
    }
    if chain.contains("not logged in") {
        return "This account is not logged in. Unlock or log in to it, then try again.".into();
    }
    FALLBACK.into()
}

fn api_message(error: &rbw::error::Error) -> Option<String> {
    use rbw::error::Error;
    let (status, body) = match error {
        Error::RequestUnauthorized => {
            return Some("The server rejected your session. Unlock the account again or sync your vault, then try again.".into());
        }
        Error::RequestFailed { status } => (*status, ""),
        Error::RequestFailedWithBody { status, body } => {
            (*status, body.as_str())
        }
        _ => return None,
    };
    let body = body.to_ascii_lowercase();
    Some(match status {
        400 | 403
            if status == 403
                || body.contains("not write accessible")
                || body.contains("permission")
                || body.contains("read only")
                || body.contains("read-only") =>
        {
            "The server refused the change: you do not have permission to edit this item. Items in a read-only organization collection cannot take a passkey; pick another item or create a new login.".into()
        }
        404 => "The item no longer exists on the server. Sync your vault and try again.".into(),
        401 => "The server rejected your session. Unlock the account again or sync your vault, then try again.".into(),
        413 => "The server refused the change because it is too large.".into(),
        429 => "The server is rate limiting requests. Wait a moment and try again.".into(),
        500..=599 => format!("The server reported an error (HTTP {status}). Try again later."),
        _ => format!("The server rejected the change (HTTP {status}). Open \"Details\" for the reason."),
    })
}

/// The error chain, one cause per line, without anything opaque.
pub fn detail(error: &anyhow::Error) -> String {
    let mut out = String::new();
    for (index, cause) in error.chain().enumerate() {
        if index > 0 {
            out.push_str("\ncaused by: ");
        }
        out.push_str(&sanitize(&cause.to_string()));
        if out.len() >= MAX_DETAIL {
            break;
        }
    }
    truncate(&mut out, MAX_DETAIL);
    out
}

fn truncate(text: &mut String, max: usize) {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
}

// Control characters out (they could forge log lines), and anything that
// looks like a key, token or ciphertext (a long run of base64/hex
// characters) replaced.
fn sanitize(text: &str) -> String {
    let text: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= 32 {
            out.push_str("[redacted]");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || "+/=_-.".contains(c) {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_redacts_opaque_tokens_and_controls() {
        let error = anyhow::anyhow!(
            "bad value 2.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|BBBB\nnext"
        )
        .context("outer");
        let text = detail(&error);
        assert!(text.starts_with("outer\ncaused by: bad value [redacted]"));
        assert!(!text.contains('A'));
        assert!(!text.contains("\nnext"));
    }

    #[test]
    fn detail_is_capped() {
        let error = anyhow::anyhow!("{}", "word ".repeat(1000));
        assert!(detail(&error).len() <= MAX_DETAIL + 3);
    }

    #[test]
    fn api_errors_are_explained() {
        let read_only =
            anyhow::Error::new(rbw::error::Error::RequestFailedWithBody {
                status: 400,
                body: "Cipher is not write accessible".into(),
            })
            .context("saving the passkey");
        let failure = describe(&read_only, Context::default());
        assert!(failure.message.contains("do not have permission"));
        assert!(failure.detail.contains("Cipher is not write accessible"));
        let server = anyhow::Error::new(rbw::error::Error::RequestFailed {
            status: 502,
        });
        assert!(describe(&server, Context::default())
            .message
            .contains("HTTP 502"));
    }

    #[test]
    fn catch_all_does_not_claim_the_vault_is_locked() {
        let failure =
            describe(&anyhow::anyhow!("something odd"), Context::default());
        assert_eq!(failure.message, FALLBACK);
        assert!(!failure.message.to_lowercase().contains("unlock"));
        assert_eq!(failure.detail, "something odd");
    }

    #[test]
    fn locked_agent_is_recognized() {
        let failure =
            describe(&anyhow::anyhow!("agent is locked"), Context::default());
        assert!(failure.message.contains("locked"));
    }
}
