//! Bitwarden URI matching shared by the CLI and remote API.

// A stored URI's scheme (when it has one) and its URL; scheme-less values such
// as "example.com" or "localhost:3000" are read as hosts.
fn stored_url(url: &str) -> Option<(Option<String>, url::Url)> {
    if let Ok(parsed) = url::Url::parse(url) {
        if parsed.host_str().is_some() {
            return Some((Some(parsed.scheme().to_string()), parsed));
        }
    }
    url::Url::parse(&format!("https://{url}"))
        .ok()
        .filter(|parsed| parsed.host_str().is_some())
        .map(|parsed| (None, parsed))
}

// Bitwarden's "Base domain": both hosts share a registrable domain (eTLD+1
// per the public suffix list). Hosts without one (IP addresses, localhost,
// single labels, bare public suffixes) must match exactly, including port.
fn registrable_domain(url: &url::Url) -> Option<&str> {
    match url.host() {
        Some(url::Host::Domain(host)) => psl::domain_str(host),
        _ => None,
    }
}

fn same_base_domain(stored: &url::Url, given: &url::Url) -> bool {
    match (registrable_domain(stored), registrable_domain(given)) {
        (Some(stored), Some(given)) => stored.eq_ignore_ascii_case(given),
        (None, None) => host_port(stored) == host_port(given),
        _ => false,
    }
}

// rbw's own default: the stored host (with port) or any of its subdomains.
fn matches_host_or_subdomain(url: &str, given_url: &url::Url) -> bool {
    let Some(given_host_port) = host_port(given_url) else {
        return false;
    };
    if let Ok(self_url) = url::Url::parse(url) {
        if let Some(self_host_port) = host_port(&self_url) {
            if self_url.scheme() == given_url.scheme()
                && (self_host_port == given_host_port
                    || given_host_port
                        .ends_with(&format!(".{self_host_port}")))
            {
                return true;
            }
        }
    }
    url == given_host_port || given_host_port.ends_with(&format!(".{url}"))
}

/// On a plain-HTTP page (other than loopback) only URIs that are explicitly
/// `http:` may match; `https:` and scheme-less values are skipped, so a
/// credential saved for HTTPS never goes to an HTTP page.
pub fn skip_insecure_uri(url: &url::Url, value: &str) -> bool {
    url.scheme() == "http"
        && !matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        )
        && !value.trim_start().to_ascii_lowercase().starts_with("http:")
}

pub fn matches_url(
    url: &str,
    match_type: Option<crate::api::UriMatchType>,
    given_url: &url::Url,
    default: crate::config::UriMatchDefault,
) -> bool {
    let Some(match_type) = match_type.or_else(|| default.match_type()) else {
        return matches_host_or_subdomain(url, given_url);
    };
    match match_type {
        crate::api::UriMatchType::Domain => {
            let Some((scheme, stored)) = stored_url(url) else {
                return false;
            };
            scheme.is_none_or(|scheme| scheme == given_url.scheme())
                && same_base_domain(&stored, given_url)
        }
        crate::api::UriMatchType::Host => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && self_host_port == given_host_port
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
        }
        crate::api::UriMatchType::StartsWith => {
            // Compare against the normalized stored URL so that an origin
            // like "https://example.com" cannot match
            // "https://example.com.evil.net/".
            match url::Url::parse(url) {
                Ok(stored) if stored.host_str().is_some() => {
                    stored.origin() == given_url.origin()
                        && given_url.as_str().starts_with(stored.as_str())
                }
                _ => given_url.to_string().starts_with(url),
            }
        }
        crate::api::UriMatchType::Exact => {
            if given_url.path() == "/" {
                given_url.to_string().trim_end_matches('/')
                    == url.trim_end_matches('/')
            } else {
                given_url.to_string() == url
            }
        }
        crate::api::UriMatchType::RegularExpression => {
            let Ok(rx) = regex::Regex::new(url) else {
                return false;
            };
            rx.is_match(given_url.as_ref())
        }
        crate::api::UriMatchType::Never => false,
    }
}

fn host_port(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        url.port().map_or_else(
            || host.to_string(),
            |port| format!("{host}:{port}"),
        ),
    )
}
