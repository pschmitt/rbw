// Pure logic behind `rbw audit`: password strength estimate, reuse
// detection and the Have I Been Pwned range lookup. Nothing here prints or
// returns a password -- findings only reference entries.

use sha1::Digest as _;
use std::fmt::Write as _;

const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Issue {
    Weak { estimated_bits: u32 },
    Reused { with: Vec<String> },
    Breached { count: u64 },
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Weak { estimated_bits } => {
                write!(f, "weak (~{estimated_bits} bits)")
            }
            Self::Reused { with } => {
                write!(f, "reused ({} other)", with.len())
            }
            Self::Breached { count } => write!(f, "breached ({count}x)"),
        }
    }
}

// A rough upper bound: length (counting each distinct character at most
// twice, so "aaaaaaaaaaaa" doesn't look strong) times the size of the
// character classes used. It can't see dictionary words or patterns --
// that's what the breach check is for.
pub fn estimate_bits(password: &str) -> u32 {
    let mut pool = 0_u32;
    let mut has = [false; 5];
    let mut counts = std::collections::HashMap::new();
    for c in password.chars() {
        let class = if c.is_ascii_lowercase() {
            0
        } else if c.is_ascii_uppercase() {
            1
        } else if c.is_ascii_digit() {
            2
        } else if c.is_ascii() {
            3
        } else {
            4
        };
        if !has[class] {
            has[class] = true;
            pool += [26, 26, 10, 33, 100][class];
        }
        *counts.entry(c).or_insert(0_usize) += 1;
    }
    let effective_len: usize = counts.values().map(|&n| n.min(2)).sum();
    if pool == 0 {
        return 0;
    }
    let effective_len = u32::try_from(effective_len).unwrap_or(u32::MAX);
    let bits = (f64::from(effective_len) * f64::from(pool).log2()).floor();
    // `bits` is finite, non-negative and integral here; f64 -> u32 has no
    // lossless conversion trait, and `as` saturates anyway.
    #[allow(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let bits = bits as u32;
    bits
}

// Groups entry indices sharing the same password; only groups of two or
// more are returned.
pub fn reused_groups<'a>(
    passwords: impl IntoIterator<Item = &'a str>,
) -> Vec<Vec<usize>> {
    let mut by_password: std::collections::HashMap<&str, Vec<usize>> =
        std::collections::HashMap::new();
    for (index, password) in passwords.into_iter().enumerate() {
        by_password.entry(password).or_default().push(index);
    }
    let mut groups: Vec<Vec<usize>> = by_password
        .into_values()
        .filter(|indices| indices.len() > 1)
        .collect();
    groups.sort();
    groups
}

// Uppercase hex SHA-1, split into the 5-character prefix sent to the API
// and the 35-character suffix matched locally (k-anonymity).
pub fn hibp_hash(password: &str) -> (String, String) {
    let digest = sha1::Sha1::digest(password.as_bytes());
    let hex = digest.iter().fold(String::with_capacity(40), |mut hex, b| {
        let _ = write!(hex, "{b:02X}");
        hex
    });
    let (prefix, suffix) = hex.split_at(5);
    (prefix.to_string(), suffix.to_string())
}

// Parses a range response (`SUFFIX:COUNT` per line). Padding entries
// (`Add-Padding: true`) have a count of 0 and therefore never match.
pub fn hibp_count(range_body: &str, suffix: &str) -> u64 {
    range_body
        .lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .and_then(|(_, count)| count.trim().parse().ok())
        .unwrap_or(0)
}

pub fn hibp_range(
    client: &reqwest::blocking::Client,
    prefix: &str,
) -> anyhow::Result<String> {
    let response = client
        .get(format!("{HIBP_RANGE_URL}{prefix}"))
        .header("Add-Padding", "true")
        .header("User-Agent", concat!("rbw/", env!("CARGO_PKG_VERSION")))
        .send()?
        .error_for_status()?;
    Ok(response.text()?)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_estimate_bits() {
        assert_eq!(estimate_bits(""), 0);
        assert!(estimate_bits("aaaaaaaaaaaaaaaaaaaa") < 20);
        assert!(estimate_bits("hunter2") < 60);
        assert!(estimate_bits("xK9#mQ2$vL7!pR4@wT6&") > 100);
        // diceware-style passphrase
        assert!(estimate_bits("correct horse battery staple") > 60);
    }

    #[test]
    fn test_reused_groups() {
        let groups = reused_groups(["a", "b", "a", "c", "b", "a"]);
        assert_eq!(groups, vec![vec![0, 2, 5], vec![1, 4]]);
        assert!(reused_groups(["a", "b"]).is_empty());
    }

    #[test]
    fn test_hibp_hash_and_count() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = hibp_hash("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n\
                    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n";
        assert_eq!(hibp_count(body, &suffix), 9_545_824);
        assert_eq!(hibp_count(body, &suffix.to_lowercase()), 9_545_824);
        assert_eq!(
            hibp_count(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            0
        );
        assert_eq!(
            hibp_count(body, "0000000000000000000000000000000000A"),
            0
        );
    }
}
