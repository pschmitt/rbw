use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::{fmt::Write as _, io::Write as _, os::unix::ffi::OsStrExt as _};

use anyhow::Context as _;
use is_terminal::IsTerminal as _;

// The default number of seconds the generated TOTP
// code lasts for before a new one must be generated
const TOTP_DEFAULT_STEP: u64 = 30;

const MISSING_CONFIG_HELP: &str =
    "Before using rbw, you must configure the email address you would like to \
    use to log in to the server by running:\n\n    \
        rbw config set email <email>\n\n\
    Additionally, if you are using a self-hosted installation, you should \
    run:\n\n    \
        rbw config set baseUrl <url>\n\n\
    and, if your server has a non-default identity url:\n\n    \
    rbw config set identityUrl <url>\n";

const EXPORT_PASSPHRASE_ENV: &str = "RBW_EXPORT_PASSPHRASE";

struct RestoreEcho {
    fd: std::os::fd::RawFd,
    original: libc::termios,
}

impl Drop for RestoreEcho {
    fn drop(&mut self) {
        let _ = tcsetattr(self.fd, &self.original);
    }
}

#[derive(Debug, Clone)]
pub enum Needle {
    Name(String),
    Uri(url::Url),
    Uuid(uuid::Uuid, String),
}

impl std::fmt::Display for Needle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match &self {
            Self::Name(name) => name.clone(),
            Self::Uri(uri) => uri.to_string(),
            Self::Uuid(_, s) => s.clone(),
        };
        write!(f, "{value}")
    }
}

#[allow(clippy::unnecessary_wraps)]
pub fn parse_needle(arg: &str) -> Result<Needle, std::convert::Infallible> {
    if let Ok(uuid) = uuid::Uuid::parse_str(arg) {
        return Ok(Needle::Uuid(uuid, arg.to_string()));
    }
    if let Ok(url) = url::Url::parse(arg) {
        if url.is_special() {
            return Ok(Needle::Uri(url));
        }
    }

    Ok(Needle::Name(arg.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Field {
    Notes,
    Username,
    Password,
    Totp,
    Uris,
    Fido2Credential,
    IdentityName,
    City,
    State,
    PostalCode,
    Country,
    Phone,
    Ssn,
    License,
    Passport,
    CardNumber,
    Expiration,
    ExpMonth,
    ExpYear,
    Cvv,
    Cardholder,
    Brand,
    Name,
    Email,
    Address,
    Address1,
    Address2,
    Address3,
    Fingerprint,
    PublicKey,
    PrivateKey,
    Title,
    FirstName,
    MiddleName,
    LastName,
}

impl std::str::FromStr for Field {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "notes" | "note" => Self::Notes,
            "username" | "user" => Self::Username,
            "password" => Self::Password,
            "totp" | "code" => Self::Totp,
            "uris" | "urls" | "sites" => Self::Uris,
            "identityname" => Self::IdentityName,
            "city" => Self::City,
            "state" => Self::State,
            "postcode" | "zipcode" | "zip" => Self::PostalCode,
            "country" => Self::Country,
            "phone" => Self::Phone,
            "ssn" => Self::Ssn,
            "license" => Self::License,
            "passport" => Self::Passport,
            "number" | "card" => Self::CardNumber,
            "exp" => Self::Expiration,
            "exp_month" | "month" => Self::ExpMonth,
            "exp_year" | "year" => Self::ExpYear,
            // the word "code" got preceeded by Totp
            "cvv" => Self::Cvv,
            "cardholder" | "cardholder_name" => Self::Cardholder,
            "brand" | "type" => Self::Brand,
            "name" => Self::Name,
            "email" => Self::Email,
            "address1" => Self::Address1,
            "address2" => Self::Address2,
            "address3" => Self::Address3,
            "address" => Self::Address,
            "fingerprint" => Self::Fingerprint,
            "public_key" => Self::PublicKey,
            "private_key" => Self::PrivateKey,
            "title" => Self::Title,
            "first_name" => Self::FirstName,
            "middle_name" => Self::MiddleName,
            "last_name" => Self::LastName,
            _ => anyhow::bail!("unknown field {s}"),
        })
    }
}

impl Field {
    fn as_str(&self) -> &str {
        match self {
            Self::Notes => "notes",
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Uris => "uris",
            Self::Fido2Credential => "fido2_credential",
            Self::IdentityName => "identityname",
            Self::City => "city",
            Self::State => "state",
            Self::PostalCode => "postcode",
            Self::Country => "country",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::License => "license",
            Self::Passport => "passport",
            Self::CardNumber => "number",
            Self::Expiration => "exp",
            Self::ExpMonth => "exp_month",
            Self::ExpYear => "exp_year",
            Self::Cvv => "cvv",
            Self::Cardholder => "cardholder",
            Self::Brand => "brand",
            Self::Name => "name",
            Self::Email => "email",
            Self::Address1 => "address1",
            Self::Address2 => "address2",
            Self::Address3 => "address3",
            Self::Address => "address",
            Self::Fingerprint => "fingerprint",
            Self::PublicKey => "public_key",
            Self::PrivateKey => "private_key",
            Self::Title => "title",
            Self::FirstName => "first_name",
            Self::MiddleName => "middle_name",
            Self::LastName => "last_name",
        }
    }
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, serde::Serialize)]
struct DecryptedListCipher {
    id: String,
    name: Option<String>,
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    folder: Option<String>,
    uris: Option<Vec<String>>,
    #[serde(rename = "type")]
    entry_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    collection_ids: Option<Vec<String>>,
    #[serde(flatten)]
    attachment_metadata: AttachmentMetadata,
    archived: bool,
    deleted: bool,
    // Set when this entry was merged in from a non-active account (multi-
    // account `list`/`search`); omitted otherwise so single-account output is
    // unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedSearchCipher {
    pub id: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub folder: Option<String>,
    pub name: String,
    pub user: Option<String>,
    pub uris: Vec<(String, Option<rbw::api::UriMatchType>)>,
    pub fields: Vec<String>,
    pub notes: Option<String>,
    pub attachment_count: usize,
    pub archived: bool,
    pub deleted: bool,
    #[serde(skip)]
    sensitive_fields: Vec<String>,
    #[serde(skip)]
    password: Option<String>,
}

// How `list`/`search` (and the TUI) treat archived entries: hidden by
// default (per the `hide.archived` config option), shown alongside normal
// entries with `--include-archived`, or exclusively with `--archived`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ArchivedFilter {
    Hide,
    Only,
    Include,
}

impl ArchivedFilter {
    pub fn matches(self, archived: bool) -> bool {
        match self {
            Self::Hide => !archived,
            Self::Only => archived,
            Self::Include => true,
        }
    }

    // Resolves the `--archived`/`--include-archived` flags (mutually
    // exclusive, enforced by clap) against the configured default: when
    // neither flag is given, falls back to `hide.archived` from
    // `config.yaml`.
    pub fn from_flags(
        archived: bool,
        include_archived: bool,
        hide_archived_default: bool,
    ) -> Self {
        if archived {
            Self::Only
        } else if include_archived {
            Self::Include
        } else if hide_archived_default {
            Self::Hide
        } else {
            Self::Include
        }
    }

    // Cycles the TUI's runtime archived-filter override: Hide -> Only ->
    // Include -> Hide.
    pub fn next(self) -> Self {
        match self {
            Self::Hide => Self::Only,
            Self::Only => Self::Include,
            Self::Include => Self::Hide,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Hide => "hiding archived",
            Self::Only => "archived only",
            Self::Include => "including archived",
        }
    }
}

// How `list`/`search` (and the TUI) treat trashed (soft-deleted, via `rbw
// remove`/`rbw delete`) entries: hidden by default (per the
// `hide.trashed` config option), shown alongside normal entries with
// `--include-trashed`/`--include-deleted`, or exclusively with
// `--trashed`/`--deleted`. Structurally identical to `ArchivedFilter`, but
// kept as a separate type since the two dimensions are independent and
// naming call sites `trash_filter.matches(entry.deleted)` stays clearer
// than reusing one generic type for both.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TrashFilter {
    Hide,
    Only,
    Include,
}

impl TrashFilter {
    pub fn matches(self, deleted: bool) -> bool {
        match self {
            Self::Hide => !deleted,
            Self::Only => deleted,
            Self::Include => true,
        }
    }

    // Resolves the `--trashed`/`--deleted` and `--include-trashed`/
    // `--include-deleted` flags (mutually exclusive, enforced by clap)
    // against the configured default: when neither flag is given, falls
    // back to `hide.trashed` from `config.yaml`.
    pub fn from_flags(
        trashed: bool,
        include_trashed: bool,
        hide_trashed_default: bool,
    ) -> Self {
        if trashed {
            Self::Only
        } else if include_trashed {
            Self::Include
        } else if hide_trashed_default {
            Self::Hide
        } else {
            Self::Include
        }
    }
}

// One AND-ed word of a `search`/`list`/TUI-filter query: either a bare word
// matched against every field (the historical plain-substring behavior), or
// one scoped to a single field via a "prefix:value" word, e.g. "u:alice" or
// "uri:google.com". An unrecognized prefix (or a bare trailing colon) falls
// back to matching the whole word literally, so a search for something that
// happens to contain a colon doesn't break.
enum QueryToken {
    Any(String),
    Name(String),
    User(String),
    Uri(String),
    Folder(String),
    Notes(String),
    Field(String),
    Organization(String),
    Collection(String),
}

impl QueryToken {
    // Whether `prefix` (case-insensitive) is a recognized field-scoping
    // prefix — shared with `scope_prefix_ranges` so the TUI's "this word is
    // scoped" coloring can never drift from what parsing actually
    // recognizes. Deliberately doesn't care whether a value follows: the
    // prefix alone (e.g. "uri:", value still empty) is enough to color it,
    // even though `parse` below still needs a non-empty value to actually
    // scope a match by it.
    fn recognizes_prefix(prefix: &str) -> bool {
        matches!(
            prefix.to_ascii_lowercase().as_str(),
            "n" | "name"
                | "u"
                | "user"
                | "username"
                | "uri"
                | "url"
                | "f"
                | "folder"
                | "note"
                | "notes"
                | "field"
                | "org"
                | "organization"
                | "col"
                | "collection"
        )
    }

    fn parse(word: &str) -> Self {
        let Some((prefix, value)) = word.split_once(':') else {
            return Self::Any(word.to_string());
        };
        if value.is_empty() || !Self::recognizes_prefix(prefix) {
            return Self::Any(word.to_string());
        }
        match prefix.to_ascii_lowercase().as_str() {
            "n" | "name" => Self::Name(value.to_string()),
            "u" | "user" | "username" => Self::User(value.to_string()),
            "uri" | "url" => Self::Uri(value.to_string()),
            "f" | "folder" => Self::Folder(value.to_string()),
            "note" | "notes" => Self::Notes(value.to_string()),
            "field" => Self::Field(value.to_string()),
            "org" | "organization" => Self::Organization(value.to_string()),
            "col" | "collection" => Self::Collection(value.to_string()),
            _ => unreachable!("checked by recognizes_prefix"),
        }
    }
}

// Parse a full query string (e.g. "u:alice uri:google admin") into its
// AND-ed tokens, splitting on whitespace.
fn parse_query(input: &str) -> Vec<QueryToken> {
    input.split_whitespace().map(QueryToken::parse).collect()
}

// Byte ranges within `query` covering a *recognized* scope prefix, colon
// included (e.g. the "u:" in "u:alice") — used by the TUI to color the
// prefix distinctly in the search bar, so a scoped search is visibly
// different from a plain one. A word with an unrecognized prefix (which
// `QueryToken::parse` treats as a literal bare word) isn't included.
pub fn scope_prefix_ranges(query: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut search_from = 0;
    for word in query.split_whitespace() {
        let Some(rel) = query[search_from..].find(word) else {
            continue;
        };
        let start = search_from + rel;
        search_from = start + word.len();

        let Some((prefix, _)) = word.split_once(':') else {
            continue;
        };
        if QueryToken::recognizes_prefix(prefix) {
            ranges.push((start, start + prefix.len() + 1));
        }
    }
    ranges
}

// Which displayed field a piece of text (a TUI list row, a TUI detail-pane
// row, or a CLI table cell) is showing — used to decide which query words
// apply to it for `highlight_ranges`.
#[derive(Clone, Copy)]
pub enum SearchField {
    Name,
    User,
    Folder,
    Uri,
    Notes,
    Field,
    Organization,
    Collection,
    // A hidden/sensitive value with no scoping prefix of its own (password,
    // card number, ssh private key, …) — only ever reached by a bare word
    // (`QueryToken::Any`), matching `search_match`'s own `sensitive_fields`
    // scan.
    Secret,
}

// Byte ranges within `text` (a `field`-typed piece of an entry, e.g. its
// name) that any word of `query` matches — a bare word always applies to
// every field, a scoped word like "u:alice" only applies to its own field.
// Used to highlight *why* a row matched the current filter/search term, in
// both the TUI and the CLI's `list`/`search`.
pub fn highlight_ranges(
    query: &str,
    field: SearchField,
    text: &str,
) -> Vec<(usize, usize)> {
    if text.is_empty() {
        return Vec::new();
    }
    let lower_text = text.to_lowercase();
    let mut ranges = Vec::new();
    for token in parse_query(query) {
        let ((QueryToken::Any(term), _)
        | (QueryToken::Name(term), SearchField::Name)
        | (QueryToken::User(term), SearchField::User)
        | (QueryToken::Folder(term), SearchField::Folder)
        | (QueryToken::Uri(term), SearchField::Uri)
        | (QueryToken::Notes(term), SearchField::Notes)
        | (QueryToken::Field(term), SearchField::Field)
        | (QueryToken::Organization(term), SearchField::Organization)
        | (QueryToken::Collection(term), SearchField::Collection)) =
            (token, field)
        else {
            continue;
        };
        let needle = term.to_lowercase();
        if needle.is_empty() {
            continue;
        }
        let mut start = 0;
        while let Some(pos) = lower_text[start..].find(&needle) {
            let s = start + pos;
            let e = s + needle.len();
            ranges.push((s, e));
            start = e.max(s + 1);
            if start >= lower_text.len() {
                break;
            }
        }
    }
    ranges.sort_unstable();
    ranges
}

// Relevance weights for entry lookup. A match's location decides how strongly
// it counts, so a name hit always outranks a hit inside a hidden field, and an
// exact (case-insensitive) name match wins decisively. Per-needle scores are
// summed; `SCORE_FULL_NAME_BONUS` is added when the whole needle string equals
// the entry name.
const SCORE_UID_EXACT: u32 = 10_000;
const SCORE_NAME_EXACT: u32 = 1_000;
const SCORE_NAME_PREFIX: u32 = 200;
const SCORE_NAME_SUBSTR: u32 = 100;
const SCORE_URI: u32 = 80;
const SCORE_ID_SUBSTR: u32 = 20;
const SCORE_SENSITIVE: u32 = 10;
const SCORE_FULL_NAME_BONUS: u32 = 5_000;

impl DecryptedSearchCipher {
    // Minimal entry for tests outside this module (e.g. the TUI's) that just
    // need *an* entry to select, not specific field content.
    #[cfg(test)]
    pub(crate) fn test_entry(name: &str) -> Self {
        Self {
            id: name.to_string(),
            entry_type: "Login".to_string(),
            folder: None,
            name: name.to_string(),
            user: None,
            uris: vec![],
            fields: vec![],
            notes: None,
            attachment_count: 0,
            archived: false,
            deleted: false,
            sensitive_fields: vec![],
            password: None,
        }
    }

    pub fn display_name(&self) -> String {
        self.user.as_ref().map_or_else(
            || self.name.clone(),
            |user| format!("{user}@{}", self.name),
        )
    }

    // Folder/username pre-filter, independent of the needle. `strict_*`
    // rejects an entry that *has* a folder/username when the caller gave none
    // (used only for tie-breaking between otherwise-equal candidates).
    fn passes_user_folder(
        &self,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
        exact: bool,
        strict_username: bool,
        strict_folder: bool,
    ) -> bool {
        let match_str = |field: &str, term: &str| match (ignore_case, exact) {
            (true, true) => field.to_lowercase() == term.to_lowercase(),
            (true, false) => {
                field.to_lowercase().contains(&term.to_lowercase())
            }
            (false, true) => field == term,
            (false, false) => field.contains(term),
        };

        match (self.folder.as_deref(), folder) {
            (Some(folder), Some(given_folder)) => {
                if !match_str(folder, given_folder) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_folder {
                    return false;
                }
            }
            (None, Some(_)) => return false,
            (None, None) => {}
        }

        match (&self.user, username) {
            (Some(username), Some(given_username)) => {
                if !match_str(username, given_username) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_username {
                    return false;
                }
            }
            (None, Some(_)) => return false,
            (None, None) => {}
        }

        true
    }

    // Score how strongly `needle` matches this entry by *where* it matches, so
    // candidates can be ranked: an exact name beats a name substring beats a
    // hit buried in a hidden field. `None` means no match. With `exact`
    // (--exact) only an exact name match counts. Substring/prefix matching is
    // always case-insensitive (so `micro` finds `Microsoft`); the `ignore_case`
    // flag only affects exact matching.
    fn match_score(
        &self,
        needle: &Needle,
        ignore_case: bool,
        exact: bool,
    ) -> Option<u32> {
        // Tiered score against the entry name only. `ci` chooses case
        // sensitivity. In --exact mode only an exact match counts.
        let name_score = |term: &str, ci: bool| -> Option<u32> {
            let (name, term) = if ci {
                (self.name.to_lowercase(), term.to_lowercase())
            } else {
                (self.name.clone(), term.to_string())
            };
            if exact {
                return (name == term).then_some(SCORE_NAME_EXACT);
            }
            if name == term {
                Some(SCORE_NAME_EXACT)
            } else if name.starts_with(&term) {
                Some(SCORE_NAME_PREFIX)
            } else if name.contains(&term) {
                Some(SCORE_NAME_SUBSTR)
            } else {
                None
            }
        };

        match needle {
            // A uuid needle matches the id exactly (case-insensitive), else
            // falls back to a name match honouring `ignore_case`.
            Needle::Uuid(uuid, s) => {
                if uuid::Uuid::parse_str(&self.id) == Ok(*uuid) {
                    Some(SCORE_UID_EXACT)
                } else {
                    name_score(s, ignore_case)
                }
            }
            // A name needle matches the name case-insensitively; only if the
            // name doesn't match at all do we fall back to the id or a hidden
            // field (never under --exact).
            Needle::Name(name) => name_score(name, true).or_else(|| {
                if exact {
                    return None;
                }
                let term = name.to_lowercase();
                if self.id.to_lowercase().contains(&term) {
                    Some(SCORE_ID_SUBSTR)
                } else if self
                    .sensitive_fields
                    .iter()
                    .any(|f| f.to_lowercase().contains(&term))
                {
                    Some(SCORE_SENSITIVE)
                } else {
                    None
                }
            }),
            Needle::Uri(given_uri) => self
                .uris
                .iter()
                .any(|(uri, match_type)| {
                    matches_url(uri, *match_type, given_uri)
                })
                .then_some(SCORE_URI),
        }
    }

    fn matches(
        &self,
        needle: &Needle,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
        strict_username: bool,
        strict_folder: bool,
        exact: bool,
    ) -> bool {
        self.passes_user_folder(
            username,
            folder,
            ignore_case,
            exact,
            strict_username,
            strict_folder,
        ) && self.match_score(needle, ignore_case, exact).is_some()
    }

    // `term` is a space-separated query: each word either matches any field
    // (today's plain substring behavior) or, prefixed like "u:alice" or
    // "uri:google", scopes that word to one field. Every word must match
    // (AND) for the entry as a whole to match. See `QueryToken`.
    #[cfg(test)]
    pub fn search_match(
        &self,
        term: &str,
        folder: Option<&str>,
        with_attachments: bool,
    ) -> bool {
        self.search_match_with_scope(term, folder, with_attachments, None)
    }

    pub fn search_match_with_scope(
        &self,
        term: &str,
        folder: Option<&str>,
        with_attachments: bool,
        scope: Option<&TuiEntryScope>,
    ) -> bool {
        if let Some(folder) = folder {
            if self.folder.as_deref() != Some(folder) {
                return false;
            }
        }

        if with_attachments && self.attachment_count == 0 {
            return false;
        }

        if term.trim().is_empty() {
            return true;
        }

        parse_query(term)
            .iter()
            .all(|token| self.token_match(token, scope))
    }

    fn token_match(
        &self,
        token: &QueryToken,
        scope: Option<&TuiEntryScope>,
    ) -> bool {
        let contains = |field: &str, needle: &str| {
            field.to_lowercase().contains(&needle.to_lowercase())
        };
        match token {
            QueryToken::Any(term) => {
                contains(&self.name, term)
                    || self
                        .folder
                        .as_deref()
                        .is_some_and(|f| contains(f, term))
                    || self.user.as_deref().is_some_and(|u| contains(u, term))
                    || self
                        .notes
                        .as_deref()
                        .is_some_and(|n| contains(n, term))
                    || self.uris.iter().any(|(u, _)| contains(u, term))
                    || self.fields.iter().any(|f| contains(f, term))
                    || self.sensitive_fields.iter().any(|f| contains(f, term))
            }
            QueryToken::Name(term) => contains(&self.name, term),
            QueryToken::User(term) => {
                self.user.as_deref().is_some_and(|u| contains(u, term))
            }
            QueryToken::Uri(term) => {
                self.uris.iter().any(|(u, _)| contains(u, term))
            }
            QueryToken::Folder(term) => {
                self.folder.as_deref().is_some_and(|f| contains(f, term))
            }
            QueryToken::Notes(term) => {
                self.notes.as_deref().is_some_and(|n| contains(n, term))
            }
            QueryToken::Field(term) => {
                self.fields.iter().any(|f| contains(f, term))
            }
            QueryToken::Organization(term) => scope
                .and_then(|scope| scope.organization.as_deref())
                .is_some_and(|org| contains(org, term)),
            QueryToken::Collection(term) => scope.is_some_and(|scope| {
                scope.collections.iter().any(|col| contains(col, term))
            }),
        }
    }
}

impl From<DecryptedSearchCipher> for DecryptedListCipher {
    fn from(value: DecryptedSearchCipher) -> Self {
        let attachment_metadata =
            AttachmentMetadata::new(&value.id, value.attachment_count);
        Self {
            id: value.id,
            entry_type: Some(value.entry_type),
            name: Some(value.name),
            user: value.user,
            password: value.password,
            folder: value.folder,
            uris: Some(value.uris.into_iter().map(|(s, _)| s).collect()),
            collection_ids: None,
            attachment_metadata,
            archived: value.archived,
            deleted: value.deleted,
            account: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedAttachment {
    pub id: String,
    pub file_name: Option<String>,
    pub size: Option<String>,
    pub size_name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AttachmentMetadata {
    #[serde(skip_serializing_if = "is_zero")]
    pub attachment_count: usize,
}

impl AttachmentMetadata {
    fn new(_entry_id: &str, attachment_count: usize) -> Self {
        Self { attachment_count }
    }

    fn has_attachments(&self) -> bool {
        self.attachment_count > 0
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedCipher {
    pub id: String,
    pub folder: Option<String>,
    pub name: String,
    pub data: DecryptedData,
    pub fields: Vec<DecryptedField>,
    pub notes: Option<String>,
    pub history: Vec<DecryptedHistoryEntry>,
    pub attachments: Vec<DecryptedAttachment>,
    #[serde(flatten)]
    pub attachment_metadata: AttachmentMetadata,
    pub archived: bool,
    pub deleted: bool,
    // Set when this entry was merged in from a non-active account (multi-
    // account `list`/`search`); omitted otherwise so single-account output is
    // unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

// Where a plain `rbw get` value was resolved from — surfaced by --verbose.
enum SecretSource {
    Password,
    Field(String),
    Notes,
}

impl SecretSource {
    fn field(field: &DecryptedField) -> Self {
        Self::Field(field.name.clone().unwrap_or_else(|| "(unnamed)".into()))
    }

    fn label(&self) -> String {
        match self {
            Self::Password => "password".to_string(),
            Self::Field(name) => format!("field '{name}'"),
            Self::Notes => "notes".to_string(),
        }
    }
}

impl DecryptedCipher {
    // The item's "default" secret for a plain `rbw get NAME`: the login
    // password, else a custom password/passphrase/pass/passwd field, else the
    // notes, else a lone custom field. This keeps the resolution logic in one
    // place (here) instead of every consumer reimplementing it. The second
    // tuple element records *where* the value came from (for --verbose).
    fn default_secret(&self) -> Option<(String, SecretSource)> {
        const FIELD_NAMES: [&str; 4] =
            ["password", "passphrase", "pass", "passwd"];

        if let DecryptedData::Login {
            password: Some(password),
            ..
        } = &self.data
        {
            return Some((password.clone(), SecretSource::Password));
        }

        if let Some(field) = self.fields.iter().find(|field| {
            field.name.as_deref().is_some_and(|name| {
                FIELD_NAMES.contains(&name.to_lowercase().as_str())
            })
        }) {
            if let Some(value) = &field.value {
                return Some((value.clone(), SecretSource::field(field)));
            }
        }

        if let Some(notes) = &self.notes {
            return Some((notes.clone(), SecretSource::Notes));
        }

        if let [field] = self.fields.as_slice() {
            if let Some(value) = &field.value {
                return Some((value.clone(), SecretSource::field(field)));
            }
        }

        None
    }

    fn display_short(&self, desc: &str, clipboard: bool) -> bool {
        match &self.data {
            DecryptedData::Login { .. } => self.default_secret().map_or_else(
                || {
                    eprintln!("entry for '{desc}' had no password");
                    false
                },
                |(password, _)| val_display_or_store(clipboard, &password),
            ),
            DecryptedData::Card { number, .. } => {
                number.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no card number");
                        false
                    },
                    |number| val_display_or_store(clipboard, number),
                )
            }
            DecryptedData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                let names: Vec<_> =
                    [title, first_name, middle_name, last_name]
                        .iter()
                        .copied()
                        .flatten()
                        .cloned()
                        .collect();
                if names.is_empty() {
                    eprintln!("entry for '{desc}' had no name");
                    false
                } else {
                    val_display_or_store(clipboard, &names.join(" "))
                }
            }
            DecryptedData::SecureNote => self.default_secret().map_or_else(
                || {
                    eprintln!("entry for '{desc}' had no notes");
                    false
                },
                |(value, _)| val_display_or_store(clipboard, &value),
            ),
            DecryptedData::SshKey { public_key, .. } => {
                public_key.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no public key");
                        false
                    },
                    |public_key| val_display_or_store(clipboard, public_key),
                )
            }
        }
    }

    fn display_field(&self, desc: &str, field: &str, clipboard: bool) {
        let field = field.to_lowercase();
        let field = field.as_str();
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => match field.parse() {
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = &username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Totp) => {
                    if let Some(totp) = totp {
                        match generate_totp(totp) {
                            Ok(code) => {
                                val_display_or_store(clipboard, &code);
                            }
                            Err(e) => {
                                eprintln!("{e}");
                            }
                        }
                    }
                }
                Ok(Field::Uris) => {
                    if let Some(uris) = uris {
                        let uri_strs: Vec<_> =
                            uris.iter().map(|uri| uri.uri.clone()).collect();
                        val_display_or_store(clipboard, &uri_strs.join("\n"));
                    }
                }
                Ok(Field::Password) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => match field.parse() {
                Ok(Field::CardNumber) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Expiration) => {
                    if let (Some(month), Some(year)) = (exp_month, exp_year) {
                        val_display_or_store(
                            clipboard,
                            &format!("{month}/{year}"),
                        );
                    }
                }
                Ok(Field::ExpMonth) => {
                    if let Some(exp_month) = exp_month {
                        val_display_or_store(clipboard, exp_month);
                    }
                }
                Ok(Field::ExpYear) => {
                    if let Some(exp_year) = exp_year {
                        val_display_or_store(clipboard, exp_year);
                    }
                }
                Ok(Field::Cvv) => {
                    if let Some(code) = code {
                        val_display_or_store(clipboard, code);
                    }
                }
                Ok(Field::Name | Field::Cardholder) => {
                    if let Some(cardholder_name) = cardholder_name {
                        val_display_or_store(clipboard, cardholder_name);
                    }
                }
                Ok(Field::Brand) => {
                    if let Some(brand) = brand {
                        val_display_or_store(clipboard, brand);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::Identity {
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
                ..
            } => match field.parse() {
                Ok(Field::Name) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Email) => {
                    if let Some(email) = email {
                        val_display_or_store(clipboard, email);
                    }
                }
                Ok(Field::Address) => {
                    let mut strs = vec![];
                    if let Some(address1) = address1 {
                        strs.push(address1.clone());
                    }
                    if let Some(address2) = address2 {
                        strs.push(address2.clone());
                    }
                    if let Some(address3) = address3 {
                        strs.push(address3.clone());
                    }
                    if !strs.is_empty() {
                        val_display_or_store(clipboard, &strs.join("\n"));
                    }
                }
                Ok(Field::City) => {
                    if let Some(city) = city {
                        val_display_or_store(clipboard, city);
                    }
                }
                Ok(Field::State) => {
                    if let Some(state) = state {
                        val_display_or_store(clipboard, state);
                    }
                }
                Ok(Field::PostalCode) => {
                    if let Some(postal_code) = postal_code {
                        val_display_or_store(clipboard, postal_code);
                    }
                }
                Ok(Field::Country) => {
                    if let Some(country) = country {
                        val_display_or_store(clipboard, country);
                    }
                }
                Ok(Field::Phone) => {
                    if let Some(phone) = phone {
                        val_display_or_store(clipboard, phone);
                    }
                }
                Ok(Field::Ssn) => {
                    if let Some(ssn) = ssn {
                        val_display_or_store(clipboard, ssn);
                    }
                }
                Ok(Field::License) => {
                    if let Some(license_number) = license_number {
                        val_display_or_store(clipboard, license_number);
                    }
                }
                Ok(Field::Passport) => {
                    if let Some(passport_number) = passport_number {
                        val_display_or_store(clipboard, passport_number);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SecureNote => match field.parse() {
                Ok(Field::Notes) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SshKey {
                fingerprint,
                private_key,
                ..
            } => match field.parse() {
                Ok(Field::Fingerprint) => {
                    if let Some(fingerprint) = fingerprint {
                        val_display_or_store(clipboard, fingerprint);
                    }
                }
                Ok(Field::PublicKey) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::PrivateKey) => {
                    if let Some(private_key) = private_key {
                        val_display_or_store(clipboard, private_key);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
        }
    }

    /// This implementation mirror the `fn display_fied` method on which field to list
    fn display_fields_list(&self) {
        match &self.data {
            DecryptedData::Login {
                username,
                password,
                totp,
                uris,
                ..
            } => {
                if username.is_some() {
                    println!("{}", Field::Username);
                }
                if totp.is_some() {
                    println!("{}", Field::Totp);
                }
                if uris.is_some() {
                    println!("{}", Field::Uris);
                }
                if password.is_some() {
                    println!("{}", Field::Password);
                }
            }
            DecryptedData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                if number.is_some() {
                    println!("{}", Field::CardNumber);
                }
                if exp_month.is_some() {
                    println!("{}", Field::ExpMonth);
                }
                if exp_year.is_some() {
                    println!("{}", Field::ExpYear);
                }
                if code.is_some() {
                    println!("{}", Field::Cvv);
                }
                if cardholder_name.is_some() {
                    println!("{}", Field::Cardholder);
                }
                if brand.is_some() {
                    println!("{}", Field::Brand);
                }
            }

            DecryptedData::Identity {
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                if [title, first_name, middle_name, last_name]
                    .iter()
                    .any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("name");
                }
                if email.is_some() {
                    println!("{}", Field::Email);
                }
                if [address1, address2, address3].iter().any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("address");
                }
                if city.is_some() {
                    println!("{}", Field::City);
                }
                if state.is_some() {
                    println!("{}", Field::State);
                }
                if postal_code.is_some() {
                    println!("{}", Field::PostalCode);
                }
                if country.is_some() {
                    println!("{}", Field::Country);
                }
                if phone.is_some() {
                    println!("{}", Field::Phone);
                }
                if ssn.is_some() {
                    println!("{}", Field::Ssn);
                }
                if license_number.is_some() {
                    println!("{}", Field::License);
                }
                if passport_number.is_some() {
                    println!("{}", Field::Passport);
                }
                if username.is_some() {
                    println!("{}", Field::Username);
                }
            }

            DecryptedData::SecureNote => (), // handled at the end
            DecryptedData::SshKey {
                fingerprint,
                public_key,
                ..
            } => {
                if fingerprint.is_some() {
                    println!("{}", Field::Fingerprint);
                }
                if public_key.is_some() {
                    println!("{}", Field::PublicKey);
                }
            }
        }

        if self.notes.is_some() {
            println!("{}", Field::Notes);
        }
        for f in &self.fields {
            if let Some(name) = &f.name {
                println!("{name}");
            }
        }
    }

    fn display_structured(
        &self,
        desc: &str,
        output: OutputMode,
    ) -> anyhow::Result<()> {
        write_serialized_pretty(
            &self,
            output,
            format!("failed to write entry '{desc}' to stdout"),
        )
    }

    fn display_show(&self) {
        let c = stdout_supports_color();
        let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
        let dim = |s: &str| style::dim(s, c);
        let secret = |s: &str| style::secret(s, c);
        let section = |s: &str| style::section(s, c);

        // Header fields: Name, UID, Type, Folder
        println!("{} {}", lbl("Name"), style::name(&self.name, c));
        println!("{} {}", lbl("UID"), style::uid(&self.id, c));
        let type_name = match &self.data {
            DecryptedData::Login { .. } => "login",
            DecryptedData::Card { .. } => "card",
            DecryptedData::Identity { .. } => "identity",
            DecryptedData::SecureNote => "secure_note",
            DecryptedData::SshKey { .. } => "ssh_key",
        };
        println!("{} {}", lbl("Type"), style::entry_type(type_name, c));
        if let Some(folder) = &self.folder {
            println!("{} {}", lbl("Folder"), style::folder(folder, c));
        }

        // Type-specific fields
        match &self.data {
            DecryptedData::Login {
                username,
                password,
                totp,
                uris,
                fido2_credentials,
            } => {
                if let Some(u) = username {
                    println!("{} {}", lbl("Username"), style::user(u, c));
                }
                if let Some(p) = password {
                    println!("{} {}", lbl("Password"), secret(p));
                }
                if let Some(t) = totp {
                    println!("{} {}", lbl("TOTP"), dim(t));
                }
                if let Some(uris) = uris {
                    for (i, uri_entry) in uris.iter().enumerate() {
                        // Only label the first URI; align the rest under it
                        // so the "URI" label isn't repeated for every value.
                        let label =
                            if i == 0 { lbl("URI") } else { " ".repeat(12) };
                        print!("{} {}", label, style::uri(&uri_entry.uri, c));
                        if let Some(mt) = uri_entry.match_type {
                            print!("  {}", dim(&format!("[{mt}]")));
                        }
                        println!();
                    }
                }
                // Never prints the raw key material -- just enough to
                // confirm a passkey is present and which relying party/
                // account it's for.
                for (i, cred) in fido2_credentials.iter().enumerate() {
                    let label = if i == 0 {
                        lbl("Passkey")
                    } else {
                        " ".repeat(12)
                    };
                    let rp =
                        cred.rp_name.as_deref().unwrap_or("(unknown rp)");
                    let user = cred
                        .user_display_name
                        .as_deref()
                        .or(cred.user_name.as_deref());
                    match user {
                        Some(user) => println!("{label} {rp} ({user})"),
                        None => println!("{label} {rp}"),
                    }
                }
            }
            DecryptedData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => {
                if let Some(n) = number {
                    println!("{} {}", lbl("Number"), secret(n));
                }
                if let (Some(m), Some(y)) = (exp_month, exp_year) {
                    println!("{} {m}/{y}", lbl("Expires"));
                }
                if let Some(cv) = code {
                    println!("{} {}", lbl("CVV"), secret(cv));
                }
                if let Some(n) = cardholder_name {
                    println!("{} {n}", lbl("Name"));
                }
                if let Some(b) = brand {
                    println!("{} {b}", lbl("Brand"));
                }
            }
            DecryptedData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
            } => {
                let full_name = [
                    title.as_deref(),
                    first_name.as_deref(),
                    middle_name.as_deref(),
                    last_name.as_deref(),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
                if !full_name.is_empty() {
                    println!("{} {full_name}", lbl("Name"));
                }
                for addr in
                    [address1, address2, address3].into_iter().flatten()
                {
                    println!("{} {addr}", lbl("Address"));
                }
                if let Some(v) = city {
                    println!("{} {v}", lbl("City"));
                }
                if let Some(v) = state {
                    println!("{} {v}", lbl("State"));
                }
                if let Some(v) = postal_code {
                    println!("{} {v}", lbl("Postcode"));
                }
                if let Some(v) = country {
                    println!("{} {v}", lbl("Country"));
                }
                if let Some(v) = phone {
                    println!("{} {v}", lbl("Phone"));
                }
                if let Some(v) = email {
                    println!("{} {v}", lbl("Email"));
                }
                if let Some(v) = username {
                    println!("{} {}", lbl("Username"), style::user(v, c));
                }
                if let Some(v) = ssn {
                    println!("{} {}", lbl("SSN"), secret(v));
                }
                if let Some(v) = license_number {
                    println!("{} {v}", lbl("License"));
                }
                if let Some(v) = passport_number {
                    println!("{} {v}", lbl("Passport"));
                }
            }
            DecryptedData::SecureNote => {}
            DecryptedData::SshKey {
                public_key,
                private_key,
                fingerprint,
            } => {
                if let Some(fp) = fingerprint {
                    println!("{} {}", lbl("Fingerprint"), dim(fp));
                }
                if let Some(pk) = public_key {
                    println!("{} {pk}", lbl("Public key"));
                }
                if let Some(pk) = private_key {
                    println!("{} {}", lbl("Private key"), secret(pk));
                }
            }
        }

        // Custom fields
        if !self.fields.is_empty() {
            println!("\n{}", section("FIELDS"));
            for field in &self.fields {
                let name = field.name.as_deref().unwrap_or("(unnamed)");
                let value = field.value.as_deref().unwrap_or("");
                let is_hidden =
                    matches!(field.ty, Some(rbw::api::FieldType::Hidden));
                if is_hidden {
                    println!("{} {}", lbl(name), secret(value));
                } else {
                    println!("{} {value}", lbl(name));
                }
            }
        }

        // Notes
        if let Some(notes) = &self.notes {
            if !notes.is_empty() {
                println!("\n{}", section("NOTES"));
                println!("{notes}");
            }
        }

        // Attachments
        if !self.attachments.is_empty() {
            println!("\n{}", section("ATTACHMENTS"));
            for att in &self.attachments {
                let fname = att.file_name.as_deref().unwrap_or(&att.id);
                let size = att
                    .size_name
                    .as_deref()
                    .or(att.size.as_deref())
                    .unwrap_or("");
                println!("\u{1f4ce} {fname:<30}  {}", style::size(size, c));
            }
        }
    }
}

// serde's `skip_serializing_if` requires a `fn(&T) -> bool`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

fn stdout_supports_color() -> bool {
    stdout_is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn stdout_is_terminal() -> bool {
    std::io::stdout().is_terminal()
}

fn stderr_supports_color() -> bool {
    std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

// A `{position}/{len} items` progress bar on stderr for long per-item loops
// (bulk import/mirror creates, collection purges). Renders nothing (every
// method becomes a no-op) when stderr isn't a terminal, so piped/logged
// output stays exactly as before -- no half-drawn bar frames in a log file.
#[allow(clippy::literal_string_with_formatting_args)]
fn item_progress_bar(len: u64) -> indicatif::ProgressBar {
    if !std::io::stderr().is_terminal() {
        return indicatif::ProgressBar::hidden();
    }
    let pb = indicatif::ProgressBar::new(len);
    pb.set_draw_target(indicatif::ProgressDrawTarget::stderr());
    if let Ok(style) = indicatif::ProgressStyle::with_template(
        "{spinner} {msg} [{bar:30}] {pos:>5}/{len:5} items",
    ) {
        pb.set_style(style.progress_chars("=> "));
    }
    // Without this, indicatif only redraws when `inc`/`set_message` are
    // called -- once per item, i.e. once per network round-trip -- so the
    // spinner visibly stutters instead of animating. A steady background
    // tick decouples the redraw rate from the actual work rate.
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

// The fixed display width `item_progress_bar`'s `{msg}` is held to (via
// `fit_to_width` below) -- otherwise everything after it (the bar, the
// counter) visibly shifts left/right as different items' names scroll
// through at different lengths.
const PROGRESS_MSG_WIDTH: usize = 40;

// Truncates (with a trailing "...") or space-pads `text` to exactly `width`
// display columns, measuring with `unicode_width` so multi-byte/wide
// characters don't throw off a fixed-width single-line progress message.
fn fit_to_width(text: &str, width: usize) -> String {
    let text_width = unicode_width::UnicodeWidthStr::width(text);
    if text_width <= width {
        return format!("{text}{}", " ".repeat(width - text_width));
    }

    let mut out = String::new();
    let mut out_width = 0;
    for ch in text.chars() {
        let ch_width =
            unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if out_width + ch_width > width.saturating_sub(3) {
            break;
        }
        out.push(ch);
        out_width += ch_width;
    }
    out.push_str("...");
    out_width += 3;
    out.push_str(&" ".repeat(width.saturating_sub(out_width)));
    out
}

// Ask for confirmation before a destructive operation. Only prompts when
// stdin is a tty, so scripts and pipelines keep the historical no-prompt
// behavior; interactive callers can skip the prompt with `-y`/`--yes`.
// Returns false (after printing "Aborted.") when the user declines.
fn confirm(prompt: &str) -> anyhow::Result<bool> {
    use std::io::Write as _;

    if !std::io::stdin().is_terminal() {
        return Ok(true);
    }

    eprint!("{prompt} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("failed to read confirmation")?;
    if matches!(answer.trim(), "y" | "Y") {
        Ok(true)
    } else {
        eprintln!("Aborted.");
        Ok(false)
    }
}

// Central style palette.  Every coloured output in rbw goes through
// these functions so that each semantic type always looks the same
// regardless of which command produced it.
mod style {
    fn paint(text: &str, code: &str, color: bool) -> String {
        if color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    // Semantic roles → ANSI style
    // uid     dim cyan       — long, secondary, but distinctive
    pub fn uid(s: &str, c: bool) -> String {
        paint(s, "2;36", c)
    }
    // name    bold           — most prominent field
    pub fn name(s: &str, c: bool) -> String {
        paint(s, "1", c)
    }
    // user    green          — "who" (accounts)
    pub fn user(s: &str, c: bool) -> String {
        paint(s, "32", c)
    }
    // secret  yellow         — sensitive / caution
    pub fn secret(s: &str, c: bool) -> String {
        paint(s, "33", c)
    }
    // folder  blue           — organisation / location
    pub fn folder(s: &str, c: bool) -> String {
        paint(s, "34", c)
    }
    // uri     cyan           — links / references
    pub fn uri(s: &str, c: bool) -> String {
        paint(s, "36", c)
    }
    // entry_type  magenta    — category label
    pub fn entry_type(s: &str, c: bool) -> String {
        paint(s, "35", c)
    }
    // label   bold cyan      — field-name label in aligned display
    pub fn label(s: &str, c: bool) -> String {
        paint(s, "1;36", c)
    }
    // section bold white     — section headers (FIELDS / NOTES / …)
    pub fn section(s: &str, c: bool) -> String {
        paint(s, "1", c)
    }
    // dim     dim            — secondary / decorative text
    pub fn dim(s: &str, c: bool) -> String {
        paint(s, "2", c)
    }
    // empty   dim italic     — "none" / "N/A" placeholder values
    pub fn empty(s: &str, c: bool) -> String {
        paint(s, "2;3", c)
    }
    // success bold green     — action verbs ("Created", "Attached", …)
    pub fn success(s: &str, c: bool) -> String {
        paint(s, "1;32", c)
    }
    // old_val dim red        — value about to be replaced
    pub fn old_val(s: &str, c: bool) -> String {
        paint(s, "2;31", c)
    }
    // new_val green          — replacement / updated value
    pub fn new_val(s: &str, c: bool) -> String {
        paint(s, "32", c)
    }
    // warning bold yellow    — warnings / notices
    pub fn warning(s: &str, c: bool) -> String {
        paint(s, "1;33", c)
    }
    // size    dim            — file sizes (same weight as dim)
    pub fn size(s: &str, c: bool) -> String {
        paint(s, "2", c)
    }
    // header  bold white     — table column headers
    pub fn header(s: &str, c: bool) -> String {
        paint(s, "1;37", c)
    }
    // raw escape for the rare case where a specific code is needed
    pub fn paint_raw(s: &str, code: &str, c: bool) -> String {
        paint(s, code, c)
    }

    // Like `paint`, but the byte ranges in `ranges` (e.g. from
    // `highlight_ranges`) are painted bold red — grep's own default match
    // color — instead of `code`, which still applies to the rest of the
    // text. `code` may be empty for a column with no color of its own.
    pub fn paint_with_matches(
        text: &str,
        code: &str,
        ranges: &[(usize, usize)],
        c: bool,
    ) -> String {
        if !c || ranges.is_empty() {
            return if code.is_empty() {
                text.to_string()
            } else {
                paint(text, code, c)
            };
        }
        let based = |s: &str| {
            if code.is_empty() {
                s.to_string()
            } else {
                paint(s, code, true)
            }
        };
        let mut out = String::new();
        let mut pos = 0;
        for &(s, e) in ranges {
            if s > pos {
                out.push_str(&based(&text[pos..s]));
            }
            out.push_str(&paint(&text[s..e], "1;31", true));
            pos = e;
        }
        if pos < text.len() {
            out.push_str(&based(&text[pos..]));
        }
        out
    }
}

fn write_yaml_pretty<T>(
    value: &T,
    context: impl Into<String>,
) -> anyhow::Result<()>
where
    T: serde::Serialize,
{
    let context = context.into();
    serde_yaml::to_writer(std::io::stdout(), value).context(context)?;
    println!();

    Ok(())
}

fn write_json_pretty<T>(
    value: &T,
    context: impl Into<String>,
) -> anyhow::Result<()>
where
    T: serde::Serialize,
{
    let context = context.into();
    if stdout_supports_color() {
        let value = serde_json::to_value(value).context(context.clone())?;
        let rendered = colored_json::to_colored_json_auto(&value)
            .map_err(|err| anyhow::anyhow!(err.to_string()))
            .context(context)?;
        println!("{rendered}");
    } else {
        serde_json::to_writer_pretty(std::io::stdout(), value)
            .context(context)?;
        println!();
    }

    Ok(())
}

fn attachment_rows(
    attachments: &[DecryptedAttachment],
    color: bool,
) -> Vec<String> {
    attachments
        .iter()
        .map(|attachment| {
            format!(
                "{}\t{}\t{}",
                style::uid(&attachment.id, color),
                style::name(
                    &attachment.file_name.clone().unwrap_or_default(),
                    color,
                ),
                style::size(
                    &attachment
                        .size_name
                        .clone()
                        .or_else(|| attachment.size.clone())
                        .unwrap_or_default(),
                    color,
                )
            )
        })
        .collect()
}

fn attachments_cell(attachment_count: usize) -> String {
    if attachment_count == 0 {
        "none".to_string()
    } else if attachment_count == 1 {
        "📎".to_string()
    } else {
        format!("📎 x{attachment_count}")
    }
}

fn output_is_structured(output: OutputMode) -> bool {
    matches!(output, OutputMode::Json | OutputMode::Yaml)
}

fn write_serialized_pretty<T>(
    value: &T,
    output: OutputMode,
    context: impl Into<String>,
) -> anyhow::Result<()>
where
    T: serde::Serialize,
{
    match output {
        OutputMode::Json => write_json_pretty(value, context),
        OutputMode::Yaml => write_yaml_pretty(value, context),
        OutputMode::Default | OutputMode::Name => {
            Err(anyhow::anyhow!("unsupported serialized output mode"))
        }
    }
}

fn format_ambiguous_entry(entry: &DecryptedSearchCipher, c: bool) -> String {
    let mut details = vec![format!("uid: {}", style::uid(&entry.id, c))];
    if let Some(user) = &entry.user {
        details.push(format!("username: {}", style::user(user, c)));
    }
    if let Some(folder) = &entry.folder {
        details.push(format!("folder: {}", style::folder(folder, c)));
    }
    if entry.attachment_count > 0 {
        details.push(format!("attachments: {}", entry.attachment_count));
    }

    format!(
        "  - {} ({})",
        style::name(&entry.name, c),
        details.join(" | ")
    )
}

// The `SearchField` a table column's cells should be matched against for
// grep-style highlighting, or `None` for a column search doesn't reason
// about at all (id, password, type, …). The `uri` column is the only one
// rendered with `TableColumnStyle::Default` today.
fn search_field_for_column(style: TableColumnStyle) -> Option<SearchField> {
    match style {
        TableColumnStyle::Name => Some(SearchField::Name),
        TableColumnStyle::User => Some(SearchField::User),
        TableColumnStyle::Folder => Some(SearchField::Folder),
        TableColumnStyle::Default => Some(SearchField::Uri),
        _ => None,
    }
}

fn colorize_table_cell(
    text: &str,
    col_style: TableColumnStyle,
    color: bool,
    ranges: &[(usize, usize)],
) -> String {
    if text.is_empty() {
        return String::new();
    }

    if (col_style == TableColumnStyle::User && text == "N/A")
        || (col_style == TableColumnStyle::Attachments && text == "none")
    {
        return style::empty(text, color);
    }

    let code = match col_style {
        TableColumnStyle::Id => "2;36",
        TableColumnStyle::Name => "1",
        TableColumnStyle::User => "32",
        TableColumnStyle::Password => "33",
        TableColumnStyle::Folder => "34",
        TableColumnStyle::EntryType => "35",
        TableColumnStyle::Collections
        | TableColumnStyle::Size
        | TableColumnStyle::Account => "2",
        TableColumnStyle::Attachments => "36",
        TableColumnStyle::Default => "",
    };
    style::paint_with_matches(text, code, ranges, color)
}

fn table_cell_width(text: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(text)
}

fn compute_table_widths(
    columns: &[TableColumn<'_>],
    rows: &[Vec<String>],
) -> Vec<usize> {
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let header_width =
                table_cell_width(&column.header.to_uppercase());
            let row_width = rows
                .iter()
                .filter_map(|row| row.get(index))
                .map(|cell| table_cell_width(cell))
                .max()
                .unwrap_or(0);
            header_width.max(row_width)
        })
        .collect()
}

fn render_table_row<F>(
    cells: &[String],
    widths: &[usize],
    mut render_cell: F,
) -> String
where
    F: FnMut(usize, &str) -> String,
{
    let last_index = cells.len().saturating_sub(1);
    let mut rendered = String::new();

    for (index, cell) in cells.iter().enumerate() {
        rendered.push_str(&render_cell(index, cell));

        if index != last_index {
            let padding =
                widths[index].saturating_sub(table_cell_width(cell));
            rendered.push_str(&" ".repeat(padding + 2));
        }
    }

    rendered
}

// `term` is the search/filter query behind these rows, if any (empty for a
// plain `rbw list`) — matched substrings are painted grep-style (bold red)
// within a cell's usual color, same match logic as `search_match`.
fn print_table(
    columns: &[TableColumn<'_>],
    rows: &[Vec<String>],
    term: &str,
) -> anyhow::Result<()> {
    if stdout_is_terminal() {
        let widths = compute_table_widths(columns, rows);
        let header_cells = columns
            .iter()
            .map(|column| column.header.to_uppercase())
            .collect::<Vec<_>>();
        let header = render_table_row(&header_cells, &widths, |_, cell| {
            style::header(cell, stdout_supports_color())
        });
        println!("{header}");
        for row in rows {
            let rendered = render_table_row(row, &widths, |index, cell| {
                columns.get(index).map_or_else(String::new, |column| {
                    let ranges = search_field_for_column(column.style)
                        .map(|field| highlight_ranges(term, field, cell))
                        .unwrap_or_default();
                    colorize_table_cell(
                        cell,
                        column.style,
                        stdout_supports_color(),
                        &ranges,
                    )
                })
            });
            println!("{rendered}");
        }
    } else {
        for row in rows {
            match writeln!(&mut std::io::stdout(), "{}", row.join("\t")) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    return Ok(());
                }
                res => res?,
            }
        }
    }

    Ok(())
}

fn available_attachments_error(
    entry_name: &str,
    attachments: &[DecryptedAttachment],
    reason: &str,
) -> anyhow::Error {
    if attachments.is_empty() {
        return anyhow::anyhow!(
            "{reason}\nNo attachments are available for '{entry_name}'."
        );
    }

    let mut message = String::new();
    let _ = writeln!(&mut message, "{reason}");
    let _ =
        writeln!(&mut message, "Available attachments for '{entry_name}':");
    for row in attachment_rows(attachments, false) {
        let _ = writeln!(&mut message, "{row}");
    }
    let _ = write!(
        &mut message,
        "Use `rbw attachment get <entry> --attachment <id-or-filename>` to download one."
    );
    anyhow::anyhow!(message)
}

fn val_display_or_store(clipboard: bool, password: &str) -> bool {
    if clipboard {
        match clipboard_store(password) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("{e}");
                false
            }
        }
    } else {
        println!("{password}");
        true
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type")]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum DecryptedData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Option<Vec<DecryptedUri>>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fido2_credentials: Vec<DecryptedFido2Credential>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        public_key: Option<String>,
        fingerprint: Option<String>,
        private_key: Option<String>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedField {
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(serialize_with = "serialize_field_type", rename = "type")]
    pub ty: Option<rbw::api::FieldType>,
}

#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
fn serialize_field_type<S>(
    ty: &Option<rbw::api::FieldType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match ty {
        Some(ty) => {
            let s = match ty {
                rbw::api::FieldType::Text => "text",
                rbw::api::FieldType::Hidden => "hidden",
                rbw::api::FieldType::Boolean => "boolean",
                rbw::api::FieldType::Linked => "linked",
            };
            serializer.serialize_some(&Some(s))
        }
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedHistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedUri {
    pub uri: String,
    pub match_type: Option<rbw::api::UriMatchType>,
}

// A decrypted passkey. `creation_date` is never encrypted to begin with
// (see `rbw::db::Fido2Credential`); every other field was decrypted the
// same way `password`/`username` are.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedFido2Credential {
    pub credential_id: Option<String>,
    pub key_type: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_curve: Option<String>,
    pub key_value: Option<String>,
    pub rp_id: Option<String>,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: Option<String>,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub discoverable: Option<String>,
    pub creation_date: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EditableCipher {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub data: EditableData,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<EditableCustomField>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EditableData {
    Login {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        uris: Vec<EditableUri>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        totp: Option<String>,
        // Round-trips unchanged if left untouched in the editor -- not
        // meant to be hand-edited (it's opaque key material), just carried
        // through so editing an entry can never destroy its passkey the
        // way an absent field on the outgoing request would (Vaultwarden
        // stores the whole `login` object wholesale, no per-field merge).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fido2_credentials: Vec<EditableFido2Credential>,
    },
    Card {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cardholder_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brand: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exp_month: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exp_year: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    Identity {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        first_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        middle_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address1: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address2: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address3: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        city: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        postal_code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        country: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        phone: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ssn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        license_number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passport_number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        private_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fingerprint: Option<String>,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EditableUri {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct EditableFido2Credential {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_curve: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discoverable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EditableCustomField {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(
        rename = "type",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ty: Option<String>,
}

fn matches_url(
    url: &str,
    match_type: Option<rbw::api::UriMatchType>,
    given_url: &url::Url,
) -> bool {
    match match_type.unwrap_or(rbw::api::UriMatchType::Domain) {
        rbw::api::UriMatchType::Domain => {
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
            url == given_host_port
                || given_host_port.ends_with(&format!(".{url}"))
        }
        rbw::api::UriMatchType::Host => {
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
        rbw::api::UriMatchType::StartsWith => {
            given_url.to_string().starts_with(url)
        }
        rbw::api::UriMatchType::Exact => {
            if given_url.path() == "/" {
                given_url.to_string().trim_end_matches('/')
                    == url.trim_end_matches('/')
            } else {
                given_url.to_string() == url
            }
        }
        rbw::api::UriMatchType::RegularExpression => {
            let Ok(rx) = regex::Regex::new(url) else {
                return false;
            };
            rx.is_match(given_url.as_ref())
        }
        rbw::api::UriMatchType::Never => false,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListField {
    Id,
    Name,
    User,
    Password,
    Folder,
    Uri,
    EntryType,
    Collections,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TableColumnStyle {
    Id,
    Name,
    User,
    Password,
    Folder,
    EntryType,
    Collections,
    Attachments,
    Size,
    Account,
    Default,
}

struct TableColumn<'a> {
    header: &'a str,
    style: TableColumnStyle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Default,
    Name,
    Json,
    Yaml,
}

impl std::convert::TryFrom<&String> for ListField {
    type Error = anyhow::Error;

    fn try_from(s: &String) -> anyhow::Result<Self> {
        Ok(match s.as_str() {
            "name" => Self::Name,
            "id" | "uid" => Self::Id,
            "user" => Self::User,
            "password" => Self::Password,
            "folder" => Self::Folder,
            "type" => Self::EntryType,
            "collections" => Self::Collections,
            _ => return Err(anyhow::anyhow!("unknown field {s}")),
        })
    }
}

pub const CONFIG_KEYS: &[&str] = &[
    "email",
    "ssoId",
    "baseUrl",
    "identityUrl",
    "uiUrl",
    "notificationsUrl",
    "clientCertPath",
    "primaryAccount",
    "agent.syncInterval",
    "agent.lockTimeout",
    "pinentry.command",
    "pinentry.timeout",
    "termux.keyAlias",
    "tui.lockTimeout",
    "hide.archived",
    "hide.trashed",
    "passwordGen.length",
    "passwordGen.noSymbols",
    "passwordGen.onlyNumbers",
    "passwordGen.nonconfusables",
    "passwordGen.diceware",
    "clipboard",
];

pub fn config_show(json: bool) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    if json {
        write_json_pretty(&config, "failed to write config to stdout")
    } else {
        write_yaml_pretty(&config, "failed to write config to stdout")
    }
}

// Print a single setting's effective value: account-scoped keys resolve
// through the primary account (matching what rbw actually uses), global
// preferences come straight off the config.
pub fn config_get(key: &str) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let primary = config.primary();
    let value = match key {
        "email" => primary.email,
        "ssoId" => primary.sso_id,
        "baseUrl" => primary.base_url,
        "identityUrl" => primary.identity_url,
        "uiUrl" => primary.ui_url,
        "notificationsUrl" => primary.notifications_url,
        "clientCertPath" => {
            primary.client_cert_path.map(|p| p.display().to_string())
        }
        "primaryAccount" => config.primary_account,
        "agent.lockTimeout" => Some(config.agent.lock_timeout.to_string()),
        "agent.syncInterval" => Some(config.agent.sync_interval.to_string()),
        "pinentry.command" => Some(config.pinentry.command),
        "pinentry.timeout" => Some(config.pinentry.timeout.to_string()),
        "termux.keyAlias" => config.termux.key_alias,
        "tui.lockTimeout" => Some(config.tui.lock_timeout.to_string()),
        "hide.archived" => Some(config.hide.archived.to_string()),
        "hide.trashed" => Some(config.hide.trashed.to_string()),
        "passwordGen.length" => {
            config.password_gen.length.map(|length| length.to_string())
        }
        "passwordGen.noSymbols" => {
            Some(config.password_gen.no_symbols.to_string())
        }
        "passwordGen.onlyNumbers" => {
            Some(config.password_gen.only_numbers.to_string())
        }
        "passwordGen.nonconfusables" => {
            Some(config.password_gen.nonconfusables.to_string())
        }
        "passwordGen.diceware" => {
            Some(config.password_gen.diceware.to_string())
        }
        "clipboard" => {
            Some(clipboard_mechanism_str(config.clipboard).to_string())
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    };
    let Some(value) = value else {
        anyhow::bail!("{key} is not set");
    };
    println!("{value}");
    Ok(())
}

// Open the whole config.yaml as YAML in $EDITOR, the same
// serialize/edit/strip-comments/reparse shape as entry editing (see
// `edit`/`edit_full`). Mirrors `config_set`'s post-save `stop_agent` call --
// any field could plausibly affect already-cached agent state (accounts,
// urls, timeouts), so this always stops it rather than trying to detect
// exactly which fields changed.
pub fn config_edit() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    let serialized = serde_yaml::to_string(&config)?;

    let help = "# Edit the YAML below. Lines starting with # are ignored.";
    let contents = rbw::edit::edit(&serialized, help, "yaml")?;
    let contents_trimmed = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });

    if contents_trimmed.trim() == serialized.trim() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    let updated: rbw::config::Config =
        serde_yaml::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?;
    updated.save()?;

    // See `config_set`'s comment: not using lock() because we don't want to
    // require the agent to be running, and stop_agent() already handles
    // that gracefully.
    stop_agent()?;

    println!("updated config");
    Ok(())
}

pub fn config_set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.primary_mut().email = Some(value.to_string()),
        "ssoId" => config.primary_mut().sso_id = Some(value.to_string()),
        "baseUrl" => config.primary_mut().base_url = Some(value.to_string()),
        "identityUrl" => {
            config.primary_mut().identity_url = Some(value.to_string());
        }
        "uiUrl" => config.primary_mut().ui_url = Some(value.to_string()),
        "notificationsUrl" => {
            config.primary_mut().notifications_url = Some(value.to_string());
        }
        "clientCertPath" => {
            config.primary_mut().client_cert_path =
                Some(std::path::PathBuf::from(value.to_string()));
        }
        "primaryAccount" => config.primary_account = Some(value.to_string()),
        "agent.lockTimeout" => {
            let timeout = value
                .parse()
                .context("failed to parse value for agent.lockTimeout")?;
            if timeout == 0 {
                log::error!("agent.lockTimeout must be greater than 0");
            } else {
                config.agent.lock_timeout = timeout;
            }
        }
        "agent.syncInterval" => {
            let interval = value
                .parse()
                .context("failed to parse value for agent.syncInterval")?;
            config.agent.sync_interval = interval;
        }
        "pinentry.command" => config.pinentry.command = value.to_string(),
        "termux.keyAlias" => {
            config.termux.key_alias = Some(value.to_string());
        }
        "pinentry.timeout" => {
            config.pinentry.timeout = value
                .parse()
                .context("failed to parse value for pinentry.timeout")?;
        }
        "tui.lockTimeout" => {
            config.tui.lock_timeout = value
                .parse()
                .context("failed to parse value for tui.lockTimeout")?;
        }
        "hide.archived" => {
            config.hide.archived = value
                .parse()
                .context("failed to parse value for hide.archived")?;
        }
        "hide.trashed" => {
            config.hide.trashed = value
                .parse()
                .context("failed to parse value for hide.trashed")?;
        }
        "passwordGen.length" => {
            config.password_gen.length =
                Some(value.parse().context(
                    "failed to parse value for passwordGen.length",
                )?);
        }
        "passwordGen.noSymbols" => {
            config.password_gen.no_symbols = value
                .parse()
                .context("failed to parse value for passwordGen.noSymbols")?;
        }
        "passwordGen.onlyNumbers" => {
            config.password_gen.only_numbers = value.parse().context(
                "failed to parse value for passwordGen.onlyNumbers",
            )?;
        }
        "passwordGen.nonconfusables" => {
            config.password_gen.nonconfusables = value.parse().context(
                "failed to parse value for passwordGen.nonconfusables",
            )?;
        }
        "passwordGen.diceware" => {
            config.password_gen.diceware = value
                .parse()
                .context("failed to parse value for passwordGen.diceware")?;
        }
        "clipboard" => {
            config.clipboard = parse_clipboard_mechanism(value)?;
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

pub fn config_unset(key: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.primary_mut().email = None,
        "ssoId" => config.primary_mut().sso_id = None,
        "baseUrl" => config.primary_mut().base_url = None,
        "identityUrl" => config.primary_mut().identity_url = None,
        "uiUrl" => config.primary_mut().ui_url = None,
        "notificationsUrl" => config.primary_mut().notifications_url = None,
        "clientCertPath" => config.primary_mut().client_cert_path = None,
        "primaryAccount" => config.primary_account = None,
        "agent.lockTimeout" => {
            config.agent.lock_timeout = rbw::config::default_lock_timeout();
        }
        "agent.syncInterval" => {
            config.agent.sync_interval = rbw::config::default_sync_interval();
        }
        "pinentry.command" => {
            config.pinentry.command = rbw::config::default_pinentry();
        }
        "termux.keyAlias" => config.termux.key_alias = None,
        "pinentry.timeout" => {
            config.pinentry.timeout = rbw::config::default_pinentry_timeout();
        }
        "tui.lockTimeout" => {
            config.tui.lock_timeout = rbw::config::default_tui_lock_timeout();
        }
        "hide.archived" => {
            config.hide.archived = rbw::config::default_hide_archived();
        }
        "hide.trashed" => {
            config.hide.trashed = rbw::config::default_hide_trashed();
        }
        "passwordGen.length" => {
            config.password_gen.length = None;
        }
        "passwordGen.noSymbols" => {
            config.password_gen.no_symbols = false;
        }
        "passwordGen.onlyNumbers" => {
            config.password_gen.only_numbers = false;
        }
        "passwordGen.nonconfusables" => {
            config.password_gen.nonconfusables = false;
        }
        "passwordGen.diceware" => {
            config.password_gen.diceware = false;
        }
        "clipboard" => {
            config.clipboard = rbw::config::ClipboardMechanism::default();
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

pub fn termux_enroll(validity: u32) -> anyhow::Result<()> {
    use zeroize::Zeroize as _;

    let mut config = rbw::config::Config::load()?;
    config.migrate_legacy();
    let account_name = crate::actions::current_account()
        .unwrap_or_else(|| config.primary_account_name());
    let account = config.account(Some(&account_name))?;
    if account.unlock.termux.is_some() {
        anyhow::bail!(
            "account {account_name:?} already has Termux unlock configured"
        );
    }

    let bundle = rbw::termux::default_bundle_path(&account_name);
    if bundle.exists() {
        anyhow::bail!(
            "Termux unlock bundle {} already exists; remove it before enrolling again",
            bundle.display()
        );
    }

    let environment = crate::actions::get_environment();
    let description = format!(
        "Enroll native Android unlock for rbw account {account_name:?}"
    );
    let runtime = tokio::runtime::Runtime::new()
        .context("failed to initialize the password prompt")?;
    let mut password = runtime
        .block_on(rbw::pinentry::getpin(
            &config.pinentry.command,
            "Master password",
            &description,
            None,
            &environment,
            false,
            None,
            config.pinentry.timeout,
        ))?
        .password()
        .to_vec();

    // Verify the password actually unlocks the account before enrolling a
    // Termux key against it -- otherwise a mistyped password would get
    // baked into the encrypted bundle, and every future Termux unlock would
    // "succeed" at the crypto layer while producing a password that never
    // actually works.
    let mut password_string = String::from_utf8(password.clone())
        .context("master password was not valid UTF-8")?;
    crate::actions::set_active_account(Some(account_name.clone()))?;
    let verified =
        unlock_impl(Some(password_string.clone()), None, &mut Vec::new());
    password_string.zeroize();
    if let Err(error) = verified {
        password.zeroize();
        return Err(error.context(
            "master password did not unlock the account; refusing to \
             enroll a Termux key for a password that doesn't work",
        ));
    }

    let key_alias =
        rbw::termux::resolve_key_alias(&config, &account_name, None);
    let algorithm = "SHA256withRSA";
    let result = (|| {
        let generated_key = !rbw::termux::key_present(&key_alias)?;
        if generated_key {
            rbw::termux::generate(&key_alias, "RSA", Some(2048), validity)?;
        }
        if let Err(error) = rbw::termux::enroll(
            &bundle,
            &key_alias,
            algorithm,
            std::mem::take(&mut password),
        ) {
            if generated_key {
                let _ = rbw::termux::delete(&key_alias);
            }
            return Err(error);
        }

        let account = config
            .accounts
            .iter_mut()
            .find(|account| account.name == account_name)
            .ok_or_else(|| {
                anyhow::anyhow!("account {account_name:?} vanished")
            })?;
        account.unlock.termux = Some(rbw::config::TermuxKeystoreUnlock {
            file: bundle.clone(),
            key_alias: key_alias.clone(),
            algorithm: algorithm.to_string(),
        });
        if let Err(error) = config.save() {
            let _ = std::fs::remove_file(&bundle);
            if generated_key {
                let _ = rbw::termux::delete(&key_alias);
            }
            return Err(anyhow::Error::new(error));
        }
        let _ = stop_agent();
        println!(
            "Termux unlock enrolled for account {account_name:?}.\n\
             Key: {key_alias} ({})\n\
             Bundle: {}\n\
             Future unlocks will ask Android Keystore for authentication.",
            if generated_key { "generated" } else { "reused" },
            bundle.display()
        );
        Ok(())
    })();
    password.zeroize();
    result
}

pub fn termux_remove(yes: bool) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()?;
    config.migrate_legacy();
    let account_name = crate::actions::current_account()
        .unwrap_or_else(|| config.primary_account_name());
    let (configured, key_alias, bundle) = {
        let account = config.account(Some(&account_name))?;
        let configured = account.unlock.termux.as_ref();
        let key_alias = rbw::termux::resolve_key_alias(
            &config,
            &account_name,
            configured.map(|termux| termux.key_alias.as_str()),
        );
        let bundle = configured.map_or_else(
            || rbw::termux::default_bundle_path(&account_name),
            |termux| termux.file.clone(),
        );
        (configured.is_some(), key_alias, bundle)
    };

    let key_present = rbw::termux::key_present(&key_alias)?;
    let bundle_present = bundle.exists();
    if !configured && !key_present && !bundle_present {
        println!("No Termux unlock found for account {account_name:?}.");
        return Ok(());
    }
    if !yes && !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "refusing to remove Termux unlock non-interactively; pass --yes"
        );
    }
    if !yes
        && !confirm(&format!(
            "Permanently delete Termux key {key_alias:?} and {}?",
            bundle.display()
        ))?
    {
        return Ok(());
    }

    if key_present {
        rbw::termux::delete(&key_alias)?;
    }
    if bundle_present {
        std::fs::remove_file(&bundle).with_context(|| {
            format!("failed to remove {}", bundle.display())
        })?;
    }

    let account = config
        .accounts
        .iter_mut()
        .find(|account| account.name == account_name)
        .ok_or_else(|| {
            anyhow::anyhow!("account {account_name:?} vanished")
        })?;
    account.unlock.termux = None;
    config.save()?;
    let _ = stop_agent();

    println!(
        "Removed Termux unlock for account {account_name:?} (key: {key_alias})."
    );
    Ok(())
}

pub fn account_list() {
    let config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    let primary = config.primary_account_name();
    let accounts = config.accounts();
    if accounts.is_empty() {
        eprintln!("no accounts configured");
        return;
    }
    for account in &accounts {
        let marker = if account.name == primary { " *" } else { "" };
        let email = account.email.as_deref().unwrap_or("-");
        let server = account
            .base_url
            .as_deref()
            .unwrap_or("(public bitwarden.com)");
        println!("{}{marker}\t{email}\t{server}", account.name);
    }
}

pub fn account_add(
    name: &str,
    email: Option<String>,
    base_url: Option<String>,
    sso_id: Option<String>,
    primary: bool,
) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    if config.accounts.iter().any(|a| a.name == name) {
        anyhow::bail!("account '{name}' already exists");
    }
    let old_primary = config.primary_account_name();
    let first = config.accounts.is_empty();
    config.accounts.push(rbw::config::Account {
        name: name.to_string(),
        email,
        sso_id,
        base_url,
        identity_url: None,
        ui_url: None,
        notifications_url: None,
        client_cert_path: None,
        unlock: rbw::config::UnlockConfig::default(),
        exclude_from: Vec::new(),
    });
    // The first account is always primary; otherwise only if asked.
    if primary || first {
        config.primary_account = Some(name.to_string());
    }
    config.save()?;

    let now_primary = config.primary_account_name();
    if now_primary != old_primary {
        // Primary changed, so any keys the agent holds are for the wrong
        // account; drop them (mirrors `config set email`).
        stop_agent()?;
    }
    let suffix = if now_primary == name {
        " (primary)"
    } else {
        ""
    };
    println!("added account '{name}'{suffix}");
    Ok(())
}

pub fn account_remove(name: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    let old_primary = config.primary_account_name();
    let before = config.accounts.len();
    config.accounts.retain(|a| a.name != name);
    if config.accounts.len() == before {
        anyhow::bail!("account '{name}' not found");
    }
    if config.primary_account.as_deref() == Some(name) {
        config.primary_account =
            config.accounts.first().map(|a| a.name.clone());
    }
    config.save()?;

    if config.primary_account_name() != old_primary {
        stop_agent()?;
    }
    println!("removed account '{name}'");
    Ok(())
}

pub fn account_set_primary(name: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    if !config.accounts.iter().any(|a| a.name == name) {
        anyhow::bail!("account '{name}' not found");
    }
    let old_primary = config.primary_account_name();
    config.primary_account = Some(name.to_string());
    config.save()?;

    if old_primary != name {
        stop_agent()?;
    }
    println!("primary account is now '{name}'");
    Ok(())
}

// Change one or more per-account settings (currently `unlock.policy`,
// `exclude_from`, and `unlock.credentials` — see `rbw::config::Account`).
// Leaves a setting unchanged when its argument is `None`/empty/`false`.
#[allow(clippy::fn_params_excessive_bools)]
pub fn account_set(
    name: &str,
    unlock: Option<rbw::config::UnlockPolicy>,
    exclude_from: Vec<rbw::config::ExcludeContext>,
    clear_exclude_from: bool,
    credential_source_account: Option<String>,
    credential_source_item: Option<String>,
    clear_credential_source: bool,
) -> anyhow::Result<()> {
    if unlock.is_none()
        && exclude_from.is_empty()
        && !clear_exclude_from
        && credential_source_account.is_none()
        && credential_source_item.is_none()
        && !clear_credential_source
    {
        anyhow::bail!(
            "nothing to change: pass --unlock, --exclude-from (repeatable) \
            or --clear-exclude-from, --credential-source-account and \
            optionally --credential-source-item, or \
            --clear-credential-source"
        );
    }
    if clear_exclude_from && !exclude_from.is_empty() {
        anyhow::bail!(
            "--clear-exclude-from can't be combined with --exclude-from"
        );
    }
    if clear_credential_source
        && (credential_source_account.is_some()
            || credential_source_item.is_some())
    {
        anyhow::bail!(
            "--clear-credential-source can't be combined with \
            --credential-source-account/--credential-source-item"
        );
    }

    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    let Some(account) = config.accounts.iter_mut().find(|a| a.name == name)
    else {
        anyhow::bail!("account '{name}' not found");
    };
    if let Some(unlock) = unlock {
        account.unlock.policy = unlock;
    }
    if clear_exclude_from {
        account.exclude_from = Vec::new();
    } else if !exclude_from.is_empty() {
        account.exclude_from = exclude_from;
    }
    if clear_credential_source {
        account.unlock.credentials = None;
    } else if let Some(source_account) = credential_source_account {
        account.unlock.credentials = Some(rbw::config::CredentialSource {
            account: source_account,
            item: credential_source_item
                .filter(|item| !item.trim().is_empty()),
        });
    }

    // Reject a self-reference or a cycle before persisting, rather than
    // writing a config that would silently fall back to pinentry (or worse)
    // the next time this account tries to unlock.
    config.credential_source_chain(name)?;

    config.save()?;
    println!("updated account '{name}'");
    Ok(())
}

fn clipboard_store(val: &str) -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::clipboard_store(val)?;

    Ok(())
}

// `client_id`/`client_secret` come from `--stdin` (e.g. for a fully
// non-interactive first registration on a brand-new host); when absent,
// falls back to the normal interactive pinentry flow, exactly as before.
pub fn register(
    client_id: Option<String>,
    client_secret: Option<String>,
) -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::register(client_id, client_secret)?;

    Ok(())
}

// `password`/`totp` come from `--stdin`/`--totp` (e.g. for a fully
// non-interactive first login on a brand-new host); when absent, falls back
// to `credential_source` resolution, then the normal interactive pinentry
// flow, exactly as before.
pub fn login(
    password: Option<String>,
    totp: Option<String>,
) -> anyhow::Result<()> {
    ensure_agent()?;
    password.map_or_else(
        || login_resolving_credential_source(&mut Vec::new()),
        |password| crate::actions::login(Some(password), totp),
    )
}

pub fn unlock(
    password: Option<String>,
    totp: Option<String>,
) -> anyhow::Result<()> {
    unlock_impl(password, totp, &mut Vec::new())
}

// Max hops to follow through `credential_source` chains before giving up.
// `Config::credential_source_chain` already rejects self-references and
// cycles up front (see `resolve_credential_source`), so this is only a
// defense-in-depth backstop against ever recursing unboundedly.
const MAX_CREDENTIAL_SOURCE_DEPTH: usize = 16;

// Logs the current active account in, auto-supplying the password (and a
// fresh TOTP code for the 2FA challenge, if the linked entry has one) from
// `credential_source` when configured; falls back to the normal interactive
// pinentry flow otherwise. Shared by `login`, `unlock_impl`, and `sync`'s
// per-account login step, so every path that logs an account in benefits
// equally.
fn login_resolving_credential_source(
    visited: &mut Vec<String>,
) -> anyhow::Result<()> {
    let (password, totp) = resolve_unlock_credentials(visited)?;
    crate::actions::login(password, totp)
}

// `visited` accumulates the chain of account names already being unlocked
// on the current call stack, so a `credential_source` chain can't recurse
// into itself even if the static cycle check somehow missed something.
fn unlock_impl(
    password: Option<String>,
    totp: Option<String>,
    visited: &mut Vec<String>,
) -> anyhow::Result<()> {
    ensure_agent()?;
    let (password, totp) = password.map_or_else(
        || resolve_unlock_credentials(visited),
        |password| Ok((Some(password), totp)),
    )?;
    crate::actions::login(password.clone(), totp)?;
    crate::actions::unlock(password)?;

    Ok(())
}

// Explicit Termux configuration is fail-closed: a configured provider must
// work, rather than silently falling back to a weaker pinentry path.
fn resolve_unlock_credentials(
    visited: &mut Vec<String>,
) -> anyhow::Result<(Option<String>, Option<String>)> {
    let account = active_account()?;
    if let Some(termux) = account.unlock.termux {
        let config = rbw::config::Config::load()?;
        let mut termux = termux;
        termux.key_alias = rbw::termux::resolve_key_alias(
            &config,
            &account.name,
            Some(&termux.key_alias),
        );
        return Ok((Some(rbw::termux::unlock(&termux)?), None));
    }
    Ok(resolve_credential_source(visited)
        .map_or((None, None), |(password, totp)| (Some(password), totp)))
}

// If the currently-active account has a `credential_source` configured,
// resolve its master password (and, if the linked entry has one, a current
// TOTP code generated from its secret -- for auto-answering a 2FA challenge
// during login) from the linked item in the source account's vault instead
// of prompting via pinentry: unlock the source account (recursively
// following its own `credential_source`, if it has one), find the linked
// item in its already-unlocked vault, and pull both fields from it.
// Non-Login entry types aren't handled specially -- resolution just fails
// for those.
//
// Returns `None` (falling back to the normal pinentry prompt) if there's no
// `credential_source` configured, or if resolution fails for any reason: a
// misconfigured link should never brick the account's ability to unlock at
// all.
fn resolve_credential_source(
    visited: &mut Vec<String>,
) -> Option<(String, Option<String>)> {
    let target = crate::actions::current_account().or_else(|| {
        rbw::config::Config::load()
            .ok()
            .map(|c| c.primary_account_name())
    })?;

    if visited.contains(&target)
        || visited.len() >= MAX_CREDENTIAL_SOURCE_DEPTH
    {
        log::warn!(
            "credential_source chain reaches '{target}' again (or is too \
            deep); falling back to pinentry"
        );
        return None;
    }

    let config = rbw::config::Config::load().ok()?;
    if let Err(e) = config.credential_source_chain(&target) {
        log::warn!(
            "credential_source misconfigured for account '{target}': {e:#}; \
            falling back to pinentry"
        );
        return None;
    }

    let account = config.account(Some(&target)).ok()?;
    let source = account.unlock.credentials.as_ref()?;

    visited.push(target.clone());
    let result =
        resolve_from_credential_source(&target, &account, source, visited);
    visited.pop();

    // Whatever happened, route subsequent api calls back at the account we
    // were actually asked to unlock -- the caller still needs to send the
    // Login/Unlock request to it, not to (some ancestor of) the source.
    let _ = crate::actions::set_active_account(Some(target.clone()));

    match result {
        Ok((password, totp_secret)) => {
            // The linked entry's `totp` field is the raw secret, same as
            // what `rbw code` generates from -- the server needs a
            // computed current code, not the secret itself.
            let totp = totp_secret.and_then(|secret| {
                generate_totp(&secret)
                    .inspect_err(|e| {
                        log::warn!(
                            "failed to generate a TOTP code from the \
                            credential_source-resolved secret for account \
                            '{target}': {e:#}"
                        );
                    })
                    .ok()
            });
            Some((password, totp))
        }
        Err(e) => {
            log::warn!(
                "failed to resolve credential_source for account '{target}' \
                from account '{}': {e:#}; falling back to pinentry",
                source.account
            );
            None
        }
    }
}

// Unlocks `source.account` (recursing into its own `credential_source` if it
// has one) and resolves either the explicitly-configured source item or a
// unique URI match for `target_account`'s server in its vault.
fn resolve_from_credential_source(
    target_name: &str,
    target_account: &rbw::config::Account,
    source: &rbw::config::CredentialSource,
    visited: &mut Vec<String>,
) -> anyhow::Result<(String, Option<String>)> {
    crate::actions::set_active_account(Some(source.account.clone()))?;
    // Skip re-authenticating (pinentry, Termux fingerprint, ...) when the
    // source account is already unlocked -- this runs on every credential
    // resolution, including ones for an `unlock: always` account whose
    // source was just unlocked moments earlier in the same call.
    if !active_account_unlocked() {
        unlock_impl(None, None, visited)?;
    }
    if !active_account_unlocked() {
        anyhow::bail!("source account '{}' did not unlock", source.account);
    }

    let db = load_db()?;
    let (decrypted, item_desc) = if let Some(item) = source.item.as_deref() {
        // parse_needle is Infallible -- it always returns Ok.
        let needle = parse_needle(item).unwrap();
        let (_, decrypted) = find_entry(
            &db,
            vec![needle],
            None,
            None,
            None,
            None,
            false,
            false,
        )
        .with_context(|| {
            format!("item '{item}' not found in account '{}'", source.account)
        })?;
        (decrypted, item.to_string())
    } else {
        let target_uri = target_account.ui_url();
        let needle = parse_needle(&target_uri).unwrap();
        let (_, decrypted) =
            find_entry(&db, vec![needle], None, None, None, None, false, false)
                .with_context(|| {
                    format!(
                        "no unique item in account '{}' matched '{target_name}' by URI ({target_uri})",
                        source.account
                    )
                })?;
        (decrypted, format!("URI match for {target_uri}"))
    };

    credential_source_login_fields(&decrypted, &item_desc, &source.account)
}

// Pulls the master password (and TOTP secret, if set) out of a decrypted
// credential_source item: a plain Login item's `password`/`totp` fields.
// Non-Login entry types aren't handled specially -- resolution just fails
// (falling back to pinentry) for anything else. An entry with no TOTP
// secret is fine (`totp: None`); only a missing password is fatal, since
// that's the one field every use of `credential_source` actually needs.
fn credential_source_login_fields(
    decrypted: &DecryptedCipher,
    item: &str,
    account: &str,
) -> anyhow::Result<(String, Option<String>)> {
    match &decrypted.data {
        DecryptedData::Login {
            password: Some(password),
            totp,
            ..
        } => Ok((password.clone(), totp.clone())),
        DecryptedData::Login { password: None, .. } => Err(anyhow::anyhow!(
            "item '{item}' in account '{account}' has no password set"
        )),
        _ => Err(anyhow::anyhow!(
            "item '{item}' in account '{account}' is not a login item"
        )),
    }
}

// Unlocks every configured account per its `unlock` policy, same target
// selection as `list --all`/`sync --all`. `list_target_accounts` does the
// actual unlocking as a side effect of building its target list; this just
// reports what ended up unlocked.
pub fn unlock_all() -> anyhow::Result<()> {
    let target_accounts = list_target_accounts(
        true,
        rbw::config::ExcludeContext::Unlock,
        true,
    )?;
    let c = stdout_supports_color();
    for account in &target_accounts {
        eprintln!(
            "{} '{}'",
            style::success("unlocked", c),
            style::name(account, c),
        );
    }
    Ok(())
}

pub fn unlocked() -> anyhow::Result<()> {
    // This is a passive check: don't start the agent or perform a separate
    // version handshake before asking it for the lock state.
    crate::actions::unlocked()?;

    Ok(())
}

pub fn sync(all: bool) -> anyhow::Result<()> {
    // Sync needs a running agent and a server login, but not an unlocked
    // vault. Keep that distinction intact: an ordinary sync must not prompt
    // for the master password just to refresh the local database.
    ensure_agent()?;
    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Sync, false)?;
    let c = stdout_supports_color();

    let mut failed = Vec::new();
    for account in &target_accounts {
        crate::actions::set_active_account(Some(account.clone()))?;
        match login_resolving_credential_source(&mut Vec::new())
            .and_then(|()| crate::actions::sync())
        {
            Ok(()) => {
                eprintln!(
                    "{} '{}'",
                    style::success("synced", c),
                    style::name(account, c),
                );
            }
            Err(e) => {
                eprintln!(
                    "{} '{}': {e:#}",
                    style::warning("failed to sync", c),
                    style::name(account, c),
                );
                failed.push(account.clone());
            }
        }
    }

    if !failed.is_empty() {
        anyhow::bail!("failed to sync: {}", failed.join(", "));
    }
    Ok(())
}

// `list --from-file`: no term to filter by (a term routes through
// `search_from_file` instead -- see `Opt::List`'s dispatch in main.rs), so
// the only filtering here is `with_attachments`.
fn list_from_file(
    path: &std::path::Path,
    fields: &[String],
    with_attachments: bool,
    insecure: bool,
    output: OutputMode,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;
    let mut entries = vault.entries;
    if with_attachments {
        entries.retain(|entry| entry.attachment_metadata.has_attachments());
    }

    if output_is_structured(output) {
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        return write_serialized_pretty(
            &entries,
            output,
            "failed to write entries to stdout",
        );
    }

    let mut fields: Vec<ListField> = fields
        .iter()
        .map(std::convert::TryFrom::try_from)
        .collect::<anyhow::Result<_>>()?;
    if insecure && !fields.contains(&ListField::Password) {
        let insert_pos = fields
            .iter()
            .position(|f| matches!(f, ListField::User))
            .map_or(fields.len(), |i| i + 1);
        fields.insert(insert_pos, ListField::Password);
    }

    let mut entries: Vec<DecryptedListCipher> = entries
        .iter()
        .map(decrypted_cipher_to_search)
        .map(std::convert::Into::into)
        .collect();
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, output, "")?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn list(
    fields: &[String],
    with_attachments: bool,
    insecure: bool,
    collection: Option<&str>,
    org: Option<&str>,
    output: OutputMode,
    all: bool,
    archived_filter: ArchivedFilter,
    trash_filter: TrashFilter,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return list_from_file(
            path,
            fields,
            with_attachments,
            insecure,
            output,
            from_file_passphrase,
        );
    }

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::List, true)?;
    let tag_account = target_accounts.len() > 1;

    // Structured output (`--json`/`--yaml`) always emits the *full* decrypted
    // entry — same shape as `rbw get --json`: password, custom fields with
    // values, notes, totp, uris, etc. This lets consumers retrieve everything
    // in a single call instead of following up with `rbw get`.
    if output_is_structured(output) {
        let mut entries: Vec<DecryptedCipher> = Vec::new();
        for account in &target_accounts {
            crate::actions::set_active_account(Some(account.clone()))?;
            let db = load_db()?;
            // Same as `find_entry_multi`'s `--all` loop: a `--collection`/
            // `--org` needle that doesn't resolve in this particular
            // account just means it contributes nothing.
            let Ok((collection_id, org_id)) =
                resolve_entry_scope(&db, collection, org)
            else {
                continue;
            };
            let mut account_entries: Vec<DecryptedCipher> = db
                .entries
                .iter()
                .filter(|entry| {
                    entry_in_collection_org_scope(
                        entry,
                        collection_id.as_deref(),
                        org_id.as_deref(),
                    )
                })
                .map(decrypt_cipher)
                .collect::<anyhow::Result<_>>()?;
            if tag_account {
                for entry in &mut account_entries {
                    entry.account = Some(account.clone());
                }
            }
            entries.extend(account_entries);
        }
        if with_attachments {
            entries
                .retain(|entry| entry.attachment_metadata.has_attachments());
        }
        entries.retain(|entry| archived_filter.matches(entry.archived));
        entries.retain(|entry| trash_filter.matches(entry.deleted));
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        return write_serialized_pretty(
            &entries,
            output,
            "failed to write entries to stdout",
        );
    }

    let mut fields: Vec<ListField> = fields
        .iter()
        .map(std::convert::TryFrom::try_from)
        .collect::<anyhow::Result<_>>()?;
    if insecure && !fields.contains(&ListField::Password) {
        // Insert password after user (or at position 2 if user column present)
        let insert_pos = fields
            .iter()
            .position(|f| matches!(f, ListField::User))
            .map_or(fields.len(), |i| i + 1);
        fields.insert(insert_pos, ListField::Password);
    }

    let mut entries: Vec<DecryptedListCipher> = Vec::new();
    for account in &target_accounts {
        crate::actions::set_active_account(Some(account.clone()))?;
        let db = load_db()?;
        let Ok((collection_id, org_id)) =
            resolve_entry_scope(&db, collection, org)
        else {
            continue;
        };

        // Gather every cipherstring that needs decrypting across all entries,
        // then decrypt them in a single batch request to the agent. This
        // avoids a separate socket round-trip per field per entry, which
        // dominates the runtime of `list` on large vaults.
        let mut requests = BatchRequests::new();
        let plans: Vec<ListCipherPlan> = db
            .entries
            .iter()
            .filter(|entry| {
                entry_in_collection_org_scope(
                    entry,
                    collection_id.as_deref(),
                    org_id.as_deref(),
                )
            })
            .map(|entry| ListCipherPlan::build(entry, &fields, &mut requests))
            .collect();

        let results = if requests.is_empty() {
            Vec::new()
        } else {
            crate::actions::decrypt_batch(requests.into_vec())?
        };

        let mut account_entries: Vec<DecryptedListCipher> = plans
            .into_iter()
            .map(|plan| plan.resolve(&results))
            .collect::<anyhow::Result<_>>()?;
        if tag_account {
            for entry in &mut account_entries {
                entry.account = Some(account.clone());
            }
        }
        entries.extend(account_entries);
    }
    if with_attachments {
        entries.retain(|entry| entry.attachment_metadata.has_attachments());
    }
    entries.retain(|entry| archived_filter.matches(entry.archived));
    entries.retain(|entry| trash_filter.matches(entry.deleted));
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, output, "")?;

    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
#[allow(clippy::too_many_arguments)]
// `get --from-file`: same needle matching/display shape as the
// live-account path below (`DecryptedCipher` carries the same display
// methods either way), against an already-decrypted in-memory vault
// instead of an unlocked agent/account.
fn get_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    field: Option<&str>,
    output: OutputMode,
    clipboard: bool,
    ignore_case: bool,
    list_fields: bool,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if list_fields {
        decrypted.display_fields_list();
    } else if output_is_structured(output) {
        decrypted.display_structured(&desc, output)?;
    } else if output == OutputMode::Name {
        println!("{}", decrypted.name);
    } else if let Some(field) = field {
        decrypted.display_field(&desc, field, clipboard);
    } else {
        decrypted.display_short(&desc, clipboard);
    }

    Ok(())
}

// Resolve a bare `rbw get NAME` against a configured item alias (see
// `rbw::config::ItemAlias`). Only fires when there's exactly one needle and
// none of --user/--folder/--collection/--org are already set -- any of
// those being present means the caller is doing an explicit search, not
// invoking a shortcut, so the alias is left alone. Returns the alias name
// alongside its config when `needles` matches one; `None` otherwise (no
// alias by that name, or the trigger conditions aren't met).
fn resolve_get_alias<'a>(
    config: &'a rbw::config::Config,
    needles: &[Needle],
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
) -> Option<(&'a str, &'a rbw::config::ItemAlias)> {
    let [Needle::Name(name)] = needles else {
        return None;
    };
    if user.is_some()
        || folder.is_some()
        || collection.is_some()
        || org.is_some()
    {
        return None;
    }
    let alias = config.find_alias(name)?;
    // `find_alias` only returns an entry whose `alias` list contains `name`,
    // so this is always present; borrowing it from `alias` (rather than
    // `name`, which only lives as long as `needles`) is what lets the
    // returned tuple satisfy the `'a` lifetime.
    let matched_name = alias
        .alias
        .iter()
        .find(|n| n.as_str() == name)
        .expect("find_alias guarantees a matching name")
        .as_str();
    Some((matched_name, alias))
}

#[allow(clippy::too_many_arguments)]
pub fn get(
    mut needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    field: Option<&str>,
    output: OutputMode,
    clipboard: bool,
    ignore_case: bool,
    list_fields: bool,
    verbose: bool,
    force_exact: bool,
    all: bool,
    no_alias: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return get_from_file(
            path,
            &needles,
            user,
            folder,
            field,
            output,
            clipboard,
            ignore_case,
            list_fields,
            force_exact,
            from_file_passphrase,
        );
    }

    let mut collection = collection.map(str::to_string);
    let mut org = org.map(str::to_string);
    let mut field = field.map(str::to_string);

    if !no_alias {
        let config = rbw::config::Config::load()?;
        if let Some((alias_name, alias)) = resolve_get_alias(
            &config,
            &needles,
            user,
            folder,
            collection.as_deref(),
            org.as_deref(),
        ) {
            let account = crate::actions::current_account()
                .unwrap_or_else(|| alias.account_name(&config));
            if verbose {
                let c = std::io::stderr().is_terminal()
                    && std::env::var_os("NO_COLOR").is_none();
                let field_suffix = alias
                    .field
                    .as_deref()
                    .map(|f| format!(", field '{f}'"))
                    .unwrap_or_default();
                eprintln!(
                    "{}",
                    style::dim(
                        &format!(
                            "Resolved alias '{alias_name}' -> account \
                            '{account}', item '{}'{field_suffix}",
                            alias.item,
                        ),
                        c,
                    )
                );
            }
            if crate::actions::current_account().is_none() {
                crate::actions::set_account(Some(account));
            }
            needles = vec![parse_needle(&alias.item).unwrap()];
            collection = alias.collection.clone();
            org = alias.org.clone();
            if field.is_none() {
                field.clone_from(&alias.field);
            }
        }
    }

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Get, true)?;
    let tag_account = target_accounts.len() > 1;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (account, _, decrypted) = find_entry_multi(
        &target_accounts,
        needles,
        user,
        folder,
        collection.as_deref(),
        org.as_deref(),
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if verbose {
        let c = std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        // Note which field the value is coming from — useful now that a plain
        // `get` may fall back to a passphrase field, notes, etc.
        let source = if list_fields || output_is_structured(output) {
            None
        } else if let Some(field) = &field {
            Some(format!("field '{field}'"))
        } else {
            decrypted.default_secret().map(|(_, src)| src.label())
        };
        let account_suffix = if tag_account {
            format!(" [{account}]")
        } else {
            String::new()
        };
        let suffix = source
            .map(|s| format!(" {}", style::dim(&format!("({s})"), c)))
            .unwrap_or_default();
        eprintln!(
            "Matched item: {}{account_suffix}{suffix}",
            style::name(&decrypted.name, c),
        );
    }

    if list_fields {
        decrypted.display_fields_list();
    } else if output_is_structured(output) {
        decrypted.display_structured(&desc, output)?;
    } else if output == OutputMode::Name {
        println!("{}", decrypted.name);
    } else if let Some(field) = &field {
        decrypted.display_field(&desc, field, clipboard);
    } else {
        decrypted.display_short(&desc, clipboard);
    }

    Ok(())
}

// `show --from-file`: mirrors `get_from_file` but always uses
// `display_show`/`display_structured` (no field/clipboard support, matching
// the live-account `show` command's own limited output shape).
fn show_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if output_is_structured(output) {
        decrypted.display_structured(&desc, output)?;
    } else if output == OutputMode::Name {
        println!("{}", decrypted.name);
    } else {
        decrypted.display_show();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn show(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
    force_exact: bool,
    all: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return show_from_file(
            path,
            &needles,
            user,
            folder,
            ignore_case,
            output,
            force_exact,
            from_file_passphrase,
        );
    }

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Show, true)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );
    let (_, _, decrypted) = find_entry_multi(
        &target_accounts,
        needles,
        user,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    if output_is_structured(output) {
        decrypted.display_structured(&desc, output)?;
    } else if output == OutputMode::Name {
        println!("{}", decrypted.name);
    } else {
        decrypted.display_show();
    }
    Ok(())
}

// `attachment list --from-file`: same output shape as the live-account
// path, listing `decrypted.attachments` off an in-memory `DecryptedCipher`.
fn attachment_list_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if output_is_structured(output) {
        write_serialized_pretty(
            &decrypted.attachments,
            output,
            "failed to write attachments to stdout",
        )?;
    } else if output == OutputMode::Name {
        for attachment in &decrypted.attachments {
            println!(
                "{}",
                attachment
                    .file_name
                    .clone()
                    .unwrap_or_else(|| attachment.id.clone())
            );
        }
    } else {
        let rows = decrypted
            .attachments
            .iter()
            .map(|attachment| {
                vec![
                    attachment.id.clone(),
                    attachment.file_name.clone().unwrap_or_default(),
                    attachment
                        .size_name
                        .clone()
                        .or_else(|| attachment.size.clone())
                        .unwrap_or_default(),
                ]
            })
            .collect::<Vec<_>>();
        print_table(
            &[
                TableColumn {
                    header: "id",
                    style: TableColumnStyle::Id,
                },
                TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
                TableColumn {
                    header: "size",
                    style: TableColumnStyle::Size,
                },
            ],
            &rows,
            "",
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn attachment_list(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return attachment_list_from_file(
            path,
            &needles,
            user,
            folder,
            ignore_case,
            output,
            force_exact,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;
    let db = load_db()?;
    let (_, decrypted) = find_entry(
        &db,
        needles,
        user,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )?;

    if output_is_structured(output) {
        write_serialized_pretty(
            &decrypted.attachments,
            output,
            "failed to write attachments to stdout",
        )?;
    } else if output == OutputMode::Name {
        for attachment in &decrypted.attachments {
            println!(
                "{}",
                attachment
                    .file_name
                    .clone()
                    .unwrap_or_else(|| attachment.id.clone())
            );
        }
    } else {
        let rows = decrypted
            .attachments
            .iter()
            .map(|attachment| {
                vec![
                    attachment.id.clone(),
                    attachment.file_name.clone().unwrap_or_default(),
                    attachment
                        .size_name
                        .clone()
                        .or_else(|| attachment.size.clone())
                        .unwrap_or_default(),
                ]
            })
            .collect::<Vec<_>>();
        print_table(
            &[
                TableColumn {
                    header: "id",
                    style: TableColumnStyle::Id,
                },
                TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
                TableColumn {
                    header: "size",
                    style: TableColumnStyle::Size,
                },
            ],
            &rows,
            "",
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
// `attachment get --from-file`: reads the attachment bytes directly from
// `vault.attachment_data` (populated by `rbw export --attachments`/`add
// --attachment`, keyed by attachment id) instead of downloading and
// decrypting them over the network.
fn attachment_get_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
    output: Option<&std::path::Path>,
    raw: bool,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    let decrypted_attachment =
        resolve_attachment_in_file(&decrypted, attachment)?;

    let data = vault
        .attachment_data
        .get(&decrypted_attachment.id)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "attachment data for '{}' is not present in {}",
                decrypted_attachment.id,
                path.display()
            )
        })?;

    let output_to_stdout = raw
        || output.is_some_and(|output| output == std::path::Path::new("-"));

    if output_to_stdout {
        std::io::stdout()
            .write_all(&data)
            .context("failed to write attachment to stdout")?;
        return Ok(());
    }

    let file_name = decrypted_attachment
        .file_name
        .as_deref()
        .and_then(|name| std::path::Path::new(name).file_name())
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("BitwardenAttachment");
    let out_path = output.map_or_else(
        || std::path::PathBuf::from(file_name),
        |output| {
            if output.is_dir() {
                output.join(file_name)
            } else {
                output.to_path_buf()
            }
        },
    );
    std::fs::write(&out_path, data)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    println!("{}", out_path.display());

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn attachment_get(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
    output: Option<&std::path::Path>,
    raw: bool,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return attachment_get_from_file(
            path,
            &needles,
            user,
            folder,
            ignore_case,
            attachment,
            output,
            raw,
            force_exact,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;
    let mut db = load_db()?;
    let (entry, decrypted) = find_entry(
        &db,
        needles,
        user,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )?;
    let (attachment, decrypted_attachment) =
        resolve_attachment(&entry, &decrypted, attachment)?;

    let access_token = db
        .access_token
        .as_ref()
        .context("failed to find access token in db")?
        .clone();
    let refresh_token = db
        .refresh_token
        .as_ref()
        .context("failed to find refresh token in db")?
        .clone();
    let url = match rbw::actions::attachment_url(
        &access_token,
        &refresh_token,
        &entry.id,
        &attachment.id,
    ) {
        Ok((new_access_token, url)) => {
            if let Some(new_access_token) = new_access_token {
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }
            url
        }
        Err(e) => attachment.url.clone().ok_or(e)?,
    };
    let encrypted = rbw::actions::download_attachment(&url)
        .context("failed to download attachment")?;
    let decrypted = crate::actions::decrypt_attachment(
        encrypted,
        attachment.key.as_deref(),
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;

    let output_to_stdout = raw
        || output.is_some_and(|output| output == std::path::Path::new("-"));

    if output_to_stdout {
        std::io::stdout()
            .write_all(&decrypted)
            .context("failed to write attachment to stdout")?;
        return Ok(());
    }

    let file_name = decrypted_attachment
        .file_name
        .as_deref()
        .and_then(|name| std::path::Path::new(name).file_name())
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("BitwardenAttachment");
    let path = output.map_or_else(
        || std::path::PathBuf::from(file_name),
        |output| {
            if output.is_dir() {
                output.join(file_name)
            } else {
                output.to_path_buf()
            }
        },
    );
    std::fs::write(&path, decrypted)
        .with_context(|| format!("failed to write {}", path.display()))?;
    println!("{}", path.display());

    Ok(())
}

// `attachment create --from-file`: mirrors `set --attachment --from-file`'s
// attachment-adding logic (new random id, raw bytes into
// `vault.attachment_data`), but for the dedicated `attachment create`
// command instead of as a side effect of `set`.
fn attachment_create_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    file: &std::path::Path,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let mut vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let mut decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let filename = file
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?
        .to_string();
    let data = std::fs::read(file)
        .with_context(|| format!("failed to read {}", file.display()))?;

    let id = uuid::Uuid::new_v4().to_string();
    decrypted.attachments.push(DecryptedAttachment {
        id: id.clone(),
        file_name: Some(filename.clone()),
        size: None,
        size_name: None,
    });
    decrypted.attachment_metadata =
        AttachmentMetadata::new(&decrypted.id, decrypted.attachments.len());
    vault.attachment_data.insert(id, data);

    let entry_name = decrypted.name.clone();
    if let Some(pos) = vault.entries.iter().position(|e| e.id == decrypted.id)
    {
        vault.entries[pos] = decrypted;
    }

    backup_file(path)?;
    let exported = vault
        .entries
        .iter()
        .map(|e| {
            to_exported_entry(e, &vault.attachment_data, &vault.entry_extra)
        })
        .collect();
    save_to_file(
        path,
        exported,
        vault.collections,
        vault.passphrase.as_deref(),
    )?;

    let c = stdout_supports_color();
    eprintln!(
        "{} {} \u{2192} {}",
        style::success("Attached", c),
        style::name(&filename, c),
        style::name(&entry_name, c),
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn attachment_create(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    file: &std::path::Path,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return attachment_create_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            file,
            force_exact,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;
    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (entry, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        None,
        None,
        ignore_case,
        force_exact,
    )?;

    let filename = file
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?;

    let data = std::fs::read(file)
        .with_context(|| format!("failed to read {}", file.display()))?;

    let (encrypted_data, encrypted_key, encrypted_filename) =
        crate::actions::encrypt_attachment(
            data,
            filename,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?;

    if let (Some(new_token), ()) = rbw::actions::create_attachment(
        &access_token,
        &refresh_token,
        &entry.id,
        &encrypted_filename,
        &encrypted_key,
        &encrypted_data,
    )? {
        db.access_token = Some(new_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    let c = stdout_supports_color();
    eprintln!(
        "{} {} \u{2192} {}",
        style::success("Attached", c),
        style::name(filename, c),
        style::name(&decrypted.name, c),
    );

    Ok(())
}

// `attachment rm --from-file`: same resolution/confirmation shape as the
// live-account path, then drops the attachment (and its raw bytes) from
// the in-memory vault and writes back.
#[allow(clippy::too_many_arguments)]
fn attachment_rm_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
    force_exact: bool,
    yes: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let mut vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let mut decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    let decrypted_attachment =
        resolve_attachment_in_file(&decrypted, attachment)?;

    let attachment_id = decrypted_attachment.id.clone();
    let file_name = decrypted_attachment
        .file_name
        .clone()
        .unwrap_or_else(|| attachment_id.clone());

    if !yes {
        let c = stdout_supports_color();
        if !confirm(&format!(
            "Delete attachment {} from {}?",
            style::name(&file_name, c),
            style::name(&decrypted.name, c)
        ))? {
            return Ok(());
        }
    }

    decrypted.attachments.retain(|a| a.id != attachment_id);
    decrypted.attachment_metadata =
        AttachmentMetadata::new(&decrypted.id, decrypted.attachments.len());
    vault.attachment_data.remove(&attachment_id);

    let entry_name = decrypted.name.clone();
    if let Some(pos) = vault.entries.iter().position(|e| e.id == decrypted.id)
    {
        vault.entries[pos] = decrypted;
    }

    backup_file(path)?;
    let exported = vault
        .entries
        .iter()
        .map(|e| {
            to_exported_entry(e, &vault.attachment_data, &vault.entry_extra)
        })
        .collect();
    save_to_file(
        path,
        exported,
        vault.collections,
        vault.passphrase.as_deref(),
    )?;

    let c = stdout_supports_color();
    eprintln!(
        "{} {} from {}",
        style::success("Deleted", c),
        style::name(&file_name, c),
        style::name(&entry_name, c),
    );

    Ok(())
}

// Delete an attachment from an entry and sync. Shares the entry/attachment
// resolution behavior of `attachment_get`, including the only-attachment
// fallback when --attachment is omitted.
#[allow(clippy::too_many_arguments)]
pub fn attachment_rm(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
    force_exact: bool,
    yes: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return attachment_rm_from_file(
            path,
            &needles,
            user,
            folder,
            ignore_case,
            attachment,
            force_exact,
            yes,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;
    let mut db = load_db()?;
    let (entry, decrypted) = find_entry(
        &db,
        needles,
        user,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )?;
    let (attachment, decrypted_attachment) =
        resolve_attachment(&entry, &decrypted, attachment)?;

    let access_token = db
        .access_token
        .as_ref()
        .context("failed to find access token in db")?
        .clone();
    let refresh_token = db
        .refresh_token
        .as_ref()
        .context("failed to find refresh token in db")?
        .clone();

    let attachment_id = attachment.id.clone();
    let file_name = decrypted_attachment
        .file_name
        .clone()
        .unwrap_or_else(|| attachment_id.clone());

    if !yes {
        let c = stdout_supports_color();
        if !confirm(&format!(
            "Delete attachment {} from {}?",
            style::name(&file_name, c),
            style::name(&decrypted.name, c)
        ))? {
            return Ok(());
        }
    }

    if let (Some(new_token), ()) = rbw::actions::delete_attachment(
        &access_token,
        &refresh_token,
        &entry.id,
        &attachment_id,
    )? {
        db.access_token = Some(new_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    let c = stdout_supports_color();
    eprintln!(
        "{} {} from {}",
        style::success("Deleted", c),
        style::name(&file_name, c),
        style::name(&decrypted.name, c),
    );

    Ok(())
}

fn print_entry_list(
    entries: &[DecryptedListCipher],
    fields: &[ListField],
    output: OutputMode,
    term: &str,
) -> anyhow::Result<()> {
    if output_is_structured(output) {
        write_serialized_pretty(
            &entries,
            output,
            "failed to write entries to stdout",
        )?;
    } else if output == OutputMode::Name {
        for entry in entries {
            println!("{}", entry.name.clone().unwrap_or_default());
        }
    } else {
        let mut columns = fields
            .iter()
            .map(|field| match field {
                ListField::Id => TableColumn {
                    header: "uid",
                    style: TableColumnStyle::Id,
                },
                ListField::Name => TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
                ListField::User => TableColumn {
                    header: "user",
                    style: TableColumnStyle::User,
                },
                ListField::Folder => TableColumn {
                    header: "folder",
                    style: TableColumnStyle::Folder,
                },
                ListField::Uri => TableColumn {
                    header: "uri",
                    style: TableColumnStyle::Default,
                },
                ListField::EntryType => TableColumn {
                    header: "type",
                    style: TableColumnStyle::EntryType,
                },
                ListField::Collections => TableColumn {
                    header: "collections",
                    style: TableColumnStyle::Collections,
                },
                ListField::Password => TableColumn {
                    header: "password",
                    style: TableColumnStyle::Password,
                },
            })
            .collect::<Vec<_>>();
        let show_account = entries.iter().any(|e| e.account.is_some());
        if show_account {
            columns.push(TableColumn {
                header: "account",
                style: TableColumnStyle::Account,
            });
        }
        let show_attachments = entries
            .iter()
            .any(|e| e.attachment_metadata.has_attachments());
        if show_attachments {
            columns.push(TableColumn {
                header: "attachments",
                style: TableColumnStyle::Attachments,
            });
        }

        let rows = entries
            .iter()
            .map(|entry| {
                let mut values = fields
                    .iter()
                    .map(|field| match field {
                        ListField::Id => entry.id.clone(),
                        ListField::Name => entry.name.as_ref().map_or_else(
                            String::new,
                            std::string::ToString::to_string,
                        ),
                        ListField::User => entry.user.as_ref().map_or_else(
                            || "N/A".to_string(),
                            std::string::ToString::to_string,
                        ),
                        ListField::Folder => {
                            entry.folder.as_ref().map_or_else(
                                String::new,
                                std::string::ToString::to_string,
                            )
                        }
                        ListField::Uri => unreachable!(),
                        ListField::EntryType => {
                            entry.entry_type.as_ref().map_or_else(
                                String::new,
                                std::string::ToString::to_string,
                            )
                        }
                        ListField::Collections => entry
                            .collection_ids
                            .as_ref()
                            .map_or_else(String::new, |ids| ids.join(",")),
                        ListField::Password => {
                            entry.password.as_ref().map_or_else(
                                String::new,
                                std::string::ToString::to_string,
                            )
                        }
                    })
                    .collect::<Vec<_>>();
                if show_account {
                    values.push(entry.account.clone().unwrap_or_default());
                }
                if show_attachments {
                    values.push(attachments_cell(
                        entry.attachment_metadata.attachment_count,
                    ));
                }
                values
            })
            .collect::<Vec<_>>();

        print_table(&columns, &rows, term)?;
    }

    Ok(())
}

// `search --from-file`: same matching/output shape as the live-account
// path below, just sourced from an already-decrypted in-memory vault.
fn search_from_file(
    path: &std::path::Path,
    term: &str,
    fields: &[String],
    folder: Option<&str>,
    with_attachments: bool,
    insecure: bool,
    output: OutputMode,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;
    let scope_target = FileSaveTarget {
        path: path.to_path_buf(),
        passphrase: vault.passphrase.clone(),
        collections: vault.collections.clone(),
        entry_extra: vault.entry_extra.clone(),
    };

    if output_is_structured(output) {
        let mut entries: Vec<DecryptedCipher> = vault
            .entries
            .into_iter()
            .filter(|entry| {
                let scope = tui_file_entry_scope(&scope_target, &entry.id);
                decrypted_cipher_to_search(entry).search_match_with_scope(
                    term,
                    folder,
                    with_attachments,
                    Some(&scope),
                )
            })
            .collect();
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        if entries.is_empty() {
            let c = std::io::stderr().is_terminal()
                && std::env::var_os("NO_COLOR").is_none();
            let msg = format!("no entries found matching '{term}'");
            eprintln!("{}", style::warning(&msg, c));
            std::process::exit(1);
        }
        return write_serialized_pretty(
            &entries,
            output,
            "failed to write entries to stdout",
        );
    }

    let mut fields: Vec<ListField> = fields
        .iter()
        .map(std::convert::TryFrom::try_from)
        .collect::<anyhow::Result<_>>()?;
    if insecure && !fields.contains(&ListField::Password) {
        let insert_pos = fields
            .iter()
            .position(|f| matches!(f, ListField::User))
            .map_or(fields.len(), |i| i + 1);
        fields.insert(insert_pos, ListField::Password);
    }

    let mut entries: Vec<DecryptedListCipher> = vault
        .entries
        .iter()
        .filter_map(|entry| {
            let scope = tui_file_entry_scope(&scope_target, &entry.id);
            let searchable = decrypted_cipher_to_search(entry);
            searchable
                .search_match_with_scope(
                    term,
                    folder,
                    with_attachments,
                    Some(&scope),
                )
                .then_some(searchable)
        })
        .map(std::convert::Into::into)
        .collect();
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    if entries.is_empty() {
        let c = std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        let msg = format!("no entries found matching '{term}'");
        eprintln!("{}", style::warning(&msg, c));
        std::process::exit(1);
    }

    print_entry_list(&entries, &fields, output, term)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn search(
    term: &str,
    fields: &[String],
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    with_attachments: bool,
    insecure: bool,
    output: OutputMode,
    all: bool,
    archived_filter: ArchivedFilter,
    trash_filter: TrashFilter,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return search_from_file(
            path,
            term,
            fields,
            folder,
            with_attachments,
            insecure,
            output,
            from_file_passphrase,
        );
    }

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Search, true)?;
    let tag_account = target_accounts.len() > 1;

    // Structured output (`--json`/`--yaml`) emits the *full* decrypted entry
    // (same shape as `rbw get --json`) for every match, so consumers get
    // everything in one call. Matching still uses the lightweight searchable
    // view; only the matching entries are fully decrypted.
    if output_is_structured(output) {
        let mut entries: Vec<DecryptedCipher> = Vec::new();
        for account in &target_accounts {
            crate::actions::set_active_account(Some(account.clone()))?;
            let db = load_db()?;
            // Same as `find_entry_multi`'s `--all` loop: a `--collection`/
            // `--org` needle that doesn't resolve in this particular
            // account just means it contributes nothing.
            let Ok((collection_id, org_id)) =
                resolve_entry_scope(&db, collection, org)
            else {
                continue;
            };
            let mut account_entries: Vec<DecryptedCipher> = db
                .entries
                .iter()
                .filter(|entry| {
                    entry_in_collection_org_scope(
                        entry,
                        collection_id.as_deref(),
                        org_id.as_deref(),
                    )
                })
                .filter_map(|entry| match decrypt_search_cipher(entry) {
                    Ok(searchable) => {
                        let scope = tui_entry_scope(&db, entry);
                        (searchable.search_match_with_scope(
                            term,
                            folder,
                            with_attachments,
                            Some(&scope),
                        ) && archived_filter.matches(searchable.archived)
                            && trash_filter.matches(searchable.deleted))
                        .then(|| decrypt_cipher(entry).ok())
                        .flatten()
                    }
                    Err(_) => None,
                })
                .collect();
            if tag_account {
                for entry in &mut account_entries {
                    entry.account = Some(account.clone());
                }
            }
            entries.extend(account_entries);
        }
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        if entries.is_empty() {
            let c = std::io::stderr().is_terminal()
                && std::env::var_os("NO_COLOR").is_none();
            let msg = format!("no entries found matching '{term}'");
            eprintln!("{}", style::warning(&msg, c));
            std::process::exit(1);
        }
        return write_serialized_pretty(
            &entries,
            output,
            "failed to write entries to stdout",
        );
    }

    let mut fields: Vec<ListField> = fields
        .iter()
        .map(std::convert::TryFrom::try_from)
        .collect::<anyhow::Result<_>>()?;
    if insecure && !fields.contains(&ListField::Password) {
        let insert_pos = fields
            .iter()
            .position(|f| matches!(f, ListField::User))
            .map_or(fields.len(), |i| i + 1);
        fields.insert(insert_pos, ListField::Password);
    }

    let mut entries: Vec<DecryptedListCipher> = Vec::new();
    for account in &target_accounts {
        crate::actions::set_active_account(Some(account.clone()))?;
        let db = load_db()?;
        let Ok((collection_id, org_id)) =
            resolve_entry_scope(&db, collection, org)
        else {
            continue;
        };

        // As in `list`, decrypt every entry's searchable fields in a single
        // batch request rather than one socket round-trip per field per
        // entry.
        let mut requests = BatchRequests::new();
        let plans: Vec<(TuiEntryScope, SearchCipherPlan)> = db
            .entries
            .iter()
            .filter(|entry| {
                entry_in_collection_org_scope(
                    entry,
                    collection_id.as_deref(),
                    org_id.as_deref(),
                )
            })
            .map(|entry| {
                (
                    tui_entry_scope(&db, entry),
                    SearchCipherPlan::build(entry, &mut requests),
                )
            })
            .collect();

        let results = if requests.is_empty() {
            Vec::new()
        } else {
            crate::actions::decrypt_batch(requests.into_vec())?
        };

        let mut account_entries: Vec<DecryptedListCipher> = plans
            .into_iter()
            .map(|(scope, plan)| {
                plan.resolve(&results).map(|entry| {
                    let matches = entry.search_match_with_scope(
                        term,
                        folder,
                        with_attachments,
                        Some(&scope),
                    ) && archived_filter
                        .matches(entry.archived)
                        && trash_filter.matches(entry.deleted);
                    (matches, entry)
                })
            })
            .filter_map(|entry| match entry {
                Ok((true, entry)) => Some(Ok(entry.into())),
                Ok((false, _)) => None,
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<_, anyhow::Error>>()?;
        if tag_account {
            for entry in &mut account_entries {
                entry.account = Some(account.clone());
            }
        }
        entries.extend(account_entries);
    }
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    if entries.is_empty() {
        let c = std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        let msg = format!("no entries found matching '{term}'");
        eprintln!("{}", style::warning(&msg, c));
        std::process::exit(1);
    }

    print_entry_list(&entries, &fields, output, term)?;

    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
// `code --from-file`: same TOTP-generation logic as the live-account path,
// against a `DecryptedCipher` found in-memory instead of via an unlocked
// account.
fn code_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    clipboard: bool,
    ignore_case: bool,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let DecryptedData::Login { totp, .. } = decrypted.data {
        if let Some(totp) = totp {
            val_display_or_store(clipboard, &generate_totp(&totp)?);
        } else {
            return Err(anyhow::anyhow!(
                "entry does not contain a totp secret"
            ));
        }
    } else {
        return Err(anyhow::anyhow!("not a login entry"));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn code(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    clipboard: bool,
    ignore_case: bool,
    force_exact: bool,
    all: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return code_from_file(
            path,
            &needles,
            user,
            folder,
            clipboard,
            ignore_case,
            force_exact,
            from_file_passphrase,
        );
    }

    let target_accounts =
        list_target_accounts(all, rbw::config::ExcludeContext::Code, true)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (_, _, decrypted) = find_entry_multi(
        &target_accounts,
        needles,
        user,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let DecryptedData::Login { totp, .. } = decrypted.data {
        if let Some(totp) = totp {
            val_display_or_store(clipboard, &generate_totp(&totp)?);
        } else {
            return Err(anyhow::anyhow!(
                "entry does not contain a totp secret"
            ));
        }
    } else {
        return Err(anyhow::anyhow!("not a login entry"));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn add(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    json: bool,
    _yaml: bool,
    generate: bool,
    gen_len: usize,
    gen_ty: rbw::pwgen::Type,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if generate && !std::io::stdin().is_terminal() {
        // The editor ignores its template entirely and reads the entry
        // straight from stdin when it isn't a tty (see `rbw::edit::edit`),
        // so a generated password would be silently discarded anyway --
        // treat the combination as a user error rather than a silent no-op.
        anyhow::bail!(
            "--generate cannot be combined with a piped entry; provide the \
             password via generation or stdin, not both"
        );
    }
    let generated = generate.then(|| rbw::pwgen::pwgen(gen_ty, gen_len));
    if let Some(path) = from_file {
        return add_from_file(
            path,
            name,
            username,
            uris,
            folder,
            json,
            generated.as_deref(),
            from_file_passphrase,
        );
    }
    add_structured(name, username, uris, folder, json, generated.as_deref())
}

// `add --from-file`'s counterpart to `add_structured`: same
// template/`$EDITOR`/reparse flow, but `editable_to_decrypted` into a
// fresh `DecryptedCipher` (a locally-generated id -- there's no server
// here to assign one) instead of encrypting and pushing to the server.
#[allow(clippy::too_many_arguments)]
fn add_from_file(
    path: &std::path::Path,
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    json: bool,
    generated_password: Option<&str>,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let mut vault = load_from_file(path, passphrase)?;

    let editable_uris: Vec<EditableUri> = if uris.is_empty() {
        vec![EditableUri {
            uri: String::new(),
            match_type: None,
        }]
    } else {
        uris.iter()
            .map(|(uri, mt)| EditableUri {
                uri: uri.clone(),
                match_type: mt.map(|m| uri_match_type_str(m).to_string()),
            })
            .collect()
    };

    let template = EditableCipher {
        name: name.unwrap_or("").to_string(),
        folder: folder.map(std::string::ToString::to_string),
        notes: None,
        data: EditableData::Login {
            username: Some(username.unwrap_or("").to_string()),
            password: Some(
                generated_password.unwrap_or_default().to_string(),
            ),
            uris: editable_uris,
            totp: None,
            fido2_credentials: Vec::new(),
        },
        fields: Vec::new(),
    };

    let serialized = if json {
        serde_json::to_string_pretty(&template)?
    } else {
        serde_yaml::to_string(&template)?
    };

    let (help, ext) = if json {
        (
            "# Fill in the JSON below. Lines starting with # are ignored.",
            "json",
        )
    } else {
        (
            "# Fill in the YAML below. Lines starting with # are ignored.",
            "yaml",
        )
    };

    let contents = rbw::edit::edit(&serialized, help, ext)?;
    let contents_trimmed = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });

    if generated_password.is_none()
        && contents_trimmed.trim() == serialized.trim()
    {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    let cipher: EditableCipher = if json {
        serde_json::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse JSON: {e}"))?
    } else {
        serde_yaml::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?
    };

    if cipher.name.is_empty() {
        return Err(anyhow::anyhow!("name cannot be empty"));
    }

    let (data, fields, notes) = editable_to_decrypted(&cipher);
    let id = uuid::Uuid::new_v4().to_string();
    vault.entries.push(DecryptedCipher {
        attachment_metadata: AttachmentMetadata::new(&id, 0),
        id,
        folder: cipher.folder.clone(),
        name: cipher.name.clone(),
        data,
        fields,
        notes,
        history: Vec::new(),
        attachments: Vec::new(),
        archived: false,
        deleted: false,
        account: None,
    });

    backup_file(path)?;
    let exported = vault
        .entries
        .iter()
        .map(|e| {
            to_exported_entry(e, &vault.attachment_data, &vault.entry_extra)
        })
        .collect();
    save_to_file(
        path,
        exported,
        vault.collections,
        vault.passphrase.as_deref(),
    )?;

    print_created(&cipher.name);
    Ok(())
}

pub fn generate(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let password = rbw::pwgen::pwgen(ty, len);
    println!("{password}");

    if let Some(name) = name {
        unlock(None, None)?;

        let mut db = load_db()?;
        // unwrap is safe here because the call to unlock above is guaranteed
        // to populate these or error
        let mut access_token = db.access_token.as_ref().unwrap().clone();
        let refresh_token = db.refresh_token.as_ref().unwrap();

        let name = crate::actions::encrypt(name, None, None)?;
        let username = username
            .map(|username| crate::actions::encrypt(username, None, None))
            .transpose()?;
        let password = crate::actions::encrypt(&password, None, None)?;
        let uris: Vec<_> = uris
            .iter()
            .map(|uri| {
                Ok(rbw::db::Uri {
                    uri: crate::actions::encrypt(&uri.0, None, None)?,
                    match_type: uri.1,
                })
            })
            .collect::<anyhow::Result<_>>()?;

        let mut folder_id = None;
        if let Some(folder_name) = folder {
            let (new_access_token, folders) =
                rbw::actions::list_folders(&access_token, refresh_token)?;
            if let Some(new_access_token) = new_access_token {
                access_token.clone_from(&new_access_token);
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }

            let folders: Vec<(String, String)> = folders
                .iter()
                .cloned()
                .map(|(id, name)| {
                    Ok((id, crate::actions::decrypt(&name, None, None)?))
                })
                .collect::<anyhow::Result<_>>()?;

            for (id, name) in folders {
                if name == folder_name {
                    folder_id = Some(id);
                }
            }
            if folder_id.is_none() {
                let (new_access_token, id) = rbw::actions::create_folder(
                    &access_token,
                    refresh_token,
                    &crate::actions::encrypt(folder_name, None, None)?,
                )?;
                if let Some(new_access_token) = new_access_token {
                    access_token.clone_from(&new_access_token);
                    db.access_token = Some(new_access_token);
                    save_db(&db)?;
                }
                folder_id = Some(id);
            }
        }

        if let (Some(access_token), _) = rbw::actions::add(
            &access_token,
            refresh_token,
            &name,
            &rbw::db::EntryData::Login {
                username,
                password: Some(password),
                uris,
                totp: None,
                fido2_credentials: Vec::new(),
            },
            &[],
            None,
            folder_id.as_deref(),
        )? {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }

        crate::actions::sync()?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn edit(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    json: bool,
    _yaml: bool,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return edit_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            json,
            force_exact,
            from_file_passphrase,
        );
    }
    edit_structured(
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        json,
        force_exact,
    )
}

// `edit --from-file`'s counterpart to `edit_structured`: same
// `decrypted_to_editable` → `$EDITOR` → reparse flow (including no-op
// detection on an untouched buffer and password-history tracking), but
// `editable_to_decrypted` (plain data, no crypto) instead of
// `editable_to_encrypted`, and saved back to `path` instead of pushed to
// the server.
fn edit_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    json: bool,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let mut vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let editable = decrypted_to_editable(&decrypted);

    let serialized = if json {
        serde_json::to_string_pretty(&editable)?
    } else {
        serde_yaml::to_string(&editable)?
    };

    let (help, ext) = if json {
        (
            "# Edit the JSON below. Lines starting with # are ignored.",
            "json",
        )
    } else {
        (
            "# Edit the YAML below. Lines starting with # are ignored.",
            "yaml",
        )
    };

    let contents = rbw::edit::edit(&serialized, help, ext)?;
    let contents_trimmed = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });

    if contents_trimmed.trim() == serialized.trim() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    let updated: EditableCipher = if json {
        serde_json::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse JSON: {e}"))?
    } else {
        serde_yaml::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?
    };

    let (data, fields, notes) = editable_to_decrypted(&updated);

    let mut new_entry = decrypted.clone();
    new_entry.name = updated.name;
    new_entry.folder = updated.folder;
    new_entry.data = data;
    new_entry.fields = fields;
    new_entry.notes = notes;

    if let (
        DecryptedData::Login {
            password: Some(old_pw),
            ..
        },
        DecryptedData::Login {
            password: new_pw, ..
        },
    ) = (&decrypted.data, &new_entry.data)
    {
        if Some(old_pw) != new_pw.as_ref() {
            new_entry.history.insert(
                0,
                DecryptedHistoryEntry {
                    last_used_date: format!(
                        "{}",
                        humantime::format_rfc3339(
                            std::time::SystemTime::now()
                        )
                    ),
                    password: old_pw.clone(),
                },
            );
        }
    }

    if let Some(pos) = vault.entries.iter().position(|e| e.id == decrypted.id)
    {
        vault.entries[pos] = new_entry;
    }

    backup_file(path)?;
    let exported = vault
        .entries
        .iter()
        .map(|e| {
            to_exported_entry(e, &vault.attachment_data, &vault.entry_extra)
        })
        .collect();
    save_to_file(
        path,
        exported,
        vault.collections,
        vault.passphrase.as_deref(),
    )
}

// `remove --from-file`: same needle matching and confirmation prompt as
// the live-account path, but drops the entry from an in-memory vault and
// saves it back to `path` instead of calling `rbw::actions::remove`.
fn remove_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    yes: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let mut vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if !yes
        && !confirm(&format!(
            "Delete entry {}?",
            style::name(&decrypted.name, stdout_supports_color())
        ))?
    {
        return Ok(());
    }

    vault.entries.retain(|e| e.id != decrypted.id);

    backup_file(path)?;
    let exported = vault
        .entries
        .iter()
        .map(|e| {
            to_exported_entry(e, &vault.attachment_data, &vault.entry_extra)
        })
        .collect();
    save_to_file(
        path,
        exported,
        vault.collections,
        vault.passphrase.as_deref(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn remove(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    force: bool,
    yes: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return remove_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            force_exact,
            yes,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;

    let mut db = load_db()?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    // Plain `remove` only ever targets a live (non-trashed) entry -- moving
    // it to trash. `--force` additionally falls back to a trashed entry (to
    // permanently purge something already there) if no live match exists.
    let (entry, decrypted) = if force {
        find_entry(
            &db,
            needles.clone(),
            username,
            folder,
            collection,
            org,
            ignore_case,
            force_exact,
        )
        .or_else(|_| {
            find_deleted_entry(
                &db,
                &needles,
                username,
                folder,
                collection,
                org,
                ignore_case,
                force_exact,
            )
        })
        .with_context(|| format!("couldn't find entry for '{desc}'"))?
    } else {
        find_entry(
            &db,
            needles,
            username,
            folder,
            collection,
            org,
            ignore_case,
            force_exact,
        )
        .with_context(|| format!("couldn't find entry for '{desc}'"))?
    };

    let prompt = if force {
        format!(
            "Permanently delete entry {}? This cannot be undone!",
            style::name(&decrypted.name, stdout_supports_color())
        )
    } else {
        format!(
            "Delete entry {}?",
            style::name(&decrypted.name, stdout_supports_color())
        )
    };
    if !yes && !confirm(&prompt)? {
        return Ok(());
    }

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let rotated = if force {
        rbw::actions::delete_permanently(
            access_token,
            refresh_token,
            &entry.id,
        )?
    } else {
        rbw::actions::remove(access_token, refresh_token, &entry.id)?
    };
    if let (Some(access_token), ()) = rotated {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

// Permanently, irrecoverably deletes every entry in the current account's
// personal vault via the server's single-call purge endpoint -- not a loop
// of individual deletes. Named distinctly from the existing `rbw purge`
// (which only clears the *local* db.json cache). Org-owned entries
// (assigned to a collection) aren't touched; purging those needs org
// owner/admin privileges and isn't what this is for (resetting a personal
// test account between imports).
pub fn purge_vault(
    yes: bool,
    password: Option<String>,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let c = stdout_supports_color();
    let prompt = format!(
        "{} this will permanently delete EVERY entry in this account's \
         personal vault. This cannot be undone! Continue?",
        style_error("DANGER:", c),
    );
    if !yes && !confirm(&prompt)? {
        return Ok(());
    }

    crate::actions::purge_vault(password)?;

    eprintln!("{}", style::success("Vault purged.", c));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn archive(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return archive_or_unarchive_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            force_exact,
            bulk,
            yes,
            true,
            from_file_passphrase,
        );
    }
    archive_or_unarchive(
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
        bulk,
        yes,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn unarchive(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return archive_or_unarchive_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            force_exact,
            bulk,
            yes,
            false,
            from_file_passphrase,
        );
    }
    archive_or_unarchive(
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
        bulk,
        yes,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn archive_or_unarchive_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    archive: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    let mut vault = load_from_file(path, passphrase)?;
    let verb = if archive { "archive" } else { "unarchive" };
    let mut ids = Vec::new();
    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if bulk {
        for needle in needles {
            let matches = find_entries_all_in_file(
                &vault.entries,
                needle,
                username,
                folder,
                ignore_case,
            );
            if matches.is_empty() {
                eprintln!("{needle}: no entry found");
                continue;
            }
            for entry in matches {
                if entry.archived == archive || !seen.insert(entry.id.clone())
                {
                    continue;
                }
                ids.push(entry.id);
                names.push(entry.name);
            }
        }
    } else {
        let needle_str = needles
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let desc = format!(
            "{}{}",
            username.map_or_else(String::new, |s| format!("{s}@")),
            needle_str
        );
        let entry = find_entry_in_file(
            &vault.entries,
            needles,
            username,
            folder,
            ignore_case,
            force_exact,
        )
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
        if entry.archived == archive {
            println!(
                "{} is already {}",
                style::name(&entry.name, stdout_supports_color()),
                if archive { "archived" } else { "unarchived" }
            );
            return Ok(());
        }
        ids.push(entry.id);
        names.push(entry.name);
    }

    if ids.is_empty() {
        anyhow::bail!("no entries to {verb}");
    }

    if bulk && !yes {
        let c = stdout_supports_color();
        eprintln!(
            "About to {verb} {} {}:",
            style::name(&ids.len().to_string(), c),
            if ids.len() == 1 { "entry" } else { "entries" }
        );
        for name in &names {
            eprintln!("  {}", style::name(name, c));
        }
        eprintln!();
        eprint!("Apply to all ({})? [y/N] ", ids.len());
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("failed to read confirmation")?;
        if !matches!(answer.trim(), "y" | "Y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    for entry in &mut vault.entries {
        if ids.iter().any(|id| id == &entry.id) {
            entry.archived = archive;
        }
    }
    save_loaded_file_vault(path, &vault)?;

    let c = stdout_supports_color();
    for name in names {
        println!("Item {} was {verb}d", style::name(&name, c));
    }
    Ok(())
}

fn save_loaded_file_vault(
    path: &std::path::Path,
    vault: &FileVault,
) -> anyhow::Result<()> {
    backup_file(path)?;
    let entries = vault
        .entries
        .iter()
        .map(|entry| {
            to_exported_entry(
                entry,
                &vault.attachment_data,
                &vault.entry_extra,
            )
        })
        .collect();
    save_to_file(
        path,
        entries,
        vault.collections.clone(),
        vault.passphrase.as_deref(),
    )
}

// Shared implementation for `rbw archive`/`rbw unarchive`: unlike `remove`,
// this is fully reversible, so neither path confirms by default -- only the
// bulk path prints a preview and confirms (unless `-y`), same as `set
// --bulk`, since it can silently touch many entries at once.
#[allow(clippy::too_many_arguments)]
fn archive_or_unarchive(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    archive: bool,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    let verb = if archive { "archive" } else { "unarchive" };

    if bulk {
        unlock(None, None)?;
        let mut db = load_db()?;
        let mut any_err = false;

        let mut pending: Vec<(rbw::db::Entry, String)> = Vec::new();
        let c = stdout_supports_color();

        for needle in &needles {
            match find_entries_all(
                &db,
                needle,
                username,
                folder,
                collection,
                org,
                ignore_case,
            ) {
                Err(e) => {
                    eprintln!("{needle}: {e:#}");
                    any_err = true;
                }
                Ok(entries) => {
                    for (entry, decrypted) in entries {
                        if entry.archived == archive {
                            eprintln!(
                                "{} {}",
                                style::name(&decrypted.name, c),
                                style::dim(
                                    if archive {
                                        "(already archived)"
                                    } else {
                                        "(not archived)"
                                    },
                                    c
                                )
                            );
                            continue;
                        }
                        pending.push((entry, decrypted.name.clone()));
                    }
                }
            }
        }

        if pending.is_empty() {
            return if any_err {
                Err(anyhow::anyhow!("one or more entries failed to resolve"))
            } else {
                Ok(())
            };
        }

        if !yes {
            eprintln!(
                "About to {verb} {} {}:",
                style::name(&format!("{}", pending.len()), c),
                if pending.len() == 1 {
                    "entry"
                } else {
                    "entries"
                }
            );
            for (_, name) in &pending {
                eprintln!("  {}", style::name(name, c));
            }
            eprintln!();
            eprint!("Apply to all ({})? [y/N] ", pending.len());
            let _ = std::io::stderr().flush();
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .context("failed to read confirmation")?;
            if !matches!(answer.trim(), "y" | "Y") {
                eprintln!("Aborted.");
                return Ok(());
            }
        }

        let access_token = db.access_token.as_ref().unwrap();
        let refresh_token = db.refresh_token.as_ref().unwrap();
        let ids: Vec<String> =
            pending.iter().map(|(entry, _)| entry.id.clone()).collect();

        let rotated = if archive {
            rbw::actions::archive_multiple(access_token, refresh_token, &ids)?
        } else {
            rbw::actions::unarchive_multiple(
                access_token,
                refresh_token,
                &ids,
            )?
        };
        if let (Some(access_token), ()) = rotated {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }

        crate::actions::sync()?;

        for (_, name) in &pending {
            println!("Item {} was {verb}d", style::name(name, c));
        }

        return if any_err {
            Err(anyhow::anyhow!("one or more entries failed to resolve"))
        } else {
            Ok(())
        };
    }

    unlock(None, None)?;

    let mut db = load_db()?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (entry, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let c = stdout_supports_color();
    if entry.archived == archive {
        println!(
            "{} {}",
            style::name(&decrypted.name, c),
            if archive {
                "is already archived"
            } else {
                "is not archived"
            }
        );
        return Ok(());
    }

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let rotated = if archive {
        rbw::actions::archive(access_token, refresh_token, &entry.id)?
    } else {
        rbw::actions::unarchive(access_token, refresh_token, &entry.id)?
    };
    if let (Some(access_token), ()) = rotated {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    println!("Item {} was {verb}d", style::name(&decrypted.name, c));

    Ok(())
}

// `find_entry`'s counterpart for `rbw restore`: only matches entries that
// *are* trashed (the exact opposite of `find_entry`'s exclusion, kept as a
// separate function rather than a shared parameter so the exclusion in
// `find_entry`/`find_entry_multi` can stay an unconditional invariant
// everywhere else).
fn find_deleted_entry(
    db: &rbw::db::Db,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    let (collection_id, org_id) = resolve_entry_scope(db, collection, org)?;
    let mut requests = BatchRequests::new();
    let plans: Vec<SearchCipherPlan> = db
        .entries
        .iter()
        .map(|entry| SearchCipherPlan::build(entry, &mut requests))
        .collect();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };
    let mut ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .zip(plans)
        .map(|(entry, plan)| {
            plan.resolve(&results)
                .map(|decrypted| (entry.clone(), decrypted))
        })
        .collect::<anyhow::Result<_>>()?;
    ciphers.retain(|(entry, _)| entry.deleted);
    ciphers.retain(|(entry, _)| {
        entry_in_collection_org_scope(
            entry,
            collection_id.as_deref(),
            org_id.as_deref(),
        )
    });
    let (entry, _) = find_entry_raw(
        &ciphers,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )?;
    let decrypted_entry = decrypt_cipher(&entry)?;
    Ok((entry, decrypted_entry))
}

// `find_entries_all`'s counterpart for `rbw restore --bulk`: same idea as
// `find_deleted_entry` above, but for the bulk path.
fn find_deleted_entries_all(
    db: &rbw::db::Db,
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<Vec<(rbw::db::Entry, DecryptedCipher)>> {
    let (collection_id, org_id) = resolve_entry_scope(db, collection, org)?;
    let mut requests = BatchRequests::new();
    let plans: Vec<SearchCipherPlan> = db
        .entries
        .iter()
        .map(|entry| SearchCipherPlan::build(entry, &mut requests))
        .collect();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };
    let ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .zip(plans)
        .map(|(entry, plan)| {
            plan.resolve(&results).map(|d| (entry.clone(), d))
        })
        .collect::<anyhow::Result<_>>()?;

    let matches: Vec<_> = ciphers
        .iter()
        .filter(|(entry, _)| entry.deleted)
        .filter(|(entry, _)| {
            entry_in_collection_org_scope(
                entry,
                collection_id.as_deref(),
                org_id.as_deref(),
            )
        })
        .filter(|(_, d)| {
            d.matches(
                needle,
                username,
                folder,
                ignore_case,
                false,
                false,
                false,
            )
        })
        .collect();

    if matches.is_empty() {
        return Err(anyhow::anyhow!("no trashed entry found for '{needle}'"));
    }

    matches
        .iter()
        .map(|(entry, _)| {
            decrypt_cipher(entry).map(|d| ((*entry).clone(), d))
        })
        .collect()
}

// `rbw restore`: undoes `rbw remove`/`rbw delete` -- restores an entry out
// of the trash. Unlike `archive`/`unarchive`, this only ever goes one
// direction, so there's no toggle to share between two public entry
// points; otherwise modeled directly on `archive_or_unarchive` (same
// single/`--bulk` shape, same non-destructive no-confirm-unless-`--bulk`
// policy, since restoring is itself the "undo" and needs no undo of its
// own).
#[allow(clippy::too_many_arguments)]
pub fn restore(
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    if let Some(path) = from_file {
        return restore_from_file(
            path,
            needles,
            username,
            folder,
            ignore_case,
            force_exact,
            bulk,
            yes,
            from_file_passphrase,
        );
    }
    if bulk {
        unlock(None, None)?;
        let mut db = load_db()?;
        let mut any_err = false;

        let mut pending: Vec<(rbw::db::Entry, String)> = Vec::new();
        let c = stdout_supports_color();

        for needle in needles {
            match find_deleted_entries_all(
                &db,
                needle,
                username,
                folder,
                collection,
                org,
                ignore_case,
            ) {
                Err(e) => {
                    eprintln!("{needle}: {e:#}");
                    any_err = true;
                }
                Ok(entries) => {
                    for (entry, decrypted) in entries {
                        pending.push((entry, decrypted.name.clone()));
                    }
                }
            }
        }

        if pending.is_empty() {
            return if any_err {
                Err(anyhow::anyhow!("one or more entries failed to resolve"))
            } else {
                Ok(())
            };
        }

        if !yes {
            eprintln!(
                "About to restore {} {}:",
                style::name(&format!("{}", pending.len()), c),
                if pending.len() == 1 {
                    "entry"
                } else {
                    "entries"
                }
            );
            for (_, name) in &pending {
                eprintln!("  {}", style::name(name, c));
            }
            eprintln!();
            eprint!("Apply to all ({})? [y/N] ", pending.len());
            let _ = std::io::stderr().flush();
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .context("failed to read confirmation")?;
            if !matches!(answer.trim(), "y" | "Y") {
                eprintln!("Aborted.");
                return Ok(());
            }
        }

        let access_token = db.access_token.as_ref().unwrap();
        let refresh_token = db.refresh_token.as_ref().unwrap();
        let ids: Vec<String> =
            pending.iter().map(|(entry, _)| entry.id.clone()).collect();

        if let (Some(access_token), ()) =
            rbw::actions::restore_multiple(access_token, refresh_token, &ids)?
        {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }

        crate::actions::sync()?;

        for (_, name) in &pending {
            println!("Item {} was restored", style::name(name, c));
        }

        return if any_err {
            Err(anyhow::anyhow!("one or more entries failed to resolve"))
        } else {
            Ok(())
        };
    }

    unlock(None, None)?;

    let mut db = load_db()?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (entry, decrypted) = find_deleted_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find a trashed entry for '{desc}'"))?;

    let c = stdout_supports_color();

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    if let (Some(access_token), ()) =
        rbw::actions::restore(access_token, refresh_token, &entry.id)?
    {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    println!("Item {} was restored", style::name(&decrypted.name, c));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn restore_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    bulk: bool,
    yes: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    let mut vault = load_from_file(path, passphrase)?;
    let mut ids = Vec::new();
    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if bulk {
        for needle in needles {
            let matches = find_entries_all_in_file(
                &vault.entries,
                needle,
                username,
                folder,
                ignore_case,
            );
            if matches.is_empty() {
                eprintln!("{needle}: no entry found");
                continue;
            }
            for entry in matches {
                if !entry.deleted || !seen.insert(entry.id.clone()) {
                    continue;
                }
                ids.push(entry.id);
                names.push(entry.name);
            }
        }
    } else {
        let needle_str = needles
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let desc = format!(
            "{}{}",
            username.map_or_else(String::new, |s| format!("{s}@")),
            needle_str
        );
        let entry = find_entry_in_file(
            &vault.entries,
            needles,
            username,
            folder,
            ignore_case,
            force_exact,
        )
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
        if !entry.deleted {
            anyhow::bail!("entry '{}' is not in the trash", entry.name);
        }
        ids.push(entry.id);
        names.push(entry.name);
    }

    if ids.is_empty() {
        anyhow::bail!("no trashed entries to restore");
    }

    if bulk && !yes {
        let c = stdout_supports_color();
        eprintln!(
            "About to restore {} {}:",
            style::name(&ids.len().to_string(), c),
            if ids.len() == 1 { "entry" } else { "entries" }
        );
        for name in &names {
            eprintln!("  {}", style::name(name, c));
        }
        eprintln!();
        eprint!("Apply to all ({})? [y/N] ", ids.len());
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("failed to read confirmation")?;
        if !matches!(answer.trim(), "y" | "Y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    for entry in &mut vault.entries {
        if ids.iter().any(|id| id == &entry.id) {
            entry.deleted = false;
        }
    }
    save_loaded_file_vault(path, &vault)?;

    let c = stdout_supports_color();
    for name in names {
        println!("Item {} was restored", style::name(&name, c));
    }
    Ok(())
}

fn edit_structured(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    json: bool,
    force_exact: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (entry, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let editable = decrypted_to_editable(&decrypted);

    let serialized = if json {
        serde_json::to_string_pretty(&editable)?
    } else {
        serde_yaml::to_string(&editable)?
    };

    let (help, ext) = if json {
        (
            "# Edit the JSON below. Lines starting with # are ignored.",
            "json",
        )
    } else {
        (
            "# Edit the YAML below. Lines starting with # are ignored.",
            "yaml",
        )
    };

    let contents = rbw::edit::edit(&serialized, help, ext)?;
    let contents_trimmed = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });

    if contents_trimmed.trim() == serialized.trim() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    let updated: EditableCipher = if json {
        serde_json::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse JSON: {e}"))?
    } else {
        serde_yaml::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?
    };

    let (data, fields, notes) = editable_to_encrypted(
        &updated,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;

    let encrypted_name = crate::actions::encrypt(
        &updated.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;

    let encrypted_notes = notes
        .as_deref()
        .map(|n| {
            crate::actions::encrypt(
                n,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose()?;

    let mut history = entry.history.clone();
    if let (
        rbw::db::EntryData::Login {
            password: Some(old_pw),
            ..
        },
        rbw::db::EntryData::Login {
            password: new_pw, ..
        },
    ) = (&entry.data, &data)
    {
        if Some(old_pw) != new_pw.as_ref() {
            history.insert(
                0,
                rbw::db::HistoryEntry {
                    last_used_date: format!(
                        "{}",
                        humantime::format_rfc3339(
                            std::time::SystemTime::now()
                        )
                    ),
                    password: old_pw.clone(),
                },
            );
        }
    }

    let folder_id = if let Some(folder_name) = updated.folder.as_deref() {
        resolve_folder_id(
            &mut db,
            &access_token,
            &refresh_token,
            folder_name,
        )?
    } else {
        entry.folder_id.clone()
    };

    if let (Some(new_token), ()) = rbw::actions::edit(
        &access_token,
        &refresh_token,
        &entry.id,
        entry.org_id.as_deref(),
        entry.key.as_deref(),
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
        &history,
    )? {
        db.access_token = Some(new_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

fn add_structured(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    json: bool,
    generated_password: Option<&str>,
) -> anyhow::Result<()> {
    let editable_uris: Vec<EditableUri> = if uris.is_empty() {
        vec![EditableUri {
            uri: String::new(),
            match_type: None,
        }]
    } else {
        uris.iter()
            .map(|(uri, mt)| EditableUri {
                uri: uri.clone(),
                match_type: mt.map(|m| uri_match_type_str(m).to_string()),
            })
            .collect()
    };

    let template = EditableCipher {
        name: name.unwrap_or("").to_string(),
        folder: folder.map(std::string::ToString::to_string),
        notes: None,
        data: EditableData::Login {
            username: Some(username.unwrap_or("").to_string()),
            password: Some(
                generated_password.unwrap_or_default().to_string(),
            ),
            uris: editable_uris,
            totp: None,
            fido2_credentials: Vec::new(),
        },
        fields: Vec::new(),
    };

    let serialized = if json {
        serde_json::to_string_pretty(&template)?
    } else {
        serde_yaml::to_string(&template)?
    };

    let (help, ext) = if json {
        (
            "# Fill in the JSON below. Lines starting with # are ignored.",
            "json",
        )
    } else {
        (
            "# Fill in the YAML below. Lines starting with # are ignored.",
            "yaml",
        )
    };

    let contents = rbw::edit::edit(&serialized, help, ext)?;
    let contents_trimmed = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });

    // With `--generate`, the template already has a real (generated)
    // password filled in, so leaving the editor untouched means "accept the
    // generated entry as shown", not "I opened this by accident" -- only
    // treat an unmodified buffer as a no-op cancel when there's nothing
    // pre-filled worth keeping.
    if generated_password.is_none()
        && contents_trimmed.trim() == serialized.trim()
    {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    let cipher: EditableCipher = if json {
        serde_json::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse JSON: {e}"))?
    } else {
        serde_yaml::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?
    };

    if cipher.name.is_empty() {
        return Err(anyhow::anyhow!("name cannot be empty"));
    }

    unlock(None, None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (data, fields, notes) = editable_to_encrypted(&cipher, None, None)?;

    let encrypted_name = crate::actions::encrypt(&cipher.name, None, None)?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, None, None))
        .transpose()?;

    let folder_id = if let Some(folder_name) = cipher.folder.as_deref() {
        resolve_folder_id(
            &mut db,
            &access_token,
            &refresh_token,
            folder_name,
        )?
    } else {
        None
    };

    if let (Some(new_token), _) = rbw::actions::add(
        &access_token,
        &refresh_token,
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
    )? {
        db.access_token = Some(new_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;
    print_created(&cipher.name);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn set(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    bulk: bool,
    yes: bool,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    struct BulkPending {
        entry: rbw::db::Entry,
        entry_name: String,
        changes: Vec<(&'static str, String, String)>,
    }

    if let Some(path) = from_file {
        if bulk {
            return set_from_file_bulk(
                path,
                &needles,
                username,
                folder,
                ignore_case,
                new_name,
                new_username,
                new_password,
                new_notes,
                new_uris,
                new_totp,
                diff,
                new_attachments,
                yes,
                from_file_passphrase,
            );
        }
        return set_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            new_name,
            new_username,
            new_password,
            new_notes,
            new_uris,
            new_totp,
            diff,
            new_attachments,
            yes,
            force_exact,
            from_file_passphrase,
        );
    }

    if bulk {
        unlock(None, None)?;
        let mut db = load_db()?;
        let mut any_err = false;

        let mut pending: Vec<BulkPending> = Vec::new();

        for needle in &needles {
            match find_entries_all(
                &db,
                needle,
                username,
                folder,
                collection,
                org,
                ignore_case,
            ) {
                Err(e) => {
                    eprintln!("{needle}: {e:#}");
                    any_err = true;
                }
                Ok(entries) => {
                    for (entry, decrypted) in entries {
                        let entry_name = decrypted.name.clone();
                        match compute_entry_changes(
                            &decrypted,
                            new_name,
                            new_username,
                            new_password,
                            new_notes,
                            new_uris,
                            new_totp,
                        ) {
                            Err(e) => {
                                eprintln!("{entry_name}: {e:#}");
                                any_err = true;
                            }
                            Ok(changes)
                                if changes.is_empty()
                                    && new_attachments.is_empty() =>
                            {
                                let c = stdout_supports_color();
                                eprintln!(
                                    "{} {}",
                                    style::name(&entry_name, c),
                                    style::dim("(no changes)", c)
                                );
                            }
                            Ok(changes) => {
                                pending.push(BulkPending {
                                    entry,
                                    entry_name,
                                    changes,
                                });
                            }
                        }
                    }
                }
            }
        }

        if !pending.is_empty() && !yes {
            let c = stdout_supports_color();
            let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
            eprintln!(
                "About to update {} {}:",
                style::name(&format!("{}", pending.len()), c),
                if pending.len() == 1 {
                    "entry"
                } else {
                    "entries"
                }
            );
            for pu in &pending {
                eprintln!();
                eprintln!("{}:", style::name(&pu.entry_name, c));
                for (field, old, new) in &pu.changes {
                    eprintln!(
                        "  {} {} {} {}",
                        lbl(field),
                        style::old_val(old, c),
                        style::dim("→", c),
                        style::new_val(new, c),
                    );
                }
                for file in new_attachments {
                    eprintln!("  {} {}", lbl("attach"), file.display());
                }
            }
            eprintln!();
            eprint!("Apply all ({})? [y/N] ", pending.len());
            let _ = std::io::stderr().flush();
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .context("failed to read confirmation")?;
            if !matches!(answer.trim(), "y" | "Y") {
                eprintln!("Aborted.");
                return Ok(());
            }
        }

        let c = stdout_supports_color();
        let pb = item_progress_bar(
            u64::try_from(pending.len()).unwrap_or(u64::MAX),
        );
        for pu in pending {
            pb.set_message(fit_to_width(&pu.entry_name, PROGRESS_MSG_WIDTH));

            let result = apply_entry_update(
                &mut db,
                &pu.entry,
                new_name,
                new_username,
                new_password,
                new_notes,
                new_uris,
                new_totp,
                !pu.changes.is_empty(),
                new_attachments,
            );
            // `apply_entry_update`'s existing output is a mix of println!
            // (stdout) and eprintln! (stderr) -- suspend the bar around it
            // rather than routing through `pb.println` (which always
            // targets the bar's own stream), so neither stream's output
            // changes.
            pb.suspend(|| {
                if let Err(e) = &result {
                    eprintln!("{}: {e:#}", pu.entry_name);
                } else {
                    println!(
                        "Item {} was updated",
                        style::name(&pu.entry_name, c)
                    );
                    if diff {
                        print_entry_diff(&pu.changes);
                    }
                }
            });
            if result.is_err() {
                any_err = true;
            }
            pb.inc(1);
        }
        pb.finish_and_clear();

        return if any_err {
            Err(anyhow::anyhow!("one or more entries failed to update"))
        } else {
            Ok(())
        };
    }
    set_one(
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
        diff,
        new_attachments,
        yes,
        force_exact,
    )
}

fn find_entries_all(
    db: &rbw::db::Db,
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<Vec<(rbw::db::Entry, DecryptedCipher)>> {
    let (collection_id, org_id) = resolve_entry_scope(db, collection, org)?;
    let mut requests = BatchRequests::new();
    let plans: Vec<SearchCipherPlan> = db
        .entries
        .iter()
        .map(|entry| SearchCipherPlan::build(entry, &mut requests))
        .collect();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };
    let ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .zip(plans)
        .map(|(entry, plan)| {
            plan.resolve(&results).map(|d| (entry.clone(), d))
        })
        .collect::<anyhow::Result<_>>()?;

    let matches: Vec<_> = ciphers
        .iter()
        // Trashed entries are never a `--bulk` candidate (matches
        // `find_entry_raw`'s exclusion, and Bitwarden's own precondition
        // that a trashed item can't be re-edited/re-archived) -- see
        // `find_deleted_entries_all` for `rbw restore --bulk`'s dedicated
        // trashed-only counterpart.
        .filter(|(_, d)| !d.deleted)
        .filter(|(entry, _)| {
            entry_in_collection_org_scope(
                entry,
                collection_id.as_deref(),
                org_id.as_deref(),
            )
        })
        .filter(|(_, d)| {
            d.matches(
                needle,
                username,
                folder,
                ignore_case,
                false,
                false,
                false,
            )
        })
        .collect();

    if matches.is_empty() {
        return Err(anyhow::anyhow!("no entry found for '{needle}'"));
    }

    matches
        .iter()
        .map(|(entry, _)| {
            decrypt_cipher(entry).map(|d| ((*entry).clone(), d))
        })
        .collect()
}

// `find_entries_all`'s `--from-file` counterpart: same matching
// (`DecryptedSearchCipher::matches`) against the already-decrypted vault,
// no agent/batch-decrypt involved -- can't fail the way a live decrypt
// can, so this returns the plain `Vec` rather than a `Result`.
fn find_entries_all_in_file(
    entries: &[DecryptedCipher],
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> Vec<DecryptedCipher> {
    entries
        .iter()
        .filter(|entry| {
            decrypted_cipher_to_search(entry).matches(
                needle,
                username,
                folder,
                ignore_case,
                false,
                false,
                false,
            )
        })
        .cloned()
        .collect()
}

// `set --bulk --from-file`: same per-needle "find every match, compute
// changes, confirm once, apply all" flow as the live `bulk` branch above,
// but against the in-memory vault -- `apply_entry_update_decrypted`
// instead of `apply_entry_update`, and a single `save_to_file` at the end
// instead of a `rbw::actions::edit` + `sync` per entry.
#[allow(clippy::too_many_arguments)]
fn set_from_file_bulk(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    yes: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    struct BulkPending {
        decrypted: DecryptedCipher,
        entry_name: String,
        changes: Vec<(&'static str, String, String)>,
    }

    let mut vault = load_from_file(path, passphrase)?;
    let mut any_err = false;
    let mut pending: Vec<BulkPending> = Vec::new();

    for needle in needles {
        let matches = find_entries_all_in_file(
            &vault.entries,
            needle,
            username,
            folder,
            ignore_case,
        );
        if matches.is_empty() {
            eprintln!("{needle}: no entry found");
            any_err = true;
            continue;
        }
        for decrypted in matches {
            let entry_name = decrypted.name.clone();
            match compute_entry_changes(
                &decrypted,
                new_name,
                new_username,
                new_password,
                new_notes,
                new_uris,
                new_totp,
            ) {
                Err(e) => {
                    eprintln!("{entry_name}: {e:#}");
                    any_err = true;
                }
                Ok(changes)
                    if changes.is_empty() && new_attachments.is_empty() =>
                {
                    let c = stdout_supports_color();
                    eprintln!(
                        "{} {}",
                        style::name(&entry_name, c),
                        style::dim("(no changes)", c)
                    );
                }
                Ok(changes) => {
                    pending.push(BulkPending {
                        decrypted,
                        entry_name,
                        changes,
                    });
                }
            }
        }
    }

    if !pending.is_empty() && !yes {
        let c = stdout_supports_color();
        let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
        eprintln!(
            "About to update {} {}:",
            style::name(&format!("{}", pending.len()), c),
            if pending.len() == 1 {
                "entry"
            } else {
                "entries"
            }
        );
        for pu in &pending {
            eprintln!();
            eprintln!("{}:", style::name(&pu.entry_name, c));
            for (field, old, new) in &pu.changes {
                eprintln!(
                    "  {} {} {} {}",
                    lbl(field),
                    style::old_val(old, c),
                    style::dim("→", c),
                    style::new_val(new, c),
                );
            }
            for file in new_attachments {
                eprintln!("  {} {}", lbl("attach"), file.display());
            }
        }
        eprintln!();
        eprint!("Apply all ({})? [y/N] ", pending.len());
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("failed to read confirmation")?;
        if !matches!(answer.trim(), "y" | "Y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    if pending.is_empty() {
        return if any_err {
            Err(anyhow::anyhow!("one or more needles matched no entry"))
        } else {
            Ok(())
        };
    }

    let c = stdout_supports_color();
    for pu in pending {
        match apply_entry_update_decrypted(
            &pu.decrypted,
            new_name,
            new_password,
            new_username,
            new_notes,
            new_uris,
            new_totp,
            new_attachments,
        ) {
            Ok((updated, new_attachment_bytes)) => {
                for (id, bytes) in new_attachment_bytes {
                    vault.attachment_data.insert(id, bytes);
                }
                if let Some(pos) =
                    vault.entries.iter().position(|e| e.id == updated.id)
                {
                    vault.entries[pos] = updated;
                }
                println!(
                    "Item {} was updated",
                    style::name(&pu.entry_name, c)
                );
                if diff {
                    print_entry_diff(&pu.changes);
                }
            }
            Err(e) => {
                eprintln!("{}: {e:#}", pu.entry_name);
                any_err = true;
            }
        }
    }

    backup_file(path)?;
    let exported = vault
        .entries
        .iter()
        .map(|e| {
            to_exported_entry(e, &vault.attachment_data, &vault.entry_extra)
        })
        .collect();
    save_to_file(
        path,
        exported,
        vault.collections,
        vault.passphrase.as_deref(),
    )?;

    if any_err {
        Err(anyhow::anyhow!("one or more entries failed to update"))
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn set_one(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    yes: bool,
    force_exact: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (entry, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    set_entry(
        &mut db,
        &entry,
        &decrypted,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
        diff,
        new_attachments,
        yes,
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_entry_changes(
    decrypted: &DecryptedCipher,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
) -> anyhow::Result<Vec<(&'static str, String, String)>> {
    let login_fields_requested = new_username.is_some()
        || new_password.is_some()
        || !new_uris.is_empty()
        || new_totp.is_some();
    if login_fields_requested
        && !matches!(decrypted.data, DecryptedData::Login { .. })
    {
        return Err(anyhow::anyhow!(
            "username/password/uri/totp are only supported for Login entries"
        ));
    }

    let mut changes: Vec<(&'static str, String, String)> = Vec::new();

    if let Some(n) = new_name {
        if n != decrypted.name.as_str() {
            changes.push(("name", decrypted.name.clone(), n.to_string()));
        }
    }
    if let Some(n) = new_notes {
        let cur = decrypted.notes.as_deref().unwrap_or("");
        if n != cur {
            let old_d = if cur.is_empty() {
                "(none)".to_string()
            } else {
                "(set)".to_string()
            };
            let new_d = if n.is_empty() {
                "(cleared)".to_string()
            } else {
                "(set)".to_string()
            };
            changes.push(("notes", old_d, new_d));
        }
    }
    if let DecryptedData::Login {
        username: cur_user,
        password: cur_pw,
        uris: cur_uris,
        totp: cur_totp,
        ..
    } = &decrypted.data
    {
        if let Some(u) = new_username {
            if Some(u) != cur_user.as_deref() {
                let old = cur_user.as_deref().map_or_else(
                    || "(none)".to_string(),
                    std::string::ToString::to_string,
                );
                changes.push(("username", old, u.to_string()));
            }
        }
        if let Some(p) = new_password {
            if Some(p) != cur_pw.as_deref() {
                let old = cur_pw.as_deref().map_or_else(
                    || "(none)".to_string(),
                    |s| format!("\"{}\"", censor(s)),
                );
                changes.push(("password", old, format!("\"{}\"", censor(p))));
            }
        }
        if !new_uris.is_empty() {
            let cur_strs: Vec<&str> = cur_uris
                .as_ref()
                .map(|v| v.iter().map(|u| u.uri.as_str()).collect())
                .unwrap_or_default();
            let new_strs: Vec<&str> =
                new_uris.iter().map(String::as_str).collect();
            if new_strs != cur_strs {
                let fmt_uris = |v: &[&str]| match v {
                    [] => "(none)".to_string(),
                    [u] => (*u).to_string(),
                    _ => format!("[{} uris]", v.len()),
                };
                changes.push((
                    "uri",
                    fmt_uris(&cur_strs),
                    fmt_uris(&new_strs),
                ));
            }
        }
        if let Some(t) = new_totp {
            if Some(t) != cur_totp.as_deref() {
                let old = cur_totp.as_deref().map_or_else(
                    || "(none)".to_string(),
                    |s| format!("\"{}\"", censor(s)),
                );
                changes.push(("totp", old, format!("\"{}\"", censor(t))));
            }
        }
    }
    Ok(changes)
}

#[allow(clippy::too_many_arguments)]
fn apply_entry_update(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    has_field_changes: bool,
    new_attachments: &[std::path::PathBuf],
) -> anyhow::Result<()> {
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();
    let org_id = entry.org_id.as_deref();
    // Every field re-encrypted below must use the entry's own individual
    // key when it has one, exactly like `decrypt_cipher` does when reading
    // it back -- otherwise the fields this edit leaves untouched (still
    // ciphertext under the entry's key) end up alongside a freshly
    // touched field encrypted under the wrong (account/org) key, and
    // whichever ciphertext doesn't match the key actually in effect
    // becomes permanently undecryptable.
    let entry_key = entry.key.as_deref();

    let encrypted_name = if let Some(n) = new_name {
        crate::actions::encrypt(n, entry_key, org_id)?
    } else {
        entry.name.clone()
    };

    let encrypted_notes = if let Some(n) = new_notes {
        if n.is_empty() {
            None
        } else {
            Some(crate::actions::encrypt(n, entry_key, org_id)?)
        }
    } else {
        entry.notes.clone()
    };

    let mut history = entry.history.clone();

    let data = match &entry.data {
        rbw::db::EntryData::Login {
            username: entry_username,
            password: entry_password,
            uris: entry_uris,
            totp: entry_totp,
            fido2_credentials: entry_fido2_credentials,
        } => {
            let enc_user = if new_username.is_some() {
                new_username
                    .map(|u| crate::actions::encrypt(u, entry_key, org_id))
                    .transpose()?
            } else {
                entry_username.clone()
            };
            let enc_pw = if let Some(pw) = new_password {
                if let Some(prev) = entry_password.clone() {
                    history.insert(
                        0,
                        rbw::db::HistoryEntry {
                            last_used_date: format!(
                                "{}",
                                humantime::format_rfc3339(
                                    std::time::SystemTime::now()
                                )
                            ),
                            password: prev,
                        },
                    );
                }
                Some(crate::actions::encrypt(pw, entry_key, org_id)?)
            } else {
                entry_password.clone()
            };
            let enc_uris = if new_uris.is_empty() {
                entry_uris.clone()
            } else {
                new_uris
                    .iter()
                    .map(|u| {
                        Ok(rbw::db::Uri {
                            uri: crate::actions::encrypt(
                                u, entry_key, org_id,
                            )?,
                            match_type: None,
                        })
                    })
                    .collect::<anyhow::Result<_>>()?
            };
            let enc_totp = if new_totp.is_some() {
                new_totp
                    .map(|t| crate::actions::encrypt(t, entry_key, org_id))
                    .transpose()?
            } else {
                entry_totp.clone()
            };
            rbw::db::EntryData::Login {
                username: enc_user,
                password: enc_pw,
                uris: enc_uris,
                totp: enc_totp,
                // `rbw set` never touches passkeys -- always carried over
                // unchanged from the entry being updated, exactly like
                // `password_history` above, so this can never destroy a
                // fido2 credential the way an absent field on the outgoing
                // request would (Vaultwarden stores the whole `login`
                // object wholesale, no per-field merge).
                fido2_credentials: entry_fido2_credentials.clone(),
            }
        }
        other => other.clone(),
    };

    if has_field_changes {
        if let (Some(new_token), ()) = rbw::actions::edit(
            &access_token,
            &refresh_token,
            &entry.id,
            org_id,
            entry_key,
            &encrypted_name,
            &data,
            &entry.fields,
            encrypted_notes.as_deref(),
            entry.folder_id.as_deref(),
            &history,
        )? {
            db.access_token = Some(new_token);
            save_db(db)?;
        }
    }

    for file in new_attachments {
        let filename = file
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| {
                anyhow::anyhow!("invalid filename: {}", file.display())
            })?;
        let file_data = std::fs::read(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let access_token = db.access_token.as_ref().unwrap().clone();
        let refresh_token = db.refresh_token.as_ref().unwrap().clone();
        let (encrypted_data, encrypted_key, encrypted_filename) =
            crate::actions::encrypt_attachment(
                file_data,
                filename,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )?;
        if let (Some(new_token), ()) = rbw::actions::create_attachment(
            &access_token,
            &refresh_token,
            &entry.id,
            &encrypted_filename,
            &encrypted_key,
            &encrypted_data,
        )? {
            db.access_token = Some(new_token);
            save_db(db)?;
        }
    }

    // Nothing after this call in any caller depends on a freshly-synced
    // `db` -- only skip when there were no attachments uploaded above,
    // since that's the one thing here the local cache doesn't already
    // reflect (same reasoning as `import_create_entry`'s sync-skip).
    if !new_attachments.is_empty() {
        crate::actions::sync()?;
    }
    Ok(())
}

// Shared by `set_entry` (live account) and `set_from_file`: prints the
// pending changes and asks to confirm, unless `yes`. `Ok(false)` means the
// caller should abort without applying anything.
fn confirm_entry_update(
    entry_name: &str,
    changes: &[(&'static str, String, String)],
    new_attachments: &[std::path::PathBuf],
    yes: bool,
) -> anyhow::Result<bool> {
    use std::io::Write as _;

    if yes {
        return Ok(true);
    }

    let c = stdout_supports_color();
    let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
    eprintln!("About to update {}:", style::name(entry_name, c));
    eprintln!();
    for (field, old, new) in changes {
        eprintln!(
            "{} {} {} {}",
            lbl(field),
            style::old_val(old, c),
            style::dim("→", c),
            style::new_val(new, c),
        );
    }
    for file in new_attachments {
        eprintln!("{} {}", lbl("attach"), file.display());
    }
    eprintln!();
    eprint!("Apply? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("failed to read confirmation")?;
    if matches!(answer.trim(), "y" | "Y") {
        Ok(true)
    } else {
        eprintln!("Aborted.");
        Ok(false)
    }
}

// `set --from-file`'s counterpart to `apply_entry_update`: same field
// updates (including inserting the outgoing password into history -- pure
// data, no crypto involved) but on a `DecryptedCipher` directly instead of
// encrypting and pushing to the server. New attachments (`--attach`) are
// read from disk and handed back with their raw bytes for the caller to
// fold into the vault's attachment side table -- there's no server here to
// assign them an id, so a fresh one is generated.
fn apply_entry_update_decrypted(
    decrypted: &DecryptedCipher,
    new_name: Option<&str>,
    new_password: Option<&str>,
    new_username: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    new_attachments: &[std::path::PathBuf],
) -> anyhow::Result<(DecryptedCipher, Vec<(String, Vec<u8>)>)> {
    let mut updated = decrypted.clone();

    if let Some(n) = new_name {
        updated.name = n.to_string();
    }
    if let Some(n) = new_notes {
        updated.notes = (!n.is_empty()).then(|| n.to_string());
    }

    if let DecryptedData::Login {
        username,
        password,
        uris,
        totp,
        ..
    } = &mut updated.data
    {
        if new_username.is_some() {
            *username = new_username.map(str::to_string);
        }
        if let Some(pw) = new_password {
            if let Some(prev) = password.clone() {
                updated.history.insert(
                    0,
                    DecryptedHistoryEntry {
                        last_used_date: format!(
                            "{}",
                            humantime::format_rfc3339(
                                std::time::SystemTime::now()
                            )
                        ),
                        password: prev,
                    },
                );
            }
            *password = Some(pw.to_string());
        }
        if !new_uris.is_empty() {
            *uris = Some(
                new_uris
                    .iter()
                    .map(|u| DecryptedUri {
                        uri: u.clone(),
                        match_type: None,
                    })
                    .collect(),
            );
        }
        if new_totp.is_some() {
            *totp = new_totp.map(str::to_string);
        }
    }

    let mut new_attachment_bytes = Vec::new();
    for file in new_attachments {
        let filename = file
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| {
                anyhow::anyhow!("invalid filename: {}", file.display())
            })?
            .to_string();
        let data = std::fs::read(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let id = uuid::Uuid::new_v4().to_string();
        updated.attachments.push(DecryptedAttachment {
            id: id.clone(),
            file_name: Some(filename),
            size: None,
            size_name: None,
        });
        new_attachment_bytes.push((id, data));
    }
    updated.attachment_metadata =
        AttachmentMetadata::new(&updated.id, updated.attachments.len());

    Ok((updated, new_attachment_bytes))
}

#[allow(clippy::too_many_arguments)]
fn set_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    yes: bool,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let mut vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let entry_name = decrypted.name.clone();
    let changes = compute_entry_changes(
        &decrypted,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
    )?;

    if changes.is_empty() && new_attachments.is_empty() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    if !confirm_entry_update(&entry_name, &changes, new_attachments, yes)? {
        return Ok(());
    }

    let (updated, new_attachment_bytes) = apply_entry_update_decrypted(
        &decrypted,
        new_name,
        new_password,
        new_username,
        new_notes,
        new_uris,
        new_totp,
        new_attachments,
    )?;
    for (id, bytes) in new_attachment_bytes {
        vault.attachment_data.insert(id, bytes);
    }
    if let Some(pos) = vault.entries.iter().position(|e| e.id == decrypted.id)
    {
        vault.entries[pos] = updated;
    }

    backup_file(path)?;
    let exported = vault
        .entries
        .iter()
        .map(|e| {
            to_exported_entry(e, &vault.attachment_data, &vault.entry_extra)
        })
        .collect();
    save_to_file(
        path,
        exported,
        vault.collections,
        vault.passphrase.as_deref(),
    )?;

    let c = stdout_supports_color();
    println!("Item {} was updated", style::name(&entry_name, c));
    if diff {
        print_entry_diff(&changes);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn set_entry(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    decrypted: &DecryptedCipher,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    yes: bool,
) -> anyhow::Result<()> {
    let entry_name = decrypted.name.clone();

    let changes = compute_entry_changes(
        decrypted,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
    )?;

    if changes.is_empty() && new_attachments.is_empty() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    if !confirm_entry_update(&entry_name, &changes, new_attachments, yes)? {
        return Ok(());
    }

    apply_entry_update(
        db,
        entry,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
        !changes.is_empty(),
        new_attachments,
    )?;
    let c = stdout_supports_color();
    println!("Item {} was updated", style::name(&entry_name, c));
    if diff {
        print_entry_diff(&changes);
    }
    Ok(())
}

fn resolve_folder_id(
    db: &mut rbw::db::Db,
    access_token: &str,
    refresh_token: &str,
    folder_name: &str,
) -> anyhow::Result<Option<String>> {
    let (new_access_token, folders) =
        rbw::actions::list_folders(access_token, refresh_token)?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(db)?;
    }
    let access_token = db.access_token.as_deref().unwrap();
    let refresh_token_str = db.refresh_token.as_deref().unwrap();

    let folders: Vec<(String, String)> = folders
        .iter()
        .cloned()
        .map(|(id, name)| {
            Ok((id, crate::actions::decrypt(&name, None, None)?))
        })
        .collect::<anyhow::Result<_>>()?;

    for (id, name) in &folders {
        if name == folder_name {
            return Ok(Some(id.clone()));
        }
    }

    let (new_access_token, id) = rbw::actions::create_folder(
        access_token,
        refresh_token_str,
        &crate::actions::encrypt(folder_name, None, None)?,
    )?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(db)?;
    }
    Ok(Some(id))
}

fn censor(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    if len <= 4 {
        return "****".to_string();
    }
    let prefix = len.div_ceil(3).min(8);
    let suffix = len.div_ceil(4).min(5);
    if prefix + suffix >= len {
        return "****".to_string();
    }
    format!(
        "{}…{}",
        chars[..prefix].iter().collect::<String>(),
        chars[len - suffix..].iter().collect::<String>()
    )
}

// Exposed for main.rs error rendering — keeps all ANSI codes in one place.
pub fn style_error(msg: &str, color: bool) -> String {
    style::paint_raw(msg, "1;31", color)
}

fn paint_no_changes() -> String {
    style::dim("No changes.", stdout_supports_color())
}

fn print_created(entry_name: &str) {
    let c = stdout_supports_color();
    eprintln!(
        "{} {}",
        style::success("Created", c),
        style::name(entry_name, c)
    );
}

fn print_entry_diff(changes: &[(&str, String, String)]) {
    let c = stdout_supports_color();
    let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
    for (field, old, new) in changes {
        println!(
            "  {} {} {} {}",
            lbl(field),
            style::old_val(old, c),
            style::dim("→", c),
            style::new_val(new, c),
        );
    }
}

#[derive(serde::Serialize, Debug, PartialEq, Eq)]
struct ExportedAttachment {
    id: String,
    file_name: String,
    // decrypted attachment contents, base64-encoded so the export
    // round-trips cleanly through JSON
    data_base64: String,
}

#[derive(serde::Serialize)]
struct ExportedEntry {
    id: String,
    org_id: Option<String>,
    folder: Option<String>,
    name: String,
    #[serde(flatten)]
    data: DecryptedData,
    fields: Vec<DecryptedField>,
    notes: Option<String>,
    history: Vec<DecryptedHistoryEntry>,
    collection_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    archived: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    deleted: bool,
    // empty unless `--attachments` was passed, so exports produced
    // without that flag are byte-for-byte identical to before it
    // existed
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<ExportedAttachment>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportedCollection {
    pub id: String,
    pub org_id: String,
    pub name: String,
}

#[derive(serde::Serialize)]
struct ExportedVault {
    entries: Vec<ExportedEntry>,
    collections: Vec<ExportedCollection>,
}

// Downloads and decrypts every attachment on `entry`, using the
// already-decrypted `decrypted_attachments` (from `decrypt_cipher`)
// for filenames. This mirrors `attachment_get`'s handling of the
// legacy quirk where an attachment's filename may still be
// entry-key-encrypted even though its data is attachment-key-encrypted:
// `decrypt_cipher` already resolved that via
// `decrypt_field_with_attachment_key`, so we just reuse its result
// here rather than re-deriving it.
fn export_attachments(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    decrypted_attachments: &[DecryptedAttachment],
) -> anyhow::Result<Vec<ExportedAttachment>> {
    let access_token = db
        .access_token
        .as_ref()
        .context("failed to find access token in db")?
        .clone();
    let refresh_token = db
        .refresh_token
        .as_ref()
        .context("failed to find refresh token in db")?
        .clone();

    let mut out = Vec::with_capacity(entry.attachments.len());
    for (attachment, decrypted_attachment) in
        entry.attachments.iter().zip(decrypted_attachments)
    {
        let url = match rbw::actions::attachment_url(
            &access_token,
            &refresh_token,
            &entry.id,
            &attachment.id,
        ) {
            Ok((new_access_token, url)) => {
                if let Some(new_access_token) = new_access_token {
                    db.access_token = Some(new_access_token);
                    save_db(db)?;
                }
                url
            }
            Err(e) => attachment.url.clone().ok_or(e)?,
        };
        let encrypted = rbw::actions::download_attachment(&url)
            .with_context(|| {
                format!("failed to download attachment {}", attachment.id)
            })?;
        let decrypted_bytes = crate::actions::decrypt_attachment(
            encrypted,
            attachment.key.as_deref(),
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?;
        let file_name = decrypted_attachment
            .file_name
            .clone()
            .unwrap_or_else(|| attachment.id.clone());
        out.push(ExportedAttachment {
            id: attachment.id.clone(),
            file_name,
            data_base64: rbw::base64::encode(&decrypted_bytes),
        });
    }
    Ok(out)
}

// Whether an entry belongs in `export`/`mirror`'s output, within the given
// collection/org scope, if any. Trashed entries are deliberately not
// filtered here: native rbw exports carry their `deleted` flag, and the
// export command is a backup of the whole vault. `mirror` applies its own
// live-entry filter because the upstream Bitwarden-shaped conversion
// cannot represent trash status.
fn export_entry_in_scope(
    entry: &rbw::db::Entry,
    scope_collection_id: Option<&str>,
    scope_org_id: Option<&str>,
) -> bool {
    entry_in_collection_org_scope(entry, scope_collection_id, scope_org_id)
}

fn export_entry_status_allowed(
    entry: &rbw::db::Entry,
    skip_trash: bool,
    skip_archived: bool,
) -> bool {
    !(skip_trash && entry.deleted || skip_archived && entry.archived)
}

// Whether `entry` belongs to the given collection/org scope (either or both
// `None` matches everything regardless of the entry's own collection/org).
// `collection_ids`/`org_id` are plain IDs on every synced entry, never
// encrypted, so this needs no decryption -- shared by the mirror/export
// scope above and by `--collection`/`--org` filtering on
// `find_entry`/`list`/`search`.
fn entry_in_collection_org_scope(
    entry: &rbw::db::Entry,
    collection_id: Option<&str>,
    org_id: Option<&str>,
) -> bool {
    if let Some(cid) = collection_id {
        if !entry.collection_ids.iter().any(|c| c == cid) {
            return false;
        }
    }
    if let Some(oid) = org_id {
        if entry.org_id.as_deref() != Some(oid) {
            return false;
        }
    }
    true
}

// Builds rbw's own decrypted `ExportedVault` shape from the currently
// active account (see `crate::actions::set_active_account`) -- shared by
// `export` and `mirror_vault`, both of which can additionally scope to a
// single `--collection` and/or `--org`, since neither an export nor a
// cross-account copy should have to mean "the entire vault". Assumes the
// account is already unlocked.
fn build_exported_vault(
    attachments: bool,
    collection: Option<&str>,
    org: Option<&str>,
    skip_trash: bool,
    skip_archived: bool,
) -> anyhow::Result<ExportedVault> {
    let mut db = load_db()?;

    // Same name-or-ID `--collection`/`--org` resolution the find-family
    // commands (get/show/list/search/...) use: `--org` alone filters by
    // organization directly, `--collection` (optionally combined with
    // `--org` to disambiguate a name shared across orgs) resolves to one
    // specific collection.
    let (scope_collection_id, scope_org_id) =
        resolve_entry_scope(&db, collection, org)?;

    let entries_snapshot: Vec<rbw::db::Entry> = db
        .entries
        .iter()
        .filter(|entry| {
            export_entry_status_allowed(entry, skip_trash, skip_archived)
        })
        .filter(|entry| {
            export_entry_in_scope(
                entry,
                scope_collection_id.as_deref(),
                scope_org_id.as_deref(),
            )
        })
        .cloned()
        .collect();

    let mut entries: Vec<ExportedEntry> = Vec::new();
    let pb = item_progress_bar(
        u64::try_from(entries_snapshot.len()).unwrap_or(u64::MAX),
    );
    for entry in &entries_snapshot {
        let decrypted = decrypt_cipher(entry)?;
        pb.set_message(fit_to_width(&decrypted.name, PROGRESS_MSG_WIDTH));

        let exported_attachments =
            if attachments && !entry.attachments.is_empty() {
                export_attachments(&mut db, entry, &decrypted.attachments)?
            } else {
                Vec::new()
            };

        entries.push(ExportedEntry {
            id: decrypted.id,
            org_id: entry.org_id.clone(),
            folder: decrypted.folder,
            name: decrypted.name,
            data: decrypted.data,
            fields: decrypted.fields,
            notes: decrypted.notes,
            history: decrypted.history,
            collection_ids: entry.collection_ids.clone(),
            archived: entry.archived,
            deleted: entry.deleted,
            attachments: exported_attachments,
        });
        pb.inc(1);
    }
    pb.finish_and_clear();

    let mut collections: Vec<ExportedCollection> = db
        .collections
        .iter()
        .filter(|c| scope_org_id.as_deref().is_none_or(|oid| c.org_id == oid))
        .map(|c| {
            let name =
                crate::actions::decrypt(&c.name, None, Some(&c.org_id))?;
            Ok(ExportedCollection {
                id: c.id.clone(),
                org_id: c.org_id.clone(),
                name,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    collections.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ExportedVault {
        entries,
        collections,
    })
}

pub fn export(
    format: crate::import_bitwarden::ExportFormat,
    attachments: bool,
    skip_trash: bool,
    skip_archived: bool,
    encrypt: Option<&str>,
    output: Option<&std::path::Path>,
    collection: Option<&str>,
    org: Option<&str>,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    use crate::import_bitwarden::ExportFormat;

    // Resolve the passphrase up front (from $RBW_EXPORT_PASSPHRASE or an
    // interactive prompt when `--encrypt` was given without a value), so a
    // mistyped confirmation fails before any decryption work happens.
    // `--encrypt` means two different things depending on `--format`: rbw's
    // own gpg passphrase for the default format, or the Bitwarden
    // "Encrypted JSON" export's password for `bitwarden-encrypted-json`.
    // That format always needs *some* password, so unlike rbw's own
    // (optionally encrypted) format, choosing it prompts on its own even
    // without `--encrypt` -- `--encrypt` only still matters there to
    // supply the password inline and skip the prompt.
    let passphrase = resolve_export_passphrase(encrypt)?;
    let passphrase = if matches!(format, ExportFormat::BitwardenEncryptedJson)
        && passphrase.is_none()
    {
        Some(resolve_env_or_prompted_passphrase(true)?)
    } else {
        passphrase
    };

    if let Some(path) = from_file {
        let file_vault = load_from_file(path, from_file_passphrase)?;
        let vault = exported_vault_from_file(
            &file_vault,
            collection,
            org,
            skip_trash,
            skip_archived,
        )?;
        return write_exported_vault(
            format, passphrase, output, &vault, None,
        );
    }

    unlock(None, None)?;

    let vault = build_exported_vault(
        attachments,
        collection,
        org,
        skip_trash,
        skip_archived,
    )?;
    // Reloaded (rather than threaded through `build_exported_vault`) purely
    // for the KDF settings the `BitwardenEncryptedJson` branch below needs;
    // cheap, since it's just the local db.json cache, and none of those
    // fields change as a side effect of building the vault.
    let db = load_db()?;

    write_exported_vault(format, passphrase, output, &vault, Some(&db))
}

fn exported_vault_from_file(
    file_vault: &FileVault,
    collection: Option<&str>,
    org: Option<&str>,
    skip_trash: bool,
    skip_archived: bool,
) -> anyhow::Result<ExportedVault> {
    let collection_id = collection
        .map(|wanted| {
            file_vault
                .collections
                .iter()
                .find(|c| {
                    (c.id == wanted || c.name == wanted)
                        && org.is_none_or(|org_id| c.org_id == org_id)
                })
                .map(|c| c.id.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "collection '{wanted}' not found in export"
                    )
                })
        })
        .transpose()?;

    let entries = file_vault
        .entries
        .iter()
        .filter(|entry| {
            !(skip_trash && entry.deleted || skip_archived && entry.archived)
        })
        .filter(|entry| {
            let extra = file_vault.entry_extra.get(&entry.id);
            org.is_none_or(|org_id| {
                extra.and_then(|extra| extra.org_id.as_deref())
                    == Some(org_id)
            })
        })
        .filter(|entry| {
            collection_id.as_deref().is_none_or(|collection_id| {
                file_vault.entry_extra.get(&entry.id).is_some_and(|extra| {
                    extra.collection_ids.iter().any(|id| id == collection_id)
                })
            })
        })
        .map(|entry| {
            to_exported_entry(
                entry,
                &file_vault.attachment_data,
                &file_vault.entry_extra,
            )
        })
        .collect();

    let collections = file_vault
        .collections
        .iter()
        .filter(|collection| {
            org.is_none_or(|org_id| collection.org_id == org_id)
        })
        .filter(|collection| {
            collection_id
                .as_deref()
                .is_none_or(|collection_id| collection.id == collection_id)
        })
        .cloned()
        .collect();

    Ok(ExportedVault {
        entries,
        collections,
    })
}

fn write_exported_vault(
    format: crate::import_bitwarden::ExportFormat,
    passphrase: Option<String>,
    output: Option<&std::path::Path>,
    vault: &ExportedVault,
    db: Option<&rbw::db::Db>,
) -> anyhow::Result<()> {
    use crate::import_bitwarden::ExportFormat;

    match format {
        ExportFormat::Rbw => {
            if let Some(passphrase) = passphrase {
                let archive = build_export_tar_gz(vault)?;
                let encrypted = gpg_symmetric_encrypt(&passphrase, &archive)?;
                write_export_bytes(
                    output,
                    &encrypted,
                    "failed to write encrypted export",
                )
            } else if let Some(path) = output {
                let mut json = serde_json::to_vec_pretty(vault)
                    .context("failed to serialize export to JSON")?;
                json.push(b'\n');
                write_export_bytes(
                    Some(path),
                    &json,
                    "failed to write export JSON",
                )
            } else {
                write_json_pretty(vault, "failed to write export to stdout")
            }
        }
        ExportFormat::BitwardenJson => {
            let (bw, _attachments) = exported_vault_to_bw(vault);
            let mut json = serde_json::to_vec_pretty(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            json.push(b'\n');
            write_export_bytes(
                output,
                &json,
                "failed to write Bitwarden JSON export",
            )
        }
        ExportFormat::BitwardenEncryptedJson => {
            let (bw, _attachments) = exported_vault_to_bw(vault);
            let json_text = serde_json::to_string(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            let passphrase = passphrase
                .context("Bitwarden encrypted JSON requires a passphrase")?;
            let (kdf, iterations, memory, parallelism) = db.map_or(
                (rbw::api::KdfType::Pbkdf2, 600_000, None, None),
                |db| {
                    (
                        db.kdf.unwrap_or(rbw::api::KdfType::Pbkdf2),
                        db.iterations.unwrap_or(600_000),
                        db.memory,
                        db.parallelism,
                    )
                },
            );
            let encrypted = crate::import_bitwarden::encrypt_encrypted_json(
                &json_text,
                &passphrase,
                kdf,
                iterations,
                memory,
                parallelism,
            )?;
            write_export_bytes(
                output,
                encrypted.as_bytes(),
                "failed to write encrypted Bitwarden export",
            )
        }
        ExportFormat::BitwardenZip => {
            let (bw, zip_attachments) = exported_vault_to_bw(vault);
            let json_text = serde_json::to_string_pretty(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            let zip_bytes = crate::import_bitwarden::write_zip(
                &json_text,
                &zip_attachments,
            )?;
            write_export_bytes(
                output,
                &zip_bytes,
                "failed to write zip export",
            )
        }
        ExportFormat::BitwardenCsv => {
            let (bw, _attachments) = exported_vault_to_bw(vault);
            let (csv_text, skipped) =
                crate::import_bitwarden::write_csv(&bw)?;
            if skipped > 0 {
                eprintln!(
                    "{} {skipped} entr{} of a type Bitwarden's CSV export \
                     doesn't support (Card/Identity/SSH key) were skipped",
                    style::warning("Warning:", stdout_supports_color()),
                    if skipped == 1 { "y" } else { "ies" },
                );
            }
            write_export_bytes(
                output,
                csv_text.as_bytes(),
                "failed to write CSV export",
            )
        }
    }
}

fn resolve_export_passphrase(
    encrypt: Option<&str>,
) -> anyhow::Result<Option<String>> {
    match encrypt {
        None => Ok(None),
        Some(passphrase) if !passphrase.is_empty() => {
            Ok(Some(passphrase.to_string()))
        }
        Some(_) => resolve_env_or_prompted_passphrase(true).map(Some),
    }
}

pub fn resolve_import_passphrase(
    decrypt: bool,
    decrypt_passphrase: Option<&str>,
) -> anyhow::Result<Option<String>> {
    if let Some(passphrase) = decrypt_passphrase {
        return Ok(Some(passphrase.to_string()));
    }
    if decrypt {
        return resolve_env_or_prompted_passphrase(false).map(Some);
    }
    Ok(None)
}

fn resolve_env_or_prompted_passphrase(
    confirm: bool,
) -> anyhow::Result<String> {
    if let Ok(passphrase) = std::env::var(EXPORT_PASSPHRASE_ENV) {
        if !passphrase.is_empty() {
            return Ok(passphrase);
        }
    }

    if confirm {
        prompt_new_passphrase()
    } else {
        prompt_existing_passphrase()
    }
}

fn prompt_new_passphrase() -> anyhow::Result<String> {
    let first = prompt_hidden_tty("Export passphrase: ")?;
    if first.is_empty() {
        anyhow::bail!("passphrase must not be empty");
    }
    let second = prompt_hidden_tty("Confirm export passphrase: ")?;
    if first != second {
        anyhow::bail!("passphrases did not match");
    }
    Ok(first)
}

fn prompt_existing_passphrase() -> anyhow::Result<String> {
    prompt_hidden_tty("Import passphrase: ")
}

fn prompt_hidden_tty(prompt: &str) -> anyhow::Result<String> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("failed to open /dev/tty for passphrase prompt")?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&tty);
    let original = tcgetattr(fd)?;
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    tcsetattr(fd, &hidden)
        .context("failed to disable terminal echo for passphrase prompt")?;

    let _restore = RestoreEcho { fd, original };

    tty.write_all(prompt.as_bytes())
        .context("failed to write passphrase prompt")?;
    tty.flush().context("failed to flush passphrase prompt")?;

    let mut input = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(&mut tty),
        &mut input,
    )
    .context("failed to read passphrase from /dev/tty")?;
    tty.write_all(b"\n")
        .context("failed to finish passphrase prompt")?;
    tty.flush().context("failed to flush passphrase prompt")?;

    Ok(input.trim_end_matches(['\r', '\n']).to_string())
}

fn tcgetattr(fd: std::os::fd::RawFd) -> std::io::Result<libc::termios> {
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `termios` points to valid uninitialized memory, and `fd` is an
    // open tty fd when this helper is called.
    let rc = unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: successful `tcgetattr` initialized `termios`.
        Ok(unsafe { termios.assume_init() })
    }
}

fn tcsetattr(
    fd: std::os::fd::RawFd,
    termios: &libc::termios,
) -> std::io::Result<()> {
    // SAFETY: `termios` points to a valid termios struct and `fd` is an open
    // tty fd when this helper is called.
    let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, termios) };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn write_export_bytes(
    output: Option<&std::path::Path>,
    bytes: &[u8],
    stdout_context: &'static str,
) -> anyhow::Result<()> {
    output.map_or_else(
        || std::io::stdout().write_all(bytes).context(stdout_context),
        |path| write_secure_output_file(path, bytes),
    )
}

fn write_secure_output_file(
    path: &std::path::Path,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => std::path::Path::new("."),
    };
    let mut file = tempfile::Builder::new()
        .prefix(".rbw-export.")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "failed to open temporary export output near {}",
                path.display()
            )
        })?;
    file.as_file_mut()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| {
            format!("failed to set secure permissions on {}", path.display())
        })?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.as_file_mut()
        .sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    file.persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("failed to persist {}", path.display()))?;
    std::fs::File::open(parent)
        .with_context(|| {
            format!(
                "failed to sync export output directory {}",
                parent.display()
            )
        })?
        .sync_all()
        .with_context(|| {
            format!(
                "failed to sync export output directory {}",
                parent.display()
            )
        })?;
    Ok(())
}

// Packages `value` as pretty-printed JSON named `vault.json` inside an
// in-memory tar.gz archive, returning the compressed bytes.
fn build_export_tar_gz<T: serde::Serialize>(
    value: &T,
) -> anyhow::Result<Vec<u8>> {
    let json = serde_json::to_vec_pretty(value)
        .context("failed to serialize export to JSON")?;

    let mut header = tar::Header::new_gnu();
    header.set_size(u64::try_from(json.len()).unwrap_or(u64::MAX));
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();

    let encoder = flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    );
    let mut builder = tar::Builder::new(encoder);
    builder
        .append_data(&mut header, "vault.json", json.as_slice())
        .context("failed to write vault.json into tar archive")?;
    let encoder = builder
        .into_inner()
        .context("failed to finalize tar archive")?;
    encoder.finish().context("failed to finalize gzip stream")
}

// Symmetrically encrypts `plaintext` with `gpg`, passing the passphrase over
// an inherited pipe fd and streaming the plaintext over stdin so neither the
// passphrase nor the decrypted archive ever hit argv or the filesystem.
fn gpg_symmetric_encrypt(
    passphrase: &str,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let output = run_gpg_with_passphrase(
        [
            "--batch",
            "--yes",
            "--passphrase-fd",
            "3",
            "--symmetric",
            "--cipher-algo",
            "AES256",
            "-o",
            "-",
        ],
        passphrase,
        plaintext.to_vec(),
        "gpg not found on PATH; install GnuPG to use `rbw export --encrypt`",
    )?;

    if !output.status.success() {
        anyhow::bail!(
            "gpg failed to encrypt export: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(output.stdout)
}

fn run_gpg_with_passphrase<const N: usize>(
    args: [&str; N],
    passphrase: &str,
    stdin_data: Vec<u8>,
    not_found_message: &'static str,
) -> anyhow::Result<std::process::Output> {
    let (read_fd, write_fd) =
        rustix::pipe::pipe().context("failed to create passphrase pipe")?;
    let passphrase_fd = std::os::fd::AsRawFd::as_raw_fd(&read_fd);

    {
        let mut writer = std::fs::File::from(write_fd);
        writer
            .write_all(passphrase.as_bytes())
            .and_then(|()| writer.write_all(b"\n"))
            .context("failed to write passphrase to gpg pipe")?;
    }

    let mut child = {
        let mut command = std::process::Command::new("gpg");
        command
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // SAFETY: this runs in the child between fork and exec. It only calls
        // async-signal-safe libc functions (`dup2`/`close`) to map the pipe's
        // read end to fd 3 for gpg's `--passphrase-fd 3`.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(passphrase_fd, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if passphrase_fd != 3 && libc::close(passphrase_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        command.spawn().map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(not_found_message)
            } else {
                anyhow::Error::from(source).context("failed to spawn gpg")
            }
        })?
    };

    drop(read_fd);

    let stdin = child.stdin.take().context("failed to open gpg's stdin")?;
    let stdin_writer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut stdin = stdin;
        stdin.write_all(&stdin_data)
    });

    let output = child
        .wait_with_output()
        .context("failed to wait for gpg to finish")?;
    stdin_writer
        .join()
        .map_err(|_| anyhow::anyhow!("gpg stdin writer thread panicked"))?
        .context("failed to write payload to gpg")?;

    Ok(output)
}

// ===========================================================================
// Import
//
// Reads the JSON produced by `rbw export` (optionally wrapped in a
// gpg-encrypted tar.gz, as produced by `rbw export --encrypt`) and recreates
// its entries and collections in the active account's vault (the active
// account is whatever the global `--account`/`-a` flag or $RBW_ACCOUNT
// resolved to, same as every other command). Deliberately reuses the same
// add/edit/create-collection/create-attachment protocol calls the rest of
// this file already uses instead of hand-rolling anything new.
// ===========================================================================

// Deserialize-only mirrors of the `Decrypted*`/`Exported*` export shapes.
// Kept separate from those (serialize-only) types rather than adding
// `Deserialize` to them, since the wire format mixes representations (field
// types are strings, URI match types are numbers) that are easier to pin
// down explicitly here. Every field that isn't strictly required uses
// `#[serde(default)]` so small differences in a newer/older export (an
// absent `attachments` array, an unrecognized extra field, etc.) degrade
// gracefully instead of failing the whole import.
#[derive(Debug, serde::Deserialize)]
struct ImportedUri {
    uri: String,
    #[serde(default)]
    match_type: Option<rbw::api::UriMatchType>,
}

// Deserialize-only mirror of `DecryptedFido2Credential`, same reasoning as
// `ImportedUri` above.
#[derive(Debug, Default, serde::Deserialize)]
struct ImportedFido2Credential {
    #[serde(default)]
    credential_id: Option<String>,
    #[serde(default)]
    key_type: Option<String>,
    #[serde(default)]
    key_algorithm: Option<String>,
    #[serde(default)]
    key_curve: Option<String>,
    #[serde(default)]
    key_value: Option<String>,
    #[serde(default)]
    rp_id: Option<String>,
    #[serde(default)]
    user_handle: Option<String>,
    #[serde(default)]
    user_name: Option<String>,
    #[serde(default)]
    counter: Option<String>,
    #[serde(default)]
    rp_name: Option<String>,
    #[serde(default)]
    user_display_name: Option<String>,
    #[serde(default)]
    discoverable: Option<String>,
    #[serde(default)]
    creation_date: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ImportedField {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(rename = "type", default)]
    ty: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct ImportedHistoryEntry {
    #[serde(default)]
    last_used_date: String,
    #[serde(default)]
    password: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type")]
enum ImportedData {
    Login {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        totp: Option<String>,
        #[serde(default)]
        uris: Option<Vec<ImportedUri>>,
        #[serde(default)]
        fido2_credentials: Vec<ImportedFido2Credential>,
    },
    Card {
        #[serde(default)]
        cardholder_name: Option<String>,
        #[serde(default)]
        number: Option<String>,
        #[serde(default)]
        brand: Option<String>,
        #[serde(default)]
        exp_month: Option<String>,
        #[serde(default)]
        exp_year: Option<String>,
        #[serde(default)]
        code: Option<String>,
    },
    Identity {
        #[serde(default)]
        title: Option<String>,
        #[serde(default)]
        first_name: Option<String>,
        #[serde(default)]
        middle_name: Option<String>,
        #[serde(default)]
        last_name: Option<String>,
        #[serde(default)]
        address1: Option<String>,
        #[serde(default)]
        address2: Option<String>,
        #[serde(default)]
        address3: Option<String>,
        #[serde(default)]
        city: Option<String>,
        #[serde(default)]
        state: Option<String>,
        #[serde(default)]
        postal_code: Option<String>,
        #[serde(default)]
        country: Option<String>,
        #[serde(default)]
        phone: Option<String>,
        #[serde(default)]
        email: Option<String>,
        #[serde(default)]
        ssn: Option<String>,
        #[serde(default)]
        license_number: Option<String>,
        #[serde(default)]
        passport_number: Option<String>,
        #[serde(default)]
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        #[serde(default)]
        public_key: Option<String>,
        #[serde(default)]
        fingerprint: Option<String>,
        #[serde(default)]
        private_key: Option<String>,
    },
}

// Mirrors the (still-unlanded, as of this writing) `ExportedAttachment`
// shape from `rbw export --attachments`. Kept as raw `serde_json::Value`s on
// `ImportedEntry` rather than a typed `Vec<ImportedAttachment>` so that if
// the real field name/shape ends up slightly different, we still parse the
// rest of the entry -- we just skip (and warn about) the attachments that
// don't match this shape instead of failing to parse the whole entry.
#[derive(Debug, serde::Deserialize)]
struct ImportedAttachment {
    // Not used by `import` (a freshly-uploaded attachment always gets a new
    // id from the server) -- only read by `load_from_file`, which has no
    // server to assign one and needs a stable id to key its side table of
    // attachment bytes by.
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    data_base64: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ImportedEntry {
    // Same story as `ImportedAttachment::id`: `import` doesn't need it (new
    // entries get a fresh id from the server), `load_from_file` does.
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    folder: Option<String>,
    name: String,
    #[serde(flatten)]
    data: ImportedData,
    #[serde(default)]
    fields: Vec<ImportedField>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    history: Vec<ImportedHistoryEntry>,
    #[serde(default)]
    collection_ids: Vec<String>,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    attachments: Vec<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct ImportedCollection {
    #[serde(default)]
    id: Option<String>,
    org_id: String,
    name: String,
}

#[derive(Debug, Default, serde::Deserialize)]
struct ImportedVault {
    #[serde(default)]
    entries: Vec<ImportedEntry>,
    #[serde(default)]
    collections: Vec<ImportedCollection>,
}

// Converts a parsed Bitwarden vault export into the same `ImportedVault`
// shape `rbw export`'s own JSON deserializes into, so the rest of `import`
// (collection creation, entry create/overwrite, attachment upload) doesn't
// need to know which kind of export it came from. `attachments` is only
// `Some` for a "zip (with attachments)" export; the plain/encrypted JSON
// formats never carry attachment bytes at all (confirmed against real
// exports: their items have no `attachments` field, populated or
// otherwise), so entries from those formats never get an `attachments`
// list.
fn bw_vault_to_imported(
    bw: crate::import_bitwarden::BwVault,
    mut attachments: Option<
        std::collections::HashMap<
            String,
            Vec<crate::import_bitwarden::ZipAttachment>,
        >,
    >,
) -> ImportedVault {
    let c = stdout_supports_color();

    let folder_names: std::collections::HashMap<String, String> = bw
        .folders
        .iter()
        .filter_map(|f| f.id.clone().map(|id| (id, f.name.clone())))
        .collect();

    let collections = bw
        .collections
        .into_iter()
        .filter_map(|col| {
            let Some(org_id) = col.organization_id else {
                eprintln!(
                    "{} skipped collection '{}' (no organization id)",
                    style::warning("Warning:", c),
                    col.name,
                );
                return None;
            };
            Some(ImportedCollection {
                id: col.id,
                org_id,
                name: col.name,
            })
        })
        .collect();

    let entries = bw
        .items
        .into_iter()
        .filter_map(|item| {
            let name = item.name.clone();
            let Some(data) = bw_item_data(&item) else {
                eprintln!(
                    "{} skipped '{name}' (unrecognized item type {})",
                    style::warning("Warning:", c),
                    item.ty,
                );
                return None;
            };

            let fields = item
                .fields
                .iter()
                .map(|f| ImportedField {
                    name: f.name.clone(),
                    value: f.value.clone(),
                    ty: f.ty.map(|ty| field_type_str(ty).to_string()),
                })
                .collect();

            let history = item
                .password_history
                .iter()
                .map(|h| ImportedHistoryEntry {
                    last_used_date: h.last_used_date.clone(),
                    password: h.password.clone(),
                })
                .collect();

            let entry_attachments = attachments
                .as_mut()
                .map_or_else(Vec::new, |all| bw_item_attachments(&name, all));

            Some(ImportedEntry {
                id: item.id,
                org_id: item.organization_id,
                folder: item
                    .folder_id
                    .as_deref()
                    .and_then(|id| folder_names.get(id).cloned()),
                name,
                data,
                fields,
                notes: item.notes,
                history,
                collection_ids: item.collection_ids,
                archived: item.archived_date.is_some(),
                deleted: item.deleted_date.is_some(),
                attachments: entry_attachments,
            })
        })
        .collect();

    if let Some(leftover) = &attachments {
        if !leftover.is_empty() {
            eprintln!(
                "{} {} attachment folder(s) in the zip archive didn't \
                 match any item name and were skipped: {}",
                style::warning("Warning:", c),
                leftover.len(),
                leftover.keys().cloned().collect::<Vec<_>>().join(", "),
            );
        }
    }

    ImportedVault {
        entries,
        collections,
    }
}

fn bw_item_data(
    item: &crate::import_bitwarden::BwItem,
) -> Option<ImportedData> {
    match item.ty {
        1 => {
            let login = item.login.as_ref();
            Some(ImportedData::Login {
                username: login.and_then(|l| l.username.clone()),
                password: login.and_then(|l| l.password.clone()),
                totp: login.and_then(|l| l.totp.clone()),
                uris: login.map(|l| {
                    l.uris
                        .iter()
                        .filter_map(|u| {
                            u.uri.clone().map(|uri| ImportedUri {
                                uri,
                                match_type: u.match_type,
                            })
                        })
                        .collect()
                }),
                fido2_credentials: login.map_or_else(Vec::new, |l| {
                    l.fido2_credentials
                        .iter()
                        .map(|c| ImportedFido2Credential {
                            credential_id: c.credential_id.clone(),
                            key_type: c.key_type.clone(),
                            key_algorithm: c.key_algorithm.clone(),
                            key_curve: c.key_curve.clone(),
                            key_value: c.key_value.clone(),
                            rp_id: c.rp_id.clone(),
                            user_handle: c.user_handle.clone(),
                            user_name: c.user_name.clone(),
                            counter: c.counter.clone(),
                            rp_name: c.rp_name.clone(),
                            user_display_name: c.user_display_name.clone(),
                            discoverable: c.discoverable.clone(),
                            creation_date: c.creation_date.clone(),
                        })
                        .collect()
                }),
            })
        }
        2 => Some(ImportedData::SecureNote),
        3 => {
            let card = item.card.as_ref();
            Some(ImportedData::Card {
                cardholder_name: card
                    .and_then(|card| card.cardholder_name.clone()),
                number: card.and_then(|card| card.number.clone()),
                brand: card.and_then(|card| card.brand.clone()),
                exp_month: card.and_then(|card| card.exp_month.clone()),
                exp_year: card.and_then(|card| card.exp_year.clone()),
                code: card.and_then(|card| card.code.clone()),
            })
        }
        4 => {
            let identity = item.identity.as_ref();
            Some(ImportedData::Identity {
                title: identity.and_then(|i| i.title.clone()),
                first_name: identity.and_then(|i| i.first_name.clone()),
                middle_name: identity.and_then(|i| i.middle_name.clone()),
                last_name: identity.and_then(|i| i.last_name.clone()),
                address1: identity.and_then(|i| i.address1.clone()),
                address2: identity.and_then(|i| i.address2.clone()),
                address3: identity.and_then(|i| i.address3.clone()),
                city: identity.and_then(|i| i.city.clone()),
                state: identity.and_then(|i| i.state.clone()),
                postal_code: identity.and_then(|i| i.postal_code.clone()),
                country: identity.and_then(|i| i.country.clone()),
                phone: identity.and_then(|i| i.phone.clone()),
                email: identity.and_then(|i| i.email.clone()),
                ssn: identity.and_then(|i| i.ssn.clone()),
                license_number: identity
                    .and_then(|i| i.license_number.clone()),
                passport_number: identity
                    .and_then(|i| i.passport_number.clone()),
                username: identity.and_then(|i| i.username.clone()),
            })
        }
        5 => {
            let ssh_key = item.ssh_key.as_ref();
            Some(ImportedData::SshKey {
                public_key: ssh_key.and_then(|k| k.public_key.clone()),
                fingerprint: ssh_key.and_then(|k| k.fingerprint.clone()),
                private_key: ssh_key.and_then(|k| k.private_key.clone()),
            })
        }
        _ => None,
    }
}

// Pulls every attachment the zip archive has under `item_name`'s (sanitized)
// folder -- see `import_bitwarden::sanitize_zip_folder_name` -- since a
// real export's per-item `attachments` metadata is always empty even
// inside a zip export, leaving the sanitized display name as the only
// association between a folder and the item that owns it. Two items
// sharing an identical name are therefore inherently ambiguous; whichever
// is converted first claims the shared folder.
fn bw_item_attachments(
    item_name: &str,
    all: &mut std::collections::HashMap<
        String,
        Vec<crate::import_bitwarden::ZipAttachment>,
    >,
) -> Vec<serde_json::Value> {
    let key = crate::import_bitwarden::sanitize_zip_folder_name(item_name);
    let Some(candidates) = all.remove(&key) else {
        return Vec::new();
    };

    candidates
        .into_iter()
        .map(|za| {
            serde_json::json!({
                "file_name": za.file_name,
                "data_base64": rbw::base64::encode(&za.data),
            })
        })
        .collect()
}

// Converts rbw's own decrypted export vault into a Bitwarden `BwVault` --
// the inverse of `bw_vault_to_imported` -- so `rbw export --format
// bitwarden-*` can reuse the same schema plumbing `rbw import` uses. Also
// returns every attachment as (item name, file name, decrypted bytes),
// keyed by name (not id) since that's the only association a zip export
// preserves; only the `bitwarden-zip` format actually embeds these.
fn exported_vault_to_bw(
    vault: &ExportedVault,
) -> (
    crate::import_bitwarden::BwVault,
    Vec<(String, String, Vec<u8>)>,
) {
    let mut folder_ids: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for entry in &vault.entries {
        if let Some(name) = &entry.folder {
            folder_ids
                .entry(name.clone())
                .or_insert_with(|| uuid::Uuid::new_v4().to_string());
        }
    }
    let folders = folder_ids
        .iter()
        .map(|(name, id)| crate::import_bitwarden::BwFolder {
            id: Some(id.clone()),
            name: name.clone(),
        })
        .collect();

    let collections = vault
        .collections
        .iter()
        .map(|c| crate::import_bitwarden::BwCollection {
            id: Some(c.id.clone()),
            organization_id: Some(c.org_id.clone()),
            name: c.name.clone(),
        })
        .collect();

    let mut attachments_out = Vec::new();
    let items = vault
        .entries
        .iter()
        .map(|entry| {
            for attachment in &entry.attachments {
                if let Ok(data) = rbw::base64::decode(&attachment.data_base64)
                {
                    attachments_out.push((
                        entry.name.clone(),
                        attachment.file_name.clone(),
                        data,
                    ));
                }
            }

            let (ty, login, card, identity, ssh_key) =
                bw_data_from_decrypted(&entry.data);

            crate::import_bitwarden::BwItem {
                id: Some(entry.id.clone()),
                organization_id: entry.org_id.clone(),
                folder_id: entry
                    .folder
                    .as_ref()
                    .and_then(|name| folder_ids.get(name).cloned()),
                archived_date: entry.archived.then(|| {
                    humantime::format_rfc3339(std::time::SystemTime::now())
                        .to_string()
                }),
                deleted_date: entry.deleted.then(|| {
                    humantime::format_rfc3339(std::time::SystemTime::now())
                        .to_string()
                }),
                ty,
                name: entry.name.clone(),
                notes: entry.notes.clone(),
                login,
                card,
                identity,
                ssh_key,
                fields: entry
                    .fields
                    .iter()
                    .map(|f| crate::import_bitwarden::BwField {
                        name: f.name.clone(),
                        value: f.value.clone(),
                        ty: f.ty,
                    })
                    .collect(),
                password_history: entry
                    .history
                    .iter()
                    .map(|h| crate::import_bitwarden::BwPasswordHistory {
                        last_used_date: h.last_used_date.clone(),
                        password: h.password.clone(),
                    })
                    .collect(),
                collection_ids: entry.collection_ids.clone(),
            }
        })
        .collect();

    (
        crate::import_bitwarden::BwVault {
            folders,
            collections,
            items,
        },
        attachments_out,
    )
}

#[allow(clippy::type_complexity)]
fn bw_data_from_decrypted(
    data: &DecryptedData,
) -> (
    u16,
    Option<crate::import_bitwarden::BwLogin>,
    Option<crate::import_bitwarden::BwCard>,
    Option<crate::import_bitwarden::BwIdentity>,
    Option<crate::import_bitwarden::BwSshKey>,
) {
    match data {
        DecryptedData::Login {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        } => (
            1,
            Some(crate::import_bitwarden::BwLogin {
                username: username.clone(),
                password: password.clone(),
                totp: totp.clone(),
                uris: uris
                    .as_ref()
                    .map(|us| {
                        us.iter()
                            .map(|u| crate::import_bitwarden::BwUri {
                                uri: Some(u.uri.clone()),
                                match_type: u.match_type,
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                fido2_credentials: fido2_credentials
                    .iter()
                    .map(|c| crate::import_bitwarden::BwFido2Credential {
                        credential_id: c.credential_id.clone(),
                        key_type: c.key_type.clone(),
                        key_algorithm: c.key_algorithm.clone(),
                        key_curve: c.key_curve.clone(),
                        key_value: c.key_value.clone(),
                        rp_id: c.rp_id.clone(),
                        user_handle: c.user_handle.clone(),
                        user_name: c.user_name.clone(),
                        counter: c.counter.clone(),
                        rp_name: c.rp_name.clone(),
                        user_display_name: c.user_display_name.clone(),
                        discoverable: c.discoverable.clone(),
                        creation_date: c.creation_date.clone(),
                    })
                    .collect(),
            }),
            None,
            None,
            None,
        ),
        DecryptedData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => (
            3,
            None,
            Some(crate::import_bitwarden::BwCard {
                cardholder_name: cardholder_name.clone(),
                brand: brand.clone(),
                number: number.clone(),
                exp_month: exp_month.clone(),
                exp_year: exp_year.clone(),
                code: code.clone(),
            }),
            None,
            None,
        ),
        DecryptedData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => (
            4,
            None,
            None,
            Some(crate::import_bitwarden::BwIdentity {
                title: title.clone(),
                first_name: first_name.clone(),
                middle_name: middle_name.clone(),
                last_name: last_name.clone(),
                address1: address1.clone(),
                address2: address2.clone(),
                address3: address3.clone(),
                city: city.clone(),
                state: state.clone(),
                postal_code: postal_code.clone(),
                country: country.clone(),
                phone: phone.clone(),
                email: email.clone(),
                ssn: ssn.clone(),
                license_number: license_number.clone(),
                passport_number: passport_number.clone(),
                username: username.clone(),
            }),
            None,
        ),
        DecryptedData::SecureNote => (2, None, None, None, None),
        DecryptedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => (
            5,
            None,
            None,
            None,
            Some(crate::import_bitwarden::BwSshKey {
                private_key: private_key.clone(),
                public_key: public_key.clone(),
                fingerprint: fingerprint.clone(),
            }),
        ),
    }
}

fn imported_data_to_editable(data: &ImportedData) -> EditableData {
    match data {
        ImportedData::Login {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        } => EditableData::Login {
            username: username.clone(),
            password: password.clone(),
            uris: uris
                .as_ref()
                .map(|v| {
                    v.iter()
                        .map(|u| EditableUri {
                            uri: u.uri.clone(),
                            match_type: u
                                .match_type
                                .map(|mt| uri_match_type_str(mt).to_string()),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            totp: totp.clone(),
            fido2_credentials: fido2_credentials
                .iter()
                .map(|c| EditableFido2Credential {
                    credential_id: c.credential_id.clone(),
                    key_type: c.key_type.clone(),
                    key_algorithm: c.key_algorithm.clone(),
                    key_curve: c.key_curve.clone(),
                    key_value: c.key_value.clone(),
                    rp_id: c.rp_id.clone(),
                    user_handle: c.user_handle.clone(),
                    user_name: c.user_name.clone(),
                    counter: c.counter.clone(),
                    rp_name: c.rp_name.clone(),
                    user_display_name: c.user_display_name.clone(),
                    discoverable: c.discoverable.clone(),
                    creation_date: c.creation_date.clone(),
                })
                .collect(),
        },
        ImportedData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => EditableData::Card {
            cardholder_name: cardholder_name.clone(),
            number: number.clone(),
            brand: brand.clone(),
            exp_month: exp_month.clone(),
            exp_year: exp_year.clone(),
            code: code.clone(),
        },
        ImportedData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => EditableData::Identity {
            title: title.clone(),
            first_name: first_name.clone(),
            middle_name: middle_name.clone(),
            last_name: last_name.clone(),
            address1: address1.clone(),
            address2: address2.clone(),
            address3: address3.clone(),
            city: city.clone(),
            state: state.clone(),
            postal_code: postal_code.clone(),
            country: country.clone(),
            phone: phone.clone(),
            email: email.clone(),
            ssn: ssn.clone(),
            license_number: license_number.clone(),
            passport_number: passport_number.clone(),
            username: username.clone(),
        },
        ImportedData::SecureNote => EditableData::SecureNote,
        ImportedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => EditableData::SshKey {
            private_key: private_key.clone(),
            public_key: public_key.clone(),
            fingerprint: fingerprint.clone(),
        },
    }
}

fn imported_to_editable(imported: &ImportedEntry) -> EditableCipher {
    EditableCipher {
        name: imported.name.clone(),
        folder: imported.folder.clone(),
        notes: imported.notes.clone(),
        data: imported_data_to_editable(&imported.data),
        fields: imported
            .fields
            .iter()
            .map(|f| EditableCustomField {
                name: f.name.clone(),
                value: f.value.clone(),
                ty: f.ty.clone(),
            })
            .collect(),
    }
}

// Mirrors `imported_data_to_editable`, but into `DecryptedData` -- the
// shape `list`/`search`/`tui` already render -- for `--from-file`, which
// treats an export as an already-decrypted, in-memory-only vault instead of
// importing it. Unlike `EditableUri`, `DecryptedUri` keeps `match_type` as
// the native enum rather than a display string, so no conversion needed.
fn imported_data_to_decrypted(data: &ImportedData) -> DecryptedData {
    match data {
        ImportedData::Login {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        } => DecryptedData::Login {
            username: username.clone(),
            password: password.clone(),
            totp: totp.clone(),
            uris: uris.as_ref().map(|v| {
                v.iter()
                    .map(|u| DecryptedUri {
                        uri: u.uri.clone(),
                        match_type: u.match_type,
                    })
                    .collect()
            }),
            fido2_credentials: fido2_credentials
                .iter()
                .map(|c| DecryptedFido2Credential {
                    credential_id: c.credential_id.clone(),
                    key_type: c.key_type.clone(),
                    key_algorithm: c.key_algorithm.clone(),
                    key_curve: c.key_curve.clone(),
                    key_value: c.key_value.clone(),
                    rp_id: c.rp_id.clone(),
                    user_handle: c.user_handle.clone(),
                    user_name: c.user_name.clone(),
                    counter: c.counter.clone(),
                    rp_name: c.rp_name.clone(),
                    user_display_name: c.user_display_name.clone(),
                    discoverable: c.discoverable.clone(),
                    creation_date: c.creation_date.clone(),
                })
                .collect(),
        },
        ImportedData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: cardholder_name.clone(),
            number: number.clone(),
            brand: brand.clone(),
            exp_month: exp_month.clone(),
            exp_year: exp_year.clone(),
            code: code.clone(),
        },
        ImportedData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => DecryptedData::Identity {
            title: title.clone(),
            first_name: first_name.clone(),
            middle_name: middle_name.clone(),
            last_name: last_name.clone(),
            address1: address1.clone(),
            address2: address2.clone(),
            address3: address3.clone(),
            city: city.clone(),
            state: state.clone(),
            postal_code: postal_code.clone(),
            country: country.clone(),
            phone: phone.clone(),
            email: email.clone(),
            ssn: ssn.clone(),
            license_number: license_number.clone(),
            passport_number: passport_number.clone(),
            username: username.clone(),
        },
        ImportedData::SecureNote => DecryptedData::SecureNote,
        ImportedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => DecryptedData::SshKey {
            public_key: public_key.clone(),
            fingerprint: fingerprint.clone(),
            private_key: private_key.clone(),
        },
    }
}

fn imported_history_to_encrypted(
    history: &[ImportedHistoryEntry],
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<Vec<rbw::db::HistoryEntry>> {
    history
        .iter()
        .map(|h| {
            Ok(rbw::db::HistoryEntry {
                last_used_date: h.last_used_date.clone(),
                password: crate::actions::encrypt(
                    &h.password,
                    entry_key,
                    org_id,
                )?,
            })
        })
        .collect()
}

pub fn read_import_input(
    file: Option<&std::path::Path>,
) -> anyhow::Result<Vec<u8>> {
    if let Some(path) = file {
        std::fs::read(path)
            .with_context(|| format!("failed to read {}", path.display()))
    } else {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("failed to read import data from stdin")?;
        Ok(buf)
    }
}

// Decrypts a gpg-encrypted tar.gz archive (as produced by `rbw export
// --encrypt`) and returns the JSON text found inside it. The ciphertext is
// streamed through gpg's stdin (with the passphrase on a dedicated pipe fd)
// and the archive is unpacked entirely in memory, so the decrypted vault
// never touches the filesystem.
fn decrypt_import_archive(
    data: &[u8],
    passphrase: &str,
) -> anyhow::Result<String> {
    let output = run_gpg_with_passphrase(
        ["--batch", "--yes", "--passphrase-fd", "3", "--decrypt"],
        passphrase,
        data.to_vec(),
        "failed to run gpg (is it installed and on $PATH?)",
    )?;
    if !output.status.success() {
        anyhow::bail!(
            "gpg decryption failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    extract_vault_json(&output.stdout)
}

// Extracts the JSON text from an in-memory tar.gz archive: the first
// `*.json` entry, falling back to the first regular file of any kind if
// none has a `.json` extension. `rbw export --encrypt` is expected to wrap
// a single JSON file in the tar.gz, but the exact filename isn't something
// worth hard-coding here.
fn extract_vault_json(targz: &[u8]) -> anyhow::Result<String> {
    let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(targz));
    let mut archive = tar::Archive::new(gz);
    let mut fallback: Option<String> = None;
    let entries = archive
        .entries()
        .context("failed to read the decrypted archive as a tar.gz")?;
    for entry in entries {
        let mut entry = entry
            .context("failed to read the decrypted archive as a tar.gz")?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let is_json = entry.path().ok().is_some_and(|path| {
            path.extension().and_then(std::ffi::OsStr::to_str) == Some("json")
        });
        if !is_json && fallback.is_some() {
            continue;
        }
        let mut contents = String::new();
        entry
            .read_to_string(&mut contents)
            .context("failed to read a file from the decrypted archive")?;
        if is_json {
            return Ok(contents);
        }
        fallback = Some(contents);
    }
    fallback.ok_or_else(|| {
        anyhow::anyhow!("no JSON file found inside the decrypted archive")
    })
}

// Figures out whether `raw` is plain JSON (today's `rbw export` output) or a
// gpg-encrypted tar.gz (`rbw export --encrypt`'s output) and returns the
// JSON text either way.
pub fn load_import_json(
    raw: &[u8],
    decrypt_passphrase: Option<&str>,
) -> anyhow::Result<String> {
    if decrypt_passphrase.is_none() {
        if let Ok(text) = std::str::from_utf8(raw) {
            if serde_json::from_str::<serde_json::Value>(text).is_ok() {
                return Ok(text.to_string());
            }
        }
    }

    if let Some(passphrase) = decrypt_passphrase {
        return decrypt_import_archive(raw, passphrase);
    }

    anyhow::bail!(
        "failed to parse import data as JSON; if this is a gpg-encrypted \
         export archive (from `rbw export --encrypt`), pass --decrypt or \
         --decrypt-passphrase"
    );
}

// If `raw` isn't already resolvable as plain JSON and no passphrase was
// given, this is exactly the shape of rbw's own gpg-encrypted export
// archive (`load_import_json` would otherwise just fail with a "pass
// --decrypt" hint) -- resolve one from RBW_EXPORT_PASSPHRASE or a
// `/dev/tty` prompt instead of erroring, same as `--decrypt` itself and
// `load_from_file`'s existing `--from-file` behavior. Falls through to
// `None` (and `load_import_json`'s existing hard failure) when a
// passphrase was already resolved, `raw` turns out to parse as plain JSON
// on its own, or no tty is available to prompt on -- so a script piping in
// ciphertext without `--decrypt` still fails fast instead of hanging.
pub fn prompt_for_encrypted_export_if_needed(
    raw: &[u8],
    decrypt_passphrase: Option<String>,
) -> Option<String> {
    if decrypt_passphrase.is_some() {
        return decrypt_passphrase;
    }
    if let Ok(text) = std::str::from_utf8(raw) {
        if serde_json::from_str::<serde_json::Value>(text).is_ok() {
            return None;
        }
    }
    resolve_env_or_prompted_passphrase(false).ok()
}

// A vault loaded from an export file for `--from-file` (`list`/`search`/
// `tui`): entries are already decrypted, since that's what the export
// format is. Attachment bytes are kept in a side table keyed by attachment
// id, since `DecryptedAttachment` itself only carries metadata.
pub struct FileVault {
    pub entries: Vec<DecryptedCipher>,
    pub attachment_data: std::collections::HashMap<String, Vec<u8>>,
    // `org_id`/`collection_ids` per entry, keyed by id: `DecryptedCipher`
    // (shared with the live-account paths, where these are tracked on
    // `rbw::db::Entry` instead) has no room for them, but a save still
    // needs to round-trip them for any entry that isn't the one being
    // edited -- otherwise editing one entry would silently drop another's
    // org association.
    pub entry_extra: std::collections::HashMap<String, FileEntryExtra>,
    // Collections aren't editable through `--from-file` (nothing here
    // creates/renames one), but are carried through so a `save_to_file`
    // after editing entries doesn't silently drop them.
    pub collections: Vec<ExportedCollection>,
    // `Some` when the file was gpg-encrypted -- `save_to_file` re-encrypts
    // with the same passphrase instead of re-prompting.
    pub passphrase: Option<String>,
}

#[derive(Clone, Default)]
pub struct FileEntryExtra {
    pub org_id: Option<String>,
    pub collection_ids: Vec<String>,
}

// Loads an export file as a one-off, in-memory, read-only vault: no config,
// no agent, no account touched at all. This deliberately shares the format
// detection and upstream Bitwarden conversion used by `import`, so every
// command accepting `--from-file` understands rbw JSON/gpg archives as well
// as Bitwarden JSON, encrypted JSON, and zip exports.
//
// `passphrase` is the explicit, non-interactive override from `--passphrase`
// (with the old `--from-file-passphrase` spelling retained as an alias); when
// `None`, the passphrase falls back to `$RBW_EXPORT_PASSPHRASE`, then an
// interactive `/dev/tty` prompt.
pub fn load_from_file(
    path: &std::path::Path,
    passphrase: Option<&str>,
) -> anyhow::Result<FileVault> {
    let raw = read_import_input(Some(path))?;
    let mut passphrase = passphrase.map(std::string::ToString::to_string);

    let detected = crate::import_bitwarden::detect_format(&raw)?;
    let vault = match detected {
        crate::import_bitwarden::DetectedFormat::Rbw => {
            let json_text = if std::str::from_utf8(&raw).is_ok_and(|text| {
                serde_json::from_str::<serde_json::Value>(text).is_ok()
            }) {
                String::from_utf8(raw).unwrap()
            } else {
                let resolved = match &passphrase {
                    Some(p) if !p.is_empty() => p.clone(),
                    _ => resolve_env_or_prompted_passphrase(false)?,
                };
                let text = decrypt_import_archive(&raw, &resolved)?;
                passphrase = Some(resolved);
                text
            };
            let vault: ImportedVault = serde_json::from_str(&json_text)
                .context(
                    "failed to parse import data (expected the JSON shape \
                     produced by `rbw export`)",
                )?;
            vault
        }
        crate::import_bitwarden::DetectedFormat::BitwardenJson => {
            let text = std::str::from_utf8(&raw)
                .context("Bitwarden JSON export is not valid UTF-8")?;
            let bw = crate::import_bitwarden::parse_bitwarden_json(text)?;
            bw_vault_to_imported(bw, None)
        }
        crate::import_bitwarden::DetectedFormat::BitwardenEncryptedJson => {
            let resolved = match &passphrase {
                Some(p) if !p.is_empty() => p.clone(),
                _ => resolve_env_or_prompted_passphrase(false)?,
            };
            let text = crate::import_bitwarden::decrypt_encrypted_json(
                &raw, &resolved,
            )?;
            let bw = crate::import_bitwarden::parse_bitwarden_json(&text)?;
            passphrase = Some(resolved);
            bw_vault_to_imported(bw, None)
        }
        crate::import_bitwarden::DetectedFormat::BitwardenZip => {
            let (bw, attachments) = crate::import_bitwarden::parse_zip(&raw)?;
            bw_vault_to_imported(bw, Some(attachments))
        }
    };

    Ok(file_vault_from_imported(&vault, passphrase))
}

fn file_vault_from_imported(
    vault: &ImportedVault,
    passphrase: Option<String>,
) -> FileVault {
    let mut attachment_data = std::collections::HashMap::new();
    let mut entry_extra = std::collections::HashMap::new();
    let entries = vault
        .entries
        .iter()
        .enumerate()
        .map(|(i, imported)| {
            let attachments = imported
                .attachments
                .iter()
                .filter_map(|raw_attachment| {
                    match parse_file_attachment(raw_attachment) {
                        Ok((attachment, data)) => {
                            attachment_data
                                .insert(attachment.id.clone(), data);
                            Some(attachment)
                        }
                        Err(e) => {
                            log::warn!(
                                "couldn't parse an attachment on '{}': {e:#}",
                                imported.name
                            );
                            None
                        }
                    }
                })
                .collect::<Vec<_>>();
            let id = imported
                .id
                .clone()
                .unwrap_or_else(|| format!("from-file-{i}"));
            entry_extra.insert(
                id.clone(),
                FileEntryExtra {
                    org_id: imported.org_id.clone(),
                    collection_ids: imported.collection_ids.clone(),
                },
            );
            DecryptedCipher {
                attachment_metadata: AttachmentMetadata::new(
                    &id,
                    attachments.len(),
                ),
                id,
                folder: imported.folder.clone(),
                name: imported.name.clone(),
                data: imported_data_to_decrypted(&imported.data),
                fields: imported
                    .fields
                    .iter()
                    .map(|f| DecryptedField {
                        name: f.name.clone(),
                        value: f.value.clone(),
                        ty: f.ty.as_deref().and_then(|ty| {
                            parse_field_type(ty)
                                .inspect_err(|e| {
                                    log::warn!(
                                        "skipping an unrecognized field \
                                        type on '{}': {e:#}",
                                        imported.name
                                    );
                                })
                                .ok()
                        }),
                    })
                    .collect(),
                notes: imported.notes.clone(),
                history: imported
                    .history
                    .iter()
                    .map(|h| DecryptedHistoryEntry {
                        last_used_date: h.last_used_date.clone(),
                        password: h.password.clone(),
                    })
                    .collect(),
                attachments,
                archived: imported.archived,
                deleted: imported.deleted,
                account: None,
            }
        })
        .collect();

    let collections = vault
        .collections
        .iter()
        .enumerate()
        .map(|(i, imported)| ExportedCollection {
            id: imported
                .id
                .clone()
                .unwrap_or_else(|| format!("from-file-collection-{i}")),
            org_id: imported.org_id.clone(),
            name: imported.name.clone(),
        })
        .collect();

    FileVault {
        entries,
        attachment_data,
        entry_extra,
        collections,
        passphrase,
    }
}

// Parses one raw attachment JSON value (see `ImportedAttachment`) into a
// `DecryptedAttachment` plus its decoded bytes. A missing id gets a
// synthetic one (stable within this one load, which is all `--from-file`
// needs it for) rather than failing the whole attachment.
fn parse_file_attachment(
    raw: &serde_json::Value,
) -> anyhow::Result<(DecryptedAttachment, Vec<u8>)> {
    let parsed: ImportedAttachment = serde_json::from_value(raw.clone())
        .context("unrecognized attachment shape")?;
    let data_base64 = parsed
        .data_base64
        .context("attachment is missing data_base64")?;
    let data = rbw::base64::decode(&data_base64)
        .context("failed to decode attachment data")?;
    let id = parsed.id.unwrap_or_else(|| {
        format!(
            "from-file-attachment-{}",
            &data_base64[..data_base64.len().min(16)]
        )
    });
    Ok((
        DecryptedAttachment {
            id,
            file_name: parsed.file_name,
            size: None,
            size_name: None,
        },
        data,
    ))
}

// Writes `entries`/`collections` back to `path` in whatever format they
// were loaded in (`format` is `FileVault::format`, and `passphrase` is
// `FileVault::passphrase`/
// `TuiFileVault::passphrase` -- `Some` round-trips back through gpg with
// the same passphrase, `None` writes plain JSON), via the exact same
// tar.gz/gpg/atomic-write pipeline `export()` uses. Attachment bytes
// aren't re-embedded here -- callers that add/keep an attachment already
// have its `ExportedAttachment` (with `data_base64`) to put on the entry
// before calling this.
fn save_to_file(
    path: &std::path::Path,
    entries: Vec<ExportedEntry>,
    collections: Vec<ExportedCollection>,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    // Read the existing file before replacing it. This keeps all existing
    // writeback call sites format-preserving, including TUI edits, without
    // trusting a caller to remember to thread the detected format through.
    let format = crate::import_bitwarden::detect_format(&read_import_input(
        Some(path),
    )?)?;
    let vault = ExportedVault {
        entries,
        collections,
    };
    match format {
        crate::import_bitwarden::DetectedFormat::Rbw => {
            if let Some(passphrase) = passphrase {
                let archive = build_export_tar_gz(&vault)?;
                let encrypted = gpg_symmetric_encrypt(passphrase, &archive)?;
                write_secure_output_file(path, &encrypted)
            } else {
                let mut json = serde_json::to_vec_pretty(&vault)
                    .context("failed to serialize vault to JSON")?;
                json.push(b'\n');
                write_secure_output_file(path, &json)
            }
        }
        crate::import_bitwarden::DetectedFormat::BitwardenJson => {
            let (bw, _) = exported_vault_to_bw(&vault);
            let mut json = serde_json::to_vec_pretty(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            json.push(b'\n');
            write_secure_output_file(path, &json)
        }
        crate::import_bitwarden::DetectedFormat::BitwardenEncryptedJson => {
            let passphrase = passphrase.context(
                "cannot write an encrypted Bitwarden export without a \
                 passphrase",
            )?;
            let (bw, _) = exported_vault_to_bw(&vault);
            let json = serde_json::to_string(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            let encrypted = crate::import_bitwarden::encrypt_encrypted_json(
                &json,
                passphrase,
                rbw::api::KdfType::Pbkdf2,
                600_000,
                None,
                None,
            )?;
            write_secure_output_file(path, encrypted.as_bytes())
        }
        crate::import_bitwarden::DetectedFormat::BitwardenZip => {
            let (bw, attachments) = exported_vault_to_bw(&vault);
            let json = serde_json::to_string_pretty(&bw)
                .context("failed to serialize Bitwarden JSON export")?;
            let zip =
                crate::import_bitwarden::write_zip(&json, &attachments)?;
            write_secure_output_file(path, &zip)
        }
    }
}

// Snapshots `path` to a sibling `.bak` file before the first write of a
// `--from-file` writeback session, so there's always a copy of the
// pre-edit content sitting next to it regardless of how the edits that
// follow turn out.
fn backup_file(path: &std::path::Path) -> anyhow::Result<()> {
    let mut backup = path.as_os_str().to_os_string();
    backup.push(".bak");
    std::fs::copy(path, &backup).with_context(|| {
        format!(
            "failed to back up {} to {}",
            path.display(),
            std::path::Path::new(&backup).display()
        )
    })?;
    Ok(())
}

// The inverse of `load_from_file`'s per-entry mapping: re-attaches
// `org_id`/`collection_ids` (not on `DecryptedCipher` at all -- see
// `FileEntryExtra`) and re-embeds attachment bytes from the side table
// (not on `DecryptedAttachment`, which only carries metadata) so a saved
// entry round-trips through `load_from_file` unchanged if untouched.
fn to_exported_entry(
    decrypted: &DecryptedCipher,
    attachment_data: &std::collections::HashMap<String, Vec<u8>>,
    entry_extra: &std::collections::HashMap<String, FileEntryExtra>,
) -> ExportedEntry {
    let extra = entry_extra.get(&decrypted.id).cloned().unwrap_or_default();
    ExportedEntry {
        id: decrypted.id.clone(),
        org_id: extra.org_id,
        folder: decrypted.folder.clone(),
        name: decrypted.name.clone(),
        data: decrypted.data.clone(),
        fields: decrypted.fields.clone(),
        notes: decrypted.notes.clone(),
        history: decrypted.history.clone(),
        collection_ids: extra.collection_ids,
        archived: decrypted.archived,
        deleted: decrypted.deleted,
        attachments: decrypted
            .attachments
            .iter()
            .map(|a| ExportedAttachment {
                id: a.id.clone(),
                file_name: a
                    .file_name
                    .clone()
                    .unwrap_or_else(|| a.id.clone()),
                data_base64: attachment_data
                    .get(&a.id)
                    .map(rbw::base64::encode)
                    .unwrap_or_default(),
            })
            .collect(),
    }
}

// Uploads any embedded attachments on an imported entry to `entry` (the
// entry's current, post-creation-or-update state). `skip_names` are
// filenames already present on the entry (used by the `--overwrite` path so
// re-running an import doesn't pile up duplicate attachments). Returns
// (restored, failed) counts; a failure to restore one attachment is a
// warning, not a fatal error for the whole import.
fn upload_imported_attachments(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &str,
    entry: &rbw::db::Entry,
    attachments: &[serde_json::Value],
    skip_names: &std::collections::HashSet<String>,
) -> anyhow::Result<(usize, usize)> {
    if attachments.is_empty() {
        return Ok((0, 0));
    }

    let c = stdout_supports_color();
    let mut restored = 0usize;
    let mut failed = 0usize;

    for raw in attachments {
        let parsed: ImportedAttachment =
            match serde_json::from_value(raw.clone()) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "{} couldn't parse an attachment on '{}': {e}",
                        style::warning("Warning:", c),
                        entry.name,
                    );
                    failed += 1;
                    continue;
                }
            };

        let (Some(file_name), Some(data_base64)) =
            (parsed.file_name.as_deref(), parsed.data_base64.as_deref())
        else {
            eprintln!(
                "{} an attachment on '{}' is missing file_name/data_base64; \
                 skipped",
                style::warning("Warning:", c),
                entry.name,
            );
            failed += 1;
            continue;
        };

        if skip_names.contains(file_name) {
            continue;
        }

        let data = match rbw::base64::decode(data_base64) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "{} couldn't decode attachment '{file_name}' on '{}': \
                     {e}",
                    style::warning("Warning:", c),
                    entry.name,
                );
                failed += 1;
                continue;
            }
        };

        let encrypted = crate::actions::encrypt_attachment(
            data,
            file_name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        );
        let (encrypted_data, encrypted_key, encrypted_filename) =
            match encrypted {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "{} couldn't encrypt attachment '{file_name}' on \
                         '{}': {e}",
                        style::warning("Warning:", c),
                        entry.name,
                    );
                    failed += 1;
                    continue;
                }
            };

        match rbw::actions::create_attachment(
            access_token,
            refresh_token,
            &entry.id,
            &encrypted_filename,
            &encrypted_key,
            &encrypted_data,
        ) {
            Ok((new_token, ())) => {
                if let Some(new_token) = new_token {
                    access_token.clone_from(&new_token);
                    db.access_token = Some(new_token);
                    save_db(db)?;
                }
                restored += 1;
            }
            Err(e) => {
                eprintln!(
                    "{} failed to upload attachment '{file_name}' to '{}': \
                     {e}",
                    style::warning("Warning:", c),
                    entry.name,
                );
                failed += 1;
            }
        }
    }

    if restored > 0 {
        crate::actions::sync()?;
    }

    Ok((restored, failed))
}

// Applies the status flags carried by an rbw export after the entry's data
// has been created or updated. The server's import endpoints don't accept
// archive/trash state, and a trashed entry generally needs to be restored
// temporarily before its archive state can be changed.
fn apply_imported_status(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &str,
    id: &str,
    mut archived: bool,
    mut deleted: bool,
    target_archived: bool,
    target_deleted: bool,
) -> anyhow::Result<()> {
    if deleted && (!target_deleted || archived != target_archived) {
        let (new_token, ()) =
            rbw::actions::restore(access_token, refresh_token, id)?;
        if let Some(new_token) = new_token {
            access_token.clone_from(&new_token);
            db.access_token = Some(new_token);
            save_db(db)?;
        }
        deleted = false;
    }

    if archived != target_archived {
        let (new_token, ()) = if target_archived {
            rbw::actions::archive(access_token, refresh_token, id)?
        } else {
            rbw::actions::unarchive(access_token, refresh_token, id)?
        };
        if let Some(new_token) = new_token {
            access_token.clone_from(&new_token);
            db.access_token = Some(new_token);
            save_db(db)?;
        }
        archived = target_archived;
    }

    if deleted != target_deleted {
        let (new_token, ()) =
            rbw::actions::remove(access_token, refresh_token, id)?;
        if let Some(new_token) = new_token {
            access_token.clone_from(&new_token);
            db.access_token = Some(new_token);
            save_db(db)?;
        }
        deleted = true;
    }

    if let Some(entry) = db.entries.iter_mut().find(|entry| entry.id == id) {
        entry.archived = archived;
        entry.deleted = deleted;
    }
    save_db(db)?;

    Ok(())
}

// Creates a brand-new entry for `imported`. Always creates it in the
// personal vault first (`rbw::actions::add` has no organization parameter),
// then -- only if we're a member of the entry's original organization
// locally -- moves it into that organization and assigns the collections we
// were able to map, mirroring what a human would do by hand. Entries whose
// source organization isn't available locally are left as personal-vault
// entries (a `Warning:` line is not printed for this case to avoid being
// noisy on large multi-org imports; see the final summary's "collections
// skipped" count instead).
fn import_create_entry(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    collection_id_map: &std::collections::HashMap<String, String>,
    imported: &ImportedEntry,
) -> anyhow::Result<(usize, usize)> {
    let editable = imported_to_editable(imported);

    let (data, fields, notes) = editable_to_encrypted(&editable, None, None)?;
    let encrypted_name = crate::actions::encrypt(&imported.name, None, None)?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, None, None))
        .transpose()?;

    let folder_id = if let Some(folder_name) = imported.folder.as_deref() {
        resolve_folder_id(db, access_token, refresh_token, folder_name)?
    } else {
        None
    };

    let (new_token, new_entry_id) = rbw::actions::add(
        access_token,
        refresh_token,
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
    )?;
    if let Some(new_token) = new_token {
        access_token.clone_from(&new_token);
        db.access_token = Some(new_token);
        save_db(db)?;
    }

    let target_org = imported
        .org_id
        .as_deref()
        .filter(|org_id| db.protected_org_keys.contains_key(*org_id));

    let has_fields_or_history =
        !imported.fields.is_empty() || !imported.history.is_empty();

    if target_org.is_some() || has_fields_or_history {
        let org_id = target_org;
        let (org_data, org_fields, org_notes) =
            editable_to_encrypted(&editable, None, org_id)?;
        let org_encrypted_name =
            crate::actions::encrypt(&imported.name, None, org_id)?;
        let org_encrypted_notes = org_notes
            .as_deref()
            .map(|n| crate::actions::encrypt(n, None, org_id))
            .transpose()?;
        let history =
            imported_history_to_encrypted(&imported.history, None, org_id)?;

        if let (Some(new_token), ()) = rbw::actions::edit(
            access_token,
            refresh_token,
            &new_entry_id,
            org_id,
            None,
            &org_encrypted_name,
            &org_data,
            &org_fields,
            org_encrypted_notes.as_deref(),
            folder_id.as_deref(),
            &history,
        )? {
            access_token.clone_from(&new_token);
            db.access_token = Some(new_token);
            save_db(db)?;
        }
    }

    if target_org.is_some() {
        let resolved_collections: Vec<String> = imported
            .collection_ids
            .iter()
            .filter_map(|id| collection_id_map.get(id).cloned())
            .collect();
        if !resolved_collections.is_empty() {
            if let (Some(new_token), ()) = rbw::actions::edit_collections(
                access_token,
                refresh_token,
                &new_entry_id,
                &resolved_collections,
            )? {
                access_token.clone_from(&new_token);
                db.access_token = Some(new_token);
                save_db(db)?;
            }
        }
    }

    let attachment_result = if imported.attachments.is_empty() {
        Ok((0, 0))
    } else {
        crate::actions::sync()?;
        *db = load_db()?;
        *access_token = db.access_token.as_ref().unwrap().clone();
        *refresh_token = db.refresh_token.as_ref().unwrap().clone();

        let Some(final_entry) =
            db.entries.iter().find(|e| e.id == new_entry_id).cloned()
        else {
            anyhow::bail!("entry disappeared from the vault after import");
        };

        upload_imported_attachments(
            db,
            access_token,
            refresh_token,
            &final_entry,
            &imported.attachments,
            &std::collections::HashSet::new(),
        )
    }?;

    apply_imported_status(
        db,
        access_token,
        refresh_token,
        &new_entry_id,
        false,
        false,
        imported.archived,
        imported.deleted,
    )?;

    Ok(attachment_result)
}

// Updates an already-existing entry (`--overwrite`) in place: data, fields,
// notes and history are replaced, but the entry keeps its current id,
// organization, and folder (unless `imported` names a different folder) --
// import never moves an existing entry between organizations, to keep
// `--overwrite` predictable.
fn import_overwrite_entry(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    existing: &rbw::db::Entry,
    imported: &ImportedEntry,
) -> anyhow::Result<(usize, usize)> {
    // The edit endpoint may reject trashed entries. Restore one temporarily;
    // `apply_imported_status` below reapplies the source flags afterward.
    if existing.deleted {
        apply_imported_status(
            db,
            access_token,
            refresh_token,
            &existing.id,
            existing.archived,
            true,
            existing.archived,
            false,
        )?;
    }

    let editable = imported_to_editable(imported);

    let org_id = existing.org_id.as_deref();
    let entry_key = existing.key.as_deref();
    let (data, fields, notes) =
        editable_to_encrypted(&editable, entry_key, org_id)?;
    let encrypted_name =
        crate::actions::encrypt(&imported.name, entry_key, org_id)?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, entry_key, org_id))
        .transpose()?;
    let history =
        imported_history_to_encrypted(&imported.history, entry_key, org_id)?;

    let folder_id = if let Some(folder_name) = imported.folder.as_deref() {
        resolve_folder_id(db, access_token, refresh_token, folder_name)?
    } else {
        existing.folder_id.clone()
    };

    if let (Some(new_token), ()) = rbw::actions::edit(
        access_token,
        refresh_token,
        &existing.id,
        org_id,
        entry_key,
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
        &history,
    )? {
        access_token.clone_from(&new_token);
        db.access_token = Some(new_token);
        save_db(db)?;
    }

    let attachment_result = if imported.attachments.is_empty() {
        Ok((0, 0))
    } else {
        crate::actions::sync()?;
        *db = load_db()?;
        *access_token = db.access_token.as_ref().unwrap().clone();
        *refresh_token = db.refresh_token.as_ref().unwrap().clone();

        let Some(refreshed) =
            db.entries.iter().find(|e| e.id == existing.id).cloned()
        else {
            anyhow::bail!("entry disappeared from the vault after update");
        };

        let already_attached: std::collections::HashSet<String> =
            decrypt_cipher(&refreshed).map_or_else(
                |_| std::collections::HashSet::new(),
                |d| {
                    d.attachments
                        .into_iter()
                        .filter_map(|a| a.file_name)
                        .collect()
                },
            );

        upload_imported_attachments(
            db,
            access_token,
            refresh_token,
            &refreshed,
            &imported.attachments,
            &already_attached,
        )
    }?;

    apply_imported_status(
        db,
        access_token,
        refresh_token,
        &existing.id,
        existing.archived,
        false,
        imported.archived,
        imported.deleted,
    )?;

    Ok(attachment_result)
}

// The same (name, username) key `import_vault`'s `existing_index` and the
// bulk-import path's post-creation matching both use to identify an entry
// -- factored out so the two stay in sync.
fn imported_entry_key(imported: &ImportedEntry) -> (String, Option<String>) {
    let username = match &imported.data {
        ImportedData::Login { username, .. } => username.clone(),
        _ => None,
    };
    (imported.name.clone(), username)
}

// The pre-bulk-import creation path, one entry at a time via
// `import_create_entry` -- used directly for entries that can't safely go
// through bulk import (two entries in the same batch sharing a (name,
// username) key, which the bulk endpoints' lack of per-cipher ids can't
// disambiguate afterward), and as the fallback for a batch whose bulk call
// itself failed, or for individual entries the post-bulk verification
// couldn't find.
fn create_entries_individually(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    collection_id_map: &std::collections::HashMap<String, String>,
    entries: &[&ImportedEntry],
    // Appended to each success line (e.g. " (recovered from a dropped bulk-
    // import entry -- already counted, not additional)") -- empty for
    // callers where an individually-created entry isn't otherwise
    // surprising, non-empty for the post-bulk-import retry, where it isn't
    // obvious without this that the entry was already part of the batch
    // total rather than an extra one.
    note: &str,
) -> (usize, Vec<(String, String)>, usize, usize) {
    if entries.is_empty() {
        return (0, Vec::new(), 0, 0);
    }

    let c = stdout_supports_color();
    let mut created = 0usize;
    let mut failed_names = Vec::new();
    let mut attachments_restored = 0usize;
    let mut attachments_failed = 0usize;

    let pb =
        item_progress_bar(u64::try_from(entries.len()).unwrap_or(u64::MAX));
    for imported in entries {
        pb.set_message(fit_to_width(&imported.name, PROGRESS_MSG_WIDTH));
        match import_create_entry(
            db,
            access_token,
            refresh_token,
            collection_id_map,
            imported,
        ) {
            Ok((restored, failed)) => {
                created += 1;
                attachments_restored += restored;
                attachments_failed += failed;
                pb.println(format!(
                    "{} '{}'{note}",
                    style::success("Created", c),
                    imported.name,
                ));
            }
            Err(e) => {
                pb.println(format!(
                    "{} failed to import '{}': {e:#}",
                    style_error("Error:", c),
                    imported.name,
                ));
                failed_names.push((imported.name.clone(), format!("{e:#}")));
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    (
        created,
        failed_names,
        attachments_restored,
        attachments_failed,
    )
}

// Bulk-creates every entry in `entries` (all destined for the same place --
// the personal vault if `org_id` is `None`, otherwise that one
// organization) via a single `/ciphers/import`(-organization) request,
// falling back to `create_entries_individually` wherever bulk import can't
// safely or actually cover an entry. Mirrors `import_create_entry`'s
// behavior exactly (same encryption, same collection/folder resolution,
// same attachment restoration) -- just batched.
//
// Two things force a per-entry fallback despite the bulk call:
// 1. Two entries in this same batch sharing a (name, username) key: the
//    bulk endpoints don't return per-cipher ids, so recovering them
//    afterward means matching newly-appeared entries back to their
//    intended import entry by that same key -- which is ambiguous if two
//    entries in the batch share one. Routed to individual creation before
//    the bulk call is even made.
// 2. An entry intended for the batch that isn't found among the newly-
//    appeared entries after syncing post-bulk-call: either the whole bulk
//    call failed outright, or the server silently dropped that one cipher
//    (Vaultwarden's import handler validates the whole batch up front, but
//    swallows a per-cipher failure during the actual creation loop).
//    Either way, retried individually rather than silently reported as
//    missing.
fn bulk_create_batch(
    db: &mut rbw::db::Db,
    access_token: &mut String,
    refresh_token: &mut String,
    collection_id_map: &std::collections::HashMap<String, String>,
    org_id: Option<&str>,
    entries: &[&ImportedEntry],
) -> anyhow::Result<(usize, Vec<(String, String)>, usize, usize)> {
    if entries.is_empty() {
        return Ok((0, Vec::new(), 0, 0));
    }

    let c = stdout_supports_color();

    // Split off same-batch (name, username) collisions up front -- see
    // point 1 above. `dedup_seen`/`dedup_dupes` are built in one pass so a
    // key appearing 3+ times still routes every occurrence (not just the
    // 2nd-and-later) to the individual path.
    let mut dedup_seen = std::collections::HashSet::new();
    let mut dedup_dupes = std::collections::HashSet::new();
    for imported in entries {
        if !dedup_seen.insert(imported_entry_key(imported)) {
            dedup_dupes.insert(imported_entry_key(imported));
        }
    }
    let (bulk_entries, individual_entries): (Vec<_>, Vec<_>) =
        entries.iter().copied().partition(|imported| {
            !dedup_dupes.contains(&imported_entry_key(imported))
        });

    let mut created = 0usize;
    let mut failed_names = Vec::new();
    let mut attachments_restored = 0usize;
    let mut attachments_failed = 0usize;

    if !individual_entries.is_empty() {
        eprintln!(
            "{} {} entr{} share a name/username with another entry in this \
             batch -- creating {} individually to avoid ambiguity",
            style::warning("Note:", c),
            individual_entries.len(),
            if individual_entries.len() == 1 {
                "y"
            } else {
                "ies"
            },
            if individual_entries.len() == 1 {
                "it"
            } else {
                "them"
            },
        );
        let (c2, f2, ar2, af2) = create_entries_individually(
            db,
            access_token,
            refresh_token,
            collection_id_map,
            &individual_entries,
            "",
        );
        created += c2;
        failed_names.extend(f2);
        attachments_restored += ar2;
        attachments_failed += af2;
    }

    if bulk_entries.is_empty() {
        return Ok((
            created,
            failed_names,
            attachments_restored,
            attachments_failed,
        ));
    }

    // Resolve (or create) every distinct folder name referenced, once --
    // personal-vault entries only; org-owned entries never get a personal
    // folder (Vaultwarden's org-import handler clears it unconditionally).
    let mut folder_ids: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    if org_id.is_none() {
        for imported in &bulk_entries {
            if let Some(folder_name) = imported.folder.as_deref() {
                if !folder_ids.contains_key(folder_name) {
                    let id = resolve_folder_id(
                        db,
                        access_token,
                        refresh_token,
                        folder_name,
                    )?;
                    folder_ids.insert(folder_name.to_string(), id);
                }
            }
        }
    }

    let pb = item_progress_bar(
        u64::try_from(bulk_entries.len()).unwrap_or(u64::MAX),
    );
    let mut cipher_entries = Vec::with_capacity(bulk_entries.len());
    // Indices into `bulk_entries`, not `ImportedEntry` values -- `ImportedEntry`
    // doesn't derive `PartialEq`, and index identity is exact anyway.
    let mut encrypt_failed: std::collections::HashSet<usize> =
        std::collections::HashSet::new();
    for (index, imported) in bulk_entries.iter().enumerate() {
        pb.set_message(fit_to_width(&imported.name, PROGRESS_MSG_WIDTH));

        let result =
            (|| -> anyhow::Result<rbw::actions::ImportCipherEntry> {
                let editable = imported_to_editable(imported);
                let (data, fields, notes) =
                    editable_to_encrypted(&editable, None, org_id)?;
                let encrypted_name =
                    crate::actions::encrypt(&imported.name, None, org_id)?;
                let encrypted_notes = notes
                    .as_deref()
                    .map(|n| crate::actions::encrypt(n, None, org_id))
                    .transpose()?;
                let history = imported_history_to_encrypted(
                    &imported.history,
                    None,
                    org_id,
                )?;
                let folder_id = imported
                    .folder
                    .as_deref()
                    .and_then(|name| folder_ids.get(name).cloned().flatten());
                let collection_ids: Vec<String> = imported
                    .collection_ids
                    .iter()
                    .filter_map(|id| collection_id_map.get(id).cloned())
                    .collect();
                Ok(rbw::actions::ImportCipherEntry {
                    name: encrypted_name,
                    data,
                    fields,
                    notes: encrypted_notes,
                    history,
                    folder_id,
                    collection_ids,
                })
            })();

        match result {
            Ok(cipher_entry) => cipher_entries.push(cipher_entry),
            Err(e) => {
                pb.println(format!(
                    "{} failed to prepare '{}': {e:#}",
                    style_error("Error:", c),
                    imported.name,
                ));
                failed_names.push((imported.name.clone(), format!("{e:#}")));
                encrypt_failed.insert(index);
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    // Entries that failed to even encrypt aren't sent to the server at
    // all, and can't usefully be retried (the same encryption call would
    // just fail again) -- already recorded as failed above. `cipher_entries`
    // was built skipping the same indices, in the same relative order, so
    // it still lines up 1:1 with the filtered `bulk_entries` below.
    let bulk_entries: Vec<&ImportedEntry> = bulk_entries
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !encrypt_failed.contains(index))
        .map(|(_, imported)| imported)
        .collect();
    if bulk_entries.is_empty() {
        return Ok((
            created,
            failed_names,
            attachments_restored,
            attachments_failed,
        ));
    }

    let batch_desc = org_id.map_or_else(
        || "the personal vault".to_string(),
        |oid| format!("organization '{oid}'"),
    );
    eprintln!(
        "{} bulk-creating {} entr{} in {batch_desc}...",
        style::section("Importing:", c),
        bulk_entries.len(),
        if bulk_entries.len() == 1 { "y" } else { "ies" }
    );

    let bulk_result = org_id.map_or_else(
        || {
            rbw::actions::import_ciphers(
                access_token,
                refresh_token,
                &cipher_entries,
            )
        },
        |oid| {
            rbw::actions::import_organization_ciphers(
                access_token,
                refresh_token,
                oid,
                &cipher_entries,
            )
        },
    );

    match bulk_result {
        Err(e) => {
            // The batch call itself failed outright (network error, or the
            // server rejected the whole batch during its up-front
            // validation pass) -- fall back to individual creation for
            // every entry in it, rather than losing the batch.
            eprintln!(
                "{} bulk import failed ({e:#}); falling back to one-by-one \
                 creation for this batch",
                style_error("Warning:", c),
            );
            let (c2, f2, ar2, af2) = create_entries_individually(
                db,
                access_token,
                refresh_token,
                collection_id_map,
                &bulk_entries,
                "",
            );
            return Ok((
                created + c2,
                {
                    failed_names.extend(f2);
                    failed_names
                },
                attachments_restored + ar2,
                attachments_failed + af2,
            ));
        }
        Ok((new_token, ())) => {
            if let Some(new_token) = new_token {
                access_token.clone_from(&new_token);
                db.access_token = Some(new_token);
                save_db(db)?;
            }
        }
    }

    // The bulk endpoints return no per-cipher ids (and don't even
    // guarantee every cipher in the batch was actually created --
    // Vaultwarden silently drops one that fails during its per-cipher
    // creation loop after the batch-level pre-check passes), and
    // attachments need the new cipher's id regardless -- so always resync
    // and match every intended entry back to its real id by (name,
    // username), same key `existing_index` uses.
    let before_ids: std::collections::HashSet<String> =
        db.entries.iter().map(|e| e.id.clone()).collect();
    crate::actions::sync()?;
    *db = load_db()?;
    *access_token = db.access_token.as_ref().unwrap().clone();
    *refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let new_entries: Vec<rbw::db::Entry> = db
        .entries
        .iter()
        .filter(|e| !before_ids.contains(&e.id))
        .cloned()
        .collect();

    let new_index: std::collections::HashMap<
        (String, Option<String>),
        rbw::db::Entry,
    > = {
        let mut requests = BatchRequests::new();
        let plans: Vec<SearchCipherPlan> = new_entries
            .iter()
            .map(|entry| SearchCipherPlan::build(entry, &mut requests))
            .collect();
        let results = if requests.is_empty() {
            Vec::new()
        } else {
            crate::actions::decrypt_batch(requests.into_vec())?
        };
        let mut index = std::collections::HashMap::new();
        for (entry, plan) in new_entries.iter().zip(plans) {
            if let Ok(decrypted) = plan.resolve(&results) {
                index.insert((decrypted.name, decrypted.user), entry.clone());
            }
        }
        index
    };

    let mut retry: Vec<&ImportedEntry> = Vec::new();
    let pb = item_progress_bar(
        u64::try_from(bulk_entries.len()).unwrap_or(u64::MAX),
    );
    for imported in &bulk_entries {
        pb.set_message(fit_to_width(&imported.name, PROGRESS_MSG_WIDTH));

        let Some(new_entry) =
            new_index.get(&imported_entry_key(imported)).cloned()
        else {
            retry.push(imported);
            pb.inc(1);
            continue;
        };

        if !imported.attachments.is_empty() {
            match upload_imported_attachments(
                db,
                access_token,
                refresh_token,
                &new_entry,
                &imported.attachments,
                &std::collections::HashSet::new(),
            ) {
                Ok((restored, failed)) => {
                    attachments_restored += restored;
                    attachments_failed += failed;
                }
                Err(e) => {
                    pb.println(format!(
                        "{} failed to restore attachments for '{}': {e:#}",
                        style_error("Error:", c),
                        imported.name,
                    ));
                    attachments_failed += imported.attachments.len();
                }
            }
        }

        match apply_imported_status(
            db,
            access_token,
            refresh_token,
            &new_entry.id,
            new_entry.archived,
            new_entry.deleted,
            imported.archived,
            imported.deleted,
        ) {
            Ok(()) => {
                created += 1;
                pb.println(format!(
                    "{} '{}'",
                    style::success("Created", c),
                    imported.name,
                ));
            }
            Err(e) => {
                pb.println(format!(
                    "{} failed to restore status for '{}': {e:#}",
                    style_error("Error:", c),
                    imported.name,
                ));
                failed_names.push((imported.name.clone(), format!("{e:#}")));
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    if !retry.is_empty() {
        eprintln!(
            "{} {} of the {} entr{} above weren't found after the bulk \
             import -- retrying {} individually (already counted in the \
             total, not additional)",
            style::warning("Note:", c),
            retry.len(),
            bulk_entries.len(),
            if bulk_entries.len() == 1 { "y" } else { "ies" },
            if retry.len() == 1 { "it" } else { "them" },
        );
        let (c2, f2, ar2, af2) = create_entries_individually(
            db,
            access_token,
            refresh_token,
            collection_id_map,
            &retry,
            " (recovered)",
        );
        created += c2;
        failed_names.extend(f2);
        attachments_restored += ar2;
        attachments_failed += af2;
    }

    Ok((
        created,
        failed_names,
        attachments_restored,
        attachments_failed,
    ))
}

pub fn import(
    file: Option<&std::path::Path>,
    format: crate::import_bitwarden::ImportFormat,
    decrypt: bool,
    decrypt_passphrase: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    overwrite: bool,
) -> anyhow::Result<()> {
    // Resolve the passphrase up front so `--decrypt`'s prompt happens
    // before any input is read (the prompt goes to /dev/tty, so this works
    // even when the archive itself arrives on stdin).
    let decrypt_passphrase =
        resolve_import_passphrase(decrypt, decrypt_passphrase)?;
    let raw = read_import_input(file)?;

    let detected = match format {
        crate::import_bitwarden::ImportFormat::Auto => {
            crate::import_bitwarden::detect_format(&raw)?
        }
        crate::import_bitwarden::ImportFormat::Rbw => {
            crate::import_bitwarden::DetectedFormat::Rbw
        }
        crate::import_bitwarden::ImportFormat::BitwardenJson => {
            crate::import_bitwarden::DetectedFormat::BitwardenJson
        }
        crate::import_bitwarden::ImportFormat::BitwardenEncryptedJson => {
            crate::import_bitwarden::DetectedFormat::BitwardenEncryptedJson
        }
        crate::import_bitwarden::ImportFormat::BitwardenZip => {
            crate::import_bitwarden::DetectedFormat::BitwardenZip
        }
    };

    let vault: ImportedVault = match detected {
        crate::import_bitwarden::DetectedFormat::Rbw => {
            let decrypt_passphrase = prompt_for_encrypted_export_if_needed(
                &raw,
                decrypt_passphrase,
            );
            let json_text =
                load_import_json(&raw, decrypt_passphrase.as_deref())?;
            serde_json::from_str(&json_text).context(
                "failed to parse import data (expected the JSON shape \
                 produced by `rbw export`)",
            )?
        }
        crate::import_bitwarden::DetectedFormat::BitwardenJson => {
            let text = std::str::from_utf8(&raw)
                .context("Bitwarden JSON export is not valid UTF-8")?;
            let bw = crate::import_bitwarden::parse_bitwarden_json(text)?;
            bw_vault_to_imported(bw, None)
        }
        crate::import_bitwarden::DetectedFormat::BitwardenEncryptedJson => {
            let passphrase = decrypt_passphrase.as_deref().context(
                "this looks like a Bitwarden \"Encrypted JSON\" export; \
                 pass --decrypt or --decrypt-passphrase",
            )?;
            let text = crate::import_bitwarden::decrypt_encrypted_json(
                &raw, passphrase,
            )?;
            let bw = crate::import_bitwarden::parse_bitwarden_json(&text)?;
            bw_vault_to_imported(bw, None)
        }
        crate::import_bitwarden::DetectedFormat::BitwardenZip => {
            let (bw, attachments) = crate::import_bitwarden::parse_zip(&raw)?;
            bw_vault_to_imported(bw, Some(attachments))
        }
    };

    import_vault(vault, collection, org, overwrite)
}

// Creates/updates entries and collections in the currently active account
// from an already-parsed `ImportedVault` -- the part of `import` that
// doesn't care which export format the data originally came from. Also
// reused by `mirror_vault`, which builds an `ImportedVault` in memory (via
// `exported_vault_to_bw` + `bw_vault_to_imported`) from a *source account's*
// vault rather than parsing it from a file, but otherwise wants the exact
// same create-or-skip-or-overwrite/collection-creation/attachment-upload
// behavior and summary output.
fn import_vault(
    mut vault: ImportedVault,
    collection: Option<&str>,
    dest_org: Option<&str>,
    overwrite: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    // Case-insensitive by name so the created/updated/skipped log (and the
    // progress bar below) reads in a human-sensible order instead of
    // whatever order the source vault happened to return entries in.
    vault.entries.sort_by_cached_key(|e| e.name.to_lowercase());

    let mut db = load_db()?;
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let mut refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let c = stdout_supports_color();

    // `--dest-org` only disambiguates a `--collection` name that matches
    // more than one collection across different orgs (mirroring how
    // `resolve_collection`'s own `org_id` scoping already works elsewhere);
    // it never restricts anything on its own.
    let dest_org_id = dest_org
        .map(|needle| {
            resolve_organization(&db.organizations, needle)
                .map(|org| org.id.clone())
        })
        .transpose()?;

    // `--collection` redirects every entry into one existing collection,
    // ignoring whatever organization/collection/folder metadata the export
    // carries -- so none of the export's own collections need to be
    // created, and every entry's destination is the same fixed org/
    // collection pair.
    let dest_collection = if let Some(needle) = collection {
        let decrypted = decrypt_collections(&db)?;
        let found =
            resolve_collection(&decrypted, needle, dest_org_id.as_deref())?;
        Some((found.id.clone(), found.org_id.clone()))
    } else {
        None
    };
    if let Some((dest_id, dest_org_id)) = &dest_collection {
        vault.collections.clear();
        for entry in &mut vault.entries {
            entry.org_id = Some(dest_org_id.clone());
            entry.collection_ids = vec![dest_id.clone()];
        }
    }

    let mut collections_created = 0usize;
    let mut collections_reused = 0usize;
    let mut collections_unavailable = 0usize;

    // Existing collections, decrypted once up front: (collection, plaintext
    // name).
    let mut existing_collections: Vec<(rbw::db::Collection, String)> = db
        .collections
        .iter()
        .cloned()
        .map(|col| {
            let name =
                crate::actions::decrypt(&col.name, None, Some(&col.org_id))?;
            Ok((col, name))
        })
        .collect::<anyhow::Result<_>>()?;

    // Maps an imported collection id to the id it has (or now has) in this
    // vault.
    let mut collection_id_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // `vault.collections` is empty when `--collection` was given (nothing
    // to create/reuse), so seed the map directly with the one destination
    // collection every entry now points at.
    if let Some((dest_id, _)) = &dest_collection {
        collection_id_map.insert(dest_id.clone(), dest_id.clone());
    }

    for imported_col in &vault.collections {
        if !db.protected_org_keys.contains_key(&imported_col.org_id) {
            // We're not a member of this organization locally, so we can't
            // create (or assign entries to) its collections.
            collections_unavailable += 1;
            continue;
        }

        if let Some((existing, _)) =
            existing_collections.iter().find(|(col, name)| {
                col.org_id == imported_col.org_id
                    && *name == imported_col.name
            })
        {
            if let Some(orig_id) = &imported_col.id {
                collection_id_map
                    .insert(orig_id.clone(), existing.id.clone());
            }
            collections_reused += 1;
            continue;
        }

        let encrypted_name = crate::actions::encrypt(
            &imported_col.name,
            None,
            Some(&imported_col.org_id),
        )?;
        match rbw::actions::create_collection(
            &access_token,
            &refresh_token,
            &imported_col.org_id,
            &encrypted_name,
        ) {
            Ok((new_token, new_id)) => {
                if let Some(new_token) = new_token {
                    access_token.clone_from(&new_token);
                    db.access_token = Some(new_token);
                    save_db(&db)?;
                }
                if let Some(orig_id) = &imported_col.id {
                    collection_id_map.insert(orig_id.clone(), new_id.clone());
                }
                existing_collections.push((
                    rbw::db::Collection {
                        id: new_id,
                        org_id: imported_col.org_id.clone(),
                        name: encrypted_name,
                    },
                    imported_col.name.clone(),
                ));
                collections_created += 1;
            }
            Err(e) => {
                eprintln!(
                    "{} failed to create collection '{}': {e:#}",
                    style::warning("Warning:", c),
                    imported_col.name,
                );
            }
        }
    }

    if collections_created > 0 {
        crate::actions::sync()?;
        db = load_db()?;
        access_token = db.access_token.as_ref().unwrap().clone();
        refresh_token = db.refresh_token.as_ref().unwrap().clone();
    }

    // Index existing entries by (name, username) so already-imported
    // entries can be detected without recreating them. Login-typed entries
    // are additionally keyed on their username, so two different logins
    // that happen to share a name don't collide with each other. When
    // `--collection`/`--dest-collection` names one destination collection,
    // this is scoped to just that collection's own members -- otherwise an
    // unrelated entry with the same name/username sitting in some other
    // collection (or the personal vault) would count as "already there"
    // and get skipped, leaving the target collection missing it entirely.
    let existing_index = {
        let mut requests = BatchRequests::new();
        let plans: Vec<SearchCipherPlan> = db
            .entries
            .iter()
            .map(|entry| SearchCipherPlan::build(entry, &mut requests))
            .collect();
        let results = if requests.is_empty() {
            Vec::new()
        } else {
            crate::actions::decrypt_batch(requests.into_vec())?
        };
        let mut index: std::collections::HashMap<
            (String, Option<String>),
            rbw::db::Entry,
        > = std::collections::HashMap::new();
        for (entry, plan) in db.entries.iter().zip(plans) {
            if let Some((dest_id, _)) = &dest_collection {
                if !entry.collection_ids.contains(dest_id) {
                    continue;
                }
            }
            if let Ok(decrypted) = plan.resolve(&results) {
                index.insert((decrypted.name, decrypted.user), entry.clone());
            }
        }
        index
    };

    let mut entries_created = 0usize;
    let mut entries_updated = 0usize;
    let mut entries_skipped = 0usize;
    let mut entries_failed = 0usize;
    let mut attachments_restored = 0usize;
    let mut attachments_failed = 0usize;
    let mut skipped_names: Vec<String> = Vec::new();
    let mut failed_names: Vec<(String, String)> = Vec::new();

    // Classify every entry up front: already-exists (skip, or overwrite --
    // handled immediately below, one at a time, same as ever, since there's
    // no bulk *update* endpoint) vs new (grouped by destination -- the
    // personal vault, or one bucket per target organization -- so each
    // group can go through a single `/ciphers/import`(-organization) bulk
    // request in `bulk_create_batch` below instead of one create call per
    // entry).
    let mut to_overwrite: Vec<(&ImportedEntry, rbw::db::Entry)> = Vec::new();
    let mut personal_batch: Vec<&ImportedEntry> = Vec::new();
    let mut org_batches: std::collections::HashMap<
        String,
        Vec<&ImportedEntry>,
    > = std::collections::HashMap::new();

    for imported in &vault.entries {
        let key = imported_entry_key(imported);

        if let Some(existing) = existing_index.get(&key) {
            if overwrite {
                to_overwrite.push((imported, existing.clone()));
            } else {
                eprintln!(
                    "{} '{}' (already exists; use --overwrite to replace)",
                    style::warning("Skipped", c),
                    imported.name,
                );
                entries_skipped += 1;
                skipped_names.push(imported.name.clone());
            }
            continue;
        }

        let target_org = imported
            .org_id
            .as_deref()
            .filter(|org_id| db.protected_org_keys.contains_key(*org_id));
        match target_org {
            Some(org_id) => {
                org_batches
                    .entry(org_id.to_string())
                    .or_default()
                    .push(imported);
            }
            None => personal_batch.push(imported),
        }
    }

    if !to_overwrite.is_empty() {
        let pb = item_progress_bar(
            u64::try_from(to_overwrite.len()).unwrap_or(u64::MAX),
        );
        for (imported, existing) in &to_overwrite {
            pb.set_message(fit_to_width(&imported.name, PROGRESS_MSG_WIDTH));
            match import_overwrite_entry(
                &mut db,
                &mut access_token,
                &mut refresh_token,
                existing,
                imported,
            ) {
                Ok((restored, failed)) => {
                    attachments_restored += restored;
                    attachments_failed += failed;
                    entries_updated += 1;
                    pb.println(format!(
                        "{} '{}'",
                        style::success("Updated", c),
                        imported.name,
                    ));
                }
                Err(e) => {
                    pb.println(format!(
                        "{} failed to import '{}': {e:#}",
                        style_error("Error:", c),
                        imported.name,
                    ));
                    entries_failed += 1;
                    failed_names
                        .push((imported.name.clone(), format!("{e:#}")));
                }
            }
            pb.inc(1);
        }
        pb.finish_and_clear();
    }

    if !personal_batch.is_empty() {
        let (created, failed, restored, att_failed) = bulk_create_batch(
            &mut db,
            &mut access_token,
            &mut refresh_token,
            &collection_id_map,
            None,
            &personal_batch,
        )?;
        entries_created += created;
        entries_failed += failed.len();
        failed_names.extend(failed);
        attachments_restored += restored;
        attachments_failed += att_failed;
    }

    for (org_id, batch) in &org_batches {
        let (created, failed, restored, att_failed) = bulk_create_batch(
            &mut db,
            &mut access_token,
            &mut refresh_token,
            &collection_id_map,
            Some(org_id.as_str()),
            batch,
        )?;
        entries_created += created;
        entries_failed += failed.len();
        failed_names.extend(failed);
        attachments_restored += restored;
        attachments_failed += att_failed;
    }

    eprintln!();
    eprintln!("{}", style::section("Import summary:", c));
    eprintln!(
        "  entries created:      {}",
        style::success(&entries_created.to_string(), c)
    );
    if entries_updated > 0 {
        eprintln!(
            "  entries updated:      {}",
            style::success(&entries_updated.to_string(), c)
        );
    }
    if entries_skipped > 0 {
        eprintln!(
            "  entries skipped:      {}",
            style::warning(&entries_skipped.to_string(), c)
        );
    }
    if entries_failed > 0 {
        eprintln!(
            "  entries failed:       {}",
            style_error(&entries_failed.to_string(), c)
        );
    }
    if attachments_restored > 0 {
        eprintln!(
            "  attachments restored: {}",
            style::success(&attachments_restored.to_string(), c)
        );
    }
    if attachments_failed > 0 {
        eprintln!(
            "  attachments failed:   {}",
            style_error(&attachments_failed.to_string(), c)
        );
    }
    if collections_created > 0 || collections_reused > 0 {
        eprintln!(
            "  collections created:  {collections_created} (reused \
             {collections_reused})"
        );
    }
    if collections_unavailable > 0 {
        eprintln!(
            "  collections skipped:  {} (organization not available \
             locally)",
            style::warning(&collections_unavailable.to_string(), c)
        );
    }

    if !skipped_names.is_empty() {
        eprintln!();
        eprintln!("{}", style::section("Skipped entries:", c));
        for name in &skipped_names {
            eprintln!("  {}", style::warning(name, c));
        }
    }
    if !failed_names.is_empty() {
        eprintln!();
        eprintln!("{}", style::section("Failed entries:", c));
        for (name, err) in &failed_names {
            eprintln!("  {}: {err}", style_error(name, c));
        }
    }

    if entries_failed > 0 {
        anyhow::bail!(
            "{entries_failed} entr{} failed to import",
            if entries_failed == 1 { "y" } else { "ies" }
        );
    }

    Ok(())
}

// The scoped counterpart to `purge_vault` for `mirror --purge-dest
// --dest-collection`: permanently deletes every entry currently assigned to
// `needle` (name or ID) in the active account, via the same per-cipher
// `delete_permanently` primitive `rbw remove --force` uses -- not the
// server's whole-vault purge endpoint, which explicitly skips org/
// collection-owned ciphers and so can't do this. Entries outside this
// collection, and the collection itself, are left untouched.
fn purge_collection_entries(
    needle: &str,
    dest_org: Option<&str>,
) -> anyhow::Result<()> {
    let mut db = load_db()?;
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let dest_org_id = dest_org
        .map(|needle| {
            resolve_organization(&db.organizations, needle)
                .map(|org| org.id.clone())
        })
        .transpose()?;

    let decrypted_collections = decrypt_collections(&db)?;
    let collection = resolve_collection(
        &decrypted_collections,
        needle,
        dest_org_id.as_deref(),
    )?;
    let collection_id = collection.id.clone();
    let collection_name = collection.name.clone();

    let targets: Vec<rbw::db::Entry> = db
        .entries
        .iter()
        .filter(|e| e.collection_ids.contains(&collection_id))
        .cloned()
        .collect();

    let c = stdout_supports_color();
    if targets.is_empty() {
        eprintln!(
            "{} no entries currently in '{collection_name}' -- nothing to \
             purge",
            style::warning("Note:", c)
        );
        return Ok(());
    }

    eprintln!(
        "{} permanently deleting {} entr{} from '{collection_name}'...",
        style_error("Purging:", c),
        targets.len(),
        if targets.len() == 1 { "y" } else { "ies" }
    );

    let mut failed = 0usize;
    let pb =
        item_progress_bar(u64::try_from(targets.len()).unwrap_or(u64::MAX));
    for entry in &targets {
        match rbw::actions::delete_permanently(
            &access_token,
            &refresh_token,
            &entry.id,
        ) {
            Ok((Some(new_token), ())) => {
                access_token.clone_from(&new_token);
                db.access_token = Some(new_token);
                save_db(&db)?;
            }
            Ok((None, ())) => {}
            Err(e) => {
                pb.println(format!(
                    "{} failed to delete an entry in '{collection_name}': \
                     {e:#}",
                    style_error("Error:", c)
                ));
                failed += 1;
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    crate::actions::sync()?;

    if failed > 0 {
        anyhow::bail!(
            "{failed} entr{} in '{collection_name}' failed to purge; \
             destination may be in a mixed state",
            if failed == 1 { "y" } else { "ies" }
        );
    }

    Ok(())
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MirrorConfig {
    mirrors: Vec<MirrorConfigEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MirrorConfigEntry {
    from: String,
    to: String,
    #[serde(default)]
    collection: Option<String>,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    dest_collection: Option<String>,
    #[serde(default)]
    dest_org: Option<String>,
    #[serde(default)]
    attachments: bool,
    #[serde(default)]
    overwrite: bool,
    #[serde(default)]
    purge_dest: bool,
    // When true, a missing source collection means "mirror the whole source
    // vault" instead. This lets callers describe a destination collection
    // that is either a same-named source collection or a full-vault copy.
    #[serde(default)]
    fallback_to_whole_vault: bool,
}

fn load_mirror_config(
    path: &std::path::Path,
) -> anyhow::Result<MirrorConfig> {
    let contents = std::fs::read_to_string(path).with_context(|| {
        format!("failed to read mirror config {}", path.display())
    })?;
    let config = if matches!(
        path.extension().and_then(std::ffi::OsStr::to_str),
        Some("yaml" | "yml")
    ) {
        serde_yaml::from_str(&contents).with_context(|| {
            format!("failed to parse mirror config {}", path.display())
        })?
    } else {
        serde_json::from_str(&contents).with_context(|| {
            format!("failed to parse mirror config {}", path.display())
        })?
    };
    Ok(config)
}

pub fn mirror_vault_config(
    path: &std::path::Path,
    yes: bool,
    password: Option<&str>,
    dry_run: bool,
) -> anyhow::Result<()> {
    let config = load_mirror_config(path)?;
    if config.mirrors.is_empty() {
        anyhow::bail!("mirror config {} contains no mirrors", path.display());
    }

    for (index, mirror) in config.mirrors.iter().enumerate() {
        mirror_vault_config_entry(
            mirror,
            yes,
            password.map(std::string::ToString::to_string),
            dry_run,
        )
        .with_context(|| {
            format!("mirror config entry {} failed", index + 1)
        })?;
    }

    Ok(())
}

fn mirror_vault_config_entry(
    mirror: &MirrorConfigEntry,
    yes: bool,
    password: Option<String>,
    dry_run: bool,
) -> anyhow::Result<()> {
    let (collection, purge_dest) =
        if mirror.fallback_to_whole_vault && mirror.collection.is_some() {
            crate::actions::set_active_account(Some(mirror.from.clone()))?;
            unlock(None, None)?;
            if source_collection_is_present(
                mirror.collection.as_deref().unwrap(),
                mirror.org_id.as_deref(),
            )? {
                (mirror.collection.as_deref(), false)
            } else {
                (None, mirror.purge_dest)
            }
        } else {
            (mirror.collection.as_deref(), mirror.purge_dest)
        };

    mirror_vault_with_options(
        &mirror.from,
        &mirror.to,
        collection,
        mirror.org_id.as_deref(),
        mirror.dest_collection.as_deref(),
        mirror.dest_org.as_deref(),
        mirror.attachments,
        mirror.overwrite,
        purge_dest,
        yes,
        password,
        dry_run,
        true,
    )
}

// `rbw mirror --from A --to B`: copies vault contents from one already-
// configured local account to another, reusing the same export/import
// conversion machinery `rbw export`/`rbw import` are built on, rather than
// reimplementing the separate-CLI-logins-plus-temp-files pipeline the
// standalone `bw-sync.sh` migration script this replaces used. Named
// `mirror` rather than `sync` -- `rbw sync` already means "pull the latest
// vault from the server for the active account", unrelated to copying
// between two accounts.
//
// Builds an `ExportedVault` from the source account entirely in memory
// (`build_exported_vault`, optionally scoped to a single `--collection`
// and/or `--org-id`), converts it through the same `exported_vault_to_bw`
// -> `bw_vault_to_imported` pipeline `rbw export --format bitwarden-json`
// and `rbw import` already use, then feeds the result through the same
// `import_vault` entry-creation logic `rbw import` uses -- so behavior
// (skip-vs-overwrite matching, collection creation/reuse, personal-vault
// fallback for organizations the destination isn't a member of, the
// per-entry summary) is identical to importing an export file, without a
// file ever touching disk.
//
// `--purge-dest` wipes the destination first. For a whole-vault mirror (no
// `--collection`/`--org-id`) it goes through the same `purge_vault`/
// `Action::PurgeVault` path `rbw purge-vault` uses; combined with
// `--dest-collection` it instead permanently deletes only the entries
// currently assigned to that one destination collection (`purge_vault`'s
// own server-side endpoint explicitly skips org/collection-owned ciphers,
// so it can't do this), leaving the rest of the destination untouched.
#[allow(clippy::too_many_arguments)]
pub fn mirror_vault(
    from: &str,
    to: &str,
    collection: Option<&str>,
    org_id: Option<&str>,
    dest_collection: Option<&str>,
    dest_org: Option<&str>,
    attachments: bool,
    overwrite: bool,
    purge_dest: bool,
    yes: bool,
    password: Option<String>,
    dry_run: bool,
) -> anyhow::Result<()> {
    mirror_vault_with_options(
        from,
        to,
        collection,
        org_id,
        dest_collection,
        dest_org,
        attachments,
        overwrite,
        purge_dest,
        yes,
        password,
        dry_run,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn mirror_vault_with_options(
    from: &str,
    to: &str,
    collection: Option<&str>,
    org_id: Option<&str>,
    dest_collection: Option<&str>,
    dest_org: Option<&str>,
    attachments: bool,
    overwrite: bool,
    purge_dest: bool,
    yes: bool,
    password: Option<String>,
    dry_run: bool,
    create_destination_collection: bool,
) -> anyhow::Result<()> {
    if from == to {
        anyhow::bail!("--from and --to must name different accounts");
    }

    if purge_dest && (collection.is_some() || org_id.is_some()) {
        anyhow::bail!(
            "--purge-dest only supports a whole-vault mirror right now; \
             it can't be combined with --collection/--org-id (there's no \
             scoped-purge implementation yet). Run without --purge-dest, \
             or without --collection/--org-id."
        );
    }

    let config = rbw::config::Config::load()?;
    let from_account = config.account(Some(from))?;
    let to_account = config.account(Some(to))?;

    let c = stdout_supports_color();

    // Gather the source vault before asking for confirmation, so the
    // preview shows real counts instead of vague "everything" language.
    crate::actions::set_active_account(Some(from.to_string()))?;
    unlock(None, None)?;
    let vault =
        build_exported_vault(attachments, collection, org_id, true, false)?;

    let entry_count = vault.entries.len();
    let collection_count = vault.collections.len();
    let plural = if entry_count == 1 { "y" } else { "ies" };

    eprintln!("{}", style::section("Mirror plan:", c));
    eprintln!(
        "  from: {} ({})",
        style::name(from, c),
        from_account.email.as_deref().unwrap_or("no email set")
    );
    eprintln!(
        "  to:   {} ({})",
        style::name(to, c),
        to_account.email.as_deref().unwrap_or("no email set")
    );
    if let Some(needle) = collection {
        eprintln!("  scope: collection '{needle}'");
    } else if let Some(org) = org_id {
        eprintln!("  scope: organization '{org}'");
    } else {
        eprintln!("  scope: entire vault");
    }
    if let Some(needle) = dest_org {
        eprintln!("  destination organization: '{needle}'");
    }
    if let Some(needle) = dest_collection {
        eprintln!("  destination collection: '{needle}'");
    }
    eprintln!(
        "  entries to copy: {entry_count} ({collection_count} \
         collection(s))"
    );
    if attachments {
        eprintln!("  attachments: included");
    }
    eprintln!(
        "  existing entries at destination: {}",
        if overwrite {
            "will be overwritten"
        } else {
            "will be skipped"
        }
    );
    if purge_dest {
        if let Some(needle) = dest_collection {
            eprintln!(
                "  {} destination collection '{needle}' (rest of the \
                 destination untouched)",
                style_error("Purge:", c)
            );
        } else {
            eprintln!(
                "  {} destination's entire personal vault",
                style_error("Purge:", c)
            );
        }
    }

    if dry_run {
        eprintln!(
            "\n{} no changes made; the destination account was never \
             touched.",
            style::success("Dry run:", c)
        );
        return Ok(());
    }

    if !yes {
        let prompt = if purge_dest {
            let purge_desc = dest_collection.map_or_else(
                || format!("purge '{to}'"),
                |needle| format!("purge collection '{needle}' in '{to}'"),
            );
            format!(
                "{} this will {purge_desc} and then copy {entry_count} \
                 entr{plural} from '{from}'. This cannot be undone! \
                 Continue?",
                style_error("DANGER:", c),
            )
        } else {
            format!(
                "Copy {entry_count} entr{plural} from '{from}' to '{to}'?"
            )
        };
        if !confirm(&prompt)? {
            return Ok(());
        }
    }

    crate::actions::set_active_account(Some(to.to_string()))?;
    unlock(None, None)?;

    if create_destination_collection {
        if let Some(destination_collection) = dest_collection {
            ensure_destination_collection(destination_collection, dest_org)?;
        }
    }

    if purge_dest {
        if let Some(needle) = dest_collection {
            // Scoped purge: no master-password re-proof needed here (unlike
            // the whole-vault path below) since it's just a loop of ordinary
            // per-cipher permanent deletes, the same primitive `rbw remove
            // --force` uses.
            purge_collection_entries(needle, dest_org)?;
        } else {
            // Already confirmed above (the whole-mirror confirmation covers
            // it), so pass `yes: true` to skip `purge_vault`'s own prompt --
            // but it still requires the master-password re-proof, exactly
            // like a standalone `rbw purge-vault` (`--stdin`-suppliable the
            // same way).
            purge_vault(true, password)?;
        }
    }

    let (bw, attachments_flat) = exported_vault_to_bw(&vault);

    let attachments_map = if attachments {
        let mut map: std::collections::HashMap<
            String,
            Vec<crate::import_bitwarden::ZipAttachment>,
        > = std::collections::HashMap::new();
        for (name, file_name, data) in attachments_flat {
            map.entry(crate::import_bitwarden::sanitize_zip_folder_name(
                &name,
            ))
            .or_default()
            .push(crate::import_bitwarden::ZipAttachment { file_name, data });
        }
        Some(map)
    } else {
        None
    };

    let imported = bw_vault_to_imported(bw, attachments_map);

    import_vault(imported, dest_collection, dest_org, overwrite)
}

// Resolve or create the destination organization/collection named by a
// mirror spec. Keeping this here makes a config-file mirror self-contained;
// callers no longer need a shell preflight that separately runs `org list`,
// `org create`, and `collection create`.
fn ensure_destination_collection(
    collection: &str,
    org: Option<&str>,
) -> anyhow::Result<()> {
    let mut db = load_db()?;
    let org_id = match org {
        Some(needle) => match resolve_organization(&db.organizations, needle)
        {
            Ok(found) => found.id.clone(),
            Err(error)
                if error.to_string().starts_with("no organization found")
                    && uuid::Uuid::parse_str(needle).is_err() =>
            {
                let id = crate::actions::create_org(needle)?;
                crate::actions::sync()?;
                id
            }
            Err(error) => return Err(error),
        },
        None => resolve_org(&db, None)?,
    };

    db = load_db()?;
    let existing = decrypt_collections(&db)?;
    if existing.iter().any(|candidate| {
        candidate.org_id == org_id && candidate.name == collection
    }) {
        return Ok(());
    }

    let encrypted_name =
        crate::actions::encrypt(collection, None, Some(&org_id))?;
    let access_token = db
        .access_token
        .as_ref()
        .context("destination account has no access token")?;
    let refresh_token = db
        .refresh_token
        .as_ref()
        .context("destination account has no refresh token")?;
    let (new_access_token, _) = rbw::actions::create_collection(
        access_token,
        refresh_token,
        &org_id,
        &encrypted_name,
    )?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(&db)?;
    }
    crate::actions::sync()?;
    Ok(())
}

// A collection from the synced database, with its name decrypted.
#[derive(Debug, serde::Serialize)]
struct DecryptedCollection {
    id: String,
    org_id: String,
    name: String,
}

fn decrypt_collections(
    db: &rbw::db::Db,
) -> anyhow::Result<Vec<DecryptedCollection>> {
    db.collections
        .iter()
        .map(|c| {
            let name =
                crate::actions::decrypt(&c.name, None, Some(&c.org_id))
                    .with_context(|| {
                        format!(
                            "failed to decrypt collection name for {}",
                            c.id
                        )
                    })?;
            Ok(DecryptedCollection {
                id: c.id.clone(),
                org_id: c.org_id.clone(),
                name,
            })
        })
        .collect()
}

// Resolve a collection given by name or ID against the synced collection
// list (restricted to `org_id` when given). Mirrors entry lookup: exact ID
// first, then exact name, then a case-insensitive substring fallback, and
// errors listing the candidates when a name is ambiguous.
fn resolve_collection<'a>(
    collections: &'a [DecryptedCollection],
    needle: &str,
    org_id: Option<&str>,
) -> anyhow::Result<&'a DecryptedCollection> {
    let in_org =
        |c: &&DecryptedCollection| org_id.is_none_or(|o| c.org_id == o);

    if let Some(collection) = collections
        .iter()
        .filter(in_org)
        .find(|c| c.id.eq_ignore_ascii_case(needle))
    {
        return Ok(collection);
    }

    let mut matches: Vec<&DecryptedCollection> = collections
        .iter()
        .filter(in_org)
        .filter(|c| c.name == needle)
        .collect();
    if matches.is_empty() {
        let needle_lower = needle.to_lowercase();
        matches = collections
            .iter()
            .filter(in_org)
            .filter(|c| c.name.to_lowercase().contains(&needle_lower))
            .collect();
    }

    match matches[..] {
        [] => Err(anyhow::anyhow!("no collection found for '{needle}'")),
        [collection] => Ok(collection),
        _ => {
            let candidates = matches
                .iter()
                .map(|c| format!("{} ({})", c.name, c.id))
                .collect::<Vec<_>>()
                .join(", ");
            Err(anyhow::anyhow!(
                "multiple collections found for '{needle}': {candidates}; \
                use the collection ID instead"
            ))
        }
    }
}

pub fn list_collections(output: OutputMode) -> anyhow::Result<()> {
    unlock(None, None)?;

    let db = load_db()?;

    let mut collections = decrypt_collections(&db)?;
    collections.sort_by(|a, b| a.name.cmp(&b.name));

    if output_is_structured(output) {
        write_serialized_pretty(
            &collections,
            output,
            "failed to write collections to stdout",
        )?;
    } else if output == OutputMode::Name {
        for collection in &collections {
            println!("{}", collection.name);
        }
    } else {
        let rows = collections
            .iter()
            .map(|c| vec![c.id.clone(), c.name.clone()])
            .collect::<Vec<_>>();
        print_table(
            &[
                TableColumn {
                    header: "id",
                    style: TableColumnStyle::Id,
                },
                TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
            ],
            &rows,
            "",
        )?;
    }

    Ok(())
}

// Unlike `list_collections`, there's no decrypt step here -- organization
// names are plaintext in the sync response (see `db::Organization`'s doc
// comment), so `db.organizations` is already display-ready.
pub fn list_organizations(output: OutputMode) -> anyhow::Result<()> {
    unlock(None, None)?;

    let db = load_db()?;

    let mut organizations = db.organizations;
    organizations.sort_by(|a, b| a.name.cmp(&b.name));

    if output_is_structured(output) {
        write_serialized_pretty(
            &organizations,
            output,
            "failed to write organizations to stdout",
        )?;
    } else if output == OutputMode::Name {
        for org in &organizations {
            println!("{}", org.name);
        }
    } else {
        let rows = organizations
            .iter()
            .map(|o| vec![o.id.clone(), o.name.clone()])
            .collect::<Vec<_>>();
        print_table(
            &[
                TableColumn {
                    header: "id",
                    style: TableColumnStyle::Id,
                },
                TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
            ],
            &rows,
            "",
        )?;
    }

    Ok(())
}

// Moves an org-owned entry back into the personal vault. Bitwarden/
// Vaultwarden's server rejects clearing `organizationId` via a plain
// `PUT /ciphers/{id}` edit ("Organization mismatch. Please resync the
// client before updating the cipher" -- confirmed live against
// bw.brkn.lol), so unlike `import_create_entry`'s personal-to-org move
// (which the server does accept via a plain edit), this direction has to
// go through the same create-then-delete dance the official Bitwarden
// clients use for "clone to individual vault": re-encrypt the entry with
// the personal key, create it as a brand-new personal entry (`add` has no
// org parameter -- it's always personal), copy over history with a
// follow-up edit (safe now, since both sides are personal), and only then
// permanently delete the original org-owned entry. Creating before
// deleting means a failure here leaves a duplicate rather than losing the
// entry. Does not touch attachments (callers must refuse entries that
// have any, since their encryption keys aren't re-wrapped here).
fn move_entry_to_personal(
    entry: &rbw::db::Entry,
    decrypted: &DecryptedCipher,
    access_token: &mut String,
    refresh_token: &str,
    db: &mut rbw::db::Db,
) -> anyhow::Result<()> {
    let editable = decrypted_to_editable(decrypted);

    let (data, fields, notes) = editable_to_encrypted(&editable, None, None)?;
    let encrypted_name = crate::actions::encrypt(&editable.name, None, None)?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, None, None))
        .transpose()?;

    let (new_token, new_entry_id) = rbw::actions::add(
        access_token,
        refresh_token,
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        entry.folder_id.as_deref(),
    )?;
    if let Some(new_token) = new_token {
        access_token.clone_from(&new_token);
        db.access_token = Some(new_token);
        save_db(db)?;
    }

    if !decrypted.history.is_empty() {
        let history = decrypted
            .history
            .iter()
            .map(|h| {
                Ok(rbw::db::HistoryEntry {
                    last_used_date: h.last_used_date.clone(),
                    password: crate::actions::encrypt(
                        &h.password,
                        None,
                        None,
                    )?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        if let (Some(new_token), ()) = rbw::actions::edit(
            access_token,
            refresh_token,
            &new_entry_id,
            None,
            None,
            &encrypted_name,
            &data,
            &fields,
            encrypted_notes.as_deref(),
            entry.folder_id.as_deref(),
            &history,
        )? {
            access_token.clone_from(&new_token);
            db.access_token = Some(new_token);
            save_db(db)?;
        }
    }

    if let (Some(new_token), ()) = rbw::actions::delete_permanently(
        access_token,
        refresh_token,
        &entry.id,
    )? {
        access_token.clone_from(&new_token);
        db.access_token = Some(new_token);
        save_db(db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

// Set the collections one or more entries belong to, addressing entries by
// needle(s) and the collections by name or ID (resolved per entry's own
// organization, since different matched entries could belong to different
// orgs under `--bulk`). Without `--bulk`, exactly one needle must resolve
// to exactly one entry, same as `find_entry` elsewhere; with `--bulk`,
// every needle is matched against every entry it fits (`find_entries_all`),
// previewed, and confirmed once (unless `-y`) before any are touched --
// same convention as `archive --bulk`/`set --bulk`.
//
// `personal: true` (`--personal`) takes a different path entirely: instead
// of a `PUT /ciphers/{id}/collections` call, it fully re-encrypts the
// entry's name/data/fields/notes/history with the account's personal key
// and clears `organizationId` server-side via a normal `edit`, moving the
// entry out of the organization and back into the personal vault --
// mirroring `import_create_entry`'s personal-vault-to-org move, just in
// the opposite direction. Entries with attachments are refused for now:
// attachment encryption keys aren't re-wrapped by this move, so they'd be
// left undecryptable under the new ownership.
#[allow(clippy::too_many_arguments)]
pub fn assign_collections(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    collections: &[String],
    personal: bool,
    bulk: bool,
    yes: bool,
) -> anyhow::Result<()> {
    if !personal && collections.is_empty() {
        anyhow::bail!(
            "either --collection (repeatable) or --personal must be given"
        );
    }

    unlock(None, None)?;

    let mut db = load_db()?;
    let c = stdout_supports_color();

    let targets: Vec<(rbw::db::Entry, DecryptedCipher)> = if bulk {
        let mut any_err = false;
        let mut pending: Vec<(rbw::db::Entry, DecryptedCipher)> = Vec::new();
        for needle in &needles {
            match find_entries_all(
                &db,
                needle,
                user,
                folder,
                None,
                None,
                ignore_case,
            ) {
                Err(e) => {
                    eprintln!("{needle}: {e:#}");
                    any_err = true;
                }
                Ok(entries) => pending.extend(entries),
            }
        }

        let mut seen = std::collections::HashSet::new();
        pending.retain(|(entry, _)| seen.insert(entry.id.clone()));

        if pending.is_empty() {
            if any_err {
                anyhow::bail!("no entries found");
            }
            eprintln!("No matching entries.");
            return Ok(());
        }

        eprintln!(
            "{}",
            style::section(
                if personal {
                    "The following entries will be moved to your personal \
                     vault:"
                } else {
                    "The following entries will be assigned to collections:"
                },
                c
            )
        );
        for (_, decrypted) in &pending {
            eprintln!("  {}", style::name(&decrypted.name, c));
        }
        if !yes && !confirm("Continue?")? {
            return Ok(());
        }
        pending
    } else {
        let [needle] =
            <[Needle; 1]>::try_from(needles).map_err(|needles| {
                anyhow::anyhow!(
                    "expected exactly one needle without --bulk, got {}",
                    needles.len()
                )
            })?;
        let desc = format!(
            "{}{}",
            user.map_or_else(String::new, |s| format!("{s}@")),
            needle
        );
        let entry = find_entry(
            &db,
            vec![needle],
            user,
            folder,
            None,
            None,
            ignore_case,
            force_exact,
        )
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
        vec![entry]
    };

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();
    let all_collections = decrypt_collections(&db)?;

    let mut failed = 0_usize;
    let pb =
        item_progress_bar(u64::try_from(targets.len()).unwrap_or(u64::MAX));
    for (entry, decrypted) in &targets {
        pb.set_message(fit_to_width(&decrypted.name, PROGRESS_MSG_WIDTH));

        if entry.org_id.is_none() {
            pb.println(format!(
                "{} '{}' is {}",
                style_error("Error:", c),
                decrypted.name,
                if personal {
                    "already in your personal vault"
                } else {
                    "not owned by an organization, so it cannot be \
                     assigned to collections"
                },
            ));
            failed += 1;
            pb.inc(1);
            continue;
        }

        if personal {
            if !entry.attachments.is_empty() {
                pb.println(format!(
                    "{} '{}' has attachments, which aren't re-keyed by \
                     this move yet -- refusing to move it to the personal \
                     vault",
                    style_error("Error:", c),
                    decrypted.name,
                ));
                failed += 1;
                pb.inc(1);
                continue;
            }

            match move_entry_to_personal(
                entry,
                decrypted,
                &mut access_token,
                &refresh_token,
                &mut db,
            ) {
                Ok(()) => {
                    pb.println(format!(
                        "{} {} to your personal vault",
                        style::success("Moved", c),
                        style::name(&decrypted.name, c),
                    ));
                }
                Err(e) => {
                    pb.println(format!(
                        "{} failed to move '{}': {e:#}",
                        style_error("Error:", c),
                        decrypted.name,
                    ));
                    failed += 1;
                }
            }
            pb.inc(1);
            continue;
        }

        let org_id = entry.org_id.as_deref().unwrap();
        let mut collection_ids = Vec::new();
        let mut collection_names = Vec::new();
        let mut resolve_failed = false;
        for needle in collections {
            match resolve_collection(&all_collections, needle, Some(org_id)) {
                Ok(collection) => {
                    if !collection_ids.contains(&collection.id) {
                        collection_ids.push(collection.id.clone());
                        collection_names.push(collection.name.clone());
                    }
                }
                Err(e) => {
                    pb.println(format!(
                        "{} '{}': {e:#}",
                        style_error("Error:", c),
                        decrypted.name,
                    ));
                    resolve_failed = true;
                    break;
                }
            }
        }
        if resolve_failed {
            failed += 1;
            pb.inc(1);
            continue;
        }

        match rbw::actions::edit_collections(
            &access_token,
            &refresh_token,
            &entry.id,
            &collection_ids,
        ) {
            Ok((new_access_token, ())) => {
                if let Some(new_access_token) = new_access_token {
                    access_token.clone_from(&new_access_token);
                    db.access_token = Some(new_access_token);
                    save_db(&db)?;
                }
                pb.println(format!(
                    "{} {} to {}",
                    style::success("Assigned", c),
                    style::name(&decrypted.name, c),
                    collection_names
                        .iter()
                        .map(|name| style::name(name, c))
                        .collect::<Vec<_>>()
                        .join(", "),
                ));
            }
            Err(e) => {
                pb.println(format!(
                    "{} failed to assign '{}': {e:#}",
                    style_error("Error:", c),
                    decrypted.name,
                ));
                failed += 1;
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    crate::actions::sync()?;

    if failed > 0 {
        anyhow::bail!(
            "{failed} entr{} failed to be assigned",
            if failed == 1 { "y" } else { "ies" }
        );
    }

    Ok(())
}

// The complement to `assign_collections`: removes the given collections
// (by name or ID, resolved per entry's own organization) from an entry
// that stays in the organization, rather than replacing its whole
// collection list. With no `--collection` given at all, removes every
// collection the entry currently belongs to, leaving it org-owned but
// unassigned to any collection -- distinct from `assign --personal`, which
// actually moves the entry out of the organization entirely. Same
// `--bulk`/preview/confirm convention as `assign_collections`.
#[allow(clippy::too_many_arguments)]
pub fn unassign_collections(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
    collections: &[String],
    bulk: bool,
    yes: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let c = stdout_supports_color();

    let targets: Vec<(rbw::db::Entry, DecryptedCipher)> = if bulk {
        let mut any_err = false;
        let mut pending: Vec<(rbw::db::Entry, DecryptedCipher)> = Vec::new();
        for needle in &needles {
            match find_entries_all(
                &db,
                needle,
                user,
                folder,
                None,
                None,
                ignore_case,
            ) {
                Err(e) => {
                    eprintln!("{needle}: {e:#}");
                    any_err = true;
                }
                Ok(entries) => pending.extend(entries),
            }
        }

        let mut seen = std::collections::HashSet::new();
        pending.retain(|(entry, _)| seen.insert(entry.id.clone()));

        if pending.is_empty() {
            if any_err {
                anyhow::bail!("no entries found");
            }
            eprintln!("No matching entries.");
            return Ok(());
        }

        eprintln!(
            "{}",
            style::section(
                if collections.is_empty() {
                    "The following entries will be removed from all their \
                     collections:"
                } else {
                    "The following entries will be removed from the given \
                     collections:"
                },
                c
            )
        );
        for (_, decrypted) in &pending {
            eprintln!("  {}", style::name(&decrypted.name, c));
        }
        if !yes && !confirm("Continue?")? {
            return Ok(());
        }
        pending
    } else {
        let [needle] =
            <[Needle; 1]>::try_from(needles).map_err(|needles| {
                anyhow::anyhow!(
                    "expected exactly one needle without --bulk, got {}",
                    needles.len()
                )
            })?;
        let desc = format!(
            "{}{}",
            user.map_or_else(String::new, |s| format!("{s}@")),
            needle
        );
        let entry = find_entry(
            &db,
            vec![needle],
            user,
            folder,
            None,
            None,
            ignore_case,
            force_exact,
        )
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
        vec![entry]
    };

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();
    let all_collections = decrypt_collections(&db)?;

    let mut failed = 0_usize;
    let pb =
        item_progress_bar(u64::try_from(targets.len()).unwrap_or(u64::MAX));
    for (entry, decrypted) in &targets {
        pb.set_message(fit_to_width(&decrypted.name, PROGRESS_MSG_WIDTH));

        let Some(org_id) = entry.org_id.as_deref() else {
            pb.println(format!(
                "{} '{}' is not owned by an organization, so it has no \
                 collections to remove",
                style_error("Error:", c),
                decrypted.name,
            ));
            failed += 1;
            pb.inc(1);
            continue;
        };

        let new_ids: Vec<String> = if collections.is_empty() {
            Vec::new()
        } else {
            let mut remove_ids = Vec::new();
            let mut resolve_failed = false;
            for needle in collections {
                match resolve_collection(
                    &all_collections,
                    needle,
                    Some(org_id),
                ) {
                    Ok(collection) => remove_ids.push(collection.id.clone()),
                    Err(e) => {
                        pb.println(format!(
                            "{} '{}': {e:#}",
                            style_error("Error:", c),
                            decrypted.name,
                        ));
                        resolve_failed = true;
                        break;
                    }
                }
            }
            if resolve_failed {
                failed += 1;
                pb.inc(1);
                continue;
            }
            entry
                .collection_ids
                .iter()
                .filter(|id| !remove_ids.contains(id))
                .cloned()
                .collect()
        };

        match rbw::actions::edit_collections(
            &access_token,
            &refresh_token,
            &entry.id,
            &new_ids,
        ) {
            Ok((new_access_token, ())) => {
                if let Some(new_access_token) = new_access_token {
                    access_token.clone_from(&new_access_token);
                    db.access_token = Some(new_access_token);
                    save_db(&db)?;
                }
                pb.println(format!(
                    "{} {} from {}",
                    style::success("Removed", c),
                    style::name(&decrypted.name, c),
                    if collections.is_empty() {
                        "all collections".to_string()
                    } else {
                        collections.join(", ")
                    },
                ));
            }
            Err(e) => {
                pb.println(format!(
                    "{} failed to unassign '{}': {e:#}",
                    style_error("Error:", c),
                    decrypted.name,
                ));
                failed += 1;
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();

    crate::actions::sync()?;

    if failed > 0 {
        anyhow::bail!(
            "{failed} entr{} failed to be unassigned",
            if failed == 1 { "y" } else { "ies" }
        );
    }

    Ok(())
}

pub fn create_collection(
    name: &str,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let encrypted_name = crate::actions::encrypt(name, None, Some(&org_id))?;

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let (new_access_token, id) = rbw::actions::create_collection(
        access_token,
        refresh_token,
        &org_id,
        &encrypted_name,
    )?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    println!("{id}");

    Ok(())
}

pub fn delete_collection(
    collection: &str,
    org_id: Option<&str>,
    yes: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;
    let all_collections = decrypt_collections(&db)?;
    let collection =
        resolve_collection(&all_collections, collection, Some(&org_id))?;

    if !yes
        && !confirm(&format!(
            "Delete collection {}?",
            style::name(&collection.name, stdout_supports_color())
        ))?
    {
        return Ok(());
    }

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    if let (Some(access_token), ()) = rbw::actions::delete_collection(
        access_token,
        refresh_token,
        &org_id,
        &collection.id,
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

// Permanently deletes every entry in a collection, leaving the (now empty)
// collection itself and everything outside it untouched -- the standalone,
// user-facing counterpart to `purge_collection_entries` (which `mirror
// --purge-dest --dest-collection` already calls, under its own whole-
// mirror confirmation). Confirms here instead, matching `purge-vault`/
// `collection delete`'s gating convention, since this has no other prompt
// covering it.
pub fn purge_collection(
    collection: &str,
    org_id: Option<&str>,
    yes: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;
    let all_collections = decrypt_collections(&db)?;
    let resolved =
        resolve_collection(&all_collections, collection, Some(&org_id))?;
    let collection_id = resolved.id.clone();
    let collection_name = resolved.name.clone();

    let count = db
        .entries
        .iter()
        .filter(|e| e.collection_ids.contains(&collection_id))
        .count();

    let c = stdout_supports_color();
    if count == 0 {
        eprintln!(
            "{} no entries currently in '{collection_name}' -- nothing to \
             purge",
            style::warning("Note:", c)
        );
        return Ok(());
    }

    if !yes {
        let prompt = format!(
            "{} this will permanently delete {count} entr{} from \
             collection '{collection_name}'. This cannot be undone! \
             Continue?",
            style_error("DANGER:", c),
            if count == 1 { "y" } else { "ies" }
        );
        if !confirm(&prompt)? {
            return Ok(());
        }
    }

    purge_collection_entries(&collection_id, None)
}

// Organization names are plaintext (unlike collection names, which are
// encrypted with the org key -- see the `Organization` doc comment in
// db.rs), so no `crate::actions::encrypt` call is needed here. The server
// requires billing_email on every update even though this only ever
// changes the name; there's nowhere to read the org's *current* billing
// email back from (the locally-cached `Organization` only has id/name), so
// this just passes through the active account's own email -- fine for the
// common case of a self-hosted instance where the account owns the org it's
// renaming.
pub fn rename_org(org_id: Option<&str>, name: &str) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let config = rbw::config::Config::load()?;
    let account =
        config.account(crate::actions::current_account().as_deref())?;
    let billing_email = account_email(&account)?;

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    if let (Some(access_token), ()) = rbw::actions::rename_org(
        access_token,
        refresh_token,
        &org_id,
        name,
        billing_email,
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn rename_collection(
    collection: &str,
    org_id: Option<&str>,
    name: &str,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;
    let all_collections = decrypt_collections(&db)?;
    let collection =
        resolve_collection(&all_collections, collection, Some(&org_id))?;

    let encrypted_name = crate::actions::encrypt(name, None, Some(&org_id))?;

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    if let (Some(access_token), ()) = rbw::actions::rename_collection(
        access_token,
        refresh_token,
        &org_id,
        &collection.id,
        &encrypted_name,
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

const EDIT: rbw::api::CollectionUser = rbw::api::CollectionUser {
    id: String::new(),
    read_only: false,
    hide_passwords: false,
    manage: false,
};

const MANAGE: rbw::api::CollectionUser = rbw::api::CollectionUser {
    id: String::new(),
    read_only: false,
    hide_passwords: false,
    manage: true,
};

fn perm_rank(u: &rbw::api::CollectionUser) -> u8 {
    if u.manage {
        return 4;
    }
    match (u.read_only, u.hide_passwords) {
        (false, false) => 3,
        (false, true) => 2,
        (true, false) => 1,
        (true, true) => 0,
    }
}

fn perm_level_name(u: &rbw::api::CollectionUser) -> &'static str {
    match perm_rank(u) {
        4 => "manage",
        3 => "edit",
        2 => "edit-no-pw",
        1 => "view",
        _ => "view-no-pw",
    }
}

fn same_flags(
    a: &rbw::api::CollectionUser,
    b: &rbw::api::CollectionUser,
) -> bool {
    a.read_only == b.read_only
        && a.hide_passwords == b.hide_passwords
        && a.manage == b.manage
}

fn normalize_collection_name(name: &str) -> anyhow::Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('/')
        || trimmed.ends_with('/')
    {
        anyhow::bail!("collection name is empty or has a leading/trailing slash: {name:?}");
    }
    Ok(trimmed.to_string())
}

// Resolve an organization given by name or ID against the account's
// organization list (`db.organizations`, already plaintext -- see the
// comment on that field). Mirrors `resolve_collection`: exact ID first,
// then exact name, then a case-insensitive substring fallback, erroring
// when a name is ambiguous.
fn resolve_organization<'a>(
    organizations: &'a [rbw::db::Organization],
    needle: &str,
) -> anyhow::Result<&'a rbw::db::Organization> {
    if let Some(org) = organizations
        .iter()
        .find(|o| o.id.eq_ignore_ascii_case(needle))
    {
        return Ok(org);
    }

    let mut matches: Vec<&rbw::db::Organization> =
        organizations.iter().filter(|o| o.name == needle).collect();
    if matches.is_empty() {
        let needle_lower = needle.to_lowercase();
        matches = organizations
            .iter()
            .filter(|o| o.name.to_lowercase().contains(&needle_lower))
            .collect();
    }

    match matches[..] {
        [] => Err(anyhow::anyhow!("no organization found for '{needle}'")),
        [org] => Ok(org),
        _ => {
            let candidates = matches
                .iter()
                .map(|o| format!("{} ({})", o.name, o.id))
                .collect::<Vec<_>>()
                .join(", ");
            Err(anyhow::anyhow!(
                "multiple organizations found for '{needle}': {candidates}; \
                use the organization ID instead"
            ))
        }
    }
}

// Resolve `--collection`/`--org` (name or ID) from the `find`-family
// commands (get/show/edit/... and list/search) into concrete IDs for
// `entry_in_collection_org_scope`. `--org` alone scopes by organization;
// `--collection` (optionally combined with `--org` to disambiguate a name
// shared across orgs, same as `resolve_collection`'s own `org_id` scoping)
// resolves to one specific collection -- its own org is returned instead of
// the raw `--org` needle in that case, since the collection already pins it
// down more precisely.
fn resolve_entry_scope(
    db: &rbw::db::Db,
    collection: Option<&str>,
    org: Option<&str>,
) -> anyhow::Result<(Option<String>, Option<String>)> {
    let org_id = org
        .map(|needle| {
            resolve_organization(&db.organizations, needle)
                .map(|found| found.id.clone())
        })
        .transpose()?;

    if let Some(needle) = collection {
        let decrypted = decrypt_collections(db)?;
        let found =
            resolve_collection(&decrypted, needle, org_id.as_deref())?;
        Ok((Some(found.id.clone()), Some(found.org_id.clone())))
    } else {
        Ok((None, org_id))
    }
}

fn source_collection_is_present(
    collection: &str,
    org: Option<&str>,
) -> anyhow::Result<bool> {
    let db = load_db()?;
    match resolve_entry_scope(&db, Some(collection), org) {
        Ok((Some(_), _)) => Ok(true),
        Err(error)
            if error.to_string().starts_with("no collection found") =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
        Ok((None, _)) => Ok(false),
    }
}

// Resolve the target organization: the given `--org-id` (validated), or
// auto-detected when the vault belongs to exactly one org. The org universe
// is every org key delivered by sync, plus any org referenced by a synced
// collection (for older local dbs that predate the org key list).
fn resolve_org(
    db: &rbw::db::Db,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut org_ids: std::collections::BTreeSet<&str> =
        db.protected_org_keys.keys().map(String::as_str).collect();
    org_ids.extend(db.collections.iter().map(|c| c.org_id.as_str()));
    org_id.map_or_else(
        || match org_ids.len() {
            0 => Err(anyhow::anyhow!("no organization found in vault")),
            1 => Ok((*org_ids.iter().next().unwrap()).to_string()),
            _ => Err(anyhow::anyhow!(
                "multiple organizations found ({}); pass --org-id",
                org_ids.iter().copied().collect::<Vec<_>>().join(", ")
            )),
        },
        |o| {
            if org_ids.contains(o) {
                Ok(o.to_string())
            } else {
                Err(anyhow::anyhow!("org {o} not found in this vault"))
            }
        },
    )
}

fn parse_org_role(role: &str) -> anyhow::Result<i32> {
    match role.to_lowercase().as_str() {
        "owner" => Ok(0),
        "admin" => Ok(1),
        "user" => Ok(2),
        "manager" => Ok(3),
        _ => anyhow::bail!(
            "invalid role '{role}' (expected owner, admin, user, or manager)"
        ),
    }
}

// Invites a user by email into an org. No key material changes hands here
// Pulls organizationId/organizationUserId/token out of a pasted invite
// link, tolerating the `#/accept-organization/?...` fragment-based query
// string the web vault uses (a plain URL parse would treat everything
// after `#` as an opaque fragment and miss the query params inside it).
fn parse_accept_org_url(
    url: &str,
) -> anyhow::Result<(String, String, String)> {
    let query = url.rsplit_once('?').map(|(_, q)| q).ok_or_else(|| {
        anyhow::anyhow!("couldn't find a query string in the invite URL")
    })?;

    let mut org_id = None;
    let mut user_id = None;
    let mut token = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "organizationId" => org_id = Some(value.into_owned()),
            "organizationUserId" => user_id = Some(value.into_owned()),
            "token" => token = Some(value.into_owned()),
            _ => {}
        }
    }

    Ok((
        org_id.context("invite URL is missing organizationId")?,
        user_id.context("invite URL is missing organizationUserId")?,
        token.context("invite URL is missing token")?,
    ))
}

// Accepts an org invite, called by the invitee using either the whole
// invite link or the org id/user id/token from it individually -- not
// `resolve_org`, since an invited-but-unaccepted account generally has no
// other way to know any of that (it isn't a member yet, so it doesn't
// show up in `rbw org list`/db.protected_org_keys locally).
pub fn accept_org_invite(
    url: Option<&str>,
    org_id: Option<&str>,
    user_id: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    let (org_id, user_id, token) = if let Some(url) = url {
        parse_accept_org_url(url)?
    } else {
        (
            org_id
                .context("--org-id is required without --url")?
                .to_string(),
            user_id
                .context("--user-id is required without --url")?
                .to_string(),
            token
                .context("--token is required without --url")?
                .to_string(),
        )
    };

    unlock(None, None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let (new_access_token, ()) = rbw::actions::accept_org_invite(
        access_token,
        refresh_token,
        &org_id,
        &user_id,
        &token,
    )?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(&db)?;
    }

    eprintln!(
        "{}",
        style::success(
            "Accepted the organization invite.",
            stdout_supports_color(),
        ),
    );

    Ok(())
}

// Creates a new organization with the current account as its (initial,
// and at creation time only) owner. Agent-mediated -- see
// `create_org`'s comment in `rbw-agent/actions.rs` for why.
pub fn create_org(name: &str) -> anyhow::Result<()> {
    unlock(None, None)?;

    let id = crate::actions::create_org(name)?;

    eprintln!(
        "{} organization '{name}' ({id})",
        style::success("Created", stdout_supports_color()),
    );

    Ok(())
}

// Permanently deletes an entire organization -- same danger class as
// `purge_vault`, so it's gated the same way: a strong confirmation
// (`-y`/`--yes` to skip) plus the master-password re-entry itself
// (`--stdin` to skip that too).
pub fn delete_org(
    org_id: Option<&str>,
    yes: bool,
    password: Option<String>,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let c = stdout_supports_color();
    let prompt = format!(
        "{} this will permanently delete the organization {} and \
         everything in it. This cannot be undone! Continue?",
        style_error("DANGER:", c),
        style::name(&org_id, c),
    );
    if !yes && !confirm(&prompt)? {
        return Ok(());
    }

    crate::actions::delete_org(&org_id, password)?;

    eprintln!("{}", style::success("Organization deleted.", c));

    Ok(())
}

pub fn invite_org_user(
    org_id: Option<&str>,
    email: &str,
    role: &str,
) -> anyhow::Result<()> {
    let role = parse_org_role(role)?;

    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let (new_access_token, ()) = rbw::actions::invite_org_user(
        access_token,
        refresh_token,
        &org_id,
        email,
        role,
    )?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(&db)?;
    }

    eprintln!(
        "{} '{email}' to the organization",
        style::success("Invited", stdout_supports_color()),
    );

    Ok(())
}

pub fn remove_org_user(
    org_id: Option<&str>,
    user: &str,
    yes: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (new_access_token, users) =
        rbw::actions::org_users(&access_token, &refresh_token, &org_id)?;
    if let Some(new_access_token) = new_access_token {
        access_token.clone_from(&new_access_token);
        db.access_token = Some(new_access_token);
        save_db(&db)?;
    }

    let target = users
        .iter()
        .find(|u| u.id == user)
        .or_else(|| users.iter().find(|u| u.email.eq_ignore_ascii_case(user)))
        .ok_or_else(|| {
            anyhow::anyhow!("no organization member found for '{user}'")
        })?;

    let c = stdout_supports_color();
    let prompt = format!(
        "Remove {} from the organization?",
        style::name(&target.email, c),
    );
    if !yes && !confirm(&prompt)? {
        return Ok(());
    }

    let (new_access_token, ()) = rbw::actions::remove_org_user(
        &access_token,
        &refresh_token,
        &org_id,
        &target.id,
    )?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(&db)?;
    }

    eprintln!(
        "{} '{}' from the organization",
        style::success("Removed", c),
        target.email,
    );

    Ok(())
}

// Confirms a member who has accepted their invite -- required before they
// can decrypt anything in the org, since that's what actually re-encrypts
// the org key to their now-known public key. Resolving the member and
// fetching their public key are both plain lookups done here; only the
// re-encryption itself is agent-mediated (needs the org key already
// cached from unlock).
pub fn confirm_org_user(
    org_id: Option<&str>,
    user: &str,
) -> anyhow::Result<()> {
    unlock(None, None)?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (new_access_token, users) =
        rbw::actions::org_users(&access_token, &refresh_token, &org_id)?;
    if let Some(new_access_token) = new_access_token {
        access_token.clone_from(&new_access_token);
        db.access_token = Some(new_access_token);
        save_db(&db)?;
    }

    let target = users
        .iter()
        .find(|u| u.id == user)
        .or_else(|| users.iter().find(|u| u.email.eq_ignore_ascii_case(user)))
        .ok_or_else(|| {
            anyhow::anyhow!("no organization member found for '{user}'")
        })?;
    // The public-key lookup needs the account's own (global) user id --
    // a different id than the OrganizationUser relationship id `confirm`
    // itself uses. Only unset if they haven't registered an account for
    // that email yet.
    let target_user_id = target.user_id.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "'{}' hasn't registered an account for this email yet -- \
             they need to do that before they can be confirmed",
            target.email,
        )
    })?;

    let (new_access_token, public_key_der_b64) =
        rbw::actions::user_public_key(
            &access_token,
            &refresh_token,
            target_user_id,
        )?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(&db)?;
    }

    crate::actions::confirm_org_user(
        &org_id,
        &target.id,
        &public_key_der_b64,
    )?;

    eprintln!(
        "{} '{}'",
        style::success("Confirmed", stdout_supports_color()),
        target.email,
    );

    Ok(())
}

// Sets one member's permissions on one collection directly, without any
// of `propagate_collection_permissions`'s hierarchy-inference policy
// (topmost held -> edit, descendants -> manage). That command bakes in a
// specific naming-convention-driven policy that doesn't fit every org;
// this is the generic primitive underneath it, for anyone who just wants
// to set a permission on a (collection, member) pair directly.
#[allow(clippy::fn_params_excessive_bools)]
pub fn grant_collection_access(
    collection: &str,
    user: &str,
    org_id: Option<&str>,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    crate::actions::sync()?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let all_collections = decrypt_collections(&db)?;
    let resolved =
        resolve_collection(&all_collections, collection, Some(&org_id))?;
    let collection_id = resolved.id.clone();
    let collection_name = resolved.name.clone();

    // The still-encrypted name, needed to re-submit the PUT below --
    // reusing it directly avoids any risk of a decrypt/re-encrypt
    // mismatch changing it.
    let encrypted_name = db
        .collections
        .iter()
        .find(|c| c.id == collection_id)
        .map(|c| c.name.clone())
        .context("collection disappeared from the local db")?;

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (new_token, members) =
        rbw::actions::org_users(&access_token, &refresh_token, &org_id)?;
    if let Some(t) = new_token {
        access_token.clone_from(&t);
        db.access_token = Some(t);
        save_db(&db)?;
    }

    let target = members
        .iter()
        .find(|m| m.id == user)
        .or_else(|| {
            members.iter().find(|m| m.email.eq_ignore_ascii_case(user))
        })
        .ok_or_else(|| {
            anyhow::anyhow!("no organization member found for '{user}'")
        })?;

    let (new_token, details) = rbw::actions::collections_details(
        &access_token,
        &refresh_token,
        &org_id,
    )?;
    if let Some(t) = new_token {
        access_token.clone_from(&t);
        db.access_token = Some(t);
        save_db(&db)?;
    }

    let detail =
        details
            .iter()
            .find(|d| d.id == collection_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "collection '{collection_name}' has no per-user \
                 permission data from the API (accessAll members aren't \
                 listed there)"
                )
            })?;

    let mut users: Vec<rbw::api::CollectionUser> = detail
        .users
        .iter()
        .filter(|u| u.id != target.id)
        .cloned()
        .collect();
    users.push(rbw::api::CollectionUser {
        id: target.id.clone(),
        read_only,
        hide_passwords,
        manage,
    });

    let (new_token, ()) = rbw::actions::set_collection_users(
        &access_token,
        &refresh_token,
        &org_id,
        &collection_id,
        &encrypted_name,
        detail.external_id.as_deref(),
        &detail.groups,
        &users,
    )?;
    if let Some(t) = new_token {
        db.access_token = Some(t);
        save_db(&db)?;
    }

    eprintln!(
        "{} permissions for '{}' on collection '{collection_name}'",
        style::success("Set", stdout_supports_color()),
        target.email,
    );

    Ok(())
}

pub fn propagate_collection_permissions(
    org_id: Option<&str>,
    apply: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    unlock(None, None)?;
    crate::actions::sync()?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let mut id2name: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for c in &db.collections {
        if c.org_id != org_id {
            continue;
        }
        let name = crate::actions::decrypt(&c.name, None, Some(&c.org_id))
            .with_context(|| {
                format!("failed to decrypt collection name for {}", c.id)
            })?;
        let name = normalize_collection_name(&name)?;
        id2name.insert(c.id.clone(), name);
    }

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (new_token, members) =
        rbw::actions::org_users(&access_token, &refresh_token, &org_id)?;
    if let Some(t) = new_token {
        access_token.clone_from(&t);
        db.access_token = Some(t);
        save_db(&db)?;
    }

    let (new_token, details) = rbw::actions::collections_details(
        &access_token,
        &refresh_token,
        &org_id,
    )?;
    if let Some(t) = new_token {
        access_token.clone_from(&t);
        db.access_token = Some(t);
        save_db(&db)?;
    }

    // Exclude Owners (role 0) and Admins (role 1); only Users (2) and
    // Managers (3) get permission propagation. confirmed (status==2) and
    // non-access-all members only.
    let eligible: std::collections::HashMap<String, String> = members
        .iter()
        .filter(|m| m.status == 2 && !m.access_all && m.role >= 2)
        .map(|m| (m.id.clone(), m.email.clone()))
        .collect();

    let details_by_id: std::collections::HashMap<
        &str,
        &rbw::api::CollectionDetail,
    > = details.iter().map(|d| (d.id.as_str(), d)).collect();
    for d in &details {
        if !id2name.contains_key(&d.id) {
            anyhow::bail!(
                "collection {} returned by the API is missing or undecryptable in the local db; aborting",
                d.id
            );
        }
    }
    for id in id2name.keys() {
        if !details_by_id.contains_key(id.as_str()) {
            anyhow::bail!(
                "collection {} ({}) is in the local db but absent from the live API response; aborting",
                id,
                id2name[id]
            );
        }
    }

    let mut held: std::collections::HashMap<
        String,
        std::collections::HashMap<String, rbw::api::CollectionUser>,
    > = std::collections::HashMap::new();
    for d in &details {
        for u in &d.users {
            if eligible.contains_key(&u.id) {
                held.entry(u.id.clone())
                    .or_default()
                    .insert(d.id.clone(), u.clone());
            }
        }
    }

    let mut desired: std::collections::HashMap<
        (String, String),
        rbw::api::CollectionUser,
    > = std::collections::HashMap::new();
    for member_id in held.keys() {
        let held_ids = &held[member_id];
        let held_names: Vec<&str> =
            held_ids.keys().map(|id| id2name[id].as_str()).collect();
        let topmost: Vec<&str> = held_names
            .iter()
            .copied()
            .filter(|n| {
                !held_names
                    .iter()
                    .any(|h| *h != *n && n.starts_with(&format!("{h}/")))
            })
            .collect();
        for (id, name) in &id2name {
            if topmost.iter().any(|t| name.starts_with(&format!("{t}/"))) {
                desired.insert((member_id.clone(), id.clone()), MANAGE);
            }
        }
        for (id, name) in &id2name {
            if topmost.contains(&name.as_str()) {
                desired.insert((member_id.clone(), id.clone()), EDIT);
            }
        }
    }

    let mut changes: std::collections::BTreeMap<
        String,
        Vec<(String, rbw::api::CollectionUser)>,
    > = std::collections::BTreeMap::new();
    for ((member_id, coll_id), target) in &desired {
        let current = held.get(member_id).and_then(|h| h.get(coll_id));
        let needs_change = current.is_none_or(|c| !same_flags(c, target));
        if needs_change {
            changes
                .entry(coll_id.clone())
                .or_default()
                .push((member_id.clone(), target.clone()));
        }
    }
    for member_targets in changes.values_mut() {
        member_targets.sort_by(|a, b| a.0.cmp(&b.0));
    }

    for coll_id in changes.keys() {
        if !details_by_id[coll_id.as_str()].groups.is_empty() {
            anyhow::bail!(
                "collection {} ({}) has groups assigned; groups passthrough on PUT is unverified, aborting (see docs/collection-permissions-spec.md §4.3)",
                coll_id,
                id2name[coll_id]
            );
        }
    }

    let mut changed_members: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut grants = 0usize;
    for (coll_id, member_targets) in &changes {
        let name = &id2name[coll_id];
        for (member_id, target) in member_targets {
            let email = &eligible[member_id];
            let level = if target.manage { "MANAGE" } else { "EDIT" };
            let current = held.get(member_id).and_then(|h| h.get(coll_id));
            let downgrade =
                current.is_some_and(|c| perm_rank(target) < perm_rank(c));
            let prefix = if apply { "" } else { "WOULD " };
            if downgrade {
                let cur_level = perm_level_name(current.unwrap());
                let tgt_level = perm_level_name(target);
                println!(
                    "{prefix}DOWNGRADE {email} {cur_level}->{tgt_level} on {name}"
                );
            } else {
                println!("{prefix}SET {email} -> {level} on {name}");
            }
            changed_members.insert(member_id.clone());
            grants += 1;
        }
    }

    if verbose {
        eprintln!(
            "{} eligible members, {} collections in org, {} collections to change",
            eligible.len(),
            id2name.len(),
            changes.len()
        );
    }

    if apply {
        let mut applied: Vec<String> = Vec::new();
        for (coll_id, member_targets) in &changes {
            let detail = details_by_id[coll_id.as_str()];
            let mut new_users = detail.users.clone();
            for (member_id, target) in member_targets {
                let entry = new_users.iter_mut().find(|u| &u.id == member_id);
                if let Some(u) = entry {
                    u.read_only = target.read_only;
                    u.hide_passwords = target.hide_passwords;
                    u.manage = target.manage;
                } else {
                    new_users.push(rbw::api::CollectionUser {
                        id: member_id.clone(),
                        read_only: target.read_only,
                        hide_passwords: target.hide_passwords,
                        manage: target.manage,
                    });
                }
            }
            let enc_name = db
                .collections
                .iter()
                .find(|c| &c.id == coll_id)
                .map(|c| c.name.clone())
                .unwrap();
            let res = rbw::actions::set_collection_users(
                &access_token,
                &refresh_token,
                &org_id,
                coll_id,
                &enc_name,
                detail.external_id.as_deref(),
                &detail.groups,
                &new_users,
            );
            match res {
                Ok((new_token, ())) => {
                    if let Some(t) = new_token {
                        access_token.clone_from(&t);
                        db.access_token = Some(t);
                        save_db(&db)?;
                    }
                    applied.push(coll_id.clone());
                }
                Err(e) => {
                    eprintln!(
                        "PUT failed on collection {} ({}); already applied to: {:?}",
                        coll_id, id2name[coll_id], applied
                    );
                    return Err(e.into());
                }
            }
        }
        crate::actions::sync()?;
    }

    let mode = if apply { "applied" } else { "dry-run" };
    println!(
        "Done: {} members, {} collections changed, {} grants set ({})",
        changed_members.len(),
        changes.len(),
        grants,
        mode
    );

    Ok(())
}

// `history --from-file`: same output shape as the live-account path,
// reading `decrypted.history` from an in-memory `DecryptedCipher`.
fn history_from_file(
    path: &std::path::Path,
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
    force_exact: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<()> {
    let vault = load_from_file(path, passphrase)?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let decrypted = find_entry_in_file(
        &vault.entries,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if output_is_structured(output) {
        write_serialized_pretty(
            &decrypted.history,
            output,
            "failed to write history to stdout",
        )?;
    } else if output == OutputMode::Name {
        for history in decrypted.history {
            println!("{}", history.password);
        }
    } else {
        for history in decrypted.history {
            println!("{}: {}", history.last_used_date, history.password);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn history(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
    force_exact: bool,
    from_file: Option<&std::path::Path>,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        return history_from_file(
            path,
            &needles,
            username,
            folder,
            ignore_case,
            output,
            force_exact,
            from_file_passphrase,
        );
    }

    unlock(None, None)?;

    let db = load_db()?;

    let needle_str = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (_, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )
    .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    if output_is_structured(output) {
        write_serialized_pretty(
            &decrypted.history,
            output,
            "failed to write history to stdout",
        )?;
    } else if output == OutputMode::Name {
        // There is no "name" for a history item; print just the previous
        // passwords (the primary value), one per line.
        for history in decrypted.history {
            println!("{}", history.password);
        }
    } else {
        for history in decrypted.history {
            println!("{}: {}", history.last_used_date, history.password);
        }
    }

    Ok(())
}

// Locks the active account when one is selected via --account/RBW_ACCOUNT
// (the request carries the account name, and the agent only clears that
// account's keys); with no account selected, or with `--all`, every account
// is locked.
pub fn lock(all: bool) -> anyhow::Result<()> {
    ensure_agent()?;
    if all {
        crate::actions::lock_all()?;
    } else {
        crate::actions::lock()?;
    }

    Ok(())
}

pub fn purge(yes: bool) -> anyhow::Result<()> {
    let account = active_account()?;
    let termux_configured = account.unlock.termux.is_some();
    let what = if termux_configured {
        "the local database and its Termux key/bundle"
    } else {
        "the local copy of the password database"
    };
    if !yes
        && !confirm(&format!(
            "Remove {what} for {}?",
            style::name(account_email(&account)?, stdout_supports_color())
        ))?
    {
        return Ok(());
    }

    stop_agent()?;

    remove_db()?;
    termux_remove(true)?;

    Ok(())
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()?;

    Ok(())
}

pub fn kill_agent() -> anyhow::Result<()> {
    crate::actions::kill()?;

    Ok(())
}

pub fn inject(
    input: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let ctx = InjectContext::load()?;
    let rendered = ctx.render_input(input)?;

    match output {
        Some(path) => write_rendered_template_file(path, &rendered)?,
        None => {
            std::io::stdout()
                .write_all(rendered.as_bytes())
                .context("failed to write rendered template to stdout")?;
        }
    }

    Ok(())
}

pub fn run(
    env_file: &std::path::Path,
    command: &[OsString],
) -> anyhow::Result<std::process::ExitStatus> {
    let ctx = InjectContext::load()?;
    let env_bindings = ctx.env_bindings_from_file(env_file)?;
    run_inject_command(command, &env_bindings)
}

fn ensure_agent() -> anyhow::Result<()> {
    check_config()?;
    if matches!(check_agent_version(), Ok(())) {
        return Ok(());
    }
    run_agent()?;
    check_agent_version()?;
    Ok(())
}

fn run_agent() -> anyhow::Result<()> {
    let agent_path = std::env::var_os("RBW_AGENT");
    let agent_path = agent_path
        .as_deref()
        .unwrap_or_else(|| std::ffi::OsStr::from_bytes(b"rbw-agent"));
    let status = std::process::Command::new(agent_path)
        .status()
        .context("failed to run rbw-agent")?;
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                return Err(anyhow::anyhow!(
                    "failed to run rbw-agent: {status}"
                ));
            }
        }
    }

    Ok(())
}

fn check_config() -> anyhow::Result<()> {
    rbw::config::Config::validate().map_err(|e| {
        log::error!("{MISSING_CONFIG_HELP}");
        anyhow::Error::new(e)
    })
}

fn check_agent_version() -> anyhow::Result<()> {
    let client_version = rbw::protocol::VERSION;
    let agent_version = version_or_quit()?;
    if agent_version != client_version {
        crate::actions::quit()?;
        return Err(anyhow::anyhow!(
            "client protocol version is {client_version} but agent protocol version is {agent_version}"
        ));
    }
    Ok(())
}

fn version_or_quit() -> anyhow::Result<u32> {
    crate::actions::version().inspect_err(|_| {
        let _ = crate::actions::quit();
    })
}

fn find_entry(
    db: &rbw::db::Db,
    mut needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    let (collection_id, org_id) = resolve_entry_scope(db, collection, org)?;
    let in_scope = |entry: &rbw::db::Entry| {
        entry_in_collection_org_scope(
            entry,
            collection_id.as_deref(),
            org_id.as_deref(),
        )
    };

    // Fast-path: exactly one UUID needle — try exact match first. Trashed
    // entries are never a candidate for ordinary name/UUID resolution
    // (restoring one is the one exception -- see
    // `find_deleted_entry`/`find_deleted_entries_all`, `rbw restore`'s
    // dedicated trashed-only counterpart).
    if needles.len() == 1 {
        if let Needle::Uuid(uuid, s) = &needles[0] {
            let uuid = *uuid;
            for cipher in &db.entries {
                if !cipher.deleted
                    && uuid::Uuid::parse_str(&cipher.id) == Ok(uuid)
                    && in_scope(cipher)
                {
                    return Ok((cipher.clone(), decrypt_cipher(cipher)?));
                }
            }
            // UUID not found by exact match; fall through to name search
            needles = vec![Needle::Name(s.clone())];
        }
    }

    let mut requests = BatchRequests::new();
    let plans: Vec<SearchCipherPlan> = db
        .entries
        .iter()
        .filter(|entry| in_scope(entry))
        .map(|entry| SearchCipherPlan::build(entry, &mut requests))
        .collect();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };
    let mut ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .filter(|entry| in_scope(entry))
        .zip(plans)
        .map(|(entry, plan)| {
            plan.resolve(&results)
                .map(|decrypted| (entry.clone(), decrypted))
        })
        .collect::<anyhow::Result<_>>()?;
    ciphers.retain(|(entry, _)| !entry.deleted);
    let (entry, _) = find_entry_raw(
        &ciphers,
        &needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )?;
    let decrypted_entry = decrypt_cipher(&entry)?;
    Ok((entry, decrypted_entry))
}

// Like `find_entry`, but resolves against every account in `target_accounts`
// (see `list_target_accounts`) instead of a single db. With one target
// account this is exactly `find_entry`. With several, every account's
// entries are pooled into one list and scored together by the same
// `find_entry_raw` logic used within a single vault — a name match in one
// account beats a weaker match in another exactly as it would within one
// vault, and genuine ties across accounts are reported as ambiguous. Returns
// the name of the account that owns the winning entry alongside it, since the
// caller needs to route the follow-up detail decrypt to the right account.
fn find_entry_multi(
    target_accounts: &[String],
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    collection: Option<&str>,
    org: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
) -> anyhow::Result<(String, rbw::db::Entry, DecryptedCipher)> {
    let [account] = target_accounts else {
        let mut pool: Vec<(rbw::db::Entry, DecryptedSearchCipher)> =
            Vec::new();
        let mut owner: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for account in target_accounts {
            crate::actions::set_active_account(Some(account.clone()))?;
            let db = load_db()?;
            // A `--collection`/`--org` needle that doesn't resolve in this
            // particular account (name not found here, or ambiguous here)
            // just means this account contributes nothing -- it doesn't
            // abort the search across the other accounts in `--all`.
            let Ok((collection_id, org_id)) =
                resolve_entry_scope(&db, collection, org)
            else {
                continue;
            };
            let in_scope = |entry: &rbw::db::Entry| {
                entry_in_collection_org_scope(
                    entry,
                    collection_id.as_deref(),
                    org_id.as_deref(),
                )
            };
            let mut requests = BatchRequests::new();
            let plans: Vec<SearchCipherPlan> = db
                .entries
                .iter()
                .filter(|entry| in_scope(entry))
                .map(|entry| SearchCipherPlan::build(entry, &mut requests))
                .collect();
            let results = if requests.is_empty() {
                Vec::new()
            } else {
                crate::actions::decrypt_batch(requests.into_vec())?
            };
            for (entry, plan) in
                db.entries.iter().filter(|entry| in_scope(entry)).zip(plans)
            {
                owner.insert(entry.id.clone(), account.clone());
                pool.push((entry.clone(), plan.resolve(&results)?));
            }
        }
        // Trashed entries are never a candidate for ordinary name/UUID
        // resolution -- see `find_entry`'s matching exclusion.
        pool.retain(|(entry, _)| !entry.deleted);

        // Fast-path a single UUID needle, same as `find_entry`.
        let mut needles = needles;
        if let [Needle::Uuid(uuid, s)] = needles.as_slice() {
            let uuid = *uuid;
            if let Some((entry, _)) = pool
                .iter()
                .find(|(e, _)| uuid::Uuid::parse_str(&e.id) == Ok(uuid))
            {
                let entry = entry.clone();
                let account = owner[&entry.id].clone();
                crate::actions::set_active_account(Some(account.clone()))?;
                let decrypted = decrypt_cipher(&entry)?;
                return Ok((account, entry, decrypted));
            }
            needles = vec![Needle::Name(s.clone())];
        }

        let (entry, _) = find_entry_raw(
            &pool,
            &needles,
            username,
            folder,
            ignore_case,
            force_exact,
        )?;
        let account = owner[&entry.id].clone();
        crate::actions::set_active_account(Some(account.clone()))?;
        let decrypted = decrypt_cipher(&entry)?;
        return Ok((account, entry, decrypted));
    };

    crate::actions::set_active_account(Some(account.clone()))?;
    let db = load_db()?;
    let (entry, decrypted) = find_entry(
        &db,
        needles,
        username,
        folder,
        collection,
        org,
        ignore_case,
        force_exact,
    )?;
    Ok((account.clone(), entry, decrypted))
}

// Resolve which attachment a command should operate on: the one matching
// `needle` when given, else the entry's only attachment. No needle with
// several attachments is an error listing what's available.
fn resolve_attachment<'a>(
    entry: &'a rbw::db::Entry,
    decrypted: &'a DecryptedCipher,
    needle: Option<&str>,
) -> anyhow::Result<(&'a rbw::db::Attachment, &'a DecryptedAttachment)> {
    needle
        .map_or_else(
            || match entry.attachments.as_slice() {
                [] => Err(anyhow::anyhow!(
                    "no attachments available for this item"
                )),
                [attachment] => decrypted
                    .attachments
                    .first()
                    .map(|decrypted| (attachment, decrypted))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "failed to decrypt attachment metadata"
                        )
                    }),
                _ => Err(anyhow::anyhow!(
                    "attachment id or filename is required"
                )),
            },
            |needle| find_attachment(entry, decrypted, needle),
        )
        .map_err(|err| {
            available_attachments_error(
                &decrypted.name,
                &decrypted.attachments,
                &err.to_string(),
            )
        })
}

fn find_attachment<'a>(
    entry: &'a rbw::db::Entry,
    decrypted: &'a DecryptedCipher,
    needle: &str,
) -> anyhow::Result<(&'a rbw::db::Attachment, &'a DecryptedAttachment)> {
    if entry.attachments.is_empty() {
        return Err(anyhow::anyhow!(
            "no attachments available for this item"
        ));
    }

    let needle = needle.to_lowercase();
    let mut matches: Vec<_> = entry
        .attachments
        .iter()
        .zip(&decrypted.attachments)
        .filter(|(attachment, decrypted)| {
            attachment.id.to_lowercase() == needle
                || decrypted.file_name.as_ref().is_some_and(|file_name| {
                    file_name.to_lowercase().contains(&needle)
                })
        })
        .collect();

    let exact_matches: Vec<_> = matches
        .iter()
        .copied()
        .filter(|(_, decrypted)| {
            decrypted
                .file_name
                .as_ref()
                .is_some_and(|file_name| file_name.to_lowercase() == needle)
        })
        .collect();
    if exact_matches.len() == 1 {
        matches = exact_matches;
    }

    match matches.as_slice() {
        [] => Err(anyhow::anyhow!("attachment '{needle}' was not found")),
        [(attachment, decrypted)] => Ok((*attachment, *decrypted)),
        _ => Err(anyhow::anyhow!(
            "multiple attachments found: {}",
            matches
                .iter()
                .map(|(attachment, _)| attachment.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

// `resolve_attachment`'s from-file counterpart: same only-attachment
// fallback and needle matching, but against a `DecryptedCipher`'s own
// `attachments` list (no separate `rbw::db::Entry` exists for
// `--from-file`, and none of the matching logic needs one).
fn resolve_attachment_in_file<'a>(
    decrypted: &'a DecryptedCipher,
    needle: Option<&str>,
) -> anyhow::Result<&'a DecryptedAttachment> {
    needle
        .map_or_else(
            || match decrypted.attachments.as_slice() {
                [] => Err(anyhow::anyhow!(
                    "no attachments available for this item"
                )),
                [attachment] => Ok(attachment),
                _ => Err(anyhow::anyhow!(
                    "attachment id or filename is required"
                )),
            },
            |needle| find_attachment_in_file(decrypted, needle),
        )
        .map_err(|err| {
            available_attachments_error(
                &decrypted.name,
                &decrypted.attachments,
                &err.to_string(),
            )
        })
}

fn find_attachment_in_file<'a>(
    decrypted: &'a DecryptedCipher,
    needle: &str,
) -> anyhow::Result<&'a DecryptedAttachment> {
    if decrypted.attachments.is_empty() {
        return Err(anyhow::anyhow!(
            "no attachments available for this item"
        ));
    }

    let needle = needle.to_lowercase();
    let mut matches: Vec<_> = decrypted
        .attachments
        .iter()
        .filter(|attachment| {
            attachment.id.to_lowercase() == needle
                || attachment.file_name.as_ref().is_some_and(|file_name| {
                    file_name.to_lowercase().contains(&needle)
                })
        })
        .collect();

    let exact_matches: Vec<_> = matches
        .iter()
        .copied()
        .filter(|attachment| {
            attachment
                .file_name
                .as_ref()
                .is_some_and(|file_name| file_name.to_lowercase() == needle)
        })
        .collect();
    if exact_matches.len() == 1 {
        matches = exact_matches;
    }

    match matches.as_slice() {
        [] => Err(anyhow::anyhow!("attachment '{needle}' was not found")),
        [attachment] => Ok(attachment),
        _ => Err(anyhow::anyhow!(
            "multiple attachments found: {}",
            matches
                .iter()
                .map(|attachment| attachment.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn find_entry_raw(
    entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
    if needles.is_empty() {
        return Err(anyhow::anyhow!("no entry found"));
    }

    let joined = needles
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");

    // Total relevance score for an entry, or None if it isn't a candidate
    // (fails the user/folder filter, or some needle matches nowhere). Every
    // needle must match somewhere; the score reflects the best location each
    // matched, so name hits dominate hits in hidden fields.
    let score = |d: &DecryptedSearchCipher,
                 strict_username: bool,
                 strict_folder: bool|
     -> Option<u32> {
        if !d.passes_user_folder(
            username,
            folder,
            ignore_case,
            force_exact,
            strict_username,
            strict_folder,
        ) {
            return None;
        }
        let mut total: u32 = 0;
        for needle in needles {
            total = total.saturating_add(d.match_score(
                needle,
                ignore_case,
                force_exact,
            )?);
        }
        // The whole needle string equalling the name (e.g.
        // `get private gpg key` -> "Private GPG Key") is the strongest signal.
        let name_eq_joined = if ignore_case {
            d.name.to_lowercase() == joined.to_lowercase()
        } else {
            d.name == joined
        };
        if name_eq_joined {
            total = total.saturating_add(SCORE_FULL_NAME_BONUS);
        }
        Some(total)
    };

    let mut scored: Vec<(&(rbw::db::Entry, DecryptedSearchCipher), u32)> =
        entries
            .iter()
            .filter_map(|entry| {
                score(&entry.1, false, false).map(|s| (entry, s))
            })
            .collect();

    if scored.is_empty() {
        return Err(anyhow::anyhow!("no entry found"));
    }

    let max_score = scored.iter().map(|(_, s)| *s).max().unwrap_or(0);
    scored.retain(|(_, s)| *s == max_score);

    if scored.len() == 1 {
        return Ok(scored[0].0.clone());
    }

    // Several candidates tied at the top score. If they share a name they're
    // the "same" entry across folders/users, so try to disambiguate with the
    // strict user/folder filter; differently-named ties are a real ambiguity.
    let first_name = scored[0].0 .1.name.as_str();
    if scored.iter().all(|(entry, _)| entry.1.name == first_name) {
        let narrow = |strict_username: bool, strict_folder: bool| {
            scored
                .iter()
                .filter(|(entry, _)| {
                    score(&entry.1, strict_username, strict_folder).is_some()
                })
                .map(|(entry, _)| *entry)
                .collect::<Vec<_>>()
        };

        let strict_both = narrow(true, true);
        if strict_both.len() == 1 {
            return Ok(strict_both[0].clone());
        }
        // Pick a winner only when exactly one of the stricter filters
        // resolves to a single candidate; if both do (a folder match *and* a
        // user match), it's genuinely ambiguous.
        let strict_folder = narrow(false, true);
        let strict_username = narrow(true, false);
        if strict_folder.len() == 1 && strict_username.len() != 1 {
            return Ok(strict_folder[0].clone());
        } else if strict_folder.len() != 1 && strict_username.len() == 1 {
            return Ok(strict_username[0].clone());
        }
    }

    // This error is printed to stderr (wrapped in red by `style_error`), so
    // colour based on stderr. The leading reset stops the outer red from
    // bleeding into the per-field styling of the entry list.
    let c = stderr_supports_color();
    let reset = if c { "\x1b[0m" } else { "" };
    let entries_str: Vec<String> = scored
        .iter()
        .map(|(entry, _)| format_ambiguous_entry(&entry.1, c))
        .collect();
    let hint = format!(
        "Try `rbw list {joined}` to inspect the matches, or add --user/--folder to disambiguate."
    );
    Err(anyhow::anyhow!(
        "multiple entries found:{reset}\n{}\n\n{}",
        entries_str.join("\n"),
        style::dim(&hint, c),
    ))
}

// `find_entry`'s `--from-file` counterpart: same matching
// (`find_entry_raw`), against a `--from-file` vault's already-decrypted
// entries instead of a live account's cipherstring `Db`. Builds the same
// `(rbw::db::Entry, DecryptedSearchCipher)` pairs `find_entry` builds via
// the agent (`placeholder_entry`/`decrypted_cipher_to_search` -- no agent
// involved here, both are already in memory), then looks the winning id
// back up in `entries` for the real (non-placeholder) result.
fn find_entry_in_file(
    entries: &[DecryptedCipher],
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    force_exact: bool,
) -> anyhow::Result<DecryptedCipher> {
    let pairs: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = entries
        .iter()
        .map(|entry| {
            (
                placeholder_entry(entry.id.clone()),
                decrypted_cipher_to_search(entry),
            )
        })
        .collect();
    let (matched, _) = find_entry_raw(
        &pairs,
        needles,
        username,
        folder,
        ignore_case,
        force_exact,
    )?;
    entries
        .iter()
        .find(|entry| entry.id == matched.id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("entry no longer exists"))
}

fn decrypt_field(
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> Option<String> {
    decrypt_field_with_attachment_key(name, field, entry_key, org_id, None)
}

// Like `decrypt_field`, but for a field wrapped in an attachment's own key
// (e.g. an attachment file name) rather than directly in the entry's key.
fn decrypt_field_with_attachment_key(
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    attachment_key: Option<&str>,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| {
            crate::actions::decrypt_with_attachment_key(
                field,
                entry_key,
                org_id,
                attachment_key,
            )
        })
        .transpose();
    match field {
        Ok(field) => field,
        Err(e) => {
            log::warn!("failed to decrypt {name}: {e}");
            None
        }
    }
}

// Accumulates the cipherstrings to be decrypted in a single `decrypt_batch`
// call. `push` returns the index at which the corresponding plaintext will
// appear in the results vector, which the cipher plans record and later
// resolve.
struct BatchRequests(Vec<rbw::protocol::DecryptRequest>);

impl BatchRequests {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(
        &mut self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> usize {
        let index = self.0.len();
        self.0.push(rbw::protocol::DecryptRequest {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        });
        index
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn into_vec(self) -> Vec<rbw::protocol::DecryptRequest> {
        self.0
    }
}

fn entry_type_name(data: &rbw::db::EntryData) -> &'static str {
    match data {
        rbw::db::EntryData::Login { .. } => "Login",
        rbw::db::EntryData::Identity { .. } => "Identity",
        rbw::db::EntryData::SshKey { .. } => "SSH Key",
        rbw::db::EntryData::SecureNote => "Note",
        rbw::db::EntryData::Card { .. } => "Card",
    }
}

// Mirrors `entry_type_name`, but for the already-decrypted `DecryptedData`
// (used by `--from-file`, which has nothing else to call `entry_type_name`
// with -- there's no `rbw::db::EntryData` cipherstring involved at all).
fn decrypted_entry_type_name(data: &DecryptedData) -> &'static str {
    match data {
        DecryptedData::Login { .. } => "Login",
        DecryptedData::Identity { .. } => "Identity",
        DecryptedData::SshKey { .. } => "SSH Key",
        DecryptedData::SecureNote => "Note",
        DecryptedData::Card { .. } => "Card",
    }
}

// A plan describing which batch-decrypt results make up a single list entry.
// The `usize` fields are indices into the flat results vector returned by
// `decrypt_batch`; `entry_type` needs no decryption so it is resolved up front.
struct ListCipherPlan {
    id: String,
    name: Option<usize>,
    user: Option<usize>,
    password: Option<usize>,
    folder: Option<usize>,
    uris: Option<Vec<usize>>,
    entry_type: Option<String>,
    collection_ids: Option<Vec<String>>,
    attachment_count: usize,
    archived: bool,
    deleted: bool,
}

impl ListCipherPlan {
    fn build(
        entry: &rbw::db::Entry,
        fields: &[ListField],
        requests: &mut BatchRequests,
    ) -> Self {
        let name = fields.contains(&ListField::Name).then(|| {
            requests.push(
                &entry.name,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        });

        let user = if fields.contains(&ListField::User) {
            match &entry.data {
                rbw::db::EntryData::Login {
                    username: Some(username),
                    ..
                } => Some(requests.push(
                    username,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )),
                _ => None,
            }
        } else {
            None
        };

        let password = if fields.contains(&ListField::Password) {
            match &entry.data {
                rbw::db::EntryData::Login {
                    password: Some(password),
                    ..
                } => Some(requests.push(
                    password,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )),
                _ => None,
            }
        } else {
            None
        };

        let folder = if fields.contains(&ListField::Folder) {
            // folder name should always be decrypted with the local key
            // because folders are local to a specific user's vault, not the
            // organization
            entry
                .folder
                .as_ref()
                .map(|folder| requests.push(folder, None, None))
        } else {
            None
        };

        let uris = if fields.contains(&ListField::Uri) {
            match &entry.data {
                rbw::db::EntryData::Login { uris, .. } => Some(
                    uris.iter()
                        .map(|s| {
                            requests.push(
                                &s.uri,
                                entry.key.as_deref(),
                                entry.org_id.as_deref(),
                            )
                        })
                        .collect(),
                ),
                _ => None,
            }
        } else {
            None
        };

        let entry_type = fields
            .contains(&ListField::EntryType)
            .then(|| entry_type_name(&entry.data).to_string());
        let collection_ids = if fields.contains(&ListField::Collections) {
            Some(entry.collection_ids.clone())
        } else {
            None
        };

        Self {
            id: entry.id.clone(),
            name,
            user,
            password,
            folder,
            uris,
            entry_type,
            collection_ids,
            attachment_count: entry.attachments.len(),
            archived: entry.archived,
            deleted: entry.deleted,
        }
    }

    fn resolve(
        self,
        results: &[rbw::protocol::DecryptResult],
    ) -> anyhow::Result<DecryptedListCipher> {
        // entry name and folder are required, so a decryption failure is fatal
        let name = self
            .name
            .map(|index| strict_result(&results[index]))
            .transpose()?;
        let folder = self
            .folder
            .map(|index| strict_result(&results[index]))
            .transpose()?;
        // optional login fields are skipped (with a warning) on failure, to
        // match the previous best-effort behavior of `decrypt_field`
        let user = self.user.and_then(|index| {
            lenient_result(&results[index], Field::Username)
        });
        let password = self.password.and_then(|index| {
            lenient_result(&results[index], Field::Password)
        });
        let uris = self.uris.map(|indices| {
            indices
                .iter()
                .filter_map(|&index| {
                    lenient_result(&results[index], Field::Uris)
                })
                .collect()
        });
        let attachment_metadata =
            AttachmentMetadata::new(&self.id, self.attachment_count);

        Ok(DecryptedListCipher {
            id: self.id,
            name,
            user,
            password,
            folder,
            uris,
            entry_type: self.entry_type,
            collection_ids: self.collection_ids,
            attachment_metadata,
            archived: self.archived,
            deleted: self.deleted,
            account: None,
        })
    }
}

fn strict_result(
    result: &rbw::protocol::DecryptResult,
) -> anyhow::Result<String> {
    match result {
        rbw::protocol::DecryptResult::Success { plaintext } => {
            Ok(plaintext.clone())
        }
        rbw::protocol::DecryptResult::Failure { error } => {
            Err(anyhow::anyhow!("{error}"))
        }
    }
}

fn lenient_result(
    result: &rbw::protocol::DecryptResult,
    name: Field,
) -> Option<String> {
    match result {
        rbw::protocol::DecryptResult::Success { plaintext } => {
            Some(plaintext.clone())
        }
        rbw::protocol::DecryptResult::Failure { error } => {
            log::warn!("failed to decrypt {name}: {error}");
            None
        }
    }
}

// A plan describing which batch-decrypt results make up a single search entry.
// Like `ListCipherPlan`, the `usize` fields index into the flat results vector
// returned by `decrypt_batch`. Search decrypts more per entry than list (notes
// and the custom field values), because those are searchable too.
struct SearchCipherPlan {
    id: String,
    entry_type: String,
    name: usize,
    user: Option<usize>,
    folder: Option<usize>,
    notes: Option<usize>,
    uris: Vec<(usize, Option<rbw::api::UriMatchType>)>,
    fields: Vec<usize>,
    sensitive_fields: Vec<usize>,
    attachment_count: usize,
    archived: bool,
    deleted: bool,
    password: Option<usize>,
}

impl SearchCipherPlan {
    fn build(entry: &rbw::db::Entry, requests: &mut BatchRequests) -> Self {
        let name = requests.push(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        );

        let user = match &entry.data {
            rbw::db::EntryData::Login {
                username: Some(username),
                ..
            } => Some(requests.push(
                username,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )),
            _ => None,
        };

        // folder name should always be decrypted with the local key because
        // folders are local to a specific user's vault, not the organization
        let folder = entry
            .folder
            .as_ref()
            .map(|folder| requests.push(folder, None, None));

        let notes = entry.notes.as_ref().map(|notes| {
            requests.push(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        });

        let uris = match &entry.data {
            rbw::db::EntryData::Login { uris, .. } => uris
                .iter()
                .map(|s| {
                    (
                        requests.push(
                            &s.uri,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        ),
                        s.match_type,
                    )
                })
                .collect(),
            _ => vec![],
        };

        let fields = entry
            .fields
            .iter()
            .filter_map(|field| {
                if field.ty == Some(rbw::api::FieldType::Hidden) {
                    None
                } else {
                    field.value.as_ref()
                }
            })
            .map(|value| {
                requests.push(
                    value,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
            })
            .collect();

        let push_opt = |v: Option<&String>, requests: &mut BatchRequests| {
            v.map(|s| {
                requests.push(
                    s,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
            })
        };
        let mut sensitive_fields: Vec<usize> = Vec::new();
        let mut password_idx: Option<usize> = None;
        match &entry.data {
            rbw::db::EntryData::Login { password, .. } => {
                let idx = push_opt(password.as_ref(), requests);
                sensitive_fields.extend(idx);
                password_idx = idx;
            }
            rbw::db::EntryData::Card { number, code, .. } => {
                sensitive_fields.extend(push_opt(number.as_ref(), requests));
                sensitive_fields.extend(push_opt(code.as_ref(), requests));
            }
            rbw::db::EntryData::Identity {
                ssn,
                license_number,
                passport_number,
                ..
            } => {
                sensitive_fields.extend(push_opt(ssn.as_ref(), requests));
                sensitive_fields
                    .extend(push_opt(license_number.as_ref(), requests));
                sensitive_fields
                    .extend(push_opt(passport_number.as_ref(), requests));
            }
            rbw::db::EntryData::SshKey { private_key, .. } => {
                sensitive_fields
                    .extend(push_opt(private_key.as_ref(), requests));
            }
            rbw::db::EntryData::SecureNote => {}
        }
        for field in &entry.fields {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                sensitive_fields
                    .extend(push_opt(field.value.as_ref(), requests));
            }
        }

        Self {
            id: entry.id.clone(),
            entry_type: entry_type_name(&entry.data).to_string(),
            name,
            user,
            folder,
            notes,
            uris,
            fields,
            sensitive_fields,
            attachment_count: entry.attachments.len(),
            archived: entry.archived,
            deleted: entry.deleted,
            password: password_idx,
        }
    }

    fn resolve(
        self,
        results: &[rbw::protocol::DecryptResult],
    ) -> anyhow::Result<DecryptedSearchCipher> {
        // name, folder, and the (non-hidden) custom fields were previously
        // decrypted with `?`, so their failures stay fatal; user, uris, and
        // notes were best-effort and are skipped (with a warning) on failure
        let name = strict_result(&results[self.name])?;
        let folder = self
            .folder
            .map(|index| strict_result(&results[index]))
            .transpose()?;
        let fields = self
            .fields
            .iter()
            .map(|&index| strict_result(&results[index]))
            .collect::<anyhow::Result<_>>()?;
        let user = self.user.and_then(|index| {
            lenient_result(&results[index], Field::Username)
        });
        let notes = self
            .notes
            .and_then(|index| lenient_result(&results[index], Field::Notes));
        let uris = self
            .uris
            .into_iter()
            .filter_map(|(index, match_type)| {
                lenient_result(&results[index], Field::Uris)
                    .map(|uri| (uri, match_type))
            })
            .collect();

        let sensitive_fields = self
            .sensitive_fields
            .iter()
            .filter_map(|&index| {
                lenient_result(&results[index], Field::Password)
            })
            .collect();

        let password = self.password.and_then(|index| {
            lenient_result(&results[index], Field::Password)
        });

        Ok(DecryptedSearchCipher {
            id: self.id,
            entry_type: self.entry_type,
            folder,
            name,
            user,
            uris,
            fields,
            notes,
            sensitive_fields,
            attachment_count: self.attachment_count,
            archived: self.archived,
            deleted: self.deleted,
            password,
        })
    }
}

fn decrypt_search_cipher(
    entry: &rbw::db::Entry,
) -> anyhow::Result<DecryptedSearchCipher> {
    let id = entry.id.clone();
    let name = crate::actions::decrypt(
        &entry.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let user = match &entry.data {
        rbw::db::EntryData::Login { username, .. } => decrypt_field(
            Field::Username,
            username.as_deref(),
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        ),
        _ => None,
    };
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crate::actions::decrypt(folder, None, None))
        .transpose()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            crate::actions::decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let uris = if let rbw::db::EntryData::Login { uris, .. } = &entry.data {
        uris.iter()
            .filter_map(|s| {
                decrypt_field(
                    Field::Uris,
                    Some(&s.uri),
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .map(|uri| (uri, s.match_type))
            })
            .collect()
    } else {
        vec![]
    };
    let fields = entry
        .fields
        .iter()
        .filter_map(|field| {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                None
            } else {
                field.value.as_ref()
            }
        })
        .map(|value| {
            crate::actions::decrypt(
                value,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };

    let decrypt_opt = |v: Option<&String>| -> Option<String> {
        v.and_then(|s| {
            decrypt_field(
                Field::Password,
                Some(s),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
    };
    let login_password = match &entry.data {
        rbw::db::EntryData::Login { password, .. } => {
            decrypt_opt(password.as_ref())
        }
        _ => None,
    };
    let sensitive_fields: Vec<String> = {
        let mut sf: Vec<String> = Vec::new();
        match &entry.data {
            rbw::db::EntryData::Login { password, .. } => {
                sf.extend(decrypt_opt(password.as_ref()));
            }
            rbw::db::EntryData::Card { number, code, .. } => {
                sf.extend(decrypt_opt(number.as_ref()));
                sf.extend(decrypt_opt(code.as_ref()));
            }
            rbw::db::EntryData::Identity {
                ssn,
                license_number,
                passport_number,
                ..
            } => {
                sf.extend(decrypt_opt(ssn.as_ref()));
                sf.extend(decrypt_opt(license_number.as_ref()));
                sf.extend(decrypt_opt(passport_number.as_ref()));
            }
            rbw::db::EntryData::SshKey { private_key, .. } => {
                sf.extend(decrypt_opt(private_key.as_ref()));
            }
            rbw::db::EntryData::SecureNote => {}
        }
        for field in &entry.fields {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                sf.extend(decrypt_opt(field.value.as_ref()));
            }
        }
        sf
    };

    Ok(DecryptedSearchCipher {
        id,
        entry_type: entry_type_name(&entry.data).to_string(),
        folder,
        name,
        user,
        uris,
        fields,
        notes,
        sensitive_fields,
        attachment_count: entry.attachments.len(),
        archived: entry.archived,
        deleted: entry.deleted,
        password: login_password,
    })
}

// Mirrors `decrypt_search_cipher`, but as a pure field projection off an
// already-decrypted `DecryptedCipher` -- no decryption, can't fail. Used by
// `--from-file`'s `list`/`search` to reuse the exact same matching
// (`DecryptedSearchCipher::search_match`) and `Into<DecryptedListCipher>`
// the live-account path uses.
fn decrypted_cipher_to_search(
    decrypted: &DecryptedCipher,
) -> DecryptedSearchCipher {
    let user = match &decrypted.data {
        DecryptedData::Login { username, .. } => username.clone(),
        _ => None,
    };
    let uris = if let DecryptedData::Login { uris, .. } = &decrypted.data {
        uris.clone()
            .unwrap_or_default()
            .into_iter()
            .map(|u| (u.uri, u.match_type))
            .collect()
    } else {
        vec![]
    };
    let fields = decrypted
        .fields
        .iter()
        .filter_map(|field| {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                None
            } else {
                field.value.clone()
            }
        })
        .collect();
    let login_password = match &decrypted.data {
        DecryptedData::Login { password, .. } => password.clone(),
        _ => None,
    };
    let sensitive_fields: Vec<String> = {
        let mut sf: Vec<String> = Vec::new();
        match &decrypted.data {
            DecryptedData::Login { password, .. } => {
                sf.extend(password.clone());
            }
            DecryptedData::Card { number, code, .. } => {
                sf.extend(number.clone());
                sf.extend(code.clone());
            }
            DecryptedData::Identity {
                ssn,
                license_number,
                passport_number,
                ..
            } => {
                sf.extend(ssn.clone());
                sf.extend(license_number.clone());
                sf.extend(passport_number.clone());
            }
            DecryptedData::SshKey { private_key, .. } => {
                sf.extend(private_key.clone());
            }
            DecryptedData::SecureNote => {}
        }
        for field in &decrypted.fields {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                sf.extend(field.value.clone());
            }
        }
        sf
    };

    DecryptedSearchCipher {
        id: decrypted.id.clone(),
        entry_type: decrypted_entry_type_name(&decrypted.data).to_string(),
        folder: decrypted.folder.clone(),
        name: decrypted.name.clone(),
        user,
        uris,
        fields,
        notes: decrypted.notes.clone(),
        sensitive_fields,
        attachment_count: decrypted.attachment_metadata.attachment_count,
        archived: decrypted.archived,
        deleted: decrypted.deleted,
        password: login_password,
    }
}

pub fn decrypt_cipher(
    entry: &rbw::db::Entry,
) -> anyhow::Result<DecryptedCipher> {
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crate::actions::decrypt(folder, None, None))
        .transpose();
    let folder = match folder {
        Ok(folder) => folder,
        Err(e) => {
            log::warn!("failed to decrypt folder name: {e}");
            None
        }
    };
    let fields = entry
        .fields
        .iter()
        .map(|field| {
            Ok(DecryptedField {
                name: field
                    .name
                    .as_ref()
                    .map(|name| {
                        crate::actions::decrypt(
                            name,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                value: field
                    .value
                    .as_ref()
                    .map(|value| {
                        crate::actions::decrypt(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                ty: field.ty,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            crate::actions::decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };
    // Unlike every other field here, a bad history entry must not fail
    // the whole decrypt: history is append-only and never rewritten by
    // later edits, so a single old, unrelated corrupt entry (e.g. from
    // data written before a since-fixed bug) would otherwise permanently
    // hide this cipher's current, perfectly good name/username/password/
    // etc. -- exactly the "everything but the field I just changed
    // disappeared" failure mode this is guarding against.
    let history = entry
        .history
        .iter()
        .map(|history_entry| DecryptedHistoryEntry {
            last_used_date: history_entry.last_used_date.clone(),
            password: crate::actions::decrypt(
                &history_entry.password,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .unwrap_or_else(|e| {
                log::warn!("failed to decrypt history entry: {e}");
                "[failed to decrypt]".to_string()
            }),
        })
        .collect();
    let attachments: Vec<_> = entry
        .attachments
        .iter()
        .map(|attachment| DecryptedAttachment {
            id: attachment.id.clone(),
            file_name: decrypt_field_with_attachment_key(
                Field::Name,
                attachment.file_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                attachment.key.as_deref(),
            ),
            size: attachment.size.clone(),
            size_name: attachment.size_name.clone(),
        })
        .collect();
    let attachment_count = attachments.len();

    let data = match &entry.data {
        rbw::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        } => DecryptedData::Login {
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            password: decrypt_field(
                Field::Password,
                password.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            totp: decrypt_field(
                Field::Totp,
                totp.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(
                        Field::Uris,
                        Some(&s.uri),
                        entry.key.as_deref(),
                        entry.org_id.as_deref(),
                    )
                    .map(|uri| DecryptedUri {
                        uri,
                        match_type: s.match_type,
                    })
                })
                .collect(),
            fido2_credentials: fido2_credentials
                .iter()
                .map(|c| {
                    let dec = |field: Option<&str>| {
                        decrypt_field(
                            Field::Fido2Credential,
                            field,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    };
                    DecryptedFido2Credential {
                        credential_id: dec(c.credential_id.as_deref()),
                        key_type: dec(c.key_type.as_deref()),
                        key_algorithm: dec(c.key_algorithm.as_deref()),
                        key_curve: dec(c.key_curve.as_deref()),
                        key_value: dec(c.key_value.as_deref()),
                        rp_id: dec(c.rp_id.as_deref()),
                        user_handle: dec(c.user_handle.as_deref()),
                        user_name: dec(c.user_name.as_deref()),
                        counter: dec(c.counter.as_deref()),
                        rp_name: dec(c.rp_name.as_deref()),
                        user_display_name: dec(c
                            .user_display_name
                            .as_deref()),
                        discoverable: dec(c.discoverable.as_deref()),
                        // never encrypted to begin with
                        creation_date: c.creation_date.clone(),
                    }
                })
                .collect(),
        },
        rbw::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: decrypt_field(
                Field::Cardholder,
                cardholder_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            number: decrypt_field(
                Field::CardNumber,
                number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            brand: decrypt_field(
                Field::Brand,
                brand.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_month: decrypt_field(
                Field::ExpMonth,
                exp_month.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_year: decrypt_field(
                Field::ExpYear,
                exp_year.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            code: decrypt_field(
                Field::Cvv,
                code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        rbw::db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => DecryptedData::Identity {
            title: decrypt_field(
                Field::Title,
                title.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            first_name: decrypt_field(
                Field::FirstName,
                first_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            middle_name: decrypt_field(
                Field::MiddleName,
                middle_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            last_name: decrypt_field(
                Field::LastName,
                last_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address1: decrypt_field(
                Field::Address1,
                address1.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address2: decrypt_field(
                Field::Address2,
                address2.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address3: decrypt_field(
                Field::Address3,
                address3.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            city: decrypt_field(
                Field::City,
                city.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            state: decrypt_field(
                Field::State,
                state.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            postal_code: decrypt_field(
                Field::PostalCode,
                postal_code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            country: decrypt_field(
                Field::Country,
                country.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            phone: decrypt_field(
                Field::Phone,
                phone.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            email: decrypt_field(
                Field::Email,
                email.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            ssn: decrypt_field(
                Field::Ssn,
                ssn.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            license_number: decrypt_field(
                Field::License,
                license_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            passport_number: decrypt_field(
                Field::Passport,
                passport_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        rbw::db::EntryData::SecureNote => DecryptedData::SecureNote {},
        rbw::db::EntryData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => DecryptedData::SshKey {
            public_key: decrypt_field(
                Field::PublicKey,
                public_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            fingerprint: decrypt_field(
                Field::Fingerprint,
                fingerprint.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            private_key: decrypt_field(
                Field::PrivateKey,
                private_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name: crate::actions::decrypt(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?,
        data,
        fields,
        notes,
        history,
        attachments,
        attachment_metadata: AttachmentMetadata::new(
            &entry.id,
            attachment_count,
        ),
        archived: entry.archived,
        deleted: entry.deleted,
        account: None,
    })
}

fn uri_match_type_str(mt: rbw::api::UriMatchType) -> &'static str {
    match mt {
        rbw::api::UriMatchType::Domain => "domain",
        rbw::api::UriMatchType::Host => "host",
        rbw::api::UriMatchType::StartsWith => "starts_with",
        rbw::api::UriMatchType::Exact => "exact",
        rbw::api::UriMatchType::RegularExpression => "regular_expression",
        rbw::api::UriMatchType::Never => "never",
    }
}

fn parse_uri_match_type(s: &str) -> anyhow::Result<rbw::api::UriMatchType> {
    match s {
        "domain" => Ok(rbw::api::UriMatchType::Domain),
        "host" => Ok(rbw::api::UriMatchType::Host),
        "starts_with" => Ok(rbw::api::UriMatchType::StartsWith),
        "exact" => Ok(rbw::api::UriMatchType::Exact),
        "regular_expression" => Ok(rbw::api::UriMatchType::RegularExpression),
        "never" => Ok(rbw::api::UriMatchType::Never),
        other => Err(anyhow::anyhow!("unknown uri match type: '{other}'")),
    }
}

fn clipboard_mechanism_str(
    m: rbw::config::ClipboardMechanism,
) -> &'static str {
    match m {
        rbw::config::ClipboardMechanism::Auto => "auto",
        rbw::config::ClipboardMechanism::System => "system",
        rbw::config::ClipboardMechanism::Osc52 => "osc52",
    }
}

fn parse_clipboard_mechanism(
    s: &str,
) -> anyhow::Result<rbw::config::ClipboardMechanism> {
    match s {
        "auto" => Ok(rbw::config::ClipboardMechanism::Auto),
        "system" => Ok(rbw::config::ClipboardMechanism::System),
        "osc52" => Ok(rbw::config::ClipboardMechanism::Osc52),
        other => {
            Err(anyhow::anyhow!("unknown clipboard mechanism: '{other}'"))
        }
    }
}

fn field_type_str(ft: rbw::api::FieldType) -> &'static str {
    match ft {
        rbw::api::FieldType::Text => "text",
        rbw::api::FieldType::Hidden => "hidden",
        rbw::api::FieldType::Boolean => "boolean",
        rbw::api::FieldType::Linked => "linked",
    }
}

fn parse_field_type(s: &str) -> anyhow::Result<rbw::api::FieldType> {
    match s {
        "text" => Ok(rbw::api::FieldType::Text),
        "hidden" => Ok(rbw::api::FieldType::Hidden),
        "boolean" => Ok(rbw::api::FieldType::Boolean),
        "linked" => Ok(rbw::api::FieldType::Linked),
        other => Err(anyhow::anyhow!("unknown field type: '{other}'")),
    }
}

pub fn decrypted_to_editable(decrypted: &DecryptedCipher) -> EditableCipher {
    let data = match &decrypted.data {
        DecryptedData::Login {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        } => EditableData::Login {
            username: username.clone(),
            password: password.clone(),
            uris: uris
                .as_ref()
                .map(|v| {
                    v.iter()
                        .map(|u| EditableUri {
                            uri: u.uri.clone(),
                            match_type: u
                                .match_type
                                .map(|mt| uri_match_type_str(mt).to_string()),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            totp: totp.clone(),
            fido2_credentials: fido2_credentials
                .iter()
                .map(|c| EditableFido2Credential {
                    credential_id: c.credential_id.clone(),
                    key_type: c.key_type.clone(),
                    key_algorithm: c.key_algorithm.clone(),
                    key_curve: c.key_curve.clone(),
                    key_value: c.key_value.clone(),
                    rp_id: c.rp_id.clone(),
                    user_handle: c.user_handle.clone(),
                    user_name: c.user_name.clone(),
                    counter: c.counter.clone(),
                    rp_name: c.rp_name.clone(),
                    user_display_name: c.user_display_name.clone(),
                    discoverable: c.discoverable.clone(),
                    creation_date: c.creation_date.clone(),
                })
                .collect(),
        },
        DecryptedData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => EditableData::Card {
            cardholder_name: cardholder_name.clone(),
            number: number.clone(),
            brand: brand.clone(),
            exp_month: exp_month.clone(),
            exp_year: exp_year.clone(),
            code: code.clone(),
        },
        DecryptedData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => EditableData::Identity {
            title: title.clone(),
            first_name: first_name.clone(),
            middle_name: middle_name.clone(),
            last_name: last_name.clone(),
            address1: address1.clone(),
            address2: address2.clone(),
            address3: address3.clone(),
            city: city.clone(),
            state: state.clone(),
            postal_code: postal_code.clone(),
            country: country.clone(),
            phone: phone.clone(),
            email: email.clone(),
            ssn: ssn.clone(),
            license_number: license_number.clone(),
            passport_number: passport_number.clone(),
            username: username.clone(),
        },
        DecryptedData::SecureNote => EditableData::SecureNote,
        DecryptedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => EditableData::SshKey {
            private_key: private_key.clone(),
            public_key: public_key.clone(),
            fingerprint: fingerprint.clone(),
        },
    };

    let fields = decrypted
        .fields
        .iter()
        .map(|f| EditableCustomField {
            name: f.name.clone(),
            value: f.value.clone(),
            ty: f.ty.map(|t| field_type_str(t).to_string()),
        })
        .collect();

    EditableCipher {
        name: decrypted.name.clone(),
        folder: decrypted.folder.clone(),
        notes: decrypted.notes.clone(),
        data,
        fields,
    }
}

fn editable_to_encrypted(
    editable: &EditableCipher,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<(rbw::db::EntryData, Vec<rbw::db::Field>, Option<String>)>
{
    let data = match &editable.data {
        EditableData::Login {
            username,
            password,
            uris,
            totp,
            fido2_credentials,
        } => {
            let enc = |s: &Option<String>| {
                s.as_deref()
                    .filter(|v| !v.is_empty())
                    .map(|v| crate::actions::encrypt(v, entry_key, org_id))
                    .transpose()
            };
            let username = enc(username)?;
            let password = enc(password)?;
            let uris = uris
                .iter()
                .filter(|u| !u.uri.is_empty())
                .map(|u| {
                    let match_type = u
                        .match_type
                        .as_deref()
                        .map(parse_uri_match_type)
                        .transpose()?;
                    Ok(rbw::db::Uri {
                        uri: crate::actions::encrypt(
                            &u.uri, entry_key, org_id,
                        )?,
                        match_type,
                    })
                })
                .collect::<anyhow::Result<_>>()?;
            let totp = enc(totp)?;
            let fido2_credentials = fido2_credentials
                .iter()
                .map(|c| {
                    Ok(rbw::db::Fido2Credential {
                        credential_id: enc(&c.credential_id)?,
                        key_type: enc(&c.key_type)?,
                        key_algorithm: enc(&c.key_algorithm)?,
                        key_curve: enc(&c.key_curve)?,
                        key_value: enc(&c.key_value)?,
                        rp_id: enc(&c.rp_id)?,
                        user_handle: enc(&c.user_handle)?,
                        user_name: enc(&c.user_name)?,
                        counter: enc(&c.counter)?,
                        rp_name: enc(&c.rp_name)?,
                        user_display_name: enc(&c.user_display_name)?,
                        discoverable: enc(&c.discoverable)?,
                        // never encrypted to begin with
                        creation_date: c.creation_date.clone(),
                    })
                })
                .collect::<anyhow::Result<_>>()?;
            rbw::db::EntryData::Login {
                username,
                password,
                uris,
                totp,
                fido2_credentials,
            }
        }
        EditableData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => {
            let enc = |s: &Option<String>| {
                s.as_deref()
                    .filter(|v| !v.is_empty())
                    .map(|v| crate::actions::encrypt(v, entry_key, org_id))
                    .transpose()
            };
            rbw::db::EntryData::Card {
                cardholder_name: enc(cardholder_name)?,
                number: enc(number)?,
                brand: enc(brand)?,
                exp_month: enc(exp_month)?,
                exp_year: enc(exp_year)?,
                code: enc(code)?,
            }
        }
        EditableData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => {
            let enc = |s: &Option<String>| {
                s.as_deref()
                    .filter(|v| !v.is_empty())
                    .map(|v| crate::actions::encrypt(v, entry_key, org_id))
                    .transpose()
            };
            rbw::db::EntryData::Identity {
                title: enc(title)?,
                first_name: enc(first_name)?,
                middle_name: enc(middle_name)?,
                last_name: enc(last_name)?,
                address1: enc(address1)?,
                address2: enc(address2)?,
                address3: enc(address3)?,
                city: enc(city)?,
                state: enc(state)?,
                postal_code: enc(postal_code)?,
                country: enc(country)?,
                phone: enc(phone)?,
                email: enc(email)?,
                ssn: enc(ssn)?,
                license_number: enc(license_number)?,
                passport_number: enc(passport_number)?,
                username: enc(username)?,
            }
        }
        EditableData::SecureNote => rbw::db::EntryData::SecureNote,
        EditableData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => {
            let enc = |s: &Option<String>| {
                s.as_deref()
                    .filter(|v| !v.is_empty())
                    .map(|v| crate::actions::encrypt(v, entry_key, org_id))
                    .transpose()
            };
            rbw::db::EntryData::SshKey {
                private_key: enc(private_key)?,
                public_key: enc(public_key)?,
                fingerprint: enc(fingerprint)?,
            }
        }
    };

    let fields = editable
        .fields
        .iter()
        .map(|f| {
            let ty = f.ty.as_deref().map(parse_field_type).transpose()?;
            let name = f
                .name
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|n| crate::actions::encrypt(n, entry_key, org_id))
                .transpose()?;
            let value = f
                .value
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|v| crate::actions::encrypt(v, entry_key, org_id))
                .transpose()?;
            Ok(rbw::db::Field {
                ty,
                name,
                value,
                linked_id: None,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let notes = editable
        .notes
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string);

    Ok((data, fields, notes))
}

// `--from-file`'s counterpart to `editable_to_encrypted`: same shape, same
// empty-string-means-unset filtering, but a plain field copy instead of
// `crate::actions::encrypt(...)` -- there's nothing to encrypt against,
// and nothing here can fail the way encryption can, so this is infallible.
fn editable_to_decrypted(
    editable: &EditableCipher,
) -> (DecryptedData, Vec<DecryptedField>, Option<String>) {
    let unset_if_empty =
        |s: &Option<String>| s.clone().filter(|v| !v.is_empty());

    let data = match &editable.data {
        EditableData::Login {
            username,
            password,
            uris,
            totp,
            fido2_credentials,
        } => DecryptedData::Login {
            username: unset_if_empty(username),
            password: unset_if_empty(password),
            uris: (!uris.is_empty()).then(|| {
                uris.iter()
                    .filter(|u| !u.uri.is_empty())
                    .map(|u| DecryptedUri {
                        uri: u.uri.clone(),
                        match_type: u
                            .match_type
                            .as_deref()
                            .and_then(|mt| parse_uri_match_type(mt).ok()),
                    })
                    .collect()
            }),
            totp: unset_if_empty(totp),
            fido2_credentials: fido2_credentials
                .iter()
                .map(|c| DecryptedFido2Credential {
                    credential_id: c.credential_id.clone(),
                    key_type: c.key_type.clone(),
                    key_algorithm: c.key_algorithm.clone(),
                    key_curve: c.key_curve.clone(),
                    key_value: c.key_value.clone(),
                    rp_id: c.rp_id.clone(),
                    user_handle: c.user_handle.clone(),
                    user_name: c.user_name.clone(),
                    counter: c.counter.clone(),
                    rp_name: c.rp_name.clone(),
                    user_display_name: c.user_display_name.clone(),
                    discoverable: c.discoverable.clone(),
                    creation_date: c.creation_date.clone(),
                })
                .collect(),
        },
        EditableData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: unset_if_empty(cardholder_name),
            number: unset_if_empty(number),
            brand: unset_if_empty(brand),
            exp_month: unset_if_empty(exp_month),
            exp_year: unset_if_empty(exp_year),
            code: unset_if_empty(code),
        },
        EditableData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => DecryptedData::Identity {
            title: unset_if_empty(title),
            first_name: unset_if_empty(first_name),
            middle_name: unset_if_empty(middle_name),
            last_name: unset_if_empty(last_name),
            address1: unset_if_empty(address1),
            address2: unset_if_empty(address2),
            address3: unset_if_empty(address3),
            city: unset_if_empty(city),
            state: unset_if_empty(state),
            postal_code: unset_if_empty(postal_code),
            country: unset_if_empty(country),
            phone: unset_if_empty(phone),
            email: unset_if_empty(email),
            ssn: unset_if_empty(ssn),
            license_number: unset_if_empty(license_number),
            passport_number: unset_if_empty(passport_number),
            username: unset_if_empty(username),
        },
        EditableData::SecureNote => DecryptedData::SecureNote,
        EditableData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => DecryptedData::SshKey {
            private_key: unset_if_empty(private_key),
            public_key: unset_if_empty(public_key),
            fingerprint: unset_if_empty(fingerprint),
        },
    };

    let fields = editable
        .fields
        .iter()
        .map(|f| DecryptedField {
            name: unset_if_empty(&f.name),
            value: unset_if_empty(&f.value),
            ty: f.ty.as_deref().and_then(|ty| parse_field_type(ty).ok()),
        })
        .collect();

    let notes = unset_if_empty(&editable.notes);

    (data, fields, notes)
}

// ===========================================================================
// TUI support
//
// Thin orchestration helpers used by the interactive `rbw tui` front-end. They
// deliberately live here so the encryption / API / save / sync logic stays in
// one place (shared with `edit`, `add`, and `remove`) instead of being
// re-implemented in the UI layer.
// ===========================================================================

// Unlock the vault and return the local db together with a lightweight,
// batch-decrypted search index (one agent round-trip for the whole vault). The
// index is parallel to `db.entries` and drives list rendering and filtering;
// full per-entry detail is decrypted lazily via `decrypt_cipher`.
// A single unlocked account's loaded vault for the TUI.
pub struct TuiVault {
    pub account: String,
    pub db: rbw::db::Db,
    pub search: Vec<DecryptedSearchCipher>,
}

#[derive(Debug, Clone, Default)]
pub struct TuiEntryScope {
    pub organization: Option<String>,
    pub collections: Vec<String>,
}

pub fn tui_entry_scope(
    db: &rbw::db::Db,
    entry: &rbw::db::Entry,
) -> TuiEntryScope {
    let organization = entry.org_id.as_deref().map(|id| {
        db.organizations
            .iter()
            .find(|org| org.id == id)
            .map_or_else(|| id.to_string(), |org| org.name.clone())
    });
    let collections = entry
        .collection_ids
        .iter()
        .map(|id| {
            db.collections
                .iter()
                .find(|collection| collection.id == *id)
                .map_or_else(
                    || id.clone(),
                    |collection| collection.name.clone(),
                )
        })
        .collect();
    TuiEntryScope {
        organization,
        collections,
    }
}

// The initial state handed to the TUI: the vaults of every currently-unlocked
// account, the names of configured-but-locked accounts (offered for lazy
// unlock in the accounts panel), and whether more than one account exists (so
// the UI can hide account badges in the common single-account case).
pub struct TuiOpen {
    pub vaults: Vec<TuiVault>,
    pub locked: Vec<String>,
    pub multi: bool,
}

// The synthetic single vault behind `rbw tui --from-file`: like `TuiVault`,
// but `decrypted`/`attachment_data` carry what would otherwise be decrypted
// lazily via the agent -- there's no agent in this mode, since the export
// format is already plaintext.
pub struct TuiFileVault {
    pub label: String,
    pub db: rbw::db::Db,
    pub search: Vec<DecryptedSearchCipher>,
    pub decrypted: std::collections::HashMap<String, DecryptedCipher>,
    pub attachment_data: std::collections::HashMap<String, Vec<u8>>,
    pub entry_extra: std::collections::HashMap<String, FileEntryExtra>,
    pub collections: Vec<ExportedCollection>,
    pub passphrase: Option<String>,
    pub path: std::path::PathBuf,
    pub write: bool,
}

// Loads `path` (see `load_from_file`) into a `TuiFileVault`: a placeholder
// `rbw::db::Entry` per real entry (only `id` is real, used for indexing --
// nothing will ever decrypt these through `decrypt_cipher`) plus the real
// search index and full detail built directly from the already-decrypted
// entries. `write` (`rbw tui --from-file FILE --write`) takes a `.bak`
// snapshot of the file right away, before any edit can happen.
pub fn tui_vault_from_file(
    path: &std::path::Path,
    write: bool,
    passphrase: Option<&str>,
) -> anyhow::Result<TuiFileVault> {
    let vault = load_from_file(path, passphrase)?;
    if write {
        backup_file(path)?;
    }
    let label = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .map_or_else(
            || "export".to_string(),
            |name| format!("export: {name}"),
        );

    let mut db = rbw::db::Db::new();
    db.entries = vault
        .entries
        .iter()
        .map(|entry| placeholder_entry(entry.id.clone()))
        .collect();
    let search = vault
        .entries
        .iter()
        .map(decrypted_cipher_to_search)
        .collect();
    let decrypted = vault
        .entries
        .into_iter()
        .map(|entry| (entry.id.clone(), entry))
        .collect();

    Ok(TuiFileVault {
        label,
        db,
        search,
        decrypted,
        attachment_data: vault.attachment_data,
        entry_extra: vault.entry_extra,
        collections: vault.collections,
        passphrase: vault.passphrase,
        path: path.to_path_buf(),
        write,
    })
}

// Rebuilds the placeholder `db.entries`/search index pair from a
// `--from-file` vault's `decrypted` map -- the same construction
// `tui_vault_from_file` does for the initial load, reused after every
// `--write` mutation so the TUI's list/filtering stays in sync with
// entries added, edited, or removed in memory.
pub fn rebuild_file_vault_indices(
    decrypted: &std::collections::HashMap<String, DecryptedCipher>,
) -> (Vec<rbw::db::Entry>, Vec<DecryptedSearchCipher>) {
    let entries = decrypted
        .values()
        .map(|entry| placeholder_entry(entry.id.clone()))
        .collect();
    let search = decrypted.values().map(decrypted_cipher_to_search).collect();
    (entries, search)
}

// Everything a writable (`--write`) `--from-file` TUI vault needs to save
// itself back to disk, alongside the `decrypted`/`attachment_data` maps
// already on `AccountVault`.
pub struct FileSaveTarget {
    pub path: std::path::PathBuf,
    pub passphrase: Option<String>,
    pub collections: Vec<ExportedCollection>,
    pub entry_extra: std::collections::HashMap<String, FileEntryExtra>,
}

pub fn tui_file_entry_scope(
    target: &FileSaveTarget,
    entry_id: &str,
) -> TuiEntryScope {
    let Some(extra) = target.entry_extra.get(entry_id) else {
        return TuiEntryScope::default();
    };
    let collections = extra
        .collection_ids
        .iter()
        .map(|id| {
            target
                .collections
                .iter()
                .find(|collection| collection.id == *id)
                .map_or_else(
                    || id.clone(),
                    |collection| collection.name.clone(),
                )
        })
        .collect();
    TuiEntryScope {
        // The export format carries collection organization IDs, but not the
        // organization names. Keep the ID visible/searchable rather than
        // dropping the organization association from the preview.
        organization: extra.org_id.clone(),
        collections,
    }
}

// Writes `decrypted`/`attachment_data` back to `target.path`, in whatever
// format it was loaded in. Called after every `--write` TUI mutation.
fn save_file_vault(
    decrypted: &std::collections::HashMap<String, DecryptedCipher>,
    attachment_data: &std::collections::HashMap<String, Vec<u8>>,
    target: &FileSaveTarget,
) -> anyhow::Result<()> {
    let exported = decrypted
        .values()
        .map(|e| to_exported_entry(e, attachment_data, &target.entry_extra))
        .collect();
    save_to_file(
        &target.path,
        exported,
        target.collections.clone(),
        target.passphrase.as_deref(),
    )
}

// `rbw tui --from-file FILE --write`'s counterpart to `tui_save_edit`/
// `tui_save_add`: applies an `EditableCipher` (a new entry if `entry_id`
// is `None`, matching `tui_save_add`'s contract) directly to the in-memory
// vault and saves back to the file, instead of encrypting and pushing to
// the server. Existing attachments/history are preserved when editing;
// history additionally gets the outgoing password inserted, same as
// `tui_save_edit`.
pub fn tui_save_edit_to_file(
    decrypted: &mut std::collections::HashMap<String, DecryptedCipher>,
    attachment_data: &std::collections::HashMap<String, Vec<u8>>,
    target: &FileSaveTarget,
    entry_id: Option<&str>,
    updated: &EditableCipher,
) -> anyhow::Result<()> {
    if updated.name.trim().is_empty() {
        anyhow::bail!("name cannot be empty");
    }

    let existing = entry_id.and_then(|id| decrypted.get(id));
    let (data, fields, notes) = editable_to_decrypted(updated);

    let mut history = existing.map(|e| e.history.clone()).unwrap_or_default();
    if let Some(existing) = existing {
        if let (
            DecryptedData::Login {
                password: Some(old_pw),
                ..
            },
            DecryptedData::Login {
                password: new_pw, ..
            },
        ) = (&existing.data, &data)
        {
            if Some(old_pw) != new_pw.as_ref() {
                history.insert(
                    0,
                    DecryptedHistoryEntry {
                        last_used_date: format!(
                            "{}",
                            humantime::format_rfc3339(
                                std::time::SystemTime::now()
                            )
                        ),
                        password: old_pw.clone(),
                    },
                );
            }
        }
    }
    let attachments =
        existing.map(|e| e.attachments.clone()).unwrap_or_default();
    let archived = existing.is_some_and(|e| e.archived);
    let deleted = existing.is_some_and(|e| e.deleted);
    let id = entry_id.map_or_else(
        || uuid::Uuid::new_v4().to_string(),
        std::string::ToString::to_string,
    );

    decrypted.insert(
        id.clone(),
        DecryptedCipher {
            attachment_metadata: AttachmentMetadata::new(
                &id,
                attachments.len(),
            ),
            id,
            folder: updated.folder.clone(),
            name: updated.name.clone(),
            data,
            fields,
            notes,
            history,
            attachments,
            archived,
            deleted,
            account: None,
        },
    );

    save_file_vault(decrypted, attachment_data, target)
}

// `--write` TUI's counterpart to `tui_delete`.
pub fn tui_delete_from_file(
    decrypted: &mut std::collections::HashMap<String, DecryptedCipher>,
    attachment_data: &std::collections::HashMap<String, Vec<u8>>,
    target: &FileSaveTarget,
    entry_id: &str,
) -> anyhow::Result<()> {
    decrypted.remove(entry_id);
    save_file_vault(decrypted, attachment_data, target)
}

// `--write` TUI's counterpart to `tui_attachment_create`: reads `file`
// straight into the vault's attachment side table (there's no server to
// encrypt-and-upload to) and assigns it a fresh id.
pub fn tui_attachment_create_to_file(
    decrypted: &mut std::collections::HashMap<String, DecryptedCipher>,
    attachment_data: &mut std::collections::HashMap<String, Vec<u8>>,
    target: &FileSaveTarget,
    entry_id: &str,
    file: &std::path::Path,
) -> anyhow::Result<()> {
    let Some(entry) = decrypted.get_mut(entry_id) else {
        anyhow::bail!("entry no longer exists");
    };
    let filename = file
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?
        .to_string();
    let data = std::fs::read(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    let id = uuid::Uuid::new_v4().to_string();
    entry.attachments.push(DecryptedAttachment {
        id: id.clone(),
        file_name: Some(filename),
        size: None,
        size_name: None,
    });
    entry.attachment_metadata =
        AttachmentMetadata::new(&entry.id, entry.attachments.len());
    attachment_data.insert(id, data);

    save_file_vault(decrypted, attachment_data, target)
}

// `--write` TUI's counterpart to `tui_attachment_delete`.
pub fn tui_attachment_delete_from_file(
    decrypted: &mut std::collections::HashMap<String, DecryptedCipher>,
    attachment_data: &mut std::collections::HashMap<String, Vec<u8>>,
    target: &FileSaveTarget,
    entry_id: &str,
    attachment_id: &str,
) -> anyhow::Result<()> {
    let Some(entry) = decrypted.get_mut(entry_id) else {
        anyhow::bail!("entry no longer exists");
    };
    entry.attachments.retain(|a| a.id != attachment_id);
    entry.attachment_metadata =
        AttachmentMetadata::new(&entry.id, entry.attachments.len());
    attachment_data.remove(attachment_id);

    save_file_vault(decrypted, attachment_data, target)
}

// A stand-in `rbw::db::Entry` carrying just enough (a real `id`) to satisfy
// the TUI's `db.entries`/`search`/`slot` indexing for a `--from-file` vault.
// Every other field is unused: `ensure_detail` reads full detail from
// `AccountVault::decrypted` instead of ever calling `decrypt_cipher` on
// this.
fn placeholder_entry(id: String) -> rbw::db::Entry {
    rbw::db::Entry {
        id,
        org_id: None,
        folder: None,
        folder_id: None,
        name: String::new(),
        data: rbw::db::EntryData::Login {
            username: None,
            password: None,
            totp: None,
            uris: Vec::new(),
            fido2_credentials: Vec::new(),
        },
        fields: Vec::new(),
        notes: None,
        history: Vec::new(),
        key: None,
        master_password_reprompt: rbw::api::CipherRepromptType::None,
        archived: false,
        deleted: false,
        collection_ids: Vec::new(),
        attachments: Vec::new(),
    }
}

// Status of one configured account, for the accounts panel.
pub struct TuiAccount {
    pub name: String,
    pub email: Option<String>,
    pub server: String,
    pub unlocked: bool,
    pub primary: bool,
    // `(source account, optional source item)` from
    // `Account::credential_source`, if this account's master password is
    // linked to another account's vault.
    pub credential_source: Option<(String, Option<String>)>,
}

// True if the currently-active account is unlocked in the agent.
fn active_account_unlocked() -> bool {
    crate::actions::unlocked().is_ok()
}

// True if the named configured account is currently unlocked in the agent.
// Used by the TUI's periodic lock-detection poll (`App::poll_agent_lock`) to
// notice when an account it already loaded gets locked out from under it —
// by another process running `rbw lock`/`rbw stop-agent`, or a `lock_timeout`
// expiry — independently of the TUI's own lifetime. Like every other
// per-account tui_* helper, this leaves `crate::actions`' active-account
// pointer set to `name`; that's harmless for a passive check since the next
// real operation always re-points it before doing anything.
pub fn tui_account_unlocked(name: &str) -> anyhow::Result<bool> {
    crate::actions::set_active_account(Some(name.to_string()))?;
    Ok(active_account_unlocked())
}

// Whether an account should be proactively unlocked (prompting as needed)
// for a multi-account merge: `Always` unconditionally, `Never` not even with
// `all`, and the default `OnDemand` only when `all` is set. Shared by
// `list_target_accounts` and `tui_open_with_progress` so the two can't drift
// apart the way they used to -- `tui_open_with_progress` independently
// re-implemented this as `all && account.unlock != Never`, which silently
// dropped the "unconditionally" half of `Always`: an account configured
// `unlock: always` only actually got unlocked by `rbw tui` if `--all` was
// also passed on that invocation, unlike every other command honoring the
// same policy.
fn should_unlock_for_merge(
    policy: rbw::config::UnlockPolicy,
    all: bool,
) -> bool {
    match policy {
        rbw::config::UnlockPolicy::Always => true,
        rbw::config::UnlockPolicy::Never => false,
        rbw::config::UnlockPolicy::OnDemand => all,
    }
}

// Which accounts `list`/`search`/`get` should query. An explicit --account/
// RBW_ACCOUNT always wins and scopes to just that one account. Otherwise every
// configured account is a candidate, filtered per-account by
// `Account::excluded_from(ctx)` and `Account::unlock` (see
// `should_unlock_for_merge`); an account that isn't proactively unlocked
// still makes it into the merge if it happens to already be unlocked. `ctx`
// identifies the calling subcommand (e.g. `List`, `Search`, `Get`) so each can
// be excluded independently via `exclude_from`. `unlock_single_account`
// preserves the normal single-account behavior for commands that need vault
// data, while allowing login-only commands such as `sync` to stay locked.
fn list_target_accounts(
    all: bool,
    ctx: rbw::config::ExcludeContext,
    unlock_single_account: bool,
) -> anyhow::Result<Vec<String>> {
    if let Some(name) = crate::actions::current_account() {
        if unlock_single_account {
            unlock(None, None)?;
        }
        return Ok(vec![name]);
    }

    crate::actions::set_active_account(None)?;

    let config = rbw::config::Config::load()?;
    let accounts = config.accounts();
    if accounts.len() <= 1 {
        if unlock_single_account {
            unlock(None, None)?;
        }
        return Ok(vec![config.primary_account_name()]);
    }

    let mut out = Vec::new();
    for account in &accounts {
        if account.excluded_from(ctx) {
            continue;
        }
        crate::actions::set_active_account(Some(account.name.clone()))?;
        if should_unlock_for_merge(account.unlock.policy, all) {
            unlock(None, None)?;
            out.push(account.name.clone());
        } else if active_account_unlocked() {
            out.push(account.name.clone());
        }
    }
    Ok(out)
}

// Open the multi-account TUI. Unlocks the target account (--account /
// RBW_ACCOUNT, else primary) up front — pinentry runs here, on the real
// terminal, before the UI takes over the screen; the target is always
// loaded regardless of `exclude_from`, since it was asked for explicitly.
// Every other configured account not excluded from `Tui` is then unlocked
// per `should_unlock_for_merge` (so `unlock: always` accounts always come
// up, `--all` additionally brings in the `on-demand` ones, and `never`
// accounts are only loaded if already unlocked); the rest are reported as
// locked for lazy unlock from the accounts panel. An account excluded from
// `Tui` is skipped entirely -- it won't appear locked in the accounts panel
// either, unless it's the target.
pub fn tui_open_with_progress<F>(
    all: bool,
    target_unlocked: bool,
    mut progress: F,
) -> anyhow::Result<TuiOpen>
where
    F: FnMut(&str),
{
    let config = rbw::config::Config::load()?;
    let accounts = config.accounts();
    let target = crate::actions::current_account()
        .unwrap_or_else(|| config.primary_account_name());

    if !target_unlocked {
        crate::actions::set_active_account(Some(target.clone()))?;
        unlock(None, None)?;
    }

    let mut vaults = Vec::new();
    let mut locked = Vec::new();
    for account in &accounts {
        if account.name != target
            && account.excluded_from(rbw::config::ExcludeContext::Tui)
        {
            continue;
        }
        crate::actions::set_active_account(Some(account.name.clone()))?;
        let should_unlock =
            should_unlock_for_merge(account.unlock.policy, all);
        if should_unlock && !active_account_unlocked() {
            let msg = format!("unlocking '{}'...", account.name);
            progress(&msg);
            unlock(None, None)?;
        }
        if active_account_unlocked() {
            let msg = format!("syncing '{}'...", account.name);
            progress(&msg);
            let (db, search) = tui_reload()?;
            vaults.push(TuiVault {
                account: account.name.clone(),
                db,
                search,
            });
        } else {
            locked.push(account.name.clone());
        }
    }

    Ok(TuiOpen {
        multi: accounts.len() > 1,
        vaults,
        locked,
    })
}

pub fn tui_unlock_target() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    let target = crate::actions::current_account()
        .unwrap_or_else(|| config.primary_account_name());
    crate::actions::set_active_account(Some(target))?;
    unlock(None, None)?;
    Ok(())
}

// Lazily unlock one account and load its vault. pinentry runs here, so the
// caller must have restored the real terminal first (like the $EDITOR path).
pub fn tui_unlock_account(name: &str) -> anyhow::Result<TuiVault> {
    crate::actions::set_active_account(Some(name.to_string()))?;
    unlock(None, None)?;
    let (db, search) = tui_reload()?;
    Ok(TuiVault {
        account: name.to_string(),
        db,
        search,
    })
}

// Sync one account from the server and reload its vault.
pub fn tui_account_sync(name: &str) -> anyhow::Result<TuiVault> {
    crate::actions::set_active_account(Some(name.to_string()))?;
    let (db, search) = tui_sync()?;
    Ok(TuiVault {
        account: name.to_string(),
        db,
        search,
    })
}

// A `base_url` for display in the accounts panel: the bare hostname (no
// `https://`/`http://` scheme or trailing slash), or "bitwarden.com" for the
// official server (an unset `base_url`).
fn tui_account_server(base_url: Option<&str>) -> String {
    base_url.map_or_else(
        || "bitwarden.com".to_string(),
        |url| {
            url.strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))
                .unwrap_or(url)
                .trim_end_matches('/')
                .to_string()
        },
    )
}

// The status of every configured account, for the accounts panel.
pub fn tui_accounts() -> anyhow::Result<Vec<TuiAccount>> {
    let config = rbw::config::Config::load()?;
    let primary = config.primary_account_name();
    let accounts = config.accounts();
    let mut out = Vec::with_capacity(accounts.len());
    for account in accounts {
        if account.excluded_from(rbw::config::ExcludeContext::Tui) {
            continue;
        }
        crate::actions::set_active_account(Some(account.name.clone()))?;
        out.push(TuiAccount {
            unlocked: active_account_unlocked(),
            primary: account.name == primary,
            server: tui_account_server(account.base_url.as_deref()),
            email: account.email.clone(),
            credential_source: account
                .unlock
                .credentials
                .as_ref()
                .map(|cs| (cs.account.clone(), cs.item.clone())),
            name: account.name,
        });
    }
    Ok(out)
}

// Upload a file as an attachment on an already-loaded, already-unlocked entry
// (the TUI equivalent of `attachment_create`, which finds+unlocks itself).
pub fn tui_attachment_create(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    file: &std::path::Path,
) -> anyhow::Result<()> {
    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    let filename = file
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?;
    let data = std::fs::read(file)
        .with_context(|| format!("failed to read {}", file.display()))?;

    let (encrypted_data, encrypted_key, encrypted_filename) =
        crate::actions::encrypt_attachment(
            data,
            filename,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?;

    if let (Some(new_token), ()) = rbw::actions::create_attachment(
        &access_token,
        &refresh_token,
        &entry.id,
        &encrypted_filename,
        &encrypted_key,
        &encrypted_data,
    )? {
        db.access_token = Some(new_token);
        save_db(db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

// Delete an attachment from an entry and sync.
pub fn tui_attachment_delete(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    attachment_id: &str,
) -> anyhow::Result<()> {
    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    if let (Some(new_token), ()) = rbw::actions::delete_attachment(
        &access_token,
        &refresh_token,
        &entry.id,
        attachment_id,
    )? {
        db.access_token = Some(new_token);
        save_db(db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

// Add a new account to the config from the TUI accounts panel. Mirrors
// `account_add` but without printing or tearing down the agent (per-account
// keysets make that unnecessary). The account starts locked; unlocking it from
// the panel runs the login/unlock flow.
pub fn tui_account_add(
    name: &str,
    email: Option<String>,
    base_url: Option<String>,
) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("account name cannot be empty");
    }
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    if config.accounts.iter().any(|a| a.name == name) {
        anyhow::bail!("account '{name}' already exists");
    }
    let first = config.accounts.is_empty();
    config.accounts.push(rbw::config::Account {
        name: name.to_string(),
        email,
        sso_id: None,
        base_url,
        identity_url: None,
        ui_url: None,
        notifications_url: None,
        client_cert_path: None,
        unlock: rbw::config::UnlockConfig::default(),
        exclude_from: Vec::new(),
    });
    if first {
        config.primary_account = Some(name.to_string());
    }
    config.save()?;
    Ok(())
}

// Set the primary account without tearing down the agent: under per-account
// keysets (see the agent's State) the other accounts' keys stay valid, so
// there is no need to lock everything the way the CLI `account primary` does.
pub fn tui_set_primary(name: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()?;
    config.migrate_legacy();
    if !config.accounts.iter().any(|a| a.name == name) {
        anyhow::bail!("account '{name}' not found");
    }
    config.primary_account = Some(name.to_string());
    config.save()?;
    Ok(())
}

// The configured default password-generation policy, for the TUI's settings
// view. Never fails: a missing/unreadable config just means "no overrides
// yet" (mirrors `App::new`'s handling of the keymap config).
pub fn tui_password_gen_policy() -> rbw::config::PasswordGenPolicy {
    rbw::config::Config::load()
        .map(|c| c.password_gen)
        .unwrap_or_default()
}

// Persist an updated password-generation policy from the TUI's settings view.
pub fn tui_save_password_gen_policy(
    policy: rbw::config::PasswordGenPolicy,
) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    config.password_gen = policy;
    config.save()?;
    Ok(())
}

// Link (or edit) an account's `credential_source` from the TUI accounts
// panel. Mirrors `account_set`'s credential_source handling but without
// printing, per the other tui_* wrappers (see `tui_account_add`).
pub fn tui_account_set_credential_source(
    name: &str,
    source_account: &str,
    source_item: Option<&str>,
) -> anyhow::Result<()> {
    if source_account.trim().is_empty() {
        anyhow::bail!("source account is required");
    }

    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    let Some(account) = config.accounts.iter_mut().find(|a| a.name == name)
    else {
        anyhow::bail!("account '{name}' not found");
    };
    account.unlock.credentials = Some(rbw::config::CredentialSource {
        account: source_account.to_string(),
        item: source_item
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToString::to_string),
    });

    // Reject a self-reference or a cycle before persisting, same guard as
    // the CLI's `account_set`.
    config.credential_source_chain(name)?;

    config.save()?;
    Ok(())
}

// Clear an account's `credential_source` link from the TUI accounts panel.
pub fn tui_account_clear_credential_source(name: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    config.migrate_legacy();
    let Some(account) = config.accounts.iter_mut().find(|a| a.name == name)
    else {
        anyhow::bail!("account '{name}' not found");
    };
    account.unlock.credentials = None;
    config.save()?;
    Ok(())
}

// Re-read the (already unlocked) vault from disk and rebuild the search index.
// Used after an edit/add/remove has synced changes back to the local db.
pub fn tui_reload(
) -> anyhow::Result<(rbw::db::Db, Vec<DecryptedSearchCipher>)> {
    let db = load_db()?;
    let mut requests = BatchRequests::new();
    let plans: Vec<SearchCipherPlan> = db
        .entries
        .iter()
        .map(|entry| SearchCipherPlan::build(entry, &mut requests))
        .collect();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };
    let search = plans
        .into_iter()
        .map(|plan| plan.resolve(&results))
        .collect::<anyhow::Result<_>>()?;
    Ok((db, search))
}

// Pull remote changes from the server (via the agent), then rebuild the local
// view. Used by the TUI's manual sync shortcut.
pub fn tui_sync() -> anyhow::Result<(rbw::db::Db, Vec<DecryptedSearchCipher>)>
{
    crate::actions::sync()?;
    tui_reload()
}

// Blank empty/whitespace-only folder names to `None` so clearing the folder
// field doesn't create a folder literally named "".
fn folder_arg(folder: Option<&str>) -> Option<&str> {
    folder.map(str::trim).filter(|s| !s.is_empty())
}

// Persist an edited entry: encrypt the changed fields, preserve password
// history, resolve/create the folder, push to the server, and sync.
pub fn tui_save_edit(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    updated: &EditableCipher,
) -> anyhow::Result<()> {
    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    let (data, fields, notes) = editable_to_encrypted(
        updated,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let encrypted_name = crate::actions::encrypt(
        &updated.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| {
            crate::actions::encrypt(
                n,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose()?;

    let mut history = entry.history.clone();
    if let (
        rbw::db::EntryData::Login {
            password: Some(old_pw),
            ..
        },
        rbw::db::EntryData::Login {
            password: new_pw, ..
        },
    ) = (&entry.data, &data)
    {
        if Some(old_pw) != new_pw.as_ref() {
            history.insert(
                0,
                rbw::db::HistoryEntry {
                    last_used_date: format!(
                        "{}",
                        humantime::format_rfc3339(
                            std::time::SystemTime::now()
                        )
                    ),
                    password: old_pw.clone(),
                },
            );
        }
    }

    let folder_id =
        if let Some(folder_name) = folder_arg(updated.folder.as_deref()) {
            resolve_folder_id(db, &access_token, &refresh_token, folder_name)?
        } else {
            entry.folder_id.clone()
        };

    if let (Some(new_token), ()) = rbw::actions::edit(
        &access_token,
        &refresh_token,
        &entry.id,
        entry.org_id.as_deref(),
        entry.key.as_deref(),
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
        &history,
    )? {
        db.access_token = Some(new_token);
        save_db(db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

// Create a new entry from a filled-in template.
pub fn tui_save_add(
    db: &mut rbw::db::Db,
    cipher: &EditableCipher,
) -> anyhow::Result<()> {
    if cipher.name.trim().is_empty() {
        anyhow::bail!("name cannot be empty");
    }

    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    let (data, fields, notes) = editable_to_encrypted(cipher, None, None)?;
    let encrypted_name = crate::actions::encrypt(&cipher.name, None, None)?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, None, None))
        .transpose()?;

    let folder_id =
        if let Some(folder_name) = folder_arg(cipher.folder.as_deref()) {
            resolve_folder_id(db, &access_token, &refresh_token, folder_name)?
        } else {
            None
        };

    if let (Some(new_token), _) = rbw::actions::add(
        &access_token,
        &refresh_token,
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
    )? {
        db.access_token = Some(new_token);
        save_db(db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

// Delete an entry and sync.
pub fn tui_delete(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
) -> anyhow::Result<()> {
    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    if let (Some(new_token), ()) =
        rbw::actions::remove(&access_token, &refresh_token, &entry.id)?
    {
        db.access_token = Some(new_token);
        save_db(db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

// `TuiAction::ToggleArchived`'s implementation: archives the entry if it
// isn't archived, unarchives it if it is. Otherwise identical to
// `tui_delete` -- same token handling, same trailing sync.
pub fn tui_toggle_archived(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
) -> anyhow::Result<()> {
    let access_token = db
        .access_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;
    let refresh_token = db
        .refresh_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not logged in"))?;

    let rotated = if entry.archived {
        rbw::actions::unarchive(&access_token, &refresh_token, &entry.id)?
    } else {
        rbw::actions::archive(&access_token, &refresh_token, &entry.id)?
    };
    if let (Some(new_token), ()) = rotated {
        db.access_token = Some(new_token);
        save_db(db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

// Open the full entry as YAML in `$EDITOR` for structured editing of every
// field (including entry-type-specific fields the inline form omits). Returns
// `true` if the entry was changed and saved. The caller is responsible for
// suspending/restoring the terminal around this call.
pub fn tui_edit_in_editor(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    decrypted: &DecryptedCipher,
) -> anyhow::Result<bool> {
    let editable = decrypted_to_editable(decrypted);
    let serialized = serde_yaml::to_string(&editable)?;
    let help = "# Edit the YAML below. Lines starting with # are ignored.";

    let contents = rbw::edit::edit(&serialized, help, "yaml")?;
    let contents_trimmed = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });

    if contents_trimmed.trim() == serialized.trim() {
        return Ok(false);
    }

    let updated: EditableCipher = serde_yaml::from_str(&contents_trimmed)
        .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?;
    tui_save_edit(db, entry, &updated)?;
    Ok(true)
}

// Download and decrypt a single attachment (identified by id) into `dest_dir`,
// returning the path written. Mirrors `attachment_get` but operates on an
// already-loaded, already-unlocked db so the TUI can call it inline.
pub fn tui_attachment_get(
    db: &mut rbw::db::Db,
    entry: &rbw::db::Entry,
    decrypted: &DecryptedCipher,
    attachment_id: &str,
    dest_dir: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    let (attachment, decrypted_attachment) =
        find_attachment(entry, decrypted, attachment_id)?;

    let access_token = db
        .access_token
        .as_ref()
        .context("failed to find access token in db")?
        .clone();
    let refresh_token = db
        .refresh_token
        .as_ref()
        .context("failed to find refresh token in db")?
        .clone();
    let url = match rbw::actions::attachment_url(
        &access_token,
        &refresh_token,
        &entry.id,
        &attachment.id,
    ) {
        Ok((new_access_token, url)) => {
            if let Some(new_access_token) = new_access_token {
                db.access_token = Some(new_access_token);
                save_db(db)?;
            }
            url
        }
        Err(e) => attachment.url.clone().ok_or(e)?,
    };
    let encrypted = rbw::actions::download_attachment(&url)
        .context("failed to download attachment")?;
    let bytes = crate::actions::decrypt_attachment(
        encrypted,
        attachment.key.as_deref(),
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;

    let file_name = decrypted_attachment
        .file_name
        .as_deref()
        .and_then(|name| std::path::Path::new(name).file_name())
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("BitwardenAttachment");
    let path = dest_dir.join(file_name);
    std::fs::write(&path, bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

// The account the current operation targets: the one selected via
// --account / RBW_ACCOUNT (or, in the TUI, set per-entry via
// `set_active_account`), else the primary account. Keeps the local db path
// (server + email) aligned with whichever account the agent request targeted.
fn active_account() -> anyhow::Result<rbw::config::Account> {
    let config = rbw::config::Config::load()?;
    config
        .account(crate::actions::current_account().as_deref())
        .map_err(anyhow::Error::new)
}

fn account_email(account: &rbw::config::Account) -> anyhow::Result<&str> {
    account.email.as_deref().ok_or_else(|| {
        anyhow::anyhow!("failed to find email address in config")
    })
}

pub fn load_db() -> anyhow::Result<rbw::db::Db> {
    let account = active_account()?;
    rbw::db::Db::load(&account.server_name(), account_email(&account)?)
        .map_err(anyhow::Error::new)
}

fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let account = active_account()?;
    db.save(&account.server_name(), account_email(&account)?)
        .map_err(anyhow::Error::new)
}

fn remove_db() -> anyhow::Result<()> {
    let account = active_account()?;
    rbw::db::Db::remove(&account.server_name(), account_email(&account)?)
        .map_err(anyhow::Error::new)
}

struct TotpParams {
    secret: Vec<u8>,
    algorithm: String,
    digits: usize,
    period: u64,
}

fn decode_totp_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    let secret = secret.trim().replace(' ', "");
    let alphabets = [
        base32::Alphabet::Rfc4648 { padding: false },
        base32::Alphabet::Rfc4648 { padding: true },
        base32::Alphabet::Rfc4648Lower { padding: false },
        base32::Alphabet::Rfc4648Lower { padding: true },
    ];
    for alphabet in alphabets {
        if let Some(secret) = base32::decode(alphabet, &secret) {
            return Ok(secret);
        }
    }
    Err(anyhow::anyhow!("totp secret was not valid base32"))
}

fn parse_totp_secret(secret: &str) -> anyhow::Result<TotpParams> {
    if let Ok(u) = url::Url::parse(secret) {
        match u.scheme() {
            "otpauth" => {
                if u.host_str() != Some("totp") {
                    return Err(anyhow::anyhow!(
                        "totp secret url must have totp host"
                    ));
                }

                let query: std::collections::HashMap<_, _> =
                    u.query_pairs().collect();

                let secret = decode_totp_secret(
                    query.get("secret").ok_or_else(|| {
                        anyhow::anyhow!("totp secret url must have secret")
                    })?,
                )?;
                let algorithm = query.get("algorithm").map_or_else(
                    || String::from("SHA1"),
                    std::string::ToString::to_string,
                );
                let digits = match query.get("digits") {
                    Some(dig) => dig
                        .parse::<usize>()
                        .map_err(|_| anyhow::anyhow!("digits parameter in totp url must be a valid integer."))?,
                    None => 6,
                };
                let period = match query.get("period") {
                    Some(dig) => {
                        dig.parse::<u64>().map_err(|_| anyhow::anyhow!("period parameter in totp url must be a valid integer."))?
                    }
                    None => TOTP_DEFAULT_STEP,
                };

                Ok(TotpParams {
                    secret,
                    algorithm,
                    digits,
                    period,
                })
            }
            "steam" => {
                let steam_secret = u.host_str().unwrap();

                Ok(TotpParams {
                    secret: decode_totp_secret(steam_secret)?,
                    algorithm: String::from("STEAM"),
                    digits: 5,
                    period: TOTP_DEFAULT_STEP,
                })
            }
            _ => Err(anyhow::anyhow!(
                "totp secret url must have 'otpauth' or 'steam' scheme"
            )),
        }
    } else {
        Ok(TotpParams {
            secret: decode_totp_secret(secret)?,
            algorithm: String::from("SHA1"),
            digits: 6,
            period: TOTP_DEFAULT_STEP,
        })
    }
}

struct InjectContext {
    entries: Vec<rbw::db::Entry>,
}

impl InjectContext {
    fn load() -> anyhow::Result<Self> {
        unlock(None, None)?;

        let db = load_db()?;
        Ok(Self {
            entries: db.entries,
        })
    }

    fn render_input(
        &self,
        input: Option<&std::path::Path>,
    ) -> anyhow::Result<String> {
        let template = read_inject_template(input)?;
        InjectTemplate::new(&template)
            .render(|reference| self.resolve(reference))
    }

    fn env_bindings_from_file(
        &self,
        env_file: &std::path::Path,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let template =
            std::fs::read_to_string(env_file).with_context(|| {
                format!("failed to read env file {}", env_file.display())
            })?;
        parse_run_env_file(&template, |reference| self.resolve(reference))
            .with_context(|| {
                format!("failed to parse env file {}", env_file.display())
            })
    }

    fn resolve(&self, reference: &InjectReference) -> anyhow::Result<String> {
        let (entry, _) = self.find_entry_raw(&reference.target)?;
        let decrypted = decrypt_cipher(&entry).with_context(|| {
            format!("failed to decrypt entry '{}'", reference.id)
        })?;
        resolve_inject_value(&decrypted, reference.field.as_deref())
            .with_context(|| {
                format!(
                    "failed to resolve inject reference '{}'",
                    reference.id
                )
            })
    }

    fn find_entry_raw(
        &self,
        target: &InjectReferenceTarget,
    ) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                decrypt_search_cipher(entry)
                    .map(|decrypted| (entry.clone(), decrypted))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        target.find_entry(&entries)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum InjectReferenceTarget {
    Uuid(String),
    Name(String),
}

impl InjectReferenceTarget {
    fn parse(raw_target: &str) -> anyhow::Result<Self> {
        if let Ok(uuid) = uuid::Uuid::parse_str(raw_target) {
            Ok(Self::Uuid(uuid.to_string()))
        } else if Self::is_valid_name(raw_target) {
            Ok(Self::Name(raw_target.to_string()))
        } else {
            anyhow::bail!(
                "invalid item uuid or supported name '{raw_target}'"
            );
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Uuid(value) | Self::Name(value) => value,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Uuid(_) => "id",
            Self::Name(_) => "name",
        }
    }

    fn matches_entry(
        &self,
        entry: &rbw::db::Entry,
        decrypted: &DecryptedSearchCipher,
    ) -> bool {
        match self {
            Self::Uuid(id) => entry.id.eq_ignore_ascii_case(id),
            Self::Name(name) => decrypted.name.eq_ignore_ascii_case(name),
        }
    }

    fn find_entry(
        &self,
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
    ) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
        let matches: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = entries
            .iter()
            .filter(|(entry, decrypted)| self.matches_entry(entry, decrypted))
            .cloned()
            .collect();

        if matches.is_empty() {
            anyhow::bail!(
                "no entry found for item {} '{}'",
                self.kind(),
                self.as_str()
            );
        } else if matches.len() == 1 {
            Ok(matches[0].clone())
        } else {
            let entries: Vec<String> = matches
                .iter()
                .map(|(_, decrypted)| decrypted.display_name())
                .collect();
            match self {
                Self::Name(name) => anyhow::bail!(
                    "multiple entries found for item name '{}': {}; use bw://<uuid> instead",
                    name,
                    entries.join(", ")
                ),
                Self::Uuid(id) => anyhow::bail!(
                    "multiple entries found for item id '{}': {}",
                    id,
                    entries.join(", ")
                ),
            }
        }
    }

    fn is_valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.chars().all(|ch| {
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
            })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct InjectReference {
    id: String,
    target: InjectReferenceTarget,
    field: Option<String>,
}

impl InjectReference {
    fn parse(reference: &str) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(reference).with_context(|| {
            format!("invalid inject reference '{reference}'")
        })?;
        if parsed.scheme() != "bw" {
            anyhow::bail!(
                "invalid inject reference scheme '{}'",
                parsed.scheme()
            );
        }
        if parsed.fragment().is_some() {
            anyhow::bail!("inject references do not support fragments");
        }
        if !parsed.username().is_empty() {
            anyhow::bail!("inject references do not support usernames");
        }
        if parsed.password().is_some() {
            anyhow::bail!("inject references do not support passwords");
        }
        if parsed.port().is_some() {
            anyhow::bail!("inject references do not support ports");
        }
        if !parsed.path().is_empty() {
            anyhow::bail!("inject references do not support paths");
        }

        let raw_target = parsed
            .host_str()
            .context("inject reference is missing an item id or name")?;
        let target = InjectReferenceTarget::parse(raw_target)?;

        let mut field = None;
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "field" => {
                    if field.replace(value.into_owned()).is_some() {
                        anyhow::bail!(
                            "inject reference has multiple field parameters"
                        );
                    }
                }
                _ => anyhow::bail!(
                    "unsupported inject query parameter '{key}'"
                ),
            }
        }

        let field = field
            .map(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    anyhow::bail!(
                        "inject field query parameter cannot be empty"
                    );
                }
                Ok(trimmed.to_string())
            })
            .transpose()?;

        Ok(Self {
            id: target.as_str().to_string(),
            target,
            field,
        })
    }

    fn parse_braced(expr: &str) -> anyhow::Result<Option<Self>> {
        let expr = expr.trim();
        let expr = if expr.starts_with('"') {
            match serde_json::from_str::<String>(expr) {
                Ok(expr) => expr,
                Err(_) => return Ok(None),
            }
        } else {
            expr.to_string()
        };
        if !expr.starts_with("bw://") {
            return Ok(None);
        }
        Self::parse(&expr).map(Some)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum InjectMarker {
    Braced,
    Raw,
}

struct InjectTemplate<'a> {
    src: &'a str,
}

impl<'a> InjectTemplate<'a> {
    fn new(src: &'a str) -> Self {
        Self { src }
    }

    fn render<F>(&self, mut resolver: F) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        self.render_with_variable_resolver(
            lookup_inject_template_variable,
            |reference| resolver(reference),
        )
    }

    fn render_with_variable_resolver<F, G>(
        &self,
        mut lookup_variable: G,
        mut resolver: F,
    ) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
        G: FnMut(&str) -> Option<String>,
    {
        let expanded =
            self.expand_variables_with_lookup(&mut lookup_variable)?;
        InjectTemplate::new(&expanded)
            .render_secret_references(|reference| resolver(reference))
    }

    fn render_secret_references<F>(
        &self,
        mut resolver: F,
    ) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let mut rendered = String::with_capacity(self.src.len());
        let mut start = 0;
        while let Some((idx, marker)) = self.next_marker(start) {
            rendered.push_str(
                self.src
                    .get(start..idx)
                    .expect("marker range should be valid"),
            );
            start = match marker {
                InjectMarker::Braced => {
                    self.render_braced(idx, &mut rendered, &mut resolver)?
                }
                InjectMarker::Raw => {
                    self.render_raw(idx, &mut rendered, &mut resolver)?
                }
            };
        }
        rendered.push_str(
            self.src
                .get(start..)
                .expect("template tail range should be valid"),
        );
        Ok(rendered)
    }

    fn expand_variables_with_lookup<G>(
        &self,
        lookup_variable: &mut G,
    ) -> anyhow::Result<String>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let mut rendered = String::with_capacity(self.src.len());
        let mut start = 0;
        while let Some(offset) = self
            .src
            .get(start..)
            .expect("variable search start should be valid")
            .find('$')
        {
            let idx = start + offset;
            rendered.push_str(
                self.src
                    .get(start..idx)
                    .expect("variable prefix range should be valid"),
            );
            if let Some((value, next_start)) =
                self.resolve_variable_at(idx, lookup_variable)?
            {
                rendered.push_str(&value);
                start = next_start;
            } else {
                rendered.push('$');
                start = idx + '$'.len_utf8();
            }
        }
        rendered.push_str(
            self.src
                .get(start..)
                .expect("variable tail range should be valid"),
        );
        Ok(rendered)
    }

    fn take_braced_expression(
        &self,
        idx: usize,
    ) -> anyhow::Result<(&'a str, usize)> {
        let rest = self
            .src
            .get(idx..)
            .expect("braced expression start should be valid")
            .strip_prefix("{{")
            .expect("braced expression must start with '{{'");
        let Some((expr, tail)) = rest.split_once("}}") else {
            anyhow::bail!("unterminated inject template expression");
        };
        Ok((expr, self.src.len() - tail.len()))
    }

    fn render_braced<F>(
        &self,
        idx: usize,
        out: &mut String,
        resolver: &mut F,
    ) -> anyhow::Result<usize>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let (expr, next_start) = self.take_braced_expression(idx)?;
        if let Some(reference) = InjectReference::parse_braced(expr)? {
            out.push_str(&resolver(&reference)?);
        } else {
            out.push_str("{{");
            out.push_str(expr);
            out.push_str("}}");
        }
        Ok(next_start)
    }

    fn render_raw<F>(
        &self,
        idx: usize,
        out: &mut String,
        resolver: &mut F,
    ) -> anyhow::Result<usize>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let end = self.raw_reference_end(idx);
        let candidate = self
            .src
            .get(idx..end)
            .expect("raw reference range should be valid");
        let reference = InjectReference::parse(candidate)?;
        out.push_str(&resolver(&reference)?);
        Ok(end)
    }

    fn resolve_variable_at<G>(
        &self,
        idx: usize,
        lookup_variable: &mut G,
    ) -> anyhow::Result<Option<(String, usize)>>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let rest = self
            .src
            .get(idx + '$'.len_utf8()..)
            .expect("variable suffix range should be valid");
        match rest.chars().next() {
            Some('{') => self.resolve_braced_variable(idx, lookup_variable),
            Some(ch) if Self::is_valid_variable_start(ch) => {
                let name_len = rest
                    .char_indices()
                    .take_while(|(_, ch)| {
                        Self::is_valid_variable_continue(*ch)
                    })
                    .last()
                    .map_or(0, |(offset, ch)| offset + ch.len_utf8());
                let name = rest
                    .get(..name_len)
                    .expect("raw variable name range should be valid");
                if let Some(value) = lookup_variable(name) {
                    Ok(Some((value, idx + '$'.len_utf8() + name_len)))
                } else {
                    anyhow::bail!(
                        "inject template variable '{name}' is not set"
                    );
                }
            }
            _ => Ok(None),
        }
    }

    fn resolve_braced_variable<G>(
        &self,
        idx: usize,
        lookup_variable: &mut G,
    ) -> anyhow::Result<Option<(String, usize)>>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let expr_start = idx + "${".len();
        let rest = self
            .src
            .get(expr_start..)
            .expect("braced variable start should be valid");
        let mut depth = 1usize;
        let mut end = None;
        let mut offset = 0;
        while offset < rest.len() {
            let tail = rest
                .get(offset..)
                .expect("braced variable tail range should be valid");
            if tail.starts_with("\\}") {
                offset += "\\}".len();
                continue;
            }
            if tail.starts_with("${") {
                depth += 1;
                offset += "${".len();
                continue;
            }
            let ch = tail
                .chars()
                .next()
                .expect("braced variable tail should not be empty");
            if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    end = Some(expr_start + offset);
                    break;
                }
            }
            offset += ch.len_utf8();
        }
        let end = end.context("unterminated inject template variable")?;
        let expr = self
            .src
            .get(expr_start..end)
            .expect("braced variable expression range should be valid");
        let (name, default) = match expr.split_once(":-") {
            Some((name, default)) => (name.trim(), Some(default)),
            None => (expr.trim(), None),
        };
        if !Self::is_valid_variable_name(name) {
            return Ok(None);
        }
        let value = if let Some(value) = lookup_variable(name) {
            value
        } else if let Some(default) = default {
            InjectTemplate::new(default)
                .expand_variables_with_lookup(lookup_variable)?
        } else {
            anyhow::bail!("inject template variable '{name}' is not set");
        };
        Ok(Some((value, end + '}'.len_utf8())))
    }

    fn next_marker(&self, start: usize) -> Option<(usize, InjectMarker)> {
        let rest = self
            .src
            .get(start..)
            .expect("marker search start should be valid");
        let braced = rest
            .find("{{")
            .map(|offset| (start + offset, InjectMarker::Braced));
        let raw = rest
            .match_indices("bw://")
            .map(|(offset, _)| start + offset)
            .find(|&idx| Self::raw_reference_can_start(self.src, idx))
            .map(|idx| (idx, InjectMarker::Raw));

        match (braced, raw) {
            (Some(braced), Some(raw)) => {
                Some(if braced.0 <= raw.0 { braced } else { raw })
            }
            (Some(braced), None) => Some(braced),
            (None, Some(raw)) => Some(raw),
            (None, None) => None,
        }
    }

    fn raw_reference_end(&self, start: usize) -> usize {
        let mut end = start + "bw://".len();
        let mut seen_query = false;
        let mut seen_query_equals = false;
        for (offset, ch) in self
            .src
            .get(end..)
            .expect("raw reference start should be valid")
            .char_indices()
        {
            let is_allowed = if ch.is_ascii_alphanumeric()
                || matches!(ch, '-' | '_')
                || (seen_query_equals && matches!(ch, '.' | '%' | '+'))
            {
                true
            } else if ch == '?' && !seen_query {
                seen_query = true;
                true
            } else if ch == '=' && seen_query && !seen_query_equals {
                seen_query_equals = true;
                true
            } else {
                false
            };
            if !is_allowed {
                break;
            }
            end = start + "bw://".len() + offset + ch.len_utf8();
        }
        end
    }

    fn raw_reference_can_start(template: &str, idx: usize) -> bool {
        template
            .get(..idx)
            .and_then(|prefix| prefix.chars().next_back())
            .is_none_or(|ch| {
                !ch.is_ascii_alphanumeric()
                    && !matches!(ch, '-' | '+' | '\\' | '.')
            })
    }

    fn is_valid_variable_name(name: &str) -> bool {
        let mut chars = name.chars();
        matches!(chars.next(), Some(ch) if Self::is_valid_variable_start(ch))
            && chars.all(Self::is_valid_variable_continue)
    }

    fn is_valid_variable_start(ch: char) -> bool {
        ch.is_ascii_alphabetic() || ch == '_'
    }

    fn is_valid_variable_continue(ch: char) -> bool {
        ch.is_ascii_alphanumeric() || ch == '_'
    }
}

fn lookup_inject_template_variable(name: &str) -> Option<String> {
    std::env::vars().find_map(|(key, value)| {
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

fn read_inject_template(
    input: Option<&std::path::Path>,
) -> anyhow::Result<String> {
    let mut template = String::new();
    match input {
        Some(path) => {
            std::fs::File::open(path)
                .with_context(|| {
                    format!("failed to open template {}", path.display())
                })?
                .read_to_string(&mut template)
                .with_context(|| {
                    format!("failed to read template {}", path.display())
                })?;
        }
        None => {
            std::io::stdin()
                .read_to_string(&mut template)
                .context("failed to read template from stdin")?;
        }
    }
    Ok(template)
}

fn parse_run_env_file<F>(
    template: &str,
    mut resolver: F,
) -> anyhow::Result<Vec<(String, String)>>
where
    F: FnMut(&InjectReference) -> anyhow::Result<String>,
{
    dotenvy::from_read_iter(std::io::Cursor::new(template))
        .map(|item| {
            let (key, value) = item.map_err(anyhow::Error::from)?;
            InjectTemplate::new(&value)
                .render_secret_references(|reference| resolver(reference))
                .map(|rendered| (key, rendered))
        })
        .collect()
}

fn build_inject_run_command(
    command: &[OsString],
    env_bindings: &[(String, String)],
) -> anyhow::Result<std::process::Command> {
    let Some(program) = command.first() else {
        anyhow::bail!("missing child command");
    };

    let mut child = std::process::Command::new(program);
    child.args(&command[1..]);
    child.stdin(std::process::Stdio::inherit());
    child.stdout(std::process::Stdio::inherit());
    child.stderr(std::process::Stdio::inherit());
    for (key, value) in env_bindings {
        child.env(key, value);
    }
    Ok(child)
}

fn run_inject_command(
    command: &[OsString],
    env_bindings: &[(String, String)],
) -> anyhow::Result<std::process::ExitStatus> {
    let mut child = build_inject_run_command(command, env_bindings)?;
    child.status().with_context(|| {
        let program = command.first().map_or_else(
            || "<missing command>".to_string(),
            |program| program.to_string_lossy().into_owned(),
        );
        format!("failed to run child command '{program}'")
    })
}

fn resolve_inject_value(
    cipher: &DecryptedCipher,
    field: Option<&str>,
) -> anyhow::Result<String> {
    let normalized = field
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .map(str::to_lowercase);
    match normalized.as_deref() {
        None | Some("password") => match &cipher.data {
            DecryptedData::Login {
                password: Some(password),
                ..
            } => Ok(password.clone()),
            DecryptedData::Login { .. } => {
                anyhow::bail!("entry '{}' has no password", cipher.name)
            }
            _ => {
                anyhow::bail!("entry '{}' is not a login entry", cipher.name)
            }
        },
        Some("username" | "user") => match &cipher.data {
            DecryptedData::Login {
                username: Some(username),
                ..
            } => Ok(username.clone()),
            DecryptedData::Login { .. } => {
                anyhow::bail!("entry '{}' has no username", cipher.name)
            }
            _ => {
                anyhow::bail!("entry '{}' is not a login entry", cipher.name)
            }
        },
        Some(field) => cipher
            .fields
            .iter()
            .find(|custom| {
                custom
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(field))
            })
            .and_then(|custom| custom.value.clone())
            .with_context(|| {
                format!(
                    "entry '{}' has no field named '{}'",
                    cipher.name, field
                )
            }),
    }
}

fn write_rendered_template_file(
    path: &std::path::Path,
    rendered: &str,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "rendered template target '{}' must not be a symlink",
                        path.display()
                    );
                }
                if !metadata.file_type().is_file() {
                    anyhow::bail!(
                        "rendered template target '{}' is not a regular file",
                        path.display()
                    );
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect rendered template {}",
                        path.display()
                    )
                });
            }
        }

        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => std::path::Path::new("."),
        };
        let mut file = tempfile::Builder::new()
            .prefix(".rbw-rendered-template.")
            .tempfile_in(parent)
            .with_context(|| {
                format!(
                    "failed to open temporary rendered template near {}",
                    path.display()
                )
            })?;
        file.as_file_mut()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to set secure permissions on {}",
                    path.display()
                )
            })?;
        file.write_all(rendered.as_bytes()).with_context(|| {
            format!("failed to write rendered template {}", path.display())
        })?;
        file.as_file_mut().sync_all().with_context(|| {
            format!("failed to sync rendered template {}", path.display())
        })?;
        file.persist(path)
            .map_err(|err| err.error)
            .with_context(|| {
                format!(
                    "failed to persist rendered template {}",
                    path.display()
                )
            })?;
        std::fs::File::open(parent)
            .with_context(|| {
                format!(
                    "failed to sync rendered template directory {}",
                    parent.display()
                )
            })?
            .sync_all()
            .with_context(|| {
                format!(
                    "failed to sync rendered template directory {}",
                    parent.display()
                )
            })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, rendered).with_context(|| {
            format!("failed to write rendered template {}", path.display())
        })?;
        Ok(())
    }
}

// This function exists for the sake of making the generate_totp function less
// densely packed and more readable
fn generate_totp_algorithm_type(
    alg: &str,
) -> anyhow::Result<totp_rs::Algorithm> {
    match alg {
        "SHA1" => Ok(totp_rs::Algorithm::SHA1),
        "SHA256" => Ok(totp_rs::Algorithm::SHA256),
        "SHA512" => Ok(totp_rs::Algorithm::SHA512),
        "STEAM" => Ok(totp_rs::Algorithm::Steam),
        _ => Err(anyhow::anyhow!(format!("{alg} is not a valid algorithm"))),
    }
}

pub fn generate_totp(secret: &str) -> anyhow::Result<String> {
    let totp_params = parse_totp_secret(secret)?;
    let alg = totp_params.algorithm.as_str();

    match alg {
        "SHA1" | "SHA256" | "SHA512" => Ok(totp_rs::TOTP::new_unchecked(
            generate_totp_algorithm_type(alg)?,
            totp_params.digits,
            1, // the library docs say this should be a 1
            totp_params.period,
            totp_params.secret,
        )
        .generate_current()?),
        "STEAM" => Ok(totp_rs::TOTP::new_steam(totp_params.secret)
            .generate_current()?),
        _ => Err(anyhow::anyhow!(format!(
            "{alg} is not a valid totp algorithm"
        ))),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_load_mirror_config_uses_camel_case_fields() {
        let mut file = tempfile::NamedTempFile::with_suffix(".yaml").unwrap();
        write!(
            file,
            "mirrors:\n  - from: source\n    to: destination\n    destCollection: Shared\n    fallbackToWholeVault: true\n"
        )
        .unwrap();
        file.flush().unwrap();

        let config = load_mirror_config(file.path()).unwrap();
        assert_eq!(config.mirrors.len(), 1);
        assert_eq!(config.mirrors[0].from, "source");
        assert_eq!(
            config.mirrors[0].dest_collection.as_deref(),
            Some("Shared")
        );
        assert!(config.mirrors[0].fallback_to_whole_vault);
    }

    fn imported_login(name: &str, username: Option<&str>) -> ImportedEntry {
        ImportedEntry {
            id: None,
            org_id: None,
            folder: None,
            name: name.to_string(),
            data: ImportedData::Login {
                username: username.map(std::string::ToString::to_string),
                password: None,
                totp: None,
                uris: None,
                fido2_credentials: Vec::new(),
            },
            fields: Vec::new(),
            notes: None,
            history: Vec::new(),
            collection_ids: Vec::new(),
            archived: false,
            deleted: false,
            attachments: Vec::new(),
        }
    }

    // `bulk_create_batch`'s same-batch dedup, and its post-bulk-import
    // matching of newly-appeared entries back to their intended import
    // entry, both key off this -- must exactly match `existing_index`'s key
    // in `import_vault` (built the same way from `db::DecryptedCipher`) or
    // entries would spuriously collide or never be found after bulk import.
    #[test]
    fn test_imported_entry_key_uses_username_only_for_logins() {
        let login = imported_login("foo", Some("bar"));
        assert_eq!(
            imported_entry_key(&login),
            ("foo".to_string(), Some("bar".to_string()))
        );
    }

    #[test]
    fn test_imported_entry_key_ignores_username_for_non_logins() {
        let note = ImportedEntry {
            data: ImportedData::SecureNote,
            ..imported_login("foo", Some("bar"))
        };
        assert_eq!(imported_entry_key(&note), ("foo".to_string(), None));
    }

    #[test]
    fn test_imported_entry_key_distinguishes_by_username() {
        let a = imported_login("shared-name", Some("alice"));
        let b = imported_login("shared-name", Some("bob"));
        assert_ne!(imported_entry_key(&a), imported_entry_key(&b));
    }

    // `item_progress_bar`'s `{msg}` field must stay a fixed display width,
    // otherwise the bar/counter after it visibly shifts left/right as
    // different items' names scroll through at different lengths.
    #[test]
    fn test_fit_to_width_pads_short_text() {
        let out = fit_to_width("abc", 6);
        assert_eq!(out, "abc   ");
        assert_eq!(unicode_width::UnicodeWidthStr::width(out.as_str()), 6);
    }

    #[test]
    fn test_fit_to_width_leaves_exact_width_text_untouched() {
        let out = fit_to_width("abcdef", 6);
        assert_eq!(out, "abcdef");
    }

    #[test]
    fn test_fit_to_width_truncates_long_text_with_ellipsis() {
        let out = fit_to_width("abcdefghij", 6);
        assert_eq!(out, "abc...");
        assert_eq!(unicode_width::UnicodeWidthStr::width(out.as_str()), 6);
    }

    #[test]
    fn test_fit_to_width_measures_wide_characters_not_bytes() {
        // Each "字" is 2 display columns wide but 3 bytes -- a naive
        // byte-length truncation would cut a multi-byte character in half.
        let out = fit_to_width("字字字字字", 6);
        assert_eq!(unicode_width::UnicodeWidthStr::width(out.as_str()), 6);
        assert!(out.contains("..."), "{out:?}");
    }

    #[test]
    fn test_export_entry_in_scope_includes_trashed_entries() {
        let trashed = rbw::db::Entry {
            deleted: true,
            ..placeholder_entry("id".to_string())
        };
        assert!(export_entry_in_scope(&trashed, None, None));
        assert!(export_entry_status_allowed(&trashed, false, false));
        assert!(!export_entry_status_allowed(&trashed, true, false));
    }

    #[test]
    fn test_export_entry_status_can_skip_archived_entries() {
        let archived = rbw::db::Entry {
            archived: true,
            ..placeholder_entry("id".to_string())
        };
        assert!(export_entry_status_allowed(&archived, false, false));
        assert!(!export_entry_status_allowed(&archived, false, true));
    }

    #[test]
    fn test_export_entry_in_scope_includes_everything_when_unscoped() {
        let entry = placeholder_entry("id".to_string());
        assert!(export_entry_in_scope(&entry, None, None));
    }

    #[test]
    fn test_export_entry_in_scope_filters_by_collection() {
        let entry = rbw::db::Entry {
            collection_ids: vec!["c1".to_string()],
            ..placeholder_entry("id".to_string())
        };
        assert!(export_entry_in_scope(&entry, Some("c1"), None));
        assert!(!export_entry_in_scope(&entry, Some("other"), None));
    }

    #[test]
    fn test_export_entry_in_scope_filters_by_org() {
        let entry = rbw::db::Entry {
            org_id: Some("org1".to_string()),
            ..placeholder_entry("id".to_string())
        };
        assert!(export_entry_in_scope(&entry, None, Some("org1")));
        assert!(!export_entry_in_scope(&entry, None, Some("other")));
    }

    // `Always` unlocks regardless of `--all`/`all` -- the bug this guards
    // against had `tui_open_with_progress` gating it behind `all` too, so an
    // `unlock: always` account silently stayed locked on a plain `rbw tui`.
    #[test]
    fn test_should_unlock_for_merge_always_ignores_the_all_flag() {
        assert!(should_unlock_for_merge(
            rbw::config::UnlockPolicy::Always,
            false
        ));
        assert!(should_unlock_for_merge(
            rbw::config::UnlockPolicy::Always,
            true
        ));
    }

    #[test]
    fn test_should_unlock_for_merge_never_ignores_the_all_flag() {
        assert!(!should_unlock_for_merge(
            rbw::config::UnlockPolicy::Never,
            false
        ));
        assert!(!should_unlock_for_merge(
            rbw::config::UnlockPolicy::Never,
            true
        ));
    }

    #[test]
    fn test_should_unlock_for_merge_on_demand_follows_the_all_flag() {
        assert!(!should_unlock_for_merge(
            rbw::config::UnlockPolicy::OnDemand,
            false
        ));
        assert!(should_unlock_for_merge(
            rbw::config::UnlockPolicy::OnDemand,
            true
        ));
    }

    #[test]
    fn test_tui_account_server_strips_scheme_and_trailing_slash() {
        assert_eq!(tui_account_server(None), "bitwarden.com");
        assert_eq!(
            tui_account_server(Some("https://vault.wiit.one")),
            "vault.wiit.one"
        );
        assert_eq!(
            tui_account_server(Some("http://vault.example.com/")),
            "vault.example.com"
        );
        // A bare hostname (no scheme) is passed through unchanged.
        assert_eq!(
            tui_account_server(Some("vault.example.com")),
            "vault.example.com"
        );
    }

    #[test]
    fn test_attachment_metadata_serializes_attachment_count() {
        let metadata = AttachmentMetadata::new("cipher-id", 2);

        assert_eq!(
            serde_json::to_value(&metadata).unwrap(),
            serde_json::json!({
                "attachment_count": 2
            })
        );
    }

    #[test]
    fn test_attachment_metadata_omits_empty_json_fields() {
        let metadata = AttachmentMetadata::new("cipher-id", 0);

        assert_eq!(
            serde_json::to_value(&metadata).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn test_history_entry_serializes_expected_fields() {
        let entry = DecryptedHistoryEntry {
            last_used_date: "2026-01-01T00:00:00Z".to_string(),
            password: "hunter2".to_string(),
        };

        assert_eq!(
            serde_json::to_value(&entry).unwrap(),
            serde_json::json!({
                "last_used_date": "2026-01-01T00:00:00Z",
                "password": "hunter2",
            })
        );
    }

    #[test]
    fn test_list_field_accepts_uid_alias() {
        let field = "uid".to_string();

        assert!(matches!(
            ListField::try_from(&field).unwrap(),
            ListField::Id
        ));
    }

    #[test]
    fn test_format_ambiguous_entry_renders_multiline_details() {
        let rendered = format_ambiguous_entry(
            &DecryptedSearchCipher {
                id: "cipher-id".to_string(),
                entry_type: "Login".to_string(),
                folder: Some("mail".to_string()),
                name: "google.com".to_string(),
                user: Some("alice@example.com".to_string()),
                uris: vec![],
                fields: vec![],
                notes: None,
                attachment_count: 2,
                archived: false,
                deleted: false,
                sensitive_fields: vec![],
                password: None,
            },
            false,
        );

        assert_eq!(
            rendered,
            "  - google.com (uid: cipher-id | username: alice@example.com | folder: mail | attachments: 2)"
        );
    }

    #[test]
    fn test_search_match_respects_with_attachments_filter() {
        let entry = DecryptedSearchCipher {
            id: "cipher-id".to_string(),
            entry_type: "Login".to_string(),
            folder: None,
            name: "example".to_string(),
            user: None,
            uris: vec![],
            fields: vec![],
            notes: None,
            attachment_count: 0,
            archived: false,
            deleted: false,
            sensitive_fields: vec![],
            password: None,
        };

        assert!(entry.search_match("exa", None, false));
        assert!(!entry.search_match("exa", None, true));
    }

    #[test]
    fn test_search_match_supports_field_scoped_query_syntax() {
        let entry = DecryptedSearchCipher {
            id: "cipher-id".to_string(),
            entry_type: "Login".to_string(),
            folder: Some("Work".to_string()),
            name: "Google".to_string(),
            user: Some("alice".to_string()),
            uris: vec![("https://google.com".to_string(), None)],
            fields: vec!["custom-value".to_string()],
            notes: Some("some notes here".to_string()),
            attachment_count: 0,
            archived: false,
            deleted: false,
            sensitive_fields: vec![],
            password: None,
        };

        // A scoped term only matches its own field.
        assert!(entry.search_match("u:alice", None, false));
        assert!(!entry.search_match("u:google", None, false));
        assert!(entry.search_match("uri:google", None, false));
        assert!(!entry.search_match("uri:alice", None, false));
        assert!(entry.search_match("n:goog", None, false));
        assert!(entry.search_match("f:work", None, false));
        assert!(entry.search_match("notes:here", None, false));
        assert!(entry.search_match("field:custom", None, false));

        // Multiple words AND together, mixing scoped and bare terms.
        assert!(entry.search_match("u:alice uri:google", None, false));
        assert!(!entry.search_match("u:alice uri:bing", None, false));
        assert!(entry.search_match("Google u:alice", None, false));

        // An unrecognized prefix falls back to a literal substring match
        // instead of erroring or matching nothing.
        assert!(!entry.search_match("bogus:alice", None, false));

        let scope = TuiEntryScope {
            organization: Some("Acme Engineering".to_string()),
            collections: vec!["Production".to_string()],
        };
        assert!(entry.search_match_with_scope(
            "org:acme col:prod",
            None,
            false,
            Some(&scope),
        ));
        assert!(!entry.search_match_with_scope(
            "org:personal",
            None,
            false,
            Some(&scope),
        ));
    }

    #[test]
    fn test_highlight_ranges_scopes_to_the_matching_field() {
        // A bare word highlights in every field it appears in.
        assert_eq!(
            highlight_ranges("goog", SearchField::Name, "Google"),
            vec![(0, 4)]
        );
        assert_eq!(
            highlight_ranges("goog", SearchField::User, "googler"),
            vec![(0, 4)]
        );

        // A scoped word only highlights its own field.
        assert_eq!(
            highlight_ranges("u:ali", SearchField::User, "alice"),
            vec![(0, 3)]
        );
        assert_eq!(
            highlight_ranges("u:ali", SearchField::Name, "alice corp"),
            Vec::new()
        );

        // Multiple non-overlapping occurrences all highlight.
        assert_eq!(
            highlight_ranges("a", SearchField::Name, "banana"),
            vec![(1, 2), (3, 4), (5, 6)]
        );

        // No match, or an empty query, highlights nothing.
        assert_eq!(
            highlight_ranges("zzz", SearchField::Name, "Google"),
            Vec::new()
        );
        assert_eq!(
            highlight_ranges("", SearchField::Name, "Google"),
            Vec::new()
        );
    }

    #[test]
    fn test_paint_with_matches_colors_the_matched_ranges_grep_style() {
        // No ranges: falls back to plain base-color painting (or none, for
        // an empty base code).
        assert_eq!(
            style::paint_with_matches("hi", "32", &[], true),
            "\x1b[32mhi\x1b[0m"
        );
        assert_eq!(style::paint_with_matches("hi", "", &[], true), "hi");

        // A match is bold red, wrapped by the base color on either side.
        assert_eq!(
            style::paint_with_matches(
                "philipp@schmitt.co",
                "32",
                &[(0, 7)],
                true
            ),
            "\x1b[1;31mphilipp\x1b[0m\x1b[32m@schmitt.co\x1b[0m"
        );

        // Same, but with no base color (e.g. the uri column).
        assert_eq!(
            style::paint_with_matches("google.com", "", &[(0, 6)], true),
            "\x1b[1;31mgoogle\x1b[0m.com"
        );

        // Color disabled: always plain, match or not.
        assert_eq!(
            style::paint_with_matches("hi", "32", &[(0, 2)], false),
            "hi"
        );
    }

    #[test]
    fn test_search_field_for_column_covers_the_matchable_columns() {
        assert!(matches!(
            search_field_for_column(TableColumnStyle::Name),
            Some(SearchField::Name)
        ));
        assert!(matches!(
            search_field_for_column(TableColumnStyle::User),
            Some(SearchField::User)
        ));
        assert!(matches!(
            search_field_for_column(TableColumnStyle::Folder),
            Some(SearchField::Folder)
        ));
        assert!(matches!(
            search_field_for_column(TableColumnStyle::Default),
            Some(SearchField::Uri)
        ));
        assert!(search_field_for_column(TableColumnStyle::Id).is_none());
        assert!(search_field_for_column(TableColumnStyle::Password).is_none());
    }

    #[test]
    fn test_scope_prefix_ranges_marks_only_recognized_prefixes() {
        // "u:" is recognized; the value after it is not part of the range.
        assert_eq!(scope_prefix_ranges("u:alice"), vec![(0, 2)]);

        // Multiple scoped words, each found at its own position, plus a
        // bare word (no range) in between.
        assert_eq!(
            scope_prefix_ranges("u:alice google uri:github"),
            vec![(0, 2), (15, 19)]
        );

        // An unrecognized prefix isn't marked (it's a literal bare word to
        // `QueryToken`).
        assert_eq!(scope_prefix_ranges("bogus:alice"), Vec::new());

        // A recognized prefix marks immediately, even with no value typed
        // yet — no need to wait for the first character after the colon.
        assert_eq!(scope_prefix_ranges("u:"), vec![(0, 2)]);
        assert_eq!(scope_prefix_ranges("uri:"), vec![(0, 4)]);

        assert_eq!(scope_prefix_ranges(""), Vec::new());
    }

    #[test]
    fn test_render_table_row_aligns_columns_with_padding() {
        let row =
            vec!["UID".to_string(), "NAME".to_string(), "USER".to_string()];
        let widths = vec![5, 10, 4];

        let rendered =
            render_table_row(&row, &widths, |_, cell| cell.to_string());

        assert_eq!(rendered, "UID    NAME        USER");
    }

    #[test]
    fn test_available_attachments_error_lists_candidates() {
        let error = available_attachments_error(
            "example",
            &[DecryptedAttachment {
                id: "id-1".to_string(),
                file_name: Some("invoice.pdf".to_string()),
                size: None,
                size_name: Some("1 KB".to_string()),
            }],
            "attachment 'foo' was not found",
        );

        let message = error.to_string();
        assert!(message.contains("attachment 'foo' was not found"));
        assert!(message.contains("Available attachments for 'example':"));
        assert!(message.contains("id-1\tinvoice.pdf\t1 KB"));
    }

    #[test]
    fn test_find_entry() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry("gitter", Some("baz"), None, &[]),
            make_entry("git", Some("foo"), None, &[]),
            make_entry("bitwarden", None, None, &[]),
            make_entry("github", Some("foo"), Some("websites"), &[]),
            make_entry("github", Some("foo"), Some("ssh"), &[]),
            make_entry("github", Some("root"), Some("ssh"), &[]),
            make_entry("codeberg", Some("foo"), None, &[]),
            make_entry("codeberg", None, None, &[]),
            make_entry("1password", Some("foo"), None, &[]),
            make_entry("1password", None, Some("foo"), &[]),
        ];

        assert!(
            one_match(entries, "github", Some("foo"), None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), None, 0, true),
            "foo@GITHUB"
        );
        assert!(one_match(entries, "github", None, None, 0, false), "github");
        assert!(one_match(entries, "GITHUB", None, None, 0, true), "GITHUB");
        assert!(
            one_match(entries, "gitlab", Some("foo"), None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, "GITLAB", Some("foo"), None, 1, true),
            "foo@GITLAB"
        );
        assert!(
            one_match(entries, "git", Some("bar"), None, 2, false),
            "bar@git"
        );
        assert!(
            one_match(entries, "GIT", Some("bar"), None, 2, true),
            "bar@GIT"
        );
        assert!(
            one_match(entries, "gitter", Some("ba"), None, 3, false),
            "ba@gitter"
        );
        assert!(
            one_match(entries, "GITTER", Some("ba"), None, 3, true),
            "ba@GITTER"
        );
        assert!(
            one_match(entries, "git", Some("foo"), None, 4, false),
            "foo@git"
        );
        assert!(
            one_match(entries, "GIT", Some("foo"), None, 4, true),
            "foo@GIT"
        );
        assert!(one_match(entries, "git", None, None, 4, false), "git");
        assert!(one_match(entries, "GIT", None, None, 4, true), "GIT");
        assert!(
            one_match(entries, "bitwarden", None, None, 5, false),
            "bitwarden"
        );
        assert!(
            one_match(entries, "BITWARDEN", None, None, 5, true),
            "BITWARDEN"
        );
        assert!(
            one_match(
                entries,
                "github",
                Some("foo"),
                Some("websites"),
                6,
                false
            ),
            "websites/foo@github"
        );
        assert!(
            one_match(
                entries,
                "GITHUB",
                Some("foo"),
                Some("websites"),
                6,
                true
            ),
            "websites/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("foo"), Some("ssh"), 7, false),
            "ssh/foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), Some("ssh"), 7, true),
            "ssh/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("root"), None, 8, false),
            "ssh/root@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("root"), None, 8, true),
            "ssh/root@GITHUB"
        );

        assert!(
            no_matches(entries, "gitlab", Some("baz"), None, false),
            "baz@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("baz"), None, true),
            "baz@"
        );
        assert!(
            no_matches(entries, "bitbucket", Some("foo"), None, false),
            "foo@bitbucket"
        );
        assert!(
            no_matches(entries, "BITBUCKET", Some("foo"), None, true),
            "foo@BITBUCKET"
        );
        assert!(
            no_matches(entries, "github", Some("foo"), Some("bar"), false),
            "bar/foo@github"
        );
        assert!(
            no_matches(entries, "GITHUB", Some("foo"), Some("bar"), true),
            "bar/foo@"
        );
        assert!(
            no_matches(entries, "gitlab", Some("foo"), Some("bar"), false),
            "bar/foo@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("foo"), Some("bar"), true),
            "bar/foo@GITLAB"
        );

        assert!(many_matches(entries, "gitlab", None, None, false), "gitlab");
        assert!(many_matches(entries, "gitlab", None, None, true), "GITLAB");
        assert!(
            many_matches(entries, "gi", Some("foo"), None, false),
            "foo@gi"
        );
        assert!(
            many_matches(entries, "GI", Some("foo"), None, true),
            "foo@GI"
        );
        assert!(
            many_matches(entries, "git", Some("ba"), None, false),
            "ba@git"
        );
        assert!(
            many_matches(entries, "GIT", Some("ba"), None, true),
            "ba@GIT"
        );
        assert!(
            many_matches(entries, "github", Some("foo"), Some("s"), false),
            "s/foo@github"
        );
        assert!(
            many_matches(entries, "GITHUB", Some("foo"), Some("s"), true),
            "s/foo@GITHUB"
        );

        assert!(
            one_match(entries, "codeberg", Some("foo"), None, 9, false),
            "foo@codeberg"
        );
        assert!(
            one_match(entries, "codeberg", None, None, 10, false),
            "codeberg"
        );
        assert!(
            no_matches(entries, "codeberg", Some("bar"), None, false),
            "bar@codeberg"
        );

        assert!(
            many_matches(entries, "1password", None, None, false),
            "1password"
        );
    }

    #[test]
    fn test_find_entry_scoring() {
        // An entry with the given name and an optional secret-field value.
        let entry_with_secret = |name: &str, secret: Option<&str>| {
            let mut e = make_entry(name, None, None, &[]);
            if let Some(secret) = secret {
                e.1.sensitive_fields = vec![secret.to_string()];
            }
            e
        };

        let gpg =
            entry_with_secret("Private GPG Key", Some("passphrase value"));
        let github = entry_with_secret(
            "GPG Key for github",
            Some("-----BEGIN PGP PRIVATE KEY-----"),
        );
        let smappee =
            entry_with_secret("smappee.com", Some("note mentions gpg"));
        let entries = &[gpg.clone(), github, smappee.clone()];

        let find = |needles: &[&str]| {
            let needles: Vec<_> =
                needles.iter().map(|n| parse_needle(n).unwrap()).collect();
            find_entry_raw(entries, &needles, None, None, false, false)
        };

        // "gpg" matches smappee only inside a secret field, but the GPG-named
        // entries match it in the name and outrank it — smappee is never picked.
        let (entry, _) = find(&["gpg"]).unwrap();
        assert_ne!(entry.id, smappee.0.id);

        // A multi-needle whose join equals a name wins decisively over an entry
        // that merely contains the words across its name and a secret field.
        let (entry, _) = find(&["private", "gpg", "key"]).unwrap();
        assert_eq!(entry.id, gpg.0.id, "joined-name match should win");

        // An exact (case-insensitive) name match resolves uniquely.
        let (entry, _) = find(&["private gpg key"]).unwrap();
        assert_eq!(entry.id, gpg.0.id, "ci-exact name match");

        // A needle that only appears in a secret field still resolves when
        // nothing matches by name (low-weight fallback still works).
        let (entry, _) = find(&["mentions"]).unwrap();
        assert_eq!(entry.id, smappee.0.id, "secret-field fallback");
    }

    #[test]
    fn test_default_secret() {
        let field = |name: &str, value: &str, hidden: bool| DecryptedField {
            name: Some(name.to_string()),
            value: Some(value.to_string()),
            ty: Some(if hidden {
                rbw::api::FieldType::Hidden
            } else {
                rbw::api::FieldType::Text
            }),
        };
        let cipher =
            |data: DecryptedData,
             fields: Vec<DecryptedField>,
             notes: Option<&str>| DecryptedCipher {
                id: "id".to_string(),
                folder: None,
                name: "name".to_string(),
                data,
                fields,
                notes: notes.map(std::string::ToString::to_string),
                history: vec![],
                attachments: vec![],
                attachment_metadata: AttachmentMetadata {
                    attachment_count: 0,
                },
                archived: false,
                deleted: false,
                account: None,
            };
        let login = |password: Option<&str>| DecryptedData::Login {
            username: None,
            password: password.map(std::string::ToString::to_string),
            totp: None,
            uris: None,
            fido2_credentials: Vec::new(),
        };
        let resolved = |c: &DecryptedCipher| {
            c.default_secret().map(|(v, s)| (v, s.label()))
        };

        // login password wins, even over a password-named custom field
        assert_eq!(
            resolved(&cipher(login(Some("pw")), vec![], None)),
            Some(("pw".to_string(), "password".to_string()))
        );
        assert_eq!(
            resolved(&cipher(
                login(Some("pw")),
                vec![field("password", "other", true)],
                None,
            )),
            Some(("pw".to_string(), "password".to_string()))
        );
        // no password -> custom passphrase field
        assert_eq!(
            resolved(&cipher(
                DecryptedData::SecureNote,
                vec![field("passphrase", "secret", true)],
                None,
            )),
            Some(("secret".to_string(), "field 'passphrase'".to_string()))
        );
        // a password-named field beats notes
        assert_eq!(
            resolved(&cipher(
                DecryptedData::SecureNote,
                vec![field("password", "p", true)],
                Some("the notes"),
            )),
            Some(("p".to_string(), "field 'password'".to_string()))
        );
        // notes fallback
        assert_eq!(
            resolved(&cipher(DecryptedData::SecureNote, vec![], Some("hi"))),
            Some(("hi".to_string(), "notes".to_string()))
        );
        // a single non-standard field is used as a last resort
        assert_eq!(
            resolved(&cipher(
                DecryptedData::SecureNote,
                vec![field("api token", "tok", false)],
                None,
            )),
            Some(("tok".to_string(), "field 'api token'".to_string()))
        );
        // nothing to resolve
        assert_eq!(
            cipher(DecryptedData::SecureNote, vec![], None)
                .default_secret()
                .map(|(v, _)| v),
            None
        );
    }

    #[test]
    fn test_find_by_uuid() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry(
                "12345678-1234-1234-1234-1234567890ab",
                None,
                None,
                &[],
            ),
            make_entry(
                "12345678-1234-1234-1234-1234567890AC",
                None,
                None,
                &[],
            ),
            make_entry("123456781234123412341234567890AD", None, None, &[]),
        ];

        assert!(
            one_match(entries, &entries[0].0.id, None, None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, &entries[1].0.id, None, None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, &entries[2].0.id, None, None, 2, false),
            "bar@gitlab"
        );

        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_uppercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );
        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_lowercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );

        assert!(one_match(entries, &entries[3].0.id, None, None, 3, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890ab",
            None,
            None,
            3,
            false
        ));
        assert!(no_matches(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            false
        ));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            3,
            true
        ));
        assert!(one_match(entries, &entries[4].0.id, None, None, 4, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AC",
            None,
            None,
            4,
            false
        ));
        assert!(one_match(entries, &entries[5].0.id, None, None, 5, false));
        assert!(one_match(
            entries,
            "123456781234123412341234567890AD",
            None,
            None,
            5,
            false
        ));
    }

    #[test]
    fn test_find_by_url_default() {
        let entries = &[
            make_entry("one", None, None, &[("https://one.com/", None)]),
            make_entry("two", None, None, &[("https://two.com/login", None)]),
            make_entry(
                "three",
                None,
                None,
                &[("https://login.three.com/", None)],
            ),
            make_entry("four", None, None, &[("four.com", None)]),
            make_entry(
                "five",
                None,
                None,
                &[("https://five.com:8080/", None)],
            ),
            make_entry("six", None, None, &[("six.com:8080", None)]),
            make_entry("seven", None, None, &[("192.168.0.128:8080", None)]),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(
                entries,
                "https://login.one.com/",
                None,
                None,
                0,
                false
            ),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_domain() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[(
                    "192.168.0.128:8080",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(
                entries,
                "https://login.one.com/",
                None,
                None,
                0,
                false
            ),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_host() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[("192.168.0.128:8080", Some(rbw::api::UriMatchType::Host))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_starts_with() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    "https://one.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                1,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_exact() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Exact))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("https://four.com", Some(rbw::api::UriMatchType::Exact))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com/foo", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );
        assert!(
            one_match(entries, "https://four.com", None, None, 3, false),
            "four"
        );
        assert!(
            no_matches(entries, "https://four.com/foo", None, None, false),
            "four"
        );
    }

    #[test]
    fn test_find_by_url_regex() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    r"^https://one\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    r"^https://two\.com/(login|start)",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    r"^https://(login\.)?three\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/start", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                1,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            one_match(entries, "https://three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://www.three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_never() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Never))],
            ),
        ];

        assert!(
            no_matches(entries, "https://one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com:443/", None, None, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            no_matches(
                entries,
                "https://login.three.com/",
                None,
                None,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            no_matches(entries, "https://four.com/", None, None, false),
            "four"
        );

        assert!(
            no_matches(entries, "https://five.com:8080/", None, None, false),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            no_matches(entries, "https://six.com:8080/", None, None, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
    }

    #[test]
    fn test_find_with_multiple_urls() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[
                    (
                        "https://one.com/",
                        Some(rbw::api::UriMatchType::Domain),
                    ),
                    (
                        "https://two.com/",
                        Some(rbw::api::UriMatchType::Domain),
                    ),
                ],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            no_matches(entries, "https://zero.com/", None, None, false),
            "zero"
        );
        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            many_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
    }

    #[test]
    fn test_decode_totp_secret() {
        let decoded = decode_totp_secret("NBSW Y3DP EB3W 64TM MQQQ").unwrap();
        let want = b"hello world!".to_vec();
        assert!(decoded == want, "strips spaces");
    }

    fn login_cipher(
        password: Option<&str>,
        totp: Option<&str>,
    ) -> DecryptedCipher {
        DecryptedCipher {
            id: "id".to_string(),
            folder: None,
            name: "name".to_string(),
            data: DecryptedData::Login {
                username: None,
                password: password.map(std::string::ToString::to_string),
                totp: totp.map(std::string::ToString::to_string),
                uris: None,
                fido2_credentials: Vec::new(),
            },
            fields: vec![],
            notes: None,
            history: vec![],
            attachments: vec![],
            attachment_metadata: AttachmentMetadata {
                attachment_count: 0,
            },
            archived: false,
            deleted: false,
            account: None,
        }
    }

    #[test]
    fn test_credential_source_login_fields_extracts_password_and_totp() {
        let cipher = login_cipher(Some("hunter2"), Some("JBSWY3DPEHPK3PXP"));
        let (password, totp) =
            credential_source_login_fields(&cipher, "entry", "account")
                .unwrap();
        assert_eq!(password, "hunter2");
        assert_eq!(totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    // No TOTP secret on the entry is fine -- only a missing password should
    // fail resolution (the account might not have 2FA enabled at all).
    #[test]
    fn test_credential_source_login_fields_totp_is_optional() {
        let cipher = login_cipher(Some("hunter2"), None);
        let (password, totp) =
            credential_source_login_fields(&cipher, "entry", "account")
                .unwrap();
        assert_eq!(password, "hunter2");
        assert_eq!(totp, None);
    }

    #[test]
    fn test_credential_source_login_fields_requires_a_password() {
        let cipher = login_cipher(None, None);
        assert!(credential_source_login_fields(&cipher, "entry", "account")
            .is_err());
    }

    #[test]
    fn test_credential_source_login_fields_rejects_non_login_entries() {
        let cipher = DecryptedCipher {
            id: "id".to_string(),
            folder: None,
            name: "name".to_string(),
            data: DecryptedData::SecureNote,
            fields: vec![],
            notes: None,
            history: vec![],
            attachments: vec![],
            attachment_metadata: AttachmentMetadata {
                attachment_count: 0,
            },
            archived: false,
            deleted: false,
            account: None,
        };
        assert!(credential_source_login_fields(&cipher, "entry", "account")
            .is_err());
    }

    #[test]
    fn test_imported_data_to_decrypted_login() {
        let imported = ImportedData::Login {
            username: Some("alice".to_string()),
            password: Some("hunter2".to_string()),
            totp: Some("JBSWY3DPEHPK3PXP".to_string()),
            uris: Some(vec![ImportedUri {
                uri: "https://example.com".to_string(),
                match_type: Some(rbw::api::UriMatchType::Domain),
            }]),
            fido2_credentials: Vec::new(),
        };
        let DecryptedData::Login {
            username,
            password,
            totp,
            uris,
            ..
        } = imported_data_to_decrypted(&imported)
        else {
            panic!("expected DecryptedData::Login");
        };
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password.as_deref(), Some("hunter2"));
        assert_eq!(totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        let uris = uris.unwrap();
        assert_eq!(uris.len(), 1);
        assert_eq!(uris[0].uri, "https://example.com");
        assert_eq!(uris[0].match_type, Some(rbw::api::UriMatchType::Domain));
    }

    fn sample_imported_fido2_credential() -> ImportedFido2Credential {
        ImportedFido2Credential {
            credential_id: Some("cred-1".to_string()),
            key_type: Some("public-key".to_string()),
            key_algorithm: Some("ECDSA".to_string()),
            key_curve: Some("P-256".to_string()),
            key_value: Some("base64-key-material".to_string()),
            rp_id: Some("example.com".to_string()),
            user_handle: Some("user-handle".to_string()),
            user_name: Some("alice".to_string()),
            counter: Some("0".to_string()),
            rp_name: Some("Example".to_string()),
            user_display_name: Some("Alice".to_string()),
            discoverable: Some("true".to_string()),
            creation_date: Some("2024-01-01T00:00:00.000Z".to_string()),
        }
    }

    // The exact bug this feature fixes: `rbw mirror` previously dropped
    // passkeys silently because none of `ImportedData`/`DecryptedData`/
    // `BwLogin` carried a fido2Credentials field at all, so it never
    // reached the decrypt/import layer regardless of what the source
    // account actually had.
    #[test]
    fn test_imported_data_to_decrypted_login_carries_fido2_credentials() {
        let imported = ImportedData::Login {
            username: Some("alice".to_string()),
            password: None,
            totp: None,
            uris: None,
            fido2_credentials: vec![sample_imported_fido2_credential()],
        };
        let DecryptedData::Login {
            fido2_credentials, ..
        } = imported_data_to_decrypted(&imported)
        else {
            panic!("expected DecryptedData::Login");
        };
        assert_eq!(fido2_credentials.len(), 1);
        let cred = &fido2_credentials[0];
        assert_eq!(cred.credential_id.as_deref(), Some("cred-1"));
        assert_eq!(cred.rp_id.as_deref(), Some("example.com"));
        assert_eq!(cred.rp_name.as_deref(), Some("Example"));
        assert_eq!(cred.user_name.as_deref(), Some("alice"));
        assert_eq!(cred.user_display_name.as_deref(), Some("Alice"));
        assert_eq!(cred.key_value.as_deref(), Some("base64-key-material"));
        assert_eq!(
            cred.creation_date.as_deref(),
            Some("2024-01-01T00:00:00.000Z")
        );
    }

    // `rbw mirror`'s own critical path: source `DecryptedData` -> `BwLogin`
    // (`bw_data_from_decrypted`) -> back into `ImportedData`
    // (`bw_item_data`), the exact two hops a mirror run makes between
    // exporting from the source account and importing into the
    // destination. A passkey must survive both hops unchanged.
    #[test]
    fn test_mirror_round_trip_carries_fido2_credentials() {
        let decrypted = DecryptedData::Login {
            username: Some("alice".to_string()),
            password: None,
            totp: None,
            uris: None,
            fido2_credentials: vec![DecryptedFido2Credential {
                credential_id: Some("cred-1".to_string()),
                key_type: Some("public-key".to_string()),
                key_algorithm: Some("ECDSA".to_string()),
                key_curve: Some("P-256".to_string()),
                key_value: Some("base64-key-material".to_string()),
                rp_id: Some("example.com".to_string()),
                user_handle: Some("user-handle".to_string()),
                user_name: Some("alice".to_string()),
                counter: Some("0".to_string()),
                rp_name: Some("Example".to_string()),
                user_display_name: Some("Alice".to_string()),
                discoverable: Some("true".to_string()),
                creation_date: Some("2024-01-01T00:00:00.000Z".to_string()),
            }],
        };

        let (ty, login, _, _, _) = bw_data_from_decrypted(&decrypted);
        assert_eq!(ty, 1);
        let bw_login = login.expect("expected a BwLogin");
        assert_eq!(bw_login.fido2_credentials.len(), 1);
        assert_eq!(
            bw_login.fido2_credentials[0].credential_id.as_deref(),
            Some("cred-1")
        );

        let item = crate::import_bitwarden::BwItem {
            id: None,
            organization_id: None,
            folder_id: None,
            archived_date: None,
            deleted_date: None,
            ty: 1,
            name: "example".to_string(),
            notes: None,
            login: Some(bw_login),
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![],
            password_history: vec![],
            collection_ids: vec![],
        };
        let Some(ImportedData::Login {
            fido2_credentials, ..
        }) = bw_item_data(&item)
        else {
            panic!("expected ImportedData::Login");
        };
        assert_eq!(fido2_credentials.len(), 1);
        let cred = &fido2_credentials[0];
        assert_eq!(cred.credential_id.as_deref(), Some("cred-1"));
        assert_eq!(cred.rp_id.as_deref(), Some("example.com"));
        assert_eq!(cred.key_value.as_deref(), Some("base64-key-material"));
        assert_eq!(
            cred.creation_date.as_deref(),
            Some("2024-01-01T00:00:00.000Z")
        );
    }

    // `--from-file`'s core path (no gpg/passphrase involved): a plain JSON
    // export, as `rbw export` (without `--encrypt`) produces, loads
    // directly with no config/agent/account touched.
    #[test]
    fn test_load_from_file_reads_plain_json_export() {
        let vault = ExportedVault {
            entries: vec![ExportedEntry {
                id: "entry-id".to_string(),
                org_id: None,
                folder: Some("Work".to_string()),
                name: "example.com".to_string(),
                data: DecryptedData::Login {
                    username: Some("alice".to_string()),
                    password: Some("hunter2".to_string()),
                    totp: None,
                    uris: None,
                    fido2_credentials: Vec::new(),
                },
                fields: vec![],
                notes: Some("note text".to_string()),
                history: vec![],
                collection_ids: vec![],
                archived: false,
                deleted: false,
                attachments: vec![ExportedAttachment {
                    id: "att-1".to_string(),
                    file_name: "secret.txt".to_string(),
                    data_base64: rbw::base64::encode(b"attachment bytes"),
                }],
            }],
            collections: vec![],
        };
        let json = serde_json::to_string(&vault).unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();
        file.flush().unwrap();

        let loaded = load_from_file(file.path(), None).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        let entry = &loaded.entries[0];
        assert_eq!(entry.id, "entry-id");
        assert_eq!(entry.folder.as_deref(), Some("Work"));
        assert_eq!(entry.notes.as_deref(), Some("note text"));
        assert_eq!(entry.attachments.len(), 1);
        assert_eq!(entry.attachments[0].id, "att-1");
        assert_eq!(&loaded.attachment_data["att-1"], b"attachment bytes");
        let DecryptedData::Login {
            username, password, ..
        } = &entry.data
        else {
            panic!("expected DecryptedData::Login");
        };
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn test_load_from_file_reads_bitwarden_json_export() {
        let json = r#"{
            "folders": [{"id": "folder-1", "name": "Work"}],
            "collections": [],
            "items": [{
                "id": "item-1",
                "folderId": "folder-1",
                "type": 1,
                "name": "example.com",
                "login": {
                    "username": "alice",
                    "password": "hunter2",
                    "uris": [{"uri": "https://example.com", "match": 0}]
                }
            }]
        }"#;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();
        file.flush().unwrap();

        let loaded = load_from_file(file.path(), None).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].name, "example.com");
        assert_eq!(loaded.entries[0].folder.as_deref(), Some("Work"));
        let DecryptedData::Login {
            username, password, ..
        } = &loaded.entries[0].data
        else {
            panic!("expected a login entry");
        };
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn test_load_from_file_reads_bitwarden_encrypted_json_with_passphrase() {
        let json = r#"{"folders":[],"collections":[],"items":[{
            "id":"item-1","type":2,"name":"private note"
        }]}"#;
        let encrypted = crate::import_bitwarden::encrypt_encrypted_json(
            json,
            "test passphrase",
            rbw::api::KdfType::Pbkdf2,
            1,
            None,
            None,
        )
        .unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(encrypted.as_bytes()).unwrap();
        file.flush().unwrap();

        let loaded =
            load_from_file(file.path(), Some("test passphrase")).unwrap();
        assert_eq!(loaded.entries[0].name, "private note");
        assert!(matches!(loaded.entries[0].data, DecryptedData::SecureNote));
        assert_eq!(loaded.passphrase.as_deref(), Some("test passphrase"));
    }

    #[test]
    fn test_load_from_file_reads_bitwarden_zip_attachments() {
        let json = r#"{"folders":[],"collections":[],"items":[{
            "id":"item-1","type":2,"name":"example"
        }]}"#;
        let zip = crate::import_bitwarden::write_zip(
            json,
            &[(
                "example".to_string(),
                "notes.txt".to_string(),
                b"attachment bytes".to_vec(),
            )],
        )
        .unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&zip).unwrap();
        file.flush().unwrap();

        let loaded = load_from_file(file.path(), None).unwrap();
        assert_eq!(loaded.entries[0].attachments.len(), 1);
        assert_eq!(
            loaded.entries[0].attachments[0].file_name.as_deref(),
            Some("notes.txt")
        );
        assert_eq!(
            loaded.attachment_data.values().next().unwrap(),
            b"attachment bytes"
        );
    }

    // A hand-written/older export missing `id` (added to `ImportedEntry`
    // specifically for `--from-file`; `import` never needed it) still
    // loads, with a synthetic-but-stable id instead of failing outright.
    #[test]
    fn test_load_from_file_generates_ids_when_missing() {
        let json = serde_json::json!({
            "entries": [{"name": "no id here", "type": "SecureNote"}],
            "collections": []
        })
        .to_string();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();
        file.flush().unwrap();

        let loaded = load_from_file(file.path(), None).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].id, "from-file-0");
    }

    #[test]
    fn test_editable_to_decrypted_login() {
        let editable = EditableCipher {
            name: "Example".to_string(),
            folder: None,
            notes: Some(String::new()),
            data: EditableData::Login {
                username: Some("alice".to_string()),
                password: Some(String::new()),
                uris: vec![EditableUri {
                    uri: "https://example.com".to_string(),
                    match_type: Some("domain".to_string()),
                }],
                totp: None,
                fido2_credentials: Vec::new(),
            },
            fields: vec![],
        };
        let (data, _fields, notes) = editable_to_decrypted(&editable);
        // An empty string means "unset", same as `editable_to_encrypted`.
        assert_eq!(notes, None);
        let DecryptedData::Login {
            username,
            password,
            uris,
            ..
        } = data
        else {
            panic!("expected DecryptedData::Login");
        };
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(password, None);
        let uris = uris.unwrap();
        assert_eq!(uris[0].uri, "https://example.com");
        assert_eq!(uris[0].match_type, Some(rbw::api::UriMatchType::Domain));
    }

    fn sample_decrypted_cipher(id: &str, name: &str) -> DecryptedCipher {
        DecryptedCipher {
            id: id.to_string(),
            folder: None,
            name: name.to_string(),
            data: DecryptedData::SecureNote,
            fields: vec![],
            notes: None,
            history: vec![],
            attachments: vec![],
            attachment_metadata: AttachmentMetadata {
                attachment_count: 0,
            },
            archived: false,
            deleted: false,
            account: None,
        }
    }

    #[test]
    fn test_find_entry_in_file_matches_by_name() {
        let entries = vec![
            sample_decrypted_cipher("id-1", "GitHub"),
            sample_decrypted_cipher("id-2", "GitLab"),
        ];
        let found = find_entry_in_file(
            &entries,
            &[parse_needle("GitHub").unwrap()],
            None,
            None,
            false,
            false,
        )
        .unwrap();
        assert_eq!(found.id, "id-1");
    }

    #[test]
    fn test_find_entry_in_file_reports_no_match() {
        let entries = vec![sample_decrypted_cipher("id-1", "GitHub")];
        assert!(find_entry_in_file(
            &entries,
            &[parse_needle("nonexistent").unwrap()],
            None,
            None,
            false,
            false,
        )
        .is_err());
    }

    // `save_to_file` -> `load_from_file` round trip: entries, collections,
    // and org_id/collection_ids (via `FileEntryExtra`, not on
    // `DecryptedCipher` itself) all survive a save untouched.
    #[test]
    fn test_save_to_file_round_trips_through_load_from_file() {
        let file = tempfile::NamedTempFile::new().unwrap();

        let exported = vec![ExportedEntry {
            id: "id-1".to_string(),
            org_id: Some("org-1".to_string()),
            folder: Some("Work".to_string()),
            name: "Example".to_string(),
            data: DecryptedData::Login {
                username: Some("alice".to_string()),
                password: Some("hunter2".to_string()),
                totp: None,
                uris: None,
                fido2_credentials: Vec::new(),
            },
            fields: vec![],
            notes: None,
            history: vec![],
            collection_ids: vec!["col-1".to_string()],
            archived: false,
            deleted: false,
            attachments: vec![],
        }];
        let collections = vec![ExportedCollection {
            id: "col-1".to_string(),
            org_id: "org-1".to_string(),
            name: "Shared".to_string(),
        }];

        save_to_file(file.path(), exported, collections, None).unwrap();

        let loaded = load_from_file(file.path(), None).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].name, "Example");
        assert_eq!(loaded.collections.len(), 1);
        assert_eq!(loaded.collections[0].id, "col-1");
        let extra = &loaded.entry_extra["id-1"];
        assert_eq!(extra.org_id.as_deref(), Some("org-1"));
        assert_eq!(extra.collection_ids, vec!["col-1".to_string()]);
    }

    #[track_caller]
    fn one_match(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        idx: usize,
        ignore_case: bool,
    ) -> bool {
        entries_eq(
            &find_entry_raw(
                entries,
                &[parse_needle(needle).unwrap()],
                username,
                folder,
                ignore_case,
                false,
            )
            .unwrap(),
            &entries[idx],
        )
    }

    #[track_caller]
    fn no_matches(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &[parse_needle(needle).unwrap()],
            username,
            folder,
            ignore_case,
            false,
        );
        if let Err(e) = res {
            format!("{e}").contains("no entry found")
        } else {
            false
        }
    }

    #[track_caller]
    fn many_matches(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &[parse_needle(needle).unwrap()],
            username,
            folder,
            ignore_case,
            false,
        );
        if let Err(e) = res {
            format!("{e}").contains("multiple entries found")
        } else {
            false
        }
    }

    #[track_caller]
    fn entries_eq(
        a: &(rbw::db::Entry, DecryptedSearchCipher),
        b: &(rbw::db::Entry, DecryptedSearchCipher),
    ) -> bool {
        a.0 == b.0 && a.1 == b.1
    }

    fn make_entry(
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
        uris: &[(&str, Option<rbw::api::UriMatchType>)],
    ) -> (rbw::db::Entry, DecryptedSearchCipher) {
        let id = uuid::Uuid::new_v4();
        (
            rbw::db::Entry {
                id: id.to_string(),
                org_id: None,
                folder: folder.map(|_| "encrypted folder name".to_string()),
                folder_id: None,
                name: "this is the encrypted name".to_string(),
                data: rbw::db::EntryData::Login {
                    username: username.map(|_| {
                        "this is the encrypted username".to_string()
                    }),
                    password: None,
                    uris: uris
                        .iter()
                        .map(|(_, match_type)| rbw::db::Uri {
                            uri: "this is the encrypted uri".to_string(),
                            match_type: *match_type,
                        })
                        .collect(),
                    totp: None,
                    fido2_credentials: Vec::new(),
                },
                fields: vec![],
                notes: None,
                history: vec![],
                key: None,
                master_password_reprompt: rbw::api::CipherRepromptType::None,
                archived: false,
                deleted: false,
                collection_ids: vec![],
                attachments: vec![],
            },
            DecryptedSearchCipher {
                id: id.to_string(),
                entry_type: "Login".to_string(),
                folder: folder.map(std::string::ToString::to_string),
                name: name.to_string(),
                user: username.map(std::string::ToString::to_string),
                uris: uris
                    .iter()
                    .map(|(uri, match_type)| {
                        ((*uri).to_string(), *match_type)
                    })
                    .collect(),
                fields: vec![],
                notes: None,
                attachment_count: 0,
                archived: false,
                deleted: false,
                sensitive_fields: vec![],
                password: None,
            },
        )
    }
    mod inject_tests {
        use super::*;

        fn render_inject_template<F>(
            template: &str,
            resolver: F,
        ) -> anyhow::Result<String>
        where
            F: FnMut(&InjectReference) -> anyhow::Result<String>,
        {
            InjectTemplate::new(template).render(resolver)
        }

        fn render_inject_template_with_env<F>(
            template: &str,
            env: &[(&str, &str)],
            resolver: F,
        ) -> anyhow::Result<String>
        where
            F: FnMut(&InjectReference) -> anyhow::Result<String>,
        {
            InjectTemplate::new(template).render_with_variable_resolver(
                |name| {
                    env.iter().find_map(|(key, value)| {
                        key.eq_ignore_ascii_case(name)
                            .then(|| (*value).to_string())
                    })
                },
                resolver,
            )
        }

        #[test]
        fn test_take_braced_inject_expression_returns_expression_and_tail() {
            let template = InjectTemplate::new(
                "{{ bw://some-api-key?field=username }} and more",
            );
            let (expr, next_start) =
                template.take_braced_expression(0).unwrap();

            assert_eq!(expr, " bw://some-api-key?field=username ");
            assert_eq!(template.src.get(next_start..).unwrap(), " and more");
        }

        #[test]
        fn test_parse_braced_inject_reference_trims_and_parses_bw_urls() {
            let reference = InjectReference::parse_braced(
                " bw://some-api-key?field=username ",
            )
            .unwrap()
            .unwrap();

            assert_eq!(
                reference.target,
                InjectReferenceTarget::Name("some-api-key".to_string())
            );
            assert_eq!(reference.field.as_deref(), Some("username"));
        }

        #[test]
        fn test_parse_braced_inject_reference_ignores_non_bw_expressions() {
            let reference =
                InjectReference::parse_braced(" not-a-reference ").unwrap();

            assert_eq!(reference, None);
        }

        #[test]
        fn test_render_inject_template_replaces_braced_and_raw_refs() {
            let password_id = uuid::Uuid::new_v4();
            let username_id = uuid::Uuid::new_v4();
            let template = format!(
                "password={{{{ bw://{password_id} }}}}\nuser=bw://{username_id}?field=username"
            );

            let rendered = render_inject_template(&template, |reference| {
                match (reference.id.as_str(), reference.field.as_deref()) {
                    (id, None) if id == password_id.to_string() => {
                        Ok("hunter2".to_string())
                    }
                    (id, Some("username"))
                        if id == username_id.to_string() =>
                    {
                        Ok("alice".to_string())
                    }
                    _ => Err(anyhow::anyhow!("unexpected reference")),
                }
            })
            .unwrap();

            assert_eq!(rendered, "password=hunter2\nuser=alice");
        }

        #[test]
        fn test_render_inject_template_supports_name_refs() {
            let template = "token=bw://some-api-key";

            let rendered = render_inject_template(template, |reference| {
                assert_eq!(
                    reference.target,
                    InjectReferenceTarget::Name("some-api-key".to_string())
                );
                assert_eq!(reference.field, None);
                Ok("secret".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "token=secret");
        }

        #[test]
        fn test_render_inject_template_supports_name_refs_with_field_query() {
            let template = "user=bw://some-api-key?field=username";

            let rendered = render_inject_template(template, |reference| {
                assert_eq!(
                    reference.target,
                    InjectReferenceTarget::Name("some-api-key".to_string())
                );
                assert_eq!(reference.field.as_deref(), Some("username"));
                Ok("alice".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "user=alice");
        }

        #[test]
        fn test_render_inject_template_expands_variables_before_resolving_refs(
        ) {
            let template =
                "user=bw://${ ITEM_NAME }?field=${FIELD:-username}";

            let rendered = render_inject_template_with_env(
                template,
                &[("item_name", "some-api-key")],
                |reference| {
                    assert_eq!(
                        reference.target,
                        InjectReferenceTarget::Name(
                            "some-api-key".to_string()
                        )
                    );
                    assert_eq!(reference.field.as_deref(), Some("username"));
                    Ok("alice".to_string())
                },
            )
            .unwrap();

            assert_eq!(rendered, "user=alice");
        }

        #[test]
        fn test_render_inject_template_supports_nested_default_variables() {
            let template = "${ITEM_NAME:-${FALLBACK_ITEM:-some-api-key}}";

            let rendered =
                render_inject_template_with_env(template, &[], |_| {
                    anyhow::bail!("unexpected inject reference")
                })
                .unwrap();
            assert_eq!(rendered, "some-api-key");

            let rendered = render_inject_template_with_env(
                template,
                &[("fallback_item", "fallback-key")],
                |_| anyhow::bail!("unexpected inject reference"),
            )
            .unwrap();
            assert_eq!(rendered, "fallback-key");
        }

        #[test]
        fn test_render_inject_template_treats_invalid_variable_tags_as_literals(
        ) {
            let template = "$1BAD ${foo-bar} cost=$5";

            let rendered =
                render_inject_template_with_env(template, &[], |_| {
                    anyhow::bail!("unexpected inject reference")
                })
                .unwrap();

            assert_eq!(rendered, template);
        }

        #[test]
        fn test_render_inject_template_supports_quoted_braced_refs() {
            let template =
                r#"password={{ "bw://some-api-key?field=db.password" }}"#;

            let rendered = render_inject_template(template, |reference| {
                assert_eq!(
                    reference.target,
                    InjectReferenceTarget::Name("some-api-key".to_string())
                );
                assert_eq!(reference.field.as_deref(), Some("db.password"));
                Ok("hunter2".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "password=hunter2");
        }

        #[test]
        fn test_render_inject_template_preserves_quoted_non_reference_expressions(
        ) {
            let template = r#"before {{ "not-a-reference" + "x" }} after"#;

            let rendered = render_inject_template(template, |_| {
                anyhow::bail!("unexpected inject reference")
            })
            .unwrap();

            assert_eq!(rendered, template);
        }

        #[test]
        fn test_render_inject_template_respects_op_inject_raw_start_boundaries(
        ) {
            let entry_id = uuid::Uuid::new_v4();

            let rendered = render_inject_template(
                &format!("prefix_bw://{entry_id}"),
                |reference| {
                    assert_eq!(reference.id, entry_id.to_string());
                    Ok("secret".to_string())
                },
            )
            .unwrap();
            assert_eq!(rendered, "prefix_secret");

            for template in [
                format!("prefix+bw://{entry_id}"),
                format!(r"prefix\bw://{entry_id}"),
                format!("prefix.bw://{entry_id}"),
            ] {
                let rendered = render_inject_template(&template, |_| {
                    Ok("secret".to_string())
                })
                .unwrap();
                assert_eq!(rendered, template);
            }
        }

        #[test]
        fn test_render_inject_template_preserves_trailing_punctuation() {
            let entry_id = uuid::Uuid::new_v4();
            for (template, resolved, expected) in [
                (
                    format!("dsn=bw://{entry_id}, done."),
                    "postgres://db",
                    "dsn=postgres://db, done.".to_string(),
                ),
                (
                    format!(
                        "token=bw://{entry_id}. wow! alert=bw://{entry_id}!"
                    ),
                    "secret",
                    "token=secret. wow! alert=secret!".to_string(),
                ),
            ] {
                let rendered =
                    render_inject_template(&template, |reference| {
                        assert_eq!(reference.id, entry_id.to_string());
                        assert_eq!(reference.field, None);
                        Ok(resolved.to_string())
                    })
                    .unwrap();

                assert_eq!(rendered, expected);
            }
        }

        #[test]
        fn test_render_inject_template_treats_special_characters_as_raw_reference_boundaries(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            for (template, expected, field) in [
                (
                    format!("dsn=bw://{entry_id}/extra"),
                    "dsn=secret/extra".to_string(),
                    None,
                ),
                (
                    format!("dsn=bw://{entry_id}#prod"),
                    "dsn=secret#prod".to_string(),
                    None,
                ),
                (
                    format!("value=bw://{entry_id}:5432"),
                    "value=secret:5432".to_string(),
                    None,
                ),
                (
                    format!("value=bw://{entry_id}@host"),
                    "value=secret@host".to_string(),
                    None,
                ),
                (
                    format!("value=bw://{entry_id}=suffix"),
                    "value=secret=suffix".to_string(),
                    None,
                ),
                (
                    format!("bw://{entry_id}?field=username&field=password"),
                    "alice&field=password".to_string(),
                    Some("username"),
                ),
                (
                    format!("bw://{entry_id}?field=username&bogus=1"),
                    "alice&bogus=1".to_string(),
                    Some("username"),
                ),
            ] {
                let rendered =
                    render_inject_template(&template, |reference| {
                        assert_eq!(reference.id, entry_id.to_string());
                        assert_eq!(reference.field.as_deref(), field);
                        Ok(if field.is_some() { "alice" } else { "secret" }
                            .to_string())
                    })
                    .unwrap();

                assert_eq!(rendered, expected);
            }
        }

        #[test]
        fn test_render_inject_template_supports_raw_field_names_with_periods()
        {
            let entry_id = uuid::Uuid::new_v4();
            let template =
                format!("token=bw://{entry_id}?field=db.password, done");

            let rendered = render_inject_template(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                assert_eq!(reference.field.as_deref(), Some("db.password"));
                Ok("secret".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "token=secret, done");
        }

        #[test]
        fn test_render_inject_template_supports_encoded_raw_field_queries() {
            let entry_id = uuid::Uuid::new_v4();
            for template in [
                format!("token=bw://{entry_id}?field=API%20Token"),
                format!("token=bw://{entry_id}?field=API+Token"),
            ] {
                let rendered =
                    render_inject_template(&template, |reference| {
                        assert_eq!(reference.id, entry_id.to_string());
                        assert_eq!(
                            reference.field.as_deref(),
                            Some("API Token")
                        );
                        Ok("secret".to_string())
                    })
                    .unwrap();

                assert_eq!(rendered, "token=secret");
            }
        }

        #[test]
        fn test_render_inject_template_rejects_empty_field_query() {
            let entry_id = uuid::Uuid::new_v4();
            let template = format!("token=bw://{entry_id}?field=");

            let err = render_inject_template(&template, |_| {
                Ok("secret".to_string())
            })
            .unwrap_err();

            assert!(format!("{err}").contains("empty"));
        }

        #[test]
        fn test_render_inject_template_supports_raw_refs_in_dsn_and_query_contexts(
        ) {
            let dsn_id = uuid::Uuid::new_v4();
            let query_id = uuid::Uuid::new_v4();
            let template = format!(
                "postgres://user:bw://{dsn_id}@db.example/app?token=bw://{query_id}&mode=ro"
            );

            let rendered =
                render_inject_template(
                    &template,
                    |reference| match reference.id.as_str() {
                        id if id == dsn_id.to_string() => {
                            Ok("pw".to_string())
                        }
                        id if id == query_id.to_string() => {
                            Ok("token".to_string())
                        }
                        _ => Err(anyhow::anyhow!("unexpected reference")),
                    },
                )
                .unwrap();

            assert_eq!(
                rendered,
                "postgres://user:pw@db.example/app?token=token&mode=ro"
            );
        }

        #[test]
        fn test_render_inject_template_supports_raw_field_refs_in_outer_query_contexts(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            let template = format!(
                "https://example.test?user=bw://{entry_id}?field=username&mode=ro"
            );

            let rendered = render_inject_template(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                assert_eq!(reference.field.as_deref(), Some("username"));
                Ok("alice".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "https://example.test?user=alice&mode=ro");
        }

        #[test]
        fn test_render_inject_template_supports_raw_field_refs_in_dsn_username_contexts(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            let template = format!(
                "postgres://bw://{entry_id}?field=username@db.example/app"
            );

            let rendered = render_inject_template(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                assert_eq!(reference.field.as_deref(), Some("username"));
                Ok("alice".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "postgres://alice@db.example/app");
        }

        #[test]
        fn test_render_inject_template_replaces_unenclosed_refs_in_structured_text(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            for (template, expected) in [
                (
                    format!(
                        "apiVersion: v1\nkind: Secret\nstringData:\n  password: \"{{{{ bw://{entry_id} }}}}\"\n  note: \"bw://{entry_id}\"\n"
                    ),
                    "apiVersion: v1\nkind: Secret\nstringData:\n  password: \"hunter2\"\n  note: \"hunter2\"\n"
                        .to_string(),
                ),
                (
                    format!(
                        "{{\n  \"password\": \"{{{{ bw://{entry_id} }}}}\",\n  \"note\": \"bw://{entry_id}\"\n}}\n"
                    ),
                    "{\n  \"password\": \"hunter2\",\n  \"note\": \"hunter2\"\n}\n"
                        .to_string(),
                ),
            ] {
                let rendered = render_inject_template(&template, |reference| {
                    assert_eq!(reference.id, entry_id.to_string());
                    Ok("hunter2".to_string())
                })
                .unwrap();

                assert_eq!(rendered, expected);
            }
        }

        #[test]
        fn test_find_inject_entry_raw_matches_name_refs_exactly_ignoring_case(
        ) {
            let entries = &[
                make_entry("some-api-key", None, None, &[]),
                make_entry("some-api-key-prod", None, None, &[]),
            ];

            let (entry, _) =
                InjectReferenceTarget::Name("SOME-API-KEY".to_string())
                    .find_entry(entries)
                    .unwrap();

            assert_eq!(entry.id, entries[0].0.id);
        }

        #[test]
        fn test_find_inject_entry_raw_rejects_duplicate_name_refs() {
            let entries = &[
                make_entry("some-api-key", Some("alice"), None, &[]),
                make_entry("some-api-key", Some("bob"), None, &[]),
            ];

            let err = InjectReferenceTarget::Name("some-api-key".to_string())
                .find_entry(entries)
                .unwrap_err();

            assert!(format!("{err}").contains("multiple entries found"));
            assert!(format!("{err}").contains("use bw://<uuid> instead"));
        }

        #[test]
        fn test_find_inject_entry_raw_does_not_fuzzy_match_name_refs() {
            let entries = &[make_entry("some-api-key-prod", None, None, &[])];

            let err = InjectReferenceTarget::Name("some-api-key".to_string())
                .find_entry(entries)
                .unwrap_err();

            assert!(format!("{err}").contains("no entry found"));
        }

        #[test]
        fn test_parse_inject_reference_rejects_userinfo_ports_and_paths() {
            let entry_id = uuid::Uuid::new_v4();

            for reference in [
                format!("bw://user@{entry_id}"),
                format!("bw://user:pass@{entry_id}"),
                format!("bw://{entry_id}:5432"),
                format!("bw://{entry_id}/"),
            ] {
                assert!(
                    InjectReference::parse(&reference).is_err(),
                    "{reference} should be rejected"
                );
            }
        }

        #[test]
        fn test_parse_run_env_matches_dotenvy_parsing_rules() {
            let pairs = parse_run_env_file(
                concat!(
                    "BACKSLASH='a\\\\b'\n",
                    "PATH='C:\\temp\\logs\\q'\n",
                    r#"ESCAPED="contains \"quote\" and slash \\ and newline \n""#,
                    "\n",
                    "HASH=# comment\n",
                    "MULTILINE=\"line 1\nline 2\"\n",
                ),
                |_| anyhow::bail!("unexpected inject reference"),
            )
            .unwrap();

            assert_eq!(
                pairs,
                vec![
                    ("BACKSLASH".to_string(), r"a\\b".to_string()),
                    ("PATH".to_string(), r"C:\temp\logs\q".to_string()),
                    (
                        "ESCAPED".to_string(),
                        "contains \"quote\" and slash \\ and newline \n"
                            .to_string()
                    ),
                    ("HASH".to_string(), String::new()),
                    ("MULTILINE".to_string(), "line 1\nline 2".to_string()),
                ]
            );
        }

        #[test]
        fn test_parse_run_env_expands_then_resolves_raw_references() {
            use std::sync::{Mutex, OnceLock};

            static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

            let _guard =
                ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
            let host_var = "RBW_TEST_HOST_VAR";
            std::env::set_var(host_var, "expanded-by-host");

            let entry_id = uuid::Uuid::new_v4();
            let template = format!(
                "RAW=bw://{entry_id}\nQUOTED=\"bw://{entry_id}\"\nCOPY=$RAW\nHOST=${{{host_var}}}\nMIXED=${{{host_var}}}:$RAW\nLITERAL=__RBW_RUN_BRACED_REF_0__\nEXPANDED=${{LITERAL}}\n"
            );

            let pairs = parse_run_env_file(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                Ok("secret".to_string())
            })
            .unwrap();

            std::env::remove_var(host_var);

            assert_eq!(
                pairs,
                vec![
                    ("RAW".to_string(), "secret".to_string()),
                    ("QUOTED".to_string(), "secret".to_string()),
                    ("COPY".to_string(), "secret".to_string()),
                    ("HOST".to_string(), "expanded-by-host".to_string()),
                    (
                        "MIXED".to_string(),
                        "expanded-by-host:secret".to_string()
                    ),
                    (
                        "LITERAL".to_string(),
                        "__RBW_RUN_BRACED_REF_0__".to_string()
                    ),
                    (
                        "EXPANDED".to_string(),
                        "__RBW_RUN_BRACED_REF_0__".to_string()
                    ),
                ]
            );
        }

        #[test]
        fn test_parse_run_env_preserves_injected_values_verbatim() {
            let token_id = uuid::Uuid::new_v4().to_string();
            let secret_id = uuid::Uuid::new_v4().to_string();
            let multiline_id = uuid::Uuid::new_v4().to_string();
            let template = format!(
                "TOKEN=bw://{token_id}\nSECRET='bw://{secret_id}'\nMULTILINE=\"bw://{multiline_id}\"\n"
            );

            let pairs = parse_run_env_file(&template, |reference| {
                match reference.id.as_str() {
                    id if id == token_id => {
                        Ok("abc#not-a-comment".to_string())
                    }
                    id if id == secret_id => {
                        Ok("value with \"double\" and 'single' quotes"
                            .to_string())
                    }
                    id if id == multiline_id => {
                        Ok("line 1\nline 2  ".to_string())
                    }
                    _ => anyhow::bail!(
                        "unexpected inject reference '{}'",
                        reference.id
                    ),
                }
            })
            .unwrap();

            assert_eq!(
                pairs,
                vec![
                    ("TOKEN".to_string(), "abc#not-a-comment".to_string()),
                    (
                        "SECRET".to_string(),
                        "value with \"double\" and 'single' quotes"
                            .to_string()
                    ),
                    ("MULTILINE".to_string(), "line 1\nline 2  ".to_string()),
                ]
            );
        }

        #[test]
        fn test_build_inject_run_command_overrides_inherited_env_bindings() {
            let env_bindings = vec![
                ("API_KEY".to_string(), "new-secret".to_string()),
                ("EXTRA".to_string(), "value".to_string()),
            ];
            let command = build_inject_run_command(
                &[std::ffi::OsString::from("env")],
                &env_bindings,
            )
            .unwrap();

            let envs = command
                .get_envs()
                .map(|(key, value)| {
                    (
                        key.to_os_string(),
                        value.map(std::ffi::OsStr::to_os_string),
                    )
                })
                .collect::<std::collections::BTreeMap<
                    std::ffi::OsString,
                    Option<std::ffi::OsString>,
                >>();

            assert_eq!(
                envs.get(std::ffi::OsStr::new("API_KEY")),
                Some(&Some(std::ffi::OsString::from("new-secret")))
            );
            assert_eq!(
                envs.get(std::ffi::OsStr::new("EXTRA")),
                Some(&Some(std::ffi::OsString::from("value")))
            );
        }

        #[test]
        #[cfg(unix)]
        fn test_inject_run_passes_values_without_shell_evaluation() {
            use std::process::Stdio;

            let env_bindings =
                parse_run_env_file("VALUE='$(echo still-literal)'\n", |_| {
                    anyhow::bail!("unexpected inject reference")
                })
                .unwrap();
            let mut command = build_inject_run_command(
                &[
                    std::ffi::OsString::from("printenv"),
                    std::ffi::OsString::from("VALUE"),
                ],
                &env_bindings,
            )
            .unwrap();
            command.stdout(Stdio::piped());

            let output = command.output().unwrap();

            assert!(output.status.success());
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                "$(echo still-literal)\n"
            );
        }

        #[test]
        #[cfg(unix)]
        fn test_run_inject_command_returns_child_exit_status() {
            let status =
                run_inject_command(&[std::ffi::OsString::from("false")], &[])
                    .unwrap();

            assert_eq!(status.code(), Some(1));
        }

        #[test]
        fn test_resolve_inject_value_uses_password_username_and_custom_fields(
        ) {
            let cipher = DecryptedCipher {
                id: uuid::Uuid::new_v4().to_string(),
                folder: None,
                name: "example".to_string(),
                data: DecryptedData::Login {
                    username: Some("alice".to_string()),
                    password: Some("hunter2".to_string()),
                    totp: None,
                    uris: None,
                    fido2_credentials: Vec::new(),
                },
                fields: [("api-token", "xyz"), ("deployment", "prod")]
                    .iter()
                    .map(|(name, value)| DecryptedField {
                        name: Some((*name).to_string()),
                        value: Some((*value).to_string()),
                        ty: None,
                    })
                    .collect(),
                notes: None,
                history: vec![],
                attachments: vec![],
                attachment_metadata: AttachmentMetadata::new("example-id", 0),
                archived: false,
                deleted: false,
                account: None,
            };

            assert_eq!(
                resolve_inject_value(&cipher, None).unwrap(),
                "hunter2"
            );
            assert_eq!(
                resolve_inject_value(&cipher, Some("username")).unwrap(),
                "alice"
            );
            assert_eq!(
                resolve_inject_value(&cipher, Some("api-token")).unwrap(),
                "xyz"
            );
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_replaces_existing_file_atomically(
        ) {
            use std::os::unix::fs::MetadataExt as _;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("secret.txt");
            std::fs::write(&path, "existing").unwrap();
            let original_inode = std::fs::metadata(&path).unwrap().ino();

            write_rendered_template_file(&path, "hunter2").unwrap();

            assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
            let updated_inode = std::fs::metadata(&path).unwrap().ino();
            assert_ne!(updated_inode, original_inode);
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_accepts_bare_relative_paths() {
            use std::os::unix::fs::PermissionsExt as _;

            struct CwdGuard(std::path::PathBuf);

            impl Drop for CwdGuard {
                fn drop(&mut self) {
                    let _ = std::env::set_current_dir(&self.0);
                }
            }

            let dir = tempfile::tempdir().unwrap();
            let cwd = std::env::current_dir().unwrap();
            let _guard = CwdGuard(cwd);
            std::env::set_current_dir(dir.path()).unwrap();

            let path = std::path::Path::new("secret.txt");
            write_rendered_template_file(path, "hunter2").unwrap();

            assert_eq!(std::fs::read_to_string(path).unwrap(), "hunter2");
            let mode =
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_uses_owner_only_permissions() {
            use std::os::unix::fs::PermissionsExt as _;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("secret.txt");
            write_rendered_template_file(&path, "hunter2").unwrap();

            let mode = std::fs::metadata(&path).unwrap().permissions().mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_rejects_symlinks() {
            use std::os::unix::fs::symlink;

            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("target.txt");
            std::fs::write(&target, "existing").unwrap();
            let link = dir.path().join("secret.txt");
            symlink(&target, &link).unwrap();

            let err =
                write_rendered_template_file(&link, "hunter2").unwrap_err();
            assert!(format!("{err}").contains("must not be a symlink"));
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "existing");
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_rejects_non_regular_files() {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt as _;
            use std::os::unix::fs::OpenOptionsExt as _;

            let dir = tempfile::tempdir().unwrap();
            let fifo = dir.path().join("secret.fifo");
            let fifo_cstr =
                CString::new(fifo.as_os_str().as_bytes()).unwrap();
            let status = unsafe { libc::mkfifo(fifo_cstr.as_ptr(), 0o600) };
            assert_eq!(status, 0);

            let _reader = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
                .unwrap();

            let err =
                write_rendered_template_file(&fifo, "hunter2").unwrap_err();
            assert!(format!("{err}").contains("regular file"));
        }
    }

    #[test]
    fn test_editable_cipher_yaml_roundtrip() {
        let cipher = EditableCipher {
            name: "test entry".to_string(),
            folder: None,
            notes: Some("some notes".to_string()),
            data: EditableData::Login {
                username: Some("user@example.com".to_string()),
                password: Some("hunter2".to_string()),
                uris: vec![EditableUri {
                    uri: "https://example.com".to_string(),
                    match_type: Some("domain".to_string()),
                }],
                totp: None,
                fido2_credentials: Vec::new(),
            },
            fields: vec![],
        };

        let yaml = serde_yaml::to_string(&cipher).unwrap();
        eprintln!("YAML output:\n{yaml}");
        assert!(!yaml.is_empty(), "YAML output should not be empty");
        assert!(yaml.contains("test entry"), "should contain name");
        assert!(yaml.contains("login"), "should contain type tag");

        let parsed: EditableCipher = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.name, "test entry");
        if let EditableData::Login { username, .. } = parsed.data {
            assert_eq!(username.as_deref(), Some("user@example.com"));
        } else {
            panic!("expected Login variant");
        }
    }

    fn sample_exported_entry(
        attachments: Vec<ExportedAttachment>,
    ) -> ExportedEntry {
        ExportedEntry {
            id: "entry-id".to_string(),
            org_id: None,
            folder: None,
            name: "example.com".to_string(),
            data: DecryptedData::Login {
                username: Some("alice@example.com".to_string()),
                password: Some("hunter2".to_string()),
                totp: None,
                uris: None,
                fido2_credentials: Vec::new(),
            },
            fields: vec![],
            notes: None,
            history: vec![],
            collection_ids: vec![],
            archived: false,
            deleted: false,
            attachments,
        }
    }

    #[test]
    fn test_export_omits_attachments_field_when_flag_not_set() {
        // Without `--attachments`, `attachments` stays empty, and
        // `skip_serializing_if` means the field should not appear in the
        // serialized output at all -- i.e. old exports produced before
        // this flag existed remain byte-for-byte identical.
        let entry = sample_exported_entry(vec![]);

        let value = serde_json::to_value(&entry).unwrap();
        assert!(
            value.get("attachments").is_none(),
            "attachments field should be omitted when empty, got: {value}"
        );
    }

    #[test]
    fn test_export_attachments_round_trip_through_base64() {
        // With `--attachments`, decrypted attachment bytes are
        // base64-encoded so they can travel through JSON; verify the
        // round trip and that the field is present and populated.
        let original_bytes = b"totally secret attachment contents";
        let exported_attachment = ExportedAttachment {
            id: "attachment-id".to_string(),
            file_name: "secret.txt".to_string(),
            data_base64: rbw::base64::encode(original_bytes),
        };
        let entry = sample_exported_entry(vec![exported_attachment]);

        let value = serde_json::to_value(&entry).unwrap();
        let attachments = value
            .get("attachments")
            .expect("attachments field should be present")
            .as_array()
            .expect("attachments should serialize as an array");
        assert_eq!(attachments.len(), 1);

        let data_base64 = attachments[0]["data_base64"]
            .as_str()
            .expect("data_base64 should be a string");
        let decoded = rbw::base64::decode(data_base64)
            .expect("data_base64 should decode as valid base64");
        assert_eq!(decoded, original_bytes);
        assert_eq!(attachments[0]["file_name"], "secret.txt");
        assert_eq!(attachments[0]["id"], "attachment-id");
    }

    // Exercises the actual `--encrypt` code path (tar.gz packaging +
    // shelling out to `gpg --symmetric`) end to end. Requires a real `gpg`
    // binary on PATH, so it's `#[ignore]`d by default -- run explicitly
    // with `cargo test -- --ignored test_gpg_symmetric_encrypt_round_trip`
    // on a host that has GnuPG installed.
    #[test]
    #[ignore = "requires a real `gpg` binary on PATH"]
    fn test_gpg_symmetric_encrypt_round_trip() {
        let entry = sample_exported_entry(vec![ExportedAttachment {
            id: "attachment-id".to_string(),
            file_name: "secret.txt".to_string(),
            data_base64: rbw::base64::encode(b"attachment bytes"),
        }]);
        let vault = ExportedVault {
            entries: vec![entry],
            collections: vec![],
        };

        let archive = build_export_tar_gz(&vault).unwrap();
        let encrypted =
            gpg_symmetric_encrypt("correct horse battery staple", &archive)
                .unwrap();

        // Decrypt with a fresh `gpg` invocation (mirroring how a user
        // would do it: `rbw export --encrypt PASSPHRASE | gpg --batch
        // --yes --passphrase PASSPHRASE --decrypt | tar tz`) and confirm
        // the tar.gz round-trips to the original vault JSON.
        let mut tmp_encrypted = tempfile::NamedTempFile::new().unwrap();
        tmp_encrypted.write_all(&encrypted).unwrap();
        tmp_encrypted.flush().unwrap();

        let output = std::process::Command::new("gpg")
            .args([
                "--batch",
                "--yes",
                "--passphrase",
                "correct horse battery staple",
                "--decrypt",
            ])
            .arg(tmp_encrypted.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "gpg --decrypt failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let mut archive_reader =
            flate2::read::GzDecoder::new(std::io::Cursor::new(output.stdout));
        let mut tar_bytes = Vec::new();
        archive_reader.read_to_end(&mut tar_bytes).unwrap();
        let mut tar_archive =
            tar::Archive::new(std::io::Cursor::new(tar_bytes));
        let mut entries = tar_archive.entries().unwrap();
        let mut vault_entry = entries.next().unwrap().unwrap();
        assert_eq!(
            vault_entry.path().unwrap().to_str().unwrap(),
            "vault.json"
        );
        let mut vault_json = String::new();
        vault_entry.read_to_string(&mut vault_json).unwrap();
        assert!(entries.next().is_none());

        let decoded: serde_json::Value =
            serde_json::from_str(&vault_json).unwrap();
        assert_eq!(
            decoded["entries"][0]["attachments"][0]["file_name"],
            "secret.txt"
        );
        let decoded_base64 = decoded["entries"][0]["attachments"][0]
            ["data_base64"]
            .as_str()
            .unwrap();
        assert_eq!(
            rbw::base64::decode(decoded_base64).unwrap(),
            b"attachment bytes"
        );
    }

    // Round-trips entirely through rbw's own code paths: encrypt
    // (passphrase on fd 3 + plaintext via stdin) then
    // `decrypt_import_archive` (passphrase on fd 3 + ciphertext via stdin +
    // in-memory tar.gz extraction), so both directions of the
    // passphrase-fd plumbing get exercised.
    #[test]
    #[ignore = "requires a real `gpg` binary on PATH"]
    fn test_gpg_encrypt_decrypt_round_trip_via_passphrase_fd() {
        let vault = ExportedVault {
            entries: vec![sample_exported_entry(vec![])],
            collections: vec![],
        };
        let passphrase = "correct horse battery staple";

        let archive = build_export_tar_gz(&vault).unwrap();
        let encrypted = gpg_symmetric_encrypt(passphrase, &archive).unwrap();
        assert_ne!(encrypted, archive);

        let json = decrypt_import_archive(&encrypted, passphrase).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded["entries"][0]["name"], "example.com");

        let err = decrypt_import_archive(&encrypted, "wrong passphrase")
            .unwrap_err();
        assert!(
            format!("{err}").contains("decrypt"),
            "unexpected error: {err}"
        );
    }

    // A payload much larger than the kernel's pipe buffer (64KiB), to
    // prove the stdin-writer thread keeps gpg fed while its stdout is
    // drained -- i.e. the streaming structure can't deadlock.
    #[test]
    #[ignore = "requires a real `gpg` binary on PATH"]
    fn test_gpg_round_trip_survives_payloads_larger_than_pipe_buffer() {
        let attachment_bytes: Vec<u8> = (0..2_000_000_u32)
            .map(|i| {
                u8::try_from(i.wrapping_mul(2_654_435_761) % 251).unwrap()
            })
            .collect();
        let vault = ExportedVault {
            entries: vec![sample_exported_entry(vec![ExportedAttachment {
                id: "attachment-id".to_string(),
                file_name: "big.bin".to_string(),
                data_base64: rbw::base64::encode(&attachment_bytes),
            }])],
            collections: vec![],
        };
        let passphrase = "correct horse battery staple";

        let archive = build_export_tar_gz(&vault).unwrap();
        let encrypted = gpg_symmetric_encrypt(passphrase, &archive).unwrap();

        let json = decrypt_import_archive(&encrypted, passphrase).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&json).unwrap();
        let decoded_base64 = decoded["entries"][0]["attachments"][0]
            ["data_base64"]
            .as_str()
            .unwrap();
        assert_eq!(
            rbw::base64::decode(decoded_base64).unwrap(),
            attachment_bytes
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_write_secure_output_file_uses_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.json");
        write_secure_output_file(&path, br#"{"entries":[]}"#).unwrap();

        let mode =
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"entries":[]}"#);
    }

    #[test]
    #[cfg(unix)]
    fn test_write_secure_output_file_replaces_existing_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.json");
        std::fs::write(&path, b"something much longer than the export")
            .unwrap();
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        write_secure_output_file(&path, b"{}\n").unwrap();

        // The atomic-rename replacement leaves neither stale trailing bytes
        // nor the old (looser) permissions behind.
        assert_eq!(std::fs::read(&path).unwrap(), b"{}\n");
        let mode =
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_import_json_parses_plain_export_shape() {
        let json = r#"{
            "entries": [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "org_id": null,
                    "folder": "Work",
                    "name": "example",
                    "type": "Login",
                    "username": "user@example.com",
                    "password": "hunter2",
                    "totp": null,
                    "uris": [
                        { "uri": "https://example.com", "match_type": 0 }
                    ],
                    "fields": [
                        { "name": "custom", "value": "val", "type": "text" }
                    ],
                    "notes": "some notes",
                    "history": [
                        { "last_used_date": "2024-01-01T00:00:00Z", "password": "old" }
                    ],
                    "collection_ids": ["c1"]
                }
            ],
            "collections": [
                { "id": "c1", "org_id": "org1", "name": "Engineering" }
            ]
        }"#;

        let vault: ImportedVault = serde_json::from_str(json).unwrap();
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.collections.len(), 1);

        let entry = &vault.entries[0];
        assert_eq!(entry.name, "example");
        assert_eq!(entry.folder.as_deref(), Some("Work"));
        assert_eq!(entry.collection_ids, vec!["c1".to_string()]);
        assert!(entry.attachments.is_empty());
        assert_eq!(entry.history.len(), 1);
        assert_eq!(entry.history[0].password, "old");

        match &entry.data {
            ImportedData::Login {
                username, password, ..
            } => {
                assert_eq!(username.as_deref(), Some("user@example.com"));
                assert_eq!(password.as_deref(), Some("hunter2"));
            }
            other => panic!("expected Login variant, got {other:?}"),
        }

        let collection = &vault.collections[0];
        assert_eq!(collection.org_id, "org1");
        assert_eq!(collection.name, "Engineering");
    }

    #[test]
    fn test_import_json_tolerates_absent_attachments_field() {
        // Today's `rbw export` (no --attachments support yet) never emits
        // an `attachments` key at all -- make sure that still parses.
        let json = r#"{
            "entries": [
                {
                    "id": "1",
                    "name": "no-attachments",
                    "type": "SecureNote",
                    "fields": [],
                    "notes": null,
                    "history": [],
                    "collection_ids": []
                }
            ],
            "collections": []
        }"#;

        let vault: ImportedVault = serde_json::from_str(json).unwrap();
        assert_eq!(vault.entries.len(), 1);
        assert!(vault.entries[0].attachments.is_empty());
        assert!(matches!(vault.entries[0].data, ImportedData::SecureNote));
    }

    #[test]
    fn test_import_json_tolerates_unrecognized_attachment_shape() {
        // If `rbw export --attachments` ends up emitting a slightly
        // different shape than we guessed, entries should still parse --
        // individual attachments just get skipped (with a warning) at
        // upload time instead of the whole entry failing to parse.
        let json = r#"{
            "entries": [
                {
                    "id": "1",
                    "name": "weird-attachments",
                    "type": "SecureNote",
                    "fields": [],
                    "notes": null,
                    "history": [],
                    "collection_ids": [],
                    "attachments": [
                        { "totally": "unexpected", "shape": 42 },
                        { "file_name": "known.txt", "data_base64": "aGVsbG8=" }
                    ]
                }
            ],
            "collections": []
        }"#;

        let vault: ImportedVault = serde_json::from_str(json).unwrap();
        assert_eq!(vault.entries[0].attachments.len(), 2);

        // The first doesn't match `ImportedAttachment`'s shape...
        let bad: Result<ImportedAttachment, _> =
            serde_json::from_value(vault.entries[0].attachments[0].clone());
        assert!(bad.is_ok(), "unknown fields are simply ignored");
        let bad = bad.unwrap();
        assert!(bad.file_name.is_none() && bad.data_base64.is_none());

        // ...while the second parses cleanly.
        let good: ImportedAttachment =
            serde_json::from_value(vault.entries[0].attachments[1].clone())
                .unwrap();
        assert_eq!(good.file_name.as_deref(), Some("known.txt"));
        assert_eq!(good.data_base64.as_deref(), Some("aGVsbG8="));
    }

    #[test]
    fn test_import_json_tolerates_unknown_extra_entry_fields() {
        // Forward-compatibility: an entry with a field we don't know about
        // shouldn't break parsing.
        let json = r#"{
            "entries": [
                {
                    "id": "1",
                    "name": "future-proof",
                    "type": "SecureNote",
                    "fields": [],
                    "notes": null,
                    "history": [],
                    "collection_ids": [],
                    "some_future_field": { "nested": true }
                }
            ],
            "collections": []
        }"#;

        let vault: ImportedVault = serde_json::from_str(json).unwrap();
        assert_eq!(vault.entries[0].name, "future-proof");
    }

    #[test]
    fn test_load_import_json_accepts_plain_json_without_passphrase() {
        let json = r#"{"entries":[],"collections":[]}"#;
        let loaded = load_import_json(json.as_bytes(), None).unwrap();
        assert_eq!(loaded, json);
    }

    #[test]
    fn test_load_import_json_errors_helpfully_for_non_json_without_passphrase(
    ) {
        let err = load_import_json(b"not json and not gpg either", None)
            .unwrap_err();
        assert!(
            format!("{err}").contains("--decrypt or --decrypt-passphrase"),
            "error should point at --decrypt/--decrypt-passphrase: {err}"
        );
    }

    #[test]
    fn test_imported_data_to_editable_login_preserves_fields_and_uris() {
        let data = ImportedData::Login {
            username: Some("user@example.com".to_string()),
            password: Some("hunter2".to_string()),
            totp: Some("otpauth://totp/x".to_string()),
            uris: Some(vec![ImportedUri {
                uri: "https://example.com".to_string(),
                match_type: Some(rbw::api::UriMatchType::Domain),
            }]),
            fido2_credentials: Vec::new(),
        };

        let editable = imported_data_to_editable(&data);
        match editable {
            EditableData::Login {
                username,
                password,
                totp,
                uris,
                ..
            } => {
                assert_eq!(username.as_deref(), Some("user@example.com"));
                assert_eq!(password.as_deref(), Some("hunter2"));
                assert_eq!(totp.as_deref(), Some("otpauth://totp/x"));
                assert_eq!(uris.len(), 1);
                assert_eq!(uris[0].uri, "https://example.com");
                assert_eq!(uris[0].match_type.as_deref(), Some("domain"));
            }
            other => panic!("expected Login variant, got {other:?}"),
        }
    }

    #[test]
    fn test_imported_data_to_editable_login_without_uris_is_empty() {
        let data = ImportedData::Login {
            username: None,
            password: None,
            totp: None,
            uris: None,
            fido2_credentials: Vec::new(),
        };
        match imported_data_to_editable(&data) {
            EditableData::Login { uris, .. } => assert!(uris.is_empty()),
            other => panic!("expected Login variant, got {other:?}"),
        }
    }

    #[test]
    fn test_imported_data_to_editable_ssh_key() {
        let data = ImportedData::SshKey {
            private_key: Some(
                "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
            ),
            public_key: Some("ssh-ed25519 AAAA...".to_string()),
            fingerprint: Some("SHA256:abc".to_string()),
        };

        match imported_data_to_editable(&data) {
            EditableData::SshKey {
                private_key,
                public_key,
                fingerprint,
            } => {
                assert_eq!(
                    private_key.as_deref(),
                    Some("-----BEGIN OPENSSH PRIVATE KEY-----")
                );
                assert_eq!(
                    public_key.as_deref(),
                    Some("ssh-ed25519 AAAA...")
                );
                assert_eq!(fingerprint.as_deref(), Some("SHA256:abc"));
            }
            other => panic!("expected SshKey variant, got {other:?}"),
        }
    }

    #[test]
    fn test_ssh_key_entries_parse_from_import_json() {
        let json = r#"{
            "entries": [
                {
                    "id": "1",
                    "name": "server key",
                    "type": "SshKey",
                    "public_key": "ssh-ed25519 AAAA...",
                    "fingerprint": "SHA256:abc",
                    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----",
                    "fields": [],
                    "notes": null,
                    "history": [],
                    "collection_ids": []
                }
            ],
            "collections": []
        }"#;

        let vault: ImportedVault = serde_json::from_str(json).unwrap();
        assert!(matches!(vault.entries[0].data, ImportedData::SshKey { .. }));
    }

    #[test]
    fn test_bw_vault_to_imported_converts_bitwarden_json_shape() {
        // A Bitwarden "JSON" export: different field names/casing and a
        // numeric `type` than rbw's own export, plus a folder referenced by
        // id rather than by name.
        let json = r#"{
            "folders": [
                { "id": "f1", "name": "Work" }
            ],
            "collections": [
                { "id": "c1", "organizationId": "org1", "name": "Engineering" }
            ],
            "items": [
                {
                    "id": "1",
                    "organizationId": "org1",
                    "folderId": "f1",
                    "archivedDate": "2026-07-29T12:00:00.000Z",
                    "deletedDate": "2026-07-29T12:00:00.000Z",
                    "type": 1,
                    "name": "example",
                    "notes": "some notes",
                    "login": {
                        "username": "user@example.com",
                        "password": "hunter2",
                        "totp": null,
                        "uris": [
                            { "uri": "https://example.com", "match": 0 }
                        ]
                    },
                    "fields": [
                        { "name": "custom", "value": "val", "type": 0 }
                    ],
                    "passwordHistory": [
                        { "lastUsedDate": "2024-01-01T00:00:00Z", "password": "old" }
                    ],
                    "collectionIds": ["c1"]
                },
                {
                    "id": "2",
                    "type": 2,
                    "name": "a note",
                    "notes": "shh"
                }
            ]
        }"#;

        let bw = crate::import_bitwarden::parse_bitwarden_json(json).unwrap();
        let vault = bw_vault_to_imported(bw, None);

        assert_eq!(vault.collections.len(), 1);
        assert_eq!(vault.collections[0].org_id, "org1");
        assert_eq!(vault.collections[0].name, "Engineering");

        assert_eq!(vault.entries.len(), 2);

        let login = &vault.entries[0];
        assert_eq!(login.name, "example");
        assert_eq!(login.folder.as_deref(), Some("Work"));
        assert_eq!(login.org_id.as_deref(), Some("org1"));
        assert_eq!(login.collection_ids, vec!["c1".to_string()]);
        assert!(login.archived);
        assert!(login.deleted);
        assert_eq!(login.history.len(), 1);
        assert_eq!(login.history[0].password, "old");
        assert_eq!(login.fields.len(), 1);
        assert_eq!(login.fields[0].ty.as_deref(), Some("text"));
        match &login.data {
            ImportedData::Login {
                username,
                password,
                uris,
                ..
            } => {
                assert_eq!(username.as_deref(), Some("user@example.com"));
                assert_eq!(password.as_deref(), Some("hunter2"));
                let uris = uris.as_ref().unwrap();
                assert_eq!(uris[0].uri, "https://example.com");
            }
            other => panic!("expected Login variant, got {other:?}"),
        }

        let note = &vault.entries[1];
        assert_eq!(note.name, "a note");
        assert!(note.folder.is_none());
        assert!(matches!(note.data, ImportedData::SecureNote));
    }

    #[test]
    fn test_exported_vault_to_bw_converts_rbw_export_shape() {
        let vault = ExportedVault {
            entries: vec![
                ExportedEntry {
                    id: "1".to_string(),
                    org_id: Some("org1".to_string()),
                    folder: Some("Work".to_string()),
                    name: "example".to_string(),
                    data: DecryptedData::Login {
                        username: Some("user@example.com".to_string()),
                        password: Some("hunter2".to_string()),
                        totp: None,
                        uris: Some(vec![DecryptedUri {
                            uri: "https://example.com".to_string(),
                            match_type: None,
                        }]),
                        fido2_credentials: Vec::new(),
                    },
                    fields: vec![DecryptedField {
                        name: Some("custom".to_string()),
                        value: Some("val".to_string()),
                        ty: Some(rbw::api::FieldType::Text),
                    }],
                    notes: Some("some notes".to_string()),
                    history: vec![DecryptedHistoryEntry {
                        last_used_date: "2024-01-01T00:00:00Z".to_string(),
                        password: "old".to_string(),
                    }],
                    collection_ids: vec!["c1".to_string()],
                    archived: true,
                    deleted: true,
                    attachments: vec![],
                },
                ExportedEntry {
                    id: "2".to_string(),
                    org_id: None,
                    folder: None,
                    name: "a note".to_string(),
                    data: DecryptedData::SecureNote,
                    fields: vec![],
                    notes: None,
                    history: vec![],
                    collection_ids: vec![],
                    archived: false,
                    deleted: false,
                    attachments: vec![],
                },
            ],
            collections: vec![ExportedCollection {
                id: "c1".to_string(),
                org_id: "org1".to_string(),
                name: "Engineering".to_string(),
            }],
        };

        let (bw, attachments) = exported_vault_to_bw(&vault);
        assert!(attachments.is_empty());

        assert_eq!(bw.collections.len(), 1);
        assert_eq!(
            bw.collections[0].organization_id.as_deref(),
            Some("org1")
        );
        assert_eq!(bw.collections[0].name, "Engineering");

        assert_eq!(bw.folders.len(), 1);
        assert_eq!(bw.folders[0].name, "Work");
        let work_folder_id = bw.folders[0].id.clone().unwrap();

        assert_eq!(bw.items.len(), 2);
        let login = &bw.items[0];
        assert_eq!(login.ty, 1);
        assert_eq!(login.organization_id.as_deref(), Some("org1"));
        assert_eq!(login.folder_id.as_deref(), Some(work_folder_id.as_str()));
        assert_eq!(login.collection_ids, vec!["c1".to_string()]);
        assert_eq!(login.fields.len(), 1);
        assert!(login.archived_date.is_some());
        assert!(login.deleted_date.is_some());
        let login_data = login.login.as_ref().unwrap();
        assert_eq!(login_data.username.as_deref(), Some("user@example.com"));
        assert_eq!(
            login_data.uris[0].uri.as_deref(),
            Some("https://example.com")
        );

        let note = &bw.items[1];
        assert_eq!(note.ty, 2);
        assert!(note.folder_id.is_none());
        assert!(note.login.is_none());
    }

    #[test]
    fn test_bw_vault_to_imported_skips_unrecognized_item_type() {
        let json = r#"{
            "items": [
                { "id": "1", "type": 99, "name": "mystery" }
            ]
        }"#;

        let bw = crate::import_bitwarden::parse_bitwarden_json(json).unwrap();
        let vault = bw_vault_to_imported(bw, None);
        assert!(vault.entries.is_empty());
    }

    #[test]
    fn test_detect_format_recognizes_rbw_and_bitwarden_shapes() {
        use crate::import_bitwarden::{detect_format, DetectedFormat};

        assert_eq!(
            detect_format(br#"{"entries": [], "collections": []}"#).unwrap(),
            DetectedFormat::Rbw
        );
        assert_eq!(
            detect_format(br#"{"folders": [], "items": []}"#).unwrap(),
            DetectedFormat::BitwardenJson
        );
        assert_eq!(
            detect_format(br#"{"encrypted": true, "data": "2.iv|ct|mac"}"#)
                .unwrap(),
            DetectedFormat::BitwardenEncryptedJson
        );
        assert_eq!(
            detect_format(b"PK\x03\x04rest-of-the-zip").unwrap(),
            DetectedFormat::BitwardenZip
        );
    }

    #[test]
    fn test_bw_item_attachments_matches_by_sanitized_item_name() {
        let mut all = std::collections::HashMap::new();
        all.insert(
            // The real zip layout sanitizes illegal path characters in the
            // item name (see `sanitize_zip_folder_name`) -- this key is
            // what `email: p@x.dev` becomes.
            "email_ p@x.dev".to_string(),
            vec![
                crate::import_bitwarden::ZipAttachment {
                    file_name: "photo.png".to_string(),
                    data: b"pngbytes".to_vec(),
                },
                crate::import_bitwarden::ZipAttachment {
                    file_name: "notes.txt".to_string(),
                    data: b"hello".to_vec(),
                },
            ],
        );

        let out = bw_item_attachments("email: p@x.dev", &mut all);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["file_name"], "photo.png");
        assert_eq!(out[0]["data_base64"], rbw::base64::encode(b"pngbytes"));
        assert_eq!(out[1]["file_name"], "notes.txt");
        assert_eq!(out[1]["data_base64"], rbw::base64::encode(b"hello"));
        // The whole per-item bucket is consumed in one pass.
        assert!(!all.contains_key("email_ p@x.dev"));

        // An item with no matching folder just gets no attachments.
        assert!(bw_item_attachments("nothing here", &mut all).is_empty());
    }

    // Builds an in-memory tar.gz containing the given (name, contents)
    // files, mirroring what `build_export_tar_gz` produces.
    fn tar_gz_with_files(files: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);
        for (name, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(u64::try_from(contents.len()).unwrap());
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            builder.append_data(&mut header, name, *contents).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn test_extract_vault_json_prefers_json_extension() {
        let targz = tar_gz_with_files(&[
            ("readme.txt", b"not json"),
            ("export.json", b"{}"),
        ]);
        assert_eq!(extract_vault_json(&targz).unwrap(), "{}");
    }

    #[test]
    fn test_extract_vault_json_falls_back_to_any_file() {
        let targz = tar_gz_with_files(&[("export.dat", b"{}")]);
        assert_eq!(extract_vault_json(&targz).unwrap(), "{}");
    }

    #[test]
    fn test_extract_vault_json_errors_when_archive_is_empty() {
        let targz = tar_gz_with_files(&[]);
        let err = extract_vault_json(&targz).unwrap_err();
        assert!(
            format!("{err}").contains("no JSON file found"),
            "unexpected error: {err}"
        );
    }

    fn collection(id: &str, org_id: &str, name: &str) -> DecryptedCollection {
        DecryptedCollection {
            id: id.to_string(),
            org_id: org_id.to_string(),
            name: name.to_string(),
        }
    }

    #[test]
    fn test_resolve_collection_matches_id_name_and_substring() {
        let collections = vec![
            collection("11111111-aaaa", "org1", "Infra"),
            collection("22222222-bbbb", "org1", "Infra/Prod"),
            collection("33333333-cccc", "org2", "Infra"),
        ];

        // Exact ID wins, even when other names would substring-match.
        assert_eq!(
            resolve_collection(&collections, "11111111-aaaa", None)
                .unwrap()
                .name,
            "Infra"
        );
        // Exact name, restricted to the given org.
        assert_eq!(
            resolve_collection(&collections, "Infra", Some("org2"))
                .unwrap()
                .id,
            "33333333-cccc"
        );
        // Substring fallback (case-insensitive).
        assert_eq!(
            resolve_collection(&collections, "prod", Some("org1"))
                .unwrap()
                .id,
            "22222222-bbbb"
        );
        assert!(resolve_collection(&collections, "nope", None).is_err());
    }

    #[test]
    fn test_resolve_collection_lists_candidates_on_ambiguity() {
        let collections = vec![
            collection("11111111-aaaa", "org1", "Infra"),
            collection("22222222-bbbb", "org1", "Infra/Prod"),
        ];

        let err = resolve_collection(&collections, "infra", Some("org1"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("multiple collections found"), "{err}");
        assert!(err.contains("Infra (11111111-aaaa)"), "{err}");
        assert!(err.contains("Infra/Prod (22222222-bbbb)"), "{err}");

        // An exact name match is not ambiguous with its substring siblings.
        assert_eq!(
            resolve_collection(&collections, "Infra", Some("org1"))
                .unwrap()
                .id,
            "11111111-aaaa"
        );
    }

    #[test]
    fn test_resolve_org_auto_detects_single_org() {
        let mut db = rbw::db::Db::default();
        assert!(resolve_org(&db, None).is_err());

        db.protected_org_keys
            .insert("org1".to_string(), "key".to_string());
        assert_eq!(resolve_org(&db, None).unwrap(), "org1");
        assert_eq!(resolve_org(&db, Some("org1")).unwrap(), "org1");
        assert!(resolve_org(&db, Some("org2")).is_err());

        db.protected_org_keys
            .insert("org2".to_string(), "key".to_string());
        let err = resolve_org(&db, None).unwrap_err().to_string();
        assert!(err.contains("multiple organizations found"), "{err}");
        assert!(err.contains("org1"), "{err}");
        assert!(err.contains("org2"), "{err}");
        assert_eq!(resolve_org(&db, Some("org2")).unwrap(), "org2");
    }

    fn organization(id: &str, name: &str) -> rbw::db::Organization {
        rbw::db::Organization {
            id: id.to_string(),
            name: name.to_string(),
        }
    }

    #[test]
    fn test_resolve_organization_matches_id_name_and_substring() {
        let organizations = vec![
            organization("11111111-aaaa", "bitwarden.com"),
            organization("22222222-bbbb", "bitwarden.com testing"),
        ];

        // Exact ID wins, even when other names would substring-match.
        assert_eq!(
            resolve_organization(&organizations, "11111111-aaaa")
                .unwrap()
                .name,
            "bitwarden.com"
        );
        // Exact name.
        assert_eq!(
            resolve_organization(&organizations, "bitwarden.com")
                .unwrap()
                .id,
            "11111111-aaaa"
        );
        // Substring fallback (case-insensitive).
        assert_eq!(
            resolve_organization(&organizations, "testing").unwrap().id,
            "22222222-bbbb"
        );
        assert!(resolve_organization(&organizations, "nope").is_err());
    }

    #[test]
    fn test_resolve_organization_lists_candidates_on_ambiguity() {
        let organizations = vec![
            organization("11111111-aaaa", "Infra"),
            organization("22222222-bbbb", "Infra/Prod"),
        ];

        let err = resolve_organization(&organizations, "infra")
            .unwrap_err()
            .to_string();
        assert!(err.contains("multiple organizations found"), "{err}");
        assert!(err.contains("Infra (11111111-aaaa)"), "{err}");
        assert!(err.contains("Infra/Prod (22222222-bbbb)"), "{err}");

        // An exact name match is not ambiguous with its substring siblings.
        assert_eq!(
            resolve_organization(&organizations, "Infra").unwrap().id,
            "11111111-aaaa"
        );
    }

    // Both of `mirror_vault`'s guard clauses are checked before any
    // config/agent access, so they're directly unit-testable without a
    // configured account.
    #[test]
    fn test_mirror_vault_rejects_identical_from_and_to() {
        let err = mirror_vault(
            "same", "same", None, None, None, None, false, false, false,
            true, None, false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("must name different accounts"), "{err}");
    }

    #[test]
    fn test_mirror_vault_rejects_purge_dest_with_a_scope() {
        let err = mirror_vault(
            "a",
            "b",
            Some("some-collection"),
            None,
            None,
            None,
            false,
            false,
            true,
            true,
            None,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--purge-dest"), "{err}");
        assert!(err.contains("--collection"), "{err}");

        let err = mirror_vault(
            "a",
            "b",
            None,
            Some("org-id"),
            None,
            None,
            false,
            false,
            true,
            true,
            None,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--purge-dest"), "{err}");
        assert!(err.contains("--org-id"), "{err}");
    }

    // `--purge-dest` combined with `--dest-collection` (unlike the source-
    // side `--collection`/`--org-id` above) is a supported scoped purge, so
    // it must clear the guard clause -- whatever it fails on next (loading
    // config, an unconfigured account, ...) depends on the environment the
    // test runs in, so just check the guard's own refusal text is absent.
    #[test]
    fn test_mirror_vault_allows_purge_dest_with_dest_collection() {
        let err = mirror_vault(
            "a",
            "b",
            None,
            None,
            Some("some-collection"),
            None,
            false,
            false,
            true,
            true,
            None,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(!err.contains("can't be combined"), "{err}");
    }

    fn config_with_gpg_alias() -> rbw::config::Config {
        let mut config = rbw::config::Config::new();
        config.aliases.push(rbw::config::ItemAlias {
            alias: vec!["gpg".to_string()],
            item: "GPG key".to_string(),
            field: Some("passphrase".to_string()),
            ..rbw::config::ItemAlias::default()
        });
        config
    }

    // A bare single-`Name`-needle `rbw get NAME` matching a configured
    // alias resolves to it.
    #[test]
    fn test_resolve_get_alias_matches_bare_needle() {
        let config = config_with_gpg_alias();
        let needles = [Needle::Name("gpg".to_string())];
        let (name, alias) =
            resolve_get_alias(&config, &needles, None, None, None, None)
                .expect("alias should resolve");
        assert_eq!(name, "gpg");
        assert_eq!(alias.item, "GPG key");
    }

    // A needle that doesn't match any configured alias name falls through
    // to a normal search.
    #[test]
    fn test_resolve_get_alias_ignores_unknown_name() {
        let config = config_with_gpg_alias();
        let needles = [Needle::Name("not-an-alias".to_string())];
        assert!(resolve_get_alias(&config, &needles, None, None, None, None)
            .is_none());
    }

    // Any of --user/--folder/--collection/--org being set means the caller
    // is doing an explicit search, so alias resolution is skipped even if
    // the needle would otherwise match.
    #[test]
    fn test_resolve_get_alias_skipped_when_scoping_flags_are_set() {
        let config = config_with_gpg_alias();
        let needles = [Needle::Name("gpg".to_string())];
        assert!(resolve_get_alias(
            &config,
            &needles,
            Some("someone"),
            None,
            None,
            None
        )
        .is_none());
        assert!(resolve_get_alias(
            &config,
            &needles,
            None,
            Some("folder"),
            None,
            None
        )
        .is_none());
        assert!(resolve_get_alias(
            &config,
            &needles,
            None,
            None,
            Some("collection"),
            None
        )
        .is_none());
        assert!(resolve_get_alias(
            &config,
            &needles,
            None,
            None,
            None,
            Some("org")
        )
        .is_none());
    }

    // More than one needle means the caller passed multiple search terms,
    // which can't be a bare alias invocation.
    #[test]
    fn test_resolve_get_alias_skipped_with_multiple_needles() {
        let config = config_with_gpg_alias();
        let needles = [
            Needle::Name("gpg".to_string()),
            Needle::Name("extra".to_string()),
        ];
        assert!(resolve_get_alias(&config, &needles, None, None, None, None)
            .is_none());
    }
}
