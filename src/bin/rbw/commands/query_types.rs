use super::*;

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
pub(super) enum Field {
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
    pub(super) fn as_str(&self) -> &str {
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
pub(super) struct DecryptedListCipher {
    pub(super) id: String,
    pub(super) name: Option<String>,
    pub(super) user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) password: Option<String>,
    pub(super) folder: Option<String>,
    pub(super) uris: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub(super) entry_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) collection_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) revision_date: Option<String>,
    #[serde(flatten)]
    pub(super) attachment_metadata: AttachmentMetadata,
    pub(super) archived: bool,
    pub(super) deleted: bool,
    // Set when this entry was merged in from a non-active account (multi-
    // account `list`/`search`); omitted otherwise so single-account output is
    // unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) account: Option<String>,
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
    pub(super) sensitive_fields: Vec<String>,
    #[serde(skip)]
    pub(super) password: Option<String>,
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
pub(super) enum QueryToken {
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
    pub(super) fn recognizes_prefix(prefix: &str) -> bool {
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

    pub(super) fn parse(word: &str) -> Self {
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
pub(super) fn parse_query(input: &str) -> Vec<QueryToken> {
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
pub(super) const SCORE_UID_EXACT: u32 = 10_000;
pub(super) const SCORE_NAME_EXACT: u32 = 1_000;
pub(super) const SCORE_NAME_PREFIX: u32 = 200;
pub(super) const SCORE_NAME_SUBSTR: u32 = 100;
pub(super) const SCORE_URI: u32 = 80;
pub(super) const SCORE_ID_SUBSTR: u32 = 20;
pub(super) const SCORE_SENSITIVE: u32 = 10;
pub(super) const SCORE_FULL_NAME_BONUS: u32 = 5_000;

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
    pub(super) fn passes_user_folder(
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
    pub(super) fn match_score(
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
                    matches_url(
                        uri,
                        *match_type,
                        given_uri,
                        configured_uri_match(),
                    )
                })
                .then_some(SCORE_URI),
        }
    }

    pub(super) fn matches(
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

    pub(super) fn token_match(
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
            revision_date: None,
            attachment_metadata,
            archived: value.archived,
            deleted: value.deleted,
            account: None,
        }
    }
}
