#[test]
fn domain_matches_by_base_domain() {
    let domain = Some(rbw::api::UriMatchType::Domain);
    let m = |stored: &str, page: &str| {
        super::matches_url(
            stored,
            domain,
            &url::Url::parse(page).unwrap(),
            rbw::config::UriMatchDefault::Domain,
        )
    };
    assert!(m("https://login.example.com", "https://www.example.com/"));
    assert!(m("https://example.com", "https://a.b.example.com/x"));
    assert!(m("example.com", "https://sub.example.com/"));
    assert!(m("https://example.co.uk", "https://www.example.co.uk/"));
    assert!(!m("https://example.co.uk", "https://evil.co.uk/"));
    assert!(!m("https://a.github.io", "https://b.github.io/"));
    assert!(!m("https://example.com", "http://example.com/"));
    assert!(!m("https://example.com", "https://example.com.evil.net/"));
    assert!(m("http://localhost:3000", "http://localhost:3000/login"));
    assert!(!m("http://localhost:3000", "http://localhost:4000/"));
    assert!(m("localhost:3000", "http://localhost:3000/"));
    assert!(m("192.168.1.1", "http://192.168.1.1/"));
    assert!(!m("192.168.1.1", "http://192.168.1.10/"));
}

#[test]
fn default_uri_match_applies_only_without_a_match_type() {
    use rbw::api::UriMatchType::{Host, Never};
    use rbw::config::UriMatchDefault;
    let page = url::Url::parse("https://www.example.com/login").unwrap();
    let m = |stored, match_type, default| {
        super::matches_url(stored, match_type, &page, default)
    };
    // rbw's default: the stored host and its subdomains only.
    assert!(m("https://example.com", None, UriMatchDefault::Domain));
    assert!(!m(
        "https://login.example.com",
        None,
        UriMatchDefault::Domain
    ));
    // Bitwarden's base domain, when chosen as the default.
    assert!(m(
        "https://login.example.com",
        None,
        UriMatchDefault::BaseDomain
    ));
    assert!(!m("https://example.com", None, UriMatchDefault::Host));
    assert!(!m("https://www.example.com", None, UriMatchDefault::Never));
    // Explicit per-URI match types win over the default.
    assert!(m(
        "https://www.example.com",
        Some(Host),
        UriMatchDefault::Never
    ));
    assert!(!m(
        "https://example.com",
        Some(Never),
        UriMatchDefault::Domain
    ));
    assert!(m(
        "https://login.example.com",
        Some(rbw::api::UriMatchType::Domain),
        UriMatchDefault::Domain
    ));
}

#[test]
fn default_uri_match_config_keys_parse() {
    assert_eq!(
        super::parse_uri_match_default("starts_with").unwrap(),
        rbw::config::UriMatchDefault::StartsWith
    );
    assert_eq!(
        super::parse_uri_match_default("base_domain").unwrap(),
        rbw::config::UriMatchDefault::BaseDomain
    );
    assert!(super::parse_uri_match_default("bogus").is_err());
}

#[test]
fn starts_with_requires_same_origin() {
    let sw = Some(rbw::api::UriMatchType::StartsWith);
    let m = |stored: &str, page: &str| {
        super::matches_url(
            stored,
            sw,
            &url::Url::parse(page).unwrap(),
            rbw::config::UriMatchDefault::Domain,
        )
    };
    assert!(!m("https://example.com", "https://example.com.evil.net/"));
    assert!(!m("https://example.com/", "https://example.com.evil.net/"));
    assert!(m(
        "https://example.com/app",
        "https://example.com/app/login"
    ));
    assert!(!m("https://example.com/app", "https://example.com/other"));
    assert!(m("https://example.com", "https://example.com/"));
    assert!(m("https://example.com", "https://example.com/some/page"));
    assert!(!m("https://example.com", "http://example.com/"));
    assert!(!m("https://example.com", "https://example.com:8443/"));
}

#[test]
fn browser_totp_codes_include_their_actual_validity_window() {
    // Public RFC-style test material, never a real authenticator key.
    for (secret, expected_period, digits) in [
        ("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 30, 6),
        ("otpauth://totp/demo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=45&digits=8", 45, 8),
        ("steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 30, 5),
    ] {
        let (code, period, expires) = super::generate_totp_with_expiry(secret).unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(code.len(), digits);
        assert_eq!(period, expected_period);
        assert_eq!(expires % period, 0);
        assert!(expires >= now && expires <= now + period);
    }
    assert!(super::generate_totp_with_expiry("otpauth://totp/demo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=0").is_err());
}

#[test]
fn write_outcomes_survive_context_and_do_not_stash_committed_edits() {
    let err = anyhow::anyhow!("sync failed")
        .context(super::WriteCommitted)
        .context("outer caller");
    assert_eq!(super::exit_status(&err), 2);
    let err = super::after_editor::<()>("dummy buffer", true, Err(err))
        .unwrap_err();
    assert_eq!(super::exit_status(&err), 2);
    assert!(!format!("{err:#}").contains("unsaved plaintext"));
    let err = super::after_editor::<()>(
        "dummy pipe",
        false,
        Err(anyhow::anyhow!("PUT failed")),
    )
    .unwrap_err();
    assert_eq!(super::exit_status(&err), 1);
    assert_eq!(format!("{err:#}"), "PUT failed");
}

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
    assert_eq!(config.mirrors[0].dest_collection.as_deref(), Some("Shared"));
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
    let row = vec!["UID".to_string(), "NAME".to_string(), "USER".to_string()];
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
        one_match(entries, "github", Some("foo"), Some("websites"), 6, false),
        "websites/foo@github"
    );
    assert!(
        one_match(entries, "GITHUB", Some("foo"), Some("websites"), 6, true),
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

    let gpg = entry_with_secret("Private GPG Key", Some("passphrase value"));
    let github = entry_with_secret(
        "GPG Key for github",
        Some("-----BEGIN PGP PRIVATE KEY-----"),
    );
    let smappee = entry_with_secret("smappee.com", Some("note mentions gpg"));
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
        linked_id: None,
    };
    let cipher = |data: DecryptedData,
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
        revision_date: None,
    };
    let login = |password: Option<&str>| DecryptedData::Login {
        username: None,
        password: password.map(std::string::ToString::to_string),
        totp: None,
        uris: None,
        fido2_credentials: Vec::new(),
    };
    let resolved =
        |c: &DecryptedCipher| c.default_secret().map(|(v, s)| (v, s.label()));

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
        make_entry("12345678-1234-1234-1234-1234567890ab", None, None, &[]),
        make_entry("12345678-1234-1234-1234-1234567890AC", None, None, &[]),
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
        make_entry("five", None, None, &[("https://five.com:8080/", None)]),
        make_entry("six", None, None, &[("six.com:8080", None)]),
        make_entry("seven", None, None, &[("192.168.0.128:8080", None)]),
    ];

    assert!(
        one_match(entries, "https://one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        one_match(entries, "https://login.one.com/", None, None, 0, false),
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
        one_match(entries, "https://login.three.com/", None, None, 2, false),
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
        one_match(entries, "https://five.com:8080/", None, None, 4, false),
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
            &[("192.168.0.128:8080", Some(rbw::api::UriMatchType::Domain))],
        ),
    ];

    assert!(
        one_match(entries, "https://one.com/", None, None, 0, false),
        "one"
    );
    assert!(
        one_match(entries, "https://login.one.com/", None, None, 0, false),
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
        one_match(entries, "https://login.three.com/", None, None, 2, false),
        "three"
    );
    // Base domain: a subdomain login also matches its parent domain.
    assert!(
        one_match(entries, "https://three.com/", None, None, 2, false),
        "three"
    );

    assert!(
        one_match(entries, "https://four.com/", None, None, 3, false),
        "four"
    );

    assert!(
        one_match(entries, "https://five.com:8080/", None, None, 4, false),
        "five"
    );
    // Base domain ignores ports for registrable domains, like Bitwarden.
    assert!(
        one_match(entries, "https://five.com/", None, None, 4, false),
        "five"
    );

    assert!(
        one_match(entries, "https://six.com:8080/", None, None, 5, false),
        "six"
    );
    assert!(
        one_match(entries, "https://six.com/", None, None, 5, false),
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
            &[("https://two.com/login", Some(rbw::api::UriMatchType::Host))],
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
            &[
                (
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Host),
                ),
            ],
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
        one_match(entries, "https://login.three.com/", None, None, 2, false),
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
        one_match(entries, "https://five.com:8080/", None, None, 4, false),
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
    let entries =
        &[
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
        one_match(entries, "https://two.com/login/sso", None, None, 1, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/", None, None, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/other-page", None, None, false),
        "two"
    );

    assert!(
        one_match(entries, "https://login.three.com/", None, None, 2, false),
        "three"
    );
    assert!(
        no_matches(entries, "https://three.com/", None, None, false),
        "three"
    );
}

#[test]
fn test_find_by_url_exact() {
    let entries =
        &[
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
        no_matches(entries, "https://two.com/login/sso", None, None, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/", None, None, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/other-page", None, None, false),
        "two"
    );

    assert!(
        one_match(entries, "https://login.three.com/", None, None, 2, false),
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
        one_match(entries, "https://two.com/login/sso", None, None, 1, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/", None, None, false),
        "two"
    );
    assert!(
        no_matches(entries, "https://two.com/other-page", None, None, false),
        "two"
    );

    assert!(
        one_match(entries, "https://login.three.com/", None, None, 2, false),
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
    let entries =
        &[
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
        no_matches(entries, "https://two.com/other-page", None, None, false),
        "two"
    );

    assert!(
        no_matches(entries, "https://login.three.com/", None, None, false),
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
                ("https://one.com/", Some(rbw::api::UriMatchType::Domain)),
                ("https://two.com/", Some(rbw::api::UriMatchType::Domain)),
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
        revision_date: None,
    }
}

fn custom_field(
    name: &str,
    value: Option<&str>,
    ty: rbw::api::FieldType,
) -> DecryptedField {
    DecryptedField {
        name: Some(name.to_string()),
        value: value.map(str::to_string),
        ty: Some(ty),
        linked_id: None,
    }
}

#[test]
fn test_raw_field_linked_id() {
    let mut f = DecryptedField {
        name: Some("n".to_string()),
        value: None,
        ty: Some(rbw::api::FieldType::Linked),
        linked_id: Some(rbw::api::LinkedIdType::LoginPassword),
    };
    let v = serde_json::to_value(&f).unwrap();
    assert_eq!(v["type"], "linked");
    assert_eq!(v["linked_id"], 101);
    f.linked_id = None;
    assert!(serde_json::to_value(&f).unwrap().get("linked_id").is_none());
}

#[test]
fn test_restore_candidate() {
    let mut cipher = login_cipher(Some("current"), None);
    assert!(restore_candidate(&cipher, 1).is_err());
    cipher.history = vec![
        DecryptedHistoryEntry {
            last_used_date: "2026-10-01T00:00:00Z".to_string(),
            password: "previous".to_string(),
        },
        DecryptedHistoryEntry {
            last_used_date: "2026-09-01T00:00:00Z".to_string(),
            password: "older".to_string(),
        },
    ];
    assert_eq!(restore_candidate(&cipher, 1).unwrap(), "previous");
    assert_eq!(restore_candidate(&cipher, 2).unwrap(), "older");
    assert!(restore_candidate(&cipher, 3).is_err());
}

#[test]
fn test_revision_dates() {
    let a = parse_revision_date("2026-09-25T08:03:10.1234567Z").unwrap();
    let b = parse_revision_date("2026-09-25T08:03:10.123456700Z").unwrap();
    assert_eq!(a, b);
    assert!(parse_revision_date("2026-09-25T08:03:10Z").unwrap() < a);
    assert!(parse_revision_date("yesterday").is_err());
    assert_eq!(
        format_revision_date("2026-09-25T08:03:10.1234567Z"),
        "2026-09-25"
    );

    let rev = "2026-09-25T08:03:10.1234567Z";
    assert!(check_revision("e", Some(rev), rev).is_ok());
    // same instant, different formatting
    assert!(
        check_revision("e", Some(rev), "2026-09-25T08:03:10.12345670Z")
            .is_ok()
    );
    assert!(check_revision("e", Some(rev), "2026-09-25T08:03:10Z").is_err());
    assert!(check_revision("e", None, rev).is_err());
}

#[test]
fn test_set_field_changes_and_updates() {
    let mut cipher = login_cipher(Some("hunter2"), None);
    cipher.fields = vec![
        custom_field(
            "api-token",
            Some("old-token-value"),
            rbw::api::FieldType::Text,
        ),
        custom_field("same", Some("v"), rbw::api::FieldType::Hidden),
    ];
    let updates = vec![
        ("api-token".to_string(), "new-token-value".to_string()),
        ("same".to_string(), "v".to_string()),
        ("fresh".to_string(), "x".to_string()),
    ];
    let changes = compute_entry_changes(
        &cipher,
        None,
        None,
        None,
        None,
        &[],
        None,
        &updates,
    )
    .unwrap();
    // the unchanged field is not reported, values are censored
    assert_eq!(changes.len(), 2);
    assert!(changes.iter().all(|(label, _, _)| *label == "field"));
    assert!(changes
        .iter()
        .all(|(_, old, new)| !old.contains("old-token-value")
            && !new.contains("new-token-value")));
    assert_eq!(changes[1].1, "fresh (none)");

    let mut fields = cipher.fields.clone();
    apply_field_updates_decrypted(&mut fields, &updates);
    assert_eq!(fields.len(), 3);
    // existing field keeps its type, new one is hidden
    assert_eq!(fields[0].value.as_deref(), Some("new-token-value"));
    assert_eq!(fields[0].ty, Some(rbw::api::FieldType::Text));
    assert_eq!(fields[2].name.as_deref(), Some("fresh"));
    assert_eq!(fields[2].ty, Some(rbw::api::FieldType::Hidden));

    cipher.fields =
        vec![custom_field("link", None, rbw::api::FieldType::Linked)];
    assert!(compute_entry_changes(
        &cipher,
        None,
        None,
        None,
        None,
        &[],
        None,
        &[("link".to_string(), "x".to_string())],
    )
    .is_err());
}

#[test]
fn test_credential_source_login_fields_extracts_password_and_totp() {
    let cipher = login_cipher(Some("hunter2"), Some("JBSWY3DPEHPK3PXP"));
    let (password, totp) =
        credential_source_login_fields(&cipher, "entry", "account").unwrap();
    assert_eq!(password, "hunter2");
    assert_eq!(totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
}

// No TOTP secret on the entry is fine -- only a missing password should
// fail resolution (the account might not have 2FA enabled at all).
#[test]
fn test_credential_source_login_fields_totp_is_optional() {
    let cipher = login_cipher(Some("hunter2"), None);
    let (password, totp) =
        credential_source_login_fields(&cipher, "entry", "account").unwrap();
    assert_eq!(password, "hunter2");
    assert_eq!(totp, None);
}

#[test]
fn test_credential_source_login_fields_requires_a_password() {
    let cipher = login_cipher(None, None);
    assert!(
        credential_source_login_fields(&cipher, "entry", "account").is_err()
    );
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
        revision_date: None,
    };
    assert!(
        credential_source_login_fields(&cipher, "entry", "account").is_err()
    );
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
        revision_date: None,
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
                username: username
                    .map(|_| "this is the encrypted username".to_string()),
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
            archived_date: None,
            favorite: false,
            archived: false,
            deleted: false,
            collection_ids: vec![],
            attachments: vec![],
            revision_date: None,
        },
        DecryptedSearchCipher {
            id: id.to_string(),
            entry_type: "Login".to_string(),
            folder: folder.map(std::string::ToString::to_string),
            name: name.to_string(),
            user: username.map(std::string::ToString::to_string),
            uris: uris
                .iter()
                .map(|(uri, match_type)| ((*uri).to_string(), *match_type))
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
#[test]
fn fzf_candidate_line_hides_id_first_and_flattens_tabs() {
    let (_, mut entry) =
        make_entry("a\tname", Some("user"), Some("folder"), &[]);
    entry.id = "id-1".to_string();
    assert_eq!(
        fzf_candidate_line(&entry, Some("work")),
        "id-1\twork\ta name\tuser\tfolder"
    );
    let (_, mut bare) = make_entry("bare", None, None, &[]);
    bare.id = "id-2".to_string();
    assert_eq!(fzf_candidate_line(&bare, None), "id-2\t\tbare\t\t");
}

#[test]
fn fzf_default_opts_puts_custom_options_last() {
    assert_eq!(
        fzf_default_opts(None, None),
        "--select-1 --header='Multiple entries match; pick one'"
    );
    assert_eq!(
        fzf_default_opts(Some("--height 40%"), Some("--no-select-1")),
        "--height 40% --select-1 --header='Multiple entries match; \
         pick one' --no-select-1"
    );
    assert_eq!(
        fzf_default_opts(Some("  "), Some("")),
        fzf_default_opts(None, None)
    );
}

#[test]
fn shell_quote_escapes_single_quotes() {
    assert_eq!(shell_quote("/usr/bin/rbw"), "'/usr/bin/rbw'");
    assert_eq!(shell_quote("it's"), r"'it'\''s'");
}

mod edit_field_tests {
    use super::*;

    fn cipher(
        data: DecryptedData,
        fields: &[(&str, &str)],
    ) -> DecryptedCipher {
        DecryptedCipher {
            id: "id".to_string(),
            folder: None,
            name: "entry".to_string(),
            data,
            fields: fields
                .iter()
                .map(|(n, v)| DecryptedField {
                    name: Some((*n).to_string()),
                    value: Some((*v).to_string()),
                    ty: Some(rbw::api::FieldType::Text),
                    linked_id: None,
                })
                .collect(),
            notes: Some("some notes".to_string()),
            history: vec![],
            attachments: vec![],
            attachment_metadata: AttachmentMetadata::new("id", 0),
            archived: false,
            deleted: false,
            revision_date: None,
            account: None,
        }
    }

    fn login() -> DecryptedData {
        DecryptedData::Login {
            username: Some("alice".to_string()),
            password: Some("hunter2".to_string()),
            totp: None,
            uris: Some(vec![
                DecryptedUri {
                    uri: "https://a.example".to_string(),
                    match_type: None,
                },
                DecryptedUri {
                    uri: "https://b.example".to_string(),
                    match_type: None,
                },
            ]),
            fido2_credentials: vec![],
        }
    }

    fn current(c: &DecryptedCipher, field: &str) -> String {
        EditFieldTarget::resolve(c, field).unwrap().current(c)
    }

    #[test]
    fn builtin_fields() {
        let c = cipher(login(), &[]);
        assert_eq!(current(&c, "username"), "alice");
        assert_eq!(current(&c, "user"), "alice");
        assert_eq!(current(&c, "Password"), "hunter2");
        assert_eq!(current(&c, "notes"), "some notes");
        assert_eq!(current(&c, "name"), "entry");
        assert_eq!(current(&c, "totp"), "");
        assert_eq!(
            current(&c, "uris"),
            "https://a.example\nhttps://b.example"
        );
    }

    #[test]
    fn custom_fields() {
        let c = cipher(login(), &[("API Key", "k1"), ("password", "f")]);
        // Built-in fields shadow a custom field of the same name.
        assert_eq!(current(&c, "password"), "hunter2");
        // Case-insensitive match keeps the stored spelling.
        assert!(matches!(
            EditFieldTarget::resolve(&c, "api key").unwrap(),
            EditFieldTarget::Custom(n) if n == "API Key"
        ));
        assert_eq!(current(&c, "api key"), "k1");
        // Unknown names become a new custom field.
        assert!(matches!(
            EditFieldTarget::resolve(&c, "new").unwrap(),
            EditFieldTarget::Custom(n) if n == "new"
        ));
        assert_eq!(current(&c, "new"), "");
    }

    #[test]
    fn rejects_unsupported_builtin_fields() {
        let c = cipher(login(), &[]);
        assert!(EditFieldTarget::resolve(&c, "cvv").is_err());
        let note = cipher(DecryptedData::SecureNote, &[]);
        assert!(EditFieldTarget::resolve(&note, "password").is_err());
        let note = cipher(DecryptedData::SecureNote, &[("password", "x")]);
        assert_eq!(current(&note, "password"), "x");
        assert_eq!(current(&note, "notes"), "some notes");
    }
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
        let (expr, next_start) = template.take_braced_expression(0).unwrap();

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

        let rendered =
            render_inject_template(&template, |reference| {
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
    fn test_render_inject_template_expands_variables_before_resolving_refs() {
        let template = "user=bw://${ ITEM_NAME }?field=${FIELD:-username}";

        let rendered = render_inject_template_with_env(
            template,
            &[("item_name", "some-api-key")],
            |reference| {
                assert_eq!(
                    reference.target,
                    InjectReferenceTarget::Name("some-api-key".to_string())
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

        let rendered = render_inject_template_with_env(template, &[], |_| {
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
    fn test_render_inject_template_treats_invalid_variable_tags_as_literals()
    {
        let template = "$1BAD ${foo-bar} cost=$5";

        let rendered = render_inject_template_with_env(template, &[], |_| {
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
    fn test_render_inject_template_respects_op_inject_raw_start_boundaries() {
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
                format!("token=bw://{entry_id}. wow! alert=bw://{entry_id}!"),
                "secret",
                "token=secret. wow! alert=secret!".to_string(),
            ),
        ] {
            let rendered = render_inject_template(&template, |reference| {
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
            let rendered = render_inject_template(&template, |reference| {
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
    fn test_render_inject_template_supports_raw_field_names_with_periods() {
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
            let rendered = render_inject_template(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                assert_eq!(reference.field.as_deref(), Some("API Token"));
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

        let err =
            render_inject_template(&template, |_| Ok("secret".to_string()))
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

        let rendered = render_inject_template(&template, |reference| {
            match reference.id.as_str() {
                id if id == dsn_id.to_string() => Ok("pw".to_string()),
                id if id == query_id.to_string() => Ok("token".to_string()),
                _ => Err(anyhow::anyhow!("unexpected reference")),
            }
        })
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
    fn test_find_inject_entry_raw_matches_name_refs_exactly_ignoring_case() {
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

        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
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
                ("MIXED".to_string(), "expanded-by-host:secret".to_string()),
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

        let pairs =
            parse_run_env_file(&template, |reference| {
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
                    "value with \"double\" and 'single' quotes".to_string()
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
                (key.to_os_string(), value.map(std::ffi::OsStr::to_os_string))
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
    fn test_resolve_inject_value_uses_password_username_and_custom_fields() {
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
                    linked_id: None,
                })
                .collect(),
            notes: None,
            history: vec![],
            attachments: vec![],
            attachment_metadata: AttachmentMetadata::new("example-id", 0),
            archived: false,
            deleted: false,
            account: None,
            revision_date: None,
        };

        assert_eq!(resolve_inject_value(&cipher, None).unwrap(), "hunter2");
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
    fn test_write_rendered_template_file_replaces_existing_file_atomically() {
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

        let mode =
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
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

        let err = write_rendered_template_file(&link, "hunter2").unwrap_err();
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
        let fifo_cstr = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        let status = unsafe { libc::mkfifo(fifo_cstr.as_ptr(), 0o600) };
        assert_eq!(status, 0);

        let _reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();

        let err = write_rendered_template_file(&fifo, "hunter2").unwrap_err();
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
    let mut tar_archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let mut entries = tar_archive.entries().unwrap();
    let mut vault_entry = entries.next().unwrap().unwrap();
    assert_eq!(vault_entry.path().unwrap().to_str().unwrap(), "vault.json");
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

    let err =
        decrypt_import_archive(&encrypted, "wrong passphrase").unwrap_err();
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
        .map(|i| u8::try_from(i.wrapping_mul(2_654_435_761) % 251).unwrap())
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

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(std::fs::read(&path).unwrap(), br#"{"entries":[]}"#);
}

#[test]
#[cfg(unix)]
fn test_write_secure_output_file_replaces_existing_file() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("backup.json");
    std::fs::write(&path, b"something much longer than the export").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .unwrap();

    write_secure_output_file(&path, b"{}\n").unwrap();

    // The atomic-rename replacement leaves neither stale trailing bytes
    // nor the old (looser) permissions behind.
    assert_eq!(std::fs::read(&path).unwrap(), b"{}\n");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
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
    assert_eq!(entry.attachments.len(), 0);
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
    assert_eq!(vault.entries[0].attachments.len(), 0);
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
fn test_load_import_json_errors_helpfully_for_non_json_without_passphrase() {
    let err =
        load_import_json(b"not json and not gpg either", None).unwrap_err();
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
        private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----".to_string()),
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
            assert_eq!(public_key.as_deref(), Some("ssh-ed25519 AAAA..."));
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
                    linked_id: None,
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
    assert_eq!(attachments.len(), 0);

    assert_eq!(bw.collections.len(), 1);
    assert_eq!(bw.collections[0].organization_id.as_deref(), Some("org1"));
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
    assert_eq!(bw_item_attachments("nothing here", &mut all).len(), 0);
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
        "same", "same", None, None, None, None, false, false, false, true,
        None, false,
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
