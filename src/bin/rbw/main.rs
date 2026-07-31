use std::ffi::OsString;
use std::io::Write as _;

use is_terminal::IsTerminal as _;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt as _;

use anyhow::Context as _;
use clap::{CommandFactory as _, Parser as _};

mod actions;
mod commands;
mod export_info;
mod import_bitwarden;
mod osc52;
mod sock;
mod tui;

#[derive(Debug, clap::Args)]
struct FindArgs {
    #[arg(
        help = "Name, URI, UUID (or multiple terms, all required to match)",
        value_parser = commands::parse_needle,
        num_args = 1..,
    )]
    needles: Vec<commands::Needle>,
    #[arg(long, help = "Username of the entry to display")]
    user: Option<String>,
    #[arg(long, help = "Folder name to search in")]
    folder: Option<String>,
    #[arg(
        long,
        value_name = "COLLECTION",
        help = "Only match entries in this collection (name or ID)"
    )]
    collection: Option<String>,
    #[arg(
        long,
        value_name = "ORG",
        help = "Only match entries in this organization (name or ID); \
            combine with --collection to disambiguate a collection name \
            that exists in more than one org"
    )]
    org: Option<String>,
    #[arg(short, long, help = "Ignore case")]
    ignorecase: bool,
    #[arg(
        short = 'e',
        long,
        help = "Only match if needle is an exact entry name (no substring fallback)"
    )]
    exact: bool,
}

// Password-generation flags shared between `rbw gen` and `rbw create
// --generate`, so the two can never drift apart. Layered at resolution time
// (see `resolve_pwgen`) over the configured `password_gen` policy over
// `rbw::pwgen`'s own hardcoded defaults.
#[derive(Debug, Default, Clone, clap::Args)]
#[command(group = clap::ArgGroup::new("password-type").args(&[
    "no_symbols",
    "only_numbers",
    "nonconfusables",
    "diceware",
]))]
struct PasswordGenArgs {
    #[arg(
        short = 'l',
        long = "length",
        help = "Length of the password to generate (or number of words \
            for --diceware); defaults to the configured password-gen \
            policy, else 20"
    )]
    length: Option<usize>,
    #[arg(
        long = "no-symbols",
        help = "Generate a password with no special characters"
    )]
    no_symbols: bool,
    #[arg(
        long = "only-numbers",
        help = "Generate a password consisting of only numbers"
    )]
    only_numbers: bool,
    #[arg(
        long,
        help = "Generate a password without visually similar \
            characters (useful for passwords intended to be \
            written down)"
    )]
    nonconfusables: bool,
    #[arg(
        long,
        help = "Generate a password of multiple dictionary \
            words chosen from the EFF word list. The length \
            parameter for this option will set the number \
            of words to generate, rather than characters."
    )]
    diceware: bool,
}

impl From<&PasswordGenArgs> for rbw::pwgen::GenFlags {
    fn from(args: &PasswordGenArgs) -> Self {
        Self {
            length: args.length,
            no_symbols: args.no_symbols,
            only_numbers: args.only_numbers,
            nonconfusables: args.nonconfusables,
            diceware: args.diceware,
        }
    }
}

// Explicit CLI flags > configured `password_gen` policy > `rbw::pwgen`'s own
// hardcoded defaults.
fn resolve_pwgen(cli: &PasswordGenArgs) -> (usize, rbw::pwgen::Type) {
    let policy = rbw::config::Config::load()
        .map(|c| c.password_gen)
        .unwrap_or_default();
    rbw::pwgen::resolve(cli.into(), (&policy).into())
}

// Resolves `--archived`/`--include-archived` against the configured
// `hide_archived` default (falling back to the hide-by-default behavior if
// the config can't be loaded).
fn resolve_archived_filter(
    archived: bool,
    include_archived: bool,
) -> commands::ArchivedFilter {
    let hide_archived_default =
        rbw::config::Config::load().map_or(true, |c| c.hide_archived);
    commands::ArchivedFilter::from_flags(
        archived,
        include_archived,
        hide_archived_default,
    )
}

// Resolves `--trashed`/`--deleted` and `--include-trashed`/
// `--include-deleted` against the configured `hide_trashed` default
// (falling back to the hide-by-default behavior if the config can't be
// loaded).
fn resolve_trash_filter(
    trashed: bool,
    include_trashed: bool,
) -> commands::TrashFilter {
    let hide_trashed_default =
        rbw::config::Config::load().map_or(true, |c| c.hide_trashed);
    commands::TrashFilter::from_flags(
        trashed,
        include_trashed,
        hide_trashed_default,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
enum OutputArg {
    Name,
    Json,
    Yaml,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
enum UnlockArg {
    Always,
    Never,
    OnDemand,
}

impl From<UnlockArg> for rbw::config::UnlockPolicy {
    fn from(value: UnlockArg) -> Self {
        match value {
            UnlockArg::Always => Self::Always,
            UnlockArg::Never => Self::Never,
            UnlockArg::OnDemand => Self::OnDemand,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
enum ExcludeContextArg {
    List,
    Search,
    Get,
    Show,
    Code,
    Sync,
    Unlock,
    Tui,
    All,
}

impl From<ExcludeContextArg> for rbw::config::ExcludeContext {
    fn from(value: ExcludeContextArg) -> Self {
        match value {
            ExcludeContextArg::List => Self::List,
            ExcludeContextArg::Search => Self::Search,
            ExcludeContextArg::Get => Self::Get,
            ExcludeContextArg::Show => Self::Show,
            ExcludeContextArg::Code => Self::Code,
            ExcludeContextArg::Sync => Self::Sync,
            ExcludeContextArg::Unlock => Self::Unlock,
            ExcludeContextArg::Tui => Self::Tui,
            ExcludeContextArg::All => Self::All,
        }
    }
}

fn resolve_output_mode(
    output: Option<OutputArg>,
    json: bool,
    yaml: bool,
) -> anyhow::Result<commands::OutputMode> {
    if output == Some(OutputArg::Name) && (json || yaml) {
        anyhow::bail!(
            "--output name cannot be combined with --json or --yaml"
        );
    }

    let mut structured = json.then_some(commands::OutputMode::Json);
    if yaml {
        if structured.is_some() {
            anyhow::bail!("conflicting output formats requested");
        }
        structured = Some(commands::OutputMode::Yaml);
    }

    if let Some(output) = output {
        return match output {
            OutputArg::Name => Ok(commands::OutputMode::Name),
            OutputArg::Json => {
                if structured == Some(commands::OutputMode::Yaml) {
                    anyhow::bail!("conflicting output formats requested");
                }
                Ok(commands::OutputMode::Json)
            }
            OutputArg::Yaml => {
                if structured == Some(commands::OutputMode::Json) {
                    anyhow::bail!("conflicting output formats requested");
                }
                Ok(commands::OutputMode::Yaml)
            }
        };
    }

    Ok(structured.unwrap_or(commands::OutputMode::Default))
}

#[derive(Debug, clap::Parser)]
#[command(version, about = "Unofficial Bitwarden CLI")]
struct Cli {
    #[arg(
        short = 'a',
        long,
        global = true,
        help = "Account to operate on (overrides RBW_ACCOUNT; defaults to \
            the primary account)"
    )]
    account: Option<String>,

    #[command(subcommand)]
    command: Opt,
}

#[derive(Debug, clap::Subcommand)]
enum Opt {
    #[command(about = "Get or set configuration options")]
    Config {
        #[command(subcommand)]
        config: Config,
    },

    #[command(about = "Manage configured accounts")]
    Account {
        #[command(subcommand)]
        account: AccountCmd,
    },

    #[command(about = "Use Termux Android Keystore for native unlocks")]
    Termux {
        #[command(subcommand)]
        termux: TermuxCmd,
    },

    #[command(
        about = "Register this device with the Bitwarden server",
        long_about = "Register this device with the Bitwarden server\n\n\
            The official Bitwarden server includes bot detection to prevent \
            brute force attacks. In order to avoid being detected as bot \
            traffic, you will need to use this command to log in with your \
            personal API key (instead of your password) first before regular \
            logins will work."
    )]
    Register {
        #[arg(
            long,
            help = "Read the API key client_id and client_secret from \
                standard input, one per line, instead of prompting via \
                pinentry"
        )]
        stdin: bool,
    },

    #[command(about = "Log in to the Bitwarden server")]
    Login {
        #[arg(long, help = "Read the password from standard input")]
        stdin: bool,
        #[arg(
            long,
            help = "TOTP code for the 2FA challenge, if the account \
                requires it (only meaningful with --stdin)"
        )]
        totp: Option<String>,
    },

    #[command(about = "Print version information")]
    Version,

    #[command(about = "Unlock the local Bitwarden database")]
    Unlock {
        #[arg(
            long,
            help = "Read the password from standard input",
            conflicts_with = "all"
        )]
        stdin: bool,
        #[arg(
            long,
            help = "TOTP code for the 2FA challenge on first-time login, \
                if the account requires it (only meaningful with --stdin)",
            conflicts_with = "all"
        )]
        totp: Option<String>,
        #[arg(
            long,
            help = "With multiple accounts configured, unlock (prompting \
                as needed) every account instead of just the active one"
        )]
        all: bool,
    },

    #[command(about = "Check if the local Bitwarden database is unlocked")]
    Unlocked,

    #[command(about = "Update the local copy of the Bitwarden database")]
    Sync {
        #[arg(
            long,
            help = "With multiple accounts configured, unlock (prompting as \
                needed) and sync every account instead of just the \
                already-unlocked ones"
        )]
        all: bool,
    },

    #[command(
        about = "Browse, search, and edit entries in an interactive terminal UI",
        long_about = "Browse, search, and edit entries in an interactive \
            terminal UI\n\n\
            Launches a full-screen interface for fuzzy-searching the vault, \
            viewing entry details (with reveal/copy for secrets), and editing \
            entries inline or in your $EDITOR.",
        visible_alias = "ui"
    )]
    Tui {
        #[arg(help = "Optional initial search term")]
        term: Option<String>,
        #[arg(
            long,
            help = "Unlock and load every configured account up front, \
                not just the ones already unlocked",
            conflicts_with = "from_file"
        )]
        all: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Browse a `rbw export` file directly instead of a \
                configured account -- read-only unless --write is also \
                given, no config/agent/account is touched. Prompts for a \
                passphrase if the file is gpg-encrypted (`rbw export \
                --encrypt`)."
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long,
            requires = "from_file",
            help = "With --from-file, allow editing/adding/deleting \
                entries and attachments, saving back to the file (a .bak \
                copy of the pre-edit file is made once, at startup)"
        )]
        write: bool,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
        #[arg(
            long,
            value_name = "SECONDS",
            conflicts_with = "from_file",
            help = "Automatically lock the TUI after this many seconds of inactivity (0 disables it; defaults to config.yaml)"
        )]
        screen_lock_timeout: Option<u64>,
    },

    #[command(
        name = "export-info",
        about = "Show counts and metadata from an export file",
        long_about = "Show counts and metadata from an export file\n\n\
            Reads rbw's own JSON or gpg-encrypted export, Bitwarden's JSON, \
            password-protected Encrypted JSON, zip, or CSV export, and prints \
            entry-type, note, passkey, collection, folder, attachment, and \
            other available counts. Reads from stdin if no file is given.\n\n\
            --format is auto-detected by default. Use --decrypt or \
            --decrypt-passphrase for password-protected exports."
    )]
    ExportInfo {
        #[arg(
            help = "Export file to inspect (defaults to stdin if omitted)"
        )]
        file: Option<std::path::PathBuf>,
        #[arg(
            long,
            alias = "type",
            value_enum,
            default_value = "auto",
            help = "Export format to inspect (default: auto-detect)"
        )]
        format: crate::export_info::Format,
        #[arg(
            long,
            conflicts_with = "decrypt_passphrase",
            help = "Decrypt a password-protected export using \
                RBW_EXPORT_PASSPHRASE or a tty prompt"
        )]
        decrypt: bool,
        #[arg(
            long,
            value_name = "PASSPHRASE",
            help = "Passphrase for a password-protected export (prefer \
                --decrypt to keep it out of process listings)"
        )]
        decrypt_passphrase: Option<String>,
        #[arg(short = 'j', long, help = "Display the counts as JSON")]
        json: bool,
    },

    #[command(
        about = "Export the entire vault as decrypted JSON",
        long_about = "Export the entire vault as decrypted JSON\n\n\
            Outputs all entries (with full details) and collections \
            to stdout, or to a file given -o/--output. Suitable for \
            backup or migration to another instance via `rbw import`.\n\n\
            --format selects the output shape: rbw's own (the default), \
            or one of Bitwarden's own \"JSON\", \"Encrypted JSON\", \"zip \
            (with attachments)\", and CSV export formats -- for migrating \
            to the official Bitwarden clients, or anything else that \
            reads their export shapes. Bitwarden's CSV format has no \
            columns for Card/Identity/SSH key entries, so \
            --format bitwarden-csv skips them (with a warning), matching \
            what the official clients do.\n\n\
            With --encrypt, rbw's own format is written as a \
            symmetrically gpg-encrypted tar.gz archive instead of raw \
            JSON. --format bitwarden-encrypted-json always needs a \
            password and prompts for one on its own even without \
            --encrypt; --encrypt there just supplies it inline instead, \
            skipping the prompt. Either way, the passphrase is read from \
            $RBW_EXPORT_PASSPHRASE if set, and prompted for on the \
            terminal (with confirmation) otherwise; it can also be passed \
            inline as `--encrypt PASSPHRASE`, but that exposes it to `ps` \
            and shell history."
    )]
    Export {
        #[arg(
            long,
            alias = "type",
            value_enum,
            default_value = "rbw",
            help = "Export format to produce (default: rbw's own)"
        )]
        format: crate::import_bitwarden::ExportFormat,

        #[arg(
            long,
            help = "Also download and embed decrypted attachment \
                contents (base64-encoded) in the export. This makes \
                the export considerably larger and slower to produce."
        )]
        attachments: bool,

        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "",
            value_name = "PASSPHRASE",
            help = "Symmetrically gpg-encrypt the export as a tar.gz \
                archive (rbw's own format). Optional with --format \
                bitwarden-encrypted-json (which prompts on its own \
                either way) to supply that format's password inline \
                instead. If PASSPHRASE is omitted, rbw reads it from \
                RBW_EXPORT_PASSPHRASE or prompts on the controlling tty \
                (twice, to confirm); passing it inline exposes it to `ps` \
                and shell history. rbw's own gpg format requires `gpg` \
                on PATH."
        )]
        encrypt: Option<String>,

        #[arg(
            short,
            long,
            value_name = "FILE",
            help = "Write the export to FILE instead of stdout. The file \
                is created with mode 0600."
        )]
        output: Option<std::path::PathBuf>,
        #[arg(
            long,
            value_name = "COLLECTION",
            help = "Only export entries in this collection (name or ID) \
                instead of the entire vault"
        )]
        collection: Option<String>,
        #[arg(
            long,
            value_name = "ORG",
            help = "Only export entries in this organization (name or ID); \
                combine with --collection to disambiguate a collection \
                name that exists in more than one org"
        )]
        org: Option<String>,
        #[arg(
            long,
            value_name = "FILE",
            help = "Read an rbw export file directly instead of a configured account"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted input export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(
        about = "Import data produced by `rbw export` or a Bitwarden vault \
            export",
        long_about = "Import data produced by `rbw export` or a Bitwarden \
            vault export\n\n\
            Reads an export file and recreates its entries and collections \
            in the target account's vault (see the global --account/-a \
            flag). Reads from stdin if no file is given.\n\n\
            --format selects how the file is parsed; it defaults to \
            auto-detecting between rbw's own export (JSON, or a \
            gpg-encrypted tar.gz produced by `rbw export --encrypt`) and \
            Bitwarden's own \"JSON\", \"Encrypted JSON\", and \"zip (with \
            attachments)\" export formats. Pass it explicitly if \
            auto-detection guesses wrong.\n\n\
            --decrypt/--decrypt-passphrase supplies the passphrase needed \
            for either an rbw gpg-encrypted archive or a Bitwarden \
            password-protected \"Encrypted JSON\" export: with --decrypt, \
            it's read from $RBW_EXPORT_PASSPHRASE if set, and prompted for \
            on the terminal otherwise; --decrypt-passphrase takes it \
            inline, but that exposes it to `ps` and shell history.\n\n\
            --collection redirects every imported entry into a single \
            existing collection, ignoring whatever \
            organization/collection/folder metadata the export carries; \
            --org disambiguates --collection's name when it exists in more \
            than one organization (it has no effect without \
            --collection).\n\n\
            Entries that already exist (matched by name, and username for \
            logins) are left untouched and reported as skipped; pass \
            --overwrite to update them in place instead. Entries belonging \
            to an organization this account isn't a member of are imported \
            into the personal vault instead (unless --collection is given)."
    )]
    Import {
        #[arg(help = "Export file to import (defaults to stdin if omitted)")]
        file: Option<std::path::PathBuf>,
        #[arg(
            long,
            alias = "type",
            value_enum,
            default_value = "auto",
            help = "Export format to expect (default: auto-detect)"
        )]
        format: crate::import_bitwarden::ImportFormat,
        #[arg(
            long,
            conflicts_with = "decrypt_passphrase",
            help = "Decrypt a passphrase-protected export (an rbw \
                gpg-encrypted archive, or a Bitwarden \"Encrypted JSON\" \
                export) using RBW_EXPORT_PASSPHRASE or a tty prompt"
        )]
        decrypt: bool,
        #[arg(
            long,
            value_name = "PASSPHRASE",
            help = "Passphrase to decrypt a passphrase-protected export \
                (produced by `rbw export --encrypt`, or Bitwarden's \
                \"Encrypted JSON\" export). Prefer --decrypt, which keeps \
                the passphrase out of `ps` and shell history"
        )]
        decrypt_passphrase: Option<String>,
        #[arg(
            long,
            value_name = "COLLECTION",
            help = "Import every entry into this existing collection \
                instead of whatever organization/collection/folder \
                metadata the export carries"
        )]
        collection: Option<String>,
        #[arg(
            long,
            value_name = "ORG",
            help = "Resolve --collection's name against only this \
                organization (name or ID), for when the same collection \
                name exists in more than one org"
        )]
        org: Option<String>,
        #[arg(
            long,
            help = "Overwrite entries that already exist (matched by \
                name/username) instead of skipping them"
        )]
        overwrite: bool,
    },

    #[command(
        about = "List all entries in the local Bitwarden database",
        visible_alias = "ls"
    )]
    List {
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder, type, collections. \
                Multiple fields will be separated by tabs.",
            default_value = "id,name,user",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[arg(help = "Optional search term to filter the listed entries")]
        term: Option<String>,
        #[arg(
            short = 'A',
            long,
            help = "Only show entries that have attachments"
        )]
        with_attachments: bool,
        #[arg(
            short,
            long,
            value_enum,
            help = "Output mode: name, json, yaml"
        )]
        output: Option<OutputArg>,
        #[arg(
            short = 'j',
            long,
            visible_alias = "json",
            help = "Display output as JSON"
        )]
        raw: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
        #[arg(
            long,
            help = "Include password column (shows sensitive data in plain text)"
        )]
        insecure: bool,
        #[arg(
            long,
            value_name = "COLLECTION",
            help = "Only list entries in this collection (name or ID)"
        )]
        collection: Option<String>,
        #[arg(
            long,
            value_name = "ORG",
            help = "Only list entries in this organization (name or ID); \
                combine with --collection to disambiguate a collection \
                name that exists in more than one org"
        )]
        org: Option<String>,
        #[arg(
            long,
            help = "Show only archived entries",
            conflicts_with = "include_archived"
        )]
        archived: bool,
        #[arg(
            long,
            help = "Include archived entries alongside normal ones (by \
                default, archived entries are hidden unless `--archived`/\
                `--include-archived` is given, or `hide_archived` is set to \
                false in config.yaml)"
        )]
        include_archived: bool,
        #[arg(
            long,
            alias = "deleted",
            help = "Show only trashed entries (i.e. removed via `rbw \
                remove`/`rbw delete`)",
            conflicts_with = "include_trashed"
        )]
        trashed: bool,
        #[arg(
            long,
            alias = "include-deleted",
            help = "Include trashed entries alongside normal ones (by \
                default, trashed entries are hidden unless `--trashed`/\
                `--include-trashed` is given, or `hide_trashed` is set to \
                false in config.yaml)"
        )]
        include_trashed: bool,
        #[arg(
            long,
            help = "With multiple accounts configured, unlock (prompting as \
                needed) and include every account instead of just the \
                already-unlocked ones",
            conflicts_with = "from_file"
        )]
        all: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "List a `rbw export` file directly instead of a \
                configured account -- no config/agent/account is touched. \
                Prompts for a passphrase if the file is gpg-encrypted \
                (`rbw export --encrypt`)."
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(about = "Get the primary value (password) of a given entry")]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(short, long, help = "Field to get")]
        field: Option<String>,
        #[arg(
            short,
            long,
            value_enum,
            help = "Output mode: name, json, yaml"
        )]
        output: Option<OutputArg>,
        #[arg(
            short = 'j',
            long,
            visible_alias = "json",
            help = "Display output as JSON"
        )]
        raw: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
        #[cfg(feature = "clipboard")]
        #[arg(short, long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[arg(short, long, help = "List fields in this entry")]
        list_fields: bool,
        #[arg(short = 'v', long, help = "Print matched item name to stderr")]
        verbose: bool,
        #[arg(
            long,
            help = "With multiple accounts configured, unlock (prompting as \
                needed) and search every account instead of just the \
                already-unlocked ones"
        )]
        all: bool,
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with = "all",
            help = "Read a `rbw export` file directly instead of a configured account"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(about = "Show all details of a given entry")]
    Show {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            short,
            long,
            value_enum,
            help = "Output mode: name, json, yaml"
        )]
        output: Option<OutputArg>,
        #[arg(
            short = 'j',
            long,
            visible_alias = "json",
            help = "Display output as JSON"
        )]
        raw: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
        #[arg(
            long,
            help = "With multiple accounts configured, unlock (prompting as \
                needed) and search every account instead of just the \
                already-unlocked ones"
        )]
        all: bool,
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with = "all",
            help = "Read a `rbw export` file directly instead of a configured account"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(about = "Search for entries")]
    Search {
        #[arg(help = "Search term to locate entries")]
        term: String,
        #[arg(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder, type, collections. \
                Multiple fields will be separated by tabs.",
            default_value = "id,name,user",
            use_value_delimiter = true
        )]
        fields: Vec<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(
            long,
            value_name = "COLLECTION",
            help = "Only search entries in this collection (name or ID)"
        )]
        collection: Option<String>,
        #[arg(
            long,
            value_name = "ORG",
            help = "Only search entries in this organization (name or ID); \
                combine with --collection to disambiguate a collection \
                name that exists in more than one org"
        )]
        org: Option<String>,
        #[arg(
            short = 'A',
            long,
            help = "Only show entries that have attachments"
        )]
        with_attachments: bool,
        #[arg(
            short,
            long,
            value_enum,
            help = "Output mode: name, json, yaml"
        )]
        output: Option<OutputArg>,
        #[arg(
            short = 'j',
            long,
            visible_alias = "json",
            help = "Display output as JSON"
        )]
        raw: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
        #[arg(
            long,
            help = "Include password column (shows sensitive data in plain text)"
        )]
        insecure: bool,
        #[arg(
            long,
            help = "Show only archived entries",
            conflicts_with = "include_archived"
        )]
        archived: bool,
        #[arg(
            long,
            help = "Include archived entries alongside normal ones (by \
                default, archived entries are hidden unless `--archived`/\
                `--include-archived` is given, or `hide_archived` is set to \
                false in config.yaml)"
        )]
        include_archived: bool,
        #[arg(
            long,
            alias = "deleted",
            help = "Show only trashed entries (i.e. removed via `rbw \
                remove`/`rbw delete`)",
            conflicts_with = "include_trashed"
        )]
        trashed: bool,
        #[arg(
            long,
            alias = "include-deleted",
            help = "Include trashed entries alongside normal ones (by \
                default, trashed entries are hidden unless `--trashed`/\
                `--include-trashed` is given, or `hide_trashed` is set to \
                false in config.yaml)"
        )]
        include_trashed: bool,
        #[arg(
            long,
            help = "With multiple accounts configured, unlock (prompting as \
                needed) and include every account instead of just the \
                already-unlocked ones",
            conflicts_with = "from_file"
        )]
        all: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Search a `rbw export` file directly instead of a \
                configured account -- no config/agent/account is touched. \
                Prompts for a passphrase if the file is gpg-encrypted \
                (`rbw export --encrypt`)."
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(about = "List or download file attachments")]
    Attachment {
        #[command(subcommand)]
        attachment: Attachment,
    },

    #[command(
        about = "Display the authenticator code for a given entry",
        visible_alias = "totp"
    )]
    Code {
        #[command(flatten)]
        find_args: FindArgs,
        #[cfg(feature = "clipboard")]
        #[arg(short, long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[arg(
            long,
            help = "With multiple accounts configured, unlock (prompting as \
                needed) and search every account instead of just the \
                already-unlocked ones"
        )]
        all: bool,
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with = "all",
            help = "Read a `rbw export` file directly instead of a configured account"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(about = "Inject secrets into a template")]
    Inject {
        #[arg(
            short = 'i',
            long = "in-file",
            help = "Read the template from a file"
        )]
        input: Option<std::path::PathBuf>,
        #[arg(
            short = 'o',
            long = "out-file",
            help = "Write the rendered template to a file"
        )]
        output: Option<std::path::PathBuf>,
    },

    #[command(about = "Run a command with injected values")]
    Run {
        #[arg(
            long,
            default_value = "./.env",
            help = "Read environment bindings from an env file"
        )]
        env_file: std::path::PathBuf,
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<OsString>,
    },

    #[command(
        about = "Add a new password to the database",
        long_about = "Add a new password to the database\n\n\
            This command will open a text editor to enter \
            the password and notes. The editor to use is determined \
            by the value of the $VISUAL or $EDITOR environment variables.
            The first line will be saved as the password and the \
            remainder will be saved as a note.",
        visible_alias = "create"
    )]
    Add {
        #[arg(help = "Name of the password entry")]
        name: Option<String>,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[arg(long, help = "Add via YAML editor (structured mode)")]
        yaml: bool,
        #[arg(long, help = "Add via JSON editor (structured mode)")]
        json: bool,
        #[arg(
            short = 'g',
            long = "generate",
            help = "Generate a password instead of entering one, using \
                the same flags as `rbw gen` (mutually exclusive with \
                piping an explicit entry via stdin)"
        )]
        generate: bool,
        #[command(flatten)]
        pwgen: PasswordGenArgs,
        #[arg(
            long,
            value_name = "FILE",
            help = "Add the entry directly to a `rbw export` file instead \
                of a configured account -- no config/agent/account is \
                touched. Prompts for a passphrase if the file is \
                gpg-encrypted (`rbw export --encrypt`)."
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(
        about = "Generate a new password",
        long_about = "Generate a new password\n\n\
            If given a password entry name, also save the generated \
            password to the database.",
        visible_alias = "gen"
    )]
    Generate {
        #[command(flatten)]
        pwgen: PasswordGenArgs,
        #[arg(help = "Name of the password entry")]
        name: Option<String>,
        #[arg(help = "Username for the password entry")]
        user: Option<String>,
        #[arg(
            long,
            help = "URI for the password entry",
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[arg(long, help = "Folder for the password entry")]
        folder: Option<String>,
    },

    #[command(
        about = "Modify an existing password",
        long_about = "Modify an existing password\n\n\
            This command will open a text editor with the existing \
            password and notes of the given entry for editing. \
            The editor to use is determined  by the value of the \
            $VISUAL or $EDITOR environment variables. The first line \
            will be saved as the password and the remainder will be saved \
            as a note."
    )]
    Edit {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(long, help = "Edit as YAML (structured mode)")]
        yaml: bool,
        #[arg(long, help = "Edit as JSON (structured mode)")]
        json: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Edit an entry directly in a `rbw export` file instead \
                of a configured account -- no config/agent/account is \
                touched. Prompts for a passphrase if the file is \
                gpg-encrypted (`rbw export --encrypt`)."
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(about = "Set specific fields of an existing entry")]
    Set {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(long, help = "New entry name")]
        name: Option<String>,
        #[arg(long, help = "New username (Login entries only)")]
        username: Option<String>,
        #[arg(long, help = "New password (Login entries only)")]
        password: Option<String>,
        #[arg(
            long,
            alias = "note",
            help = "New notes (empty string to clear)"
        )]
        notes: Option<String>,
        #[arg(
            long,
            number_of_values = 1,
            help = "Replace URIs (Login entries only; can be repeated)"
        )]
        uri: Vec<String>,
        #[arg(long, help = "New TOTP secret (Login entries only)")]
        totp: Option<String>,
        #[arg(long, help = "Show old \u{2192} new diff after updating")]
        diff: bool,
        #[arg(long, number_of_values = 1, help = "File(s) to attach")]
        attachment: Vec<std::path::PathBuf>,
        #[arg(
            long,
            help = "Treat each needle as an independent entry to update"
        )]
        bulk: bool,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Update an entry (or, with --bulk, every matching entry) \
                directly in a `rbw export` file instead of a configured \
                account -- no config/agent/account is touched. Prompts for \
                a passphrase if the file is gpg-encrypted (`rbw export \
                --encrypt`)."
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(
        about = "Remove a given entry",
        visible_aliases = ["rm", "delete", "del"]
    )]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            help = "Permanently delete the entry instead of moving it to \
                the trash -- this cannot be undone. Falls back to a \
                trashed entry if no live one matches, so this also \
                purges something already in the trash.",
            conflicts_with = "from_file"
        )]
        force: bool,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Remove an entry directly from a `rbw export` file \
                instead of a configured account -- no config/agent/account \
                is touched. Prompts for a passphrase if the file is \
                gpg-encrypted (`rbw export --encrypt`)."
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(
        about = "Archive a given entry (hidden from list/search by default)"
    )]
    Archive {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            help = "Treat each needle as matching every entry it finds, \
                archiving all of them"
        )]
        bulk: bool,
        #[arg(
            short = 'y',
            long,
            help = "Skip confirmation prompt (only asked with --bulk)"
        )]
        yes: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Read and update a `rbw export` file directly"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(about = "Unarchive a given entry")]
    Unarchive {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            help = "Treat each needle as matching every entry it finds, \
                unarchiving all of them"
        )]
        bulk: bool,
        #[arg(
            short = 'y',
            long,
            help = "Skip confirmation prompt (only asked with --bulk)"
        )]
        yes: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Read and update a `rbw export` file directly"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(
        about = "Restore a given entry out of the trash (undo `rbw remove`/`rbw delete`)"
    )]
    Restore {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            help = "Treat each needle as matching every entry it finds, \
                restoring all of them"
        )]
        bulk: bool,
        #[arg(
            short = 'y',
            long,
            help = "Skip confirmation prompt (only asked with --bulk)"
        )]
        yes: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Read and update a `rbw export` file directly"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(about = "Manage organization collections")]
    Collection {
        #[command(subcommand)]
        collection: Collection,
    },

    #[command(about = "Manage organizations")]
    Org {
        #[command(subcommand)]
        org: Org,
    },

    #[command(about = "View the password history for a given entry")]
    History {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            short,
            long,
            value_enum,
            help = "Output mode: name, json, yaml"
        )]
        output: Option<OutputArg>,
        #[arg(
            short = 'j',
            long,
            visible_alias = "json",
            help = "Display output as JSON"
        )]
        raw: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Read a `rbw export` file directly instead of a configured account"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },

    #[command(
        about = "Lock the password database",
        long_about = "Lock the password database\n\n\
            With an account selected (via --account or RBW_ACCOUNT), only \
            that account is locked; otherwise every account is locked."
    )]
    Lock {
        #[arg(
            long,
            help = "Lock every configured account, even when an account \
                is selected via --account/RBW_ACCOUNT"
        )]
        all: bool,
    },

    #[command(
        visible_alias = "panic",
        about = "Remove the local database and configured Termux unlock"
    )]
    Purge {
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
    },

    #[command(
        name = "purge-vault",
        about = "PERMANENTLY delete every entry in this account's vault",
        long_about = "PERMANENTLY delete every entry in this account's \
            personal vault via the server's own purge endpoint (a single \
            call, not a loop of individual deletes). This is not the \
            same as `rbw purge`, which only clears the local database \
            cache -- this command deletes the actual data on the server \
            and cannot be undone. Prompts for the master password (to \
            prove intent, mirroring `rbw login`/`rbw unlock`) and, unless \
            --yes is given, a confirmation; --stdin supplies the password \
            without a pinentry prompt, so `--yes --stdin` (with the \
            password piped in) purges fully non-interactively. Entries \
            assigned to an organization collection aren't touched; \
            purging those needs org owner/admin privileges."
    )]
    PurgeVault {
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
        #[arg(
            long,
            help = "Read the master password from stdin instead of \
                prompting via pinentry"
        )]
        stdin: bool,
    },

    #[command(
        about = "Copy vault contents from one configured account to another",
        long_about = "Copy vault contents from one configured account to \
            another\n\n\
            Reads every entry (and collection) from --from's vault and \
            recreates it in --to's vault, using the exact same conversion \
            and entry-creation machinery `rbw export`/`rbw import` use \
            internally -- no file ever touches disk. Both accounts must \
            already be configured (see `rbw account add`) and are unlocked \
            the same way any other command unlocks a named account.\n\n\
            Named `mirror` rather than `sync` to avoid colliding with the \
            pre-existing `rbw sync` (which means \"pull the latest vault \
            from the server for the active account\" and has nothing to do \
            with copying between accounts).\n\n\
            By default the entire source vault is copied; --collection or \
            --org-id scopes it to just one collection or organization \
            instead. --dest-collection redirects every copied entry into \
            one existing collection at the destination, ignoring whatever \
            organization/collection metadata the source carries -- the \
            same semantics as `rbw import --collection`. Entries that \
            already exist at the destination (matched by name, and \
            username for logins) are left untouched unless --overwrite is \
            given -- identical semantics to `rbw import`. --attachments \
            also downloads and re-uploads attachment contents (slower, and \
            considerably more data).\n\n\
            --purge-dest wipes the destination before copying. Combined \
            with --dest-collection, it only permanently deletes entries \
            currently assigned to that one destination collection (the \
            rest of the destination is untouched) -- otherwise it wipes \
            the destination's whole personal vault via the same server- \
            side purge endpoint `rbw purge-vault` uses. --purge-dest still \
            only supports a whole-vault mirror on the *source* side (no \
            --collection/--org-id); combining those is refused with an \
            explanatory error.\n\n\
            This is destructive-adjacent (can overwrite entries, and with \
            --purge-dest can wipe the destination entirely), so it prints \
            a preview and asks for confirmation unless -y/--yes is given. \
            --purge-dest without --dest-collection additionally needs the \
            destination's master password re-proved, exactly like `rbw \
            purge-vault` (`--stdin` supplies it non-interactively); plain \
            mirroring, and --purge-dest combined with --dest-collection, \
            need no fresh password beyond having both accounts unlocked.\n\n\
            --dry-run prints that same preview and stops there -- no \
            confirmation prompt, no destination account touched at all -- \
            for previewing what a mirror would do (including how many \
            entries it would find) without risking it."
    )]
    Mirror {
        #[arg(
            long,
            help = "Account to copy from (must already be configured)"
        )]
        from: String,
        #[arg(
            long,
            help = "Account to copy into (must already be configured)"
        )]
        to: String,
        #[arg(
            long,
            value_name = "COLLECTION",
            help = "Only copy entries in this collection (name or ID) \
                instead of the entire source vault"
        )]
        collection: Option<String>,
        #[arg(
            long = "org-id",
            value_name = "ID",
            help = "Only copy entries belonging to this organization \
                instead of the entire source vault"
        )]
        org_id: Option<String>,
        #[arg(
            long = "dest-collection",
            value_name = "COLLECTION",
            help = "Import every copied entry into this existing \
                collection at the destination, instead of whatever \
                organization/collection metadata the source carries"
        )]
        dest_collection: Option<String>,
        #[arg(
            long = "dest-org",
            value_name = "ORG",
            help = "Resolve --dest-collection's name against only this \
                destination organization (name or ID), for when the same \
                collection name exists in more than one destination org"
        )]
        dest_org: Option<String>,
        #[arg(
            long,
            help = "Also copy attachment contents (downloaded from the \
                source, re-uploaded to the destination)"
        )]
        attachments: bool,
        #[arg(
            long,
            help = "Overwrite entries that already exist at the \
                destination (matched by name/username) instead of \
                skipping them"
        )]
        overwrite: bool,
        #[arg(
            long,
            help = "Permanently wipe the destination before copying: the \
                whole personal vault, or just --dest-collection's entries \
                if given (refused together with source-side --collection/\
                --org-id)"
        )]
        purge_dest: bool,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
        #[arg(
            long,
            help = "Read the destination account's master password from \
                stdin instead of prompting via pinentry (only meaningful \
                with --purge-dest)"
        )]
        stdin: bool,
        #[arg(
            long,
            help = "Print the plan (accounts, scope, entry/collection \
                counts, flags) and exit without touching the destination \
                or prompting for confirmation"
        )]
        dry_run: bool,
    },

    #[command(name = "stop-agent", about = "Terminate the background agent")]
    StopAgent,

    #[command(
        name = "completions",
        about = "Generate completion script for the given shell"
    )]
    Completions {
        #[arg(help = "Shell to generate completions for")]
        shell: CompletionShell,
    },
}

impl Opt {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Config { config } => {
                format!("config {}", config.subcommand_name())
            }
            Self::Account { .. } => "account".to_string(),
            Self::Termux { .. } => "termux".to_string(),
            Self::Register { .. } => "register".to_string(),
            Self::Login { .. } => "login".to_string(),
            Self::Version => "version".to_string(),
            Self::Unlock { .. } => "unlock".to_string(),
            Self::Unlocked => "unlocked".to_string(),
            Self::Sync { .. } => "sync".to_string(),
            Self::Tui { .. } => "tui".to_string(),
            Self::Export { .. } => "export".to_string(),
            Self::ExportInfo { .. } => "export-info".to_string(),
            Self::Import { .. } => "import".to_string(),
            Self::List { .. } => "list".to_string(),
            Self::Get { .. } => "get".to_string(),
            Self::Show { .. } => "show".to_string(),
            Self::Search { .. } => "search".to_string(),
            Self::Attachment { attachment } => {
                format!("attachment {}", attachment.subcommand_name())
            }
            Self::Code { .. } => "code".to_string(),
            Self::Inject { .. } => "inject".to_string(),
            Self::Run { .. } => "run".to_string(),
            Self::Add { .. } => "add".to_string(),
            Self::Generate { .. } => "generate".to_string(),
            Self::Edit { .. } => "edit".to_string(),
            Self::Set { .. } => "set".to_string(),
            Self::Remove { .. } => "remove".to_string(),
            Self::Archive { .. } => "archive".to_string(),
            Self::Unarchive { .. } => "unarchive".to_string(),
            Self::Restore { .. } => "restore".to_string(),
            Self::Collection { collection } => {
                format!("collection {}", collection.subcommand_name())
            }
            Self::Org { org } => format!("org {}", org.subcommand_name()),
            Self::History { .. } => "history".to_string(),
            Self::Lock { .. } => "lock".to_string(),
            Self::Purge { .. } => "purge".to_string(),
            Self::PurgeVault { .. } => "purge-vault".to_string(),
            Self::Mirror { .. } => "mirror".to_string(),
            Self::StopAgent => "stop-agent".to_string(),
            Self::Completions { .. } => "completions".to_string(),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
    Nushell,
    Fig,
}

#[derive(Debug, clap::Parser)]
enum Config {
    #[command(about = "Show the values of all configuration settings")]
    Show,
    #[command(about = "Print the value of a single configuration setting")]
    Get {
        #[arg(help = "Configuration key to print")]
        key: String,
    },
    #[command(about = "Set a configuration option")]
    Set {
        #[arg(help = "Configuration key to set")]
        key: String,
        #[arg(help = "Value to set the configuration option to")]
        value: String,
    },
    #[command(about = "Reset a configuration option to its default")]
    Unset {
        #[arg(help = "Configuration key to unset")]
        key: String,
    },
    #[command(
        about = "Edit the full config.yaml in $EDITOR",
        long_about = "Edit the full config.yaml in $EDITOR\n\n\
            Opens the whole configuration (every account, all global \
            settings) as YAML in the editor named by the \
            $VISUAL or $EDITOR environment variables. Saved on exit if the \
            content changed and still parses as valid config."
    )]
    Edit,
}

#[derive(Debug, clap::Subcommand)]
enum TermuxCmd {
    #[command(
        about = "Generate an authentication-gated Android Keystore key"
    )]
    Generate {
        #[arg(
            help = "Android Keystore alias (defaults to RBW_TERMUX_KEY_ALIAS, config, or rbw-<account>)"
        )]
        key_alias: Option<String>,
        #[arg(
            long,
            default_value = "RSA",
            help = "Key algorithm: RSA or EC"
        )]
        algorithm: String,
        #[arg(long, help = "RSA size or EC curve size")]
        size: Option<u32>,
        #[arg(
            long,
            default_value_t = 300,
            help = "Seconds after device authentication during which signing is allowed"
        )]
        validity: u32,
    },
    #[command(
        about = "Set up native Android Keystore unlock for the active account",
        long_about = "Set up native Android Keystore unlock for the active \
            account. Prompts for the master password, generates an \
            authentication-gated key, creates the encrypted bundle, and \
            updates rbw's config.yaml automatically."
    )]
    Enroll {
        #[arg(
            long,
            default_value_t = 300,
            help = "Seconds after device authentication during which signing is allowed"
        )]
        validity: u32,
    },
    #[command(
        visible_alias = "unenroll",
        about = "Delete the active account's Termux key and unlock bundle"
    )]
    Remove {
        #[arg(short, long, help = "Do not ask for confirmation")]
        yes: bool,
    },
    #[command(about = "Show Android Keystore security properties")]
    Status {
        #[arg(help = "Only show this Android Keystore alias")]
        key_alias: Option<String>,
    },
}

#[derive(Debug, clap::Parser)]
enum AccountCmd {
    #[command(about = "List configured accounts", visible_alias = "ls")]
    List,
    #[command(about = "Add a new account")]
    Add {
        #[arg(help = "Name for the account (used with --account)")]
        name: String,
        #[arg(long, help = "Email address for the account")]
        email: Option<String>,
        #[arg(
            long,
            help = "Base URL of the server (omit for the public Bitwarden)"
        )]
        base_url: Option<String>,
        #[arg(long, help = "SSO identifier")]
        sso_id: Option<String>,
        #[arg(long, help = "Make this the primary account")]
        primary: bool,
    },
    #[command(
        about = "Remove an account",
        visible_aliases = ["rm", "delete", "del"]
    )]
    Remove {
        #[arg(help = "Name of the account to remove")]
        name: String,
    },
    #[command(about = "Set the primary account")]
    Primary {
        #[arg(help = "Name of the account to make primary")]
        name: String,
    },
    #[command(about = "Change settings for an existing account")]
    Set {
        #[arg(help = "Name of the account to modify")]
        name: String,
        #[arg(
            long,
            value_enum,
            help = "When `list`/`search`/`get` should proactively unlock \
                this account for a multi-account merge: always, never, or \
                on-demand (the default \u{2014} only if already unlocked, \
                or with --all)"
        )]
        unlock: Option<UnlockArg>,
        #[arg(
            long,
            value_enum,
            action = clap::ArgAction::Append,
            conflicts_with = "clear_exclude_from",
            help = "Skip this account for the given command(s) (repeatable), \
                even when unlocked or with --all: list, search, get, show, \
                code, sync, unlock, tui, or the magic value all. Still \
                reachable via --account. Replaces the existing list."
        )]
        exclude_from: Vec<ExcludeContextArg>,
        #[arg(
            long,
            help = "Clear this account's exclude-from list, including it \
                in every command's default merge behavior again"
        )]
        clear_exclude_from: bool,
        #[arg(
            long,
            help = "Name of another configured account whose vault holds \
                this account's master password; optionally combine with \
                --credential-source-item to name the Login item explicitly, \
                otherwise rbw will try to find a unique URI match"
        )]
        credential_source_account: Option<String>,
        #[arg(
            long,
            alias = "credential-source-entry",
            requires = "credential_source_account",
            help = "Name of the Login item, in the \
                --credential-source-account vault, whose password field \
                holds this account's master password"
        )]
        credential_source_item: Option<String>,
        #[arg(
            long,
            conflicts_with_all = [
                "credential_source_account",
                "credential_source_item"
            ],
            help = "Remove this account's credential_source, going back to \
                a normal pinentry prompt to unlock it"
        )]
        clear_credential_source: bool,
    },
}

#[derive(Debug, clap::Parser)]
enum Attachment {
    #[command(about = "List attachments for an entry", visible_alias = "ls")]
    List {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            short,
            long,
            value_enum,
            help = "Output mode: name, json, yaml"
        )]
        output: Option<OutputArg>,
        #[arg(
            short = 'j',
            long,
            visible_alias = "json",
            help = "Display output as JSON"
        )]
        raw: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Read a `rbw export` file directly instead of a configured account"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },
    #[command(
        about = "Download and decrypt an attachment by id or filename"
    )]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            help = "Attachment ID or filename (see `rbw attachment list \
                <entry>`); omit to download the entry's only attachment"
        )]
        attachment: Option<String>,
        #[arg(
            short,
            long,
            help = "Output file or directory ('-' writes to stdout)"
        )]
        output: Option<std::path::PathBuf>,
        #[arg(
            long,
            conflicts_with = "output",
            help = "Write attachment content to stdout"
        )]
        raw: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Read a `rbw export` file directly instead of a configured account"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },
    #[command(
        about = "Upload a file as an attachment",
        visible_alias = "add"
    )]
    // Can't flatten `FindArgs` here: clap requires every positional argument
    // before a required positional (`file`) to be required itself, and
    // `FindArgs`' needles are optional. Keep the same args (and help text)
    // spelled out instead, with `required = true` on the needles.
    Create {
        #[arg(
            help = "Name, URI, UUID (or multiple terms, all required to match)",
            value_parser = commands::parse_needle,
            num_args = 1..,
            required = true,
        )]
        needles: Vec<commands::Needle>,
        #[arg(help = "File to attach")]
        file: std::path::PathBuf,
        #[arg(long, help = "Username of the entry to display")]
        user: Option<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(short, long, help = "Ignore case")]
        ignorecase: bool,
        #[arg(
            short = 'e',
            long,
            help = "Only match if needle is an exact entry name (no substring fallback)"
        )]
        exact: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Read and update a `rbw export` file directly"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },
    #[command(
        about = "Delete an attachment from an entry",
        visible_aliases = ["remove", "delete"]
    )]
    Rm {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(
            long,
            help = "Attachment ID or filename (see `rbw attachment list \
                <entry>`); omit to delete the entry's only attachment"
        )]
        attachment: Option<String>,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Read and update a `rbw export` file directly"
        )]
        from_file: Option<std::path::PathBuf>,
        #[arg(
            long = "passphrase",
            alias = "from-file-passphrase",
            value_name = "PASSPHRASE",
            requires = "from_file",
            help = "Passphrase for an encrypted --from-file export; alternatively set $RBW_EXPORT_PASSPHRASE"
        )]
        from_file_passphrase: Option<String>,
    },
}

impl Attachment {
    fn subcommand_name(&self) -> String {
        match self {
            Self::List { .. } => "list",
            Self::Get { .. } => "get",
            Self::Create { .. } => "create",
            Self::Rm { .. } => "rm",
        }
        .to_string()
    }
}

#[derive(Debug, clap::Parser)]
enum Collection {
    #[command(
        about = "List all collections in the organization",
        visible_alias = "ls"
    )]
    List {
        #[arg(
            short,
            long,
            value_enum,
            help = "Output mode: name, json, yaml"
        )]
        output: Option<OutputArg>,
        #[arg(
            short = 'j',
            long,
            visible_alias = "json",
            help = "Display output as JSON"
        )]
        raw: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
    },
    #[command(
        about = "Create a new collection in an organization",
        visible_alias = "add"
    )]
    Create {
        #[arg(help = "Name of the collection")]
        name: String,
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
    },
    #[command(
        about = "Delete an organization collection",
        visible_aliases = ["rm", "remove", "del"]
    )]
    Delete {
        #[arg(help = "Name or ID of the collection")]
        collection: String,
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
    },
    #[command(
        about = "PERMANENTLY delete every entry in a collection",
        long_about = "PERMANENTLY delete every entry in a collection\n\n\
            The collection itself (and everything outside it) is left \
            untouched -- only its member entries are permanently deleted, \
            via the same per-cipher delete `rbw remove --force` uses (not \
            a soft/trash-recoverable delete). This cannot be undone.\n\n\
            Prompts for confirmation unless -y/--yes is given, matching \
            `rbw purge-vault`/`rbw collection delete`'s gating convention."
    )]
    Purge {
        #[arg(help = "Name or ID of the collection")]
        collection: String,
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
    },
    #[command(about = "Rename an organization collection")]
    Rename {
        #[arg(help = "Name or ID of the collection")]
        collection: String,
        #[arg(help = "New name for the collection")]
        name: String,
        #[arg(
            long = "org-id",
            alias = "organizationid",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
    },
    #[command(
        about = "Assign an entry to organization collections",
        long_about = "Assign an entry to organization collections\n\n\
            Replaces the matched entry's (or, with --bulk, entries') \
            current collection list with the given --collection values. \
            Collections can be given by name or ID; names are resolved \
            against each entry's own organization. Without --bulk, \
            exactly one needle must resolve to exactly one entry (all \
            given needles must jointly match it, same as elsewhere); \
            with --bulk, every needle is matched independently \
            (`archive --bulk`'s convention), previewed, and confirmed \
            once unless -y is given. Use --personal instead of \
            --collection to move the entry out of the organization \
            entirely and back into your personal vault (entries with \
            attachments aren't supported yet); see `rbw collection \
            unassign` to remove specific collections without leaving the \
            organization."
    )]
    Assign {
        #[arg(
            help = "Name, URI, or UUID of the entry (or entries, with --bulk)",
            value_parser = commands::parse_needle,
            required = true,
        )]
        needles: Vec<commands::Needle>,
        #[arg(
            long = "collection",
            value_name = "COLLECTION",
            help = "A collection (name or ID) the entry should belong to \
                -- repeat for multiple",
            conflicts_with = "personal"
        )]
        collections: Vec<String>,
        #[arg(
            long,
            help = "Move the entry out of its organization and back into \
                your personal vault, instead of assigning collections"
        )]
        personal: bool,
        #[arg(long, help = "Username of the entry to display")]
        user: Option<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(short, long, help = "Ignore case")]
        ignorecase: bool,
        #[arg(
            short = 'e',
            long,
            help = "Only match if needle is an exact entry name (no substring fallback)"
        )]
        exact: bool,
        #[arg(
            long,
            help = "Treat each needle as an independent entry to assign"
        )]
        bulk: bool,
        #[arg(
            short = 'y',
            long,
            help = "Skip confirmation prompt (only asked with --bulk)"
        )]
        yes: bool,
    },
    #[command(
        about = "Remove an entry from organization collections",
        long_about = "Remove an entry from organization collections\n\n\
            The complement to `assign`: removes the given --collection \
            values from the matched entry's (or, with --bulk, entries') \
            current collection list, leaving any other collections it \
            belongs to untouched and the entry itself still owned by the \
            organization. With no --collection given at all, removes \
            every collection the entry currently belongs to. To move the \
            entry out of the organization entirely, use `rbw collection \
            assign --personal` instead. Same --bulk/preview/confirm \
            convention as `assign`."
    )]
    Unassign {
        #[arg(
            help = "Name, URI, or UUID of the entry (or entries, with --bulk)",
            value_parser = commands::parse_needle,
            required = true,
        )]
        needles: Vec<commands::Needle>,
        #[arg(
            long = "collection",
            value_name = "COLLECTION",
            help = "A collection (name or ID) to remove the entry from \
                -- repeat for multiple; omit to remove from all"
        )]
        collections: Vec<String>,
        #[arg(long, help = "Username of the entry to display")]
        user: Option<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(short, long, help = "Ignore case")]
        ignorecase: bool,
        #[arg(
            short = 'e',
            long,
            help = "Only match if needle is an exact entry name (no substring fallback)"
        )]
        exact: bool,
        #[arg(
            long,
            help = "Treat each needle as an independent entry to unassign"
        )]
        bulk: bool,
        #[arg(
            short = 'y',
            long,
            help = "Skip confirmation prompt (only asked with --bulk)"
        )]
        yes: bool,
    },
    #[command(
        about = "Grant a member access to a collection directly",
        long_about = "Grant a member access to a collection directly\n\n\
            The generic primitive underneath `propagate-permissions`, \
            without that command's hierarchy-inference policy (topmost \
            held -> edit, descendants -> manage) -- use this if you just \
            want to set one permission on one (collection, member) pair. \
            Replaces that member's existing permissions on this \
            collection entirely; omit all three flags for read/write \
            access with no restrictions."
    )]
    Grant {
        #[arg(help = "Name or ID of the collection")]
        collection: String,
        #[arg(help = "Email or user ID of the member")]
        user: String,
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
        #[arg(long, help = "Grant read-only access")]
        read_only: bool,
        #[arg(long, help = "Hide passwords from this member")]
        hide_passwords: bool,
        #[arg(
            long,
            help = "Grant manage access (edit/delete the collection itself)"
        )]
        manage: bool,
    },
    #[command(
        name = "propagate-permissions",
        about = "Grant members access to nested collections (topmost held -> edit, descendants -> manage)"
    )]
    PropagatePermissions {
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a single org)"
        )]
        org_id: Option<String>,
        #[arg(long, help = "Execute the changes (default is a dry-run)")]
        apply: bool,
        #[arg(short, long, help = "Print per-run counts")]
        verbose: bool,
    },
}

impl Collection {
    fn subcommand_name(&self) -> String {
        match self {
            Self::List { .. } => "list",
            Self::Create { .. } => "create",
            Self::Delete { .. } => "delete",
            Self::Purge { .. } => "purge",
            Self::Rename { .. } => "rename",
            Self::Assign { .. } => "assign",
            Self::Unassign { .. } => "unassign",
            Self::Grant { .. } => "grant",
            Self::PropagatePermissions { .. } => "propagate-permissions",
        }
        .to_string()
    }
}

#[derive(Debug, clap::Parser)]
enum Org {
    #[command(
        about = "List all organizations this account is a member of",
        visible_alias = "ls"
    )]
    List {
        #[arg(
            short,
            long,
            value_enum,
            help = "Output mode: name, json, yaml"
        )]
        output: Option<OutputArg>,
        #[arg(
            short = 'j',
            long,
            visible_alias = "json",
            help = "Display output as JSON"
        )]
        raw: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
    },

    #[command(
        about = "Create a new organization owned by the current account"
    )]
    Create {
        #[arg(help = "Name of the organization")]
        name: String,
    },

    #[command(
        about = "Accept an organization invite",
        long_about = "Accept an organization invite\n\n\
            Called by the invitee, using either the whole invite link \
            (--url, easiest -- pasted straight from the invite email) or \
            the organization id/member id/token from it individually \
            (not looked up automatically -- an invited-but-not-yet-\
            accepted account has no other way to know any of that). Does \
            not make the org usable by itself; the inviter still needs \
            to `rbw org confirm` afterward."
    )]
    Accept {
        #[arg(
            long,
            help = "The full invite link/URL (from the invite email), \
                e.g. \
                'https://vault.example.com/#/accept-organization/?organizationId=...&organizationUserId=...&token=...'. \
                Overrides --org-id/--user-id/--token if given."
        )]
        url: Option<String>,
        #[arg(
            long = "org-id",
            required_unless_present = "url",
            help = "Organization id (`organizationId` in the invite link)"
        )]
        org_id: Option<String>,
        #[arg(
            long = "user-id",
            required_unless_present = "url",
            help = "This account's member id in the org \
                (`organizationUserId` in the invite link)"
        )]
        user_id: Option<String>,
        #[arg(
            long,
            required_unless_present = "url",
            help = "Invite token (`token` in the invite link)"
        )]
        token: Option<String>,
    },

    #[command(about = "Invite a user into an organization by email")]
    Invite {
        #[arg(help = "Email address to invite")]
        email: String,
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
        #[arg(
            long,
            default_value = "user",
            help = "Role to invite as: owner, admin, user, or manager"
        )]
        role: String,
    },

    #[command(
        about = "Remove a user from an organization",
        visible_aliases = ["rm", "remove", "del"]
    )]
    RemoveUser {
        #[arg(help = "Email or user ID of the member to remove")]
        user: String,
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
    },

    #[command(
        about = "PERMANENTLY delete an organization and everything in it",
        long_about = "PERMANENTLY delete an organization and everything \
            in it\n\n\
            Prompts for the master password (to prove intent, like `rbw \
            purge-vault`) and, unless --yes is given, a confirmation. \
            This cannot be undone."
    )]
    Delete {
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
        #[arg(
            long,
            help = "Read the master password from stdin instead of \
                prompting via pinentry"
        )]
        stdin: bool,
    },

    #[command(
        about = "Confirm a member who has accepted their invite",
        long_about = "Confirm a member who has accepted their invite\n\n\
            Required before a newly invited member can decrypt anything \
            in the org: this re-encrypts the org's key to their \
            now-known public key, which only happens once they've \
            accepted (`rbw org invite` alone isn't enough)."
    )]
    Confirm {
        #[arg(help = "Email or user ID of the member to confirm")]
        user: String,
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
    },

    #[command(
        about = "Rename an organization",
        long_about = "Rename an organization\n\n\
            Organization names are plaintext (unlike collection names), \
            so this is a simple metadata update -- no re-encryption \
            involved. The server also requires a billing email on every \
            update; this always sends the active account's own email, \
            since there's nowhere to read the org's current billing \
            email back from locally."
    )]
    Rename {
        #[arg(help = "New name for the organization")]
        name: String,
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
    },
}

impl Org {
    fn subcommand_name(&self) -> String {
        match self {
            Self::List { .. } => "list",
            Self::Create { .. } => "create",
            Self::Accept { .. } => "accept",
            Self::Invite { .. } => "invite",
            Self::RemoveUser { .. } => "remove-user",
            Self::Delete { .. } => "delete",
            Self::Confirm { .. } => "confirm",
            Self::Rename { .. } => "rename",
        }
        .to_string()
    }
}

impl Config {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Show => "show",
            Self::Get { .. } => "get",
            Self::Set { .. } => "set",
            Self::Unset { .. } => "unset",
            Self::Edit => "edit",
        }
        .to_string()
    }
}

// Shared by `login --stdin`, `unlock --stdin`, and (twice, for client_id then
// client_secret) `register --stdin`.
fn read_stdin_password() -> String {
    let mut buf = String::new();
    let _ = std::io::stdin()
        .read_line(&mut buf)
        .context("failed to read password from stdin");
    buf.trim_end_matches('\n').to_string()
}

fn main() {
    let cli = Cli::parse();
    let opt = cli.command;

    // Resolve the target account: --account, else $RBW_ACCOUNT, else the
    // primary account (None). This is threaded into every request sent to the
    // agent and used to point any direct lib api calls at the right server.
    let account = cli.account.or_else(|| {
        std::env::var("RBW_ACCOUNT").ok().filter(|s| !s.is_empty())
    });
    actions::set_account(account.clone());
    // If the config can't be loaded here, downstream commands surface a clearer
    // error; there is nothing to point the api client at in that case.
    if let (Some(name), Ok(config)) = (&account, rbw::config::Config::load())
    {
        match config.account(Some(name)) {
            Ok(account) => rbw::actions::set_client_account(account),
            Err(e) => {
                eprintln!(
                    "{}",
                    commands::style_error(
                        &format!("{e:#}"),
                        std::io::stderr().is_terminal()
                            && std::env::var_os("NO_COLOR").is_none()
                    )
                );
                std::process::exit(1);
            }
        }
    }

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format(|buf, record| {
        if let Some((terminal_size::Width(w), _)) =
            terminal_size::terminal_size()
        {
            let out = format!("{}: {}", record.level(), record.args());
            writeln!(buf, "{}", textwrap::fill(&out, usize::from(w) - 1))
        } else {
            writeln!(buf, "{}: {}", record.level(), record.args())
        }
    })
    .init();

    let subcommand_name = opt.subcommand_name();
    let res = match opt {
        Opt::Config { config } => match config {
            Config::Show => commands::config_show(),
            Config::Get { key } => commands::config_get(&key),
            Config::Set { key, value } => commands::config_set(&key, &value),
            Config::Unset { key } => commands::config_unset(&key),
            Config::Edit => commands::config_edit(),
        },
        Opt::Account { account } => match account {
            AccountCmd::List => {
                commands::account_list();
                Ok(())
            }
            AccountCmd::Add {
                name,
                email,
                base_url,
                sso_id,
                primary,
            } => {
                commands::account_add(&name, email, base_url, sso_id, primary)
            }
            AccountCmd::Remove { name } => commands::account_remove(&name),
            AccountCmd::Primary { name } => {
                commands::account_set_primary(&name)
            }
            AccountCmd::Set {
                name,
                unlock,
                exclude_from,
                clear_exclude_from,
                credential_source_account,
                credential_source_item,
                clear_credential_source,
            } => commands::account_set(
                &name,
                unlock.map(std::convert::Into::into),
                exclude_from.into_iter().map(Into::into).collect(),
                clear_exclude_from,
                credential_source_account,
                credential_source_item,
                clear_credential_source,
            ),
        },
        Opt::Termux { termux } => match termux {
            TermuxCmd::Generate {
                key_alias,
                algorithm,
                size,
                validity,
            } => (|| -> anyhow::Result<()> {
                let config = rbw::config::Config::load()?;
                let account_name = crate::actions::current_account()
                    .unwrap_or_else(|| config.primary_account_name());
                let key_alias = key_alias.unwrap_or_else(|| {
                    rbw::termux::resolve_key_alias(
                        &config,
                        &account_name,
                        None,
                    )
                });
                rbw::termux::generate(&key_alias, &algorithm, size, validity)
            })(),
            TermuxCmd::Enroll { validity } => {
                commands::termux_enroll(validity)
            }
            TermuxCmd::Remove { yes } => commands::termux_remove(yes),
            TermuxCmd::Status { key_alias } => {
                rbw::termux::status(key_alias.as_deref())
            }
        },
        Opt::Register { stdin } => {
            let (client_id, client_secret) = if stdin {
                (Some(read_stdin_password()), Some(read_stdin_password()))
            } else {
                (None, None)
            };
            commands::register(client_id, client_secret)
        }
        Opt::Login { stdin, totp } => {
            let password = stdin.then(read_stdin_password);
            commands::login(password, totp)
        }
        Opt::Version => {
            println!("rbw {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Opt::Unlock { stdin, totp, all } => {
            if all {
                commands::unlock_all()
            } else {
                let password = stdin.then(read_stdin_password);
                commands::unlock(password, totp)
            }
        }
        Opt::Unlocked => commands::unlocked(),
        Opt::Sync { all } => commands::sync(all),
        Opt::Tui {
            term,
            all,
            from_file,
            write,
            from_file_passphrase,
            screen_lock_timeout,
        } => tui::run(
            term.as_deref(),
            all,
            from_file.as_deref(),
            write,
            from_file_passphrase.as_deref(),
            screen_lock_timeout,
        ),
        Opt::Export {
            format,
            attachments,
            encrypt,
            output,
            collection,
            org,
            from_file,
            from_file_passphrase,
        } => commands::export(
            format,
            attachments,
            encrypt.as_deref(),
            output.as_deref(),
            collection.as_deref(),
            org.as_deref(),
            from_file.as_deref(),
            from_file_passphrase.as_deref(),
        ),
        Opt::ExportInfo {
            file,
            format,
            decrypt,
            decrypt_passphrase,
            json,
        } => export_info::run(
            file.as_deref(),
            format,
            decrypt,
            decrypt_passphrase.as_deref(),
            json,
        ),
        Opt::Import {
            file,
            format,
            decrypt,
            decrypt_passphrase,
            collection,
            org,
            overwrite,
        } => commands::import(
            file.as_deref(),
            format,
            decrypt,
            decrypt_passphrase.as_deref(),
            collection.as_deref(),
            org.as_deref(),
            overwrite,
        ),
        Opt::List {
            fields,
            term,
            with_attachments,
            output,
            raw,
            yaml,
            insecure,
            collection,
            org,
            archived,
            include_archived,
            trashed,
            include_trashed,
            all,
            from_file,
            from_file_passphrase,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw, yaml)?;
            let archived_filter =
                resolve_archived_filter(archived, include_archived);
            let trash_filter = resolve_trash_filter(trashed, include_trashed);
            term.map_or_else(
                || {
                    commands::list(
                        &fields,
                        with_attachments,
                        insecure,
                        collection.as_deref(),
                        org.as_deref(),
                        output,
                        all,
                        archived_filter,
                        trash_filter,
                        from_file.as_deref(),
                        from_file_passphrase.as_deref(),
                    )
                },
                |term| {
                    commands::search(
                        &term,
                        &fields,
                        None,
                        collection.as_deref(),
                        org.as_deref(),
                        with_attachments,
                        insecure,
                        output,
                        all,
                        archived_filter,
                        trash_filter,
                        from_file.as_deref(),
                        from_file_passphrase.as_deref(),
                    )
                },
            )
        })(),
        Opt::Attachment { attachment } => match attachment {
            Attachment::List {
                find_args,
                output,
                raw,
                yaml,
                from_file,
                from_file_passphrase,
            } => (|| -> anyhow::Result<()> {
                let output = resolve_output_mode(output, raw, yaml)?;
                commands::attachment_list(
                    find_args.needles,
                    find_args.user.as_deref(),
                    find_args.folder.as_deref(),
                    find_args.collection.as_deref(),
                    find_args.org.as_deref(),
                    find_args.ignorecase,
                    output,
                    find_args.exact,
                    from_file.as_deref(),
                    from_file_passphrase.as_deref(),
                )
            })(),
            Attachment::Get {
                find_args,
                attachment,
                output,
                raw,
                from_file,
                from_file_passphrase,
            } => commands::attachment_get(
                find_args.needles,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.collection.as_deref(),
                find_args.org.as_deref(),
                find_args.ignorecase,
                attachment.as_deref(),
                output.as_deref(),
                raw,
                find_args.exact,
                from_file.as_deref(),
                from_file_passphrase.as_deref(),
            ),
            Attachment::Create {
                needles,
                file,
                user,
                folder,
                ignorecase,
                exact,
                from_file,
                from_file_passphrase,
            } => commands::attachment_create(
                needles,
                user.as_deref(),
                folder.as_deref(),
                ignorecase,
                &file,
                exact,
                from_file.as_deref(),
                from_file_passphrase.as_deref(),
            ),
            Attachment::Rm {
                find_args,
                attachment,
                yes,
                from_file,
                from_file_passphrase,
            } => commands::attachment_rm(
                find_args.needles,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.collection.as_deref(),
                find_args.org.as_deref(),
                find_args.ignorecase,
                attachment.as_deref(),
                find_args.exact,
                yes,
                from_file.as_deref(),
                from_file_passphrase.as_deref(),
            ),
        },
        Opt::Get {
            find_args,
            field,
            output,
            raw,
            yaml,
            #[cfg(feature = "clipboard")]
            clipboard,
            list_fields,
            verbose,
            all,
            from_file,
            from_file_passphrase,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw, yaml)?;
            commands::get(
                find_args.needles.clone(),
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.collection.as_deref(),
                find_args.org.as_deref(),
                field.as_deref(),
                output,
                #[cfg(feature = "clipboard")]
                clipboard,
                #[cfg(not(feature = "clipboard"))]
                false,
                find_args.ignorecase,
                list_fields,
                verbose,
                find_args.exact,
                all,
                from_file.as_deref(),
                from_file_passphrase.as_deref(),
            )
        })(),
        Opt::Show {
            find_args,
            output,
            raw,
            yaml,
            all,
            from_file,
            from_file_passphrase,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw, yaml)?;
            commands::show(
                find_args.needles,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.collection.as_deref(),
                find_args.org.as_deref(),
                find_args.ignorecase,
                output,
                find_args.exact,
                all,
                from_file.as_deref(),
                from_file_passphrase.as_deref(),
            )
        })(),
        Opt::Search {
            term,
            fields,
            folder,
            collection,
            org,
            with_attachments,
            output,
            raw,
            yaml,
            insecure,
            archived,
            include_archived,
            trashed,
            include_trashed,
            all,
            from_file,
            from_file_passphrase,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw, yaml)?;
            let archived_filter =
                resolve_archived_filter(archived, include_archived);
            let trash_filter = resolve_trash_filter(trashed, include_trashed);
            commands::search(
                &term,
                &fields,
                folder.as_deref(),
                collection.as_deref(),
                org.as_deref(),
                with_attachments,
                insecure,
                output,
                all,
                archived_filter,
                trash_filter,
                from_file.as_deref(),
                from_file_passphrase.as_deref(),
            )
        })(),
        Opt::Code {
            find_args,
            #[cfg(feature = "clipboard")]
            clipboard,
            all,
            from_file,
            from_file_passphrase,
        } => commands::code(
            find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.collection.as_deref(),
            find_args.org.as_deref(),
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
            find_args.exact,
            all,
            from_file.as_deref(),
            from_file_passphrase.as_deref(),
        ),
        Opt::Inject { input, output } => {
            commands::inject(input.as_deref(), output.as_deref())
        }
        Opt::Run { env_file, command } => commands::run(&env_file, &command)
            .map(|status| {
                if !status.success() {
                    #[cfg(unix)]
                    if let Some(signal) = status.signal() {
                        std::process::exit(128 + signal);
                    }
                    std::process::exit(status.code().unwrap_or(1));
                }
            }),
        Opt::Add {
            name,
            user,
            uri,
            folder,
            json,
            yaml,
            generate,
            pwgen,
            from_file,
            from_file_passphrase,
        } => {
            // Password-gen flags imply --generate, so `rbw create name -g
            // -l 24` and `rbw create name -l 24` both work as expected.
            let generate = generate
                || pwgen.length.is_some()
                || pwgen.no_symbols
                || pwgen.only_numbers
                || pwgen.nonconfusables
                || pwgen.diceware;
            let (len, ty) = resolve_pwgen(&pwgen);
            commands::add(
                name.as_deref(),
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                json,
                yaml,
                generate,
                len,
                ty,
                from_file.as_deref(),
                from_file_passphrase.as_deref(),
            )
        }
        Opt::Generate {
            pwgen,
            name,
            user,
            uri,
            folder,
        } => {
            // upstream rbw muscle memory: `rbw gen 24` parses `24` as the
            // entry name, not the length
            if let Some(name) = &name {
                if pwgen.length.is_none()
                    && !name.is_empty()
                    && name.bytes().all(|b| b.is_ascii_digit())
                {
                    eprintln!(
                        "note: creating an entry named \"{name}\"; if you \
                        meant a {name}-character password, use rbw gen -l \
                        {name}"
                    );
                }
            }
            let (len, ty) = resolve_pwgen(&pwgen);
            commands::generate(
                name.as_deref(),
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                len,
                ty,
            )
        }
        Opt::Edit {
            find_args,
            json,
            yaml,
            from_file,
            from_file_passphrase,
        } => commands::edit(
            find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.collection.as_deref(),
            find_args.org.as_deref(),
            find_args.ignorecase,
            json,
            yaml,
            find_args.exact,
            from_file.as_deref(),
            from_file_passphrase.as_deref(),
        ),
        Opt::Set {
            find_args,
            name,
            username,
            password,
            notes,
            uri,
            totp,
            diff,
            attachment,
            bulk,
            yes,
            from_file,
            from_file_passphrase,
        } => commands::set(
            find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.collection.as_deref(),
            find_args.org.as_deref(),
            find_args.ignorecase,
            name.as_deref(),
            username.as_deref(),
            password.as_deref(),
            notes.as_deref(),
            &uri,
            totp.as_deref(),
            diff,
            &attachment,
            bulk,
            yes,
            find_args.exact,
            from_file.as_deref(),
            from_file_passphrase.as_deref(),
        ),
        Opt::Remove {
            find_args,
            force,
            yes,
            from_file,
            from_file_passphrase,
        } => commands::remove(
            find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.collection.as_deref(),
            find_args.org.as_deref(),
            find_args.ignorecase,
            find_args.exact,
            force,
            yes,
            from_file.as_deref(),
            from_file_passphrase.as_deref(),
        ),
        Opt::Archive {
            find_args,
            bulk,
            yes,
            from_file,
            from_file_passphrase,
        } => commands::archive(
            find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.collection.as_deref(),
            find_args.org.as_deref(),
            find_args.ignorecase,
            find_args.exact,
            bulk,
            yes,
            from_file.as_deref(),
            from_file_passphrase.as_deref(),
        ),
        Opt::Unarchive {
            find_args,
            bulk,
            yes,
            from_file,
            from_file_passphrase,
        } => commands::unarchive(
            find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.collection.as_deref(),
            find_args.org.as_deref(),
            find_args.ignorecase,
            find_args.exact,
            bulk,
            yes,
            from_file.as_deref(),
            from_file_passphrase.as_deref(),
        ),
        Opt::Restore {
            find_args,
            bulk,
            yes,
            from_file,
            from_file_passphrase,
        } => commands::restore(
            &find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.collection.as_deref(),
            find_args.org.as_deref(),
            find_args.ignorecase,
            find_args.exact,
            bulk,
            yes,
            from_file.as_deref(),
            from_file_passphrase.as_deref(),
        ),
        Opt::Collection { collection } => match collection {
            Collection::List { output, raw, yaml } => {
                (|| -> anyhow::Result<()> {
                    let output = resolve_output_mode(output, raw, yaml)?;
                    commands::list_collections(output)
                })()
            }
            Collection::Create { name, org_id } => {
                commands::create_collection(&name, org_id.as_deref())
            }
            Collection::Delete {
                collection,
                org_id,
                yes,
            } => commands::delete_collection(
                &collection,
                org_id.as_deref(),
                yes,
            ),
            Collection::Purge {
                collection,
                org_id,
                yes,
            } => commands::purge_collection(
                &collection,
                org_id.as_deref(),
                yes,
            ),
            Collection::Rename {
                collection,
                name,
                org_id,
            } => commands::rename_collection(
                &collection,
                org_id.as_deref(),
                &name,
            ),
            Collection::Assign {
                needles,
                collections,
                personal,
                user,
                folder,
                ignorecase,
                exact,
                bulk,
                yes,
            } => commands::assign_collections(
                needles,
                user.as_deref(),
                folder.as_deref(),
                ignorecase,
                exact,
                &collections,
                personal,
                bulk,
                yes,
            ),
            Collection::Unassign {
                needles,
                collections,
                user,
                folder,
                ignorecase,
                exact,
                bulk,
                yes,
            } => commands::unassign_collections(
                needles,
                user.as_deref(),
                folder.as_deref(),
                ignorecase,
                exact,
                &collections,
                bulk,
                yes,
            ),
            Collection::Grant {
                collection,
                user,
                org_id,
                read_only,
                hide_passwords,
                manage,
            } => commands::grant_collection_access(
                &collection,
                &user,
                org_id.as_deref(),
                read_only,
                hide_passwords,
                manage,
            ),
            Collection::PropagatePermissions {
                org_id,
                apply,
                verbose,
            } => commands::propagate_collection_permissions(
                org_id.as_deref(),
                apply,
                verbose,
            ),
        },
        Opt::Org { org } => match org {
            Org::List { output, raw, yaml } => (|| -> anyhow::Result<()> {
                let output = resolve_output_mode(output, raw, yaml)?;
                commands::list_organizations(output)
            })(),
            Org::Create { name } => commands::create_org(&name),
            Org::Accept {
                url,
                org_id,
                user_id,
                token,
            } => commands::accept_org_invite(
                url.as_deref(),
                org_id.as_deref(),
                user_id.as_deref(),
                token.as_deref(),
            ),
            Org::Invite {
                email,
                org_id,
                role,
            } => commands::invite_org_user(org_id.as_deref(), &email, &role),
            Org::RemoveUser { user, org_id, yes } => {
                commands::remove_org_user(org_id.as_deref(), &user, yes)
            }
            Org::Delete { org_id, yes, stdin } => {
                let password = stdin.then(read_stdin_password);
                commands::delete_org(org_id.as_deref(), yes, password)
            }
            Org::Confirm { user, org_id } => {
                commands::confirm_org_user(org_id.as_deref(), &user)
            }
            Org::Rename { name, org_id } => {
                commands::rename_org(org_id.as_deref(), &name)
            }
        },
        Opt::History {
            find_args,
            output,
            raw,
            yaml,
            from_file,
            from_file_passphrase,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw, yaml)?;
            commands::history(
                find_args.needles,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.collection.as_deref(),
                find_args.org.as_deref(),
                find_args.ignorecase,
                output,
                find_args.exact,
                from_file.as_deref(),
                from_file_passphrase.as_deref(),
            )
        })(),
        Opt::Lock { all } => commands::lock(all),
        Opt::Purge { yes } => commands::purge(yes),
        Opt::PurgeVault { yes, stdin } => {
            let password = stdin.then(read_stdin_password);
            commands::purge_vault(yes, password)
        }
        Opt::Mirror {
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
            stdin,
            dry_run,
        } => {
            let password = stdin.then(read_stdin_password);
            commands::mirror_vault(
                &from,
                &to,
                collection.as_deref(),
                org_id.as_deref(),
                dest_collection.as_deref(),
                dest_org.as_deref(),
                attachments,
                overwrite,
                purge_dest,
                yes,
                password,
                dry_run,
            )
        }
        Opt::StopAgent => commands::stop_agent(),
        Opt::Completions { shell } => {
            match shell {
                CompletionShell::Bash => {
                    clap_complete::generate(
                        clap_complete::Shell::Bash,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.bash"));
                }
                CompletionShell::Fish => {
                    clap_complete::generate(
                        clap_complete::Shell::Fish,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.fish"));
                }
                CompletionShell::Zsh => {
                    clap_complete::generate(
                        clap_complete::Shell::Zsh,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.zsh"));
                }
                CompletionShell::Powershell => {
                    clap_complete::generate(
                        clap_complete::Shell::PowerShell,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Elvish => {
                    clap_complete::generate(
                        clap_complete::Shell::Elvish,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Nushell => {
                    clap_complete::generate(
                        clap_complete_nushell::Nushell,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Fig => {
                    clap_complete::generate(
                        clap_complete_fig::Fig,
                        &mut Cli::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
            }
            Ok(())
        }
    }
    .with_context(|| format!("rbw {subcommand_name}"));

    if let Err(e) = res {
        let c = std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        let msg = format!("{e:#}");
        eprintln!("{}", commands::style_error(&msg, c));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Runs clap's internal consistency checks (positional ordering,
    // conflicting shorts, ...) over the whole CLI definition, which
    // otherwise only trip debug assertions at runtime.
    #[test]
    fn test_cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap()
    }

    // Every find-based subcommand accepts `-e`/`--exact`, including the
    // attachment subcommands that used to hand-roll their find args.
    #[test]
    fn test_find_based_subcommands_accept_exact() {
        for args in [
            &["rbw", "get", "-e", "name"][..],
            &["rbw", "show", "--exact", "name"][..],
            &["rbw", "code", "-e", "name"][..],
            &["rbw", "history", "-e", "name"][..],
            &["rbw", "attachment", "list", "-e", "name"][..],
            &["rbw", "attachment", "get", "-e", "name"][..],
            &["rbw", "attachment", "create", "-e", "name", "file.txt"][..],
            &["rbw", "attachment", "rm", "-e", "name"][..],
        ] {
            parse(args);
        }
    }

    #[test]
    fn test_find_args_accept_collection_and_org() {
        for args in [
            &[
                "rbw",
                "get",
                "--collection",
                "Infra",
                "--org",
                "acme",
                "name",
            ][..],
            &["rbw", "show", "--collection", "Infra", "name"][..],
            &["rbw", "code", "--org", "acme", "name"][..],
            &["rbw", "edit", "--collection", "Infra", "name"][..],
            &["rbw", "set", "--collection", "Infra", "name"][..],
            &["rbw", "rm", "--collection", "Infra", "name"][..],
            &["rbw", "archive", "--collection", "Infra", "name"][..],
            &["rbw", "unarchive", "--collection", "Infra", "name"][..],
            &["rbw", "restore", "--collection", "Infra", "name"][..],
            &["rbw", "history", "--collection", "Infra", "name"][..],
            &["rbw", "attachment", "list", "--collection", "Infra", "name"][..],
            &["rbw", "attachment", "get", "--collection", "Infra", "name"][..],
            &["rbw", "attachment", "rm", "--collection", "Infra", "name"][..],
            &["rbw", "list", "--collection", "Infra", "--org", "acme"][..],
            &["rbw", "list", "--collection", "Infra", "term"][..],
            &[
                "rbw",
                "search",
                "--collection",
                "Infra",
                "--org",
                "acme",
                "term",
            ][..],
        ] {
            parse(args);
        }

        let cli =
            parse(&["rbw", "list", "--collection", "Infra", "--org", "acme"]);
        let Opt::List {
            collection, org, ..
        } = cli.command
        else {
            panic!("expected Opt::List");
        };
        assert_eq!(collection.as_deref(), Some("Infra"));
        assert_eq!(org.as_deref(), Some("acme"));

        let cli = parse(&[
            "rbw",
            "search",
            "--collection",
            "Infra",
            "--org",
            "acme",
            "term",
        ]);
        let Opt::Search {
            collection, org, ..
        } = cli.command
        else {
            panic!("expected Opt::Search");
        };
        assert_eq!(collection.as_deref(), Some("Infra"));
        assert_eq!(org.as_deref(), Some("acme"));

        let cli = parse(&[
            "rbw",
            "get",
            "--collection",
            "Infra",
            "--org",
            "acme",
            "name",
        ]);
        let Opt::Get { find_args, .. } = cli.command else {
            panic!("expected Opt::Get");
        };
        assert_eq!(find_args.collection.as_deref(), Some("Infra"));
        assert_eq!(find_args.org.as_deref(), Some("acme"));
    }

    #[test]
    fn test_export_and_import_accept_collection_and_org() {
        let cli = parse(&[
            "rbw",
            "export",
            "--collection",
            "Infra",
            "--org",
            "acme",
        ]);
        let Opt::Export {
            collection, org, ..
        } = cli.command
        else {
            panic!("expected Opt::Export");
        };
        assert_eq!(collection.as_deref(), Some("Infra"));
        assert_eq!(org.as_deref(), Some("acme"));

        let cli = parse(&["rbw", "export"]);
        let Opt::Export {
            collection, org, ..
        } = cli.command
        else {
            panic!("expected Opt::Export");
        };
        assert_eq!(collection, None);
        assert_eq!(org, None);

        let cli = parse(&[
            "rbw",
            "import",
            "--collection",
            "Infra",
            "--org",
            "acme",
        ]);
        let Opt::Import {
            collection, org, ..
        } = cli.command
        else {
            panic!("expected Opt::Import");
        };
        assert_eq!(collection.as_deref(), Some("Infra"));
        assert_eq!(org.as_deref(), Some("acme"));

        // --org without --collection parses fine too (it's a no-op without
        // --collection, not an error -- same as --dest-org on `mirror`).
        parse(&["rbw", "import", "--org", "acme"]);
    }

    #[test]
    fn test_attachment_create_splits_needles_and_file() {
        let cli = parse(&["rbw", "attachment", "create", "entry", "f.txt"]);
        let Opt::Attachment {
            attachment: Attachment::Create { needles, file, .. },
        } = cli.command
        else {
            panic!("parsed as the wrong subcommand");
        };
        assert_eq!(needles.len(), 1);
        assert_eq!(file, std::path::PathBuf::from("f.txt"));
    }

    #[test]
    fn test_output_flags_on_show_and_history() {
        for args in [
            &["rbw", "show", "-o", "json", "name"][..],
            &["rbw", "show", "--all", "name"][..],
            &["rbw", "history", "-j", "name"][..],
            &["rbw", "history", "--yaml", "name"][..],
            &["rbw", "search", "--insecure", "term"][..],
            &["rbw", "code", "--all", "name"][..],
        ] {
            parse(args);
        }
    }

    #[test]
    fn test_collection_group_parses() {
        for args in [
            &["rbw", "collection", "list"][..],
            &["rbw", "collection", "ls", "-o", "json"][..],
            &["rbw", "collection", "create", "name"][..],
            &["rbw", "collection", "add", "name", "--org-id", "org"][..],
            &["rbw", "collection", "delete", "name", "-y"][..],
            &["rbw", "collection", "rm", "name"][..],
            &["rbw", "collection", "remove", "name"][..],
            &["rbw", "collection", "del", "name"][..],
            &["rbw", "collection", "purge", "name"][..],
            &[
                "rbw",
                "collection",
                "purge",
                "name",
                "--org-id",
                "org",
                "-y",
            ][..],
            &["rbw", "collection", "rename", "old", "new"][..],
            &[
                "rbw",
                "collection",
                "rename",
                "old",
                "new",
                "--org-id",
                "org",
            ][..],
            &[
                "rbw",
                "collection",
                "rename",
                "old",
                "new",
                "--organizationid",
                "org",
            ][..],
            &[
                "rbw",
                "collection",
                "assign",
                "entry",
                "--collection",
                "coll",
            ][..],
            &[
                "rbw",
                "collection",
                "assign",
                "-e",
                "entry",
                "--collection",
                "c1",
                "--collection",
                "c2",
            ][..],
            &[
                "rbw",
                "collection",
                "assign",
                "--bulk",
                "entry1",
                "entry2",
                "--collection",
                "c1",
                "-y",
            ][..],
            &["rbw", "collection", "assign", "entry", "--personal"][..],
            &[
                "rbw",
                "collection",
                "assign",
                "--bulk",
                "entry1",
                "entry2",
                "--personal",
                "-y",
            ][..],
            &["rbw", "collection", "unassign", "entry"][..],
            &[
                "rbw",
                "collection",
                "unassign",
                "entry",
                "--collection",
                "c1",
            ][..],
            &[
                "rbw",
                "collection",
                "unassign",
                "--bulk",
                "entry1",
                "entry2",
                "-y",
            ][..],
            &["rbw", "collection", "grant", "coll", "user@example.com"][..],
            &[
                "rbw",
                "collection",
                "grant",
                "coll",
                "user@example.com",
                "--read-only",
                "--hide-passwords",
            ][..],
            &["rbw", "collection", "propagate-permissions", "--apply"][..],
        ] {
            parse(args);
        }
    }

    #[test]
    fn test_collection_assign_personal_conflicts_with_collection() {
        let result = Cli::try_parse_from([
            "rbw",
            "collection",
            "assign",
            "entry",
            "--personal",
            "--collection",
            "c1",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_org_group_parses() {
        for args in [
            &["rbw", "org", "list"][..],
            &["rbw", "org", "ls", "-o", "json"][..],
            &["rbw", "org", "list", "--yaml"][..],
            &["rbw", "org", "rename", "new-name"][..],
            &["rbw", "org", "rename", "new-name", "--org-id", "some-org"][..],
        ] {
            parse(args);
        }
    }

    #[test]
    fn test_mirror_requires_from_and_to() {
        assert!(Cli::try_parse_from(["rbw", "mirror"]).is_err());
        assert!(
            Cli::try_parse_from(["rbw", "mirror", "--from", "a"]).is_err()
        );
        parse(&["rbw", "mirror", "--from", "a", "--to", "b"]);
    }

    #[test]
    fn test_mirror_parses_every_flag() {
        let cli = parse(&[
            "rbw",
            "mirror",
            "--from",
            "ai",
            "--to",
            "bw",
            "--collection",
            "some-collection",
            "--org-id",
            "some-org",
            "--dest-collection",
            "some-dest-collection",
            "--dest-org",
            "some-dest-org",
            "--attachments",
            "--overwrite",
            "--purge-dest",
            "-y",
            "--stdin",
            "--dry-run",
        ]);
        let Opt::Mirror {
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
            stdin,
            dry_run,
        } = cli.command
        else {
            panic!("expected Opt::Mirror");
        };
        assert_eq!(from, "ai");
        assert_eq!(to, "bw");
        assert_eq!(collection.as_deref(), Some("some-collection"));
        assert_eq!(org_id.as_deref(), Some("some-org"));
        assert_eq!(dest_collection.as_deref(), Some("some-dest-collection"));
        assert_eq!(dest_org.as_deref(), Some("some-dest-org"));
        assert!(attachments);
        assert!(overwrite);
        assert!(purge_dest);
        assert!(yes);
        assert!(stdin);
        assert!(dry_run);
    }

    #[test]
    fn test_collection_assign_splits_entry_and_collections() {
        let cli = parse(&[
            "rbw",
            "collection",
            "assign",
            "entry",
            "--collection",
            "c1",
            "--collection",
            "c2",
        ]);
        let Opt::Collection {
            collection:
                Collection::Assign {
                    needles,
                    collections,
                    ..
                },
        } = cli.command
        else {
            panic!("parsed as the wrong subcommand");
        };
        assert_eq!(needles.len(), 1);
        assert_eq!(needles[0].to_string(), "entry");
        assert_eq!(collections, vec!["c1".to_string(), "c2".to_string()]);
    }

    #[test]
    fn test_destructive_commands_accept_yes() {
        for args in [
            &["rbw", "remove", "-y", "name"][..],
            &["rbw", "rm", "--yes", "name"][..],
            &["rbw", "remove", "--force", "-y", "name"][..],
            &["rbw", "attachment", "rm", "-y", "name"][..],
            &["rbw", "purge", "-y"][..],
            &["rbw", "collection", "delete", "name", "--yes"][..],
            &["rbw", "collection", "purge", "name", "-y"][..],
        ] {
            parse(args);
        }
    }

    #[test]
    fn test_lock_parses_with_and_without_all() {
        for args in [
            &["rbw", "lock"][..],
            &["rbw", "lock", "--all"][..],
            &["rbw", "-a", "work", "lock"][..],
            &["rbw", "-a", "work", "lock", "--all"][..],
        ] {
            parse(args);
        }
    }

    #[test]
    fn test_resolve_output_mode_layers_flags() {
        assert_eq!(
            resolve_output_mode(None, false, false).unwrap(),
            commands::OutputMode::Default
        );
        assert_eq!(
            resolve_output_mode(None, true, false).unwrap(),
            commands::OutputMode::Json
        );
        assert_eq!(
            resolve_output_mode(None, false, true).unwrap(),
            commands::OutputMode::Yaml
        );
        assert_eq!(
            resolve_output_mode(Some(OutputArg::Name), false, false).unwrap(),
            commands::OutputMode::Name
        );
        assert!(
            resolve_output_mode(Some(OutputArg::Name), true, false).is_err()
        );
        assert!(resolve_output_mode(None, true, true).is_err());
    }
}
