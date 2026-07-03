use std::ffi::OsString;
use std::io::Write as _;

use is_terminal::IsTerminal as _;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt as _;

use anyhow::Context as _;
use clap::{CommandFactory as _, Parser as _};

mod actions;
mod commands;
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

    #[command(
        about = "Register this device with the Bitwarden server",
        long_about = "Register this device with the Bitwarden server\n\n\
            The official Bitwarden server includes bot detection to prevent \
            brute force attacks. In order to avoid being detected as bot \
            traffic, you will need to use this command to log in with your \
            personal API key (instead of your password) first before regular \
            logins will work."
    )]
    Register,

    #[command(about = "Log in to the Bitwarden server")]
    Login,

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
                not just the ones already unlocked"
        )]
        all: bool,
    },

    #[command(
        about = "Export the entire vault as decrypted JSON",
        long_about = "Export the entire vault as decrypted JSON\n\n\
            Outputs all entries (with full details) and collections \
            to stdout. Suitable for piping to a file for backup or \
            migration to another instance via `rbw import`."
    )]
    Export {
        #[arg(
            long,
            help = "Also download and embed decrypted attachment \
                contents (base64-encoded) in the export. This makes \
                the export considerably larger and slower to produce."
        )]
        attachments: bool,

        #[arg(
            long,
            value_name = "PASSPHRASE",
            help = "Symmetrically gpg-encrypt the export as a tar.gz \
                archive using the given passphrase, and write the \
                encrypted archive to stdout instead of raw JSON. \
                Requires `gpg` to be available on PATH."
        )]
        encrypt: Option<String>,
    },

    #[command(
        about = "Import data produced by `rbw export`",
        long_about = "Import data produced by `rbw export`\n\n\
            Reads a JSON export (or a gpg-encrypted tar.gz produced by \
            `rbw export --encrypt`, given --decrypt-passphrase) and \
            recreates its entries and collections in the target account's \
            vault (see the global --account/-a flag). Reads from stdin if \
            no file is given.\n\n\
            Entries that already exist (matched by name, and username for \
            logins) are left untouched and reported as skipped; pass \
            --overwrite to update them in place instead. Entries belonging \
            to an organization this account isn't a member of are imported \
            into the personal vault instead. SSH key entries are skipped: \
            this fork doesn't yet support creating them via the API."
    )]
    Import {
        #[arg(help = "Export file to import (defaults to stdin if omitted)")]
        file: Option<std::path::PathBuf>,
        #[arg(
            long,
            help = "Passphrase to decrypt a gpg-encrypted export archive \
                (produced by `rbw export --encrypt`)"
        )]
        decrypt_passphrase: Option<String>,
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
            help = "With multiple accounts configured, unlock (prompting as \
                needed) and include every account instead of just the \
                already-unlocked ones"
        )]
        all: bool,
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
            help = "With multiple accounts configured, unlock (prompting as \
                needed) and include every account instead of just the \
                already-unlocked ones"
        )]
        all: bool,
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
    },

    #[command(
        about = "Remove a given entry",
        visible_aliases = ["rm", "delete", "del"]
    )]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
    },

    #[command(about = "Manage organization collections")]
    Collection {
        #[command(subcommand)]
        collection: Collection,
    },

    // Hidden compat shim for `rbw collection list`.
    #[command(
        about = "List all collections in the organization (use `rbw \
            collection list`)",
        alias = "lsc",
        hide = true
    )]
    ListCollections {
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

    // Hidden compat shim for `rbw collection create`.
    #[command(
        about = "Create a new collection in an organization (use `rbw \
            collection create`)",
        hide = true
    )]
    CreateCollection {
        #[arg(help = "Name of the collection")]
        name: String,
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
    },

    // Hidden compat shim for `rbw collection delete`.
    #[command(
        about = "Delete an organization collection (use `rbw collection \
            delete`)",
        hide = true
    )]
    DeleteCollection {
        #[arg(help = "ID of the collection")]
        collection_id: String,
        #[arg(
            long = "org-id",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
    },

    // Hidden compat shim for `rbw collection assign`, keeping the old
    // script-oriented base64 interface intact.
    #[command(
        about = "Edit collections for an entry (use `rbw collection \
            assign`)",
        hide = true
    )]
    EditCollections {
        #[arg(help = "ID of the entry")]
        id: String,
        #[arg(help = "Base64-encoded JSON array of collection IDs")]
        collections: String,
    },

    // Hidden compat shim for `rbw collection propagate-permissions`.
    #[command(
        about = "Grant members access to nested collections (use `rbw \
            collection propagate-permissions`)",
        hide = true
    )]
    PropagateCollectionPermissions {
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

    // Hidden compat shim for `rbw collection rename`.
    #[command(
        about = "Rename an organization collection (use `rbw collection \
            rename`)",
        hide = true
    )]
    RenameCollection {
        #[arg(help = "ID of the collection")]
        id: String,
        #[arg(
            long = "org-id",
            alias = "organizationid",
            help = "Organization ID (auto-detected if the vault has a \
                single org)"
        )]
        org_id: Option<String>,
        #[arg(help = "New name for the collection")]
        name: String,
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

    #[command(about = "Remove the local copy of the password database")]
    Purge {
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
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
            Self::Register => "register".to_string(),
            Self::Login => "login".to_string(),
            Self::Version => "version".to_string(),
            Self::Unlock { .. } => "unlock".to_string(),
            Self::Unlocked => "unlocked".to_string(),
            Self::Sync { .. } => "sync".to_string(),
            Self::Tui { .. } => "tui".to_string(),
            Self::Export { .. } => "export".to_string(),
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
            Self::ListCollections { .. } => "list-collections".to_string(),
            Self::CreateCollection { .. } => "create-collection".to_string(),
            Self::DeleteCollection { .. } => "delete-collection".to_string(),
            Self::EditCollections { .. } => "edit-collections".to_string(),
            Self::PropagateCollectionPermissions { .. } => {
                "propagate-collection-permissions".to_string()
            }
            Self::RenameCollection { .. } => "rename-collection".to_string(),
            Self::History { .. } => "history".to_string(),
            Self::Lock => "lock".to_string(),
            Self::Purge => "purge".to_string(),
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
        about = "Edit the full config.json in $EDITOR",
        long_about = "Edit the full config.json in $EDITOR\n\n\
            Opens the whole configuration (every account, all global \
            settings) as pretty-printed JSON in the editor named by the \
            $VISUAL or $EDITOR environment variables. Saved on exit if the \
            content changed and still parses as valid config."
    )]
    Edit,
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
            value_parser = clap::value_parser!(bool),
            help = "Exclude this account's entries from list/search/get \
                merges, even when unlocked or with --all (still reachable \
                via --account)"
        )]
        exclude_from_list: Option<bool>,
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
                exclude_from_list,
                credential_source_account,
                credential_source_item,
                clear_credential_source,
            } => commands::account_set(
                &name,
                unlock.map(std::convert::Into::into),
                exclude_from_list,
                credential_source_account,
                credential_source_item,
                clear_credential_source,
            ),
        },
        Opt::Register => commands::register(),
        Opt::Login => commands::login(),
        Opt::Version => {
            println!("rbw {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Opt::Unlock { stdin, all } => {
            if all {
                commands::unlock_all()
            } else {
                let password = if stdin {
                    let mut buf = String::new();
                    let _ = std::io::stdin()
                        .read_line(&mut buf)
                        .context("failed to read password from stdin");
                    Some(buf.trim_end_matches('\n').to_string())
                } else {
                    None
                };

                commands::unlock(password)
            }
        }
        Opt::Unlocked => commands::unlocked(),
        Opt::Sync { all } => commands::sync(all),
        Opt::Tui { term, all } => tui::run(term.as_deref(), all),
        Opt::Export {
            attachments,
            encrypt,
        } => commands::export(attachments, encrypt.as_deref()),
        Opt::Import {
            file,
            decrypt_passphrase,
            overwrite,
        } => commands::import(
            file.as_deref(),
            decrypt_passphrase.as_deref(),
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
            all,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw, yaml)?;
            term.map_or_else(
                || {
                    commands::list(
                        &fields,
                        with_attachments,
                        insecure,
                        output,
                        all,
                    )
                },
                |term| {
                    commands::search(
                        &term,
                        &fields,
                        None,
                        with_attachments,
                        insecure,
                        output,
                        all,
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
            } => (|| -> anyhow::Result<()> {
                let output = resolve_output_mode(output, raw, yaml)?;
                commands::attachment_list(
                    find_args.needles,
                    find_args.user.as_deref(),
                    find_args.folder.as_deref(),
                    find_args.ignorecase,
                    output,
                    find_args.exact,
                )
            })(),
            Attachment::Get {
                find_args,
                attachment,
                output,
                raw,
            } => commands::attachment_get(
                find_args.needles,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                attachment.as_deref(),
                output.as_deref(),
                raw,
                find_args.exact,
            ),
            Attachment::Create {
                needles,
                file,
                user,
                folder,
                ignorecase,
                exact,
            } => commands::attachment_create(
                needles,
                user.as_deref(),
                folder.as_deref(),
                ignorecase,
                &file,
                exact,
            ),
            Attachment::Rm {
                find_args,
                attachment,
            } => commands::attachment_rm(
                find_args.needles,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                attachment.as_deref(),
                find_args.exact,
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
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw, yaml)?;
            commands::get(
                find_args.needles.clone(),
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
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
            )
        })(),
        Opt::Show {
            find_args,
            output,
            raw,
            yaml,
            all,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw, yaml)?;
            commands::show(
                find_args.needles,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                output,
                find_args.exact,
                all,
            )
        })(),
        Opt::Search {
            term,
            fields,
            folder,
            with_attachments,
            output,
            raw,
            yaml,
            insecure,
            all,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw, yaml)?;
            commands::search(
                &term,
                &fields,
                folder.as_deref(),
                with_attachments,
                insecure,
                output,
                all,
            )
        })(),
        Opt::Code {
            find_args,
            #[cfg(feature = "clipboard")]
            clipboard,
            all,
        } => commands::code(
            find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
            find_args.exact,
            all,
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
        } => commands::edit(
            find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
            json,
            yaml,
            find_args.exact,
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
        } => commands::set(
            find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
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
        ),
        Opt::Remove { find_args } => commands::remove(
            find_args.needles,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
            find_args.exact,
        ),
        Opt::ListCollections { output, raw, yaml } => {
            (|| -> anyhow::Result<()> {
                let output = resolve_output_mode(output, raw, yaml)?;
                commands::list_collections(output)
            })()
        }
        Opt::CreateCollection { name, org_id } => {
            commands::create_collection(&name, &org_id)
        }
        Opt::DeleteCollection {
            collection_id,
            org_id,
        } => commands::delete_collection(&collection_id, &org_id),
        Opt::EditCollections { id, collections } => {
            commands::edit_collections(&id, &collections)
        }
        Opt::PropagateCollectionPermissions {
            org_id,
            apply,
            verbose,
        } => commands::propagate_collection_permissions(
            org_id.as_deref(),
            apply,
            verbose,
        ),
        Opt::RenameCollection {
            id,
            organizationid,
            name,
        } => commands::rename_collection(&id, &organizationid, &name),
        Opt::History {
            find_args,
            output,
            raw,
            yaml,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw, yaml)?;
            commands::history(
                find_args.needles,
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                find_args.ignorecase,
                output,
                find_args.exact,
            )
        })(),
        Opt::Lock => commands::lock(),
        Opt::Purge => commands::purge(),
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
