use std::ffi::OsString;
use std::io::Write as _;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt as _;

use anyhow::Context as _;
use clap::{CommandFactory as _, Parser as _};

mod actions;
mod commands;
mod sock;

#[derive(Debug, clap::Args)]
struct FindArgs {
    #[arg(help = "Name, URI or UUID of the entry to display", value_parser = commands::parse_needle)]
    needle: commands::Needle,
    #[arg(help = "Username of the entry to display")]
    user: Option<String>,
    #[arg(long, help = "Folder name to search in")]
    folder: Option<String>,
    #[arg(short, long, help = "Ignore case")]
    ignorecase: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
enum OutputArg {
    Name,
    Json,
    Yaml,
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

    let mut structured = None;
    if json {
        structured = Some(commands::OutputMode::Json);
    }
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
enum Opt {
    #[command(about = "Get or set configuration options")]
    Config {
        #[command(subcommand)]
        config: Config,
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

    #[command(about = "Unlock the local Bitwarden database")]
    Unlock {
        #[arg(long, help = "Read the password from standard input")]
        stdin: bool,
    },

    #[command(about = "Check if the local Bitwarden database is unlocked")]
    Unlocked,

    #[command(about = "Update the local copy of the Bitwarden database")]
    Sync,

    #[command(
        about = "Export the entire vault as decrypted JSON",
        long_about = "Export the entire vault as decrypted JSON\n\n\
            Outputs all entries (with full details) and collections \
            to stdout. Suitable for piping to a file for backup or \
            migration to another instance via `rbw import`."
    )]
    Export,

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
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
        #[arg(long, help = "Display output as JSON")]
        json: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
        #[arg(long, help = "Dump full structured output for all items")]
        full: bool,
    },

    #[command(about = "Display the password for a given entry")]
    Get {
        #[command(flatten)]
        find_args: FindArgs,
        #[arg(short, long, help = "Field to get")]
        field: Option<String>,
        #[arg(long, help = "Display the notes in addition to the password")]
        full: bool,
        #[arg(
            short,
            long,
            value_enum,
            help = "Output mode: name, json, yaml"
        )]
        output: Option<OutputArg>,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
        #[arg(long, help = "Display output as JSON")]
        json: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
        #[cfg(feature = "clipboard")]
        #[structopt(short, long, help = "Copy result to clipboard")]
        clipboard: bool,
        #[structopt(short, long, help = "List fields in this entry")]
        list_fields: bool,
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
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
        #[arg(long, help = "Display output as JSON")]
        json: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
        #[arg(long, help = "Dump full structured output for matching items")]
        full: bool,
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
        #[structopt(long, help = "Copy result to clipboard")]
        clipboard: bool,
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
            remainder will be saved as a note."
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
    },

    #[command(
        about = "Generate a new password",
        long_about = "Generate a new password\n\n\
            If given a password entry name, also save the generated \
            password to the database.",
        visible_alias = "gen",
        group = clap::ArgGroup::new("password-type").args(&[
            "no_symbols",
            "only_numbers",
            "nonconfusables",
            "diceware",
        ])
    )]
    Generate {
        #[arg(help = "Length of the password to generate")]
        len: usize,
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
                words chosen from the EFF word list. The len \
                parameter for this option will set the number \
                of words to generate, rather than characters."
        )]
        diceware: bool,
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
        #[arg(long, alias = "user", help = "New username (Login entries only)")]
        username: Option<String>,
        #[arg(long, help = "New password (Login entries only)")]
        password: Option<String>,
        #[arg(long, alias = "note", help = "New notes (empty string to clear)")]
        notes: Option<String>,
        #[arg(
            long,
            number_of_values = 1,
            help = "Replace URIs (Login entries only; can be repeated)"
        )]
        uri: Vec<String>,
        #[arg(long, help = "New TOTP secret (Login entries only)")]
        totp: Option<String>,
        #[arg(long, help = "Show old → new for each changed field")]
        diff: bool,
    },

    #[command(about = "Remove a given entry", visible_alias = "rm")]
    Remove {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(
        about = "List all collections in the organization",
        visible_alias = "lsc"
    )]
    ListCollections {
        #[arg(
            short,
            long,
            value_enum,
            help = "Output mode: name, json, yaml"
        )]
        output: Option<OutputArg>,
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
        #[arg(long, help = "Display output as JSON")]
        json: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
    },

    #[command(about = "Create a new collection in an organization")]
    CreateCollection {
        #[arg(help = "Name of the collection")]
        name: String,
        #[arg(long = "org-id", help = "Organization ID")]
        org_id: String,
    },

    #[command(about = "Delete an organization collection")]
    DeleteCollection {
        #[arg(help = "ID of the collection")]
        collection_id: String,
        #[arg(long = "org-id", help = "Organization ID")]
        org_id: String,
    },

    #[command(about = "Edit collections for an entry")]
    EditCollections {
        #[arg(help = "ID of the entry")]
        id: String,
        #[arg(help = "Base64-encoded JSON array of collection IDs")]
        collections: String,
    },

    #[command(
        about = "Grant members access to nested collections (topmost held -> edit, descendants -> manage)"
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

    #[command(about = "Rename an organization collection")]
    RenameCollection {
        #[arg(help = "ID of the collection")]
        id: String,
        #[arg(long, help = "Organization ID")]
        organizationid: String,
        #[arg(help = "New name for the collection")]
        name: String,
    },

    #[command(about = "View the password history for a given entry")]
    History {
        #[command(flatten)]
        find_args: FindArgs,
    },

    #[command(about = "Lock the password database")]
    Lock,

    #[command(about = "Remove the local copy of the password database")]
    Purge,

    #[command(name = "stop-agent", about = "Terminate the background agent")]
    StopAgent,

    #[command(
        name = "gen-completions",
        about = "Generate completion script for the given shell"
    )]
    GenCompletions { shell: CompletionShell },
}

impl Opt {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Config { config } => {
                format!("config {}", config.subcommand_name())
            }
            Self::Register => "register".to_string(),
            Self::Login => "login".to_string(),
            Self::Unlock { .. } => "unlock".to_string(),
            Self::Unlocked => "unlocked".to_string(),
            Self::Sync => "sync".to_string(),
            Self::Export => "export".to_string(),
            Self::List { .. } => "list".to_string(),
            Self::Get { .. } => "get".to_string(),
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
            Self::GenCompletions { .. } => "gen-completions".to_string(),
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
}

#[derive(Debug, clap::Parser)]
enum Attachment {
    #[command(about = "List attachments for an entry")]
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
        #[structopt(long, help = "Display output as JSON")]
        raw: bool,
        #[arg(long, help = "Display output as JSON")]
        json: bool,
        #[arg(long, help = "Display output as YAML")]
        yaml: bool,
    },
    #[command(
        about = "Download and decrypt an attachment by id or filename"
    )]
    Get {
        #[arg(help = "Name, URI or UUID of the entry", value_parser = commands::parse_needle)]
        needle: commands::Needle,
        #[arg(
            help = "Attachment ID or filename (see `rbw attachment list <entry>`)"
        )]
        attachment: Option<String>,
        #[arg(help = "Username of the entry")]
        user: Option<String>,
        #[arg(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[arg(short, long, help = "Ignore case")]
        ignorecase: bool,
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
}

impl Attachment {
    fn subcommand_name(&self) -> String {
        match self {
            Self::List { .. } => "list",
            Self::Get { .. } => "get",
        }
        .to_string()
    }
}

impl Config {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Show => "show",
            Self::Set { .. } => "set",
            Self::Unset { .. } => "unset",
        }
        .to_string()
    }
}

fn main() {
    let opt = Opt::parse();

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
            Config::Set { key, value } => commands::config_set(&key, &value),
            Config::Unset { key } => commands::config_unset(&key),
        },
        Opt::Register => commands::register(),
        Opt::Login => commands::login(),
        Opt::Unlock { stdin } => {
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
        Opt::Unlocked => commands::unlocked(),
        Opt::Sync => commands::sync(),
        Opt::Export => commands::export(),
        Opt::List {
            fields,
            term,
            with_attachments,
            output,
            raw,
            json,
            yaml,
            full,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw || json, yaml)?;
            if let Some(term) = term {
                commands::search(
                    &term,
                    &fields,
                    None,
                    with_attachments,
                    output,
                    full,
                )
            } else {
                commands::list(&fields, with_attachments, output, full)
            }
        })(),
        Opt::Attachment { attachment } => match attachment {
            Attachment::List {
                find_args,
                output,
                raw,
                json,
                yaml,
            } => (|| -> anyhow::Result<()> {
                let output = resolve_output_mode(output, raw || json, yaml)?;
                commands::attachment_list(
                    find_args.needle,
                    find_args.user.as_deref(),
                    find_args.folder.as_deref(),
                    find_args.ignorecase,
                    output,
                )
            })(),
            Attachment::Get {
                needle,
                attachment,
                user,
                folder,
                ignorecase,
                output,
                raw,
            } => commands::attachment_get(
                needle,
                user.as_deref(),
                folder.as_deref(),
                ignorecase,
                attachment.as_deref(),
                output.as_deref(),
                raw,
            ),
        },
        Opt::Get {
            find_args,
            field,
            full,
            output,
            raw,
            json,
            yaml,
            #[cfg(feature = "clipboard")]
            clipboard,
            list_fields,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw || json, yaml)?;
            commands::get(
                find_args.needle.clone(),
                find_args.user.as_deref(),
                find_args.folder.as_deref(),
                field.as_deref(),
                full,
                output,
                #[cfg(feature = "clipboard")]
                clipboard,
                #[cfg(not(feature = "clipboard"))]
                false,
                find_args.ignorecase,
                list_fields,
            )
        })(),
        Opt::Search {
            term,
            fields,
            folder,
            with_attachments,
            output,
            raw,
            json,
            yaml,
            full,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw || json, yaml)?;
            commands::search(
                &term,
                &fields,
                folder.as_deref(),
                with_attachments,
                output,
                full,
            )
        })(),
        Opt::Code {
            find_args,
            #[cfg(feature = "clipboard")]
            clipboard,
        } => commands::code(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            #[cfg(feature = "clipboard")]
            clipboard,
            #[cfg(not(feature = "clipboard"))]
            false,
            find_args.ignorecase,
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
        } => commands::add(
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
        ),
        Opt::Generate {
            len,
            name,
            user,
            uri,
            folder,
            no_symbols,
            only_numbers,
            nonconfusables,
            diceware,
        } => {
            let ty = if no_symbols {
                rbw::pwgen::Type::NoSymbols
            } else if only_numbers {
                rbw::pwgen::Type::Numbers
            } else if nonconfusables {
                rbw::pwgen::Type::NonConfusables
            } else if diceware {
                rbw::pwgen::Type::Diceware
            } else {
                rbw::pwgen::Type::AllChars
            };
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
        Opt::Edit { find_args, json, yaml } => commands::edit(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
            json,
            yaml,
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
        } => commands::set(
            find_args.needle,
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
        ),
        Opt::Remove { find_args } => commands::remove(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::ListCollections {
            output,
            raw,
            json,
            yaml,
        } => (|| -> anyhow::Result<()> {
            let output = resolve_output_mode(output, raw || json, yaml)?;
            commands::list_collections(output)
        })(),
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
        Opt::History { find_args } => commands::history(
            find_args.needle,
            find_args.user.as_deref(),
            find_args.folder.as_deref(),
            find_args.ignorecase,
        ),
        Opt::Lock => commands::lock(),
        Opt::Purge => commands::purge(),
        Opt::StopAgent => commands::stop_agent(),
        Opt::GenCompletions { shell } => {
            match shell {
                CompletionShell::Bash => {
                    clap_complete::generate(
                        clap_complete::Shell::Bash,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.bash"));
                }
                CompletionShell::Fish => {
                    clap_complete::generate(
                        clap_complete::Shell::Fish,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.fish"));
                }
                CompletionShell::Zsh => {
                    clap_complete::generate(
                        clap_complete::Shell::Zsh,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                    println!("{}", include_str!("completion/rbw.zsh"));
                }
                CompletionShell::Powershell => {
                    clap_complete::generate(
                        clap_complete::Shell::PowerShell,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Elvish => {
                    clap_complete::generate(
                        clap_complete::Shell::Elvish,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Nushell => {
                    clap_complete::generate(
                        clap_complete_nushell::Nushell,
                        &mut Opt::command(),
                        "rbw",
                        &mut std::io::stdout(),
                    );
                }
                CompletionShell::Fig => {
                    clap_complete::generate(
                        clap_complete_fig::Fig,
                        &mut Opt::command(),
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
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
