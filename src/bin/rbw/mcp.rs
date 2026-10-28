// `rbw mcp`: a Model Context Protocol server on stdin/stdout, so an AI agent
// can search, read and change the vault without a shell.
//
// Each tool runs this same `rbw` binary as a subprocess with the matching
// command line, so the agent gets exactly the CLI's behavior (account
// routing, sync, password history, confirmation-free writes with `-y`) and
// nothing a command prints can corrupt the JSON-RPC stream on stdout.
//
// Secrets stay out of the agent's context by default: every command runs
// with `--redact`, secret values are handed to `rbw` through environment
// variables or stdin rather than argv, and the tools that need a secret
// (`secret_to_file`, `generate`, `attachment_download`) write it to a file
// and only report its size. `--allow-secrets` lets `get`, `history`, `code`
// and `generate` return plaintext when asked to (`reveal`), and
// `--read-only` removes every tool that changes something.

use std::io::{Read as _, Write as _};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
    Implementation, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerConfig, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServiceExt as _};
use serde_json::{json, Map, Value};
const MASKED_SECRET: &str = "••••••••";
const MAX_OUTPUT: usize = 256 * 1024;
const DEFAULT_LIST_LIMIT: u64 = 500;

const INSTRUCTIONS: &str = "\
rbw: a Bitwarden/Vaultwarden vault (unofficial `rbw` CLI).

- Output is redacted: passwords, TOTP seeds, notes, hidden fields, card \
numbers and keys show as ••••••••. Never write a masked value back; `update` \
and `edit` only change what you pass and refuse the mask.
- To use a secret without seeing it, `secret_to_file` writes one field (or \
the current TOTP code) to a 0600 file; read it from your shell with \
\"$(cat FILE)\" and delete the file afterwards. Never print it.
- Entries are matched like `rbw get`: `entry` is a name, URI or UUID (or an \
array of terms that must all match); narrow with `user`, `folder`, `exact`. \
Prefer the UUID once you know it. Several matches is an error.
- Every tool takes `account` for a multi-account setup; reads look in every \
unlocked account, writes act on the account that holds the entry.
- If a tool fails with a locked vault, call `unlock` (it may prompt the user \
on their desktop or phone) or ask the user to unlock rbw.
- `delete` moves to the trash (undo with `restore`); `permanent: true` \
cannot be undone.
- `rbw` runs any other rbw command line (redacted) for what the typed tools \
don't cover: sends, organizations, collections, import/export, config.";

pub fn run(
    allow_secrets: bool,
    read_only: bool,
    timeout: u64,
) -> anyhow::Result<()> {
    let server = Server {
        exe: std::env::current_exe()?,
        allow_secrets,
        read_only,
        timeout: std::time::Duration::from_secs(timeout),
    };
    tokio::runtime::Runtime::new()?.block_on(async {
        let service = server
            .serve(rmcp::transport::stdio_pipes())
            .await
            .map_err(|e| anyhow::anyhow!("MCP initialization failed: {e}"))?;
        service.waiting().await?;
        Ok(())
    })
}

#[derive(Clone)]
struct Server {
    exe: std::path::PathBuf,
    allow_secrets: bool,
    read_only: bool,
    timeout: std::time::Duration,
}

impl rmcp::ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        let mut instructions = INSTRUCTIONS.to_string();
        if self.allow_secrets {
            instructions.push_str(
                "\n- This server allows `reveal: true` on get/history/code \
                 and returning generated passwords. Only reveal what the \
                 task needs.",
            );
        }
        if self.read_only {
            instructions.push_str(
                "\n- This server is read-only: no tool changes the vault.",
            );
        }
        ServerConfig::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_server_info(
            Implementation::new("rbw", env!("CARGO_PKG_VERSION"))
                .with_title("rbw (Bitwarden)"),
        )
        .with_instructions(instructions)
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, ErrorData>>
           + Send
           + '_ {
        std::future::ready(Ok(ListToolsResult::with_all_items(
            self.tool_list(),
        )))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let tool = self.tool(&request.name).ok_or_else(|| {
            ErrorData::invalid_params(
                format!("unknown tool {}", request.name),
                None,
            )
        })?;
        let arguments = request.arguments.unwrap_or_default();
        // The tools run `rbw` and wait for it; keep that off the runtime.
        let server = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            (tool.handler)(&server, &Args(&arguments))
        })
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(match result {
            Ok(text) => CallToolResult::success(vec![ContentBlock::text(
                truncate(text),
            )]),
            Err(e) => CallToolResult::error(vec![ContentBlock::text(
                truncate(format!("{e:#}")),
            )]),
        }
        .into())
    }
}

impl Server {
    fn tool(&self, name: &str) -> Option<&'static Tool> {
        TOOLS
            .iter()
            .find(|t| t.name == name)
            .filter(|t| !(self.read_only && t.kind.writes()))
    }

    fn tool_list(&self) -> Vec<rmcp::model::Tool> {
        TOOLS
            .iter()
            .filter(|tool| !(self.read_only && tool.kind.writes()))
            .map(|tool| {
                let Value::Object(schema) = (tool.schema)() else {
                    unreachable!("tool schemas are objects")
                };
                rmcp::model::Tool::new(tool.name, tool.description, schema)
                    .with_annotations(tool.kind.annotations(tool.name))
            })
            .collect()
    }

    fn reveal(&self, args: &Args) -> anyhow::Result<bool> {
        let reveal = args.bool("reveal");
        anyhow::ensure!(
            !reveal || self.allow_secrets,
            "`reveal` is disabled: this server was started without \
             --allow-secrets. Use `secret_to_file` to use a secret without \
             reading it."
        );
        Ok(reveal)
    }

    fn rbw(&self, cmd: Cmd) -> anyhow::Result<Output> {
        let mut command = std::process::Command::new(&self.exe);
        if cmd.redact {
            command.arg("--redact");
        }
        command
            .args(&cmd.args)
            .envs(cmd.env.iter().map(|(k, v)| (k, v)))
            .env("NO_COLOR", "1")
            .env_remove("RBW_FZF_OPTS")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn()?;
        let stdin = cmd.stdin.unwrap_or_default();
        let mut child_stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || {
            // A command that doesn't read stdin closes it early; ignore that.
            let _ = child_stdin.write_all(stdin.as_bytes());
        });
        let mut child_stdout = child.stdout.take().unwrap();
        let mut child_stderr = child.stderr.take().unwrap();
        let out_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = child_stdout.read_to_end(&mut buf);
            buf
        });
        let err_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = child_stderr.read_to_end(&mut buf);
            buf
        });
        let timeout = cmd.timeout.unwrap_or(self.timeout);
        let start = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if start.elapsed() > timeout {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let _ = writer.join();
        let stdout =
            String::from_utf8_lossy(&out_reader.join().unwrap_or_default())
                .into_owned();
        let stderr =
            String::from_utf8_lossy(&err_reader.join().unwrap_or_default())
                .into_owned();
        let Some(status) = status else {
            anyhow::bail!(
                "`rbw {}` timed out after {}s",
                cmd.args.first().map_or("", String::as_str),
                timeout.as_secs()
            );
        };
        Ok(Output {
            success: status.success(),
            stdout,
            stderr,
        })
    }

    // Runs a command whose output may be shown: stdout on success (plus
    // stderr, which carries notices such as "entry updated"), stderr as the
    // error otherwise.
    fn shown(&self, cmd: Cmd) -> anyhow::Result<String> {
        let redact = cmd.redact;
        let out = self.rbw(cmd)?;
        if !out.success {
            anyhow::bail!("{}", out.failure(redact));
        }
        Ok(join_output(&out.stdout, &out.stderr))
    }

    // Runs an unredacted command whose stdout is a secret: returned to the
    // caller to store, never shown, not even on failure.
    fn secret(&self, args: Vec<String>) -> anyhow::Result<String> {
        let out = self.rbw(Cmd::new(args).unredacted())?;
        if !out.success {
            anyhow::bail!("{}", out.failure(false));
        }
        anyhow::ensure!(
            out.stdout.trim() != MASKED_SECRET,
            "rbw returned a masked value: redaction is enabled for it \
             (RBW_REDACT or the `redact` config option)"
        );
        Ok(out.stdout)
    }

    // The entry a selector names, redacted.
    fn find(&self, args: &Args) -> anyhow::Result<Value> {
        let mut argv = account_args(args);
        argv.extend(["get".to_string(), "--json".to_string()]);
        selector_args(args, &mut argv)?;
        let out = self.shown(Cmd::new(argv))?;
        Ok(serde_json::from_str(&out)?)
    }

    // Redacted JSON of the entry with this id.
    fn entry_by_id(&self, args: &Args, id: &str) -> anyhow::Result<String> {
        let mut argv = account_args(args);
        argv.extend(["get", "--json", "--", id].map(String::from));
        self.shown(Cmd::new(argv))
    }
}

struct Cmd {
    args: Vec<String>,
    stdin: Option<String>,
    env: Vec<(String, String)>,
    redact: bool,
    timeout: Option<std::time::Duration>,
}

impl Cmd {
    fn new(args: Vec<String>) -> Self {
        Self {
            args,
            stdin: None,
            env: Vec::new(),
            redact: true,
            timeout: None,
        }
    }

    fn unredacted(mut self) -> Self {
        self.redact = false;
        self
    }

    fn stdin(mut self, stdin: String) -> Self {
        self.stdin = Some(stdin);
        self
    }
}

struct Output {
    success: bool,
    stdout: String,
    stderr: String,
}

impl Output {
    fn failure(&self, show_stdout: bool) -> String {
        let stderr = self.stderr.trim();
        if stderr.is_empty() {
            if show_stdout && !self.stdout.trim().is_empty() {
                return self.stdout.trim().to_string();
            }
            return "rbw failed without an error message".to_string();
        }
        stderr.to_string()
    }
}

fn join_output(stdout: &str, stderr: &str) -> String {
    match (stdout.trim_end(), stderr.trim()) {
        (out, "") => out.to_string(),
        ("", err) => err.to_string(),
        (out, err) => format!("{out}\n\n{err}"),
    }
}

fn truncate(mut text: String) -> String {
    if text.len() > MAX_OUTPUT {
        let mut end = MAX_OUTPUT;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("\n… (output truncated; narrow the query)");
    }
    if text.is_empty() {
        text.push_str("ok");
    }
    text
}

struct Args<'a>(&'a Map<String, Value>);

impl Args<'_> {
    fn str(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(Value::as_str)
    }

    fn require(&self, key: &str) -> anyhow::Result<&str> {
        self.str(key).filter(|s| !s.is_empty()).ok_or_else(|| {
            anyhow::anyhow!("missing required argument `{key}`")
        })
    }

    fn bool(&self, key: &str) -> bool {
        self.0.get(key).and_then(Value::as_bool).unwrap_or(false)
    }

    fn u64(&self, key: &str) -> Option<u64> {
        self.0.get(key).and_then(Value::as_u64)
    }

    // A string or an array of strings.
    fn strs(&self, key: &str) -> Vec<String> {
        match self.0.get(key) {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn object(&self, key: &str) -> Option<&Map<String, Value>> {
        self.0.get(key).and_then(Value::as_object)
    }
}

fn account_args(args: &Args) -> Vec<String> {
    args.str("account")
        .filter(|a| !a.is_empty())
        .map(|a| vec!["--account".to_string(), a.to_string()])
        .unwrap_or_default()
}

fn flag(argv: &mut Vec<String>, args: &Args, key: &str, flag: &str) {
    if args.bool(key) {
        argv.push(flag.to_string());
    }
}

fn opt(argv: &mut Vec<String>, args: &Args, key: &str, flag: &str) {
    if let Some(value) = args.str(key).filter(|v| !v.is_empty()) {
        argv.push(flag.to_string());
        argv.push(value.to_string());
    }
}

// The entry-matching flags followed by the needles, after `--` so an entry
// name starting with `-` isn't taken for a flag.
fn selector_args(args: &Args, argv: &mut Vec<String>) -> anyhow::Result<()> {
    selector_flags(args, argv);
    let needles = args.strs("entry");
    anyhow::ensure!(
        !needles.is_empty(),
        "missing required argument `entry` (name, URI or UUID)"
    );
    argv.push("--".to_string());
    argv.extend(needles);
    Ok(())
}

fn selector_flags(args: &Args, argv: &mut Vec<String>) {
    opt(argv, args, "user", "--user");
    opt(argv, args, "folder", "--folder");
    opt(argv, args, "collection", "--collection");
    opt(argv, args, "org", "--org");
    flag(argv, args, "exact", "--exact");
    flag(argv, args, "ignorecase", "--ignorecase");
}

fn pwgen_args(args: &Args) -> super::PasswordGenArgs {
    super::PasswordGenArgs {
        length: args.u64("length").and_then(|l| usize::try_from(l).ok()),
        no_symbols: args.bool("no_symbols"),
        only_numbers: args.bool("only_numbers"),
        nonconfusables: args.bool("nonconfusables"),
        diceware: args.bool("diceware"),
    }
}

fn has_pwgen_args(args: &Args) -> bool {
    [
        "length",
        "no_symbols",
        "only_numbers",
        "nonconfusables",
        "diceware",
    ]
    .iter()
    .any(|k| args.0.contains_key(*k))
}

fn pwgen_flags(args: &Args, argv: &mut Vec<String>) {
    if let Some(length) = args.u64("length") {
        argv.push("--length".to_string());
        argv.push(length.to_string());
    }
    flag(argv, args, "no_symbols", "--no-symbols");
    flag(argv, args, "only_numbers", "--only-numbers");
    flag(argv, args, "nonconfusables", "--nonconfusables");
    flag(argv, args, "diceware", "--diceware");
}

fn generate_password(args: &Args) -> String {
    let (len, ty) = super::resolve_pwgen(&pwgen_args(args));
    rbw::pwgen::pwgen(ty, len)
}

// Writes a secret to a new 0600 file; the path is all that's reported.
fn write_secret_file(path: &str, secret: &str) -> anyhow::Result<String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    anyhow::ensure!(
        path != "-" && !path.is_empty(),
        "an output file path is required (not stdout)"
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| anyhow::anyhow!("couldn't write {path}: {e}"))?;
    // An existing file keeps its mode through `open`; tighten it.
    std::fs::set_permissions(
        path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;
    file.write_all(secret.as_bytes())?;
    Ok(format!(
        "wrote {} characters to {path} (mode 0600); use it as \"$(cat \
         {path})\" without printing it, and delete the file when done",
        secret.chars().count()
    ))
}

fn read_file(path: &str) -> anyhow::Result<String> {
    let mut contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("couldn't read {path}: {e}"))?;
    if contents.ends_with('\n') {
        contents.pop();
        if contents.ends_with('\r') {
            contents.pop();
        }
    }
    Ok(contents)
}

fn ensure_unmasked(value: &Value) -> anyhow::Result<()> {
    let masked = match value {
        Value::String(s) => s == MASKED_SECRET,
        Value::Array(values) => {
            return values.iter().try_for_each(ensure_unmasked);
        }
        Value::Object(map) => {
            return map.values().try_for_each(ensure_unmasked);
        }
        _ => false,
    };
    anyhow::ensure!(
        !masked,
        "refusing to store the redaction mask {MASKED_SECRET:?}; leave \
         fields you don't want to change out"
    );
    Ok(())
}

// A compact summary of a `list`/`search --json` entry, so listing a vault of
// thousands of entries stays readable.
fn summarize(entry: &Value) -> Value {
    let data = &entry["data"];
    let mut summary = Map::new();
    for key in ["id", "name", "folder", "account"] {
        if let Some(value) = entry.get(key).filter(|v| !v.is_null()) {
            summary.insert(key.to_string(), value.clone());
        }
    }
    if let Some(ty) = data.get("type").and_then(Value::as_str) {
        summary.insert("type".to_string(), json!(type_name(ty)));
    }
    if let Some(user) = data.get("username").filter(|v| !v.is_null()) {
        summary.insert("user".to_string(), user.clone());
    }
    if let Some(uris) = data.get("uris").and_then(Value::as_array) {
        let uris: Vec<&Value> = uris
            .iter()
            .filter_map(|u| u.get("uri"))
            .filter(|u| !u.is_null())
            .collect();
        if !uris.is_empty() {
            summary.insert("uris".to_string(), json!(uris));
        }
    }
    if data.get("totp").is_some_and(|t| !t.is_null()) {
        summary.insert("has_totp".to_string(), json!(true));
    }
    let attachments = entry
        .get("attachments")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if attachments > 0 {
        summary.insert("attachments".to_string(), json!(attachments));
    }
    for key in ["archived", "deleted"] {
        if entry.get(key).and_then(Value::as_bool) == Some(true) {
            summary.insert(key.to_string(), json!(true));
        }
    }
    if let Some(date) = entry.get("revision_date").filter(|v| !v.is_null()) {
        summary.insert("modified".to_string(), date.clone());
    }
    Value::Object(summary)
}

// `get --json` names types the way the API does; `edit --json` and `create`
// use snake case.
fn type_name(ty: &str) -> &str {
    match ty {
        "Login" => "login",
        "Card" => "card",
        "Identity" => "identity",
        "SecureNote" => "secure_note",
        "SshKey" => "ssh_key",
        other => other,
    }
}

// `list`/`search` fail when nothing matches; for a tool that is just an
// empty result.
fn no_match_is_empty(
    result: anyhow::Result<String>,
) -> anyhow::Result<Option<String>> {
    match result {
        Err(e) if format!("{e:#}").contains("no entries found") => Ok(None),
        other => other.map(Some),
    }
}

fn summarize_list(
    out: &str,
    limit: u64,
    full: bool,
) -> anyhow::Result<String> {
    let entries: Value = serde_json::from_str(out)?;
    let Value::Array(entries) = entries else {
        return Ok(out.to_string());
    };
    let total = entries.len();
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let shown: Vec<Value> = entries
        .iter()
        .take(limit)
        .map(|e| if full { e.clone() } else { summarize(e) })
        .collect();
    let mut result = json!({ "count": total, "entries": shown });
    if total > limit {
        result["truncated"] = json!(format!(
            "showing {limit} of {total}; narrow the query or raise `limit`"
        ));
    }
    Ok(serde_json::to_string_pretty(&result)?)
}

#[derive(Clone, Copy)]
enum Kind {
    Read,
    // Writes a local file but changes nothing in the vault.
    Local,
    Write,
    Destructive,
}

impl Kind {
    fn writes(self) -> bool {
        matches!(self, Self::Write | Self::Destructive)
    }

    fn annotations(self, name: &str) -> ToolAnnotations {
        ToolAnnotations::with_title(name)
            .read_only(matches!(self, Self::Read))
            .destructive(matches!(self, Self::Destructive))
            .idempotent(matches!(self, Self::Read | Self::Local))
            .open_world(false)
    }
}

struct Tool {
    name: &'static str,
    description: &'static str,
    kind: Kind,
    schema: fn() -> Value,
    handler: fn(&Server, &Args) -> anyhow::Result<String>,
}

fn schema(properties: &[(&str, Value)], required: &[&str]) -> Value {
    let mut props = Map::new();
    for (name, prop) in properties {
        props.insert((*name).to_string(), prop.clone());
    }
    props.insert(
        "account".to_string(),
        json!({
            "type": "string",
            "description": "Configured rbw account to use (see `status`); \
                default: the one holding the entry, or the primary",
        }),
    );
    json!({
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": false,
    })
}

fn string(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

fn boolean(description: &str) -> Value {
    json!({ "type": "boolean", "description": description })
}

fn integer(description: &str) -> Value {
    json!({ "type": "integer", "minimum": 1, "description": description })
}

fn strings(description: &str) -> Value {
    json!({
        "type": "array",
        "items": { "type": "string" },
        "description": description,
    })
}

fn selector_props() -> Vec<(&'static str, Value)> {
    vec![
        (
            "entry",
            json!({
                "anyOf": [
                    { "type": "string" },
                    { "type": "array", "items": { "type": "string" } },
                ],
                "description": "Entry name, URI or UUID; an array of terms \
                    must all match",
            }),
        ),
        ("user", string("Only match entries with this username")),
        ("folder", string("Only match entries in this folder")),
        (
            "collection",
            string("Only match entries in this collection"),
        ),
        ("org", string("Only match entries in this organization")),
        (
            "exact",
            boolean("Match the name exactly (no substring fallback)"),
        ),
        ("ignorecase", boolean("Match case-insensitively")),
    ]
}

fn with_selector(
    extra: Vec<(&'static str, Value)>,
) -> Vec<(&'static str, Value)> {
    let mut props = selector_props();
    props.extend(extra);
    props
}

fn pwgen_props() -> Vec<(&'static str, Value)> {
    vec![
        (
            "length",
            integer(
                "Password length (words with diceware); default from \
                the password_gen config, else 20",
            ),
        ),
        ("no_symbols", boolean("Letters and digits only")),
        ("only_numbers", boolean("Digits only")),
        ("nonconfusables", boolean("Avoid look-alike characters")),
        ("diceware", boolean("EFF word list passphrase")),
    ]
}

fn filter_props() -> Vec<(&'static str, Value)> {
    vec![
        (
            "collection",
            string("Only entries in this collection (name or ID)"),
        ),
        (
            "org",
            string("Only entries in this organization (name or ID)"),
        ),
        ("with_attachments", boolean("Only entries with attachments")),
        ("archived", boolean("Only archived entries")),
        ("include_archived", boolean("Include archived entries")),
        ("trashed", boolean("Only entries in the trash")),
        ("include_trashed", boolean("Include entries in the trash")),
        (
            "all_accounts",
            boolean(
                "Unlock (may prompt) and include every configured \
                account, not only the unlocked ones",
            ),
        ),
        (
            "limit",
            integer("Maximum number of entries to return (default 500)"),
        ),
        (
            "full",
            boolean(
                "Return the whole (redacted) entries instead of a \
                summary",
            ),
        ),
    ]
}

fn filter_flags(args: &Args, argv: &mut Vec<String>) {
    opt(argv, args, "collection", "--collection");
    opt(argv, args, "org", "--org");
    flag(argv, args, "with_attachments", "--with-attachments");
    flag(argv, args, "archived", "--archived");
    flag(argv, args, "include_archived", "--include-archived");
    flag(argv, args, "trashed", "--trashed");
    flag(argv, args, "include_trashed", "--include-trashed");
    flag(argv, args, "all_accounts", "--all");
}

static TOOLS: &[Tool] = &[
    Tool {
        name: "status",
        description: "Show rbw's accounts: which are logged in and \
            unlocked, server, entry counts and last sync.",
        kind: Kind::Read,
        schema: || schema(&[], &[]),
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.extend(["status", "--json"].map(String::from));
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "list",
        description: "List vault entries (id, name, type, user, folder, \
            URIs, account), optionally filtered by a term, collection, \
            organization, archive/trash state or age.",
        kind: Kind::Read,
        schema: || {
            let mut props = vec![
                ("term", string("Only entries matching this term")),
                (
                    "older_than",
                    string(
                        "Only entries last modified longer ago than \
                        this, e.g. 90d or 1year",
                    ),
                ),
            ];
            props.extend(filter_props());
            schema(&props, &[])
        },
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.extend(["list", "--json"].map(String::from));
            filter_flags(args, &mut argv);
            opt(&mut argv, args, "older_than", "--older-than");
            if let Some(term) = args.str("term").filter(|t| !t.is_empty()) {
                argv.extend(["--".to_string(), term.to_string()]);
            }
            let Some(out) = no_match_is_empty(server.shown(Cmd::new(argv)))?
            else {
                return Ok(r#"{"count": 0, "entries": []}"#.to_string());
            };
            summarize_list(
                &out,
                args.u64("limit").unwrap_or(DEFAULT_LIST_LIMIT),
                args.bool("full"),
            )
        },
    },
    Tool {
        name: "search",
        description: "Search entries by name, username, folder, URI or \
            notes, or find the logins saved for a web page (`url`).",
        kind: Kind::Read,
        schema: || {
            let mut props = vec![
                ("term", string("Search term")),
                (
                    "url",
                    string(
                        "Find logins for this page URL, the way the \
                        browser extension matches them",
                    ),
                ),
                ("folder", string("Only search this folder")),
            ];
            props.extend(filter_props());
            schema(&props, &[])
        },
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.extend(["search", "--json"].map(String::from));
            filter_flags(args, &mut argv);
            opt(&mut argv, args, "folder", "--folder");
            opt(&mut argv, args, "url", "--url");
            let term = args.str("term").filter(|t| !t.is_empty());
            anyhow::ensure!(
                term.is_some() || args.str("url").is_some(),
                "pass `term` or `url`"
            );
            if let Some(term) = term {
                argv.extend(["--".to_string(), term.to_string()]);
            }
            let Some(out) = no_match_is_empty(server.shown(Cmd::new(argv)))?
            else {
                return Ok(r#"{"count": 0, "entries": []}"#.to_string());
            };
            if args.str("url").is_some() {
                return Ok(out);
            }
            summarize_list(
                &out,
                args.u64("limit").unwrap_or(DEFAULT_LIST_LIMIT),
                args.bool("full"),
            )
        },
    },
    Tool {
        name: "get",
        description: "Show one entry: all its fields as JSON (secrets \
            masked), or the value of one `field` (username, uris, a custom \
            field name, ...). Lists the field names an entry has.",
        kind: Kind::Read,
        schema: || {
            schema(
                &with_selector(vec![
                    (
                        "field",
                        string(
                            "Only this field: username, password, totp, \
                            notes, uris, name, folder, a card/identity \
                            field or a custom field name",
                        ),
                    ),
                    (
                        "reveal",
                        boolean(
                            "Show secret values in plain text (needs \
                            a server started with --allow-secrets)",
                        ),
                    ),
                ]),
                &["entry"],
            )
        },
        handler: |server, args| {
            let reveal = server.reveal(args)?;
            let mut argv = account_args(args);
            argv.push("get".to_string());
            if let Some(field) = args.str("field").filter(|f| !f.is_empty()) {
                argv.extend(["--field".to_string(), field.to_string()]);
            } else {
                argv.push("--json".to_string());
            }
            selector_args(args, &mut argv)?;
            let mut cmd = Cmd::new(argv);
            cmd.redact = !reveal;
            server.shown(cmd)
        },
    },
    Tool {
        name: "history",
        description: "Show an entry's password history (dates; passwords \
            masked unless revealed).",
        kind: Kind::Read,
        schema: || {
            schema(
                &with_selector(vec![(
                    "reveal",
                    boolean("Show the old passwords (needs --allow-secrets)"),
                )]),
                &["entry"],
            )
        },
        handler: |server, args| {
            let reveal = server.reveal(args)?;
            let mut argv = account_args(args);
            argv.extend(["history", "--json"].map(String::from));
            selector_args(args, &mut argv)?;
            let mut cmd = Cmd::new(argv);
            cmd.redact = !reveal;
            server.shown(cmd)
        },
    },
    Tool {
        name: "code",
        description: "Show the current TOTP code of an entry (needs a \
            server started with --allow-secrets; otherwise use \
            `secret_to_file` with field `totp_code`).",
        kind: Kind::Read,
        schema: || schema(&selector_props(), &["entry"]),
        handler: |server, args| {
            anyhow::ensure!(
                server.allow_secrets,
                "`code` is disabled: this server was started without \
                 --allow-secrets. Use `secret_to_file` with field \
                 `totp_code`."
            );
            let mut argv = account_args(args);
            argv.push("code".to_string());
            selector_args(args, &mut argv)?;
            Ok(server.secret(argv)?.trim().to_string())
        },
    },
    Tool {
        name: "secret_to_file",
        description: "Write one secret of an entry (password by default, \
            any field, or the current TOTP code with field `totp_code`) to \
            a new 0600 file without returning it, so a shell command can \
            use it as \"$(cat FILE)\". Delete the file afterwards.",
        kind: Kind::Local,
        schema: || {
            schema(
                &with_selector(vec![
                    (
                        "field",
                        string(
                            "Field to write: password (default), \
                            username, totp (the seed), totp_code (the \
                            current code), notes, or a custom field",
                        ),
                    ),
                    (
                        "path",
                        string("File to write (created with mode 0600)"),
                    ),
                ]),
                &["entry", "path"],
            )
        },
        handler: |server, args| {
            let path = args.require("path")?;
            let field = args.str("field").unwrap_or("password");
            let mut argv = account_args(args);
            if field == "totp_code" {
                argv.push("code".to_string());
            } else {
                argv.extend(["get", "--field", field].map(String::from));
            }
            selector_args(args, &mut argv)?;
            let mut secret = server.secret(argv)?;
            if secret.ends_with('\n') {
                secret.pop();
            }
            write_secret_file(path, &secret)
        },
    },
    Tool {
        name: "generate",
        description: "Generate a password. It is written to `output_file` \
            (0600); it is only returned when the server allows secrets and \
            no file is given. To set an entry's password use `update` or \
            `create` with `generate`.",
        kind: Kind::Local,
        schema: || {
            let mut props = vec![(
                "output_file",
                string("File to write the password to (mode 0600)"),
            )];
            props.extend(pwgen_props());
            schema(&props, &[])
        },
        handler: |server, args| {
            let password = generate_password(args);
            if let Some(path) = args.str("output_file") {
                return write_secret_file(path, &password);
            }
            anyhow::ensure!(
                server.allow_secrets,
                "pass `output_file`: this server was started without \
                 --allow-secrets, so it doesn't return passwords"
            );
            Ok(password)
        },
    },
    Tool {
        name: "audit",
        description: "Report weak, reused and (with hibp) breached \
            passwords of the account's logins. Names entries, never \
            passwords.",
        kind: Kind::Read,
        schema: || {
            schema(
                &[
                    (
                        "min_bits",
                        integer(
                            "Flag passwords weaker than this many bits \
                            (default 60)",
                        ),
                    ),
                    (
                        "hibp",
                        boolean(
                            "Also check Have I Been Pwned (k-anonymity: \
                            only 5 hash characters leave the machine)",
                        ),
                    ),
                ],
                &[],
            )
        },
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.extend(["audit", "--json"].map(String::from));
            if let Some(bits) = args.u64("min_bits") {
                argv.extend(["--min-bits".to_string(), bits.to_string()]);
            }
            flag(&mut argv, args, "hibp", "--hibp");
            let mut cmd = Cmd::new(argv);
            if args.bool("hibp") {
                cmd.timeout = Some(std::time::Duration::from_secs(600));
            }
            server.shown(cmd)
        },
    },
    Tool {
        name: "create",
        description: "Create an entry: a login (default), secure_note, \
            card, identity or ssh_key. Pass secrets directly, read the \
            password from `password_file`, or `generate` one that is never \
            returned. Returns the new entry (masked).",
        kind: Kind::Write,
        schema: || {
            let mut props = vec![
                ("name", string("Entry name")),
                (
                    "type",
                    json!({
                        "type": "string",
                        "enum": ["login", "secure_note", "card", "identity", "ssh_key"],
                        "description": "Entry type (default login)",
                    }),
                ),
                ("folder", string("Folder (created if missing)")),
                ("notes", string("Notes")),
                ("username", string("Login username")),
                ("password", string("Login password")),
                (
                    "password_file",
                    string("Read the login password from this file"),
                ),
                (
                    "generate",
                    boolean(
                        "Generate the login password (see the length \
                        options); it is not returned",
                    ),
                ),
                (
                    "password_output_file",
                    string(
                        "With generate, also write the password to this \
                        file (mode 0600)",
                    ),
                ),
                ("uris", strings("Login URIs")),
                ("totp", string("Login TOTP secret or otpauth:// URI")),
                (
                    "data",
                    json!({
                        "type": "object",
                        "description": "Type-specific fields, as `rbw edit \
                            --json` names them: card {cardholder_name, \
                            number, brand, exp_month, exp_year, code}, \
                            identity {title, first_name, middle_name, \
                            last_name, address1..3, city, state, \
                            postal_code, country, phone, email, ssn, \
                            license_number, passport_number, username}, \
                            ssh_key {private_key, public_key, fingerprint}, \
                            login uris as [{uri, match_type}]",
                    }),
                ),
                (
                    "fields",
                    json!({
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "value": { "type": "string" },
                                "type": {
                                    "type": "string",
                                    "enum": ["text", "hidden", "boolean"],
                                },
                            },
                            "required": ["name"],
                        },
                        "description": "Custom fields; type defaults to \
                            hidden",
                    }),
                ),
            ];
            props.extend(pwgen_props());
            schema(&props, &["name"])
        },
        handler: create,
    },
    Tool {
        name: "update",
        description: "Change fields of an existing entry: name, username, \
            password (given, from a file, or generated), notes, URIs, TOTP, \
            custom fields, attachments. Only what you pass changes; the old \
            password goes to the history. Returns a masked diff.",
        kind: Kind::Write,
        schema: || {
            let mut props = with_selector(vec![
                ("name", string("New entry name")),
                ("username", string("New username")),
                ("password", string("New password")),
                (
                    "password_file",
                    string("Read the new password from this file"),
                ),
                (
                    "generate",
                    boolean(
                        "Generate a new password (see the length \
                        options); it is not returned",
                    ),
                ),
                (
                    "password_output_file",
                    string(
                        "With generate, write the new password to this \
                        file (mode 0600) after it was saved",
                    ),
                ),
                ("notes", string("New notes (empty string clears them)")),
                ("uris", strings("Replace the login URIs")),
                ("totp", string("New TOTP secret or otpauth:// URI")),
                (
                    "totp_file",
                    string("Read the new TOTP secret from this file"),
                ),
                (
                    "fields",
                    json!({
                        "type": "object",
                        "additionalProperties": { "type": "string" },
                        "description": "Custom fields to set, name -> value \
                            (an existing field keeps its type, a new one is \
                            hidden)",
                    }),
                ),
                (
                    "field_files",
                    json!({
                        "type": "object",
                        "additionalProperties": { "type": "string" },
                        "description": "Custom fields to set from files, \
                            name -> path",
                    }),
                ),
                ("attachments", strings("Files to attach")),
                (
                    "if_revision",
                    string(
                        "Only update if the entry's revision_date still \
                        equals this (optimistic locking)",
                    ),
                ),
                (
                    "bulk",
                    boolean(
                        "Apply to every entry each `entry` term \
                        matches",
                    ),
                ),
            ]);
            props.extend(pwgen_props());
            schema(&props, &["entry"])
        },
        handler: update,
    },
    Tool {
        name: "edit",
        description: "Change any part of an entry with a JSON merge patch \
            (RFC 7396) against its `rbw edit --json` form {name, folder, \
            notes, data: {type, ...}, fields: [{name, value, type}]}: \
            objects merge, null removes a key, arrays (fields, uris) are \
            replaced whole. Use it for card, identity and SSH key fields, \
            removing custom fields or changing the type. Secrets you leave \
            out are kept; masked values are refused.",
        kind: Kind::Write,
        schema: || {
            schema(
                &with_selector(vec![(
                    "patch",
                    json!({
                        "type": "object",
                        "description": "JSON merge patch, e.g. {\"data\": \
                            {\"exp_year\": \"2030\"}} or {\"folder\": null}",
                    }),
                )]),
                &["entry", "patch"],
            )
        },
        handler: |server, args| {
            let patch =
                args.0.get("patch").filter(|p| p.is_object()).ok_or_else(
                    || anyhow::anyhow!("`patch` must be an object"),
                )?;
            ensure_unmasked(patch)?;
            let entry = server.find(args)?;
            let id = entry["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("entry without an id"))?
                .to_string();
            let mut argv = account_args(args);
            argv.extend(["edit", "--patch", "--", &id].map(String::from));
            server.shown(Cmd::new(argv).stdin(patch.to_string()))?;
            server.entry_by_id(args, &id)
        },
    },
    Tool {
        name: "delete",
        description: "Move an entry to the trash (undo with `restore`), or \
            delete it permanently with `permanent` (cannot be undone).",
        kind: Kind::Destructive,
        schema: || {
            schema(
                &with_selector(vec![(
                    "permanent",
                    boolean(
                        "Delete permanently instead of trashing; also \
                        purges an entry that is already in the trash",
                    ),
                )]),
                &["entry"],
            )
        },
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.extend(["remove", "--yes"].map(String::from));
            flag(&mut argv, args, "permanent", "--force");
            selector_args(args, &mut argv)?;
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "restore",
        description: "Restore an entry from the trash.",
        kind: Kind::Write,
        schema: || bulk_schema(),
        handler: |server, args| simple_bulk(server, args, "restore"),
    },
    Tool {
        name: "archive",
        description: "Archive an entry (hidden from list/search unless \
            archived entries are asked for).",
        kind: Kind::Write,
        schema: || bulk_schema(),
        handler: |server, args| simple_bulk(server, args, "archive"),
    },
    Tool {
        name: "unarchive",
        description: "Unarchive an entry.",
        kind: Kind::Write,
        schema: || bulk_schema(),
        handler: |server, args| simple_bulk(server, args, "unarchive"),
    },
    Tool {
        name: "history_restore",
        description: "Make a previous password of an entry current again \
            (e.g. to roll back a rotation); the replaced one moves to the \
            history.",
        kind: Kind::Write,
        schema: || {
            schema(
                &with_selector(vec![(
                    "index",
                    integer(
                        "Which previous password, 1 = most recent \
                        (default)",
                    ),
                )]),
                &["entry"],
            )
        },
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.extend([
                "history".to_string(),
                format!("--restore={}", args.u64("index").unwrap_or(1)),
                "--yes".to_string(),
            ]);
            selector_args(args, &mut argv)?;
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "move",
        description: "Move or copy an entry to another configured account \
            (attachments included). The original goes to the trash \
            (`original: trash`, default), is deleted (`delete`) or kept \
            (`keep`, a copy).",
        kind: Kind::Write,
        schema: || {
            schema(
                &with_selector(vec![
                    ("to", string("Destination account")),
                    (
                        "original",
                        json!({
                            "type": "string",
                            "enum": ["trash", "delete", "keep"],
                            "description": "What happens to the original \
                                (default trash)",
                        }),
                    ),
                    ("no_attachments", boolean("Don't copy attachments")),
                ]),
                &["entry", "to"],
            )
        },
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.extend([
                "move".to_string(),
                "--yes".to_string(),
                "--to".to_string(),
                args.require("to")?.to_string(),
            ]);
            match args.str("original").unwrap_or("trash") {
                "trash" => argv.push("--trash".to_string()),
                "delete" => argv.push("--delete".to_string()),
                "keep" => argv.push("--keep".to_string()),
                other => anyhow::bail!("unknown `original` {other:?}"),
            }
            flag(&mut argv, args, "no_attachments", "--no-attachments");
            selector_args(args, &mut argv)?;
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "attachment_list",
        description: "List an entry's attachments (id, file name, size).",
        kind: Kind::Read,
        schema: || schema(&selector_props(), &["entry"]),
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.extend(["attachment", "list", "--json"].map(String::from));
            selector_args(args, &mut argv)?;
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "attachment_download",
        description: "Download and decrypt an attachment to a local file \
            or directory (contents are not returned).",
        kind: Kind::Local,
        schema: || {
            schema(
                &with_selector(vec![
                    (
                        "attachment",
                        string(
                            "Attachment id or file name; may be omitted \
                            when the entry has only one",
                        ),
                    ),
                    ("output", string("Output file or directory")),
                ]),
                &["entry", "output"],
            )
        },
        handler: |server, args| {
            let output = args.require("output")?;
            anyhow::ensure!(output != "-", "`output` must be a path");
            let mut argv = account_args(args);
            argv.extend(
                ["attachment", "get", "--output", output].map(String::from),
            );
            opt(&mut argv, args, "attachment", "--attachment");
            selector_args(args, &mut argv)?;
            server.shown(Cmd::new(argv).unredacted())
        },
    },
    Tool {
        name: "attachment_upload",
        description: "Upload a local file as an attachment of an entry.",
        kind: Kind::Write,
        schema: || {
            let mut props = selector_props();
            props.retain(|(k, _)| !matches!(*k, "collection" | "org"));
            props.push(("file", string("File to attach")));
            schema(&props, &["entry", "file"])
        },
        handler: |server, args| {
            let file = args.require("file")?.to_string();
            let mut argv = account_args(args);
            argv.extend(["attachment", "create"].map(String::from));
            opt(&mut argv, args, "user", "--user");
            opt(&mut argv, args, "folder", "--folder");
            flag(&mut argv, args, "exact", "--exact");
            flag(&mut argv, args, "ignorecase", "--ignorecase");
            let needles = args.strs("entry");
            anyhow::ensure!(!needles.is_empty(), "missing `entry`");
            argv.push("--".to_string());
            argv.extend(needles);
            argv.push(file);
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "attachment_delete",
        description: "Delete an attachment from an entry.",
        kind: Kind::Destructive,
        schema: || {
            schema(
                &with_selector(vec![(
                    "attachment",
                    string(
                        "Attachment id or file name; may be omitted when \
                        the entry has only one",
                    ),
                )]),
                &["entry"],
            )
        },
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.extend(["attachment", "rm", "--yes"].map(String::from));
            opt(&mut argv, args, "attachment", "--attachment");
            selector_args(args, &mut argv)?;
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "collections",
        description: "List the organization collections the account can \
            see.",
        kind: Kind::Read,
        schema: || schema(&[], &[]),
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.extend(["collection", "list", "--json"].map(String::from));
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "collection_assign",
        description: "Assign an entry to organization collections (moving \
            a personal entry into the organization), or with `remove` take \
            it out of them.",
        kind: Kind::Write,
        schema: || {
            let mut props = selector_props();
            props.retain(|(k, _)| !matches!(*k, "collection" | "org"));
            props.extend([
                ("collections", strings("Collection names or IDs")),
                (
                    "remove",
                    boolean("Unassign from these collections instead"),
                ),
                (
                    "bulk",
                    boolean(
                        "Apply to every entry each `entry` term \
                        matches",
                    ),
                ),
            ]);
            schema(&props, &["entry", "collections"])
        },
        handler: |server, args| {
            let collections = args.strs("collections");
            anyhow::ensure!(!collections.is_empty(), "missing `collections`");
            let mut argv = account_args(args);
            argv.push("collection".to_string());
            argv.push(
                if args.bool("remove") {
                    "unassign"
                } else {
                    "assign"
                }
                .to_string(),
            );
            argv.push("--yes".to_string());
            for collection in collections {
                argv.extend(["--collection".to_string(), collection]);
            }
            flag(&mut argv, args, "bulk", "--bulk");
            opt(&mut argv, args, "user", "--user");
            opt(&mut argv, args, "folder", "--folder");
            flag(&mut argv, args, "exact", "--exact");
            flag(&mut argv, args, "ignorecase", "--ignorecase");
            let needles = args.strs("entry");
            anyhow::ensure!(!needles.is_empty(), "missing `entry`");
            argv.push("--".to_string());
            argv.extend(needles);
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "sync",
        description: "Fetch the latest vault from the server.",
        kind: Kind::Read,
        schema: || {
            schema(
                &[(
                    "all_accounts",
                    boolean("Unlock (may prompt) and sync every account"),
                )],
                &[],
            )
        },
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.push("sync".to_string());
            flag(&mut argv, args, "all_accounts", "--all");
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "unlock",
        description: "Unlock the vault. This may show a password prompt, \
            fingerprint or phone confirmation to the user, so it can take \
            minutes; it never takes a password from the agent.",
        kind: Kind::Read,
        schema: || {
            schema(
                &[(
                    "all_accounts",
                    boolean("Unlock every configured account"),
                )],
                &[],
            )
        },
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.push("unlock".to_string());
            flag(&mut argv, args, "all_accounts", "--all");
            let mut cmd = Cmd::new(argv);
            cmd.timeout = Some(std::time::Duration::from_secs(330));
            server.shown(cmd)
        },
    },
    Tool {
        name: "lock",
        description: "Lock the vault (the selected account, or all).",
        kind: Kind::Read,
        schema: || {
            schema(&[("all_accounts", boolean("Lock every account"))], &[])
        },
        handler: |server, args| {
            let mut argv = account_args(args);
            argv.push("lock".to_string());
            flag(&mut argv, args, "all_accounts", "--all");
            server.shown(Cmd::new(argv))
        },
    },
    Tool {
        name: "rbw",
        description: "Run any other rbw command line, redacted, e.g. \
            [\"send\", \"list\", \"--json\"], [\"org\", \"list\"], \
            [\"collection\", \"create\", ...], [\"config\", \"show\"], \
            [\"export-info\"]. Pass `-y` where a command confirms. Commands \
            that only print secrets refuse; interactive ones (tui, run, \
            login) are not available.",
        kind: Kind::Destructive,
        schema: || {
            schema(
                &[
                    ("args", strings("Arguments after `rbw`")),
                    ("stdin", string("Text to pass on stdin")),
                ],
                &["args"],
            )
        },
        handler: |server, args| {
            let argv = args.strs("args");
            let command = argv
                .iter()
                .find(|a| !a.starts_with('-'))
                .map_or("", String::as_str);
            anyhow::ensure!(
                !matches!(
                    command,
                    "mcp"
                        | "tui"
                        | "ui"
                        | "run"
                        | "native-messaging"
                        | "login"
                        | "register"
                        | "agent"
                        | "stop-agent"
                        | "secret-service"
                        | "termux"
                ),
                "`rbw {command}` is not available through MCP"
            );
            anyhow::ensure!(
                !argv.iter().any(|a| matches!(
                    a.as_str(),
                    "--insecure" | "--clipboard" | "-c" | "--fzf"
                )),
                "interactive or secret-printing flags are not available \
                 through MCP"
            );
            let mut full = account_args(args);
            full.extend(argv);
            let mut cmd = Cmd::new(full);
            if let Some(stdin) = args.str("stdin") {
                cmd.stdin = Some(stdin.to_string());
            }
            server.shown(cmd)
        },
    },
];

fn bulk_schema() -> Value {
    schema(
        &with_selector(vec![(
            "bulk",
            boolean("Apply to every entry each `entry` term matches"),
        )]),
        &["entry"],
    )
}

fn simple_bulk(
    server: &Server,
    args: &Args,
    command: &str,
) -> anyhow::Result<String> {
    let mut argv = account_args(args);
    argv.extend([command.to_string(), "--yes".to_string()]);
    flag(&mut argv, args, "bulk", "--bulk");
    selector_args(args, &mut argv)?;
    server.shown(Cmd::new(argv))
}

fn create(server: &Server, args: &Args) -> anyhow::Result<String> {
    let name = args.require("name")?;
    let ty = args.str("type").unwrap_or("login");
    let mut data = args.object("data").cloned().unwrap_or_default();
    data.insert("type".to_string(), json!(ty));
    let login_only = [
        "username",
        "password",
        "password_file",
        "generate",
        "uris",
        "totp",
    ];
    if ty != "login" {
        if let Some(key) =
            login_only.iter().find(|k| args.0.contains_key(**k))
        {
            anyhow::bail!("`{key}` only applies to logins");
        }
    }
    if let Some(username) = args.str("username") {
        data.insert("username".to_string(), json!(username));
    }
    if let Some(totp) = args.str("totp") {
        data.insert("totp".to_string(), json!(totp));
    }
    let uris = args.strs("uris");
    if !uris.is_empty() {
        let uris: Vec<Value> =
            uris.iter().map(|u| json!({ "uri": u })).collect();
        data.insert("uris".to_string(), json!(uris));
    }
    let sources = [
        args.0.contains_key("password"),
        args.0.contains_key("password_file"),
        args.bool("generate"),
    ];
    anyhow::ensure!(
        sources.iter().filter(|s| **s).count() <= 1,
        "pass only one of `password`, `password_file` and `generate`"
    );
    anyhow::ensure!(
        args.bool("generate") || !has_pwgen_args(args),
        "the length options need `generate`"
    );
    let mut generated = None;
    if let Some(password) = args.str("password") {
        data.insert("password".to_string(), json!(password));
    } else if let Some(path) = args.str("password_file") {
        data.insert("password".to_string(), json!(read_file(path)?));
    } else if args.bool("generate") {
        let password = generate_password(args);
        data.insert("password".to_string(), json!(password));
        generated = Some(password);
    }

    let mut entry = Map::new();
    entry.insert("name".to_string(), json!(name));
    if let Some(folder) = args.str("folder").filter(|f| !f.is_empty()) {
        entry.insert("folder".to_string(), json!(folder));
    }
    if let Some(notes) = args.str("notes") {
        entry.insert("notes".to_string(), json!(notes));
    } else if ty == "secure_note" {
        entry.insert("notes".to_string(), json!(""));
    }
    entry.insert("data".to_string(), Value::Object(data));
    if let Some(fields) = args.0.get("fields").and_then(Value::as_array) {
        let fields: Vec<Value> = fields
            .iter()
            .map(|f| {
                let mut f = f.clone();
                if f.get("type").is_none() {
                    f["type"] = json!("hidden");
                }
                f
            })
            .collect();
        entry.insert("fields".to_string(), json!(fields));
    }
    let entry = Value::Object(entry);
    ensure_unmasked(&entry)?;

    let mut argv = account_args(args);
    argv.extend(["add", "--json"].map(String::from));
    let out = server.shown(Cmd::new(argv).stdin(entry.to_string()))?;
    let mut report = Vec::new();
    if let (Some(path), Some(password)) =
        (args.str("password_output_file"), generated.as_deref())
    {
        report.push(write_secret_file(path, password)?);
    }
    // Show what was stored, found the way `get` would find it.
    let mut find = account_args(args);
    find.extend(["get", "--json", "--exact"].map(String::from));
    if let Some(user) = args.str("username").filter(|u| !u.is_empty()) {
        find.extend(["--user".to_string(), user.to_string()]);
    }
    if let Some(folder) = args.str("folder").filter(|f| !f.is_empty()) {
        find.extend(["--folder".to_string(), folder.to_string()]);
    }
    find.extend(["--".to_string(), name.to_string()]);
    match server.shown(Cmd::new(find)) {
        Ok(created) => report.insert(0, created),
        Err(e) => report.insert(
            0,
            format!(
                "{}created (couldn't show it: {e:#})",
                with_newline(&out)
            ),
        ),
    }
    Ok(report.join("\n\n"))
}

fn with_newline(text: &str) -> String {
    if text.is_empty() {
        String::new()
    } else {
        format!("{text}\n")
    }
}

fn update(server: &Server, args: &Args) -> anyhow::Result<String> {
    let mut argv = account_args(args);
    argv.extend(["set", "--yes", "--diff"].map(String::from));
    let mut env = Vec::new();
    opt(&mut argv, args, "name", "--name");
    opt(&mut argv, args, "username", "--username");
    let sources = [
        args.0.contains_key("password"),
        args.0.contains_key("password_file"),
        args.bool("generate"),
    ];
    anyhow::ensure!(
        sources.iter().filter(|s| **s).count() <= 1,
        "pass only one of `password`, `password_file` and `generate`"
    );
    anyhow::ensure!(
        args.bool("generate") || !has_pwgen_args(args),
        "the length options need `generate`"
    );
    if let Some(password) = args.str("password") {
        ensure_unmasked(&json!(password))?;
        env.push(("RBW_MCP_PASSWORD".to_string(), password.to_string()));
        argv.extend(["--password-env", "RBW_MCP_PASSWORD"].map(String::from));
    }
    opt(&mut argv, args, "password_file", "--password-file");
    if args.bool("generate") {
        argv.push("--generate".to_string());
        pwgen_flags(args, &mut argv);
        opt(&mut argv, args, "password_output_file", "--output-file");
    } else {
        anyhow::ensure!(
            args.str("password_output_file").is_none(),
            "`password_output_file` needs `generate`"
        );
    }
    if let Some(notes) = args.str("notes") {
        ensure_unmasked(&json!(notes))?;
        argv.extend(["--notes".to_string(), notes.to_string()]);
    }
    for uri in args.strs("uris") {
        argv.extend(["--uri".to_string(), uri]);
    }
    if let Some(totp) = args.str("totp") {
        ensure_unmasked(&json!(totp))?;
        env.push(("RBW_MCP_TOTP".to_string(), totp.to_string()));
        argv.extend(["--totp-env", "RBW_MCP_TOTP"].map(String::from));
    }
    opt(&mut argv, args, "totp_file", "--totp-file");
    if let Some(fields) = args.object("fields") {
        for (i, (name, value)) in fields.iter().enumerate() {
            let value = value.as_str().ok_or_else(|| {
                anyhow::anyhow!("field {name:?} must be a string")
            })?;
            ensure_unmasked(&json!(value))?;
            let var = format!("RBW_MCP_FIELD_{i}");
            env.push((var.clone(), value.to_string()));
            argv.extend(["--field-env".to_string(), format!("{name}={var}")]);
        }
    }
    if let Some(files) = args.object("field_files") {
        for (name, path) in files {
            let path = path.as_str().ok_or_else(|| {
                anyhow::anyhow!("field {name:?} must be a path")
            })?;
            argv.extend([
                "--field-file".to_string(),
                format!("{name}={path}"),
            ]);
        }
    }
    for attachment in args.strs("attachments") {
        argv.extend(["--attachment".to_string(), attachment]);
    }
    opt(&mut argv, args, "if_revision", "--if-revision");
    flag(&mut argv, args, "bulk", "--bulk");
    selector_args(args, &mut argv)?;
    let mut cmd = Cmd::new(argv);
    cmd.env = env;
    server.shown(cmd)
}

#[cfg(test)]
mod test {
    use super::*;

    fn args(value: &Value) -> Args<'_> {
        Args(value.as_object().unwrap())
    }

    #[test]
    fn selector_puts_needles_after_double_dash() {
        let value = json!({
            "entry": ["--length", "x"],
            "user": "bob",
            "exact": true,
        });
        let mut argv = vec![];
        selector_args(&args(&value), &mut argv).unwrap();
        assert_eq!(argv, ["--user", "bob", "--exact", "--", "--length", "x"]);
    }

    #[test]
    fn selector_requires_an_entry() {
        let value = json!({ "user": "bob" });
        assert!(selector_args(&args(&value), &mut vec![]).is_err());
    }

    #[test]
    fn masked_values_are_refused() {
        assert!(ensure_unmasked(
            &json!({ "data": { "password": MASKED_SECRET } })
        )
        .is_err());
        assert!(
            ensure_unmasked(&json!({ "fields": [{ "value": "x" }] })).is_ok()
        );
    }

    #[test]
    fn summary_keeps_metadata_only() {
        let entry = json!({
            "id": "1",
            "name": "n",
            "folder": null,
            "data": {
                "type": "Login",
                "username": "u",
                "password": MASKED_SECRET,
                "totp": MASKED_SECRET,
                "uris": [{ "uri": "https://x", "match_type": null }],
            },
            "notes": MASKED_SECRET,
            "attachments": [],
            "archived": false,
            "deleted": false,
            "revision_date": "2026-01-01T00:00:00Z",
        });
        assert_eq!(
            summarize(&entry),
            json!({
                "id": "1",
                "name": "n",
                "type": "login",
                "user": "u",
                "uris": ["https://x"],
                "has_totp": true,
                "modified": "2026-01-01T00:00:00Z",
            })
        );
    }

    #[test]
    fn list_is_limited() {
        let out = json!([
            { "id": "1", "data": { "type": "SecureNote" } },
            { "id": "2", "data": { "type": "SecureNote" } },
        ])
        .to_string();
        let result: Value =
            serde_json::from_str(&summarize_list(&out, 1, false).unwrap())
                .unwrap();
        assert_eq!(result["count"], 2);
        assert_eq!(result["entries"].as_array().unwrap().len(), 1);
        assert!(result["truncated"].is_string());
    }

    #[test]
    fn read_only_hides_writes() {
        let server = Server {
            exe: "rbw".into(),
            allow_secrets: false,
            read_only: true,
            timeout: std::time::Duration::from_secs(1),
        };
        let names: Vec<String> = server
            .tool_list()
            .iter()
            .map(|t| t.name.to_string())
            .collect();
        assert!(names.contains(&"get".to_string()));
        assert!(!names.contains(&"update".to_string()));
        assert!(!names.contains(&"rbw".to_string()));
    }

    #[test]
    fn info_advertises_tools() {
        let server = Server {
            exe: "rbw".into(),
            allow_secrets: false,
            read_only: true,
            timeout: std::time::Duration::from_secs(1),
        };
        let info = rmcp::ServerHandler::get_info(&server);
        assert!(info.capabilities.tools.is_some());
        assert_eq!(info.server_info.name, "rbw");
        assert!(info.instructions.unwrap().contains("read-only"));
    }

    #[test]
    fn every_tool_schema_is_an_object() {
        for tool in TOOLS {
            let schema = (tool.schema)();
            assert_eq!(schema["type"], "object", "{}", tool.name);
            for required in schema["required"].as_array().unwrap() {
                assert!(
                    schema["properties"]
                        .get(required.as_str().unwrap())
                        .is_some(),
                    "{} requires an undeclared {required}",
                    tool.name
                );
            }
        }
    }
}
