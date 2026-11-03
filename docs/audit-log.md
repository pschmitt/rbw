# Audit log

rbw records a local security audit log by default. Disable it with
`audit.enabled: false`, or set `audit.retentionDays` to a value from 1 to
3650. The default retention is 15 calendar days. For example:

```yaml
audit:
  enabled: true
  retentionDays: 30
```

The log is stored under rbw's profile-specific data directory as daily JSONL
files (`audit-<UTC-day>.jsonl`). The directory is mode `0700`; the lock and log
files are mode `0600`. Expired daily files are removed when rbw writes the
next event. Events include a UTC timestamp, actor, operation, and outcome.

## What is recorded

The CLI records one event when a supported operation finishes. This includes
vault reads (`get`, `show`, `list`, `search`, `code`, exports, history and
attachments), writes (item, collection and organization changes, imports and
purges), and account access operations (`login`, `unlock`, `lock`, `status`,
`sync`). Configuration mutations (`config set`, `config unset`, and `config edit`)
are recorded using only the fixed operation label, never the changed key or
value. `rbw api` management commands are also recorded. The actor is `cli`;
the operation is the command name, and the outcome is `success` or `failure`.
The audit record does not include the selected account or command arguments.

The remote API records each status and field-read request handled after a
successful TLS handshake, including denied and failed requests. It identifies
a registered client by its rbw client ID, or an unregistered certificate by
its fingerprint. TLS handshake failures occur before an HTTP request reaches
the handler and are not recorded. Outcomes use stable API error categories. A
field-read event includes the target item UUID only when the route value is
already a canonical UUID. Item names, arbitrary path tokens, field names,
field values, request paths, and raw errors are not recorded.

Browser native-messaging requests are recorded individually. Their actor is
the configured browser client name, and operations use fixed labels such as
`browser.credential`, `browser.copy`, and `browser.passkey_get`. Canonical item
UUIDs are included when available; browser-supplied names and all request
content are omitted.

SSH-agent identity-list and signing requests are also recorded, with the actor
`ssh-agent` and fixed operation/outcome labels. The requested key, signing
payload, and signature are not included.

The rbw agent records timeout locks and periodic/server-notified syncs with
the actor `agent`. A sync event reports success only when every configured
account sync completes successfully; it does not include account names.

## Why the vault was locked

Every way the agent drops its keys leaves an event, so the log can say why
the vault is locked. `rbw status` shows the most recent one as "last lock"
while an account is locked (`last_lock` in `rbw status --json`).

| Operation | Actor | Meaning |
|---|---|---|
| `agent.timeout_lock` | `agent` | The idle timeout (`agent.lockTimeout`) locked every account. |
| `agent.server_logout` | `agent` | The server sent a logout notification. |
| `agent.key_rotation_lock` | `agent` | A key rotation (`rbw security rotate-key`, `change-password --rotate-key`) dropped the old key. |
| `socket.lock` | `local-agent-socket` | `rbw lock`; `reason` is `one_account` or `all_accounts`, `client` the program that asked. |
| `agent.start` | `agent` | The agent started, with no keys; `version` is its rbw version. |
| `agent.stop` | `agent` or `local-agent-socket` | The agent stopped; `reason` says why, `version` is its rbw version, `client` the program that asked. |

The `agent.stop` reasons are fixed labels:

- `stop_agent`: `rbw stop-agent` or `rbw agent stop`.
- `outdated`: a newer client (`rbw`, `rbw-browser`) replaced an older agent.
- `unresponsive`: a client could not get the agent's version and replaced it.
- `config_change`: the configuration or the primary account changed.
- `native_unlock_change`: a native unlock setting changed.
- `purge`: `rbw purge`.
- `sigterm`, `sigint`, `sighup`: a signal, such as a service stop or restart
  or a reboot.
- `unspecified`: a quit request from an rbw older than 2.43; `other`: a reason
  this agent doesn't know.

On Linux, `client` names the program on the other end of the agent socket:
the Nix package and path of its binary (`rbw-2.40.0/bin/rbw`), or the
binary's file name. It shows which program stopped or locked the agent,
such as a long-running MCP server still running an old rbw.

`SIGKILL` and crashes can't be recorded. An `agent.start` without an
`agent.stop` before it shows that the previous agent ended that way (or ran
an rbw older than 2.43).

Local MCP tools run the rbw CLI as a subprocess, so their operations are
recorded at the CLI boundary. Policy-only MCP field reads use the remote API
and are recorded there.

Audit events never contain passwords, TOTP values or seeds, notes, item names,
full command lines, or raw error messages. If writing an event fails, rbw
reports a warning and continues the requested operation.

## Coverage limits

The CLI records one event per top-level operation, including no-match search/list
results and nonzero `rbw run` child exits, not each item touched by a bulk
command or each screen action in a TUI session. CLI commands rejected during
argument parsing or account selection before dispatch do not get an event. Local
socket requests are logged only after their action type has been decoded.
Direct local agent-socket requests that dispatch a vault or key operation are
recorded with actor `local-agent-socket`, a fixed action label and outcome,
without payloads, item IDs or caller-supplied strings. The socket has no caller
identity, so these events identify only the local agent boundary. Frequent lock-state probes and version
queries are omitted; the quit action is recorded as `agent.stop`. Connections and malformed requests
that fail before an action can be classified are not recorded; normal CLI
operations that use the socket are also covered at the CLI boundary, while
agent-initiated timeout locks and background syncs are recorded. TLS handshakes
rejected before the remote API handler are also not recorded.
