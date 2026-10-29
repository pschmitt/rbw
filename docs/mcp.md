# MCP server

`rbw mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io)
server on stdin and stdout, so an AI agent (Claude Code, Codex, ...) can work
with the vault without a shell. It uses the same agent, accounts and
configuration as the CLI.

```sh
claude mcp add rbw -- rbw mcp
```

With Home Manager, `programs.rbw.mcp.enable = true;` registers it
as `programs.mcp.servers.rbw` (see [Nix](nix.md)).

## Tools

| Tool | Does |
|---|---|
| `status` | Accounts: logged in, unlocked, server, counts, last sync |
| `list`, `search` | Entry summaries (id, name, type, user, folder, URIs); `search` also finds the logins for a page `url` |
| `get` | One entry as JSON, or one `field` |
| `history`, `history_restore` | Password history, and making an old password current again |
| `create` | A login, secure note, card, identity or SSH key; `generate` makes its password |
| `update` | `rbw set`: name, username, password, notes, URIs, TOTP, custom fields, attachments, `if_revision` |
| `edit` | A JSON merge patch against the `rbw edit --json` form (`rbw edit --patch`), for any field of any type |
| `delete`, `restore` | To the trash and back; `permanent` deletes for good |
| `archive`, `unarchive` | |
| `move` | To another configured account (or a copy) |
| `attachment_list`, `attachment_upload`, `attachment_download`, `attachment_delete` | |
| `collections`, `collection_assign` | Organization collections |
| `secret_to_file` | Write one secret (or the current TOTP code) to a 0600 file |
| `generate` | A password, written to a file |
| `audit` | Weak, reused and breached passwords |
| `sync`, `unlock`, `lock` | |
| `rbw` | Any other rbw command line, redacted (sends, orgs, config, export-info, ...) |

Entries are matched like `rbw get`: `entry` is a name, URI or UUID (or a list of
terms), narrowed by `user`, `folder`, `collection`, `org`, `exact`. Every tool
takes `account`.

## Secrets

The agent's context is a transcript, so secrets stay out of it by default:

- Every command runs with `--redact`: passwords, TOTP seeds, notes, hidden
  fields, card numbers and keys show as `••••••••`, also in the `update` diff.
- Values the agent sets reach rbw through its environment or stdin, never its
  command line, and the mask itself is refused, so a redacted entry can't be
  written back.
- `secret_to_file`, `generate` and `attachment_download` write the secret to a
  file and only report its size; the agent then uses it as `"$(cat FILE)"`.

Options:

- `--allow-secrets` lets `get`, `history` and `code` return plain text when a
  call passes `reveal: true`, and `generate` return the password.
- `--read-only` only offers the tools that don't change the vault.
- `--timeout SECONDS` limits each rbw command a tool runs (default 120; `unlock`
  waits up to 330 s for a prompt to be answered).

The interactive commands (`tui`, `run`, `login`, ...) aren't available through
the `rbw` tool, and neither are `--insecure`, `--clipboard` and `--fzf`.
