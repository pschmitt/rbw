# rbw

This is an unofficial command line client for
[Bitwarden](https://bitwarden.com/). Although Bitwarden does come with its own
[command line client](https://help.bitwarden.com/article/cli/), it is
limited by being stateless - to use it, you're required to manually lock and
unlock the client, and pass the temporary keys around in environment variables,
which makes it very difficult to use. `rbw` avoids this problem by
maintaining a background process which is able to hold the keys in memory,
similar to the way that `ssh-agent` or `gpg-agent` work. This allows the client
to be used in a much simpler way, with the background agent taking care of
maintaining the necessary state.

## Maintenance

I consider `rbw` to be essentially feature-complete for me at this point. While
I still use it on a daily basis, and will continue to fix regressions as they
occur, I am unlikely to spend time implementing new features on my own. If you
would like to see new functionality in `rbw`, I am more than happy to review
and merge pull requests implementing those features.

## Installation

### Arch Linux

`rbw` is available in the [extra
repository](https://archlinux.org/packages/extra/x86_64/rbw/).
Alternatively, you can install
[`rbw-git`](https://aur.archlinux.org/packages/rbw-git/) from the AUR, which
will always build from the latest master commit.

### Debian/Ubuntu

`rbw` is officially packaged for Debian as
[`rust-rbw`](https://tracker.debian.org/pkg/rust-rbw) and is available in
testing (forky). You can install it using `sudo apt install rbw`.

Alternatively, you can download a Debian package from
[https://git.tozt.net/rbw/releases/deb/
](https://git.tozt.net/rbw/releases/deb/). The packages are signed by
[`minisign`](https://github.com/jedisct1/minisign), and can be verified using
the public key `RWTM0AZ5RpROOfAIWx1HvYQ6pw1+FKwN6526UFTKNImP/Hz3ynCFst3r`.

### Fedora/EPEL

`rbw` is available in [Fedora and EPEL 9](https://bodhi.fedoraproject.org/updates/?packages=rust-rbw)
(for RHEL and compatible distributions).

You can install it using `sudo dnf install rbw`.

### Homebrew

`rbw` is available in the [Homebrew repository](https://formulae.brew.sh/formula/rbw). You can install it via `brew install rbw`.

### Nix

`rbw` is available in the
[NixOS repository](https://search.nixos.org/packages?show=rbw). You can try
it out via `nix-shell -p rbw`.

#### Home Manager

This flake also exports a Home Manager module (`homeManagerModules.default`)
that exposes `config.json` as declarative Nix options (mirroring `Config`
and `Account` in `src/config.rs`), and installs `rbw` itself.

Its options live under `programs.rbw.declarative`, not `programs.rbw`
directly: recent Home Manager releases ship their own built-in, minimal
`programs.rbw` module (freeform-typed, install-only), and its `enable`/
`package`/`settings` options are unconditionally declared as soon as Home
Manager is imported. This module can't redeclare those same option paths,
so it lives at a sibling path instead. It's fully independent of the
built-in module -- don't set both `programs.rbw.settings` (upstream,
freeform) and `programs.rbw.declarative.enable` (this module) at once, as
only this module actually renders `config.json`.

Add the flake as an input:

```nix
inputs.rbw.url = "github:pschmitt/rbw";
```

Import the module in your Home Manager configuration:

```nix
{
  imports = [ inputs.rbw.homeManagerModules.default ];
}
```

Then configure it:

```nix
programs.rbw.declarative = {
  enable = true;
  settings = {
    pinentry = "pinentry-gnome3";
    lock_timeout = 3600;
    primary_account = "personal";
    accounts.personal = {
      email = "me@example.com";
      base_url = "https://vault.bitwarden.com";
    };
  };
};
```

This writes `~/.config/rbw/config.json` (or
`$XDG_CONFIG_HOME/rbw/config.json`) from `programs.rbw.declarative.settings`;
unset options are omitted from the generated file rather than written as
`null`. See the module's option documentation (e.g. via `home-manager
option programs.rbw.declarative` or your editor's Nix LSP) for the full
list of settings, including `accounts.<name>.unlock`,
`accounts.<name>.exclude_from_list`, and `tui_keybindings`.

### Alpine

`rbw` is available in the [community repository](https://pkgs.alpinelinux.org/packages?name=rbw). You can install it with `apk add rbw`.

### Other

With a working Rust installation, `rbw` can be installed via `cargo install
--locked rbw`. This requires that the
[`pinentry`](https://www.gnupg.org/related_software/pinentry/index.en.html)
program is installed (to display password prompts).

## Configuration

Configuration options are set using the `rbw config` command. Available
configuration options:

* `email`: The email address to use as the account name when logging into the
  Bitwarden server. Required.
* `sso_id`: The SSO organization ID. Defaults to regular login process if unset.
* `base_url`: The URL of the Bitwarden server to use. Defaults to the official
  server at `https://api.bitwarden.com/` if unset.
* `identity_url`: The URL of the Bitwarden identity server to use. If unset,
  will use the `/identity` path on the configured `base_url`, or
  `https://identity.bitwarden.com/` if no `base_url` is set.
* `ui_url`: The URL of the Bitwarden UI to use. If unset,
  will default to `https://vault.bitwarden.com/`.
* `notifications_url`: The URL of the Bitwarden notifications server to use.
  If unset, will use the `/notifications` path on the configured `base_url`,
  or `https://notifications.bitwarden.com/` if no `base_url` is set.
* `lock_timeout`: The number of seconds to keep the master keys in memory for
  before requiring the password to be entered again. Defaults to `3600` (one
  hour).
* `sync_interval`: `rbw` will automatically sync the database from the server
  at an interval of this many seconds, while the agent is running. Setting
  this value to `0` disables this behavior. Defaults to `3600` (one hour).
* `pinentry`: The
  [pinentry](https://www.gnupg.org/related_software/pinentry/index.html)
  executable to use. Defaults to `pinentry`.
* `password_gen`: The default password-generation policy used by `rbw gen`
  and `rbw create --generate` whenever the equivalent flag isn't passed
  explicitly (`length`, `no_symbols`, `only_numbers`, `nonconfusables`,
  `diceware` -- same fields as those commands' flags). Not settable via `rbw
  config set`; edit `config.json` directly, or use the TUI's settings view
  (`S` from the main screen).

### Profiles

`rbw` supports different configuration profiles, which can be switched
between by using the `RBW_PROFILE` environment variable. Setting it to a name
(for example, `RBW_PROFILE=work` or `RBW_PROFILE=personal`) can be used to
switch between several different vaults - each will use its own separate
configuration, local vault, and agent.

## Usage

Commands can generally be used directly, and will handle logging in or
unlocking as necessary. For instance, running `rbw ls` will run `rbw unlock` to
unlock the password database before generating the list of entries (but will
not attempt to log in to the server), `rbw sync` will automatically run `rbw
login` to log in to the server before downloading the password database (but
will not unlock the database), and `rbw add` will do both.

Logging into the server and unlocking the database will only be done as
necessary, so running `rbw login` when you are already logged in will do
nothing, and similarly for `rbw unlock`. If necessary, you can explicitly log
out by running `rbw purge`, and you can explicitly lock the database by running
`rbw lock` or `rbw stop-agent`.

`rbw help` can be used to get more information about the available
functionality.

Run `rbw get <name>` to get your passwords. If you also want to get the username
or the note associated, you can use the flag `--full`. You can also use the flag
`--field={field}` to get whatever default or custom field you want. The `--raw`
flag (or `--json`) will show the output as JSON. On a terminal, JSON output is
colorized automatically; when piped, plain JSON is emitted. In addition to
matching against the name, you can pass a UUID as the name to search for the
entry with that id, or a URL to search for an entry with a matching website
entry.

`rbw list` also accepts an optional search term (`rbw list google`) to show only
matching entries, and `rbw list --with-attachments` restricts the results to
items that have attachments. Interactive table-style output uses uppercase
headers, smart coloring, and default `UID`, `NAME`, `USER`, and
`ATTACHMENTS` columns. To inspect attachments directly, run
`rbw attachment list <entry>` (or `rbw attachment list <entry> --json`). To
download one, run
`rbw attachment get <entry> --attachment <attachment-id-or-filename>`. If you
omit or mistype the attachment name, `rbw` will print the available
attachments. Use
`rbw attachment get <entry> --attachment <attachment-id-or-filename> --output -`
to write the attachment to stdout instead of a file. Using the entry UUID is
the most precise option and avoids shell quoting issues for names with spaces.

For commands that support formatted output, use `-o name`, `-o json`, or
`-o yaml`. `-o json` is equivalent to `--json`, and `-o yaml` emits YAML.

`rbw create --generate` (`-g`) generates the password instead of prompting
for one, using the same flags as `rbw gen` (`--length`/`-l`, `--no-symbols`,
`--only-numbers`, `--nonconfusables`, `--diceware`); any of those flags
implies `--generate`. Omitted flags fall back to the `password_gen` config
policy, then to a 20-character password from the full character set. This
is mutually exclusive with piping a fully-formed entry into `rbw create` via
stdin.

### Template and command injection

`rbw inject` can render templates containing secret references. References use
the format `bw://<uuid-or-name>?field=<field>`, where the item can be addressed
by UUID or by an exact name consisting only of letters, digits, `-`, and `_`.
For items whose names contain spaces or other punctuation, use the item UUID
instead. If `field` is omitted, the entry password is used. References can be
written directly in the template or wrapped in `{{ bw://... }}`.

By default, `rbw inject` reads the template from stdin and writes the rendered
output to stdout. Use `--in-file` and `--out-file` to work with files instead:

```sh
echo 'database_password={{ bw://db-prod?field=password }}' | rbw inject
rbw inject --in-file config.tpl --out-file config.yaml
```

`rbw run` reads environment bindings from `./.env` by default (or another file
with `--env-file`), parses them using dotenv syntax, resolves any `bw://`
references in the resulting values, and then runs the requested command without
going through a shell:

```sh
cat > .env <<'EOF'
DATABASE_URL=postgres://app:bw://db-prod?field=password@db.example/app
API_TOKEN=bw://deploy-token
EOF

rbw run -- env
rbw run --env-file .env.local -- docker compose up -d
```

*Note to users of the official Bitwarden server (at bitwarden.com)*: The
official server has a tendency to detect command line traffic as bot traffic
(see [this issue](https://github.com/bitwarden/cli/issues/383) for details). In
order to use `rbw` with the official Bitwarden server, you will need to first
run `rbw register` to register each device using `rbw` with the Bitwarden
server. This will prompt you for your personal API key which you can find using
the instructions [here](https://bitwarden.com/help/article/personal-api-key/).

### Backup and restore (`rbw export`/`rbw import`)

`rbw export` writes the entire active vault (all entries, fully decrypted,
plus collections) as JSON to stdout:

```sh
rbw export > backup.json
```

`rbw import` reads that JSON back and recreates the entries and collections
in the target account's vault (use the global `--account`/`-a` flag to pick
a different account than the primary one):

```sh
rbw import backup.json
# or, piped:
rbw export | rbw import
```

If no file is given, `rbw import` reads from stdin. Entries that already
exist (matched by name, and by username for logins) are left untouched and
reported as skipped; pass `--overwrite` to update them in place instead.
Entries that belonged to an organization the target account isn't a member
of are imported into the personal vault instead of failing. SSH key entries
are skipped, since this fork doesn't yet support creating them via the API.

If the export was produced with `rbw export --encrypt PASSPHRASE` (a
gpg-encrypted tar.gz instead of raw JSON), pass the same passphrase back on
import:

```sh
rbw import --decrypt-passphrase PASSPHRASE backup.tar.gz.gpg
```

`rbw import` prints a summary when it's done (entries created/updated/
skipped, attachments restored, collections created) and exits non-zero if
any entry failed to import.

### SSH Agent

`rbw-agent` includes a built-in SSH agent for signing SSH authentication
challenges directly. To use it, ensure that rbw is running (in order to make
it start handling ssh agent requests), and then point your SSH client to the
SSH agent socket:

```sh
rbw unlock
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rbw/ssh-agent-socket"
```

If you're using a profile, the socket will be located at
`"XDG_RUNTIME_DIR/rbw-<profile>/ssh-agent-socket"`.

### 2FA support

`rbw` supports the following 2FA mechanisms :

* Email
* Authenticator App
* Yubico OTP security key (https://support.yubico.com/hc/en-us/articles/360013712639-Testing-Yubico-OTP)

WebAuthn / Passkey and Duo security are unsupported 2FA mechanisms.

If you use only unsupported 2FA mechanism, you need to add a supported 2FA
mechanism on your bitwarden account to use rbw. It allows you to use rbw
with a supported mechanism, and use other clients with you preferred
2FA mechanism.

## Related projects

* [rofi-rbw](https://github.com/fdw/rofi-rbw): A rofi frontend for Bitwarden
* [bw-ssh](https://framagit.org/Glandos/bw-ssh/): Manage SSH key passphrases in Bitwarden
* [rbw-menu](https://github.com/rbuchberger/rbw-menu): Tiny menu picker for rbw
* [ulauncher-rbw](https://0xacab.org/varac-projects/ulauncher-rbw): [Ulauncher](https://ulauncher.io/) rbw extension
* [fuzzel-rbw](https://github.com/sammhansen/fuzzel-rbw): A fuzzel frontend for Bitwarden
