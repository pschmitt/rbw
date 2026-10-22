<p align="center">
  <img src="browser/extension/icons/rbw-256.png" width="160" alt="rbw">
</p>

<h1 align="center">rbw</h1>

<p align="center">
  An unofficial <a href="https://bitwarden.com/">Bitwarden</a> client for the
  command line, the terminal and the browser.
</p>

Bitwarden's own CLI is stateless: you unlock it and pass session keys around
in environment variables. `rbw` instead keeps your keys in a background agent,
like `ssh-agent` or `gpg-agent`, so commands just work and lock again on a
timeout.

## Features

- **CLI and TUI** for logins, cards, identities, notes and SSH keys, with
  search, TOTP, attachments, archive and trash.
- **Multiple accounts and profiles**, including self-hosted Vaultwarden.
- **Browser extension** for Firefox and Chromium that talks to the same agent:
  autofill, passkeys, save prompts. See [browser/README.md](browser/README.md).
- **Passkeys** synced, shown and usable from the CLI and the browser.
- **Built-in SSH agent** for keys stored in the vault.
- **Backup, import and mirroring** between accounts, in rbw and Bitwarden
  formats.
- **`rbw inject` and `rbw run`** to render templates and environment files
  with secrets.
- **Organizations and collections** management.
- **Account security**: change the master password, KDF settings or account
  key (`rbw security`), and native unlock via the desktop keyring with
  fingerprint confirmation or the Termux Android Keystore.
- **Home Manager module**.

## Install

```sh
cargo install --locked --git https://github.com/pschmitt/rbw
```

You also need [`pinentry`](https://www.gnupg.org/related_software/pinentry/)
for password prompts. Signed, attested release archives are described in
[docs/install.md](docs/install.md); for Nix, Home Manager and the browser
extension on NixOS see [docs/nix.md](docs/nix.md).

## Quick start

```sh
rbw config set email you@example.com
rbw config set baseUrl https://vault.example.com   # self-hosted only
rbw login
rbw sync
rbw get github          # password
rbw get --full github   # everything
rbw code github         # TOTP
rbw tui
```

Commands log in and unlock on demand; `rbw lock` locks, `rbw help` lists the
rest. On bitwarden.com, run `rbw register` first
([details](docs/usage.md#using-the-official-bitwarden-server)).

## Documentation

| Topic | |
|---|---|
| [Installation](docs/install.md) | Cargo and release verification |
| [Nix](docs/nix.md) | Flake, overlay, Home Manager module, browser setup |
| [Configuration](docs/configuration.md) | `config.yaml`, accounts, aliases, profiles |
| [Usage](docs/usage.md) | Everyday commands, search, attachments, 2FA, `rbw security` |
| [Passkeys](docs/passkeys.md) | Counters and browser injection |
| [Organizations](docs/organizations.md) | `rbw org` and `rbw collection` |
| [Backup and restore](docs/backup.md) | `export`, `import`, file-backed vaults |
| [Mirroring](docs/mirror.md) | Copying vaults between accounts |
| [Injection](docs/inject.md) | `rbw inject` and `rbw run` |
| [SSH agent](docs/ssh-agent.md) | Using vault SSH keys |
| [Termux](docs/termux.md) | Android Keystore unlock |
| [Desktop unlock](docs/desktop-unlock.md) | Secret Service and fingerprint confirmation |
| [Browser extension](browser/README.md) | Firefox and Chromium |
| [Changelog](CHANGELOG.md) | |

## Related projects

- [rofi-rbw](https://github.com/fdw/rofi-rbw), a rofi frontend
- [bw-ssh](https://framagit.org/Glandos/bw-ssh/), SSH key passphrases in Bitwarden
- [rbw-menu](https://github.com/rbuchberger/rbw-menu), a tiny menu picker
- [ulauncher-rbw](https://0xacab.org/varac-projects/ulauncher-rbw), an [Ulauncher](https://ulauncher.io/) extension
- [fuzzel-rbw](https://github.com/sammhansen/fuzzel-rbw), a fuzzel frontend
