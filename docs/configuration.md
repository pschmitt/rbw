# Configuration

Configuration is YAML with camelCase keys. `rbw config show` prints the
readable YAML form by default; pass `--json` for JSON. The complete file can
be edited with `rbw config edit`.

The main sections are:

* `accounts` and `primaryAccount`: account connection settings use keys such
  as `ssoId`, `baseUrl`, `identityUrl`, `uiUrl`, `notificationsUrl`, and
  `clientCertPath`. Per-account unlock settings live under `unlock`, and
  account exclusions under `excludeFrom`.
* `agent`: `syncInterval` controls background synchronization and
  `lockTimeout` controls how long unlocked keys remain in memory.
* `pinentry`: `command` selects the pinentry executable and `timeout` sets
  its input timeout.
* `tui`: `lockTimeout` controls inactivity locking and `keys` contains
  camelCase action names such as `forceQuit` and `copyPassword`.
* `hide`: `archived` and `trashed` control default list/search visibility.
* `termux.keyAlias`: the default Android Keystore alias; the
  `RBW_TERMUX_KEY_ALIAS` environment variable overrides it.
* `passwordGen`: the default generation policy, with `noSymbols`,
  `onlyNumbers`, `nonconfusables`, and `diceware` options.
* `clipboard`: one of `auto`, `system`, or `osc52`.
* `aliases`: a list of shortcut names for `rbw get`. Each entry has an
  `alias` (a single name, or a list of names sharing the same target), an
  `item` (name or UUID, matched the same way as `rbw get NAME`), and
  optional `account`, `field`, `collection`, and `org` keys:

  ```yaml
  aliases:
    - alias: [gpg, gnupg]
      account: work   # unset, "primary", or "default" all mean the primary account
      item: GPG key
      field: passphrase
  ```

  `rbw get gpg` (and `rbw get gnupg`) then behaves like
  `rbw get --field passphrase "GPG key"` against the `work` account. Alias
  resolution only applies to a bare `rbw get NAME` -- passing
  `--user`/`--folder`/`--collection`/`--org` skips it in favor of a normal
  search -- and can be disabled entirely with `rbw get --no-alias NAME`.
  With `--verbose`, a resolved alias logs which account/item/field it
  expanded to.

Scalar settings can also be changed with dotted paths, for example
`rbw config set pinentry.command pinentry-curses` or
`rbw config set agent.lockTimeout 3600`.

## Profiles

`rbw` supports different configuration profiles, which can be switched
between by using the `RBW_PROFILE` environment variable. Setting it to a name
(for example, `RBW_PROFILE=work` or `RBW_PROFILE=personal`) can be used to
switch between several different vaults - each will use its own separate
configuration, local vault, and agent.
