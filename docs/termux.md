# Native Termux Android Keystore unlock

On Android, the pschmitt fork can unlock an account natively through
Termux:API. This uses an authentication-gated Android Keystore signing key;
the Keystore signing operation itself is the security boundary, and a
`termux-fingerprint` prompt is what satisfies Android's authentication check
before each sign (`termux-keystore sign` never prompts on its own — it only
checks whether you're already authenticated within the key's validity
window). The encrypted bundle contains no private key or reusable signature.

Enroll the active account in one step:

```shell
rbw security termux enroll
# Or choose a ten-minute authorization window during enrollment:
# rbw security termux enroll --validity 600
```

rbw asks for the master password using the configured pinentry, generates an
authentication-gated RSA key, prompts for fingerprint authentication, writes
the encrypted bundle below rbw's config directory, and
updates the active account in `config.yaml`. The default authorization window
is five minutes; adjust it with `--validity SECONDS`. By default the generated
key and bundle are named after the account, so multiple accounts can be
enrolled independently. To use an existing alias, set `termux.keyAlias` in
config.yaml or export `RBW_TERMUX_KEY_ALIAS`; the environment variable wins,
and enrollment reuses the selected key instead of generating another one. Use
`rbw security termux status` to inspect a readable report of the
Android Keystore properties; each enrolled key must report hardware backing,
authentication, and hardware enforcement as `yes`.

To permanently remove the active account's native unlock key and bundle:

```shell
rbw security termux remove       # asks for confirmation
rbw security termux remove --yes # non-interactive form
```

For declarative Home Manager setups, the equivalent account option is:

```yaml
unlock:
  termux:
    file: /data/data/com.termux/files/home/.config/rbw/termux/personal.bundle
    keyAlias: rbw-personal
    algorithm: SHA256withRSA
```

After that, `rbw unlock`, `rbw login`, `rbw get`, and the TUI use the native
provider automatically; no shell wrapper is involved. The provider is
fail-closed: a missing bundle, unavailable Termux API, wrong key, or
non-authenticated key is an error rather than a fallback to pinentry.
