<p align="center">
  <img src="../assets/icons/rbw-256.png" width="128" alt="rbw">
</p>

<h1 align="center">rbw for the browser</h1>

A Firefox and Chromium extension that uses your existing rbw setup. It talks to
`rbw-agent` through a native messaging host, so there is no second vault, no
browser-side key storage and no HTTP listener: unlock once, use it everywhere.

## Features

- Vault browsing, search and editing in the toolbar popup, sidebar or a window.
- Inline login and card suggestions, autofill on demand (on-load autofill is
  opt-in), save and update prompts after sign-in.
- Passkey sign-in and registration; private keys stay in rbw.
  If another extension replaces the WebAuthn handlers during startup, rbw
  retries at most five times per method within ten seconds. Browser-daemon
  keeps its live-view wrapper, with rbw as its fallback; recovery stops when
  the page is left.
- TOTP, password generator, Sends, attachments, folders, import and export.
- Clickjacking-resistant inline UI rendered in extension frames, with
  per-browser and per-URI match detection.

## Install

The extension ships with every rbw release (`rbw-browser-VERSION-firefox.xpi`
and `-chromium.crx`, signed and attested), and the flake exports
`firefox-addon`, `chromium-addon` and `browser-native-host`. Install `rbw`,
`rbw-agent` and `rbw-browser` together, then allow your browser in rbw's
config; access is denied by default:

```yaml
browser:
  clients:
    firefox:
      browser: firefox
      extensions: [rbw-browser@pschmitt.dev]
      executableRoots: [/nix/store/...-firefox]
```

NixOS and Home Manager setup is in [docs/nix.md](../docs/nix.md); manual
installs and the allowlist's rules are in the [reference](../docs/browser.md).

## Development

```sh
python3 browser/build.py                   # unpacked builds and ZIPs in browser/dist
browser/tests/e2e/run.sh firefox|chromium   # end-to-end tests (run on a scratch host)
```

Releases go through `tools/release.sh` (`just release-prepare X.Y.Z`, then
`just release-tag`); the tag's release workflow signs the packages.

## browser-daemon

[browser-daemon](https://github.com/pschmitt/browser-daemon)'s live view
fills from rbw too. Its vault popover and passkey prompt live in
[`browser-daemon/`](browser-daemon/README.md), share this extension's
`theme.css`, `icons.js` and logo, and are built with it (`build.py`, flake
package `browser-daemon-extension`); they are not in the signed packages.

## More

- [Reference](../docs/browser.md): permissions and data flow, limits, setup
  details, release assets and the 0.2.x history
- [Changelog](../CHANGELOG.md)
