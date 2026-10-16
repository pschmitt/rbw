# rbw browser extension (development preview)

Firefox and Chromium use the same extension code. A small `rbw-browser`
executable starts `rbw native-messaging`, which reuses the CLI's vault operations
and connects to the existing rbw-agent. Browser processes do not own vault keys
or run their own agent. Unlocking or locking an account affects the CLI too.
There is no HTTP listener, browser vault cache, or browser login flow.

## Build and load

Build the Rust binaries on a development host, following the repository's
AGENTS.md (never compile on fnuc). Both `rbw` and `rbw-browser` must be installed
beside each other; `rbw-agent` must be on PATH or supplied via `RBW_AGENT`.
Existing registered rbw accounts are required. Start with `rbw login` and
`rbw sync` if you have not configured the CLI yet.

Package the extension with `python3 browser/build.py`.

* Firefox: open `about:debugging#/runtime/this-firefox`, choose **Load Temporary
  Add-on**, and select `browser/dist/firefox/manifest.json`.
* Chromium: open `chrome://extensions`, enable developer mode, choose **Load
  unpacked**, select `browser/dist/chromium`, and copy its extension ID.

Register the host with:

```console
python3 browser/install.py --host /absolute/path/to/rbw-browser --firefox
python3 browser/install.py --host /absolute/path/to/rbw-browser --chromium-id EXTENSION_ID
```

Add `--chrome` to also register for Google Chrome. Linux native installation
is supported; sandboxed browser packages may need additional host integration.
The installer can register both browser families in one invocation. Restart the
extension after registration. Firefox temporary extensions disappear on restart;
the Nix packages below provide persistent installation once signed artifacts are available. Chromium's unpacked ID
can change if the extension directory moves; rerun registration with the new ID.

## Features

* Select a configured account; inspect its lock state; unlock through rbw's
  existing credential source / pinentry; lock and sync.
* Search login names and usernames, or restrict results to the current site.
  Results are capped at 200; narrow the search to see other items.
* Fill a matching login after an explicit click. URL matching uses the CLI's
  existing rules, with an additional HTTPS downgrade check. The page is checked
  again before filling. Forms are never submitted automatically.
* Copy username, password, or a fresh TOTP through the agent's system clipboard
  operation, including its existing clearing policy. The browser never receives
  copied values. OSC52 is intentionally not used by the native host.
* Generate passwords or passphrases using rbw's configured generator defaults.
  Generated values stay in the popup until it closes or the vault locks.

No persistent extension storage, broad host permissions, content scripts,
remote scripts, or external webpage messaging are used. Only the popup can
request operations. Native host registration restricts which extension can
launch the bridge. Search decrypts metadata only; fill decrypts just username
and password. It never exports passkey keys, TOTP seeds, or whole vault items.

## Current limits and next stages

This is an initial implementation, not official Bitwarden feature parity.
Autofill requires one visible password field in the main frame; username-only
flows, iframes, shadow DOM, and inline suggestions are not yet supported.
Items requiring a master password reprompt are omitted from search to avoid
prompting while browsing. Archived/deleted items are omitted. Metadata is cleared
within roughly three seconds of an external lock while the popup is open;
operations always recheck the agent lock. Credentials inserted into a page are
accessible to that page, as with other password managers.

Next: save/update prompts and item editing; keyboard/context menu actions;
cards, identities and custom fields; passkey registration and authentication;
attachments and collection management; signed packages and declarative native
host registration through the Home Manager module.

Before daily use, validate installation, shared lock state, clipboard clearing,
navigation races, rejected nonmatching sites, and real forms in both browsers
using a disposable vault. No real vault is read during packaging or compilation.

## Nix installation

The flake exports `firefox-addon`, `chromium-addon`, and
`browser-native-host`. Add `firefox-addon` to the Firefox profile's
`extensions.packages`; add `browser-native-host` to both browsers'
`nativeMessagingHosts`. For Chromium, use `chromium-addon.extensionId`,
`crxPath = "${chromiumAddon}/rbw.crx"`, and `chromium-addon.version` in
`programs.chromium.extensions`. This uses Home Manager's existing external
extension installation support. Browsers may need a restart and Chromium may
ask you to enable an externally installed extension.

`browser/packages/` contains the signed distribution artifacts and the public
Chromium identity. Private signing keys must stay outside the repository.
Firefox signing uses `web-ext sign --channel unlisted` with
`WEB_EXT_API_KEY` and `WEB_EXT_API_SECRET` supplied in the environment.
Chromium packaging uses the existing signing key; never generate a replacement
key for an update, since that changes the extension ID. Repackage and re-sign
after changing the extension sources, and bump the extension version in
`build.py` and `nix/browser.nix` for each installed update.
