# rbw browser extension

Firefox and Chromium share an extension and a native `rbw-browser` launcher.
The launcher runs `rbw native-messaging`, using the same account configuration,
vault database and rbw-agent as the CLI. Vault keys remain in the agent; there
is no browser vault cache, HTTP listener or separate browser agent.

## Features in 0.2.24

- Streamlined popup layout: footer bar replaced with a clickable view switcher dropdown on the header title (Vault, Generator, Send, Health), persistent Settings header action with quick access to in-popup settings and options page, and an animated Floating Action Button (FAB) for Add that collapses to an icon on scroll.
- Neutral charcoal surfaces throughout the popup, sidebar, settings, inline
  suggestions and notifications. Active navigation has a clear filled state,
  including the parent tab while viewing an item or editor.
- The toolbar badge shows the current page's matching-login count, reusing
  cached searches; passkey/save approvals use a distinct attention badge.
- Autofill notifications show the rbw icon and aligned Undo/Close icon buttons
  with an updated return-loop Undo icon and brief animations that respect reduced motion.
- Drag inline suggestions by their header (or use arrow keys on the move
  handle). The header displays the branded rbw app icon alongside "RBW · AUTOFILL".
  Position lasts only for the current document and resets on refresh; Home restores
  the default position immediately.

- Passkey account cards replace the old button list. Optional master-password
  entry is removed from the chooser; required WebAuthn identity verification
  appears only as a separate step after selecting a passkey.

- Autofill excludes search controls and requires explicit sign-in semantics for
  username-only forms. Ordinary pages do not trigger automatic vault searches.
  The page banner has Undo, including same-origin frames; previous values stay
  briefly in the isolated page context and later user edits are preserved.

- Live verification codes with a validity countdown and Copy control; secret
  fields in the editor have Show/Hide controls. Password history has Copy icons
  using the agent clipboard policy.

- Favorites render from a shared metadata-only cache across tabs, while site
  suggestions refresh independently. Concurrent searches share one request;
  native search batches metadata decryption through rbw-agent. Passwords and
  item details are always fetched afresh and never stored in the list cache.
- Autofill dismisses inline suggestions and suppresses programmatic-focus
  reopening. Favicon downloads happen after suggestions render.
- Sticky expanded filters, whole-card hover, and home ordering: suggestions,
  favorite cards, favorite logins, favorite secure notes.
- A dedicated, simpler toolbar icon with content-addressed filenames avoids
  stale browser icon resources while preserving the richer icon inside the UI.

- A dark vault layout with search, type/folder/collection filters, favorites,
  archive and trash views; light and system themes are also available.
  Home starts with favorites plus all matching autofill suggestions; typing
  searches the whole vault. The last view resumes on reopening.
  The compact header uses the crab/shield icon at the far left. Click it for
  the account menu; on subpages an attached chevron turns it into Back.
  Double-click to open the vault in a separate window.
  Attachment uploads and management appear only in the editor.
  Bundled SVG icons and optional direct-site favicons avoid font glyphs and
  third-party favicon services. Generator, Send and Health tabs are configurable in the popup and add-on
  settings. Send and Health are hidden by default.
- Multiline notes render sanitized Markdown (headings, lists, tables, links
  and code), with plain-text viewing/copying and a multiline editor.
- Item-list metadata is cached only in background memory for five minutes, checked
  against the agent lock state before reuse, and cleared on writes/lock/account
  changes. Passwords, note contents and item details are never cached. A delayed
  header spinner covers native requests; details are still fetched on demand.
  Popup navigation, search, filters and scroll position resume when reopened.
  Forms and generated passwords are never remembered. Filters start collapsed;
  action feedback appears in dismissible banners. Sync refreshes cached names.
- Multiple configured accounts; unlock directly with a password in the popup,
  or use the configured rbw credential source / pinentry; shared lock and sync.
- Login, card, identity, secure note and SSH key browsing, details, creation,
  editing, password history, custom fields, favorites, archive and restore.
  Item edits use revision guards and preserve existing passkeys natively.
- Explicit login/card/identity autofill; username-only flows, same-origin
  frames and open shadow roots; keyboard commands and a context menu.
  The fill shortcut fills the first match and cycles through matches when
  repeated within 30 seconds; opening the vault has a separate shortcut. A brief
  page notification identifies the filled login and username, without passwords.
  Login/custom-field filling rechecks the URI in rbw and the current document.
  Forms are never submitted automatically. On-load filling is enabled by
  default and fills the first matching login unless it requires reprompt.
- Inline matching-login suggestions in login fields. Submitted credentials can
  be saved or used to update an existing matching login after approval in the
  popup. The badge indicates pending suggestions, which expire in two minutes.
- Password, passphrase, numeric, alphanumeric and easy-to-read generators using
  CLI defaults; native clipboard operations use the agent's clearing policy.
- Passkey approval in the toolbar popup, with a badge to resume if automatic
  opening is unavailable. Conditional requests wait for a toolbar click;
  dismissing the popup keeps the request pending until cancellation or expiry.
- Passkey registration and authentication, including discoverable credentials,
  explicit account/item selection, abort/timeouts, another-authenticator
  fallback, UUID and `b64.` credential IDs, and relying-party validation using
  the public suffix list. Keys never enter the browser. Required user
  verification checks the master password inside rbw-agent; presence-only
  responses do not claim user verification. New synced credentials keep the
  standard zero counter. Existing nonzero counters are reserved on the server
  before signing, following the CLI's revision and locking safeguards.
- Attachment uploads in bounded chunks (up to 100 MiB) and native downloads
  into the user's Downloads directory, with unique names and private file
  permissions; attachment deletion.
- Encrypted text and file Sends with clipboard links, private notes, access
  limits, deletion/expiration, disabling and password protection/removal.
  File Sends currently support direct-upload servers such as Vaultwarden.
- Folder creation, rename and deletion; existing organization-item collection
  assignment. Organization/server permissions still apply.
- Local reports for reused passwords, passwords shorter than 12 characters,
  and logins without a saved TOTP seed. These reports make no external queries.
- Vault import and export using the CLI’s existing formats, with encrypted JSON
  as the default export and a confirmation for plaintext exports. Exported vault
  data goes directly to Downloads without passing through the browser.
- A dedicated browser add-on options page, quick popup settings, pop-out windows,
  Firefox sidebar and Chromium side panel.

## Permissions and data flow

Only this extension's popup and options pages can call the native API. Isolated
content scripts have narrower operations for passkeys, matching-site inline
suggestions and user-submitted save suggestions. The WebAuthn main-world shim
only exchanges public request options, credential public data and signatures.
The background takes the origin from browser-provided sender information;
webpages cannot supply an origin to sign for. Requests in cross-origin frames
fall back to the browser's normal authenticator.

Site access is needed for WebAuthn interception and inline suggestions. Native
host manifests restrict the browser extension identities allowed to launch the
bridge. Browser storage contains preferences only. Pending requests, generated
values, viewed secrets and capture suggestions are not persisted to browser
storage. Explicitly viewed/edited secrets and filled credentials do enter the
browser; a site can read values filled into its forms. Passkey private keys,
account keys and copied vault values remain native. Downloaded attachments are
intentionally saved as plaintext files after an explicit download action.

## Compatibility boundaries

This is still a development preview, not complete official Bitwarden parity.
Supported passkeys use ES256/P-256 with anonymous (`none`) attestation. PRF,
largeBlob, enterprise attestation, cross-origin frame WebAuthn, browser-native
conditional account-picker integration and other algorithms are not implemented.
Conditional requests can be approved through the rbw toolbar popup. Sites that
require unimplemented capabilities can use the other-authenticator fallback.

Filling traverses open shadow roots and same-origin frames; closed shadow roots,
cross-origin iframe filling and unusual nonstandard controls need further work.
Linked custom fields are resolved for the supported item fields. Capture suggestions require a native HTML
form submission event; script-only login flows may need manual Add/Edit.

Azure-upload file Sends, newer SDK item Sends, enterprise administration, account
onboarding/SSO in the extension, biometrics remain outside this release. Configure/login accounts using the CLI. Server features
that rbw itself cannot support (including V2 vault encryption) remain unsupported.
For passkeys whose counters are already nonzero, other clients must sync before
using the same credential, as described by `rbw passkey`.

## Build and load

Compile Rust binaries on a development host according to `AGENTS.md`, never on
fnuc. Install `rbw`, `rbw-browser` and `rbw-agent` together. Existing configured
accounts are required; start with `rbw login` and `rbw sync`.

Run `python3 browser/build.py` to create browser directories and unsigned ZIPs.
For a temporary Firefox installation, load `browser/dist/firefox/manifest.json`
from `about:debugging#/runtime/this-firefox`. In Chromium, enable developer mode
and load `browser/dist/chromium` as an unpacked extension.

Register the host for manual installations:

```console
python3 browser/install.py --host /absolute/path/to/rbw-browser --firefox
python3 browser/install.py --host /absolute/path/to/rbw-browser --chromium-id EXTENSION_ID
```

Add `--chrome` to register for Google Chrome too. Native installation supports
Linux; sandboxed browser packages may need extra integration. Refresh open site
tabs after installing an update so they receive the updated content scripts.

## Nix installation and signed updates

The flake exports `firefox-addon`, `chromium-addon`, and `browser-native-host`.
Add the Firefox add-on to `extensions.packages` and the host to both browsers'
`nativeMessagingHosts`. For Chromium use `chromium-addon.extensionId`,
`crxPath = "${chromiumAddon}/rbw.crx"`, and `chromium-addon.version` in
`programs.chromium.extensions`. Firefox's XPI must be AMO-signed (unlisted is
sufficient); Chromium uses a CRX3 package with the existing signing identity.
Browser restarts or acceptance of newly requested permissions may be necessary.

`browser/packages/` holds signed distribution artifacts and the public Chromium
identity. Never put private signing keys or AMO credentials in the repository.
After changing extension sources, bump the extension version in `build.py` and
`nix/browser.nix`, package and re-sign both artifacts using the existing keys.
The generated icon source is `browser/icon-source.png`; prompt provenance is
recorded in `browser/icon-prompt.txt`, with sized toolbar assets in
`browser/extension/icons/`.

## Native messaging allowlist

Browser access is denied by default. Configure `browser.clients` in rbw's
configuration (or `programs.rbw.declarative.settings.browser.clients` in Home
Manager). Each named rule requires `browser` (`firefox` or `chromium`),
`extensions` (exact add-on IDs), and `executableRoots` (absolute executable paths
or immutable browser package directories). For example:

```json
{"browser":{"clients":{"firefox":{"browser":"firefox","extensions":["rbw-browser@pschmitt.dev"],"executableRoots":["/nix/store/your-firefox-package"]}}}}
```

On Linux the bridge checks the immediate parent's executable through `/proc`
and the browser-supplied extension identity before reading requests, then
reloads the policy for every request. Browser updates must update the allowed
package path too; Home Manager does this declaratively. Intermediary launchers
and other platforms fail closed. The extension cannot enroll itself. Host
manifests also restrict extension identities. This protects native messaging
entry points; it does not sandbox other programs running as your Unix user,
which can invoke the regular rbw CLI.

On NixOS, enroll Home Manager’s `config.programs.firefox.finalPackage`
and the system `pkgs.firefox` package: native messaging creates another wrapper,
and its running executable belongs to that final output. The unwrapped package
alone does not cover these executables.

## Release assets

Tagged CLI releases include the checked-in Mozilla-signed Firefox XPI and signed
Chromium CRX, named `rbw-browser-VERSION-firefox.xpi` and
`rbw-browser-VERSION-chromium.crx`. They are included in `SHA256SUMS` and the
release provenance attestation. The extension version is independent of the CLI
version. Main-branch build artifacts also include both extension packages.

`python3 browser/release.py --output dist` verifies that both packages match the
shared extension source and generated manifests before preparing release assets.
Signing stays outside CI; no extension signing credentials are needed by the
release workflow.
