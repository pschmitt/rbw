# Browser extension: reference

Detailed reference for the extension; see [browser/README.md](../browser/README.md) for the overview.

Firefox and Chromium share an extension and a native `rbw-browser` launcher.
Since 2.22.0 the extension is versioned and released together with rbw.
The launcher runs `rbw native-messaging`, using the same account configuration,
vault database and rbw-agent as the CLI. Vault keys remain in the agent; there
is no browser vault cache, HTTP listener or separate browser agent.

## URI matching

Logins match pages by each URI's match detection, as in Bitwarden. URIs without
their own setting use rbw's `defaultUriMatch`: `domain` (the default) matches
the saved host and its subdomains, `base_domain` matches like Bitwarden's
"Base domain". The add-on options can override the default for this browser
only, and the item editor sets match detection per URI.

## TOTP

With "Autofill TOTP codes" on, the extension fills the current code into a
page's authenticator-code field: on 2FA pages when "Auto-fill on page load"
is on (the code of the login used for this sign-in, else of the first
matching login with an authenticator key), and whenever you fill a login
that has one. Fields are recognised by `autocomplete="one-time-code"` or an
id/name/label such as `otp`, `totp`, `mfa`, `2fa`, `signInMFA`. "Copy TOTP
after filling" puts the code on the clipboard, written by the extension;
unlike rbw's own clipboard it isn't cleared by rbw-agent afterwards. Both
settings can be set by browser policy (`autofillTotp`, `copyTotp`).

## Multiple accounts

With more than one rbw account configured the account picker has an "All
accounts" entry, which is the default. Searches merge every account that
`rbw search` would cover (accounts excluded from search, and accounts that
are locked, are skipped rather than prompting), and items from several
accounts show a small account badge. Requests about one item go to the
account that holds it. The account menu lists each account's lock state,
with an Unlock button for locked ones. New items and unsaved logins have a
"Save to account" select, and an item's menu has "Move to account...", which
does what `rbw move` does (the original goes to its account's trash). The
in-page "save this login?" prompt saves to the primary account; use the
popup's unsaved-logins list to pick another. Choosing a single account in the
picker restores the old single-account behaviour.

The settings page has an Accounts section: by default the extension follows
the rbw command line (the accounts `rbw search` covers); turn that off to
tick the accounts yourself. With two or more ticked, search, autofill, sync
and lock cover exactly those accounts (even ones `exclude_from` hides from
the CLI), and the popup picker offers only them; with one, the extension
behaves as a single-account setup.

Each account has a color for its badge in the list and item view. By default
it comes from the rbw config (`rbw account set NAME --color #rrggbb`, or
`accounts.<name>.color` in the Nix module), else the extension picks a
distinct one from a palette. A color picked on the settings page overrides
the config's; its reset button goes back to following it.

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

Run `browser/tests/e2e/run.sh chromium|firefox [page.html|csp.html]` on a
scratch host to exercise inline fills, saves and clickjacking attempts in a
real browser. It needs Nix, uses an isolated HOME and a stub native host, and
never touches a vault.

## Nix

Installing the add-ons, the native messaging host and the allowlist with
NixOS or Home Manager is described in [nix.md](nix.md).

## Signed packages and releases

Firefox's XPI must be AMO-signed (unlisted is sufficient); Chromium uses a CRX3
package with the existing signing identity.

`browser/packages/metadata.json` holds the public Chromium identity and pins the
signed packages (release assets) by version and SHA-256. Never put private signing keys or AMO credentials in the repository.
The extension shares rbw's version: `build.py` and `nix/browser.nix` read it
from `Cargo.toml`, so there is nothing to bump separately. The release workflow
signs the tagged source through AMO and with the existing Chromium key,
publishes the packages with the release and commits their pin to `main` (the Nix
package fetches the pinned release assets). The signing, pinning and pin check
are the reusable workflows of `pschmitt/ci-workflows`, shared with
browser-daemon and bruvtab. Pushes and pull requests only build unsigned ZIPs,
and check that the pinned packages are intact. Signing reads
`RBW_AMO_API_KEY`, `RBW_AMO_API_SECRET` and `RBW_CHROMIUM_SIGNING_KEY` from
GitHub Actions secrets. AMO signs each version once, so every release that
changes extension sources needs a new rbw version, and a failed release run
should be retried with "Re-run failed jobs" to reuse the signed files. Release
with
`tools/release.sh` (or the `just release-*` recipes):

1. `prepare X.Y.Z` bumps `Cargo.toml`/`Cargo.lock`, dates the changelog,
   commits and pushes.
2. `tag` waits for green build, test and docker runs on that commit and pushes
   a GPG-signed `vX.Y.Z` tag; the release workflow signs and publishes
   everything, then commits the package pin to `main`.
The logo is the blue pixel-art ninja crab in `assets/icon-source.png`: the
`rbw-*` and `toolbar-*` icons in `assets/icons/` and the unlock dialogs' logo
(`assets/rbw.png`) are its trimmed, transparent Lanczos resizes. The 128 and
256px sizes get a little padding. `assets/rbw.svg` redraws the sprite on its
30x25 pixel grid (flat colours, one path per colour, no gradients) and
`assets/rbw-toolbar.svg` is the same drawing in a square viewBox; the PNGs
remain the masters.

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

Tagged CLI releases include the Mozilla-signed Firefox XPI and signed
Chromium CRX, named `rbw-browser-VERSION-firefox.xpi` and
`rbw-browser-VERSION-chromium.crx`. They are included in `SHA256SUMS` and the
release provenance attestation. Since 2.22.0 the extension version
matches the CLI version (earlier extension releases were `browser-v0.2.x`). Main-branch build artifacts also include both extension packages.

The release workflow verifies that both signed packages match the extension
source and generated manifests (`scripts/verify-extension.py` in
`pschmitt/ci-workflows`) before publishing them. To re-check a tag without
publishing, run the release workflow by hand with its tag and `dry-run` set.

## Feature history (0.2.x)

Until 2.22.0 the extension had its own `0.2.x` versions; newer changes are in
[CHANGELOG.md](../CHANGELOG.md).

### Features in 0.2.35

- Inline login/card suggestions and the save-login prompt render inside an
  extension frame. Pages cannot read, script or restyle their contents, and
  the frame's session token reaches it only through a message addressed to the
  extension origin. Each fill or save click is verified in the background:
  Chromium additionally requires IntersectionObserver v2 visibility, and both
  browsers briefly force every page element (including pass-through
  `pointer-events:none` decoys, also inside shadow roots) to be hit-testable
  and confirm the frame is topmost, unscaled, unfiltered and fully opaque.
- End-to-end tests in `browser/tests/e2e/` drive both browsers with trusted
  input against a stub native host (see "Build and load").

### Features in 0.2.34

Security hardening following an internal review:

- Inline suggestions and the save prompt ignore clicks unless rbw's overlay is
  the topmost, fully opaque element under the pointer, has been visible for
  500 ms, and the page is focused. Pages cannot restyle the overlay
  invisible. The card chooser opens automatically only after a real click or
  key press in that field.
- Fills skip fields that are tiny, transparent, off-page or clipped away.
  Card and identity fills require a focused field and stay within its form.
  Hidden-type custom fields are never filled automatically, and linked SSN,
  passport and license fields are never filled from card or identity items.
- On-load autofill and website icons are now off by default. Existing stored
  preferences are kept.
- Filling refuses plain-HTTP pages other than localhost. On an HTTP page only
  explicitly `http:` URIs match; scheme-less URIs no longer do.
- The Starts with URI match type requires the same origin, so
  `https://example.com` no longer matches `https://example.com.evil.net/`.

### Features in 0.2.33

- Passkey sign-in shows the selected account while the native host signs. It
  signs straight away (the counter write is guarded by the entry's server
  revision, so a stale vault is refused), syncs and retries once if it was, and
  confirms the new counter in a sync after answering; a failed confirmation is
  reported through the status.
- Login save and update prompts appear inline in the page.
- Credit cards can be selected and filled from matching payment forms. Card
  brand icons appear in inline suggestions and type is filled when a recognized
  field is present. CVV/CVC handling is configurable: off by default, fill the
  field, or copy to the clipboard. When off, the notice explains that the code
  was intentionally left blank.

- Context-menu autofill opens the inline chooser at the field. Login and card
  choices support search, and the selected item is highlighted while filling.
- Autofill supports configurable typing and notification animations, with an
  adjustable speed. The card chooser shows its five-second close progress and
  a Keep open control.
- Autofill can be blocked by domain or URL path, or disabled for individual
  login, card and identity items.

### Features in 0.2.30
- Keep the app icon fixed when the back chevron appears in the popup header.

### Features in 0.2.29

- Keep the app icon fixed while the back chevron appears, and move the Add button clear of the popup edge.

### Features in 0.2.28

- Fixed FAB button clipping and scroll behavior: clamped popup height to 600px and stabilized its compact transition while scrolling.
- Kept the app icon aligned when the Back chevron appears in the header.
- Autofill animations: off, quick typing with field highlights, or Plaid mode with a crab crawling across form fields; speed can be set to slow, normal, or fast when animations are enabled.
- AMO compliance: eliminated unsafe `innerHTML` assignments in vendor dependencies for a clean automated AMO linter validation.
- Animated form element autofill: inputs dynamically highlight with a staggered glowing pulse and subtle scale when autofilled, and smoothly pulse on Undo.
- Cleaner popup header: removed redundant header loading spinner in favor of dedicated in-section progress feedback.
- Passkey progress feedback: choosing an account immediately highlights the selected card, disables choices, and replaces the "Use another authenticator" / "Cancel" buttons with dedicated in-panel status text and a loading spinner for real-time progress.
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
  repeated within 30 seconds; opening the vault has a separate shortcut.
  A sign-in that spans several pages stays with one login: for ten minutes,
  the tab's next pages (password, 2FA code) fill, offer first and start the
  shortcut with the login last filled there, or the saved login whose
  username and password were typed in and submitted, not the first match. A brief
  page notification identifies the filled login and username, without passwords.
  Login/custom-field filling rechecks the URI in rbw and the current document.
  Forms are never submitted automatically. On-load filling is off by
  default; when enabled it fills the first matching login unless it requires
  reprompt.
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
