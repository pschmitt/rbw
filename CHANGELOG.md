# Changelog

## [Unreleased]

### Added

* Browser extension: the clipboard marker in the autofill notice wiggles once.
* Browser extension: an item's collections are edited in the editor (switches,
  saved with the item), not in the read-only item view, which just shows them as
  a chip; the editor's "Authenticator key" field is called "TOTP".
* Browser extension: the in-page autofill notice has a countdown bar along its
  bottom edge (like the suggestion window's) that pauses while you hover it.
* Browser extension: the in-page autofill notice has a "next" button when several
  logins match, to fill the next one (the fill shortcut's cycle).
* Browser extension: clicks on the in-page autofill notice no longer fall through to
  the page underneath; clicking the notice dismisses it, and hovering it keeps
  it open.
* Browser extension: the autofill suggestion window and the save-login prompt
  injected into pages slide and fade in and out (not with reduced motion).
* Accounts have a `color` (`rbw account set NAME --color #rrggbb` or
  `--clear-color`; `accounts.<name>.color` in the Nix module). The native host
  reports it and the extension uses it as the default badge color, so the
  "use the rbw command line's accounts" setting covers colors too; a color
  picked in the extension overrides it, with a reset button.
* Browser extension: each account has a color (picker in the settings page's
  Accounts section, distinct defaults from a palette) used for its badge in the
  item list and item view and for its name in the account menu. The Accounts
  section is always listed now, so lock state and colors are visible even when
  the rbw command line picks the accounts.
### Fixed

* `rbw account unlock enroll` (desktop keyring) asks for the master password in
  the same dialog `rbw unlock` uses, checked against the local vault, instead of
  a bare pinentry; pinentry is only the fallback.
* Desktop keyring entries are labelled "rbw account unlock (ACCOUNT)" instead of
  all sharing one label, so several enrollments can be told apart in the
  keyring UI (they were always separate items, keyed by their own unlock id).
  Existing entries keep their old label until you enroll again.
* pinentry-curses no longer prints "no LC_CTYPE known - assuming UTF-8": rbw now
  passes it the client's locale (`LC_ALL`/`LC_CTYPE`/`LANG`, else `C.UTF-8`).

### Changed

* Browser extension: every checkbox is a switch now, including "Do not
  autofill this item" and the collection picker; any checkbox added later gets
  the switch look by default.

## [2.27.1] - 2026-10-23

### Added

* Browser extension: while syncing, the toolbar icon gets a spinning amber ring
  around the crab (a comet-tail arc) instead of a tiny badge; it stays legible
  on dark and light toolbars and at 16, 32 and 48 px.
* The item view lists the item's attachments (name and size) with a download
  button; before they only showed in the editor.
* Browser extension: unlocking an account turns the locked-accounts banner, in
  place and animated, into a short "unlocked" notice, then it goes away.
* Browser extension: all popup notices use that banner style: in the layout
  under the header (so they push the content down instead of covering it),
  colored by kind, and animated in and out.

### Changed

* Browser extension: with several accounts, a locked account is flagged: a
  banner above the list (with Unlock), an amber "L" on the toolbar icon
  while some accounts are locked (red when all are), and the account menu
  opens by itself when everything is locked.
* Browser extension: a locked account with an enrolled fingerprint gets a
  fingerprint button in the popup's account menu (before, the scan was only
  offered on the all-locked screen, for the primary account).
* Browser extension: a locked account's row in the popup's account menu can
  take its master password inline (key button, or automatically when the
  account's own unlock method fails), so "Unlock all" works with a mix of
  chained and password accounts.
* Browser extension: the popup's account menu has an Unlock button per locked
  account and "Unlock all". They first use the account's own unlock policy
  (like `rbw unlock`, so chained unlocking works) and ask for the master
  password only if that fails.
* The item view's collection picker is expanded by default.
* Browser extension settings: the account for import, export and folders
  defaults to the primary account.
* Browser extension settings: the Accounts section shows each account's lock
  state (and how to unlock a locked one), and "Vault state" counts unlocked
  accounts.
* Browser extension: the item list says which accounts are locked and so
  missing from it.
* The in-page autofill notice is larger, names the item whose TOTP or card
  code was copied, and shows a clipboard icon when something was put on the
  clipboard; its messages are shorter.

## [2.27.0] - 2026-10-22

### Added

* `rbw move ENTRY --to ACCOUNT` (alias `mv`) moves an entry, attachments
  included, to another configured account; the original goes to the trash
  (`--trash`, default), is deleted (`--delete`) or kept (`--keep`).
  `rbw copy` (alias `cp`) is `move --keep`.
* Browser extension: an "All accounts" view (the default with several
  accounts) merges search results with an account badge per item, shows
  which accounts are locked with an Unlock button each, offers "Save to
  account" for new items and unsaved logins, and "Move to account..." in the
  item menu.

### Changed

* Browser extension: "Autofill TOTP codes" (off by default, settable by
  browser policy) fills the current code into authenticator-code fields
  (`autocomplete=one-time-code`, or an id/name such as `otp`, `mfa`, `2fa`),
  on 2FA pages with "Auto-fill on page load" and whenever a login is filled.
  The "Copy TOTP after filling" copy is now done by the extension (new
  `clipboardWrite` permission) instead of the agent.
* With "Auto-fill on page load" on, the inline login suggestions no longer
  pop up on focus (they raced the autofill); the inline icon still opens them.
* The item view shows the item's folder, collections and (with several
  accounts) account as chips under its name.
* The item view's password history has a proper section header with a
  chevron, like the other sections.
* The item view shows a globe placeholder for a URI whose favicon can't be
  fetched.
* Browser extension settings: an Accounts section chooses which accounts
  the extension covers: the rbw command line's (default) or any number you
  tick, whose items are all listed and autofilled together.
* Browser extension: the on-load autofill notice shows how many logins
  matched the page ("Autofilled (1/3)"), so you know the fill shortcut can
  cycle through more. The toolbar icon's syncing badge now uses the same
  sync icon as the popup. The options page's "Sync vault" icon spins while
  syncing, like the popup's.
* Browser extension settings: Sync and Lock moved into the header as icon
  buttons (the sync icon spins while syncing), settings are grouped into
  cards of switch rows, switches have a white knob, and "Detailed settings"
  is now a full-width "More settings" button.
* "Show website icons" is now "Show favicons" and on by default, with a
  warning that fetching them lets the saved sites (and the network) see
  which ones are in the vault. A browser that already stored its settings
  keeps its current choice.
* The item view shows each URI's favicon again (with "Show favicons" on),
  and an Android logo for `androidapp://` URIs.
* Locking the vault from the browser extension asks for confirmation first,
  since it locks rbw-agent for every client, including the command line.
* The extension's options page ("More settings") uses the popup's design:
  switch rows instead of checkboxes, selects aligned on the right, and icons
  on the section headings. "Animation speed" is hidden while animations are
  off (popup too), and the export password only shows for the encrypted
  Bitwarden format, which needs it.

### Added

* "Copy TOTP after filling" (off by default, like copying the card security
  code): filling a login that has a TOTP copies the current code to the
  clipboard (through rbw-agent, so its clipboard clearing applies) and the
  in-page fill notification says so, ready for the site's second step.
* Browser policy (managed storage) can set `copyTotp` and
  `cardSecurityCode`; both settings views lock policy-set controls.
* The options page's folder manager loads on its own, lists folders
  alphabetically with a count, renames in place and uses icon buttons.

* The item editor picks the folder from a dropdown of the account's folders
  (or "No folder"); "New folder…" reveals a name field and saving creates it.

* Trashed items open in a read-only item view with Restore and "Delete
  permanently" (confirmed; only for items already in the trash), and trash
  rows offer "Delete permanently" next to Restore.

### Fixed

* `rbw-agent` no longer reports a clipboard copy as done when it has no
  clipboard (e.g. it started without a display): it adopts the asking
  client's display and retries, or returns an error. This is what made the
  browser's TOTP copy silently do nothing.
* `rbw unlock` names the account in "✓ Vault unlocked (NAME).", which
  matters when one run unlocks several accounts.
* "Manage keyboard shortcuts" did nothing in Firefox (extensions can't open
  `about:addons`); it now opens Firefox's shortcut settings directly.
* Releases commit the signed browser packages on top of the tag and point a
  new `release` branch at that commit (then merge it into `main`), so commits
  landing on `main` during a release no longer break it. Nix consumers
  should follow `github:pschmitt/rbw/release`.

## [2.26.0] - 2026-10-22

### Added

* Desktop unlock can store the master password outside the keyring:
  `rbw security unlock enroll --store tpm2` seals it with `systemd-creds` to
  the machine's TPM (and host key), `--secure-boot` also binds it to the
  Secure Boot state (PCR 7), and `--store file` keeps it in an owner-only
  file.
* `rbw-unlockd`, a root-owned unlock broker with a NixOS module
  (`nixosModules.default`, `services.rbw-unlockd.enable`). With `rbw
  security unlock enroll --broker` it holds the credential and only releases
  it after fprintd verifies a finger of the requesting user, so the
  fingerprint is enforced rather than checked by rbw alone. Requests are
  logged with the calling program, and repeated failed scans lock the user
  out for a growing period.
* Enrollment and `rbw security unlock status` warn that the fingerprint is
  only a convenience check when the user's own programs can read the saved
  password (any store without `--broker`), and when it is stored
  unencrypted.

## [2.25.1] - 2026-10-22

### Added

* `rbw show --mask` prints dots instead of secret values (password, TOTP
  seed, card number and CVV, SSN, SSH private key, hidden custom fields),
  without revealing their length.

### Changed

* The `--fzf` preview uses `rbw show --mask`, so passwords and other secrets
  no longer appear in it.

## [2.25.0] - 2026-10-22

### Added

* The browser extension unlocks with the fingerprint reader for accounts
  enrolled with `rbw security unlock enroll --keyring --fingerprint`: an
  **Unlock with fingerprint** button in the locked view runs the scan in the
  native host, and typing the password or closing the popup cancels it. The
  new `browser.fingerprintAutoStart` setting (off by default, also a Home
  Manager option) starts the scan as soon as the popup opens.

### Changed

* The terminal unlock dialog has a compact layout for terminals smaller than
  40×27 (narrow tmux panes, phones) instead of asking to enlarge the window:
  it keeps the password field and drops decoration, status and hint lines as
  space runs out. Only below 16×4 does it still pause input.

## [2.24.1] - 2026-10-22

### Fixed

* The `--fzf` preview failed with "no entry found" when the matches were
  pooled from several accounts; it now looks each entry up in its own
  account.

## [2.24.0] - 2026-10-22

### Added

* `--fzf` on `get`, `show`, `code`, `edit`, `set`, `remove`, `archive`,
  `unarchive`, `restore`, `history`, `attachment` and `passkey` lookups picks
  among several matching entries with fzf (`--select-1`, colored `rbw show`
  preview) instead of failing. Extra fzf options come from `RBW_FZF_OPTS` or
  the `fzf.options` setting; `fzf.enabled` turns the picker on without the
  flag when rbw runs on a terminal. `CLICOLOR_FORCE` forces colored output.
* `rbw security change-password`, `rbw security rotate-key` and `rbw security
  kdf` change the master password, rotate the account key (re-encrypting the
  personal vault) and show or change the KDF settings. `change-password
  --rotate-key` does both in one request. A Secret Service unlock credential
  is updated with a new password.
* `rbw security unlock enroll|remove|status` sets up native unlock with one
  command: the desktop keyring (`--fingerprint` optional) or, detected inside
  Termux, the Android Keystore; `--keyring`/`--termux` choose explicitly.

### Changed

* `rbw secret-service` and `rbw termux` are superseded by `rbw security
  unlock` and hidden from the help; they keep working.

### Fixed

* `rbw purge` no longer fails on systems without `termux-keystore`.
* The browser extension's light theme uses its own palette again: the old grey
  light colors overrode it. The palette now lives in `theme.css`, which
  browser-daemon's live view shares.
* `rbw org delete` uses `DELETE /organizations/{id}`; Vaultwarden 1.37 dropped
  the `POST .../delete` route it used.
* `rbw send create --file` uploads work against Vaultwarden again (the file
  part lacked a content type and had its encrypted name percent-encoded).
* Send API errors include the server's message.
* Per-item results and errors of bulk commands (`collection assign`, import,
  mirror, ...) are printed when stderr is not a terminal instead of dropped.

## [2.23.0] - 2026-10-22

### Added

* Native Linux fingerprint unlock and encrypted Secret Service enrollment for
  individual accounts, with password and fingerprint unlock available together.
* Integrated terminal unlock dialog and optional GTK4 window (`gtk-ui` feature,
  Nix `rbw-gtk` package), with live fingerprint status, verification animations,
  disabled submit while checking, and success feedback.
* `unlock --ui`, optional `--no-echo`, persistent `unlockUi` / `unlockNoEcho`
  settings, and matching Home Manager options. `unlock --pinentry` remains an
  explicit password-only recovery path.

### Changed

* Update `zbus` to 6, `gtk4` to 0.11 and `open` to 5.4.5. The minimum supported
  Rust version is now 1.92.

### Security

* Require Tokio 1.54.1 or newer, fixing the timer race in RUSTSEC-2026-0384.
* Integrated unlock input uses isolated, locked memory with wiping on edit and
  exit; Linux dialogs disable process dumps and suppress background logging.
* D-Bus wire diagnostics are disabled to keep credential traffic out of logs.
* Enrollment verifies the master password against the cached encrypted vault.
  Fingerprint approval is an application policy over the keyring, rather than
  hardware enforcement; see `docs/desktop-unlock.md` for the security model.

## [2.22.16] - 2026-10-21

### Changed

* Browser popup: remove the Open sidebar button from the header.

## [2.22.15] - 2026-10-21

### Changed

* Browser popup: compact the locked view, put Unlock beside the master
  password field, and show a toolbar badge while locked. Popup notifications
  now use color and leading icons, with a right-side entrance animation.

## [2.22.14] - 2026-10-21

## [2.22.13] - 2026-10-21

### Added

* `rbw get --raw` includes `linked_id` (the Bitwarden number, for example 100
  for the login username and 101 for the password) on linked custom fields.

## [2.22.12] - 2026-10-20

### Added

* Browser autofill can be enabled on plain HTTP sites in extension settings;
  it remains disabled by default. The warning shown when autofill is blocked
  links directly to settings.

## [2.22.11] - 2026-10-20

### Fixed

* Browser passkeys recover when another extension replaces a WebAuthn handler
  during startup, with at most five reinstalls per method in ten seconds. rbw
  cooperates with browser-daemon’s live-view wrapper and keeps captured older
  rbw handlers from prompting a second time during fallback.

## [2.22.10] - 2026-10-20

### Added

* Browser generator: save the generated password straight into a vault
  item. "New login" opens the editor prefilled for the current site (name
  and URI from the active tab); "Update a login" picks a login for this site
  (or any login, via search) and opens it with the new password filled in.
  Both wait for you to review and save.

### Changed

* Browser passkeys are registered with Bitwarden's AAGUID instead of the
  anonymous all-zero one, so sites label them "Bitwarden" rather than with a
  generic fallback name. The credential is stored in the Bitwarden vault and
  works from every Bitwarden client. Configurable with
  `browser.passkeyAaguid` (and the home-manager option of the same name);
  all zeros restores the anonymous AAGUID.
* Browser confirmations (deleting items, attachments, Sends and folders,
  removing a Send password, exports and imports) use an in-popup sheet
  instead of the browser's native `confirm()` dialog. Destructive actions
  start focused on Cancel.
* New items created from a saved login or a new passkey drop a leading
  `www.` from the site name (`passkeys.io`, not `www.passkeys.io`).

* Dependencies: tokio 1.54.0, a lock file refresh of transitive crates and
  the Nix flake inputs, and web-ext 10 for signing the Firefox package.
  Renovate now also tracks `flake.lock`, transitive `Cargo.lock` updates
  and the web-ext pin.

### Fixed

* Browser passkey popup: the second and later account choices are no longer
  indented relative to the first.

## [2.22.9] - 2026-10-19

### Changed

* Browser passkey popup: dropped the redundant spinner below the progress
  steps, and the toolbar popup now sizes to its content on the passkey
  approval page instead of always being 600px tall.
* Browser generator redesign: a large colour-coded result card (digits and
  symbols highlighted) with a strength meter and entropy in bits, a
  Password / Passphrase / PIN switch, a length slider (default 40
  characters, 6 words or 8 digits) and switches for symbols and easy-to-read
  output. It regenerates on every change and remembers its settings.
* Browser Send redesign: Send cards show type, expiry, view count, password
  and disabled state as chips; a friendlier empty state; and an editor with
  a Text / File switch, a file drop zone, one-tap expiry chips, a revealable
  access password and switch-style options.

## [2.22.8] - 2026-10-19

### Fixed

* Browser: a browser still running from before a Nix upgrade replaced its
  store path is accepted as the same enrolled `browser.clients` executable
  (same package name, same binary path inside the store entry), instead of
  failing with "Browser access denied" until it is restarted.
* Browser passkeys: the request's page and frame are matched by origin and
  document ID rather than exact URL, so single-page login apps (Authelia)
  that rewrite their URL no longer fail with "The requesting document
  changed." The error now names the origins that differed.

## [2.22.7] - 2026-10-19

### Changed

* Re-release of 2.22.6, whose release run failed before publishing
  (no macOS runner); AMO signs each version only once.

## [2.22.6] - 2026-10-19

### Changed

* CI: the release workflow signs the browser extension on the version tag
  (AMO and CRX), publishes it and commits the signed packages to `main`, so
  `just release-packages` is gone. Pushes and pull requests build the
  unsigned packages in one `browser` job.
* Browser passkey sign-in returns the assertion right after signing; the
  follow-up vault sync and counter confirmation run in the background
  instead of holding up the login. If that sync fails, the toolbar badge
  shows a red "!" and the popup offers "Sync now" until a sync succeeds.

### Fixed

* Browser passkey popup: "Cancel request" is now as wide as "Use another
  authenticator".

## [2.22.5] - 2026-10-19

### Changed

* The toolbar sync indicator sits in the top-right corner of the rbw icon,
  where the matching-login count is, and replaces that count until the sync
  finishes instead of overlapping it.
* The browser fill button shows a filled-in form field instead of an arrow.
* Passkey sign-in progress spins a refresh icon on the running sync step and
  marks finished steps with a green checkmark, shown briefly before the popup
  closes.
* The popup header no longer shows the settings button on the settings page.
* The left arrow key goes back from the popup's item, settings and diagnostic
  pages, like the header's back chevron.
* An unsaved item edit survives closing the popup: reopening it resumes the
  edit with a notice and a Restart button that starts over from the current
  vault state. Only the latest edit is kept, in memory, until it is saved,
  cancelled or restarted, or the vault locks.
* Leaving the item editor with unsaved changes (Cancel, back or a tab switch)
  asks "Discard your unsaved changes?"; Discard or the same exit again
  confirms.
* Login save suggestions that were dismissed, expired or lost with their tab
  show up under "Unsaved logins" in the popup, where they can still be saved
  (or update the matching login) or dismissed. Up to 10 are kept in memory,
  never shown with their password, and dropped when the vault locks or once
  the vault already has them.

### Fixed

* Going back from the settings page of a reopened popup showed an empty
  vault; the list now loads.

## [2.22.4] - 2026-10-19

### Changed

* Browser custom fields also match a form field by its label, placeholder,
  `aria-label` or `autocomplete` value (ignoring case and punctuation), so
  either `company` or `Company ID` fills the HR WORKS company field.
* The browser popup shows a "Saving…" spinner and locks the item editor while
  a save is in progress, instead of appearing to hang.

### Fixed

* Animated browser fills dispatched `change` on every typed character, which
  broke pages that post each change to their server (HR WORKS: "Invalid nonce
  while updating forms"). Only the final value now fires `change`.

## [2.22.3] - 2026-10-19

### Added

* Keyboard navigation in the browser: the popup focuses its search field when
  opened; arrow keys move through items, Enter opens one and Shift+Enter
  fills it. The inline login and card choosers accept arrow keys and Enter
  in their search field.

### Changed

* The browser popup labels verification codes "TOTP".
* Much shorter README and browser README; the detailed documentation moved
  unchanged into `docs/`.
* The Nix package builds with crane: dependencies are a separate,
  version-independent derivation, so CI and hosts reuse them instead of
  recompiling every crate on each rbw change. Tests still run in the build.
* CI: rustdoc skips dependencies, and the browser extension is only signed on
  release commits.

## [2.22.2] - 2026-10-18

### Added

* `defaultUriMatch: base_domain` (also selectable in the browser add-on
  options) opts into Bitwarden's base-domain matching for URIs without their
  own match type.
* The inline login chooser has the same search field as the card chooser; it
  searches this site's matching logins.
* The toolbar icon shows an animated sync badge while the extension syncs or
  saves.

### Changed

* `defaultUriMatch: domain` is rbw's matching again (the stored host and its
  subdomains) and remains the default, reverting 2.22.1's switch to
  Bitwarden's base domain. URIs explicitly set to "Base domain" keep
  Bitwarden's meaning.
* "Do not autofill this item" moved from the item view to an "Advanced"
  section at the bottom of the item editor.

### Fixed

* The add-on options page no longer cuts off below 600 pixels.

## [2.22.1] - 2026-10-18

### Added

* `defaultUriMatch` config option (`rbw config set defaultUriMatch host`, Home
  Manager `defaultUriMatch`): the match type for login URIs without their own,
  like Bitwarden's "Default URI match detection". The browser extension shows
  rbw's default and can override it per browser in its options.
* The browser item editor lists URIs one per row with their own match
  detection (Default, Base domain, Host, Starts with, Exact, Regular
  expression, Never) and a "Match for all" shortcut; item details show
  non-default match types.

### Changed

* `Domain` URI matching now works like Bitwarden's "Base domain": hosts match
  when they share a registrable domain (eTLD+1 per the public suffix list), so
  a login for `login.example.com` also matches `www.example.com`, and ports
  are ignored for such domains. IP addresses, `localhost` and other hosts
  without a registrable domain still need the exact host and port.

## [2.22.0] - 2026-10-18

### Changed

* The browser extension now shares rbw's version and is released together
  with it: `v*` releases ship the CLI, native host and both signed browser
  packages. `tools/release.sh` (`prepare`, `packages`, `tag`) drives a release;
  the separate browser extension release workflow is gone.
* Browser autofill hardening (extension 0.2.34–0.2.35): inline suggestions and
  the save prompt render in extension frames with background click
  verification against clickjacking; fills skip hidden, tiny or off-page fields
  and stay within the focused form; hidden custom fields and linked
  SSN/passport/license values are not auto-filled; on-load autofill and website
  icons default to off; plain-HTTP pages are never filled.
* The browser save prompt shares the autofill chooser's header (Keep open,
  close button, auto-close progress) and hides after 20 seconds; buttons have
  icons and the site's icon or the rbw logo is shown. Submitted credentials
  are compared with this site's stored logins: an identical login (for
  example one just autofilled) no longer prompts, and a stored username with a
  different password offers "Update password" directly.
* CI builds unsigned browser packages on every push and pull request
  (`browser-extensions-unsigned` artifact). Docker images build natively per
  architecture (no QEMU) with cargo-chef dependency caching.

### Fixed

* URI matching: `StartsWith` now requires the same origin, so
  `https://example.com` no longer matches `https://example.com.evil.net/`.
  Scheme-less URIs no longer match plain-HTTP pages in the browser.

## [2.21.2] - 2026-10-18

### Added

* Browser passkey authentication reports before-sync, signing and after-sync
  progress, retries a failed sync once, and confirms the reserved passkey
  counter from the synchronized vault before returning the assertion.
* Browser autofill supports credit cards, animated fills and notifications,
  inline search, and per-site and per-item autofill exclusions.

## [2.21.1] - 2026-10-17

### Fixed

* Shell completions: add dynamic completions for `rbw send` (`remove`, `view`, `edit`, `link`, etc.) resolving Send names dynamically across zsh, bash, and fish.
* Shell completions: complete configured accounts dynamically for `-a`/`--account` across zsh, bash, and fish.
* Shell completions: complete output formats (`name`, `json`, `yaml`) for `-o`/`--output`.

## [2.21.0] - 2026-10-17

### Added

* `rbw send`: Full Bitwarden Send management from the command line:
  * `rbw send list` (alias `ls`): List active and expired Sends with status, type, access count, and expiration date. Supports `--json` and `--yaml`.
  * `rbw send view` (aliases `get`, `show`): View detailed metadata and decrypted content for a Send, or print decrypted text directly with `-t`/`--text`.
  * `rbw send create` (aliases `new`, `add`): Create text or file Sends with optional password protection, expiration timestamps, access count limits, and clipboard link copying (`-c`/`--copy`).
  * `rbw send edit` (alias `update`): Update Send metadata, notes, text, access password, expiration date, max access limit, disabled state, and email visibility.
  * `rbw send remove` (aliases `rm`, `delete`): Delete a Send by name or ID with confirmation prompt (`-y`/`--yes` to skip).
  * `rbw send link` (alias `url`): Print or copy (`-c`/`--copy`) the direct shareable web access URL for a Send.
* Browser extension 0.2.14 with updated crab-and-shield icon and transparent toolbar icons for Firefox and Chromium.

### Added

* Browser preview 0.2.3: passkey registration/authentication, in-popup master
  password entry, Bitwarden-inspired vault layout and a generated shield/gear
  icon, full item editing, inline suggestions, save/update offers, cards and
  identities, generator modes, attachments, Sends, local vault reports,
  import/export, folder/collection management and a dedicated options page.
* Native messaging allowlist (`browser.clients`), denying browser access until
  both the browser executable and extension ID are explicitly enrolled.
* Firefox sidebar and Chromium side panel, context menu and keyboard commands.
* Agent operations for explicit master password verification and wrapping short
  binary key material; the browser never receives account or passkey keys.

### Fixed

* Master password reprompt now also protects passkey keys, notes and password
  history. Malformed agent requests are no longer echoed into logs.
* Browser item edits preserve existing passkeys and require the viewed revision.
* Browser passkey assertions preserve synced zero counters and only claim user
  verification after checking the master password. Existing CLI counter policy
  remains unchanged.

## [2.20.1] - 2026-10-15

### Added

* `rbw edit --field FIELD ENTRY` edits one field (name, username, password,
  notes, totp, uris one per line, or a custom field, created as hidden when
  missing): the value is read from piped stdin, e.g. `rbw edit --field
  token ENTRY <<< value`, or from `$EDITOR` prefilled with the current value,
  then saved through the same path as `rbw set`. Ported from doy/rbw#367.
* `rbw set --field NAME ENTRY` without `=VALUE` reads the value from stdin
  (a single trailing newline is stripped), e.g. `rbw set --field token ENTRY
  <<< value`.
* `rbw passkey assert --origin ORIGIN --challenge CHALLENGE [--rp-id RP]
  [--allow ID]... [ENTRY]` signs one WebAuthn assertion (ES256) and prints it
  as JSON for a caller that answers the page's `navigator.credentials.get()`
  itself, in any browser. The origin must belong to the passkey's relying
  party; the key never leaves rbw; the counter is reserved in the vault first.
* `rbw passkey find [--rp-id RP] [ENTRY]` prints, as a JSON array without any
  secret, the entries whose passkey would be used (id, name, username,
  relying party): every candidate for `--rp-id` when no entry is named, so a
  caller can pick one by id. It fails instead of prompting when the vault is
  locked.
* `rbw passkey inject --rp-id RP` without an entry name picks the one live
  login holding a passkey for that relying party (only entries carrying
  passkeys are decrypted). Several matches are an error that asks for a name.

### Changed

* `rbw passkey inject`, `assert` and `counter --set` sync the vault again
  after writing the counter, check that the server holds at least the written
  value, and remind you to sync other Bitwarden clients before using the
  passkey there (a client on an older counter is rejected as a clone).
* Dependency updates: tokio 1.53.3, zip 9.0.3, arboard 3.7.0.

### Fixed

* rustls 0.23.46 (RUSTSEC-2026-0346, RUSTSEC-2026-0347, RUSTSEC-2026-0348).
* `rbw set` asks for confirmation on the terminal when stdin already carried
  the value (`--password-stdin`, `--field NAME`) instead of reading EOF as
  "no" and aborting; without a terminal it fails asking for `--yes`.
* The agent seeds its fallback pinentry environment from its own process, so
  an ssh-agent unlock that arrives before any rbw command no longer runs
  pinentry without DISPLAY/WAYLAND_DISPLAY/TERM. Ported from doy/rbw#388.

## [2.20.0] - 2026-10-13

### Added

* `rbw passkey counter` reads or advances a credential counter;
  `rbw passkey inject` sends a passkey directly to a Chromium page over CDP,
  reserves its next counter before use, and synchronizes the browser assertion
  counter back to the vault. Prevents fresh automated browser sessions from
  resetting counters and triggering relying-party clone detection.

### Fixed

* Preserve reprompt, favorite and the original archive timestamp on full
  cipher PUTs, including passkey counter updates and imported-item edits.
* Persist a synced vault before replacing the agent's reprompt ciphertext set.
* Refresh CLI edit/set selectors before use and report stale cipher revisions
  clearly instead of a generic API error.
* Exit 2 after confirmed writes with failed local follow-up, and after partially
  successful bulk updates, so callers can avoid repeating a write.
* Retain failed interactive create/edit buffers with private permissions;
  piped input and edits already confirmed by the server are not retained.
* Passkey injection reads Chromium's final counter after disabling presence,
  including assertions that raced with the disable command, before vault
  writeback. It removes the authenticator before starting that writeback.
* Warn when injection or `passkey counter --set` enables tracking on a
  zero-counter credential: other Bitwarden clients must sync before use.

### Changed

* The Rust `actions::edit` and `api::Client::edit` methods require
  `CipherWriteMeta`; `db::Entry` also stores favorite and archive timestamp.
  Older serialized caches remain readable, but downstream Rust struct literals
  and edit callers need updating.
* Dependency updates: zip 9.0 (attachment filenames are now decoded
  fallibly; legacy CP437 names remain supported), sha2 0.11.1,
  uuid 1.28.0, serde_json 1.0.154.

## [2.19.0] - 2026-10-07

### Added

* WebAuthn / FIDO2 security key 2FA for `rbw login` (behind the new
  optional `fido2` cargo feature, enabled in the Nix package; needs libudev
  on Linux). The agent streams progress ("touch your security key")
  back to the client and asks for the key's PIN via pinentry when needed.
  Ported from doy/rbw#383 by Frederik Schwan.

### Changed

* Dependency updates: region 4.0.1, thiserror 2.0.21, libc 0.2.190,
  uuid 1.27.0, tokio 1.53.2, zeroize 1.9.1; Docker build image
  rust:1.99-bookworm.

## [2.18.0] - 2026-10-06

### Fixed

* Vaultwarden 1.37.4 compatibility: cipher writes (`add`, `generate`,
  `set`, `edit`, `import`, ...) now send `encryptedFor` (the account's
  user id, taken from the access token's `sub` claim), which Vaultwarden
  1.37.4 requires on every cipher create/update -- without it all of them
  failed with `422 Unprocessable Entity`.
* e2e: register the test account through the `send-verification-email`
  -> `finish` flow (Vaultwarden 1.37.4 dropped the legacy
  `/identity/accounts/register`), falling back to the legacy endpoint on
  older servers.
* Cipher edits (`rbw set`, `rbw edit`, and friends) now send Bitwarden's
  `lastKnownRevisionDate`, so the server rejects an update built from an
  outdated local copy instead of letting the full-object replace silently
  revert a newer change made elsewhere.
* `rbw set` now syncs after updating (it previously only did after
  uploading attachments), so a follow-up `rbw set` no longer builds its
  update from the pre-edit copy -- e.g. `rbw set --password-file ...`
  followed by `rbw set --field ...` reverted the password.

### Added

* `rbw set --password-stdin`/`--password-file FILE`/`--password-env VAR`
  (and `--totp-file`/`--totp-env`): pass a new secret without it showing
  up in the process list or shell history, as `--password`/`--totp` do.
  A single trailing newline is stripped from stdin/file input; empty
  values are refused. `--password-stdin` requires `-y`, since stdin can't
  also answer the confirmation prompt.
* `rbw set --generate` (`-g`, with the usual pwgen flags and configured
  policy): generate and store a new password in one step; the old one
  moves to the password history as usual. Nothing is printed unless
  `--output-file FILE` (mode 0600, `-` for stdout) is given, which writes
  the password only after it was saved -- e.g. to pipe it into `sops
  set`. `--output-file` requires `-y`; `--generate` conflicts with
  `--bulk`.
* `rbw set --field NAME=VALUE`/`--field-file NAME=FILE`/`--field-env
  NAME=VAR` (repeatable): set custom fields. An existing field of that
  name keeps its type; otherwise a new hidden field is added. Linked
  fields are refused. Works with `--bulk` and `--from-file` too.
* Entries now keep the server's `revisionDate` (stored in the local
  database from the next `rbw sync` on) and expose it as `revision_date`
  in `rbw get`/`rbw list --output json`.
* `rbw list --older-than AGE` (e.g. `90d`, `1year`): only list entries
  last modified more than AGE ago -- e.g. to find credentials due for
  rotation. Entries without a stored revision date are skipped with a note
  to run `rbw sync`. `rbw list --fields ...,modified` shows the date.
* `rbw set --if-revision REVISION_DATE`: syncs, then refuses to update an
  entry whose revision date no longer matches, so a change made elsewhere
  between looking at an entry and updating it isn't silently overwritten.
* `rbw history ENTRY --restore[=N]` (`-y` to skip the prompt): make the
  N-th previous password (default: the most recent one) current again,
  e.g. to roll back a rotation that failed verification. Goes through the
  regular `rbw set` path, so the replaced password lands in the history.
* `rbw audit`: report weak (rough character-class estimate below
  `--min-bits`, default 60) and reused passwords across the active
  account's live Login entries; `--hibp` also checks Have I Been Pwned via
  its k-anonymity range API (only the first 5 hex characters of each
  password's SHA-1 are sent). Reports entries only, never passwords;
  `--output json/yaml` for scripts, `--fail` to exit non-zero on findings.

## [2.17.12] - 2026-09-25

### Added

* `rbw add --secure-note`: create a secure note instead of a login (the
  counterpart of upstream doy/rbw#381). The editor template switches to
  `data: {type: secure_note}` with an empty `notes` field; piped stdin is
  stored verbatim as the note (`NAME` is then required). Conflicts with
  `USER`, `--uri`, and `--generate`/pwgen flags. Works with `--from-file`
  too.

## [2.17.11] - 2026-09-22

### Changed

* `rbw account list`: rendered as a proper aligned, colored table (same
  renderer `rbw list` uses) instead of plain tab-separated `println!`.
* `rbw account list`: added a `status` column showing each configured
  account's current locked/unlocked state (green "unlocked" / red
  "locked"), queried from `rbw-agent` the same way `rbw unlocked` and the
  TUI's lock poll already do.
* `rbw account list`: the primary-account marker is now a bold yellow `*`
  suffixed directly to the name with no space (`name*`), instead of a
  plain trailing `" *"`.

## [2.17.10] - 2026-09-22

### Changed

* Merged the outstanding Renovate dependency PRs: `textwrap` 0.16.2 ->
  0.16.4, `uuid` 1.26.0 -> 1.26.1, `open` 5.4.3 -> 5.4.4, `clap`/
  `clap_builder`/`clap_derive` 4.6.6/4.6.6/4.6.4 -> 4.6.7, `clap_complete`
  4.6.9 -> 4.6.11, `rustix` 1.1.4 -> 1.1.5, `rand` 0.10.2 -> 0.10.3, and
  `DeterminateSystems/nix-installer-action` v22 -> v23 in CI. Applied
  fresh against the current lockfile rather than merging the PRs' own
  diffs, which were based on a stale `Cargo.lock` and would have
  regressed several `windows-sys` transitive versions as a side effect.

## [2.17.9] - 2026-09-22

### Changed

* Bumped `rustls` 0.23.43 -> 0.23.45, fixing
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285)
  (TLS 1.3 handshake messages incorrectly accepted across encryption level
  boundaries).

## [2.17.8] - 2026-09-22

### Fixed

* Editing a login item holding a FIDO2/passkey credential failed against
  the official Bitwarden server with `Cannot edit item. Update to the
  latest version of Bitwarden and try again.` The server rejects such
  edits when the request's `Bitwarden-Client-Version` sorts below its
  `Fido2KeyCipherMinimumVersion` gate (`2023.10.0`), and a missing header
  counts as no version at all. rbw's shared async HTTP client sent its own
  crate version there (which will always sort below that), and
  `Client::edit()`'s separate blocking HTTP client sent no client-version
  header whatsoever. Both now send a fixed, modern version string, kept
  below `MinimumClientVersionForV2Encryption` (`2025.11.0`) since rbw
  doesn't support V2 encryption yet.
* When syncing/unlocking multiple accounts, a secondary (non-primary,
  non-target) account failing to auto-unlock aborted the whole operation.
  It's now logged as a warning and skipped, so the other accounts' entries
  are still available.

## [2.17.7] - 2026-09-14

### Fixed

* rbw only deserialized `access_token` from the OAuth token-refresh
  response, so a `refresh_token` rotated by an SSO-backed Vaultwarden (via
  an external identity provider consuming the previous one on exchange)
  was silently dropped, and rbw kept replaying the stale token -- breaking
  every refresh after the first rotation. Now persisted at every call site
  that already persists a rotated access token, across this fork's larger
  surface of token-refreshing actions (org/collection management, bulk
  import, mirror, TUI) than upstream. Adapted from
  [doy/rbw#378](https://github.com/doy/rbw/pull/378).

## [2.17.6] - 2026-09-05

### Fixed

* TUI: the detail pane's "collection" rows showed the collection's raw
  encrypted name (e.g. `2.tiYZYAaSuZRJLMJHOpqStw==|...`) instead of its
  actual name -- unlike organization names, collection names are org-key
  -encrypted in the sync response, and this one display path never
  decrypted them.
* TUI: fixed a visible flash of that same still-encrypted collection name
  before the real one replaced it, introduced by the fix above -- the
  detail pane now decrypts the org/collection scope once per entry
  (alongside the rest of the entry's detail) instead of redoing it on
  every redraw.

## [2.17.5] - 2026-09-05

### Changed

* Updated dependencies across the board via Renovate, including a
  coordinated major-version bump of the `aes`/`aes-gcm`/`argon2`/`cbc`/
  `hkdf`/`hmac`/`pbkdf2`/`rand`/`region`/`sha1`/`sha2`/`signature`/
  `ssh-agent-lib`/`tokio-tungstenite`/`totp-rs` crate group (real API
  breaks throughout, fixed and fully re-tested; `cbc` dropping its `std`
  feature was the main one) plus dozens of smaller lockfile-only bumps
  (anyhow, arrayvec, axum, base64, flate2, libc, log, rsa, rustix,
  serde_json, terminal_size, tokio-stream, env_logger, open, regex,
  tempfile, uuid, zeroize, and several GitHub Actions).

### Fixed

* Reverted `reqwest` to 0.12.28 (kept off the crypto bump above): 0.13
  pulls in `aws-lc-rs` via rustls's feature-unification default, which
  fails to link against musl (`undefined reference to
  __isoc23_sscanf`/`__isoc23_strtol`). Renovate is now told to leave
  that specific major bump alone.
* `rbw config set`/`config edit`/`stop-agent`/`kill-agent` could hang
  forever waiting for a just-stopped agent to disappear: the check used
  (`kill(pid, 0)`) keeps reporting a zombie as present until something
  reaps it, which containerized CI runners (GitHub Actions' own runner
  included) don't always do promptly. Now gives up after a few seconds
  instead.

### Added

* e2e coverage for `restore`, `archive`/`unarchive`, `history`, `code`
  (TOTP), `attachment create/list/get/rm`, `add --yaml`, `export` ->
  `purge-vault` -> `import`, and `lock`/`unlock` (the last driven through
  a scripted fake pinentry, exercising the real agent-unlock code path
  non-interactively on CI).
* Converted the e2e suite from a hand-rolled bash script to
  [bats](https://github.com/bats-core/bats-core), for per-test isolation
  and granular pass/fail reporting.

## [2.17.4] - 2026-08-27

### Added

* Home Manager module (`programs.rbw.declarative`): `email`/`ssoId`/
  `baseUrl`/`identityUrl`/`uiUrl`/`notificationsUrl` on an account can
  now be given as `{ file = /path/to/secret; }` (e.g. a sops-nix
  secret's `.path`) instead of a literal string. Resolved by `rbw`
  itself the moment it actually needs the value (login, sync, TUI,
  ...), with a clear error if the file isn't readable; round-trips
  through `config.yaml` unchanged either way, so `config
  set`/`config edit`/`account add` never bake the resolved value in.
  The module now renders `config.yaml` as a plain declarative file
  again instead of materializing it at activation time, so nothing
  about home-manager rendering it can race a secrets manager's own
  decrypt step.

### Fixed

* CI: fixed a clippy regression only newer toolchains flag
  (`manual_is_variant_and`), and the e2e job's own build step, which
  never actually built the `rbw`/`rbw-agent` binaries the script
  needs -- every e2e run had been failing since it was added.

## [2.17.3] - 2026-08-17

### Fixed

* Don't let one corrupt entry break vault-wide `list`/`search`/`get`/
  `remove`/`set --bulk`/etc. -- `find_entry`, `find_entry_multi`,
  `find_entries_all`/`find_deleted_entries_all`, `find_deleted_entry`,
  `list`, `search`, and the TUI's search-index rebuild now skip a bad
  entry and log a warning instead of failing the whole scan.

### Added

* Real-server end-to-end tests in CI: a throwaway Vaultwarden service
  container is exercised over the actual wire protocol (not mocked
  HTTP), covering single-field-edit preservation, `--bulk` edits, and
  one-corrupt-entry resilience.

## [2.17.2] - 2026-08-17

### Fixed

* Thread an entry's individual encryption key through `set`/`edit`, and
  round-trip it on every PUT, so editing one field of such an entry no
  longer risks leaving its other fields encrypted under the wrong key.
* Don't let one corrupt password-history entry hide an otherwise-fine
  entry's current data -- `decrypt_cipher` now degrades a bad history
  entry individually instead of failing the whole entry.

## [2.17.1] - 2026-08-14

### Added

* Add declarative mirror configuration with `rbw mirror --config FILE`.

## [2.17.0] - 2026-08-08

### Changed

* **Breaking:** `aliases` in `config.yaml` is now a list of entries instead
  of a map keyed by alias name, so multiple shortcut names can share one
  entry: `aliases: [{alias: [gpg, gnupg], item: "GPG key"}]`. `alias`
  accepts either a single string or a list of strings. Update any existing
  `aliases: {name: {...}}` config to the new list form.

## [2.16.3] - 2026-08-07

### Added

* Add config-driven item `aliases` for `rbw get`: a shortcut name (e.g.
  `gpg`) can resolve to a specific item, optionally pinned to an account,
  collection, org, and/or field. Only applies to a bare `rbw get NAME`;
  `--no-alias` disables resolution for a single invocation, and
  `--verbose` logs which alias was resolved.

## [2.16.2] - 2026-08-02

### Added

* Include archived and trashed entries in exports by default, with
  `--skip-archived` and `--skip-trash` opt-outs.
* Preserve archived and trash status through rbw imports and Bitwarden JSON-
  based export formats.

## [2.16.1] - 2026-07-31

### Added

* Add `org:` and `col:` filters to the TUI, `rbw search`, and `rbw list
  <term>`, and show organization/collection metadata in the TUI preview.

## [2.16.0] - 2026-07-31

### Changed

* Reorganize `config.yaml` into grouped `agent`, `pinentry`, `tui`, and
  `hide` sections, and use camelCase for configuration keys.
* Rename TUI keybinding action names to camelCase, including `forceQuit`.
* Add `rbw agent stop`, with `--kill` for an unresponsive agent; retain
  `rbw stop-agent` as a compatibility alias.

## [2.15.0] - 2026-07-31

### Added

* Use YAML for the rbw configuration by default while continuing to support
  legacy JSON configuration files. When both exist, `config.yaml` takes
  precedence over `config.json`.

### Fixed

* `rbw import` and `rbw export-info` now resolve a missing passphrase for a
  gpg-encrypted export from `RBW_EXPORT_PASSPHRASE` or a `/dev/tty` prompt,
  matching `--from-file`'s existing behavior, instead of erroring and asking
  for `--decrypt`/`--decrypt-passphrase` up front. Non-interactive runs
  (no passphrase, no tty) keep the original fail-fast error.

## [2.14.3] - 2026-07-31

### Fixed

* Verify the master password actually unlocks the account before enrolling
  a Termux Keystore key against it (`rbw termux enroll`). Previously a
  mistyped password was encrypted into the unlock bundle unchecked, so it
  would only surface as a failure on the next real unlock.

## [2.14.2] - 2026-07-31

### Fixed

* Restore the `termux-fingerprint` prompt before Termux Keystore signing --
  `termux-keystore sign` never authenticates on its own, so removing it in
  2.13.11 left every sign failing with `UserNotAuthenticatedException` and no
  prompt at all.
* Fail loudly instead of silently accepting stderr as signature data when
  `termux-keystore sign` returns no output.
* Skip redundant re-authentication (pinentry, Termux fingerprint, ...) when
  resolving a `credential_source` whose source account is already unlocked,
  which could otherwise prompt twice in a single command.

## [2.14.1] - 2026-07-31

### Changed

* Add configurable Android Keystore alias selection via `termux_key_alias`
  and `RBW_TERMUX_KEY_ALIAS`, including reuse of an existing key.
* Publish this changelog section directly as the GitHub release description.

### Fixed

* Make CI and release builds robust when `SOURCE_DATE_EPOCH` is unset.
* Keep the Home Manager configuration smoke test synchronized with current
  default settings.

## [2.14.0] - 2026-07-31

### Added

* Add a blocking TUI screen lock that requires the master password to unlock.
* Add `rbw export-info` for inspecting counts across rbw and Bitwarden export
  formats.
* Add reproducible release archives, checksum verification, and artifact
  attestations.

### Changed

* Extend `--from-file` workflows to upstream Bitwarden JSON, encrypted JSON,
  ZIP, and CSV formats.
* Use `--passphrase` consistently for encrypted `--from-file` inputs while
  retaining `--from-file-passphrase` as a compatibility alias.
* Preserve the input export format when writing `--from-file` changes.
* Improve Termux Keystore enrollment, status, and cleanup workflows.
* Add configurable TUI inactivity locking via `tui_lock_timeout` and
  `--screen-lock-timeout`.

## [2.13.12] - 2026-07-31

### Changed

* Improve `rbw termux status` with readable security indicators and colors.
* Add `rbw termux remove` for deleting the Keystore key and unlock bundle.
* Add `rbw panic` as an alias for purge; it also removes the active account's
  configured Termux unlock.

## [2.13.11] - 2026-07-31

### Added

* Native Termux Android Keystore unlock enrollment for Android builds.
* Configurable Keystore authentication validity during enrollment.

### Fixed

* Keystore unlock no longer performs a redundant separate fingerprint prompt.

## [1.15.0] - 2025-12-31

## Added

* Added `rbw inject` and `rbw run` for rendering templates and launching
  commands with `bw://` secret references (#246).
* Added support for `rbw get --field=private_key` for ssh key entries (#291).
* Added support for `rbw list --field=type` (Antoine Carnec, #283).
* `rbw list --raw` and `rbw search --raw` now also include entry uris (#279).

## Changed

* `rbw search` no longer searches hidden fields (#303).
* `ptrace` and core dumps are now also disabled on macos (Antoine Carnec,
  #300).
* Adjusted metadata to allow installation via `cargo binstall` (GideonBear, #275).
* More accurate shell completion for the `--field` option (Tin Lai, #287).

## Fixed

* `rbw list` and `rbw search` no longer trigger master password reprompt on
  entries with hidden fields (#303).
* `rbw unlocked` now ensures that the agent it is talking to is the correct
  version, even though it doesn't launch a new one (#276).
* A few improvements around pinentry protocol error parsing, to make logs
  more readable.

## [1.14.1] - 2025-09-01

## Added

* Basic shell completion for powershell, elvish, nushell, and fig (#271,
  jasonxue)

## Fixed

* TOTP entries with weak keys are supported again (#272, Maksim Karelov)
* Master password reprompt is no longer triggered for unrelated entries.
  (#268)
* Master password reprompt is always triggered even if no sync has happened.
* `rbw get` with a URL query can now return entries with multiple different
  URLs configured.

## [1.14.0] - 2025-08-24

## Added

* Steam Guard TOTP secrets are now supported. (#250, nikp123)
* SSH Key vault entries are now supported. (#252, Peter Kaplan)
* Master Password Reprompt is now supported.
* `rbw list` and `rbw search` now have a `--raw` option similar to `rbw get`.
* Shell completion now allows autocompleting of entry names, usernames, and
  folders. (#245, Patrick Lenihan)
* Added functionality to allow `rbw` to also act as an SSH agent by setting
  `SSH_AUTH_SOCK` appropriately. (#262, Peter Kaplan)

## Changed

* The `--clipboard` option now has a short alias of `-c`. (#258, Kedap)
* Sped up `rbw list` and `rbw search` by only decrypting fields that will
  actually be displayed.
* `rbw search` now displays results in the same format as `rbw list`, for
  consistency and easier parsing.

## Fixed

* We now automatically remove spaces from TOTP secrets, to handle different
  formatting or copy/pasting issues. (#247, foudil)
* If we create a new directory (for cache, sockets, etc), we now always
  ensure that its permissions are set correctly.
* `git-credential-rbw` now supports git's `credential.useHttpPath`. (#244,
   FoxAmes)
* `identity_url`, `ui_url`, and `notifications_url` are now set properly when
  configuring the `base_url` to be `https://api.bitwarden.eu`.
* `rbw search` now also searches configured URIs in entries.
* All subcommands which select a single entry are now consistent in how they
  allow the entry to be specified.
* Fixed some inconsistencies in how entries are selected when they have the
  same name but some entries have no username specified.
* Always write a pidfile for the agent even if it is not being daemonized, to
  allow running the agent manually during debugging.
* `rbw get` and `rbw search` now correctly return entries whose names are
  UUIDs.
* Email 2FA on the official Bitwarden server should now work again.

## [1.13.2] - 2025-01-06

## Fixed

* Try another clipboard backend to try to fix cross platform issues. (Mag
  Mell, #226)
* `rbw unlocked` no longer starts the agent if it isn't running. (#223)
* The cardholder_name field is now correctly populated for card entries.
  (#204)
* Fix ip address url matching when using the domain match type. (#211)
* Make the behavior of matching urls with no paths when using the exact match
  type more consistent. (#211)

## [1.13.1] - 2024-12-27

### Fixed

* Moved clipboard support to a (default-enabled) feature, since not all
  platforms support it (disabling this feature should allow Android builds to
  work again).

## [1.13.0] - 2024-12-26

### Fixed

* Fix preventing the password type selectors in `rbw generate` from being
  used together. (antecrescent, #198)
* Fix `--clipboard` on Wayland (Maksim Karelov, #192)
* Fix parsing vaults with entries that have non-null field types (Tin Lai, #212)
* Fix lock timeout being reset when checking version (aeber, #216)
* Update API request headers to pass new stricter validation on the official bitwarden.com server (Davide Laezza, #219)
* Make it possible to start the rbw agent process from a graphical session and then access it over SSH (Wim de With, #221)

## [1.12.1] - 2024-07-28

### Fixed

* Fix decrypting folder names of entries with individual item encryption keys.

## [1.12.0] - 2024-07-28

*NOTE: If you were affected by issue #163 (getting messages like `failed to
decrypt encrypted secret: invalid mac` when doing any operations on your
vault), you will need to `rbw sync` after upgrading in order to update your
local vault with the necessary new data.*

### Fixed

* Support decrypting entries encrypted with invididual item encryption keys,
  which are now generated by default from the official Bitwarden clients.
  (#163)
* Correctly handle lowercased and padded base32 TOTP secrets. (owl, #189)
* Make locking agent memory to RAM optional, since it appears to not always
  be available. (#143)

## [1.11.1] - 2024-06-26

### Fixed

* Updated the prelogin API endpoint to use the identity API instead of the
  base API, to correspond with upcoming changes to the official Bitwarden
  server (see https://github.com/bitwarden/server/pull/4206)

## [1.11.0] - 2024-06-20

### Added

* Support SSO login. (dezeroku, #174)
* Added `rbw search`, which finds and displays the name of entries matching a
  given search term.
* Added `--ignorecase` as an option to several subcommands. (Maximilian
  Götsch, #164)
* The JSON output given by `--raw` now also includes the field type.

### Fixed

* Fixed the client id used when logging in, which was causing problems with
  the official Bitwarden server. (Merlin Marek, #186)
* Reworked `rbw-pinentry-keyring` to support passwords with spaces and 2fa
  codes. (Henk van Maanen, #178)
* Try less hard to parse input as a url (so that using `rbw get` on an entry
  name containing a `:` works as expected).

## [1.10.2] - 2024-05-20

### Fixed

* Fix logging into the official Bitwarden server due to changes on their end
  (Gabriel Górski, #175)

## [1.10.1] - 2024-05-08

### Added

* `rbw code` supports TOTP codes which use a SHA256 or SHA512 hash (Jonas, #172)

### Fixed

* Fix `rbw code` searching by UUID (Robert Günzler, #169)

## [1.10.0] - 2024-04-20

### Added

* `rbw get` now supports searching by URL as well (proxict, #132)
* `rbw code` now supports `--clipboard`, and has an alias of `rbw totp` (#127)

### Changed

* Set a user agent for all API calls, not just logging in (#165)

### Fixed

* Also create runtime directories when running with `--no-daemonize` (Wim de With, #155)
* Fix builds on NetBSD (#105)
* Fix logging in when the configured email address differs in case from the email address used when registering (#158)
* Fix editing passwords inadvertently clearing custom field values (#142)

## [1.9.0] - 2024-01-01

### Added

* Secure notes can now be edited (Tin Lai, #137)
* Piping passwords to `rbw edit` is now possible (Tin Lai, #138)

### Fixed

* More consistent behavior from `rbw get --field`, and fix some panics (Jörg Thalheim, #131)
* Fix handling of pinentry EOF (Jörg Thalheim, #140)
* Pass a user agent header to fix logging into the official bitwarden server (Maksim Karelov, #151)
* Support the official bitwarden.eu server (Edvin Åkerfeldt, #152)

## [1.8.3] - 2023-07-20

### Fixed

* Fixed running on linux without an X11 context available. (Benjamin Jacobs,
  #126)

## [1.8.2] - 2023-07-19

### Fixed

* Fixed several issues with notification-based background syncing, it should
  be much more reliable now.

## [1.8.1] - 2023-07-18

### Fixed

* `rbw config set notifications_url` now actually works

## [1.8.0] - 2023-07-18

### Added

* `rbw get --clipboard` to copy the result to the clipboard instead of
  displaying it on stdout. (eatradish, #120)
* Background syncing now additionally happens when the server notifies the
  agent of password updates, instead of needing to wait for the 
  `sync_interval` timer. (Bernd Schoolman, #115)
* New helper script `rbw-pinentry-keyring` which can be used as an alternate
  pinentry program (via `rbw config set pinentry rbw-pinentry-keyring`) to
  automatically read the master password from the system keyring. Currently
  only supports the Gnome keyring via `secret-tool`. (Kai Frische, #122)
* Yubikeys in OTP mode are now supported for logging into a Bitwarden server.
  (troyready, #123)

### Fixed

* Better error reporting when `rbw login` or `rbw register` fail.

## [1.7.1] - 2023-03-27

### Fixed

* argon2 actually works now (#113, Bernd Schoolmann)

## [1.7.0] - 2023-03-25

### Added

* `rbw` now automatically syncs the database from the server at a specified
  interval while it is running. This defaults to once an hour, but is
  configurable via the `sync_interval` option
* Email 2FA is now supported (#111, René 'Necoro' Neumann)
* argon2 KDF is now supported (#109, Bernd Schoolmann)

### Fixed

* `rbw --version` now works again

## [1.6.0] - 2023-03-09

### Added

* `rbw get` now supports a `--raw` option to display the entire contents of
  the entry in JSON format (#97, classabbyamp)

## [1.5.0] - 2023-02-18

### Added

* Support for authenticating to self-hosted Bitwarden servers using client
  certificates (#92, Filipe Pina)
* Support multiple independent profiles via the `RBW_PROFILE` environment
  variable (#93, Skia)
* Add `rbw get --field` (#95, Jericho Keyne)

### Fixed

* Don't panic when not all stdout is read (#82, witcher)
* Fixed duplicated alias names in help output (#46)

## [1.4.3] - 2022-02-10

### Fixed

* Restored packaged scripts to the crate bundle, since they are used by some
  downstream packages (no functional changes) (#81)

## [1.4.2] - 2022-02-10

### Changed

* Device id is now stored in a separate file in the local data directory
  instead of as part of the config (#74)

### Fixed

* Fix api renaming in official bitwarden server (#80)

## [1.4.1] - 2021-10-28

### Added

* `bin/git-credential-rbw` to be used as a
  [git credential helper](https://git-scm.com/docs/gitcredentials#_custom_helpers)
  (#41, xPMo)

### Changed

* Also disable swap and viminfo files when using `EDITOR=nvim` (#70, Dophin2009)

### Fixed

* Properly handle a couple folder name edge cases in `bin/rbw-fzf` (#66,
  mattalexx)
* Support passing command line arguments via `EDITOR`/`VISUAL` (#61, xPMo)

## [1.4.0] - 2021-10-27

### Fixed

* Add `rbw register` to allow `rbw` to work with the official Bitwarden server
  again - see the README for details (#71)

## [1.3.0] - 2021-07-05

### Changed

* Use the system's native TLS certificate store when making HTTP requests.

### Fixed

* Correctly handle TOTP secret strings that copy with spaces (#56, TamasBarta, niki-on-github)

## [1.2.0] - 2021-04-18

### Added

* Shell completion for bash, zsh, and fish (#18)

### Changed

* Prebuilt binaries are now statically linked using musl, to prevent glibc
  version issues once and for all (#47)
* Standardize on RustCrypto in preference to ring or openssl

### Fixed

* `rbw generate` can now choose the same character more than once (#54, rjc)
* Improved handling of password history for entries with no password (#51/#53,
  simias)
* Fix configuring base_url with a trailing slash when using a self-hosted
  version of the official bitwarden server (#49, phylor)

## [1.1.2] - 2021-03-06

### Fixed

* Send warnings about failure to disable PTRACE_ATTACH to the agent logs rather
  than stderr

## [1.1.1] - 2021-03-05

### Fixed

* Fix non-Linux platforms (#44, rjc)

## [1.1.0] - 2021-03-02

### Added

* You can now `rbw config set pinentry pinentry-curses` to change the pinentry
  program used by `rbw` (#39, djmattyg007)

### Changed

* On Linux, the `rbw-agent` process can no longer be attached to by debuggers,
  and no longer produces core dumps (#42, oranenj)
* Suggest rotating the user's encryption key if we see an old cipherstring type
  (#40, rjc)
* Prefer the value of `$VISUAL` when trying to find an editor to run, before
  falling back to `$EDITOR` (#43, rjc)

## [1.0.0] - 2021-02-21

### Added

* Clarified the maintenance policy for this project in the README

### Fixed

* Stop hardcoding /tmp when using the fallback runtime directory (#37, pschmitt)
* Fix `rbw edit` clearing the match detection setting for websites associated
  with the edited password (#34, AdmiralNemo)
  * Note that you will need to `rbw sync` after upgrading and before running
    `rbw edit` in order to correctly update the local database.

## [0.5.2] - 2020-12-02

### Fixed

* `rbw` should once again be usable on systems with glibc-2.28 (such as Debian
  stable).

## [0.5.1] - 2020-12-02

### Fixed

* `rbw code` now always displays the correct number of digits. (#25, Tyilo)
* TOTP secrets can now also be supplied as `otpauth` urls.
* Logging into bitwarden.com with 2fa enabled now works again.

## [0.5.0] - 2020-10-12

### Added

* Add support for cipherstring type 6 (fixes some vaults using an older format
  for organizations data). (Jake Swenson)
* `rbw get --full` now displays URIs, TOTP secrets, and custom fields.
* Add `rbw code` for generating TOTP codes based on secrets stored in
  Bitwarden.
* Add `rbw unlocked` which will exit with success if the agent is unlocked and
  failure if the agent is locked.

### Fixed

* Don't display deleted items (#22, GnunuX)

## [0.4.6] - 2020-07-11

### Fixed

* Login passwords containing a `%` now work properly (albakham).

## [0.4.5] - 2020-07-11

### Fixed

* The pinentry window now no longer times out.

## [0.4.4] - 2020-06-23

### Fixed

* Fix regression in `rbw get` when not specifying a folder.

## [0.4.3] - 2020-06-23

### Added

* `rbw get` now accepts a `--folder` option to pick the folder to search in.

### Changed

* `rbw get --full` now also includes the username. (Jarkko Oranen)

### Fixed

* `rbw` should now be usable on systems with glibc-2.28 (such as Debian
  stable). (incredible-machine)

## [0.4.2] - 2020-05-30

### Fixed

* `rbw` now no longer requires the `XDG_RUNTIME_DIR` environment variable to be
  set.

## [0.4.1] - 2020-05-28

### Fixed

* More improved error messages.

## [0.4.0] - 2020-05-28

### Added

* Authenticator-based two-step login is now supported.

### Fixed

* Correctly handle password retries when entering an invalid password on the
  official Bitwarden server.
* Fix hang when giving an empty string to pinentry.
* The error message from the server is now shown when logging in fails.

## [0.3.5] - 2020-05-25

### Fixed

* Terminal-based pinentry methods should now work correctly (Glandos).
* Further error message improvements.

## [0.3.4] - 2020-05-24

### Fixed

* Handle edge case where a URI entry is set for a cipher but that entry has a
  null URI string (Adrien CLERC).

## [0.3.3] - 2020-05-23

### Fixed

* Set the correct default lock timeout when first creating the config file.
* Add a more useful error when `rbw` is run without being configured first.
* Don't throw an error when attempting to configure the base url before
  configuring the email.
* More improvements to error output.

## [0.3.2] - 2020-05-23

### Fixed

* Improve warning and error output a bit.

## [0.3.1] - 2020-05-23

### Fixed

* Fix option parsing for `rbw list --fields` and `rbw <add|generate> --uri`
  which was inadvertently broken in the previous release.

## [0.3.0] - 2020-05-22

### Fixed

* Better error message if the agent fails to start after daemonizing.
* Always automatically upgrade rbw-agent on new releases.
* Changing configuration now automatically drops in-memory keys (this should
  avoid errors when switching between different servers or accounts).
* Disallow setting `lock_timeout` to `0`, since this will cause the agent to
  immediately drop the decrypted keys before they can be used for decryption,
  even within a single run of the `rbw` client.

## [0.2.3] - 2020-05-17

### Fixed

* Fix syncing from the official Bitwarden server (thanks the_fdw).

### Added

* Added a couple example scripts to the repository for searching using fzf and
  rofi. Contributions and improvements welcome!

## [0.2.1] - 2020-05-03

### Fixed

* Properly maintain folder and URIs when editing an entry.

## [0.2.0] - 2020-05-03

### Added

* Multi-server support - you can now switch between multiple different
  bitwarden servers with `rbw config set base_url` without needing to
  redownload the password database each time.
* `rbw config unset` to reset configuration items back to the default
* `rbw list` and `rbw get` now support card, identity, and secure note entry
  types

### Fixed

* `rbw` is now able to decrypt secrets from organizations you are a member of.
* `rbw stop-agent` now waits for the agent to exit before returning.

### Changed

* Move to the `ring` crate for a bunch of the cryptographic functionality.
* The agent protocol is now versioned, to allow for seamless updates.

## [0.1.1] - 2020-05-01

### Fixed

* Some packaging changes.

## [0.1.0] - 2020-04-20

### Added

* Initial release
