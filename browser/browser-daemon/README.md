# rbw in browser-daemon's live view

[browser-daemon](https://github.com/pschmitt/browser-daemon)'s live view
fills logins and passkeys from an rbw vault through its secret agent. Its
toolbar button, vault popover and passkey prompt are this bundle, a
[live-view extension](https://github.com/pschmitt/browser-daemon/blob/main/docs/extensions.md)
that the view runs in sandboxed frames. It is the browser extension's
popup in another place: it loads the extension's own `popup.css`,
`theme.css`, `icons.js`, `feedback.css`/`feedback.js` and logo and builds the
popup's markup (header, search row, item rows with fill, copy and the ⋮ menu,
the passkey approval page); `embed.css` only adapts it to a frame. So a change
to the popup's look shows in both.

The bundle only draws: it asks the live view for logins, fills, copies,
favicons and passkey lookups by message and never sees a password, code or
key (a copied value goes from the live view straight to the clipboard).

`python3 browser/build.py` writes it to `browser/dist/browser-daemon` (with
the shared files and rbw's version), the flake exports it as
`browser-daemon-extension`. browser-daemon loads it with
`--extension-dir browser/dist/browser-daemon` (NixOS:
`services.browser-daemon.liveViewExtensions`, which defaults to this
package); after a rebuild, reloading the live view shows the changes.
