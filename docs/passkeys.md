# Passkeys

Passkeys (WebAuthn/FIDO2 credentials) synced onto a login item are fully
supported: `rbw sync`/decrypt, `rbw show`/the TUI detail pane (a `Passkey`
row showing the relying party and account, never the raw key material),
`rbw export`/`rbw import`, and `rbw mirror` all carry them through
end-to-end, the same way a password or TOTP secret does. `rbw edit`/`rbw
set` never expose the raw credential fields for editing (there's nothing
meaningful to hand-edit in opaque key material) but always preserve
whatever passkeys an entry already has -- important given the destination
server stores an item's `login` object as one unit, so a request that
omitted this field entirely would otherwise silently delete the passkey.

`rbw passkey counter ENTRY --rp-id example.com` reads a credential's counter;
add `--set N` to advance it without exposing or changing key material.
Decreasing a counter is rejected.

`rbw passkey inject ENTRY --rp-id example.com --cdp-url http://localhost:9222
--page-id TARGET_ID` installs a virtual authenticator in exactly that Chromium
page. It reserves the next counter in the vault before enabling assertions,
waits for an assertion, disables presence, and reads the browser's final counter
to include any assertions that raced with disabling it. It removes the
authenticator before synchronizing that final counter back to the vault.
The private key travels directly over the CDP connection;
it is never printed or served over HTTP. Use a trusted debugging endpoint and
keep the command running while driving the browser. `--timeout SECONDS` defaults
to 120. A timeout retains the reserved counter, so an interrupted login cannot
cause counter reuse. Synchronize your ordinary Bitwarden client after first
enabling a counter on a credential previously stored with counter zero;
rbw prints a warning when injection or `counter --set` enables tracking.
Clients still holding zero can skip syncing before using the credential.

Local item locks prevent simultaneous injections; revision checks reject
competing vault updates. Avoid concurrent logins with the same passkey across
clients: vault synchronization does not serialize assertion delivery. Existing
relying-party clone flags may need separate recovery even after fixing the
vault counter. In Authelia, a persisted clone warning remains set even when
later assertions advance the counter. A synchronized vault does not prove
that the site accepted the login; check the browser result too.
