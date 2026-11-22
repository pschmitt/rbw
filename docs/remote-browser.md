# Remote browser mode

Remote mode lets the browser extension connect directly to rbw over HTTPS.
It uses a P-256 signing key created by Web Crypto in the extension. Keep
the non-exportable private key in extension-owned IndexedDB and expose
only the public key during pairing. One browser profile is one client.
Native mode continues to use the native messaging host.

## HTTPS and pairing

The agent exposes a separate loopback browser API listener behind HTTPS
with a certificate the browser already trusts. The existing mTLS API
continues to serve certificate-authenticated clients. The browser listener
has a configured HTTPS origin and extension requests target that exact
origin with redirects disabled.

In rbw's `config.yaml`, enable the browser listener and set its external
origin and local port:

```yaml
api:
  enabled: true
  browser:
    origin: https://rbw.example.net
    port: 24872
```

Have the HTTPS reverse proxy on the same host forward only
`/v1/browser/challenge` and `/v1/browser/request` to `127.0.0.1:24872`.
Keep this listener on loopback, apply a request rate limit at the proxy,
and omit request bodies from access and debug logs.

1. The user enters the agent's HTTPS URL and requests pairing from the
   extension. The extension obtains a short-lived server challenge and
   submits the public key and a proof of possession.
2. The agent creates a pending request and returns a comparison code.
   The user compares it with the code shown by `rbw api pairing list`.
3. A local administrator runs
   `rbw api pairing approve REQUEST --policy read-only --account ACCOUNT`
   or `rbw api pairing deny REQUEST`. Approval binds the public key and
   account to the policy. A pending request carries no vault permissions.
4. The extension checks the result with the same key. Denied and expired
   requests cannot become active. Revoke an approved client through the
   existing client revocation command.

Bound the number of pending requests and challenges, expire them
automatically, and limit unauthenticated request sizes. Names supplied by
a client are display labels. Approval identifies the exact key behind
the comparison code.

## Request authentication and authorization

Require a new challenge for every authenticated operation, including
pairing status. Associate each challenge with the public-key fingerprint,
expire it quickly, and consume it atomically after verification. Sign the
service origin, challenge, operation and complete payload in one
domain-separated message. Validate signatures and consume the challenge
before calling the vault operation. Keep reusable credentials, signatures,
and request bodies out of logs.

`rbw api policy list` displays named policies and their assigned clients,
along with each mTLS client’s direct grants.
Resolve policy assignments on every authorized request so edits and
revocations apply immediately. Existing certificate clients retain their
explicit grants. Assigning a named policy requires an explicit account.

- `read-only` permits listing, searching, and reading the assigned account,
  including secrets and current TOTP codes. It requires the vault to be
  unlocked separately before a secret read.
- `admin` permits every browser API capability in the assigned account,
  including password-based unlock and passkey assertions. Assertions that
  require WebAuthn user verification still use the native bridge.
- Create or update a custom policy with `rbw api policy set NAME --allow read`.
  Available capabilities are `read`, `unlock`, and `passkeys`. Assign a
  policy to an existing client with `rbw api policy assign CLIENT NAME`.

The extension's remote mode supports login search, fill, item details, TOTP,
manual unlock when permitted, and passkey assertions without user
verification. Native mode serves editing, attachments, vault import and
export, passkey creation, and the rest of the extension's existing tools.
Policy edits and enrollment approvals stay local CLI operations.
