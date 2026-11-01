# Remote field API

The optional remote API lets an explicitly provisioned client read non-secret
vault status or specifically granted fields from vault items. The API is
disabled by default and binds to `127.0.0.1:24871` when enabled without options.
The agent keeps serving its normal local and SSH-agent clients when the API is
enabled or disabled.

## Enable and configure

```sh
rbw api enable
rbw api status
```

For remote access, configure a reachable local interface address and the DNS
name clients use to reach the server. rbw generates and manages its CA and TLS
certificates. The DNS name is placed in the server certificate; the listen
address is only the bind address.

```sh
rbw api enable --listen '<reachable-interface-address>:24871' --hostname '<server-dns-name>'
```

Allow inbound TCP only from the intended client network in the host firewall.
The default loopback address is suitable for clients running on the same
machine. Do not expose the listener to an untrusted network.

## Provision a client

Create a client identity. It has no access grants initially:

```sh
rbw api client create home-assistant
```

The command prints paths to a public CA certificate, client certificate, and
client private key. Transfer the CA certificate and client certificate/key to
the client over a trusted channel. Keep the private key confidential, install
it with owner-only permissions, and remove any temporary transfer copy. Do not
paste private key contents into chat, logs, shell arguments, or source control.
The server keeps its own copy of the client key so rbw can revoke and remove it.

The client must use the printed HTTPS server name, trust the CA certificate,
and present the client certificate and private key for every request. Client
identity comes from the verified TLS certificate; a request parameter cannot
choose or impersonate a client.

## Grant status without item access

Grant a client non-secret lock status for one configured account without
granting any item fields:

```sh
rbw api status-grant '<client-id>' --account '<account-name>'
```

Status reports only `locked`, `unlocked`, or `unconfigured`. It does not return
the account name, enumerate other accounts, or inspect vault items. The state
is read from the agent's existing per-account unlocked-key state; this request
does not unlock, prompt, or change timeouts. Revoke status separately from item
permissions:

```sh
rbw api status-revoke '<client-id>'
```

## Grant the minimum fields

Grant a client exact fields on an item, scoped to a configured account:

```sh
rbw api grant '<client-id>' --account '<account-name>' --item-id '<item-uuid>' --field username --field password
```

Field tokens include `name`, `username`, `password`, `totp`, `notes`,
`uri/0` (zero-based URI index), `custom/<field-name>`, card field names,
`identity/<field-name>`, and SSH key fields. Grant `totp` only when the client
needs current one-time codes. The API returns a current code, never the stored
TOTP seed or its provisioning URI. Custom field names and identity field names
are case-sensitive.

Review client identities, status permission, and field grant counts with
`rbw api client list`.
Remove a field grant with `rbw api revoke '<client-id>' --item-id
'<item-uuid>' --field password`, or remove every grant for an item by omitting
`--field`. Revoke a client identity to invalidate its certificate:

```sh
rbw api client revoke '<client-id>'
```

Policy changes are loaded for each request, so revocation applies to a client
that is already connected. Disable the listener with `rbw api disable`.

## HTTP contract

The API supports non-secret status and one field read per request:

```text
GET /v1/status
```

This endpoint requires a registered mTLS client with the explicit status grant.
Its response has `apiVersion`, `agentVersion`, and a `vault.state` property.
Clients without an account scope, or with an account that is no longer
configured, receive `vault.state: "unconfigured"` rather than global account
information.

```text
GET /v1/items/{item-id}/fields/{field-token}
```

A successful JSON response has `field`, `value`, and `sensitive` properties.
Errors have stable `code`, `message`, and `retryable` properties. Retryable
errors include `Retry-After: 5`. Responses use `Cache-Control: no-store`.
Unauthenticated, disabled, or ungranted requests fail closed before item data
is decrypted or returned.
