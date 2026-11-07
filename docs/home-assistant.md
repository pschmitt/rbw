# Home Assistant integration

The custom integration source lives in this repository at
[`homeassistant/custom_components/rbw`](../homeassistant/custom_components/rbw).
It is intended for other Home Assistant integrations that need one explicitly
granted field. It never lists items or polls vault contents, does not cache
field results, and does not expose a secret-returning Home Assistant service.

The integration bundles the rbw icon at
[`brand/icon.png`](../homeassistant/custom_components/rbw/brand/icon.png),
copied byte-for-byte from the canonical [`rbw-256.png`](../assets/icons/rbw-256.png)
asset. Home Assistant Core 2026.3 and later reads local custom-integration brand
images directly from this directory; the installer archive includes the image.

## Install

The source stays in this monorepo. Export a deterministic, source-only archive
for offline installation:

```sh
tools/homeassistant-integration.sh export /tmp/rbw-homeassistant.tar
```

To install over SSH, use the Home Assistant shell target configured in
`~/.ssh/config` (or provide its port explicitly):

```sh
tools/homeassistant-integration.sh install --port 22 <ha-shell-target>
```

The installer transfers only the integration source, stores a versioned copy
under `custom_components-local/`, and points `custom_components/rbw` at it
using Home Assistant's local integration symlink layout. It adds the generated
versioned directory to that config checkout's local Git exclude file. Prior
versioned copies remain available for rollback. Exported archives contain no
client credentials. The installer does not configure the API, transfer
certificates, or restart Home Assistant.

## Transfer the client certificates

Use the paths printed by `rbw api client create` and transfer the CA
certificate, client certificate, and private key from the rbw host to the HA
SSH shell over SCP. Replace the example values with the SSH alias and paths
printed by the CLI. The destination must be under the persistent `/config`
volume so HA Core can read the same paths after a restart:

```sh
ha_target='your-ha-shell-ssh-alias'
ca_path='/path/printed/by/rbw/ca.pem'
client_cert_path='/path/printed/by/rbw/client-ID.pem'
client_key_path='/path/printed/by/rbw/client-ID-key.pem'
ssh -p 22 "$ha_target" 'install -d -m 0700 /config/rbw-api'
scp -P 22 "$ca_path" "$client_cert_path" "$client_key_path" \
  "$ha_target:/config/rbw-api/"
ssh -p 22 "$ha_target" \
  'chmod 0644 /config/rbw-api/ca.pem /config/rbw-api/client-ID.pem && chmod 0600 /config/rbw-api/client-ID-key.pem'
```

Replace `ID` with the ID printed by `rbw api client create`, then configure the
three resulting paths in the rbw integration. HA Core runs as root and reads `/config`;
the integration rejects a client private key readable by group or others.
Keep the directory mode at `0700` and key mode at `0600`. Never put these files
in this repository or the exported integration archive. Revoking the rbw client
invalidates its certificate; remove the local copies when they are no longer
needed.

After the backend API and credentials are ready, restart Home Assistant to load
the integration. Re-run the installer to update its source. Changing the API
origin identifies a different server; remove the existing config entry and add
a new one for that server.

## Configure the connection

Follow [the remote API guide](remote-api.md) to enable the listener, create a
client identity, and grant only the item fields the integration needs. The
`rbw api client create` command prints the API origin and paths to the CA
certificate, client certificate, and client private key.

Transfer those files to the Home Assistant host over a trusted channel. Keep
the client key readable only by Home Assistant (`chmod 600`). In Home
Assistant, add the **rbw** integration and enter the printed API origin and
the three local file paths. The integration validates server TLS and presents
the client certificate on every request. It does not store private key
contents in the Home Assistant config entry.

## Read a field from another integration

The Python function is the integration's public API:

```python
from custom_components.rbw import async_get_field

result = await async_get_field(hass, entry_id, item_id, field_id)
```

`entry_id` is the rbw config-entry ID. `field_id` uses the API token syntax,
such as `password`, `totp`, `uri/0`, `custom/Recovery code`, or
`identity/first_name`. Path separators are encoded by the client. The result
has `field`, `value`, and `sensitive`; `value` can be `None` for an optional
field without a stored value. A TOTP read returns the current code, never its
seed or provisioning URI.

Every call makes a new request and raises `HomeAssistantError` on denial or
failure. Callers must handle that exception and use returned values only for
the requested operation. The helper and repair flows do not log or retain
field values.

Transient API or vault failures create a persistent repair issue. The retry
flow repeats the request and discards its value to confirm recovery; call
`async_get_field` again to obtain the field. If an item requires interactive
master-password reprompt, the repair explains that Home Assistant cannot
provide the prompt and keeps the issue open until that setting is removed or
the item is read through local interactive rbw.

## Choose which integrations may read what

Deny by default: an integration can read a vault item only when you allow it. All
integrations share one mTLS client, so the rbw API's field grants cannot tell them
apart; this adds that per-integration check, on top of those grants. Integrations
run in one process, so it stops mistakes and overreach, not hostile code: the
grants remain the security boundary.

- **When an integration asks:** a denied read raises an error and creates a repair
  naming the integration and item. Allow it there, then let the integration retry.
- **In the options:** open the rbw integration's options, pick an integration, and
  edit its items. Removing them all revokes its access.
- **Upgrading:** items that integrations were already set up to read
  (`rbw_entry_id` with `rbw_item_id` in their entries) are allowed once, so they keep
  working. Anything else needs allowing.

The check identifies the caller from the call stack; the `consumer` argument cannot
override it.

## Status device, audit event, and unlock repair

The integration also creates one diagnostic **rbw Policy API** device. It polls
`GET /v1/status` once per minute and exposes:

- API connectivity (`binary_sensor.rbw_api_connected`).
- One lock binary sensor per account returned by the status API (for example,
  `binary_sensor.rbw_ai_locked`).
- An audit log event entity (`event.rbw_audit`) that emits events whenever a
  consumer reads credentials or a TOTP code, uses or registers a passkey,
  copies a secret, signs with SSH, downloads an attachment, unlocks or locks a
  granted vault, or is denied access. Each event includes `actor`, `consumer`,
  `operation`, `outcome`, `account`, `item_id`, `item_name`, `field`, `origin`,
  `reason`, and a one-line `summary` — never secret values.
- A fixable repair issue (`default_account_locked`) whenever the granted
  `default` account is locked. Opening the repair prompts for the master
  password, sends it over mTLS (`POST /v1/unlock`) to `rbw-agent`, cascades to
  any configured follower accounts, and never stores the password in Home
  Assistant.

The device information shows the agent version as its software version and the
API contract version as its model identifier (for example, `API v1`). Account
names and audit events appear only for accounts explicitly included in this
client's status grants. The response contains no secret field values. A denied
status request still reports the API as reachable. A granted account that is no
longer configured has an unknown lock state, never an unlocked state. The
device links to the configured API endpoint.

Status access is a separate permission for one or more accounts. Grant specific
accounts to the existing client identity:

```sh
rbw api client list
rbw api status-grant '<client-id>' --account '<account-name>'
rbw api status-grant '<client-id>' --account '<first>' --account '<second>'
```

Or grant all accounts configured at the time the command runs:

```sh
rbw api status-grant '<client-id>' --all-configured
```

This is a snapshot. Accounts configured later are not added automatically;
grant them explicitly or run `--all-configured` again. The API never reports
account names outside the status grant set. Revoke one account's status grant
with `rbw api status-revoke '<client-id>' --account '<account-name>'`, or revoke
all status grants with `rbw api status-revoke '<client-id>'`.

The integration reports a persistent repair when the permission is missing and
clears it when status becomes available. Network errors retry automatically.
The status permission grants no access to item fields; grant those separately
only when another integration needs to read a specific field. Revoking an
account's status grant removes its per-account entities from Home Assistant.

## Tests

From this repository root:

```sh
cd homeassistant
python -m unittest discover -s tests -t . -v
```

The environment needs Python 3.13 or later, `aiohttp`, and `voluptuous`.
