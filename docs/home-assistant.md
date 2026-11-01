# Home Assistant integration

The custom integration source lives in this repository at
[`homeassistant/custom_components/rbw`](../homeassistant/custom_components/rbw).
It is intended for other Home Assistant integrations that need one explicitly
granted field. It does not list items, poll the vault, cache results, or expose
a secret-returning Home Assistant service.

## Install

Copy the integration into the Home Assistant configuration directory. Replace
`/path/to/ha-config` with that installation's configuration directory:

```sh
install -d /path/to/ha-config/custom_components
cp -a homeassistant/custom_components/rbw /path/to/ha-config/custom_components/
```

After the rbw API is deployed and enabled, restart Home Assistant to load the
integration. This checkout does not activate or restart Home Assistant.

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

## Tests

From this repository root:

```sh
cd homeassistant
python -m unittest discover -s tests -v
```

The environment needs Python 3.13 or later, `aiohttp`, and `voluptuous`.
