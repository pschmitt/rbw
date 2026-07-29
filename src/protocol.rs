use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

pub const VERSION: u32 = {
    const fn unwrap(res: &Result<u32, std::num::ParseIntError>) -> u32 {
        match res {
            Ok(t) => *t,
            Err(_) => panic!("failed to parse cargo version"),
        }
    }

    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let minor = env!("CARGO_PKG_VERSION_MINOR");
    let patch = env!("CARGO_PKG_VERSION_PATCH");

    unwrap(&u32::from_str_radix(major, 10)) * 1_000_000
        + unwrap(&u32::from_str_radix(minor, 10)) * 1_000
        + unwrap(&u32::from_str_radix(patch, 10))
};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Request {
    tty: Option<String>,
    environment: Option<Environment>,
    // Which configured account this request targets. `None` (including requests
    // from older clients that omit the field) means the primary account.
    #[serde(default)]
    account: Option<String>,
    action: Action,
}

impl Request {
    pub fn new(environment: Environment, action: Action) -> Self {
        Self {
            tty: None,
            environment: Some(environment),
            account: None,
            action,
        }
    }

    pub fn with_account(
        environment: Environment,
        account: Option<String>,
        action: Action,
    ) -> Self {
        Self {
            tty: None,
            environment: Some(environment),
            account,
            action,
        }
    }

    pub fn into_parts(self) -> (Action, Environment, Option<String>) {
        (
            self.action,
            self.environment.unwrap_or_else(|| Environment {
                tty: self.tty.map(|tty| SerializableOsString(tty.into())),
                env_vars: vec![],
            }),
            self.account,
        )
    }
}

// Taken from https://github.com/gpg/gnupg/blob/36dbca3e6944d13e75e96eace634e58a7d7e201d/common/session-env.c#L62-L91
pub const ENVIRONMENT_VARIABLES: &[&str] = &[
    // Used to set ttytype
    "TERM",
    // The X display
    "DISPLAY",
    // Xlib Authentication
    "XAUTHORITY",
    // Used by Xlib to select X input modules (e.g. "@im=SCIM")
    "XMODIFIERS",
    // For the Wayland display engine.
    "WAYLAND_DISPLAY",
    // Used by Qt and other non-GTK toolkits to check for X11 or Wayland
    "XDG_SESSION_TYPE",
    // Used by Qt to explicitly request X11 or Wayland; in particular, needed to
    // make Qt use Wayland on GNOME
    "QT_QPA_PLATFORM",
    // Used by GTK to select GTK input modules (e.g. "scim-bridge")
    "GTK_IM_MODULE",
    // Used by GNOME 3 to talk to gcr over dbus
    "DBUS_SESSION_BUS_ADDRESS",
    // Used by Qt to select Qt input modules (e.g. "xim")
    "QT_IM_MODULE",
    // Used for communication with non-standard Pinentries
    "PINENTRY_USER_DATA",
    // Used to pass window information
    "PINENTRY_GEOM_HINT",
];

pub static ENVIRONMENT_VARIABLES_OS: std::sync::LazyLock<
    Vec<std::ffi::OsString>,
> = std::sync::LazyLock::new(|| {
    ENVIRONMENT_VARIABLES
        .iter()
        .map(std::ffi::OsString::from)
        .collect()
});

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
struct SerializableOsString(std::ffi::OsString);

impl serde::Serialize for SerializableOsString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&crate::base64::encode(self.0.as_bytes()))
    }
}

impl<'de> serde::Deserialize<'de> for SerializableOsString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = SerializableOsString;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("base64 encoded os string")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SerializableOsString(std::ffi::OsString::from_vec(
                    crate::base64::decode(s).map_err(|_| {
                        E::invalid_value(serde::de::Unexpected::Str(s), &self)
                    })?,
                )))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct Environment {
    tty: Option<SerializableOsString>,
    env_vars: Vec<(SerializableOsString, SerializableOsString)>,
}

impl Environment {
    pub fn new(
        tty: Option<std::ffi::OsString>,
        env_vars: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> Self {
        Self {
            tty: tty.map(SerializableOsString),
            env_vars: env_vars
                .into_iter()
                .map(|(k, v)| {
                    (SerializableOsString(k), SerializableOsString(v))
                })
                .collect(),
        }
    }

    pub fn tty(&self) -> Option<&std::ffi::OsStr> {
        self.tty.as_ref().map(|tty| tty.0.as_os_str())
    }

    pub fn env_vars(
        &self,
    ) -> std::collections::HashMap<std::ffi::OsString, std::ffi::OsString>
    {
        self.env_vars
            .iter()
            .map(|(var, val)| (var.0.clone(), val.0.clone()))
            .filter(|(var, _)| (*ENVIRONMENT_VARIABLES_OS).contains(var))
            .collect()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Action {
    // `password`/`totp` let the client supply a `credential_source`-resolved
    // master password (and, if the linked entry has one, a fresh TOTP code
    // for the 2FA challenge) instead of the agent prompting via pinentry.
    // Both `None` (the common case, no `credential_source` configured or
    // the target account doesn't need 2FA) preserves the fully-interactive
    // flow exactly as before.
    Login {
        password: Option<String>,
        totp: Option<String>,
    },
    Register,
    Unlock {
        password: Option<String>,
    },
    CheckLock,
    Lock,
    Sync,
    // Permanently, irrecoverably deletes every entry in the account's
    // personal vault via the server's dedicated purge endpoint (a single
    // call, not a loop of individual deletes). Named distinctly from `rbw
    // purge` (which only clears the *local* db.json cache and has no
    // protocol action of its own). Requires re-proving the master
    // password (like `Login`/`Unlock`, `password` lets a
    // `credential_source`/`--stdin` caller supply it directly instead of
    // the agent prompting via pinentry).
    PurgeVault {
        password: Option<String>,
    },
    // Creates a new organization owned by the current account (`rbw org
    // create`). Needs the account's own RSA key pair (to encrypt the
    // freshly generated org key to itself as the initial owner), so this
    // is agent-mediated like the rest of the key-material-touching
    // actions, using the private key retained from unlock -- no
    // additional password prompt needed.
    CreateOrg {
        name: String,
    },
    // Confirms an org member who has accepted their invite (`rbw org
    // confirm`), re-encrypting the org's key to their now-known public
    // key. `public_key_der_b64` is fetched client-side (a plain
    // unauthenticated-crypto-wise lookup); only the actual re-encryption
    // needs the agent, since that needs the org key already cached from
    // unlock.
    ConfirmOrgUser {
        org_id: String,
        user_id: String,
        public_key_der_b64: String,
    },
    // Permanently deletes an entire organization (`rbw org delete`).
    // Requires re-proving the master password, exactly like `PurgeVault`
    // -- same `password` semantics (agent prompts via pinentry unless a
    // caller supplies one directly).
    DeleteOrg {
        org_id: String,
        password: Option<String>,
    },
    Decrypt {
        cipherstring: String,
        entry_key: Option<String>,
        org_id: Option<String>,
        // Set when `cipherstring` is wrapped in an attachment's own key (e.g.
        // an attachment file name) rather than directly in the entry's key.
        attachment_key: Option<String>,
    },
    DecryptBatch {
        entries: Vec<DecryptRequest>,
    },
    DecryptAttachment {
        data: Vec<u8>,
        attachment_key: Option<String>,
        entry_key: Option<String>,
        org_id: Option<String>,
    },
    EncryptAttachment {
        data: Vec<u8>,
        filename: String,
        entry_key: Option<String>,
        org_id: Option<String>,
    },
    Encrypt {
        plaintext: String,
        org_id: Option<String>,
    },
    ClipboardStore {
        text: String,
    },
    Quit,
    Version,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Response {
    Ack,
    Error {
        error: String,
    },
    Decrypt {
        plaintext: String,
    },
    DecryptBatch {
        results: Vec<DecryptResult>,
    },
    DecryptAttachment {
        data: Vec<u8>,
    },
    EncryptAttachment {
        encrypted_data: Vec<u8>,
        encrypted_key: String,
        encrypted_filename: String,
    },
    Encrypt {
        cipherstring: String,
    },
    Version {
        version: u32,
    },
    CreateOrg {
        id: String,
    },
}

// A single cipherstring to decrypt as part of an `Action::DecryptBatch`. Each
// entry carries its own keys so that fields encrypted with different keys
// (e.g. organization items vs. local folders) can be batched together.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DecryptRequest {
    pub cipherstring: String,
    pub entry_key: Option<String>,
    pub org_id: Option<String>,
}

// The result of decrypting a single `DecryptRequest`. Failures are reported
// per entry rather than failing the whole batch, so the caller can decide
// whether a given field is fatal (e.g. an entry name) or skippable (e.g. an
// optional login field).
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum DecryptResult {
    Success { plaintext: String },
    Failure { error: String },
}

#[test]
fn test_version_encoding() {
    let major: u32 = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap();
    let minor: u32 = env!("CARGO_PKG_VERSION_MINOR").parse().unwrap();
    let patch: u32 = env!("CARGO_PKG_VERSION_PATCH").parse().unwrap();

    assert_eq!(VERSION / 1_000_000, major);
    assert_eq!(VERSION / 1_000 % 1_000, minor);
    assert_eq!(VERSION % 1_000, patch);
}
