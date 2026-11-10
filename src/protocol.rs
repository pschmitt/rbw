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

/// Whether an agent reporting `version` can serve this build.
///
/// Within a major version the protocol only grows: a minor release may add
/// actions, responses and optional fields, but never removes, renames or
/// changes one (`tests/protocol/` holds what each release line sends and
/// receives, and `test_protocol_fixtures` keeps them working). So an agent
/// of the same major and the same or a newer minor understands this client,
/// and an agent that outlived an upgrade keeps serving the clients and
/// browser hosts that are still running the previous release. An older
/// minor may lack what this build sends, and another major is a different
/// protocol: those are replaced (or reported).
/// The first agent version that can replace itself in place
/// (`Action::Reexec`); an older one answers it with a parse error.
pub const REEXEC_SINCE: u32 = 2_045_000;

pub const fn compatible(version: u32) -> bool {
    version / 1_000_000 == VERSION / 1_000_000
        && version / 1_000 >= VERSION / 1_000
}

/// A protocol version (`VERSION`, or the one an agent reports) as
/// `major.minor.patch`.
pub fn version_string(version: u32) -> String {
    format!(
        "{}.{}.{}",
        version / 1_000_000,
        version / 1_000 % 1_000,
        version % 1_000
    )
}

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
    // Tell pinentry the client's locale (character set)
    "LC_ALL",
    "LC_CTYPE",
    "LANG",
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
    // Captures the allowlisted variables from this process's own
    // environment. The agent uses this to seed `last_environment` so that
    // requests arriving before any rbw client has connected (e.g. an ssh
    // agent request right after the agent was started) still give pinentry
    // a usable DISPLAY/WAYLAND_DISPLAY/TERM instead of an empty environment.
    pub fn from_process(tty: Option<std::ffi::OsString>) -> Self {
        let env_vars = std::env::vars_os()
            .filter(|(var_name, _)| {
                (*ENVIRONMENT_VARIABLES_OS).contains(var_name)
            })
            .collect();
        Self::new(tty, env_vars)
    }

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
    // `client_id`/`client_secret` let the client supply a pre-obtained
    // personal API key (e.g. from `--stdin`) instead of the agent prompting
    // for both via pinentry. Both `None` (the common case) preserves the
    // fully-interactive flow exactly as before.
    Register {
        client_id: Option<String>,
        client_secret: Option<String>,
    },
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
    // `rbw security` master key changes. The passwords come from the
    // client, which prompts for them itself so it can also update a Secret
    // Service unlock credential afterwards.
    ChangePassword {
        current_password: String,
        new_password: String,
        hint: Option<String>,
        rotate_key: bool,
    },
    ChangeKdf {
        password: String,
        // `rbw::api::KdfType` as a number.
        kdf: u8,
        iterations: u32,
        memory: Option<u32>,
        parallelism: Option<u32>,
    },
    RotateKey {
        password: String,
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
        entry_key: Option<String>,
        org_id: Option<String>,
    },
    VerifyMasterPassword {
        password: String,
    },
    CryptBytes {
        data: Vec<u8>,
        decrypt: bool,
    },
    ClipboardStore {
        text: String,
    },
    // Stop the agent. `reason` is a fixed label for the audit log
    // (`stop_agent`, `restart`, `outdated`, ...); the agent records an
    // unknown one as `other` and a missing one (from rbw before 2.43) as
    // `unspecified`. Agents before 2.43 ignore the field.
    Quit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Version,
    // Replace the agent with the `rbw-agent` at `exe` (since 2.45) without
    // locking: the agent waits for its other requests to finish, answers
    // `Ack`, then execs `exe` in place (same pid, same socket) and hands it
    // the unlocked keys in memory. An `Error` (also what an older agent
    // answers) means the agent kept running unchanged.
    Reexec {
        exe: String,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Response {
    Bytes {
        data: Vec<u8>,
    },
    Ack,
    Progress {
        message: String,
    },
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
    assert_eq!(version_string(VERSION), env!("CARGO_PKG_VERSION"));
    assert_eq!(version_string(2_031_002), "2.31.2");
    let minor = VERSION / 1_000 * 1_000;
    let major = VERSION / 1_000_000 * 1_000_000;
    // Any patch of this minor, and any newer minor of this major.
    assert!(compatible(minor) && compatible(minor + 999));
    assert!(compatible(minor + 1_000) && compatible(major + 999_999));
    // An older minor, or another major.
    assert!(!compatible(minor - 1));
    assert!(!compatible(major + 1_000_000) && !compatible(major - 1));
}

// An agent before 2.43 had a unit `Quit`; a newer client replacing it sends
// `Quit` with a reason, which the old agent must still accept.
#[test]
fn test_quit_reason_is_accepted_by_older_agents() {
    #[derive(serde::Deserialize, Debug)]
    #[serde(tag = "type")]
    enum OldAction {
        Quit,
    }
    let new = serde_json::to_value(Action::Quit {
        reason: Some("outdated".to_owned()),
    })
    .unwrap();
    assert_eq!(new["reason"], "outdated");
    assert!(matches!(
        serde_json::from_value::<OldAction>(new).unwrap(),
        OldAction::Quit
    ));
}

// Every request and response a released client sends or reads (one file
// per minor that changed the protocol, in tests/protocol/) must still parse,
// and must keep each of its fields with the same value when this build
// writes it back: a renamed field would otherwise be ignored on the way in
// and default to `None`. New optional fields may appear.
#[test]
fn test_protocol_fixtures() {
    fn keeps(
        fixture: &serde_json::Value,
        current: &serde_json::Value,
    ) -> bool {
        match (fixture, current) {
            (
                serde_json::Value::Object(old),
                serde_json::Value::Object(new),
            ) => old.iter().all(|(key, value)| {
                new.get(key).is_some_and(|other| keeps(value, other))
            }),
            (
                serde_json::Value::Array(old),
                serde_json::Value::Array(new),
            ) => {
                old.len() == new.len()
                    && old.iter().zip(new).all(|(a, b)| keeps(a, b))
            }
            (old, new) => old == new,
        }
    }

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/protocol");
    let mut files = 0;
    for file in std::fs::read_dir(&dir).unwrap() {
        let path = file.unwrap().path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        files += 1;
        let fixtures: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
                .unwrap();
        for old in fixtures["requests"].as_array().unwrap() {
            let request: Request = serde_json::from_value(old.clone())
                .unwrap_or_else(|e| {
                    panic!(
                        "{}: request {old} no longer parses: {e}",
                        path.display()
                    )
                });
            let new = serde_json::to_value(&request).unwrap();
            assert!(
                keeps(old, &new),
                "{}: request {old} lost a field: {new}",
                path.display()
            );
        }
        for old in fixtures["responses"].as_array().unwrap() {
            let response: Response = serde_json::from_value(old.clone())
                .unwrap_or_else(|e| {
                    panic!(
                        "{}: response {old} no longer parses: {e}",
                        path.display()
                    )
                });
            let new = serde_json::to_value(&response).unwrap();
            assert!(
                keeps(old, &new),
                "{}: response {old} lost a field: {new}",
                path.display()
            );
        }
    }
    assert!(files > 0, "no protocol fixtures in {}", dir.display());
}
