use super::*;

// `--redact` (also `RBW_REDACT` and the `redact` config option): secret
// material is never shown. Display goes through the same masking `rbw show
// --mask` (and so the `--fzf` preview) uses; commands whose job is to hand a
// secret out refuse instead.
static ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_redact(enabled: bool) {
    ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

pub fn redact_enabled() -> bool {
    ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

// Whether the environment or the config asks for redaction (the command line
// flag is checked by the caller).
pub fn redact_requested() -> bool {
    std::env::var("RBW_REDACT").is_ok_and(|value| {
        !matches!(value.to_lowercase().as_str(), "" | "0" | "false" | "no")
    }) || rbw::config::Config::load().is_ok_and(|config| config.redact)
}

// For commands that exist to output a secret.
pub fn deny_if_redacted(what: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !redact_enabled(),
        "{what} would show secret material, which --redact (or RBW_REDACT / \
         the `redact` config option) disables"
    );
    Ok(())
}

impl Field {
    // Fields whose value is secret material.
    pub(super) fn is_secret(self) -> bool {
        matches!(
            self,
            Self::Notes
                | Self::Password
                | Self::Totp
                | Self::Fido2Credential
                | Self::Ssn
                | Self::License
                | Self::Passport
                | Self::CardNumber
                | Self::Cvv
                | Self::PrivateKey
        )
    }
}

fn mask(value: &mut Option<String>) {
    if value.is_some() {
        *value = Some(MASKED_SECRET.to_string());
    }
}

impl DecryptedCipher {
    // Whether `get --field NAME` would print secret material.
    pub(super) fn field_is_secret(&self, field: &str) -> bool {
        if let Ok(field) = field.to_lowercase().parse::<Field>() {
            return field.is_secret();
        }
        // A custom field, matched the way `display_field` does.
        let field = field.to_lowercase();
        self.fields.iter().any(|f| {
            f.name
                .as_deref()
                .is_some_and(|name| name.to_lowercase().contains(&field))
                && !matches!(f.ty, Some(rbw::api::FieldType::Text))
        })
    }

    // A copy with every secret replaced by `MASKED_SECRET`: what `show
    // --mask` masks, plus notes, the rest of the identity numbers, passkey
    // keys and previous passwords.
    pub fn redacted(&self) -> Self {
        let mut cipher = self.clone();
        mask(&mut cipher.notes);
        for field in &mut cipher.fields {
            if !matches!(
                field.ty,
                Some(
                    rbw::api::FieldType::Text | rbw::api::FieldType::Boolean
                )
            ) {
                mask(&mut field.value);
            }
        }
        for history in &mut cipher.history {
            history.password = MASKED_SECRET.to_string();
        }
        match &mut cipher.data {
            DecryptedData::Login {
                password,
                totp,
                fido2_credentials,
                ..
            } => {
                mask(password);
                mask(totp);
                for credential in fido2_credentials {
                    mask(&mut credential.key_value);
                    mask(&mut credential.user_handle);
                }
            }
            DecryptedData::Card { number, code, .. } => {
                mask(number);
                mask(code);
            }
            DecryptedData::Identity {
                ssn,
                license_number,
                passport_number,
                ..
            } => {
                mask(ssn);
                mask(license_number);
                mask(passport_number);
            }
            DecryptedData::SshKey { private_key, .. } => mask(private_key),
            DecryptedData::SecureNote => {}
        }
        cipher
    }
}

// `get` prints one value; with `--redact` that has to be one that isn't
// secret. Structured output and `--list-fields` are masked instead.
pub(super) fn deny_secret_get(
    cipher: &DecryptedCipher,
    field: Option<&str>,
    list_fields: bool,
    output: OutputMode,
) -> anyhow::Result<()> {
    if !redact_enabled()
        || list_fields
        || output_is_structured(output)
        || output == OutputMode::Name
    {
        return Ok(());
    }
    match field {
        None => deny_if_redacted("`rbw get` without --field"),
        Some(field) if cipher.field_is_secret(field) => {
            deny_if_redacted(&format!("`rbw get --field {field}`"))
        }
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> DecryptedCipher {
        DecryptedCipher {
            id: "id".to_string(),
            folder: None,
            name: "example".to_string(),
            data: DecryptedData::Login {
                username: Some("me".to_string()),
                password: Some("hunter2".to_string()),
                totp: Some("JBSWY3DPEHPK3PXP".to_string()),
                uris: None,
                fido2_credentials: vec![],
            },
            fields: vec![
                DecryptedField {
                    name: Some("pin".to_string()),
                    value: Some("1234".to_string()),
                    ty: Some(rbw::api::FieldType::Hidden),
                    linked_id: None,
                },
                DecryptedField {
                    name: Some("site".to_string()),
                    value: Some("eu".to_string()),
                    ty: Some(rbw::api::FieldType::Text),
                    linked_id: None,
                },
            ],
            notes: Some("kubeconfig".to_string()),
            history: vec![DecryptedHistoryEntry {
                last_used_date: "2020".to_string(),
                password: "prev-pw".to_string(),
            }],
            attachments: vec![],
            attachment_metadata: AttachmentMetadata::new("id", 0),
            archived: false,
            deleted: false,
            revision_date: None,
            account: None,
        }
    }

    #[test]
    fn redacted_masks_secrets_and_keeps_the_rest() {
        let json = serde_json::to_string(&login().redacted()).unwrap();
        for secret in [
            "hunter2",
            "JBSWY3DPEHPK3PXP",
            "1234",
            "kubeconfig",
            "prev-pw",
        ] {
            assert!(!json.contains(secret), "{secret} leaked: {json}");
        }
        for kept in ["example", "\"me\"", "\"eu\""] {
            assert!(json.contains(kept), "{kept} missing: {json}");
        }
    }

    #[test]
    fn secret_fields_are_recognised() {
        let cipher = login();
        for field in ["password", "totp", "notes", "pin"] {
            assert!(cipher.field_is_secret(field), "{field}");
        }
        for field in ["username", "uris", "site"] {
            assert!(!cipher.field_is_secret(field), "{field}");
        }
    }
}
