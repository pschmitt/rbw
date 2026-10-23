use super::*;

// Accumulates the cipherstrings to be decrypted in a single `decrypt_batch`
// call. `push` returns the index at which the corresponding plaintext will
// appear in the results vector, which the cipher plans record and later
// resolve.
pub(super) struct BatchRequests(
    pub(super) Vec<rbw::protocol::DecryptRequest>,
);

impl BatchRequests {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }

    pub(super) fn push(
        &mut self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> usize {
        let index = self.0.len();
        self.0.push(rbw::protocol::DecryptRequest {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        });
        index
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn into_vec(self) -> Vec<rbw::protocol::DecryptRequest> {
        self.0
    }
}

pub(super) fn entry_type_name(data: &rbw::db::EntryData) -> &'static str {
    match data {
        rbw::db::EntryData::Login { .. } => "Login",
        rbw::db::EntryData::Identity { .. } => "Identity",
        rbw::db::EntryData::SshKey { .. } => "SSH Key",
        rbw::db::EntryData::SecureNote => "Note",
        rbw::db::EntryData::Card { .. } => "Card",
    }
}

// Mirrors `entry_type_name`, but for the already-decrypted `DecryptedData`
// (used by `--from-file`, which has nothing else to call `entry_type_name`
// with -- there's no `rbw::db::EntryData` cipherstring involved at all).
pub(super) fn decrypted_entry_type_name(
    data: &DecryptedData,
) -> &'static str {
    match data {
        DecryptedData::Login { .. } => "Login",
        DecryptedData::Identity { .. } => "Identity",
        DecryptedData::SshKey { .. } => "SSH Key",
        DecryptedData::SecureNote => "Note",
        DecryptedData::Card { .. } => "Card",
    }
}

// A plan describing which batch-decrypt results make up a single list entry.
// The `usize` fields are indices into the flat results vector returned by
// `decrypt_batch`; `entry_type` needs no decryption so it is resolved up front.
pub(super) struct ListCipherPlan {
    pub(super) id: String,
    pub(super) name: Option<usize>,
    pub(super) user: Option<usize>,
    pub(super) password: Option<usize>,
    pub(super) folder: Option<usize>,
    pub(super) uris: Option<Vec<usize>>,
    pub(super) entry_type: Option<String>,
    pub(super) collection_ids: Option<Vec<String>>,
    pub(super) revision_date: Option<String>,
    pub(super) attachment_count: usize,
    pub(super) archived: bool,
    pub(super) deleted: bool,
}

impl ListCipherPlan {
    pub(super) fn build(
        entry: &rbw::db::Entry,
        fields: &[ListField],
        requests: &mut BatchRequests,
    ) -> Self {
        let name = fields.contains(&ListField::Name).then(|| {
            requests.push(
                &entry.name,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        });

        let user = if fields.contains(&ListField::User) {
            match &entry.data {
                rbw::db::EntryData::Login {
                    username: Some(username),
                    ..
                } => Some(requests.push(
                    username,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )),
                _ => None,
            }
        } else {
            None
        };

        let password = if fields.contains(&ListField::Password) {
            match &entry.data {
                rbw::db::EntryData::Login {
                    password: Some(password),
                    ..
                } => Some(requests.push(
                    password,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )),
                _ => None,
            }
        } else {
            None
        };

        let folder = if fields.contains(&ListField::Folder) {
            // folder name should always be decrypted with the local key
            // because folders are local to a specific user's vault, not the
            // organization
            entry
                .folder
                .as_ref()
                .map(|folder| requests.push(folder, None, None))
        } else {
            None
        };

        let uris = if fields.contains(&ListField::Uri) {
            match &entry.data {
                rbw::db::EntryData::Login { uris, .. } => Some(
                    uris.iter()
                        .map(|s| {
                            requests.push(
                                &s.uri,
                                entry.key.as_deref(),
                                entry.org_id.as_deref(),
                            )
                        })
                        .collect(),
                ),
                _ => None,
            }
        } else {
            None
        };

        let entry_type = fields
            .contains(&ListField::EntryType)
            .then(|| entry_type_name(&entry.data).to_string());
        let collection_ids = if fields.contains(&ListField::Collections) {
            Some(entry.collection_ids.clone())
        } else {
            None
        };

        Self {
            id: entry.id.clone(),
            name,
            user,
            password,
            folder,
            uris,
            entry_type,
            collection_ids,
            revision_date: entry.revision_date.clone(),
            attachment_count: entry.attachments.len(),
            archived: entry.archived,
            deleted: entry.deleted,
        }
    }

    pub(super) fn resolve(
        self,
        results: &[rbw::protocol::DecryptResult],
    ) -> anyhow::Result<DecryptedListCipher> {
        // entry name and folder are required, so a decryption failure is fatal
        let name = self
            .name
            .map(|index| strict_result(&results[index]))
            .transpose()?;
        let folder = self
            .folder
            .map(|index| strict_result(&results[index]))
            .transpose()?;
        // optional login fields are skipped (with a warning) on failure, to
        // match the previous best-effort behavior of `decrypt_field`
        let user = self.user.and_then(|index| {
            lenient_result(&results[index], Field::Username)
        });
        let password = self.password.and_then(|index| {
            lenient_result(&results[index], Field::Password)
        });
        let uris = self.uris.map(|indices| {
            indices
                .iter()
                .filter_map(|&index| {
                    lenient_result(&results[index], Field::Uris)
                })
                .collect()
        });
        let attachment_metadata =
            AttachmentMetadata::new(&self.id, self.attachment_count);

        Ok(DecryptedListCipher {
            id: self.id,
            name,
            user,
            password,
            folder,
            uris,
            entry_type: self.entry_type,
            collection_ids: self.collection_ids,
            revision_date: self.revision_date,
            attachment_metadata,
            archived: self.archived,
            deleted: self.deleted,
            account: None,
        })
    }
}

pub(super) fn strict_result(
    result: &rbw::protocol::DecryptResult,
) -> anyhow::Result<String> {
    match result {
        rbw::protocol::DecryptResult::Success { plaintext } => {
            Ok(plaintext.clone())
        }
        rbw::protocol::DecryptResult::Failure { error } => {
            Err(anyhow::anyhow!("{error}"))
        }
    }
}

pub(super) fn lenient_result(
    result: &rbw::protocol::DecryptResult,
    name: Field,
) -> Option<String> {
    match result {
        rbw::protocol::DecryptResult::Success { plaintext } => {
            Some(plaintext.clone())
        }
        rbw::protocol::DecryptResult::Failure { error } => {
            log::warn!("failed to decrypt {name}: {error}");
            None
        }
    }
}

// A plan describing which batch-decrypt results make up a single search entry.
// Like `ListCipherPlan`, the `usize` fields index into the flat results vector
// returned by `decrypt_batch`. Search decrypts more per entry than list (notes
// and the custom field values), because those are searchable too.
pub(super) struct SearchCipherPlan {
    pub(super) id: String,
    pub(super) entry_type: String,
    pub(super) name: usize,
    pub(super) user: Option<usize>,
    pub(super) folder: Option<usize>,
    pub(super) notes: Option<usize>,
    pub(super) uris: Vec<(usize, Option<rbw::api::UriMatchType>)>,
    pub(super) fields: Vec<usize>,
    pub(super) sensitive_fields: Vec<usize>,
    pub(super) attachment_count: usize,
    pub(super) archived: bool,
    pub(super) deleted: bool,
    pub(super) password: Option<usize>,
}

impl SearchCipherPlan {
    pub(super) fn build(
        entry: &rbw::db::Entry,
        requests: &mut BatchRequests,
    ) -> Self {
        let name = requests.push(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        );

        let user = match &entry.data {
            rbw::db::EntryData::Login {
                username: Some(username),
                ..
            } => Some(requests.push(
                username,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )),
            _ => None,
        };

        // folder name should always be decrypted with the local key because
        // folders are local to a specific user's vault, not the organization
        let folder = entry
            .folder
            .as_ref()
            .map(|folder| requests.push(folder, None, None));

        let notes = entry.notes.as_ref().map(|notes| {
            requests.push(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        });

        let uris = match &entry.data {
            rbw::db::EntryData::Login { uris, .. } => uris
                .iter()
                .map(|s| {
                    (
                        requests.push(
                            &s.uri,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        ),
                        s.match_type,
                    )
                })
                .collect(),
            _ => vec![],
        };

        let fields = entry
            .fields
            .iter()
            .filter_map(|field| {
                if field.ty == Some(rbw::api::FieldType::Hidden) {
                    None
                } else {
                    field.value.as_ref()
                }
            })
            .map(|value| {
                requests.push(
                    value,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
            })
            .collect();

        let push_opt = |v: Option<&String>, requests: &mut BatchRequests| {
            v.map(|s| {
                requests.push(
                    s,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
            })
        };
        let mut sensitive_fields: Vec<usize> = Vec::new();
        let mut password_idx: Option<usize> = None;
        match &entry.data {
            rbw::db::EntryData::Login { password, .. } => {
                let idx = push_opt(password.as_ref(), requests);
                sensitive_fields.extend(idx);
                password_idx = idx;
            }
            rbw::db::EntryData::Card { number, code, .. } => {
                sensitive_fields.extend(push_opt(number.as_ref(), requests));
                sensitive_fields.extend(push_opt(code.as_ref(), requests));
            }
            rbw::db::EntryData::Identity {
                ssn,
                license_number,
                passport_number,
                ..
            } => {
                sensitive_fields.extend(push_opt(ssn.as_ref(), requests));
                sensitive_fields
                    .extend(push_opt(license_number.as_ref(), requests));
                sensitive_fields
                    .extend(push_opt(passport_number.as_ref(), requests));
            }
            rbw::db::EntryData::SshKey { private_key, .. } => {
                sensitive_fields
                    .extend(push_opt(private_key.as_ref(), requests));
            }
            rbw::db::EntryData::SecureNote => {}
        }
        for field in &entry.fields {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                sensitive_fields
                    .extend(push_opt(field.value.as_ref(), requests));
            }
        }

        Self {
            id: entry.id.clone(),
            entry_type: entry_type_name(&entry.data).to_string(),
            name,
            user,
            folder,
            notes,
            uris,
            fields,
            sensitive_fields,
            attachment_count: entry.attachments.len(),
            archived: entry.archived,
            deleted: entry.deleted,
            password: password_idx,
        }
    }

    pub(super) fn resolve(
        self,
        results: &[rbw::protocol::DecryptResult],
    ) -> anyhow::Result<DecryptedSearchCipher> {
        // name, folder, and the (non-hidden) custom fields were previously
        // decrypted with `?`, so their failures stay fatal; user, uris, and
        // notes were best-effort and are skipped (with a warning) on failure
        let name = strict_result(&results[self.name])?;
        let folder = self
            .folder
            .map(|index| strict_result(&results[index]))
            .transpose()?;
        let fields = self
            .fields
            .iter()
            .map(|&index| strict_result(&results[index]))
            .collect::<anyhow::Result<_>>()?;
        let user = self.user.and_then(|index| {
            lenient_result(&results[index], Field::Username)
        });
        let notes = self
            .notes
            .and_then(|index| lenient_result(&results[index], Field::Notes));
        let uris = self
            .uris
            .into_iter()
            .filter_map(|(index, match_type)| {
                lenient_result(&results[index], Field::Uris)
                    .map(|uri| (uri, match_type))
            })
            .collect();

        let sensitive_fields = self
            .sensitive_fields
            .iter()
            .filter_map(|&index| {
                lenient_result(&results[index], Field::Password)
            })
            .collect();

        let password = self.password.and_then(|index| {
            lenient_result(&results[index], Field::Password)
        });

        Ok(DecryptedSearchCipher {
            id: self.id,
            entry_type: self.entry_type,
            folder,
            name,
            user,
            uris,
            fields,
            notes,
            sensitive_fields,
            attachment_count: self.attachment_count,
            archived: self.archived,
            deleted: self.deleted,
            password,
        })
    }
}

pub(super) fn decrypt_search_cipher(
    entry: &rbw::db::Entry,
) -> anyhow::Result<DecryptedSearchCipher> {
    let id = entry.id.clone();
    let name = crate::actions::decrypt(
        &entry.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let user = match &entry.data {
        rbw::db::EntryData::Login { username, .. } => decrypt_field(
            Field::Username,
            username.as_deref(),
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        ),
        _ => None,
    };
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crate::actions::decrypt(folder, None, None))
        .transpose()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            crate::actions::decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let uris = if let rbw::db::EntryData::Login { uris, .. } = &entry.data {
        uris.iter()
            .filter_map(|s| {
                decrypt_field(
                    Field::Uris,
                    Some(&s.uri),
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .map(|uri| (uri, s.match_type))
            })
            .collect()
    } else {
        vec![]
    };
    let fields = entry
        .fields
        .iter()
        .filter_map(|field| {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                None
            } else {
                field.value.as_ref()
            }
        })
        .map(|value| {
            crate::actions::decrypt(
                value,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };

    let decrypt_opt = |v: Option<&String>| -> Option<String> {
        v.and_then(|s| {
            decrypt_field(
                Field::Password,
                Some(s),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
    };
    let login_password = match &entry.data {
        rbw::db::EntryData::Login { password, .. } => {
            decrypt_opt(password.as_ref())
        }
        _ => None,
    };
    let sensitive_fields: Vec<String> = {
        let mut sf: Vec<String> = Vec::new();
        match &entry.data {
            rbw::db::EntryData::Login { password, .. } => {
                sf.extend(decrypt_opt(password.as_ref()));
            }
            rbw::db::EntryData::Card { number, code, .. } => {
                sf.extend(decrypt_opt(number.as_ref()));
                sf.extend(decrypt_opt(code.as_ref()));
            }
            rbw::db::EntryData::Identity {
                ssn,
                license_number,
                passport_number,
                ..
            } => {
                sf.extend(decrypt_opt(ssn.as_ref()));
                sf.extend(decrypt_opt(license_number.as_ref()));
                sf.extend(decrypt_opt(passport_number.as_ref()));
            }
            rbw::db::EntryData::SshKey { private_key, .. } => {
                sf.extend(decrypt_opt(private_key.as_ref()));
            }
            rbw::db::EntryData::SecureNote => {}
        }
        for field in &entry.fields {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                sf.extend(decrypt_opt(field.value.as_ref()));
            }
        }
        sf
    };

    Ok(DecryptedSearchCipher {
        id,
        entry_type: entry_type_name(&entry.data).to_string(),
        folder,
        name,
        user,
        uris,
        fields,
        notes,
        sensitive_fields,
        attachment_count: entry.attachments.len(),
        archived: entry.archived,
        deleted: entry.deleted,
        password: login_password,
    })
}

// Mirrors `decrypt_search_cipher`, but as a pure field projection off an
// already-decrypted `DecryptedCipher` -- no decryption, can't fail. Used by
// `--from-file`'s `list`/`search` to reuse the exact same matching
// (`DecryptedSearchCipher::search_match`) and `Into<DecryptedListCipher>`
// the live-account path uses.
pub(super) fn decrypted_cipher_to_search(
    decrypted: &DecryptedCipher,
) -> DecryptedSearchCipher {
    let user = match &decrypted.data {
        DecryptedData::Login { username, .. } => username.clone(),
        _ => None,
    };
    let uris = if let DecryptedData::Login { uris, .. } = &decrypted.data {
        uris.clone()
            .unwrap_or_default()
            .into_iter()
            .map(|u| (u.uri, u.match_type))
            .collect()
    } else {
        vec![]
    };
    let fields = decrypted
        .fields
        .iter()
        .filter_map(|field| {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                None
            } else {
                field.value.clone()
            }
        })
        .collect();
    let login_password = match &decrypted.data {
        DecryptedData::Login { password, .. } => password.clone(),
        _ => None,
    };
    let sensitive_fields: Vec<String> = {
        let mut sf: Vec<String> = Vec::new();
        match &decrypted.data {
            DecryptedData::Login { password, .. } => {
                sf.extend(password.clone());
            }
            DecryptedData::Card { number, code, .. } => {
                sf.extend(number.clone());
                sf.extend(code.clone());
            }
            DecryptedData::Identity {
                ssn,
                license_number,
                passport_number,
                ..
            } => {
                sf.extend(ssn.clone());
                sf.extend(license_number.clone());
                sf.extend(passport_number.clone());
            }
            DecryptedData::SshKey { private_key, .. } => {
                sf.extend(private_key.clone());
            }
            DecryptedData::SecureNote => {}
        }
        for field in &decrypted.fields {
            if field.ty == Some(rbw::api::FieldType::Hidden) {
                sf.extend(field.value.clone());
            }
        }
        sf
    };

    DecryptedSearchCipher {
        id: decrypted.id.clone(),
        entry_type: decrypted_entry_type_name(&decrypted.data).to_string(),
        folder: decrypted.folder.clone(),
        name: decrypted.name.clone(),
        user,
        uris,
        fields,
        notes: decrypted.notes.clone(),
        sensitive_fields,
        attachment_count: decrypted.attachment_metadata.attachment_count,
        archived: decrypted.archived,
        deleted: decrypted.deleted,
        password: login_password,
    }
}

pub fn decrypt_cipher(
    entry: &rbw::db::Entry,
) -> anyhow::Result<DecryptedCipher> {
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crate::actions::decrypt(folder, None, None))
        .transpose();
    let folder = match folder {
        Ok(folder) => folder,
        Err(e) => {
            log::warn!("failed to decrypt folder name: {e}");
            None
        }
    };
    let fields = entry
        .fields
        .iter()
        .map(|field| {
            Ok(DecryptedField {
                name: field
                    .name
                    .as_ref()
                    .map(|name| {
                        crate::actions::decrypt(
                            name,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                value: field
                    .value
                    .as_ref()
                    .map(|value| {
                        crate::actions::decrypt(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                ty: field.ty,
                linked_id: field.linked_id,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            crate::actions::decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };
    // Unlike every other field here, a bad history entry must not fail
    // the whole decrypt: history is append-only and never rewritten by
    // later edits, so a single old, unrelated corrupt entry (e.g. from
    // data written before a since-fixed bug) would otherwise permanently
    // hide this cipher's current, perfectly good name/username/password/
    // etc. -- exactly the "everything but the field I just changed
    // disappeared" failure mode this is guarding against.
    let history = entry
        .history
        .iter()
        .map(|history_entry| DecryptedHistoryEntry {
            last_used_date: history_entry.last_used_date.clone(),
            password: crate::actions::decrypt(
                &history_entry.password,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .unwrap_or_else(|e| {
                log::warn!("failed to decrypt history entry: {e}");
                "[failed to decrypt]".to_string()
            }),
        })
        .collect();
    let attachments: Vec<_> = entry
        .attachments
        .iter()
        .map(|attachment| DecryptedAttachment {
            id: attachment.id.clone(),
            file_name: decrypt_field_with_attachment_key(
                Field::Name,
                attachment.file_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
                attachment.key.as_deref(),
            ),
            size: attachment.size.clone(),
            size_name: attachment.size_name.clone(),
        })
        .collect();
    let attachment_count = attachments.len();

    let data = match &entry.data {
        rbw::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        } => DecryptedData::Login {
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            password: decrypt_field(
                Field::Password,
                password.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            totp: decrypt_field(
                Field::Totp,
                totp.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(
                        Field::Uris,
                        Some(&s.uri),
                        entry.key.as_deref(),
                        entry.org_id.as_deref(),
                    )
                    .map(|uri| DecryptedUri {
                        uri,
                        match_type: s.match_type,
                    })
                })
                .collect(),
            fido2_credentials: fido2_credentials
                .iter()
                .map(|c| {
                    let dec = |field: Option<&str>| {
                        decrypt_field(
                            Field::Fido2Credential,
                            field,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    };
                    DecryptedFido2Credential {
                        credential_id: dec(c.credential_id.as_deref()),
                        key_type: dec(c.key_type.as_deref()),
                        key_algorithm: dec(c.key_algorithm.as_deref()),
                        key_curve: dec(c.key_curve.as_deref()),
                        key_value: dec(c.key_value.as_deref()),
                        rp_id: dec(c.rp_id.as_deref()),
                        user_handle: dec(c.user_handle.as_deref()),
                        user_name: dec(c.user_name.as_deref()),
                        counter: dec(c.counter.as_deref()),
                        rp_name: dec(c.rp_name.as_deref()),
                        user_display_name: dec(c
                            .user_display_name
                            .as_deref()),
                        discoverable: dec(c.discoverable.as_deref()),
                        // never encrypted to begin with
                        creation_date: c.creation_date.clone(),
                    }
                })
                .collect(),
        },
        rbw::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: decrypt_field(
                Field::Cardholder,
                cardholder_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            number: decrypt_field(
                Field::CardNumber,
                number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            brand: decrypt_field(
                Field::Brand,
                brand.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_month: decrypt_field(
                Field::ExpMonth,
                exp_month.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_year: decrypt_field(
                Field::ExpYear,
                exp_year.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            code: decrypt_field(
                Field::Cvv,
                code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        rbw::db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => DecryptedData::Identity {
            title: decrypt_field(
                Field::Title,
                title.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            first_name: decrypt_field(
                Field::FirstName,
                first_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            middle_name: decrypt_field(
                Field::MiddleName,
                middle_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            last_name: decrypt_field(
                Field::LastName,
                last_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address1: decrypt_field(
                Field::Address1,
                address1.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address2: decrypt_field(
                Field::Address2,
                address2.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address3: decrypt_field(
                Field::Address3,
                address3.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            city: decrypt_field(
                Field::City,
                city.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            state: decrypt_field(
                Field::State,
                state.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            postal_code: decrypt_field(
                Field::PostalCode,
                postal_code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            country: decrypt_field(
                Field::Country,
                country.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            phone: decrypt_field(
                Field::Phone,
                phone.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            email: decrypt_field(
                Field::Email,
                email.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            ssn: decrypt_field(
                Field::Ssn,
                ssn.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            license_number: decrypt_field(
                Field::License,
                license_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            passport_number: decrypt_field(
                Field::Passport,
                passport_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        rbw::db::EntryData::SecureNote => DecryptedData::SecureNote {},
        rbw::db::EntryData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => DecryptedData::SshKey {
            public_key: decrypt_field(
                Field::PublicKey,
                public_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            fingerprint: decrypt_field(
                Field::Fingerprint,
                fingerprint.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            private_key: decrypt_field(
                Field::PrivateKey,
                private_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name: crate::actions::decrypt(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?,
        data,
        fields,
        notes,
        history,
        attachments,
        attachment_metadata: AttachmentMetadata::new(
            &entry.id,
            attachment_count,
        ),
        archived: entry.archived,
        deleted: entry.deleted,
        account: None,
        revision_date: entry.revision_date.clone(),
    })
}
