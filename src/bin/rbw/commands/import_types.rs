use super::*;

// Deserialize-only mirrors of the `Decrypted*`/`Exported*` export shapes.
// Kept separate from those (serialize-only) types rather than adding
// `Deserialize` to them, since the wire format mixes representations (field
// types are strings, URI match types are numbers) that are easier to pin
// down explicitly here. Every field that isn't strictly required uses
// `#[serde(default)]` so small differences in a newer/older export (an
// absent `attachments` array, an unrecognized extra field, etc.) degrade
// gracefully instead of failing the whole import.
#[derive(Debug, serde::Deserialize)]
pub(super) struct ImportedUri {
    pub(super) uri: String,
    #[serde(default)]
    pub(super) match_type: Option<rbw::api::UriMatchType>,
}

// Deserialize-only mirror of `DecryptedFido2Credential`, same reasoning as
// `ImportedUri` above.
#[derive(Debug, Default, serde::Deserialize)]
pub(super) struct ImportedFido2Credential {
    #[serde(default)]
    pub(super) credential_id: Option<String>,
    #[serde(default)]
    pub(super) key_type: Option<String>,
    #[serde(default)]
    pub(super) key_algorithm: Option<String>,
    #[serde(default)]
    pub(super) key_curve: Option<String>,
    #[serde(default)]
    pub(super) key_value: Option<String>,
    #[serde(default)]
    pub(super) rp_id: Option<String>,
    #[serde(default)]
    pub(super) user_handle: Option<String>,
    #[serde(default)]
    pub(super) user_name: Option<String>,
    #[serde(default)]
    pub(super) counter: Option<String>,
    #[serde(default)]
    pub(super) rp_name: Option<String>,
    #[serde(default)]
    pub(super) user_display_name: Option<String>,
    #[serde(default)]
    pub(super) discoverable: Option<String>,
    #[serde(default)]
    pub(super) creation_date: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ImportedField {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) value: Option<String>,
    #[serde(rename = "type", default)]
    pub(super) ty: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub(super) struct ImportedHistoryEntry {
    #[serde(default)]
    pub(super) last_used_date: String,
    #[serde(default)]
    pub(super) password: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type")]
pub(super) enum ImportedData {
    Login {
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        totp: Option<String>,
        #[serde(default)]
        uris: Option<Vec<ImportedUri>>,
        #[serde(default)]
        fido2_credentials: Vec<ImportedFido2Credential>,
    },
    Card {
        #[serde(default)]
        cardholder_name: Option<String>,
        #[serde(default)]
        number: Option<String>,
        #[serde(default)]
        brand: Option<String>,
        #[serde(default)]
        exp_month: Option<String>,
        #[serde(default)]
        exp_year: Option<String>,
        #[serde(default)]
        code: Option<String>,
    },
    Identity {
        #[serde(default)]
        title: Option<String>,
        #[serde(default)]
        first_name: Option<String>,
        #[serde(default)]
        middle_name: Option<String>,
        #[serde(default)]
        last_name: Option<String>,
        #[serde(default)]
        address1: Option<String>,
        #[serde(default)]
        address2: Option<String>,
        #[serde(default)]
        address3: Option<String>,
        #[serde(default)]
        city: Option<String>,
        #[serde(default)]
        state: Option<String>,
        #[serde(default)]
        postal_code: Option<String>,
        #[serde(default)]
        country: Option<String>,
        #[serde(default)]
        phone: Option<String>,
        #[serde(default)]
        email: Option<String>,
        #[serde(default)]
        ssn: Option<String>,
        #[serde(default)]
        license_number: Option<String>,
        #[serde(default)]
        passport_number: Option<String>,
        #[serde(default)]
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        #[serde(default)]
        public_key: Option<String>,
        #[serde(default)]
        fingerprint: Option<String>,
        #[serde(default)]
        private_key: Option<String>,
    },
}

// Mirrors the (still-unlanded, as of this writing) `ExportedAttachment`
// shape from `rbw export --attachments`. Kept as raw `serde_json::Value`s on
// `ImportedEntry` rather than a typed `Vec<ImportedAttachment>` so that if
// the real field name/shape ends up slightly different, we still parse the
// rest of the entry -- we just skip (and warn about) the attachments that
// don't match this shape instead of failing to parse the whole entry.
#[derive(Debug, serde::Deserialize)]
pub(super) struct ImportedAttachment {
    // Not used by `import` (a freshly-uploaded attachment always gets a new
    // id from the server) -- only read by `load_from_file`, which has no
    // server to assign one and needs a stable id to key its side table of
    // attachment bytes by.
    #[serde(default)]
    pub(super) id: Option<String>,
    #[serde(default)]
    pub(super) file_name: Option<String>,
    #[serde(default)]
    pub(super) data_base64: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ImportedEntry {
    // Same story as `ImportedAttachment::id`: `import` doesn't need it (new
    // entries get a fresh id from the server), `load_from_file` does.
    #[serde(default)]
    pub(super) id: Option<String>,
    #[serde(default)]
    pub(super) org_id: Option<String>,
    #[serde(default)]
    pub(super) folder: Option<String>,
    pub(super) name: String,
    #[serde(flatten)]
    pub(super) data: ImportedData,
    #[serde(default)]
    pub(super) fields: Vec<ImportedField>,
    #[serde(default)]
    pub(super) notes: Option<String>,
    #[serde(default)]
    pub(super) history: Vec<ImportedHistoryEntry>,
    #[serde(default)]
    pub(super) collection_ids: Vec<String>,
    #[serde(default)]
    pub(super) archived: bool,
    #[serde(default)]
    pub(super) deleted: bool,
    #[serde(default)]
    pub(super) attachments: Vec<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ImportedCollection {
    #[serde(default)]
    pub(super) id: Option<String>,
    pub(super) org_id: String,
    pub(super) name: String,
}

#[derive(Debug, Default, serde::Deserialize)]
pub(super) struct ImportedVault {
    #[serde(default)]
    pub(super) entries: Vec<ImportedEntry>,
    #[serde(default)]
    pub(super) collections: Vec<ImportedCollection>,
}

// Converts a parsed Bitwarden vault export into the same `ImportedVault`
// shape `rbw export`'s own JSON deserializes into, so the rest of `import`
// (collection creation, entry create/overwrite, attachment upload) doesn't
// need to know which kind of export it came from. `attachments` is only
// `Some` for a "zip (with attachments)" export; the plain/encrypted JSON
// formats never carry attachment bytes at all (confirmed against real
// exports: their items have no `attachments` field, populated or
// otherwise), so entries from those formats never get an `attachments`
// list.
pub(super) fn bw_vault_to_imported(
    bw: crate::import_bitwarden::BwVault,
    mut attachments: Option<
        std::collections::HashMap<
            String,
            Vec<crate::import_bitwarden::ZipAttachment>,
        >,
    >,
) -> ImportedVault {
    let c = stdout_supports_color();

    let folder_names: std::collections::HashMap<String, String> = bw
        .folders
        .iter()
        .filter_map(|f| f.id.clone().map(|id| (id, f.name.clone())))
        .collect();

    let collections = bw
        .collections
        .into_iter()
        .filter_map(|col| {
            let Some(org_id) = col.organization_id else {
                eprintln!(
                    "{} skipped collection '{}' (no organization id)",
                    style::warning("Warning:", c),
                    col.name,
                );
                return None;
            };
            Some(ImportedCollection {
                id: col.id,
                org_id,
                name: col.name,
            })
        })
        .collect();

    let entries = bw
        .items
        .into_iter()
        .filter_map(|item| {
            let name = item.name.clone();
            let Some(data) = bw_item_data(&item) else {
                eprintln!(
                    "{} skipped '{name}' (unrecognized item type {})",
                    style::warning("Warning:", c),
                    item.ty,
                );
                return None;
            };

            let fields = item
                .fields
                .iter()
                .map(|f| ImportedField {
                    name: f.name.clone(),
                    value: f.value.clone(),
                    ty: f.ty.map(|ty| field_type_str(ty).to_string()),
                })
                .collect();

            let history = item
                .password_history
                .iter()
                .map(|h| ImportedHistoryEntry {
                    last_used_date: h.last_used_date.clone(),
                    password: h.password.clone(),
                })
                .collect();

            let entry_attachments = attachments
                .as_mut()
                .map_or_else(Vec::new, |all| bw_item_attachments(&name, all));

            Some(ImportedEntry {
                id: item.id,
                org_id: item.organization_id,
                folder: item
                    .folder_id
                    .as_deref()
                    .and_then(|id| folder_names.get(id).cloned()),
                name,
                data,
                fields,
                notes: item.notes,
                history,
                collection_ids: item.collection_ids,
                archived: item.archived_date.is_some(),
                deleted: item.deleted_date.is_some(),
                attachments: entry_attachments,
            })
        })
        .collect();

    if let Some(leftover) = &attachments {
        if !leftover.is_empty() {
            eprintln!(
                "{} {} attachment folder(s) in the zip archive didn't \
                 match any item name and were skipped: {}",
                style::warning("Warning:", c),
                leftover.len(),
                leftover.keys().cloned().collect::<Vec<_>>().join(", "),
            );
        }
    }

    ImportedVault {
        entries,
        collections,
    }
}

pub(super) fn bw_item_data(
    item: &crate::import_bitwarden::BwItem,
) -> Option<ImportedData> {
    match item.ty {
        1 => {
            let login = item.login.as_ref();
            Some(ImportedData::Login {
                username: login.and_then(|l| l.username.clone()),
                password: login.and_then(|l| l.password.clone()),
                totp: login.and_then(|l| l.totp.clone()),
                uris: login.map(|l| {
                    l.uris
                        .iter()
                        .filter_map(|u| {
                            u.uri.clone().map(|uri| ImportedUri {
                                uri,
                                match_type: u.match_type,
                            })
                        })
                        .collect()
                }),
                fido2_credentials: login.map_or_else(Vec::new, |l| {
                    l.fido2_credentials
                        .iter()
                        .map(|c| ImportedFido2Credential {
                            credential_id: c.credential_id.clone(),
                            key_type: c.key_type.clone(),
                            key_algorithm: c.key_algorithm.clone(),
                            key_curve: c.key_curve.clone(),
                            key_value: c.key_value.clone(),
                            rp_id: c.rp_id.clone(),
                            user_handle: c.user_handle.clone(),
                            user_name: c.user_name.clone(),
                            counter: c.counter.clone(),
                            rp_name: c.rp_name.clone(),
                            user_display_name: c.user_display_name.clone(),
                            discoverable: c.discoverable.clone(),
                            creation_date: c.creation_date.clone(),
                        })
                        .collect()
                }),
            })
        }
        2 => Some(ImportedData::SecureNote),
        3 => {
            let card = item.card.as_ref();
            Some(ImportedData::Card {
                cardholder_name: card
                    .and_then(|card| card.cardholder_name.clone()),
                number: card.and_then(|card| card.number.clone()),
                brand: card.and_then(|card| card.brand.clone()),
                exp_month: card.and_then(|card| card.exp_month.clone()),
                exp_year: card.and_then(|card| card.exp_year.clone()),
                code: card.and_then(|card| card.code.clone()),
            })
        }
        4 => {
            let identity = item.identity.as_ref();
            Some(ImportedData::Identity {
                title: identity.and_then(|i| i.title.clone()),
                first_name: identity.and_then(|i| i.first_name.clone()),
                middle_name: identity.and_then(|i| i.middle_name.clone()),
                last_name: identity.and_then(|i| i.last_name.clone()),
                address1: identity.and_then(|i| i.address1.clone()),
                address2: identity.and_then(|i| i.address2.clone()),
                address3: identity.and_then(|i| i.address3.clone()),
                city: identity.and_then(|i| i.city.clone()),
                state: identity.and_then(|i| i.state.clone()),
                postal_code: identity.and_then(|i| i.postal_code.clone()),
                country: identity.and_then(|i| i.country.clone()),
                phone: identity.and_then(|i| i.phone.clone()),
                email: identity.and_then(|i| i.email.clone()),
                ssn: identity.and_then(|i| i.ssn.clone()),
                license_number: identity
                    .and_then(|i| i.license_number.clone()),
                passport_number: identity
                    .and_then(|i| i.passport_number.clone()),
                username: identity.and_then(|i| i.username.clone()),
            })
        }
        5 => {
            let ssh_key = item.ssh_key.as_ref();
            Some(ImportedData::SshKey {
                public_key: ssh_key.and_then(|k| k.public_key.clone()),
                fingerprint: ssh_key.and_then(|k| k.fingerprint.clone()),
                private_key: ssh_key.and_then(|k| k.private_key.clone()),
            })
        }
        _ => None,
    }
}

// Pulls every attachment the zip archive has under `item_name`'s (sanitized)
// folder -- see `import_bitwarden::sanitize_zip_folder_name` -- since a
// real export's per-item `attachments` metadata is always empty even
// inside a zip export, leaving the sanitized display name as the only
// association between a folder and the item that owns it. Two items
// sharing an identical name are therefore inherently ambiguous; whichever
// is converted first claims the shared folder.
pub(super) fn bw_item_attachments(
    item_name: &str,
    all: &mut std::collections::HashMap<
        String,
        Vec<crate::import_bitwarden::ZipAttachment>,
    >,
) -> Vec<serde_json::Value> {
    let key = crate::import_bitwarden::sanitize_zip_folder_name(item_name);
    let Some(candidates) = all.remove(&key) else {
        return Vec::new();
    };

    candidates
        .into_iter()
        .map(|za| {
            serde_json::json!({
                "file_name": za.file_name,
                "data_base64": rbw::base64::encode(&za.data),
            })
        })
        .collect()
}

// Converts rbw's own decrypted export vault into a Bitwarden `BwVault` --
// the inverse of `bw_vault_to_imported` -- so `rbw export --format
// bitwarden-*` can reuse the same schema plumbing `rbw import` uses. Also
// returns every attachment as (item name, file name, decrypted bytes),
// keyed by name (not id) since that's the only association a zip export
// preserves; only the `bitwarden-zip` format actually embeds these.
pub(super) fn exported_vault_to_bw(
    vault: &ExportedVault,
) -> (
    crate::import_bitwarden::BwVault,
    Vec<(String, String, Vec<u8>)>,
) {
    let mut folder_ids: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for entry in &vault.entries {
        if let Some(name) = &entry.folder {
            folder_ids
                .entry(name.clone())
                .or_insert_with(|| uuid::Uuid::new_v4().to_string());
        }
    }
    let folders = folder_ids
        .iter()
        .map(|(name, id)| crate::import_bitwarden::BwFolder {
            id: Some(id.clone()),
            name: name.clone(),
        })
        .collect();

    let collections = vault
        .collections
        .iter()
        .map(|c| crate::import_bitwarden::BwCollection {
            id: Some(c.id.clone()),
            organization_id: Some(c.org_id.clone()),
            name: c.name.clone(),
        })
        .collect();

    let mut attachments_out = Vec::new();
    let items = vault
        .entries
        .iter()
        .map(|entry| {
            for attachment in &entry.attachments {
                if let Ok(data) = rbw::base64::decode(&attachment.data_base64)
                {
                    attachments_out.push((
                        entry.name.clone(),
                        attachment.file_name.clone(),
                        data,
                    ));
                }
            }

            let (ty, login, card, identity, ssh_key) =
                bw_data_from_decrypted(&entry.data);

            crate::import_bitwarden::BwItem {
                id: Some(entry.id.clone()),
                organization_id: entry.org_id.clone(),
                folder_id: entry
                    .folder
                    .as_ref()
                    .and_then(|name| folder_ids.get(name).cloned()),
                archived_date: entry.archived.then(|| {
                    humantime::format_rfc3339(std::time::SystemTime::now())
                        .to_string()
                }),
                deleted_date: entry.deleted.then(|| {
                    humantime::format_rfc3339(std::time::SystemTime::now())
                        .to_string()
                }),
                ty,
                name: entry.name.clone(),
                notes: entry.notes.clone(),
                login,
                card,
                identity,
                ssh_key,
                fields: entry
                    .fields
                    .iter()
                    .map(|f| crate::import_bitwarden::BwField {
                        name: f.name.clone(),
                        value: f.value.clone(),
                        ty: f.ty,
                    })
                    .collect(),
                password_history: entry
                    .history
                    .iter()
                    .map(|h| crate::import_bitwarden::BwPasswordHistory {
                        last_used_date: h.last_used_date.clone(),
                        password: h.password.clone(),
                    })
                    .collect(),
                collection_ids: entry.collection_ids.clone(),
            }
        })
        .collect();

    (
        crate::import_bitwarden::BwVault {
            folders,
            collections,
            items,
        },
        attachments_out,
    )
}

pub(super) fn bw_data_from_decrypted(
    data: &DecryptedData,
) -> (
    u16,
    Option<crate::import_bitwarden::BwLogin>,
    Option<crate::import_bitwarden::BwCard>,
    Option<crate::import_bitwarden::BwIdentity>,
    Option<crate::import_bitwarden::BwSshKey>,
) {
    match data {
        DecryptedData::Login {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        } => (
            1,
            Some(crate::import_bitwarden::BwLogin {
                username: username.clone(),
                password: password.clone(),
                totp: totp.clone(),
                uris: uris
                    .as_ref()
                    .map(|us| {
                        us.iter()
                            .map(|u| crate::import_bitwarden::BwUri {
                                uri: Some(u.uri.clone()),
                                match_type: u.match_type,
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                fido2_credentials: fido2_credentials
                    .iter()
                    .map(|c| crate::import_bitwarden::BwFido2Credential {
                        credential_id: c.credential_id.clone(),
                        key_type: c.key_type.clone(),
                        key_algorithm: c.key_algorithm.clone(),
                        key_curve: c.key_curve.clone(),
                        key_value: c.key_value.clone(),
                        rp_id: c.rp_id.clone(),
                        user_handle: c.user_handle.clone(),
                        user_name: c.user_name.clone(),
                        counter: c.counter.clone(),
                        rp_name: c.rp_name.clone(),
                        user_display_name: c.user_display_name.clone(),
                        discoverable: c.discoverable.clone(),
                        creation_date: c.creation_date.clone(),
                    })
                    .collect(),
            }),
            None,
            None,
            None,
        ),
        DecryptedData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => (
            3,
            None,
            Some(crate::import_bitwarden::BwCard {
                cardholder_name: cardholder_name.clone(),
                brand: brand.clone(),
                number: number.clone(),
                exp_month: exp_month.clone(),
                exp_year: exp_year.clone(),
                code: code.clone(),
            }),
            None,
            None,
        ),
        DecryptedData::Identity {
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
        } => (
            4,
            None,
            None,
            Some(crate::import_bitwarden::BwIdentity {
                title: title.clone(),
                first_name: first_name.clone(),
                middle_name: middle_name.clone(),
                last_name: last_name.clone(),
                address1: address1.clone(),
                address2: address2.clone(),
                address3: address3.clone(),
                city: city.clone(),
                state: state.clone(),
                postal_code: postal_code.clone(),
                country: country.clone(),
                phone: phone.clone(),
                email: email.clone(),
                ssn: ssn.clone(),
                license_number: license_number.clone(),
                passport_number: passport_number.clone(),
                username: username.clone(),
            }),
            None,
        ),
        DecryptedData::SecureNote => (2, None, None, None, None),
        DecryptedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => (
            5,
            None,
            None,
            None,
            Some(crate::import_bitwarden::BwSshKey {
                private_key: private_key.clone(),
                public_key: public_key.clone(),
                fingerprint: fingerprint.clone(),
            }),
        ),
    }
}

pub(super) fn imported_data_to_editable(data: &ImportedData) -> EditableData {
    match data {
        ImportedData::Login {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        } => EditableData::Login {
            username: username.clone(),
            password: password.clone(),
            uris: uris
                .as_ref()
                .map(|v| {
                    v.iter()
                        .map(|u| EditableUri {
                            uri: u.uri.clone(),
                            match_type: u
                                .match_type
                                .map(|mt| uri_match_type_str(mt).to_string()),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            totp: totp.clone(),
            fido2_credentials: fido2_credentials
                .iter()
                .map(|c| EditableFido2Credential {
                    credential_id: c.credential_id.clone(),
                    key_type: c.key_type.clone(),
                    key_algorithm: c.key_algorithm.clone(),
                    key_curve: c.key_curve.clone(),
                    key_value: c.key_value.clone(),
                    rp_id: c.rp_id.clone(),
                    user_handle: c.user_handle.clone(),
                    user_name: c.user_name.clone(),
                    counter: c.counter.clone(),
                    rp_name: c.rp_name.clone(),
                    user_display_name: c.user_display_name.clone(),
                    discoverable: c.discoverable.clone(),
                    creation_date: c.creation_date.clone(),
                })
                .collect(),
        },
        ImportedData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => EditableData::Card {
            cardholder_name: cardholder_name.clone(),
            number: number.clone(),
            brand: brand.clone(),
            exp_month: exp_month.clone(),
            exp_year: exp_year.clone(),
            code: code.clone(),
        },
        ImportedData::Identity {
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
        } => EditableData::Identity {
            title: title.clone(),
            first_name: first_name.clone(),
            middle_name: middle_name.clone(),
            last_name: last_name.clone(),
            address1: address1.clone(),
            address2: address2.clone(),
            address3: address3.clone(),
            city: city.clone(),
            state: state.clone(),
            postal_code: postal_code.clone(),
            country: country.clone(),
            phone: phone.clone(),
            email: email.clone(),
            ssn: ssn.clone(),
            license_number: license_number.clone(),
            passport_number: passport_number.clone(),
            username: username.clone(),
        },
        ImportedData::SecureNote => EditableData::SecureNote,
        ImportedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => EditableData::SshKey {
            private_key: private_key.clone(),
            public_key: public_key.clone(),
            fingerprint: fingerprint.clone(),
        },
    }
}

pub(super) fn imported_to_editable(
    imported: &ImportedEntry,
) -> EditableCipher {
    EditableCipher {
        name: imported.name.clone(),
        folder: imported.folder.clone(),
        notes: imported.notes.clone(),
        data: imported_data_to_editable(&imported.data),
        fields: imported
            .fields
            .iter()
            .map(|f| EditableCustomField {
                name: f.name.clone(),
                value: f.value.clone(),
                ty: f.ty.clone(),
            })
            .collect(),
    }
}

// Mirrors `imported_data_to_editable`, but into `DecryptedData` -- the
// shape `list`/`search`/`tui` already render -- for `--from-file`, which
// treats an export as an already-decrypted, in-memory-only vault instead of
// importing it. Unlike `EditableUri`, `DecryptedUri` keeps `match_type` as
// the native enum rather than a display string, so no conversion needed.
pub(super) fn imported_data_to_decrypted(
    data: &ImportedData,
) -> DecryptedData {
    match data {
        ImportedData::Login {
            username,
            password,
            totp,
            uris,
            fido2_credentials,
        } => DecryptedData::Login {
            username: username.clone(),
            password: password.clone(),
            totp: totp.clone(),
            uris: uris.as_ref().map(|v| {
                v.iter()
                    .map(|u| DecryptedUri {
                        uri: u.uri.clone(),
                        match_type: u.match_type,
                    })
                    .collect()
            }),
            fido2_credentials: fido2_credentials
                .iter()
                .map(|c| DecryptedFido2Credential {
                    credential_id: c.credential_id.clone(),
                    key_type: c.key_type.clone(),
                    key_algorithm: c.key_algorithm.clone(),
                    key_curve: c.key_curve.clone(),
                    key_value: c.key_value.clone(),
                    rp_id: c.rp_id.clone(),
                    user_handle: c.user_handle.clone(),
                    user_name: c.user_name.clone(),
                    counter: c.counter.clone(),
                    rp_name: c.rp_name.clone(),
                    user_display_name: c.user_display_name.clone(),
                    discoverable: c.discoverable.clone(),
                    creation_date: c.creation_date.clone(),
                })
                .collect(),
        },
        ImportedData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: cardholder_name.clone(),
            number: number.clone(),
            brand: brand.clone(),
            exp_month: exp_month.clone(),
            exp_year: exp_year.clone(),
            code: code.clone(),
        },
        ImportedData::Identity {
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
            title: title.clone(),
            first_name: first_name.clone(),
            middle_name: middle_name.clone(),
            last_name: last_name.clone(),
            address1: address1.clone(),
            address2: address2.clone(),
            address3: address3.clone(),
            city: city.clone(),
            state: state.clone(),
            postal_code: postal_code.clone(),
            country: country.clone(),
            phone: phone.clone(),
            email: email.clone(),
            ssn: ssn.clone(),
            license_number: license_number.clone(),
            passport_number: passport_number.clone(),
            username: username.clone(),
        },
        ImportedData::SecureNote => DecryptedData::SecureNote,
        ImportedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => DecryptedData::SshKey {
            public_key: public_key.clone(),
            fingerprint: fingerprint.clone(),
            private_key: private_key.clone(),
        },
    }
}

pub(super) fn imported_history_to_encrypted(
    history: &[ImportedHistoryEntry],
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<Vec<rbw::db::HistoryEntry>> {
    history
        .iter()
        .map(|h| {
            Ok(rbw::db::HistoryEntry {
                last_used_date: h.last_used_date.clone(),
                password: crate::actions::encrypt(
                    &h.password,
                    entry_key,
                    org_id,
                )?,
            })
        })
        .collect()
}

pub fn read_import_input(
    file: Option<&std::path::Path>,
) -> anyhow::Result<Vec<u8>> {
    if let Some(path) = file {
        std::fs::read(path)
            .with_context(|| format!("failed to read {}", path.display()))
    } else {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("failed to read import data from stdin")?;
        Ok(buf)
    }
}

// Decrypts a gpg-encrypted tar.gz archive (as produced by `rbw export
// --encrypt`) and returns the JSON text found inside it. The ciphertext is
// streamed through gpg's stdin (with the passphrase on a dedicated pipe fd)
// and the archive is unpacked entirely in memory, so the decrypted vault
// never touches the filesystem.
pub(super) fn decrypt_import_archive(
    data: &[u8],
    passphrase: &str,
) -> anyhow::Result<String> {
    let output = run_gpg_with_passphrase(
        ["--batch", "--yes", "--passphrase-fd", "3", "--decrypt"],
        passphrase,
        data.to_vec(),
        "failed to run gpg (is it installed and on $PATH?)",
    )?;
    if !output.status.success() {
        anyhow::bail!(
            "gpg decryption failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    extract_vault_json(&output.stdout)
}

// Extracts the JSON text from an in-memory tar.gz archive: the first
// `*.json` entry, falling back to the first regular file of any kind if
// none has a `.json` extension. `rbw export --encrypt` is expected to wrap
// a single JSON file in the tar.gz, but the exact filename isn't something
// worth hard-coding here.
pub(super) fn extract_vault_json(targz: &[u8]) -> anyhow::Result<String> {
    let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(targz));
    let mut archive = tar::Archive::new(gz);
    let mut fallback: Option<String> = None;
    let entries = archive
        .entries()
        .context("failed to read the decrypted archive as a tar.gz")?;
    for entry in entries {
        let mut entry = entry
            .context("failed to read the decrypted archive as a tar.gz")?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let is_json = entry.path().is_ok_and(|path| {
            path.extension().and_then(std::ffi::OsStr::to_str) == Some("json")
        });
        if !is_json && fallback.is_some() {
            continue;
        }
        let mut contents = String::new();
        entry
            .read_to_string(&mut contents)
            .context("failed to read a file from the decrypted archive")?;
        if is_json {
            return Ok(contents);
        }
        fallback = Some(contents);
    }
    fallback.ok_or_else(|| {
        anyhow::anyhow!("no JSON file found inside the decrypted archive")
    })
}

// Figures out whether `raw` is plain JSON (today's `rbw export` output) or a
// gpg-encrypted tar.gz (`rbw export --encrypt`'s output) and returns the
// JSON text either way.
pub fn load_import_json(
    raw: &[u8],
    decrypt_passphrase: Option<&str>,
) -> anyhow::Result<String> {
    if decrypt_passphrase.is_none() {
        if let Ok(text) = std::str::from_utf8(raw) {
            if serde_json::from_str::<serde_json::Value>(text).is_ok() {
                return Ok(text.to_string());
            }
        }
    }

    if let Some(passphrase) = decrypt_passphrase {
        return decrypt_import_archive(raw, passphrase);
    }

    anyhow::bail!(
        "failed to parse import data as JSON; if this is a gpg-encrypted \
         export archive (from `rbw export --encrypt`), pass --decrypt or \
         --decrypt-passphrase"
    );
}

// If `raw` isn't already resolvable as plain JSON and no passphrase was
// given, this is exactly the shape of rbw's own gpg-encrypted export
// archive (`load_import_json` would otherwise just fail with a "pass
// --decrypt" hint) -- resolve one from RBW_EXPORT_PASSPHRASE or a
// `/dev/tty` prompt instead of erroring, same as `--decrypt` itself and
// `load_from_file`'s existing `--from-file` behavior. Falls through to
// `None` (and `load_import_json`'s existing hard failure) when a
// passphrase was already resolved, `raw` turns out to parse as plain JSON
// on its own, or no tty is available to prompt on -- so a script piping in
// ciphertext without `--decrypt` still fails fast instead of hanging.
pub fn prompt_for_encrypted_export_if_needed(
    raw: &[u8],
    decrypt_passphrase: Option<String>,
) -> Option<String> {
    if decrypt_passphrase.is_some() {
        return decrypt_passphrase;
    }
    if let Ok(text) = std::str::from_utf8(raw) {
        if serde_json::from_str::<serde_json::Value>(text).is_ok() {
            return None;
        }
    }
    resolve_env_or_prompted_passphrase(false).ok()
}
