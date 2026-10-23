use super::*;

pub(super) fn uri_match_type_str(mt: rbw::api::UriMatchType) -> &'static str {
    match mt {
        rbw::api::UriMatchType::Domain => "domain",
        rbw::api::UriMatchType::Host => "host",
        rbw::api::UriMatchType::StartsWith => "starts_with",
        rbw::api::UriMatchType::Exact => "exact",
        rbw::api::UriMatchType::RegularExpression => "regular_expression",
        rbw::api::UriMatchType::Never => "never",
    }
}

pub(super) fn parse_uri_match_type(
    s: &str,
) -> anyhow::Result<rbw::api::UriMatchType> {
    match s {
        "domain" => Ok(rbw::api::UriMatchType::Domain),
        "host" => Ok(rbw::api::UriMatchType::Host),
        "starts_with" => Ok(rbw::api::UriMatchType::StartsWith),
        "exact" => Ok(rbw::api::UriMatchType::Exact),
        "regular_expression" => Ok(rbw::api::UriMatchType::RegularExpression),
        "never" => Ok(rbw::api::UriMatchType::Never),
        other => Err(anyhow::anyhow!("unknown uri match type: '{other}'")),
    }
}

pub(super) fn clipboard_mechanism_str(
    m: rbw::config::ClipboardMechanism,
) -> &'static str {
    match m {
        rbw::config::ClipboardMechanism::Auto => "auto",
        rbw::config::ClipboardMechanism::System => "system",
        rbw::config::ClipboardMechanism::Osc52 => "osc52",
    }
}

pub(super) fn uri_match_default_str(
    value: rbw::config::UriMatchDefault,
) -> &'static str {
    match value {
        rbw::config::UriMatchDefault::Domain => "domain",
        rbw::config::UriMatchDefault::BaseDomain => "base_domain",
        rbw::config::UriMatchDefault::Host => "host",
        rbw::config::UriMatchDefault::StartsWith => "starts_with",
        rbw::config::UriMatchDefault::Exact => "exact",
        rbw::config::UriMatchDefault::RegularExpression => {
            "regular_expression"
        }
        rbw::config::UriMatchDefault::Never => "never",
    }
}

// "domain" is rbw's host-and-subdomains matching; "base_domain" Bitwarden's.
pub fn parse_uri_match_default(
    s: &str,
) -> anyhow::Result<rbw::config::UriMatchDefault> {
    Ok(match s {
        "domain" => rbw::config::UriMatchDefault::Domain,
        "base_domain" => rbw::config::UriMatchDefault::BaseDomain,
        "host" => rbw::config::UriMatchDefault::Host,
        "starts_with" => rbw::config::UriMatchDefault::StartsWith,
        "exact" => rbw::config::UriMatchDefault::Exact,
        "regular_expression" => {
            rbw::config::UriMatchDefault::RegularExpression
        }
        "never" => rbw::config::UriMatchDefault::Never,
        other => anyhow::bail!("unknown default uri match type: '{other}'"),
    })
}

pub(super) fn parse_clipboard_mechanism(
    s: &str,
) -> anyhow::Result<rbw::config::ClipboardMechanism> {
    match s {
        "auto" => Ok(rbw::config::ClipboardMechanism::Auto),
        "system" => Ok(rbw::config::ClipboardMechanism::System),
        "osc52" => Ok(rbw::config::ClipboardMechanism::Osc52),
        other => {
            Err(anyhow::anyhow!("unknown clipboard mechanism: '{other}'"))
        }
    }
}

pub(super) fn field_type_str(ft: rbw::api::FieldType) -> &'static str {
    match ft {
        rbw::api::FieldType::Text => "text",
        rbw::api::FieldType::Hidden => "hidden",
        rbw::api::FieldType::Boolean => "boolean",
        rbw::api::FieldType::Linked => "linked",
    }
}

pub(super) fn parse_field_type(
    s: &str,
) -> anyhow::Result<rbw::api::FieldType> {
    match s {
        "text" => Ok(rbw::api::FieldType::Text),
        "hidden" => Ok(rbw::api::FieldType::Hidden),
        "boolean" => Ok(rbw::api::FieldType::Boolean),
        "linked" => Ok(rbw::api::FieldType::Linked),
        other => Err(anyhow::anyhow!("unknown field type: '{other}'")),
    }
}

pub fn decrypted_to_editable(decrypted: &DecryptedCipher) -> EditableCipher {
    let data = match &decrypted.data {
        DecryptedData::Login {
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
        DecryptedData::Card {
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
        DecryptedData::SecureNote => EditableData::SecureNote,
        DecryptedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => EditableData::SshKey {
            private_key: private_key.clone(),
            public_key: public_key.clone(),
            fingerprint: fingerprint.clone(),
        },
    };

    let fields = decrypted
        .fields
        .iter()
        .map(|f| EditableCustomField {
            name: f.name.clone(),
            value: f.value.clone(),
            ty: f.ty.map(|t| field_type_str(t).to_string()),
        })
        .collect();

    EditableCipher {
        name: decrypted.name.clone(),
        folder: decrypted.folder.clone(),
        notes: decrypted.notes.clone(),
        data,
        fields,
    }
}

pub(super) fn editable_to_encrypted(
    editable: &EditableCipher,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<(rbw::db::EntryData, Vec<rbw::db::Field>, Option<String>)>
{
    let data = match &editable.data {
        EditableData::Login {
            username,
            password,
            uris,
            totp,
            fido2_credentials,
        } => {
            let enc = |s: &Option<String>| {
                s.as_deref()
                    .filter(|v| !v.is_empty())
                    .map(|v| crate::actions::encrypt(v, entry_key, org_id))
                    .transpose()
            };
            let username = enc(username)?;
            let password = enc(password)?;
            let uris = uris
                .iter()
                .filter(|u| !u.uri.is_empty())
                .map(|u| {
                    let match_type = u
                        .match_type
                        .as_deref()
                        .map(parse_uri_match_type)
                        .transpose()?;
                    Ok(rbw::db::Uri {
                        uri: crate::actions::encrypt(
                            &u.uri, entry_key, org_id,
                        )?,
                        match_type,
                    })
                })
                .collect::<anyhow::Result<_>>()?;
            let totp = enc(totp)?;
            let fido2_credentials = fido2_credentials
                .iter()
                .map(|c| {
                    Ok(rbw::db::Fido2Credential {
                        credential_id: enc(&c.credential_id)?,
                        key_type: enc(&c.key_type)?,
                        key_algorithm: enc(&c.key_algorithm)?,
                        key_curve: enc(&c.key_curve)?,
                        key_value: enc(&c.key_value)?,
                        rp_id: enc(&c.rp_id)?,
                        user_handle: enc(&c.user_handle)?,
                        user_name: enc(&c.user_name)?,
                        counter: enc(&c.counter)?,
                        rp_name: enc(&c.rp_name)?,
                        user_display_name: enc(&c.user_display_name)?,
                        discoverable: enc(&c.discoverable)?,
                        // never encrypted to begin with
                        creation_date: c.creation_date.clone(),
                    })
                })
                .collect::<anyhow::Result<_>>()?;
            rbw::db::EntryData::Login {
                username,
                password,
                uris,
                totp,
                fido2_credentials,
            }
        }
        EditableData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => {
            let enc = |s: &Option<String>| {
                s.as_deref()
                    .filter(|v| !v.is_empty())
                    .map(|v| crate::actions::encrypt(v, entry_key, org_id))
                    .transpose()
            };
            rbw::db::EntryData::Card {
                cardholder_name: enc(cardholder_name)?,
                number: enc(number)?,
                brand: enc(brand)?,
                exp_month: enc(exp_month)?,
                exp_year: enc(exp_year)?,
                code: enc(code)?,
            }
        }
        EditableData::Identity {
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
        } => {
            let enc = |s: &Option<String>| {
                s.as_deref()
                    .filter(|v| !v.is_empty())
                    .map(|v| crate::actions::encrypt(v, entry_key, org_id))
                    .transpose()
            };
            rbw::db::EntryData::Identity {
                title: enc(title)?,
                first_name: enc(first_name)?,
                middle_name: enc(middle_name)?,
                last_name: enc(last_name)?,
                address1: enc(address1)?,
                address2: enc(address2)?,
                address3: enc(address3)?,
                city: enc(city)?,
                state: enc(state)?,
                postal_code: enc(postal_code)?,
                country: enc(country)?,
                phone: enc(phone)?,
                email: enc(email)?,
                ssn: enc(ssn)?,
                license_number: enc(license_number)?,
                passport_number: enc(passport_number)?,
                username: enc(username)?,
            }
        }
        EditableData::SecureNote => rbw::db::EntryData::SecureNote,
        EditableData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => {
            let enc = |s: &Option<String>| {
                s.as_deref()
                    .filter(|v| !v.is_empty())
                    .map(|v| crate::actions::encrypt(v, entry_key, org_id))
                    .transpose()
            };
            rbw::db::EntryData::SshKey {
                private_key: enc(private_key)?,
                public_key: enc(public_key)?,
                fingerprint: enc(fingerprint)?,
            }
        }
    };

    let fields = editable
        .fields
        .iter()
        .map(|f| {
            let ty = f.ty.as_deref().map(parse_field_type).transpose()?;
            let name = f
                .name
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|n| crate::actions::encrypt(n, entry_key, org_id))
                .transpose()?;
            let value = f
                .value
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|v| crate::actions::encrypt(v, entry_key, org_id))
                .transpose()?;
            Ok(rbw::db::Field {
                ty,
                name,
                value,
                linked_id: None,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let notes = editable
        .notes
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string);

    Ok((data, fields, notes))
}

// `--from-file`'s counterpart to `editable_to_encrypted`: same shape, same
// empty-string-means-unset filtering, but a plain field copy instead of
// `crate::actions::encrypt(...)` -- there's nothing to encrypt against,
// and nothing here can fail the way encryption can, so this is infallible.
pub(super) fn editable_to_decrypted(
    editable: &EditableCipher,
) -> (DecryptedData, Vec<DecryptedField>, Option<String>) {
    let unset_if_empty =
        |s: &Option<String>| s.clone().filter(|v| !v.is_empty());

    let data = match &editable.data {
        EditableData::Login {
            username,
            password,
            uris,
            totp,
            fido2_credentials,
        } => DecryptedData::Login {
            username: unset_if_empty(username),
            password: unset_if_empty(password),
            uris: (!uris.is_empty()).then(|| {
                uris.iter()
                    .filter(|u| !u.uri.is_empty())
                    .map(|u| DecryptedUri {
                        uri: u.uri.clone(),
                        match_type: u
                            .match_type
                            .as_deref()
                            .and_then(|mt| parse_uri_match_type(mt).ok()),
                    })
                    .collect()
            }),
            totp: unset_if_empty(totp),
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
        EditableData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: unset_if_empty(cardholder_name),
            number: unset_if_empty(number),
            brand: unset_if_empty(brand),
            exp_month: unset_if_empty(exp_month),
            exp_year: unset_if_empty(exp_year),
            code: unset_if_empty(code),
        },
        EditableData::Identity {
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
            title: unset_if_empty(title),
            first_name: unset_if_empty(first_name),
            middle_name: unset_if_empty(middle_name),
            last_name: unset_if_empty(last_name),
            address1: unset_if_empty(address1),
            address2: unset_if_empty(address2),
            address3: unset_if_empty(address3),
            city: unset_if_empty(city),
            state: unset_if_empty(state),
            postal_code: unset_if_empty(postal_code),
            country: unset_if_empty(country),
            phone: unset_if_empty(phone),
            email: unset_if_empty(email),
            ssn: unset_if_empty(ssn),
            license_number: unset_if_empty(license_number),
            passport_number: unset_if_empty(passport_number),
            username: unset_if_empty(username),
        },
        EditableData::SecureNote => DecryptedData::SecureNote,
        EditableData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } => DecryptedData::SshKey {
            private_key: unset_if_empty(private_key),
            public_key: unset_if_empty(public_key),
            fingerprint: unset_if_empty(fingerprint),
        },
    };

    let fields = editable
        .fields
        .iter()
        .map(|f| DecryptedField {
            name: unset_if_empty(&f.name),
            value: unset_if_empty(&f.value),
            ty: f.ty.as_deref().and_then(|ty| parse_field_type(ty).ok()),
            linked_id: None,
        })
        .collect();

    let notes = unset_if_empty(&editable.notes);

    (data, fields, notes)
}

// ===========================================================================
// TUI support
//
// Thin orchestration helpers used by the interactive `rbw tui` front-end. They
// deliberately live here so the encryption / API / save / sync logic stays in
// one place (shared with `edit`, `add`, and `remove`) instead of being
// re-implemented in the UI layer.
// ===========================================================================
