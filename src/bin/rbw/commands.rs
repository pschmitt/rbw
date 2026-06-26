use std::ffi::OsString;
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{fmt::Write as _, io::Write as _, os::unix::ffi::OsStrExt as _};

use anyhow::Context as _;
use is_terminal::IsTerminal as _;

// The default number of seconds the generated TOTP
// code lasts for before a new one must be generated
const TOTP_DEFAULT_STEP: u64 = 30;

const MISSING_CONFIG_HELP: &str =
    "Before using rbw, you must configure the email address you would like to \
    use to log in to the server by running:\n\n    \
        rbw config set email <email>\n\n\
    Additionally, if you are using a self-hosted installation, you should \
    run:\n\n    \
        rbw config set base_url <url>\n\n\
    and, if your server has a non-default identity url:\n\n    \
        rbw config set identity_url <url>\n";

#[derive(Debug, Clone)]
pub enum Needle {
    Name(String),
    Uri(url::Url),
    Uuid(uuid::Uuid, String),
}

impl std::fmt::Display for Needle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match &self {
            Self::Name(name) => name.clone(),
            Self::Uri(uri) => uri.to_string(),
            Self::Uuid(_, s) => s.clone(),
        };
        write!(f, "{value}")
    }
}

#[allow(clippy::unnecessary_wraps)]
pub fn parse_needle(arg: &str) -> Result<Needle, std::convert::Infallible> {
    if let Ok(uuid) = uuid::Uuid::parse_str(arg) {
        return Ok(Needle::Uuid(uuid, arg.to_string()));
    }
    if let Ok(url) = url::Url::parse(arg) {
        if url.is_special() {
            return Ok(Needle::Uri(url));
        }
    }

    Ok(Needle::Name(arg.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Field {
    Notes,
    Username,
    Password,
    Totp,
    Uris,
    IdentityName,
    City,
    State,
    PostalCode,
    Country,
    Phone,
    Ssn,
    License,
    Passport,
    CardNumber,
    Expiration,
    ExpMonth,
    ExpYear,
    Cvv,
    Cardholder,
    Brand,
    Name,
    Email,
    Address,
    Address1,
    Address2,
    Address3,
    Fingerprint,
    PublicKey,
    PrivateKey,
    Title,
    FirstName,
    MiddleName,
    LastName,
}

impl std::str::FromStr for Field {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "notes" | "note" => Self::Notes,
            "username" | "user" => Self::Username,
            "password" => Self::Password,
            "totp" | "code" => Self::Totp,
            "uris" | "urls" | "sites" => Self::Uris,
            "identityname" => Self::IdentityName,
            "city" => Self::City,
            "state" => Self::State,
            "postcode" | "zipcode" | "zip" => Self::PostalCode,
            "country" => Self::Country,
            "phone" => Self::Phone,
            "ssn" => Self::Ssn,
            "license" => Self::License,
            "passport" => Self::Passport,
            "number" | "card" => Self::CardNumber,
            "exp" => Self::Expiration,
            "exp_month" | "month" => Self::ExpMonth,
            "exp_year" | "year" => Self::ExpYear,
            // the word "code" got preceeded by Totp
            "cvv" => Self::Cvv,
            "cardholder" | "cardholder_name" => Self::Cardholder,
            "brand" | "type" => Self::Brand,
            "name" => Self::Name,
            "email" => Self::Email,
            "address1" => Self::Address1,
            "address2" => Self::Address2,
            "address3" => Self::Address3,
            "address" => Self::Address,
            "fingerprint" => Self::Fingerprint,
            "public_key" => Self::PublicKey,
            "private_key" => Self::PrivateKey,
            "title" => Self::Title,
            "first_name" => Self::FirstName,
            "middle_name" => Self::MiddleName,
            "last_name" => Self::LastName,
            _ => anyhow::bail!("unknown field {s}"),
        })
    }
}

impl Field {
    fn as_str(&self) -> &str {
        match self {
            Self::Notes => "notes",
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Uris => "uris",
            Self::IdentityName => "identityname",
            Self::City => "city",
            Self::State => "state",
            Self::PostalCode => "postcode",
            Self::Country => "country",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::License => "license",
            Self::Passport => "passport",
            Self::CardNumber => "number",
            Self::Expiration => "exp",
            Self::ExpMonth => "exp_month",
            Self::ExpYear => "exp_year",
            Self::Cvv => "cvv",
            Self::Cardholder => "cardholder",
            Self::Brand => "brand",
            Self::Name => "name",
            Self::Email => "email",
            Self::Address1 => "address1",
            Self::Address2 => "address2",
            Self::Address3 => "address3",
            Self::Address => "address",
            Self::Fingerprint => "fingerprint",
            Self::PublicKey => "public_key",
            Self::PrivateKey => "private_key",
            Self::Title => "title",
            Self::FirstName => "first_name",
            Self::MiddleName => "middle_name",
            Self::LastName => "last_name",
        }
    }
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, serde::Serialize)]
struct DecryptedListCipher {
    id: String,
    name: Option<String>,
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    folder: Option<String>,
    uris: Option<Vec<String>>,
    #[serde(rename = "type")]
    entry_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    collection_ids: Option<Vec<String>>,
    #[serde(flatten)]
    attachment_metadata: AttachmentMetadata,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedSearchCipher {
    id: String,
    #[serde(rename = "type")]
    entry_type: String,
    folder: Option<String>,
    name: String,
    user: Option<String>,
    uris: Vec<(String, Option<rbw::api::UriMatchType>)>,
    fields: Vec<String>,
    notes: Option<String>,
    attachment_count: usize,
    #[serde(skip)]
    sensitive_fields: Vec<String>,
    #[serde(skip)]
    password: Option<String>,
}

impl DecryptedSearchCipher {
    fn display_name(&self) -> String {
        self.user.as_ref().map_or_else(
            || self.name.clone(),
            |user| format!("{user}@{}", self.name),
        )
    }

    fn matches(
        &self,
        needle: &Needle,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
        strict_username: bool,
        strict_folder: bool,
        exact: bool,
    ) -> bool {
        let match_str = match (ignore_case, exact) {
            (true, true) => |field: &str, search_term: &str| {
                field.to_lowercase() == search_term.to_lowercase()
            },
            (true, false) => |field: &str, search_term: &str| {
                field.to_lowercase().contains(&search_term.to_lowercase())
            },
            (false, true) => {
                |field: &str, search_term: &str| field == search_term
            }
            (false, false) => {
                |field: &str, search_term: &str| field.contains(search_term)
            }
        };

        match (self.folder.as_deref(), folder) {
            (Some(folder), Some(given_folder)) => {
                if !match_str(folder, given_folder) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_folder {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match (&self.user, username) {
            (Some(username), Some(given_username)) => {
                if !match_str(username, given_username) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_username {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match needle {
            Needle::Uuid(uuid, s) => {
                if uuid::Uuid::parse_str(&self.id) != Ok(*uuid)
                    && !match_str(&self.name, s)
                {
                    return false;
                }
            }
            Needle::Name(name) => {
                let name_lower = name.to_lowercase();
                // For partial (non-exact) matching, always use
                // case-insensitive contains so "micro" finds "Microsoft".
                // For exact matching, honour the ignore_case flag via
                // match_str.
                let matches_name = if exact {
                    match_str(&self.name, name)
                } else {
                    self.name.to_lowercase().contains(&name_lower)
                };
                let matches_id =
                    self.id.to_lowercase().contains(&name_lower);
                let matches_sensitive = self
                    .sensitive_fields
                    .iter()
                    .any(|f| f.to_lowercase().contains(&name_lower));
                if !matches_name && !matches_id && !matches_sensitive {
                    return false;
                }
            }
            Needle::Uri(given_uri) => {
                if self.uris.iter().all(|(uri, match_type)| {
                    !matches_url(uri, *match_type, given_uri)
                }) {
                    return false;
                }
            }
        }

        true
    }

    fn search_match(
        &self,
        term: &str,
        folder: Option<&str>,
        with_attachments: bool,
    ) -> bool {
        if let Some(folder) = folder {
            if self.folder.as_deref() != Some(folder) {
                return false;
            }
        }

        if with_attachments && self.attachment_count == 0 {
            return false;
        }

        let mut fields = vec![self.name.clone()];
        if let Some(notes) = &self.notes {
            fields.push(notes.clone());
        }
        if let Some(user) = &self.user {
            fields.push(user.clone());
        }
        fields.extend(self.uris.iter().map(|(uri, _)| uri).cloned());
        fields.extend(self.fields.iter().cloned());
        fields.extend(self.sensitive_fields.iter().cloned());

        for field in fields {
            if field.to_lowercase().contains(&term.to_lowercase()) {
                return true;
            }
        }

        false
    }
}

impl From<DecryptedSearchCipher> for DecryptedListCipher {
    fn from(value: DecryptedSearchCipher) -> Self {
        let attachment_metadata =
            AttachmentMetadata::new(&value.id, value.attachment_count);
        Self {
            id: value.id,
            entry_type: Some(value.entry_type),
            name: Some(value.name),
            user: value.user,
            password: value.password,
            folder: value.folder,
            uris: Some(value.uris.into_iter().map(|(s, _)| s).collect()),
            collection_ids: None,
            attachment_metadata,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedAttachment {
    id: String,
    file_name: Option<String>,
    size: Option<String>,
    size_name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct AttachmentMetadata {
    #[serde(skip_serializing_if = "is_zero")]
    attachment_count: usize,
}

impl AttachmentMetadata {
    fn new(_entry_id: &str, attachment_count: usize) -> Self {
        Self { attachment_count }
    }

    fn has_attachments(&self) -> bool {
        self.attachment_count > 0
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedCipher {
    id: String,
    folder: Option<String>,
    name: String,
    data: DecryptedData,
    fields: Vec<DecryptedField>,
    notes: Option<String>,
    history: Vec<DecryptedHistoryEntry>,
    attachments: Vec<DecryptedAttachment>,
    #[serde(flatten)]
    attachment_metadata: AttachmentMetadata,
}

impl DecryptedCipher {
    fn display_short(&self, desc: &str, clipboard: bool) -> bool {
        match &self.data {
            DecryptedData::Login { password, .. } => {
                password.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no password");
                        false
                    },
                    |password| val_display_or_store(clipboard, password),
                )
            }
            DecryptedData::Card { number, .. } => {
                number.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no card number");
                        false
                    },
                    |number| val_display_or_store(clipboard, number),
                )
            }
            DecryptedData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                let names: Vec<_> =
                    [title, first_name, middle_name, last_name]
                        .iter()
                        .copied()
                        .flatten()
                        .cloned()
                        .collect();
                if names.is_empty() {
                    eprintln!("entry for '{desc}' had no name");
                    false
                } else {
                    val_display_or_store(clipboard, &names.join(" "))
                }
            }
            DecryptedData::SecureNote => self.notes.as_ref().map_or_else(
                || {
                    eprintln!("entry for '{desc}' had no notes");
                    false
                },
                |notes| val_display_or_store(clipboard, notes),
            ),
            DecryptedData::SshKey { public_key, .. } => {
                public_key.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no public key");
                        false
                    },
                    |public_key| val_display_or_store(clipboard, public_key),
                )
            }
        }
    }

    fn display_field(&self, desc: &str, field: &str, clipboard: bool) {
        let field = field.to_lowercase();
        let field = field.as_str();
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => match field.parse() {
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = &username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Totp) => {
                    if let Some(totp) = totp {
                        match generate_totp(totp) {
                            Ok(code) => {
                                val_display_or_store(clipboard, &code);
                            }
                            Err(e) => {
                                eprintln!("{e}");
                            }
                        }
                    }
                }
                Ok(Field::Uris) => {
                    if let Some(uris) = uris {
                        let uri_strs: Vec<_> =
                            uris.iter().map(|uri| uri.uri.clone()).collect();
                        val_display_or_store(clipboard, &uri_strs.join("\n"));
                    }
                }
                Ok(Field::Password) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => match field.parse() {
                Ok(Field::CardNumber) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Expiration) => {
                    if let (Some(month), Some(year)) = (exp_month, exp_year) {
                        val_display_or_store(
                            clipboard,
                            &format!("{month}/{year}"),
                        );
                    }
                }
                Ok(Field::ExpMonth) => {
                    if let Some(exp_month) = exp_month {
                        val_display_or_store(clipboard, exp_month);
                    }
                }
                Ok(Field::ExpYear) => {
                    if let Some(exp_year) = exp_year {
                        val_display_or_store(clipboard, exp_year);
                    }
                }
                Ok(Field::Cvv) => {
                    if let Some(code) = code {
                        val_display_or_store(clipboard, code);
                    }
                }
                Ok(Field::Name | Field::Cardholder) => {
                    if let Some(cardholder_name) = cardholder_name {
                        val_display_or_store(clipboard, cardholder_name);
                    }
                }
                Ok(Field::Brand) => {
                    if let Some(brand) = brand {
                        val_display_or_store(clipboard, brand);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::Identity {
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
                ..
            } => match field.parse() {
                Ok(Field::Name) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Email) => {
                    if let Some(email) = email {
                        val_display_or_store(clipboard, email);
                    }
                }
                Ok(Field::Address) => {
                    let mut strs = vec![];
                    if let Some(address1) = address1 {
                        strs.push(address1.clone());
                    }
                    if let Some(address2) = address2 {
                        strs.push(address2.clone());
                    }
                    if let Some(address3) = address3 {
                        strs.push(address3.clone());
                    }
                    if !strs.is_empty() {
                        val_display_or_store(clipboard, &strs.join("\n"));
                    }
                }
                Ok(Field::City) => {
                    if let Some(city) = city {
                        val_display_or_store(clipboard, city);
                    }
                }
                Ok(Field::State) => {
                    if let Some(state) = state {
                        val_display_or_store(clipboard, state);
                    }
                }
                Ok(Field::PostalCode) => {
                    if let Some(postal_code) = postal_code {
                        val_display_or_store(clipboard, postal_code);
                    }
                }
                Ok(Field::Country) => {
                    if let Some(country) = country {
                        val_display_or_store(clipboard, country);
                    }
                }
                Ok(Field::Phone) => {
                    if let Some(phone) = phone {
                        val_display_or_store(clipboard, phone);
                    }
                }
                Ok(Field::Ssn) => {
                    if let Some(ssn) = ssn {
                        val_display_or_store(clipboard, ssn);
                    }
                }
                Ok(Field::License) => {
                    if let Some(license_number) = license_number {
                        val_display_or_store(clipboard, license_number);
                    }
                }
                Ok(Field::Passport) => {
                    if let Some(passport_number) = passport_number {
                        val_display_or_store(clipboard, passport_number);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SecureNote => match field.parse() {
                Ok(Field::Notes) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SshKey {
                fingerprint,
                private_key,
                ..
            } => match field.parse() {
                Ok(Field::Fingerprint) => {
                    if let Some(fingerprint) = fingerprint {
                        val_display_or_store(clipboard, fingerprint);
                    }
                }
                Ok(Field::PublicKey) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::PrivateKey) => {
                    if let Some(private_key) = private_key {
                        val_display_or_store(clipboard, private_key);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
        }
    }

    fn display_long(&self, desc: &str, clipboard: bool) {
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => {
                let mut displayed = self.display_short(desc, clipboard);
                displayed |=
                    display_field("Username", username.as_deref(), clipboard);
                displayed |=
                    display_field("TOTP Secret", totp.as_deref(), clipboard);

                if let Some(uris) = uris {
                    for uri in uris {
                        displayed |=
                            display_field("URI", Some(&uri.uri), clipboard);
                        let match_type =
                            uri.match_type.map(|ty| format!("{ty}"));
                        displayed |= display_field(
                            "Match type",
                            match_type.as_deref(),
                            clipboard,
                        );
                    }
                }

                for field in &self.fields {
                    displayed |= display_field(
                        field.name.as_deref().unwrap_or("(null)"),
                        Some(field.value.as_deref().unwrap_or("")),
                        clipboard,
                    );
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                let mut displayed = false;

                displayed |= self.display_short(desc, clipboard);
                if let (Some(exp_month), Some(exp_year)) =
                    (exp_month, exp_year)
                {
                    println!(
                        "{}: {exp_month}/{exp_year}",
                        format_label("Expiration")
                    );
                    displayed = true;
                }
                displayed |= display_field("CVV", code.as_deref(), clipboard);
                displayed |= display_field(
                    "Name",
                    cardholder_name.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Brand", brand.as_deref(), clipboard);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::Identity {
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
                ..
            } => {
                let mut displayed = self.display_short(desc, clipboard);

                displayed |=
                    display_field("Address", address1.as_deref(), clipboard);
                displayed |=
                    display_field("Address", address2.as_deref(), clipboard);
                displayed |=
                    display_field("Address", address3.as_deref(), clipboard);
                displayed |=
                    display_field("City", city.as_deref(), clipboard);
                displayed |=
                    display_field("State", state.as_deref(), clipboard);
                displayed |= display_field(
                    "Postcode",
                    postal_code.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Country", country.as_deref(), clipboard);
                displayed |=
                    display_field("Phone", phone.as_deref(), clipboard);
                displayed |=
                    display_field("Email", email.as_deref(), clipboard);
                displayed |= display_field("SSN", ssn.as_deref(), clipboard);
                displayed |= display_field(
                    "License",
                    license_number.as_deref(),
                    clipboard,
                );
                displayed |= display_field(
                    "Passport",
                    passport_number.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Username", username.as_deref(), clipboard);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::SecureNote => {
                self.display_short(desc, clipboard);
            }
            DecryptedData::SshKey { fingerprint, .. } => {
                let mut displayed = self.display_short(desc, clipboard);
                displayed |= display_field(
                    "Fingerprint",
                    fingerprint.as_deref(),
                    clipboard,
                );

                for field in &self.fields {
                    displayed |= display_field(
                        field.name.as_deref().unwrap_or("(null)"),
                        Some(field.value.as_deref().unwrap_or("")),
                        clipboard,
                    );
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
        }
    }

    /// This implementation mirror the `fn display_fied` method on which field to list
    fn display_fields_list(&self) {
        match &self.data {
            DecryptedData::Login {
                username,
                password,
                totp,
                uris,
                ..
            } => {
                if username.is_some() {
                    println!("{}", Field::Username);
                }
                if totp.is_some() {
                    println!("{}", Field::Totp);
                }
                if uris.is_some() {
                    println!("{}", Field::Uris);
                }
                if password.is_some() {
                    println!("{}", Field::Password);
                }
            }
            DecryptedData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                if number.is_some() {
                    println!("{}", Field::CardNumber);
                }
                if exp_month.is_some() {
                    println!("{}", Field::ExpMonth);
                }
                if exp_year.is_some() {
                    println!("{}", Field::ExpYear);
                }
                if code.is_some() {
                    println!("{}", Field::Cvv);
                }
                if cardholder_name.is_some() {
                    println!("{}", Field::Cardholder);
                }
                if brand.is_some() {
                    println!("{}", Field::Brand);
                }
            }

            DecryptedData::Identity {
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
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                if [title, first_name, middle_name, last_name]
                    .iter()
                    .any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("name");
                }
                if email.is_some() {
                    println!("{}", Field::Email);
                }
                if [address1, address2, address3].iter().any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("address");
                }
                if city.is_some() {
                    println!("{}", Field::City);
                }
                if state.is_some() {
                    println!("{}", Field::State);
                }
                if postal_code.is_some() {
                    println!("{}", Field::PostalCode);
                }
                if country.is_some() {
                    println!("{}", Field::Country);
                }
                if phone.is_some() {
                    println!("{}", Field::Phone);
                }
                if ssn.is_some() {
                    println!("{}", Field::Ssn);
                }
                if license_number.is_some() {
                    println!("{}", Field::License);
                }
                if passport_number.is_some() {
                    println!("{}", Field::Passport);
                }
                if username.is_some() {
                    println!("{}", Field::Username);
                }
            }

            DecryptedData::SecureNote => (), // handled at the end
            DecryptedData::SshKey {
                fingerprint,
                public_key,
                ..
            } => {
                if fingerprint.is_some() {
                    println!("{}", Field::Fingerprint);
                }
                if public_key.is_some() {
                    println!("{}", Field::PublicKey);
                }
            }
        }

        if self.notes.is_some() {
            println!("{}", Field::Notes);
        }
        for f in &self.fields {
            if let Some(name) = &f.name {
                println!("{name}");
            }
        }
    }

    fn display_structured(
        &self,
        desc: &str,
        output: OutputMode,
    ) -> anyhow::Result<()> {
        write_serialized_pretty(
            &self,
            output,
            format!("failed to write entry '{desc}' to stdout"),
        )
    }

    fn display_show(&self) {
        let c = stdout_supports_color();
        let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
        let dim = |s: &str| style::dim(s, c);
        let secret = |s: &str| style::secret(s, c);
        let section = |s: &str| style::section(s, c);

        // Header fields: Name, UID, Type, Folder
        println!("{} {}", lbl("Name"), style::name(&self.name, c));
        println!("{} {}", lbl("UID"), style::uid(&self.id, c));
        let type_name = match &self.data {
            DecryptedData::Login { .. } => "login",
            DecryptedData::Card { .. } => "card",
            DecryptedData::Identity { .. } => "identity",
            DecryptedData::SecureNote => "secure_note",
            DecryptedData::SshKey { .. } => "ssh_key",
        };
        println!("{} {}", lbl("Type"), style::entry_type(type_name, c));
        if let Some(folder) = &self.folder {
            println!("{} {}", lbl("Folder"), style::folder(folder, c));
        }

        // Type-specific fields
        match &self.data {
            DecryptedData::Login {
                username,
                password,
                totp,
                uris,
            } => {
                if let Some(u) = username {
                    println!("{} {}", lbl("Username"), style::user(u, c));
                }
                if let Some(p) = password {
                    println!("{} {}", lbl("Password"), secret(p));
                }
                if let Some(t) = totp {
                    println!("{} {}", lbl("TOTP"), dim(t));
                }
                if let Some(uris) = uris {
                    for uri_entry in uris {
                        print!("{} {}", lbl("URI"), style::uri(&uri_entry.uri, c));
                        if let Some(mt) = uri_entry.match_type {
                            print!("  {}", dim(&format!("[{mt}]")));
                        }
                        println!();
                    }
                }
            }
            DecryptedData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => {
                if let Some(n) = number {
                    println!("{} {}", lbl("Number"), secret(n));
                }
                if let (Some(m), Some(y)) = (exp_month, exp_year) {
                    println!("{} {m}/{y}", lbl("Expires"));
                }
                if let Some(cv) = code {
                    println!("{} {}", lbl("CVV"), secret(cv));
                }
                if let Some(n) = cardholder_name {
                    println!("{} {n}", lbl("Name"));
                }
                if let Some(b) = brand {
                    println!("{} {b}", lbl("Brand"));
                }
            }
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
            } => {
                let full_name = [
                    title.as_deref(),
                    first_name.as_deref(),
                    middle_name.as_deref(),
                    last_name.as_deref(),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
                if !full_name.is_empty() {
                    println!("{} {full_name}", lbl("Name"));
                }
                for addr in [address1, address2, address3]
                    .into_iter()
                    .flatten()
                {
                    println!("{} {addr}", lbl("Address"));
                }
                if let Some(v) = city {
                    println!("{} {v}", lbl("City"));
                }
                if let Some(v) = state {
                    println!("{} {v}", lbl("State"));
                }
                if let Some(v) = postal_code {
                    println!("{} {v}", lbl("Postcode"));
                }
                if let Some(v) = country {
                    println!("{} {v}", lbl("Country"));
                }
                if let Some(v) = phone {
                    println!("{} {v}", lbl("Phone"));
                }
                if let Some(v) = email {
                    println!("{} {v}", lbl("Email"));
                }
                if let Some(v) = username {
                    println!("{} {}", lbl("Username"), style::user(v, c));
                }
                if let Some(v) = ssn {
                    println!("{} {}", lbl("SSN"), secret(v));
                }
                if let Some(v) = license_number {
                    println!("{} {v}", lbl("License"));
                }
                if let Some(v) = passport_number {
                    println!("{} {v}", lbl("Passport"));
                }
            }
            DecryptedData::SecureNote => {}
            DecryptedData::SshKey {
                public_key,
                private_key,
                fingerprint,
            } => {
                if let Some(fp) = fingerprint {
                    println!("{} {}", lbl("Fingerprint"), dim(fp));
                }
                if let Some(pk) = public_key {
                    println!("{} {pk}", lbl("Public key"));
                }
                if let Some(pk) = private_key {
                    println!("{} {}", lbl("Private key"), secret(pk));
                }
            }
        }

        // Custom fields
        if !self.fields.is_empty() {
            println!("\n{}", section("FIELDS"));
            for field in &self.fields {
                let name = field.name.as_deref().unwrap_or("(unnamed)");
                let value = field.value.as_deref().unwrap_or("");
                let is_hidden = matches!(
                    field.ty,
                    Some(rbw::api::FieldType::Hidden)
                );
                if is_hidden {
                    println!("{} {}", lbl(name), secret(value));
                } else {
                    println!("{} {value}", lbl(name));
                }
            }
        }

        // Notes
        if let Some(notes) = &self.notes {
            if !notes.is_empty() {
                println!("\n{}", section("NOTES"));
                println!("{notes}");
            }
        }

        // Attachments
        if !self.attachments.is_empty() {
            println!("\n{}", section("ATTACHMENTS"));
            for att in &self.attachments {
                let fname = att
                    .file_name
                    .as_deref()
                    .unwrap_or(&att.id);
                let size = att
                    .size_name
                    .as_deref()
                    .or(att.size.as_deref())
                    .unwrap_or("");
                println!("\u{1f4ce} {fname:<30}  {}", style::size(size, c));
            }
        }
    }
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn stdout_supports_color() -> bool {
    stdout_is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn stdout_is_terminal() -> bool {
    std::io::stdout().is_terminal()
}

// Central style palette.  Every coloured output in rbw goes through
// these functions so that each semantic type always looks the same
// regardless of which command produced it.
mod style {
    fn paint(text: &str, code: &str, color: bool) -> String {
        if color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    // Semantic roles → ANSI style
    // uid     dim cyan       — long, secondary, but distinctive
    pub fn uid(s: &str, c: bool) -> String { paint(s, "2;36", c) }
    // name    bold           — most prominent field
    pub fn name(s: &str, c: bool) -> String { paint(s, "1", c) }
    // user    green          — "who" (accounts)
    pub fn user(s: &str, c: bool) -> String { paint(s, "32", c) }
    // secret  yellow         — sensitive / caution
    pub fn secret(s: &str, c: bool) -> String { paint(s, "33", c) }
    // folder  blue           — organisation / location
    pub fn folder(s: &str, c: bool) -> String { paint(s, "34", c) }
    // uri     cyan           — links / references
    pub fn uri(s: &str, c: bool) -> String { paint(s, "36", c) }
    // entry_type  magenta    — category label
    pub fn entry_type(s: &str, c: bool) -> String { paint(s, "35", c) }
    // label   bold cyan      — field-name label in aligned display
    pub fn label(s: &str, c: bool) -> String { paint(s, "1;36", c) }
    // section bold white     — section headers (FIELDS / NOTES / …)
    pub fn section(s: &str, c: bool) -> String { paint(s, "1", c) }
    // dim     dim            — secondary / decorative text
    pub fn dim(s: &str, c: bool) -> String { paint(s, "2", c) }
    // empty   dim italic     — "none" / "N/A" placeholder values
    pub fn empty(s: &str, c: bool) -> String { paint(s, "2;3", c) }
    // success bold green     — action verbs ("Created", "Attached", …)
    pub fn success(s: &str, c: bool) -> String { paint(s, "1;32", c) }
    // old_val dim red        — value about to be replaced
    pub fn old_val(s: &str, c: bool) -> String { paint(s, "2;31", c) }
    // new_val green          — replacement / updated value
    pub fn new_val(s: &str, c: bool) -> String { paint(s, "32", c) }
    // warning bold yellow    — warnings / notices
    pub fn warning(s: &str, c: bool) -> String { paint(s, "1;33", c) }
    // size    dim            — file sizes (same weight as dim)
    pub fn size(s: &str, c: bool) -> String { paint(s, "2", c) }
    // collections dim        — metadata that rarely matters
    pub fn collections(s: &str, c: bool) -> String { paint(s, "2", c) }
    // header  bold white     — table column headers
    pub fn header(s: &str, c: bool) -> String { paint(s, "1;37", c) }
    // raw escape for the rare case where a specific code is needed
    pub fn paint_raw(s: &str, code: &str, c: bool) -> String { paint(s, code, c) }
}

fn write_yaml_pretty<T>(
    value: &T,
    context: impl Into<String>,
) -> anyhow::Result<()>
where
    T: serde::Serialize,
{
    let context = context.into();
    serde_yaml::to_writer(std::io::stdout(), value).context(context)?;
    println!();

    Ok(())
}

fn format_label(name: &str) -> String {
    style::label(name, stdout_supports_color())
}

fn write_json_pretty<T>(
    value: &T,
    context: impl Into<String>,
) -> anyhow::Result<()>
where
    T: serde::Serialize,
{
    let context = context.into();
    if stdout_supports_color() {
        let value = serde_json::to_value(value).context(context.clone())?;
        let rendered = colored_json::to_colored_json_auto(&value)
            .map_err(|err| anyhow::anyhow!(err.to_string()))
            .context(context)?;
        println!("{rendered}");
    } else {
        serde_json::to_writer_pretty(std::io::stdout(), value)
            .context(context)?;
        println!();
    }

    Ok(())
}

fn attachment_rows(
    attachments: &[DecryptedAttachment],
    color: bool,
) -> Vec<String> {
    attachments
        .iter()
        .map(|attachment| {
            format!(
                "{}\t{}\t{}",
                style::uid(&attachment.id, color),
                style::name(
                    &attachment.file_name.clone().unwrap_or_default(),
                    color,
                ),
                style::size(
                    &attachment
                        .size_name
                        .clone()
                        .or_else(|| attachment.size.clone())
                        .unwrap_or_default(),
                    color,
                )
            )
        })
        .collect()
}

fn attachments_cell(attachment_count: usize) -> String {
    if attachment_count == 0 {
        "none".to_string()
    } else if attachment_count == 1 {
        "📎".to_string()
    } else {
        format!("📎 x{attachment_count}")
    }
}

fn output_is_structured(output: OutputMode) -> bool {
    matches!(output, OutputMode::Json | OutputMode::Yaml)
}

fn write_serialized_pretty<T>(
    value: &T,
    output: OutputMode,
    context: impl Into<String>,
) -> anyhow::Result<()>
where
    T: serde::Serialize,
{
    match output {
        OutputMode::Json => write_json_pretty(value, context),
        OutputMode::Yaml => write_yaml_pretty(value, context),
        OutputMode::Default | OutputMode::Name => {
            Err(anyhow::anyhow!("unsupported serialized output mode"))
        }
    }
}

fn format_ambiguous_entry(entry: &DecryptedSearchCipher) -> String {
    let c = stdout_supports_color();
    let mut details = vec![format!("uid: {}", style::uid(&entry.id, c))];
    if let Some(user) = &entry.user {
        details.push(format!("username: {}", style::user(user, c)));
    }
    if let Some(folder) = &entry.folder {
        details.push(format!("folder: {}", style::folder(folder, c)));
    }
    if entry.attachment_count > 0 {
        details.push(format!("attachments: {}", entry.attachment_count));
    }

    format!("  - {} ({})", style::name(&entry.name, c), details.join(" | "))
}

fn colorize_table_cell(
    text: &str,
    col_style: TableColumnStyle,
    color: bool,
) -> String {
    if text.is_empty() {
        return String::new();
    }

    if (col_style == TableColumnStyle::User && text == "N/A")
        || (col_style == TableColumnStyle::Attachments && text == "none")
    {
        return style::empty(text, color);
    }

    match col_style {
        TableColumnStyle::Id => style::uid(text, color),
        TableColumnStyle::Name => style::name(text, color),
        TableColumnStyle::User => style::user(text, color),
        TableColumnStyle::Password => style::secret(text, color),
        TableColumnStyle::Folder => style::folder(text, color),
        TableColumnStyle::EntryType => style::entry_type(text, color),
        TableColumnStyle::Collections => style::collections(text, color),
        TableColumnStyle::Attachments => style::uri(text, color),
        TableColumnStyle::Size => style::size(text, color),
        TableColumnStyle::Default => text.to_string(),
    }
}

fn table_cell_width(text: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(text)
}

fn compute_table_widths(
    columns: &[TableColumn<'_>],
    rows: &[Vec<String>],
) -> Vec<usize> {
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let header_width =
                table_cell_width(&column.header.to_uppercase());
            let row_width = rows
                .iter()
                .filter_map(|row| row.get(index))
                .map(|cell| table_cell_width(cell))
                .max()
                .unwrap_or(0);
            header_width.max(row_width)
        })
        .collect()
}

fn render_table_row<F>(
    cells: &[String],
    widths: &[usize],
    mut render_cell: F,
) -> String
where
    F: FnMut(usize, &str) -> String,
{
    let last_index = cells.len().saturating_sub(1);
    let mut rendered = String::new();

    for (index, cell) in cells.iter().enumerate() {
        rendered.push_str(&render_cell(index, cell));

        if index != last_index {
            let padding =
                widths[index].saturating_sub(table_cell_width(cell));
            rendered.push_str(&" ".repeat(padding + 2));
        }
    }

    rendered
}

fn print_table(
    columns: &[TableColumn<'_>],
    rows: &[Vec<String>],
) -> anyhow::Result<()> {
    if stdout_is_terminal() {
        let widths = compute_table_widths(columns, rows);
        let header_cells = columns
            .iter()
            .map(|column| column.header.to_uppercase())
            .collect::<Vec<_>>();
        let header = render_table_row(&header_cells, &widths, |_, cell| {
            style::header(cell, stdout_supports_color())
        });
        println!("{header}");
        for row in rows {
            let rendered = render_table_row(row, &widths, |index, cell| {
                columns.get(index).map_or_else(String::new, |column| {
                    colorize_table_cell(
                        cell,
                        column.style,
                        stdout_supports_color(),
                    )
                })
            });
            println!("{rendered}");
        }
    } else {
        for row in rows {
            match writeln!(&mut std::io::stdout(), "{}", row.join("\t")) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    return Ok(());
                }
                res => res?,
            }
        }
    }

    Ok(())
}

fn available_attachments_error(
    entry_name: &str,
    attachments: &[DecryptedAttachment],
    reason: &str,
) -> anyhow::Error {
    if attachments.is_empty() {
        return anyhow::anyhow!(
            "{reason}\nNo attachments are available for '{}'.",
            entry_name
        );
    }

    let mut message = String::new();
    let _ = writeln!(&mut message, "{reason}");
    let _ =
        writeln!(&mut message, "Available attachments for '{}':", entry_name);
    for row in attachment_rows(attachments, false) {
        let _ = writeln!(&mut message, "{row}");
    }
    let _ = write!(
        &mut message,
        "Use `rbw attachment get <entry> <attachment-id-or-filename>` to download one."
    );
    anyhow::anyhow!(message)
}

fn val_display_or_store(clipboard: bool, password: &str) -> bool {
    if clipboard {
        match clipboard_store(password) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("{e}");
                false
            }
        }
    } else {
        println!("{password}");
        true
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
#[cfg_attr(test, derive(Eq, PartialEq))]
enum DecryptedData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Option<Vec<DecryptedUri>>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        public_key: Option<String>,
        fingerprint: Option<String>,
        private_key: Option<String>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedField {
    name: Option<String>,
    value: Option<String>,
    #[serde(serialize_with = "serialize_field_type", rename = "type")]
    ty: Option<rbw::api::FieldType>,
}

#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
fn serialize_field_type<S>(
    ty: &Option<rbw::api::FieldType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match ty {
        Some(ty) => {
            let s = match ty {
                rbw::api::FieldType::Text => "text",
                rbw::api::FieldType::Hidden => "hidden",
                rbw::api::FieldType::Boolean => "boolean",
                rbw::api::FieldType::Linked => "linked",
            };
            serializer.serialize_some(&Some(s))
        }
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedHistoryEntry {
    last_used_date: String,
    password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
struct DecryptedUri {
    uri: String,
    match_type: Option<rbw::api::UriMatchType>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct EditableCipher {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    folder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    data: EditableData,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fields: Vec<EditableCustomField>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum EditableData {
    Login {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        uris: Vec<EditableUri>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        totp: Option<String>,
    },
    Card {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cardholder_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brand: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exp_month: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exp_year: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    Identity {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        first_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        middle_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address1: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address2: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address3: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        city: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        postal_code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        country: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        phone: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ssn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        license_number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passport_number: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        private_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fingerprint: Option<String>,
    },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct EditableUri {
    uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    match_type: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct EditableCustomField {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    ty: Option<String>,
}

fn matches_url(
    url: &str,
    match_type: Option<rbw::api::UriMatchType>,
    given_url: &url::Url,
) -> bool {
    match match_type.unwrap_or(rbw::api::UriMatchType::Domain) {
        rbw::api::UriMatchType::Domain => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && (self_host_port == given_host_port
                            || given_host_port
                                .ends_with(&format!(".{self_host_port}")))
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
                || given_host_port.ends_with(&format!(".{url}"))
        }
        rbw::api::UriMatchType::Host => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && self_host_port == given_host_port
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
        }
        rbw::api::UriMatchType::StartsWith => {
            given_url.to_string().starts_with(url)
        }
        rbw::api::UriMatchType::Exact => {
            if given_url.path() == "/" {
                given_url.to_string().trim_end_matches('/')
                    == url.trim_end_matches('/')
            } else {
                given_url.to_string() == url
            }
        }
        rbw::api::UriMatchType::RegularExpression => {
            let Ok(rx) = regex::Regex::new(url) else {
                return false;
            };
            rx.is_match(given_url.as_ref())
        }
        rbw::api::UriMatchType::Never => false,
    }
}

fn host_port(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        url.port().map_or_else(
            || host.to_string(),
            |port| format!("{host}:{port}"),
        ),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListField {
    Id,
    Name,
    User,
    Password,
    Folder,
    Uri,
    EntryType,
    Collections,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TableColumnStyle {
    Id,
    Name,
    User,
    Password,
    Folder,
    EntryType,
    Collections,
    Attachments,
    Size,
    Default,
}

struct TableColumn<'a> {
    header: &'a str,
    style: TableColumnStyle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Default,
    Name,
    Json,
    Yaml,
}

impl ListField {
    fn all() -> Vec<Self> {
        vec![
            Self::Id,
            Self::Name,
            Self::User,
            Self::Folder,
            Self::Uri,
            Self::EntryType,
            Self::Collections,
        ]
    }

    fn all_insecure() -> Vec<Self> {
        vec![
            Self::Id,
            Self::Name,
            Self::User,
            Self::Password,
            Self::Folder,
            Self::Uri,
            Self::EntryType,
            Self::Collections,
        ]
    }
}

impl std::convert::TryFrom<&String> for ListField {
    type Error = anyhow::Error;

    fn try_from(s: &String) -> anyhow::Result<Self> {
        Ok(match s.as_str() {
            "name" => Self::Name,
            "id" | "uid" => Self::Id,
            "user" => Self::User,
            "password" => Self::Password,
            "folder" => Self::Folder,
            "type" => Self::EntryType,
            "collections" => Self::Collections,
            _ => return Err(anyhow::anyhow!("unknown field {s}")),
        })
    }
}

pub fn config_show() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    write_json_pretty(&config, "failed to write config to stdout")
}

pub fn config_set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = Some(value.to_string()),
        "sso_id" => config.sso_id = Some(value.to_string()),
        "base_url" => config.base_url = Some(value.to_string()),
        "identity_url" => config.identity_url = Some(value.to_string()),
        "ui_url" => config.ui_url = Some(value.to_string()),
        "notifications_url" => {
            config.notifications_url = Some(value.to_string());
        }
        "client_cert_path" => {
            config.client_cert_path =
                Some(std::path::PathBuf::from(value.to_string()));
        }
        "lock_timeout" => {
            let timeout = value
                .parse()
                .context("failed to parse value for lock_timeout")?;
            if timeout == 0 {
                log::error!("lock_timeout must be greater than 0");
            } else {
                config.lock_timeout = timeout;
            }
        }
        "sync_interval" => {
            let interval = value
                .parse()
                .context("failed to parse value for sync_interval")?;
            config.sync_interval = interval;
        }
        "pinentry" => config.pinentry = value.to_string(),
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

pub fn config_unset(key: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = None,
        "sso_id" => config.sso_id = None,
        "base_url" => config.base_url = None,
        "identity_url" => config.identity_url = None,
        "ui_url" => config.ui_url = None,
        "notifications_url" => config.notifications_url = None,
        "client_cert_path" => config.client_cert_path = None,
        "lock_timeout" => {
            config.lock_timeout = rbw::config::default_lock_timeout();
        }
        "pinentry" => config.pinentry = rbw::config::default_pinentry(),
        _ => return Err(anyhow::anyhow!("invalid config key: {key}")),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

fn clipboard_store(val: &str) -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::clipboard_store(val)?;

    Ok(())
}

pub fn register() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::register()?;

    Ok(())
}

pub fn login() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;

    Ok(())
}

pub fn unlock(password: Option<String>) -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::unlock(password)?;

    Ok(())
}

pub fn unlocked() -> anyhow::Result<()> {
    // not ensure_agent, because we don't want `rbw unlocked` to start the
    // agent if it's not running
    let _ = check_agent_version();
    crate::actions::unlocked()?;

    Ok(())
}

pub fn sync() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::sync()?;

    Ok(())
}

pub fn list(
    fields: &[String],
    with_attachments: bool,
    insecure: bool,
    output: OutputMode,
) -> anyhow::Result<()> {
    let mut fields: Vec<ListField> = if output_is_structured(output) {
        if insecure {
            ListField::all_insecure()
        } else {
            ListField::all()
        }
    } else {
        fields
            .iter()
            .map(std::convert::TryFrom::try_from)
            .collect::<anyhow::Result<_>>()?
    };
    if insecure && !output_is_structured(output) && !fields.contains(&ListField::Password) {
        // Insert password after user (or at position 2 if user column present)
        let insert_pos = fields
            .iter()
            .position(|f| matches!(f, ListField::User))
            .map_or(fields.len(), |i| i + 1);
        fields.insert(insert_pos, ListField::Password);
    }

    unlock(None)?;

    let db = load_db()?;

    // Gather every cipherstring that needs decrypting across all entries, then
    // decrypt them in a single batch request to the agent. This avoids a
    // separate socket round-trip per field per entry, which dominates the
    // runtime of `list` on large vaults.
    let mut requests = BatchRequests::new();
    let plans: Vec<ListCipherPlan> = db
        .entries
        .iter()
        .map(|entry| ListCipherPlan::build(entry, &fields, &mut requests))
        .collect();

    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };

    let mut entries: Vec<DecryptedListCipher> = plans
        .into_iter()
        .map(|plan| plan.resolve(&results))
        .collect::<anyhow::Result<_>>()?;
    if with_attachments {
        entries.retain(|entry| entry.attachment_metadata.has_attachments());
    }
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, output)?;

    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
pub fn get(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    field: Option<&str>,
    output: OutputMode,
    clipboard: bool,
    ignore_case: bool,
    list_fields: bool,
) -> anyhow::Result<()> {
    unlock(None)?;

    let db = load_db()?;

    let needle_str = needles
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (_, decrypted) =
        find_entry(&db, needles, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    if list_fields {
        decrypted.display_fields_list();
    } else if output_is_structured(output) {
        decrypted.display_structured(&desc, output)?;
    } else if output == OutputMode::Name {
        println!("{}", decrypted.name);
    } else if let Some(field) = field {
        decrypted.display_field(&desc, field, clipboard);
    } else {
        decrypted.display_short(&desc, clipboard);
    }

    Ok(())
}

pub fn show(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
) -> anyhow::Result<()> {
    unlock(None)?;
    let db = load_db()?;
    let needle_str = needles
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );
    let (_, decrypted) =
        find_entry(&db, needles, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    if output_is_structured(output) {
        decrypted.display_structured(&desc, output)?;
    } else {
        decrypted.display_show();
    }
    Ok(())
}

pub fn attachment_list(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    output: OutputMode,
) -> anyhow::Result<()> {
    unlock(None)?;
    let db = load_db()?;
    let (_, decrypted) = find_entry(&db, needles, user, folder, ignore_case)?;

    if output_is_structured(output) {
        write_serialized_pretty(
            &decrypted.attachments,
            output,
            "failed to write attachments to stdout",
        )?;
    } else if output == OutputMode::Name {
        for attachment in &decrypted.attachments {
            println!(
                "{}",
                attachment
                    .file_name
                    .clone()
                    .unwrap_or_else(|| attachment.id.clone())
            );
        }
    } else {
        let rows = decrypted
            .attachments
            .iter()
            .map(|attachment| {
                vec![
                    attachment.id.clone(),
                    attachment.file_name.clone().unwrap_or_default(),
                    attachment
                        .size_name
                        .clone()
                        .or_else(|| attachment.size.clone())
                        .unwrap_or_default(),
                ]
            })
            .collect::<Vec<_>>();
        print_table(
            &[
                TableColumn {
                    header: "id",
                    style: TableColumnStyle::Id,
                },
                TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
                TableColumn {
                    header: "size",
                    style: TableColumnStyle::Size,
                },
            ],
            &rows,
        )?;
    }

    Ok(())
}

pub fn attachment_get(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    attachment: Option<&str>,
    output: Option<&std::path::Path>,
    raw: bool,
) -> anyhow::Result<()> {
    unlock(None)?;
    let mut db = load_db()?;
    let (entry, decrypted) =
        find_entry(&db, needles, user, folder, ignore_case)?;
    let Some(attachment) = attachment else {
        return Err(available_attachments_error(
            &decrypted.name,
            &decrypted.attachments,
            "attachment id or filename is required",
        ));
    };
    let (attachment, decrypted_attachment) =
        find_attachment(&entry, &decrypted, attachment).map_err(|err| {
            available_attachments_error(
                &decrypted.name,
                &decrypted.attachments,
                &err.to_string(),
            )
        })?;

    let access_token = db
        .access_token
        .as_ref()
        .context("failed to find access token in db")?
        .clone();
    let refresh_token = db
        .refresh_token
        .as_ref()
        .context("failed to find refresh token in db")?
        .clone();
    let url = match rbw::actions::attachment_url(
        &access_token,
        &refresh_token,
        &entry.id,
        &attachment.id,
    ) {
        Ok((new_access_token, url)) => {
            if let Some(new_access_token) = new_access_token {
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }
            url
        }
        Err(e) => attachment.url.clone().ok_or(e)?,
    };
    let encrypted = rbw::actions::download_attachment(&url)
        .context("failed to download attachment")?;
    let decrypted = crate::actions::decrypt_attachment(
        encrypted,
        attachment.key.as_deref(),
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;

    let output_to_stdout = raw
        || output.is_some_and(|output| output == std::path::Path::new("-"));

    if output_to_stdout {
        std::io::stdout()
            .write_all(&decrypted)
            .context("failed to write attachment to stdout")?;
        return Ok(());
    }

    let file_name = decrypted_attachment
        .file_name
        .as_deref()
        .and_then(|name| std::path::Path::new(name).file_name())
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("BitwardenAttachment");
    let path = output.map_or_else(
        || std::path::PathBuf::from(file_name),
        |output| {
            if output.is_dir() {
                output.join(file_name)
            } else {
                output.to_path_buf()
            }
        },
    );
    std::fs::write(&path, decrypted)
        .with_context(|| format!("failed to write {}", path.display()))?;
    println!("{}", path.display());

    Ok(())
}

pub fn attachment_create(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    file: &std::path::Path,
) -> anyhow::Result<()> {
    unlock(None)?;
    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (entry, decrypted) =
        find_entry(&db, needles, username, folder, ignore_case)?;

    let filename = file
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("invalid filename"))?;

    let data = std::fs::read(file)
        .with_context(|| format!("failed to read {}", file.display()))?;

    let (encrypted_data, encrypted_key, encrypted_filename) =
        crate::actions::encrypt_attachment(
            data,
            filename,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?;

    if let (Some(new_token), ()) = rbw::actions::create_attachment(
        &access_token,
        &refresh_token,
        &entry.id,
        &encrypted_filename,
        &encrypted_key,
        encrypted_data,
    )? {
        db.access_token = Some(new_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    let c = stdout_supports_color();
    eprintln!(
        "{} {} \u{2192} {}",
        style::success("Attached", c),
        style::name(filename, c),
        style::name(&decrypted.name, c),
    );

    Ok(())
}

fn print_entry_list(
    entries: &[DecryptedListCipher],
    fields: &[ListField],
    output: OutputMode,
) -> anyhow::Result<()> {
    if output_is_structured(output) {
        write_serialized_pretty(
            &entries,
            output,
            "failed to write entries to stdout",
        )?;
    } else if output == OutputMode::Name {
        for entry in entries {
            println!("{}", entry.name.clone().unwrap_or_default());
        }
    } else {
        let mut columns = fields
            .iter()
            .map(|field| match field {
                ListField::Id => TableColumn {
                    header: "uid",
                    style: TableColumnStyle::Id,
                },
                ListField::Name => TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
                ListField::User => TableColumn {
                    header: "user",
                    style: TableColumnStyle::User,
                },
                ListField::Folder => TableColumn {
                    header: "folder",
                    style: TableColumnStyle::Folder,
                },
                ListField::Uri => TableColumn {
                    header: "uri",
                    style: TableColumnStyle::Default,
                },
                ListField::EntryType => TableColumn {
                    header: "type",
                    style: TableColumnStyle::EntryType,
                },
                ListField::Collections => TableColumn {
                    header: "collections",
                    style: TableColumnStyle::Collections,
                },
                ListField::Password => TableColumn {
                    header: "password",
                    style: TableColumnStyle::Password,
                },
            })
            .collect::<Vec<_>>();
        let show_attachments =
            entries.iter().any(|e| e.attachment_metadata.has_attachments());
        if show_attachments {
            columns.push(TableColumn {
                header: "attachments",
                style: TableColumnStyle::Attachments,
            });
        }

        let rows = entries
            .iter()
            .map(|entry| {
                let mut values = fields
                    .iter()
                    .map(|field| match field {
                        ListField::Id => entry.id.clone(),
                        ListField::Name => entry.name.as_ref().map_or_else(
                            String::new,
                            std::string::ToString::to_string,
                        ),
                        ListField::User => entry.user.as_ref().map_or_else(
                            || "N/A".to_string(),
                            std::string::ToString::to_string,
                        ),
                        ListField::Folder => {
                            entry.folder.as_ref().map_or_else(
                                String::new,
                                std::string::ToString::to_string,
                            )
                        }
                        ListField::Uri => unreachable!(),
                        ListField::EntryType => {
                            entry.entry_type.as_ref().map_or_else(
                                String::new,
                                std::string::ToString::to_string,
                            )
                        }
                        ListField::Collections => entry
                            .collection_ids
                            .as_ref()
                            .map_or_else(String::new, |ids| ids.join(",")),
                        ListField::Password => entry
                            .password
                            .as_ref()
                            .map_or_else(String::new, std::string::ToString::to_string),
                    })
                    .collect::<Vec<_>>();
                if show_attachments {
                    values.push(attachments_cell(
                        entry.attachment_metadata.attachment_count,
                    ));
                }
                values
            })
            .collect::<Vec<_>>();

        print_table(&columns, &rows)?;
    }

    Ok(())
}

pub fn search(
    term: &str,
    fields: &[String],
    folder: Option<&str>,
    with_attachments: bool,
    insecure: bool,
    output: OutputMode,
) -> anyhow::Result<()> {
    let mut fields: Vec<ListField> = if output_is_structured(output) {
        if insecure {
            ListField::all_insecure()
        } else {
            ListField::all()
        }
    } else {
        fields
            .iter()
            .map(std::convert::TryFrom::try_from)
            .collect::<anyhow::Result<_>>()?
    };
    if insecure && !output_is_structured(output) && !fields.contains(&ListField::Password) {
        let insert_pos = fields
            .iter()
            .position(|f| matches!(f, ListField::User))
            .map_or(fields.len(), |i| i + 1);
        fields.insert(insert_pos, ListField::Password);
    }

    unlock(None)?;

    let db = load_db()?;

    // As in `list`, decrypt every entry's searchable fields in a single batch
    // request rather than one socket round-trip per field per entry.
    let mut requests = BatchRequests::new();
    let plans: Vec<SearchCipherPlan> = db
        .entries
        .iter()
        .map(|entry| SearchCipherPlan::build(entry, &mut requests))
        .collect();

    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };

    let mut entries: Vec<DecryptedListCipher> = plans
        .into_iter()
        .map(|plan| plan.resolve(&results))
        .filter(|entry| {
            entry.as_ref().map_or(true, |entry| {
                entry.search_match(term, folder, with_attachments)
            })
        })
        .map(|entry| entry.map(std::convert::Into::into))
        .collect::<Result<_, anyhow::Error>>()?;
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    if entries.is_empty() {
        let c = std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        let msg = format!("no entries found matching '{term}'");
        eprintln!("{}", style::warning(&msg, c));
        std::process::exit(1);
    }

    print_entry_list(&entries, &fields, output)?;

    Ok(())
}

pub fn code(
    needles: Vec<Needle>,
    user: Option<&str>,
    folder: Option<&str>,
    clipboard: bool,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock(None)?;

    let db = load_db()?;

    let needle_str = needles
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (_, decrypted) =
        find_entry(&db, needles, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let DecryptedData::Login { totp, .. } = decrypted.data {
        if let Some(totp) = totp {
            val_display_or_store(clipboard, &generate_totp(&totp)?);
        } else {
            return Err(anyhow::anyhow!(
                "entry does not contain a totp secret"
            ));
        }
    } else {
        return Err(anyhow::anyhow!("not a login entry"));
    }

    Ok(())
}

pub fn add(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    json: bool,
    _yaml: bool,
) -> anyhow::Result<()> {
    add_structured(name, username, uris, folder, json)
}


pub fn generate(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let password = rbw::pwgen::pwgen(ty, len);
    println!("{password}");

    if let Some(name) = name {
        unlock(None)?;

        let mut db = load_db()?;
        // unwrap is safe here because the call to unlock above is guaranteed
        // to populate these or error
        let mut access_token = db.access_token.as_ref().unwrap().clone();
        let refresh_token = db.refresh_token.as_ref().unwrap();

        let name = crate::actions::encrypt(name, None)?;
        let username = username
            .map(|username| crate::actions::encrypt(username, None))
            .transpose()?;
        let password = crate::actions::encrypt(&password, None)?;
        let uris: Vec<_> = uris
            .iter()
            .map(|uri| {
                Ok(rbw::db::Uri {
                    uri: crate::actions::encrypt(&uri.0, None)?,
                    match_type: uri.1,
                })
            })
            .collect::<anyhow::Result<_>>()?;

        let mut folder_id = None;
        if let Some(folder_name) = folder {
            let (new_access_token, folders) =
                rbw::actions::list_folders(&access_token, refresh_token)?;
            if let Some(new_access_token) = new_access_token {
                access_token.clone_from(&new_access_token);
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }

            let folders: Vec<(String, String)> = folders
                .iter()
                .cloned()
                .map(|(id, name)| {
                    Ok((id, crate::actions::decrypt(&name, None, None)?))
                })
                .collect::<anyhow::Result<_>>()?;

            for (id, name) in folders {
                if name == folder_name {
                    folder_id = Some(id);
                }
            }
            if folder_id.is_none() {
                let (new_access_token, id) = rbw::actions::create_folder(
                    &access_token,
                    refresh_token,
                    &crate::actions::encrypt(folder_name, None)?,
                )?;
                if let Some(new_access_token) = new_access_token {
                    access_token.clone_from(&new_access_token);
                    db.access_token = Some(new_access_token);
                    save_db(&db)?;
                }
                folder_id = Some(id);
            }
        }

        if let (Some(access_token), ()) = rbw::actions::add(
            &access_token,
            refresh_token,
            &name,
            &rbw::db::EntryData::Login {
                username,
                password: Some(password),
                uris,
                totp: None,
            },
            None,
            folder_id.as_deref(),
        )? {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }

        crate::actions::sync()?;
    }

    Ok(())
}

pub fn edit(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    json: bool,
    _yaml: bool,
) -> anyhow::Result<()> {
    edit_structured(needles, username, folder, ignore_case, json)
}

pub fn remove(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock(None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let needle_str = needles
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (entry, _) = find_entry(&db, needles, username, folder, ignore_case)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let (Some(access_token), ()) =
        rbw::actions::remove(access_token, refresh_token, &entry.id)?
    {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

fn edit_structured(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    json: bool,
) -> anyhow::Result<()> {
    unlock(None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let needle_str = needles
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (entry, decrypted) =
        find_entry(&db, needles, username, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let editable = decrypted_to_editable(&decrypted);

    let serialized = if json {
        serde_json::to_string_pretty(&editable)?
    } else {
        serde_yaml::to_string(&editable)?
    };

    let (help, ext) = if json {
        (
            "# Edit the JSON below. Lines starting with # are ignored.",
            "json",
        )
    } else {
        (
            "# Edit the YAML below. Lines starting with # are ignored.",
            "yaml",
        )
    };

    let contents = rbw::edit::edit(&serialized, help, ext)?;
    let contents_trimmed = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });

    if contents_trimmed.trim() == serialized.trim() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    let updated: EditableCipher = if json {
        serde_json::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse JSON: {e}"))?
    } else {
        serde_yaml::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?
    };

    let (data, fields, notes) =
        editable_to_encrypted(&updated, entry.org_id.as_deref())?;

    let encrypted_name =
        crate::actions::encrypt(&updated.name, entry.org_id.as_deref())?;

    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, entry.org_id.as_deref()))
        .transpose()?;

    let mut history = entry.history.clone();
    if let (
        rbw::db::EntryData::Login {
            password: Some(old_pw),
            ..
        },
        rbw::db::EntryData::Login {
            password: new_pw, ..
        },
    ) = (&entry.data, &data)
    {
        if Some(old_pw) != new_pw.as_ref() {
            history.insert(
                0,
                rbw::db::HistoryEntry {
                    last_used_date: format!(
                        "{}",
                        humantime::format_rfc3339(
                            std::time::SystemTime::now()
                        )
                    ),
                    password: old_pw.clone(),
                },
            );
        }
    }

    let folder_id = if let Some(folder_name) = updated.folder.as_deref() {
        resolve_folder_id(
            &mut db,
            &access_token,
            &refresh_token,
            folder_name,
        )?
    } else {
        entry.folder_id.clone()
    };

    if let (Some(new_token), ()) = rbw::actions::edit(
        &access_token,
        &refresh_token,
        &entry.id,
        entry.org_id.as_deref(),
        &encrypted_name,
        &data,
        &fields,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
        &history,
    )? {
        db.access_token = Some(new_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

fn add_structured(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<rbw::api::UriMatchType>)],
    folder: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    let editable_uris: Vec<EditableUri> = if uris.is_empty() {
        vec![EditableUri {
            uri: String::new(),
            match_type: None,
        }]
    } else {
        uris.iter()
            .map(|(uri, mt)| EditableUri {
                uri: uri.clone(),
                match_type: mt.map(|m| uri_match_type_str(m).to_string()),
            })
            .collect()
    };

    let template = EditableCipher {
        name: name.unwrap_or("").to_string(),
        folder: folder.map(std::string::ToString::to_string),
        notes: None,
        data: EditableData::Login {
            username: Some(username.unwrap_or("").to_string()),
            password: Some(String::new()),
            uris: editable_uris,
            totp: None,
        },
        fields: Vec::new(),
    };

    let serialized = if json {
        serde_json::to_string_pretty(&template)?
    } else {
        serde_yaml::to_string(&template)?
    };

    let (help, ext) = if json {
        (
            "# Fill in the JSON below. Lines starting with # are ignored.",
            "json",
        )
    } else {
        (
            "# Fill in the YAML below. Lines starting with # are ignored.",
            "yaml",
        )
    };

    let contents = rbw::edit::edit(&serialized, help, ext)?;
    let contents_trimmed = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });

    if contents_trimmed.trim() == serialized.trim() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    let cipher: EditableCipher = if json {
        serde_json::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse JSON: {e}"))?
    } else {
        serde_yaml::from_str(&contents_trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse YAML: {e}"))?
    };

    if cipher.name.is_empty() {
        return Err(anyhow::anyhow!("name cannot be empty"));
    }

    unlock(None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (data, _fields, notes) = editable_to_encrypted(&cipher, None)?;

    let encrypted_name = crate::actions::encrypt(&cipher.name, None)?;
    let encrypted_notes = notes
        .as_deref()
        .map(|n| crate::actions::encrypt(n, None))
        .transpose()?;

    let folder_id = if let Some(folder_name) = cipher.folder.as_deref() {
        resolve_folder_id(
            &mut db,
            &access_token,
            &refresh_token,
            folder_name,
        )?
    } else {
        None
    };

    if let (Some(new_token), ()) = rbw::actions::add(
        &access_token,
        &refresh_token,
        &encrypted_name,
        &data,
        encrypted_notes.as_deref(),
        folder_id.as_deref(),
    )? {
        db.access_token = Some(new_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;
    print_created(&cipher.name);
    Ok(())
}

pub fn set(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    bulk: bool,
    yes: bool,
) -> anyhow::Result<()> {
    if bulk {
        unlock(None)?;
        let mut db = load_db()?;
        let mut any_err = false;
        for needle in &needles {
            let found = find_entries_all(
                &db,
                needle,
                username,
                folder,
                ignore_case,
            );
            match found {
                Err(e) => {
                    eprintln!("{}: {e:#}", needle);
                    any_err = true;
                }
                Ok(entries) => {
                    for (entry, decrypted) in entries {
                        if let Err(e) = set_entry(
                            &mut db,
                            entry,
                            decrypted,
                            new_name,
                            new_username,
                            new_password,
                            new_notes,
                            new_uris,
                            new_totp,
                            diff,
                            new_attachments,
                            yes,
                        ) {
                            eprintln!("{e:#}");
                            any_err = true;
                        }
                    }
                }
            }
        }
        return if any_err {
            Err(anyhow::anyhow!("one or more entries failed to update"))
        } else {
            Ok(())
        };
    }
    set_one(
        needles,
        username,
        folder,
        ignore_case,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
        diff,
        new_attachments,
        yes,
    )
}

fn find_entries_all(
    db: &rbw::db::Db,
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<Vec<(rbw::db::Entry, DecryptedCipher)>> {
    let mut requests = BatchRequests::new();
    let plans: Vec<SearchCipherPlan> = db
        .entries
        .iter()
        .map(|entry| SearchCipherPlan::build(entry, &mut requests))
        .collect();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };
    let ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .zip(plans)
        .map(|(entry, plan)| {
            plan.resolve(&results).map(|d| (entry.clone(), d))
        })
        .collect::<anyhow::Result<_>>()?;

    let matches: Vec<_> = ciphers
        .iter()
        .filter(|(_, d)| {
            d.matches(needle, username, folder, ignore_case, false, false, false)
        })
        .collect();

    if matches.is_empty() {
        return Err(anyhow::anyhow!("no entry found for '{needle}'"));
    }

    matches
        .iter()
        .map(|(entry, _)| {
            decrypt_cipher(entry).map(|d| ((*entry).clone(), d))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn set_one(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    yes: bool,
) -> anyhow::Result<()> {
    unlock(None)?;

    let mut db = load_db()?;

    let needle_str = needles
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (entry, decrypted) =
        find_entry(&db, needles, username, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    set_entry(
        &mut db,
        entry,
        decrypted,
        new_name,
        new_username,
        new_password,
        new_notes,
        new_uris,
        new_totp,
        diff,
        new_attachments,
        yes,
    )
}

#[allow(clippy::too_many_arguments)]
fn set_entry(
    db: &mut rbw::db::Db,
    entry: rbw::db::Entry,
    decrypted: DecryptedCipher,
    new_name: Option<&str>,
    new_username: Option<&str>,
    new_password: Option<&str>,
    new_notes: Option<&str>,
    new_uris: &[String],
    new_totp: Option<&str>,
    diff: bool,
    new_attachments: &[std::path::PathBuf],
    yes: bool,
) -> anyhow::Result<()> {
    let access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let org_id = entry.org_id.as_deref();
    let entry_name = decrypted.name.clone();

    // Validate Login-only fields early before touching anything
    let login_fields_requested = new_username.is_some()
        || new_password.is_some()
        || !new_uris.is_empty()
        || new_totp.is_some();
    if login_fields_requested
        && !matches!(decrypted.data, DecryptedData::Login { .. })
    {
        return Err(anyhow::anyhow!(
            "username/password/uri/totp are only supported for Login entries"
        ));
    }

    // Detect which fields actually changed; (field, old_display, new_display)
    let mut changes: Vec<(&str, String, String)> = Vec::new();

    if let Some(n) = new_name {
        if n != decrypted.name.as_str() {
            changes.push(("name", decrypted.name.clone(), n.to_string()));
        }
    }
    if let Some(n) = new_notes {
        let cur = decrypted.notes.as_deref().unwrap_or("");
        if n != cur {
            let old_d = if cur.is_empty() { "(none)".to_string() } else { "(set)".to_string() };
            let new_d = if n.is_empty() { "(cleared)".to_string() } else { "(set)".to_string() };
            changes.push(("notes", old_d, new_d));
        }
    }
    if let DecryptedData::Login {
        username: cur_user,
        password: cur_pw,
        uris: cur_uris,
        totp: cur_totp,
    } = &decrypted.data
    {
        if let Some(u) = new_username {
            if Some(u) != cur_user.as_deref() {
                let old = cur_user.as_deref()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_else(|| "(none)".to_string());
                changes.push(("username", old, u.to_string()));
            }
        }
        if let Some(p) = new_password {
            if Some(p) != cur_pw.as_deref() {
                let old = cur_pw.as_deref()
                    .map(|s| format!("\"{}\"", censor(s)))
                    .unwrap_or_else(|| "(none)".to_string());
                changes.push(("password", old, format!("\"{}\"", censor(p))));
            }
        }
        if !new_uris.is_empty() {
            let cur_strs: Vec<&str> = cur_uris.as_ref()
                .map(|v| v.iter().map(|u| u.uri.as_str()).collect())
                .unwrap_or_default();
            let new_strs: Vec<&str> = new_uris.iter().map(String::as_str).collect();
            if new_strs != cur_strs {
                let fmt_uris = |v: &[&str]| match v {
                    [] => "(none)".to_string(),
                    [u] => (*u).to_string(),
                    _ => format!("[{} uris]", v.len()),
                };
                changes.push(("uri", fmt_uris(&cur_strs), fmt_uris(&new_strs)));
            }
        }
        if let Some(t) = new_totp {
            if Some(t) != cur_totp.as_deref() {
                let old = cur_totp.as_deref()
                    .map(|s| format!("\"{}\"", censor(s)))
                    .unwrap_or_else(|| "(none)".to_string());
                changes.push(("totp", old, format!("\"{}\"", censor(t))));
            }
        }
    }

    if changes.is_empty() && new_attachments.is_empty() {
        eprintln!("{}", paint_no_changes());
        return Ok(());
    }

    if !yes {
        let c = stdout_supports_color();
        let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
        eprintln!("About to update {}:", style::name(&entry_name, c));
        eprintln!();
        for (field, old, new) in &changes {
            eprintln!(
                "{} {} {} {}",
                lbl(field),
                style::old_val(old, c),
                style::dim("→", c),
                style::new_val(new, c),
            );
        }
        for file in new_attachments {
            eprintln!("{} {}", lbl("attach"), file.display());
        }
        eprintln!();
        eprint!("Apply? [y/N] ");
        use std::io::Write as _;
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("failed to read confirmation")?;
        if !matches!(answer.trim(), "y" | "Y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    // Encrypt and save
    let encrypted_name = if let Some(n) = new_name {
        crate::actions::encrypt(n, org_id)?
    } else {
        entry.name.clone()
    };

    let encrypted_notes = if let Some(n) = new_notes {
        if n.is_empty() {
            None
        } else {
            Some(crate::actions::encrypt(n, org_id)?)
        }
    } else {
        entry.notes.clone()
    };

    let mut history = entry.history.clone();

    let data = match &entry.data {
        rbw::db::EntryData::Login {
            username: entry_username,
            password: entry_password,
            uris: entry_uris,
            totp: entry_totp,
        } => {
            let enc_user = if new_username.is_some() {
                new_username
                    .map(|u| crate::actions::encrypt(u, org_id))
                    .transpose()?
            } else {
                entry_username.clone()
            };
            let enc_pw = if let Some(pw) = new_password {
                if let Some(prev) = entry_password.clone() {
                    history.insert(
                        0,
                        rbw::db::HistoryEntry {
                            last_used_date: format!(
                                "{}",
                                humantime::format_rfc3339(
                                    std::time::SystemTime::now()
                                )
                            ),
                            password: prev,
                        },
                    );
                }
                Some(crate::actions::encrypt(pw, org_id)?)
            } else {
                entry_password.clone()
            };
            let enc_uris = if new_uris.is_empty() {
                entry_uris.clone()
            } else {
                new_uris
                    .iter()
                    .map(|u| {
                        Ok(rbw::db::Uri {
                            uri: crate::actions::encrypt(u, org_id)?,
                            match_type: None,
                        })
                    })
                    .collect::<anyhow::Result<_>>()?
            };
            let enc_totp = if new_totp.is_some() {
                new_totp
                    .map(|t| crate::actions::encrypt(t, org_id))
                    .transpose()?
            } else {
                entry_totp.clone()
            };
            rbw::db::EntryData::Login {
                username: enc_user,
                password: enc_pw,
                uris: enc_uris,
                totp: enc_totp,
            }
        }
        other => other.clone(),
    };

    if !changes.is_empty() {
        if let (Some(new_token), ()) = rbw::actions::edit(
            &access_token,
            &refresh_token,
            &entry.id,
            org_id,
            &encrypted_name,
            &data,
            &entry.fields,
            encrypted_notes.as_deref(),
            entry.folder_id.as_deref(),
            &history,
        )? {
            db.access_token = Some(new_token);
            save_db(&db)?;
        }

        print_set_changes(&entry_name, &changes, diff);
    }

    for file in new_attachments {
        let filename = file
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| anyhow::anyhow!("invalid filename: {}", file.display()))?;
        let file_data = std::fs::read(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let access_token = db.access_token.as_ref().unwrap().clone();
        let refresh_token = db.refresh_token.as_ref().unwrap().clone();
        let (encrypted_data, encrypted_key, encrypted_filename) =
            crate::actions::encrypt_attachment(
                file_data,
                filename,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )?;
        if let (Some(new_token), ()) = rbw::actions::create_attachment(
            &access_token,
            &refresh_token,
            &entry.id,
            &encrypted_filename,
            &encrypted_key,
            encrypted_data,
        )? {
            db.access_token = Some(new_token);
            save_db(&db)?;
        }
    }

    crate::actions::sync()?;
    Ok(())
}

fn resolve_folder_id(
    db: &mut rbw::db::Db,
    access_token: &str,
    refresh_token: &str,
    folder_name: &str,
) -> anyhow::Result<Option<String>> {
    let (new_access_token, folders) =
        rbw::actions::list_folders(access_token, refresh_token)?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(db)?;
    }
    let access_token = db.access_token.as_deref().unwrap();
    let refresh_token_str = db.refresh_token.as_deref().unwrap();

    let folders: Vec<(String, String)> = folders
        .iter()
        .cloned()
        .map(|(id, name)| {
            Ok((id, crate::actions::decrypt(&name, None, None)?))
        })
        .collect::<anyhow::Result<_>>()?;

    for (id, name) in &folders {
        if name == folder_name {
            return Ok(Some(id.clone()));
        }
    }

    let (new_access_token, id) = rbw::actions::create_folder(
        access_token,
        refresh_token_str,
        &crate::actions::encrypt(folder_name, None)?,
    )?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(db)?;
    }
    Ok(Some(id))
}

fn censor(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    if len <= 4 {
        return "****".to_string();
    }
    let prefix = ((len + 2) / 3).min(8);
    let suffix = ((len + 3) / 4).min(5);
    if prefix + suffix >= len {
        return "****".to_string();
    }
    format!(
        "{}…{}",
        chars[..prefix].iter().collect::<String>(),
        chars[len - suffix..].iter().collect::<String>()
    )
}

// Exposed for main.rs error rendering — keeps all ANSI codes in one place.
pub fn style_error(msg: &str, color: bool) -> String {
    style::paint_raw(msg, "1;31", color)
}

fn paint_no_changes() -> String {
    style::dim("No changes.", stdout_supports_color())
}

fn print_created(entry_name: &str) {
    let c = stdout_supports_color();
    eprintln!("{} {}", style::success("Created", c), style::name(entry_name, c));
}

fn print_set_changes(
    entry_name: &str,
    changes: &[(&str, String, String)],
    diff: bool,
) {
    let c = stdout_supports_color();
    let arrow = style::dim("→", c);

    if changes.len() == 1 {
        let (field, old, new) = &changes[0];
        let line = if diff {
            format!(
                "{}: {} {} {} {}",
                style::name(entry_name, c),
                style::label(field, c),
                style::old_val(old, c),
                arrow,
                style::new_val(new, c),
            )
        } else {
            format!(
                "{}: {} {} {}",
                style::name(entry_name, c),
                style::label(field, c),
                arrow,
                style::new_val(new, c),
            )
        };
        println!("{line}");
    } else {
        println!("{}:", style::name(entry_name, c));
        for (field, old, new) in changes {
            let line = if diff {
                format!(
                    "  {} {} {} {}",
                    style::label(field, c),
                    style::old_val(old, c),
                    arrow,
                    style::new_val(new, c),
                )
            } else {
                format!(
                    "  {} {} {}",
                    style::label(field, c),
                    arrow,
                    style::new_val(new, c),
                )
            };
            println!("{line}");
        }
    }
}

pub fn export() -> anyhow::Result<()> {
    #[derive(serde::Serialize)]
    struct ExportedEntry {
        id: String,
        org_id: Option<String>,
        folder: Option<String>,
        name: String,
        #[serde(flatten)]
        data: DecryptedData,
        fields: Vec<DecryptedField>,
        notes: Option<String>,
        history: Vec<DecryptedHistoryEntry>,
        collection_ids: Vec<String>,
    }

    #[derive(serde::Serialize)]
    struct ExportedCollection {
        id: String,
        org_id: String,
        name: String,
    }

    #[derive(serde::Serialize)]
    struct ExportedVault {
        entries: Vec<ExportedEntry>,
        collections: Vec<ExportedCollection>,
    }

    unlock(None)?;

    let db = load_db()?;

    let mut entries: Vec<ExportedEntry> = Vec::new();
    for entry in &db.entries {
        let decrypted = decrypt_cipher(entry)?;
        entries.push(ExportedEntry {
            id: decrypted.id,
            org_id: entry.org_id.clone(),
            folder: decrypted.folder,
            name: decrypted.name,
            data: decrypted.data,
            fields: decrypted.fields,
            notes: decrypted.notes,
            history: decrypted.history,
            collection_ids: entry.collection_ids.clone(),
        });
    }

    let mut collections: Vec<ExportedCollection> = db
        .collections
        .iter()
        .map(|c| {
            let name =
                crate::actions::decrypt(&c.name, None, Some(&c.org_id))?;
            Ok(ExportedCollection {
                id: c.id.clone(),
                org_id: c.org_id.clone(),
                name,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    collections.sort_by(|a, b| a.name.cmp(&b.name));

    let vault = ExportedVault {
        entries,
        collections,
    };

    write_json_pretty(&vault, "failed to write export to stdout")
}

pub fn list_collections(output: OutputMode) -> anyhow::Result<()> {
    #[derive(serde::Serialize)]
    struct DecryptedCollection {
        id: String,
        org_id: String,
        name: String,
    }

    unlock(None)?;

    let db = load_db()?;

    let mut collections: Vec<DecryptedCollection> = db
        .collections
        .iter()
        .map(|c| {
            let name =
                crate::actions::decrypt(&c.name, None, Some(&c.org_id))?;
            Ok(DecryptedCollection {
                id: c.id.clone(),
                org_id: c.org_id.clone(),
                name,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    collections.sort_by(|a, b| a.name.cmp(&b.name));

    if output_is_structured(output) {
        write_serialized_pretty(
            &collections,
            output,
            "failed to write collections to stdout",
        )?;
    } else if output == OutputMode::Name {
        for collection in &collections {
            println!("{}", collection.name);
        }
    } else {
        let rows = collections
            .iter()
            .map(|c| vec![c.id.clone(), c.name.clone()])
            .collect::<Vec<_>>();
        print_table(
            &[
                TableColumn {
                    header: "id",
                    style: TableColumnStyle::Id,
                },
                TableColumn {
                    header: "name",
                    style: TableColumnStyle::Name,
                },
            ],
            &rows,
        )?;
    }

    Ok(())
}

pub fn edit_collections(
    id: &str,
    collections_b64: &str,
) -> anyhow::Result<()> {
    unlock(None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let json_bytes = rbw::base64::decode(collections_b64)
        .context("failed to decode base64 collections")?;
    let json_str = std::str::from_utf8(&json_bytes)
        .context("collections is not valid UTF-8")?;
    let collection_ids: Vec<String> = serde_json::from_str(json_str)
        .context("failed to parse collection IDs JSON")?;

    if let (Some(access_token), ()) = rbw::actions::edit_collections(
        access_token,
        refresh_token,
        id,
        &collection_ids,
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn create_collection(name: &str, org_id: &str) -> anyhow::Result<()> {
    unlock(None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let encrypted_name = crate::actions::encrypt(name, Some(org_id))?;

    let (new_access_token, id) = rbw::actions::create_collection(
        access_token,
        refresh_token,
        org_id,
        &encrypted_name,
    )?;
    if let Some(new_access_token) = new_access_token {
        db.access_token = Some(new_access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    println!("{id}");

    Ok(())
}

pub fn delete_collection(
    collection_id: &str,
    org_id: &str,
) -> anyhow::Result<()> {
    unlock(None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    if let (Some(access_token), ()) = rbw::actions::delete_collection(
        access_token,
        refresh_token,
        org_id,
        collection_id,
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn rename_collection(
    collection_id: &str,
    org_id: &str,
    name: &str,
) -> anyhow::Result<()> {
    unlock(None)?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let encrypted_name = crate::actions::encrypt(name, Some(org_id))?;

    if let (Some(access_token), ()) = rbw::actions::rename_collection(
        access_token,
        refresh_token,
        org_id,
        collection_id,
        &encrypted_name,
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

const EDIT: rbw::api::CollectionUser = rbw::api::CollectionUser {
    id: String::new(),
    read_only: false,
    hide_passwords: false,
    manage: false,
};

const MANAGE: rbw::api::CollectionUser = rbw::api::CollectionUser {
    id: String::new(),
    read_only: false,
    hide_passwords: false,
    manage: true,
};

fn perm_rank(u: &rbw::api::CollectionUser) -> u8 {
    if u.manage {
        return 4;
    }
    match (u.read_only, u.hide_passwords) {
        (false, false) => 3,
        (false, true) => 2,
        (true, false) => 1,
        (true, true) => 0,
    }
}

fn perm_level_name(u: &rbw::api::CollectionUser) -> &'static str {
    match perm_rank(u) {
        4 => "manage",
        3 => "edit",
        2 => "edit-no-pw",
        1 => "view",
        _ => "view-no-pw",
    }
}

fn same_flags(
    a: &rbw::api::CollectionUser,
    b: &rbw::api::CollectionUser,
) -> bool {
    a.read_only == b.read_only
        && a.hide_passwords == b.hide_passwords
        && a.manage == b.manage
}

fn normalize_collection_name(name: &str) -> anyhow::Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('/')
        || trimmed.ends_with('/')
    {
        anyhow::bail!("collection name is empty or has a leading/trailing slash: {name:?}");
    }
    Ok(trimmed.to_string())
}

fn resolve_org(
    db: &rbw::db::Db,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let org_ids: std::collections::BTreeSet<&str> =
        db.collections.iter().map(|c| c.org_id.as_str()).collect();
    org_id.map_or_else(
        || match org_ids.len() {
            0 => Err(anyhow::anyhow!("no organization found in vault")),
            1 => Ok((*org_ids.iter().next().unwrap()).to_string()),
            _ => Err(anyhow::anyhow!(
                "multiple organizations found; pass --org-id"
            )),
        },
        |o| {
            if org_ids.contains(o) {
                Ok(o.to_string())
            } else {
                Err(anyhow::anyhow!(
                    "org {o} has no collections in this vault"
                ))
            }
        },
    )
}

pub fn propagate_collection_permissions(
    org_id: Option<&str>,
    apply: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    unlock(None)?;
    crate::actions::sync()?;

    let mut db = load_db()?;
    let org_id = resolve_org(&db, org_id)?;

    let mut id2name: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for c in &db.collections {
        if c.org_id != org_id {
            continue;
        }
        let name = crate::actions::decrypt(&c.name, None, Some(&c.org_id))
            .with_context(|| {
                format!("failed to decrypt collection name for {}", c.id)
            })?;
        let name = normalize_collection_name(&name)?;
        id2name.insert(c.id.clone(), name);
    }

    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap().clone();

    let (new_token, members) =
        rbw::actions::org_users(&access_token, &refresh_token, &org_id)?;
    if let Some(t) = new_token {
        access_token.clone_from(&t);
        db.access_token = Some(t);
        save_db(&db)?;
    }

    let (new_token, details) = rbw::actions::collections_details(
        &access_token,
        &refresh_token,
        &org_id,
    )?;
    if let Some(t) = new_token {
        access_token.clone_from(&t);
        db.access_token = Some(t);
        save_db(&db)?;
    }

    // Exclude Owners (role 0) and Admins (role 1); only Users (2) and
    // Managers (3) get permission propagation. confirmed (status==2) and
    // non-access-all members only.
    let eligible: std::collections::HashMap<String, String> = members
        .iter()
        .filter(|m| m.status == 2 && !m.access_all && m.role >= 2)
        .map(|m| (m.id.clone(), m.email.clone()))
        .collect();

    let details_by_id: std::collections::HashMap<
        &str,
        &rbw::api::CollectionDetail,
    > = details.iter().map(|d| (d.id.as_str(), d)).collect();
    for d in &details {
        if !id2name.contains_key(&d.id) {
            anyhow::bail!(
                "collection {} returned by the API is missing or undecryptable in the local db; aborting",
                d.id
            );
        }
    }
    for id in id2name.keys() {
        if !details_by_id.contains_key(id.as_str()) {
            anyhow::bail!(
                "collection {} ({}) is in the local db but absent from the live API response; aborting",
                id,
                id2name[id]
            );
        }
    }

    let mut held: std::collections::HashMap<
        String,
        std::collections::HashMap<String, rbw::api::CollectionUser>,
    > = std::collections::HashMap::new();
    for d in &details {
        for u in &d.users {
            if eligible.contains_key(&u.id) {
                held.entry(u.id.clone())
                    .or_default()
                    .insert(d.id.clone(), u.clone());
            }
        }
    }

    let mut desired: std::collections::HashMap<
        (String, String),
        rbw::api::CollectionUser,
    > = std::collections::HashMap::new();
    for member_id in held.keys() {
        let held_ids = &held[member_id];
        let held_names: Vec<&str> =
            held_ids.keys().map(|id| id2name[id].as_str()).collect();
        let topmost: Vec<&str> = held_names
            .iter()
            .copied()
            .filter(|n| {
                !held_names
                    .iter()
                    .any(|h| *h != *n && n.starts_with(&format!("{h}/")))
            })
            .collect();
        for (id, name) in &id2name {
            if topmost.iter().any(|t| name.starts_with(&format!("{t}/"))) {
                desired.insert((member_id.clone(), id.clone()), MANAGE);
            }
        }
        for (id, name) in &id2name {
            if topmost.contains(&name.as_str()) {
                desired.insert((member_id.clone(), id.clone()), EDIT);
            }
        }
    }

    let mut changes: std::collections::BTreeMap<
        String,
        Vec<(String, rbw::api::CollectionUser)>,
    > = std::collections::BTreeMap::new();
    for ((member_id, coll_id), target) in &desired {
        let current = held.get(member_id).and_then(|h| h.get(coll_id));
        let needs_change = current.is_none_or(|c| !same_flags(c, target));
        if needs_change {
            changes
                .entry(coll_id.clone())
                .or_default()
                .push((member_id.clone(), target.clone()));
        }
    }
    for member_targets in changes.values_mut() {
        member_targets.sort_by(|a, b| a.0.cmp(&b.0));
    }

    for coll_id in changes.keys() {
        if !details_by_id[coll_id.as_str()].groups.is_empty() {
            anyhow::bail!(
                "collection {} ({}) has groups assigned; groups passthrough on PUT is unverified, aborting (see docs/collection-permissions-spec.md §4.3)",
                coll_id,
                id2name[coll_id]
            );
        }
    }

    let mut changed_members: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut grants = 0usize;
    for (coll_id, member_targets) in &changes {
        let name = &id2name[coll_id];
        for (member_id, target) in member_targets {
            let email = &eligible[member_id];
            let level = if target.manage { "MANAGE" } else { "EDIT" };
            let current = held.get(member_id).and_then(|h| h.get(coll_id));
            let downgrade =
                current.is_some_and(|c| perm_rank(target) < perm_rank(c));
            let prefix = if apply { "" } else { "WOULD " };
            if downgrade {
                let cur_level = perm_level_name(current.unwrap());
                let tgt_level = perm_level_name(target);
                println!(
                    "{prefix}DOWNGRADE {email} {cur_level}->{tgt_level} on {name}"
                );
            } else {
                println!("{prefix}SET {email} -> {level} on {name}");
            }
            changed_members.insert(member_id.clone());
            grants += 1;
        }
    }

    if verbose {
        eprintln!(
            "{} eligible members, {} collections in org, {} collections to change",
            eligible.len(),
            id2name.len(),
            changes.len()
        );
    }

    if apply {
        let mut applied: Vec<String> = Vec::new();
        for (coll_id, member_targets) in &changes {
            let detail = details_by_id[coll_id.as_str()];
            let mut new_users = detail.users.clone();
            for (member_id, target) in member_targets {
                let entry = new_users.iter_mut().find(|u| &u.id == member_id);
                if let Some(u) = entry {
                    u.read_only = target.read_only;
                    u.hide_passwords = target.hide_passwords;
                    u.manage = target.manage;
                } else {
                    new_users.push(rbw::api::CollectionUser {
                        id: member_id.clone(),
                        read_only: target.read_only,
                        hide_passwords: target.hide_passwords,
                        manage: target.manage,
                    });
                }
            }
            let enc_name = db
                .collections
                .iter()
                .find(|c| &c.id == coll_id)
                .map(|c| c.name.clone())
                .unwrap();
            let res = rbw::actions::set_collection_users(
                &access_token,
                &refresh_token,
                &org_id,
                coll_id,
                &enc_name,
                detail.external_id.as_deref(),
                &detail.groups,
                &new_users,
            );
            match res {
                Ok((new_token, ())) => {
                    if let Some(t) = new_token {
                        access_token.clone_from(&t);
                        db.access_token = Some(t);
                        save_db(&db)?;
                    }
                    applied.push(coll_id.clone());
                }
                Err(e) => {
                    eprintln!(
                        "PUT failed on collection {} ({}); already applied to: {:?}",
                        coll_id, id2name[coll_id], applied
                    );
                    return Err(e.into());
                }
            }
        }
        crate::actions::sync()?;
    }

    let mode = if apply { "applied" } else { "dry-run" };
    println!(
        "Done: {} members, {} collections changed, {} grants set ({})",
        changed_members.len(),
        changes.len(),
        grants,
        mode
    );

    Ok(())
}

pub fn history(
    needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<()> {
    unlock(None)?;

    let db = load_db()?;

    let needle_str = needles
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        needle_str
    );

    let (_, decrypted) =
        find_entry(&db, needles, username, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    for history in decrypted.history {
        println!("{}: {}", history.last_used_date, history.password);
    }

    Ok(())
}

pub fn lock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::lock()?;

    Ok(())
}

pub fn purge() -> anyhow::Result<()> {
    stop_agent()?;

    remove_db()?;

    Ok(())
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()?;

    Ok(())
}

pub fn inject(
    input: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let ctx = InjectContext::load()?;
    let rendered = ctx.render_input(input)?;

    match output {
        Some(path) => write_rendered_template_file(path, &rendered)?,
        None => {
            std::io::stdout()
                .write_all(rendered.as_bytes())
                .context("failed to write rendered template to stdout")?;
        }
    }

    Ok(())
}

pub fn run(
    env_file: &std::path::Path,
    command: &[OsString],
) -> anyhow::Result<std::process::ExitStatus> {
    let ctx = InjectContext::load()?;
    let env_bindings = ctx.env_bindings_from_file(env_file)?;
    run_inject_command(command, &env_bindings)
}

fn ensure_agent() -> anyhow::Result<()> {
    check_config()?;
    if matches!(check_agent_version(), Ok(())) {
        return Ok(());
    }
    run_agent()?;
    check_agent_version()?;
    Ok(())
}

fn run_agent() -> anyhow::Result<()> {
    let agent_path = std::env::var_os("RBW_AGENT");
    let agent_path = agent_path
        .as_deref()
        .unwrap_or_else(|| std::ffi::OsStr::from_bytes(b"rbw-agent"));
    let status = std::process::Command::new(agent_path)
        .status()
        .context("failed to run rbw-agent")?;
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                return Err(anyhow::anyhow!(
                    "failed to run rbw-agent: {status}"
                ));
            }
        }
    }

    Ok(())
}

fn check_config() -> anyhow::Result<()> {
    rbw::config::Config::validate().map_err(|e| {
        log::error!("{MISSING_CONFIG_HELP}");
        anyhow::Error::new(e)
    })
}

fn check_agent_version() -> anyhow::Result<()> {
    let client_version = rbw::protocol::VERSION;
    let agent_version = version_or_quit()?;
    if agent_version != client_version {
        crate::actions::quit()?;
        return Err(anyhow::anyhow!(
            "client protocol version is {client_version} but agent protocol version is {agent_version}"
        ));
    }
    Ok(())
}

fn version_or_quit() -> anyhow::Result<u32> {
    crate::actions::version().inspect_err(|_| {
        let _ = crate::actions::quit();
    })
}

fn find_entry(
    db: &rbw::db::Db,
    mut needles: Vec<Needle>,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedCipher)> {
    // Fast-path: exactly one UUID needle — try exact match first
    if needles.len() == 1 {
        if let Needle::Uuid(uuid, s) = &needles[0] {
            let uuid = *uuid;
            for cipher in &db.entries {
                if uuid::Uuid::parse_str(&cipher.id) == Ok(uuid) {
                    return Ok((cipher.clone(), decrypt_cipher(cipher)?));
                }
            }
            // UUID not found by exact match; fall through to name search
            needles = vec![Needle::Name(s.clone())];
        }
    }

    let mut requests = BatchRequests::new();
    let plans: Vec<SearchCipherPlan> = db
        .entries
        .iter()
        .map(|entry| SearchCipherPlan::build(entry, &mut requests))
        .collect();
    let results = if requests.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(requests.into_vec())?
    };
    let ciphers: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .zip(plans)
        .map(|(entry, plan)| {
            plan.resolve(&results)
                .map(|decrypted| (entry.clone(), decrypted))
        })
        .collect::<anyhow::Result<_>>()?;
    let (entry, _) =
        find_entry_raw(&ciphers, &needles, username, folder, ignore_case)?;
    let decrypted_entry = decrypt_cipher(&entry)?;
    Ok((entry, decrypted_entry))
}

fn find_attachment<'a>(
    entry: &'a rbw::db::Entry,
    decrypted: &'a DecryptedCipher,
    needle: &str,
) -> anyhow::Result<(&'a rbw::db::Attachment, &'a DecryptedAttachment)> {
    if entry.attachments.is_empty() {
        return Err(anyhow::anyhow!(
            "no attachments available for this item"
        ));
    }

    let needle = needle.to_lowercase();
    let mut matches: Vec<_> = entry
        .attachments
        .iter()
        .zip(&decrypted.attachments)
        .filter(|(attachment, decrypted)| {
            attachment.id.to_lowercase() == needle
                || decrypted.file_name.as_ref().is_some_and(|file_name| {
                    file_name.to_lowercase().contains(&needle)
                })
        })
        .collect();

    let exact_matches: Vec<_> = matches
        .iter()
        .copied()
        .filter(|(_, decrypted)| {
            decrypted
                .file_name
                .as_ref()
                .is_some_and(|file_name| file_name.to_lowercase() == needle)
        })
        .collect();
    if exact_matches.len() == 1 {
        matches = exact_matches;
    }

    match matches.as_slice() {
        [] => Err(anyhow::anyhow!("attachment '{needle}' was not found")),
        [(attachment, decrypted)] => Ok((*attachment, *decrypted)),
        _ => Err(anyhow::anyhow!(
            "multiple attachments found: {}",
            matches
                .iter()
                .map(|(attachment, _)| attachment.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn find_entry_raw(
    entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
    needles: &[Needle],
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
    let mut matches: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = vec![];

    let find_matches = |strict_username, strict_folder, exact| {
        entries
            .iter()
            .filter(|&(_, decrypted_cipher)| {
                let Some((first, rest)) = needles.split_first() else {
                    return false;
                };
                // Apply full context (username, folder) to the first needle
                if !decrypted_cipher.matches(
                    first,
                    username,
                    folder,
                    ignore_case,
                    strict_username,
                    strict_folder,
                    exact,
                ) {
                    return false;
                }
                // Remaining needles must match name/id only (no user/folder
                // filtering)
                rest.iter().all(|n| {
                    decrypted_cipher.matches(
                        n,
                        None,
                        None,
                        ignore_case,
                        false,
                        false,
                        exact,
                    )
                })
            })
            .cloned()
            .collect()
    };

    for exact in [true, false] {
        let nonstrict: Vec<(rbw::db::Entry, DecryptedSearchCipher)> =
            find_matches(false, false, exact);

        if nonstrict.len() == 1 {
            return Ok(nonstrict[0].clone());
        }

        if nonstrict.len() > 1 {
            // Only apply strict username/folder tiebreaking when every
            // candidate has the same name.  If names differ these are
            // genuinely distinct entries — silently picking one would be
            // wrong; the caller should get an ambiguity error instead.
            let first_name = nonstrict[0].1.name.as_str();
            let all_same_name =
                nonstrict.iter().all(|(_, d)| d.name == first_name);

            if all_same_name {
                let strict_both = find_matches(true, true, exact);
                if strict_both.len() == 1 {
                    return Ok(strict_both[0].clone());
                }
                let strict_folder = find_matches(false, true, exact);
                let strict_username = find_matches(true, false, exact);
                if strict_folder.len() == 1 && strict_username.len() != 1 {
                    return Ok(strict_folder[0].clone());
                } else if strict_folder.len() != 1
                    && strict_username.len() == 1
                {
                    return Ok(strict_username[0].clone());
                }
            }

            matches = nonstrict;
        }
    }

    let needle_str = needles
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");

    if matches.is_empty() {
        Err(anyhow::anyhow!("no entry found"))
    } else {
        let entries: Vec<String> = matches
            .iter()
            .map(|(_, decrypted)| format_ambiguous_entry(decrypted))
            .collect();
        Err(anyhow::anyhow!(
            "multiple entries found:\n{}\n\nTry `rbw list {needle_str}` to inspect the matches, or add --user/--folder to disambiguate.",
            entries.join("\n"),
        ))
    }
}

fn decrypt_field(
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| crate::actions::decrypt(field, entry_key, org_id))
        .transpose();
    match field {
        Ok(field) => field,
        Err(e) => {
            log::warn!("failed to decrypt {name}: {e}");
            None
        }
    }
}

// Accumulates the cipherstrings to be decrypted in a single `decrypt_batch`
// call. `push` returns the index at which the corresponding plaintext will
// appear in the results vector, which the cipher plans record and later
// resolve.
struct BatchRequests(Vec<rbw::protocol::DecryptRequest>);

impl BatchRequests {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(
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

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn into_vec(self) -> Vec<rbw::protocol::DecryptRequest> {
        self.0
    }
}

fn entry_type_name(data: &rbw::db::EntryData) -> &'static str {
    match data {
        rbw::db::EntryData::Login { .. } => "Login",
        rbw::db::EntryData::Identity { .. } => "Identity",
        rbw::db::EntryData::SshKey { .. } => "SSH Key",
        rbw::db::EntryData::SecureNote => "Note",
        rbw::db::EntryData::Card { .. } => "Card",
    }
}

// A plan describing which batch-decrypt results make up a single list entry.
// The `usize` fields are indices into the flat results vector returned by
// `decrypt_batch`; `entry_type` needs no decryption so it is resolved up front.
struct ListCipherPlan {
    id: String,
    name: Option<usize>,
    user: Option<usize>,
    password: Option<usize>,
    folder: Option<usize>,
    uris: Option<Vec<usize>>,
    entry_type: Option<String>,
    collection_ids: Option<Vec<String>>,
    attachment_count: usize,
}

impl ListCipherPlan {
    fn build(
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
            attachment_count: entry.attachments.len(),
        }
    }

    fn resolve(
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
            attachment_metadata,
        })
    }
}

fn strict_result(
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

fn lenient_result(
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
struct SearchCipherPlan {
    id: String,
    entry_type: String,
    name: usize,
    user: Option<usize>,
    folder: Option<usize>,
    notes: Option<usize>,
    uris: Vec<(usize, Option<rbw::api::UriMatchType>)>,
    fields: Vec<usize>,
    sensitive_fields: Vec<usize>,
    attachment_count: usize,
    password: Option<usize>,
}

impl SearchCipherPlan {
    fn build(entry: &rbw::db::Entry, requests: &mut BatchRequests) -> Self {
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
            v.map(|s| requests.push(s, entry.key.as_deref(), entry.org_id.as_deref()))
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
            password: password_idx,
        }
    }

    fn resolve(
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
            .filter_map(|&index| lenient_result(&results[index], Field::Password))
            .collect();

        let password = self
            .password
            .and_then(|index| lenient_result(&results[index], Field::Password));

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
            password,
        })
    }
}

fn decrypt_search_cipher(
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
        password: login_password,
    })
}

fn decrypt_cipher(entry: &rbw::db::Entry) -> anyhow::Result<DecryptedCipher> {
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
    let history = entry
        .history
        .iter()
        .map(|history_entry| {
            Ok(DecryptedHistoryEntry {
                last_used_date: history_entry.last_used_date.clone(),
                password: crate::actions::decrypt(
                    &history_entry.password,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )?,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let attachments: Vec<_> = entry
        .attachments
        .iter()
        .map(|attachment| DecryptedAttachment {
            id: attachment.id.clone(),
            file_name: decrypt_field(
                Field::Name,
                attachment.file_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
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
    })
}

fn uri_match_type_str(mt: rbw::api::UriMatchType) -> &'static str {
    match mt {
        rbw::api::UriMatchType::Domain => "domain",
        rbw::api::UriMatchType::Host => "host",
        rbw::api::UriMatchType::StartsWith => "starts_with",
        rbw::api::UriMatchType::Exact => "exact",
        rbw::api::UriMatchType::RegularExpression => "regular_expression",
        rbw::api::UriMatchType::Never => "never",
    }
}

fn parse_uri_match_type(
    s: &str,
) -> anyhow::Result<rbw::api::UriMatchType> {
    match s {
        "domain" => Ok(rbw::api::UriMatchType::Domain),
        "host" => Ok(rbw::api::UriMatchType::Host),
        "starts_with" => Ok(rbw::api::UriMatchType::StartsWith),
        "exact" => Ok(rbw::api::UriMatchType::Exact),
        "regular_expression" => {
            Ok(rbw::api::UriMatchType::RegularExpression)
        }
        "never" => Ok(rbw::api::UriMatchType::Never),
        other => Err(anyhow::anyhow!("unknown uri match type: '{other}'")),
    }
}

fn field_type_str(ft: rbw::api::FieldType) -> &'static str {
    match ft {
        rbw::api::FieldType::Text => "text",
        rbw::api::FieldType::Hidden => "hidden",
        rbw::api::FieldType::Boolean => "boolean",
        rbw::api::FieldType::Linked => "linked",
    }
}

fn parse_field_type(s: &str) -> anyhow::Result<rbw::api::FieldType> {
    match s {
        "text" => Ok(rbw::api::FieldType::Text),
        "hidden" => Ok(rbw::api::FieldType::Hidden),
        "boolean" => Ok(rbw::api::FieldType::Boolean),
        "linked" => Ok(rbw::api::FieldType::Linked),
        other => Err(anyhow::anyhow!("unknown field type: '{other}'")),
    }
}

fn decrypted_to_editable(decrypted: &DecryptedCipher) -> EditableCipher {
    let data = match &decrypted.data {
        DecryptedData::Login {
            username,
            password,
            totp,
            uris,
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

fn editable_to_encrypted(
    editable: &EditableCipher,
    org_id: Option<&str>,
) -> anyhow::Result<(
    rbw::db::EntryData,
    Vec<rbw::db::Field>,
    Option<String>,
)> {
    let data = match &editable.data {
        EditableData::Login {
            username,
            password,
            uris,
            totp,
        } => {
            let username = username
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|u| crate::actions::encrypt(u, org_id))
                .transpose()?;
            let password = password
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|p| crate::actions::encrypt(p, org_id))
                .transpose()?;
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
                        uri: crate::actions::encrypt(&u.uri, org_id)?,
                        match_type,
                    })
                })
                .collect::<anyhow::Result<_>>()?;
            let totp = totp
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|t| crate::actions::encrypt(t, org_id))
                .transpose()?;
            rbw::db::EntryData::Login {
                username,
                password,
                uris,
                totp,
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
                    .map(|v| crate::actions::encrypt(v, org_id))
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
                    .map(|v| crate::actions::encrypt(v, org_id))
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
                    .map(|v| crate::actions::encrypt(v, org_id))
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
            let ty = f
                .ty
                .as_deref()
                .map(parse_field_type)
                .transpose()?;
            let name = f
                .name
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|n| crate::actions::encrypt(n, org_id))
                .transpose()?;
            let value = f
                .value
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|v| crate::actions::encrypt(v, org_id))
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

fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            rbw::db::Db::load(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            db.save(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

fn remove_db() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    config.email.as_ref().map_or_else(
        || Err(anyhow::anyhow!("failed to find email address in config")),
        |email| {
            rbw::db::Db::remove(&config.server_name(), email)
                .map_err(anyhow::Error::new)
        },
    )
}

struct TotpParams {
    secret: Vec<u8>,
    algorithm: String,
    digits: usize,
    period: u64,
}

fn decode_totp_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    let secret = secret.trim().replace(' ', "");
    let alphabets = [
        base32::Alphabet::Rfc4648 { padding: false },
        base32::Alphabet::Rfc4648 { padding: true },
        base32::Alphabet::Rfc4648Lower { padding: false },
        base32::Alphabet::Rfc4648Lower { padding: true },
    ];
    for alphabet in alphabets {
        if let Some(secret) = base32::decode(alphabet, &secret) {
            return Ok(secret);
        }
    }
    Err(anyhow::anyhow!("totp secret was not valid base32"))
}

fn parse_totp_secret(secret: &str) -> anyhow::Result<TotpParams> {
    if let Ok(u) = url::Url::parse(secret) {
        match u.scheme() {
            "otpauth" => {
                if u.host_str() != Some("totp") {
                    return Err(anyhow::anyhow!(
                        "totp secret url must have totp host"
                    ));
                }

                let query: std::collections::HashMap<_, _> =
                    u.query_pairs().collect();

                let secret = decode_totp_secret(
                    query.get("secret").ok_or_else(|| {
                        anyhow::anyhow!("totp secret url must have secret")
                    })?,
                )?;
                let algorithm = query.get("algorithm").map_or_else(
                    || String::from("SHA1"),
                    std::string::ToString::to_string,
                );
                let digits = match query.get("digits") {
                    Some(dig) => dig
                        .parse::<usize>()
                        .map_err(|_| anyhow::anyhow!("digits parameter in totp url must be a valid integer."))?,
                    None => 6,
                };
                let period = match query.get("period") {
                    Some(dig) => {
                        dig.parse::<u64>().map_err(|_| anyhow::anyhow!("period parameter in totp url must be a valid integer."))?
                    }
                    None => TOTP_DEFAULT_STEP,
                };

                Ok(TotpParams {
                    secret,
                    algorithm,
                    digits,
                    period,
                })
            }
            "steam" => {
                let steam_secret = u.host_str().unwrap();

                Ok(TotpParams {
                    secret: decode_totp_secret(steam_secret)?,
                    algorithm: String::from("STEAM"),
                    digits: 5,
                    period: TOTP_DEFAULT_STEP,
                })
            }
            _ => Err(anyhow::anyhow!(
                "totp secret url must have 'otpauth' or 'steam' scheme"
            )),
        }
    } else {
        Ok(TotpParams {
            secret: decode_totp_secret(secret)?,
            algorithm: String::from("SHA1"),
            digits: 6,
            period: TOTP_DEFAULT_STEP,
        })
    }
}

struct InjectContext {
    entries: Vec<rbw::db::Entry>,
}

impl InjectContext {
    fn load() -> anyhow::Result<Self> {
        unlock(None)?;

        let db = load_db()?;
        Ok(Self {
            entries: db.entries,
        })
    }

    fn render_input(
        &self,
        input: Option<&std::path::Path>,
    ) -> anyhow::Result<String> {
        let template = read_inject_template(input)?;
        InjectTemplate::new(&template)
            .render(|reference| self.resolve(reference))
    }

    fn env_bindings_from_file(
        &self,
        env_file: &std::path::Path,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let template =
            std::fs::read_to_string(env_file).with_context(|| {
                format!("failed to read env file {}", env_file.display())
            })?;
        parse_run_env_file(&template, |reference| self.resolve(reference))
            .with_context(|| {
                format!("failed to parse env file {}", env_file.display())
            })
    }

    fn resolve(&self, reference: &InjectReference) -> anyhow::Result<String> {
        let (entry, _) = self.find_entry_raw(&reference.target)?;
        let decrypted = decrypt_cipher(&entry).with_context(|| {
            format!("failed to decrypt entry '{}'", reference.id)
        })?;
        resolve_inject_value(&decrypted, reference.field.as_deref())
            .with_context(|| {
                format!(
                    "failed to resolve inject reference '{}'",
                    reference.id
                )
            })
    }

    fn find_entry_raw(
        &self,
        target: &InjectReferenceTarget,
    ) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                decrypt_search_cipher(entry)
                    .map(|decrypted| (entry.clone(), decrypted))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        target.find_entry(&entries)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum InjectReferenceTarget {
    Uuid(String),
    Name(String),
}

impl InjectReferenceTarget {
    fn parse(raw_target: &str) -> anyhow::Result<Self> {
        if let Ok(uuid) = uuid::Uuid::parse_str(raw_target) {
            Ok(Self::Uuid(uuid.to_string()))
        } else if Self::is_valid_name(raw_target) {
            Ok(Self::Name(raw_target.to_string()))
        } else {
            anyhow::bail!(
                "invalid item uuid or supported name '{raw_target}'"
            );
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Uuid(value) | Self::Name(value) => value,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Uuid(_) => "id",
            Self::Name(_) => "name",
        }
    }

    fn matches_entry(
        &self,
        entry: &rbw::db::Entry,
        decrypted: &DecryptedSearchCipher,
    ) -> bool {
        match self {
            Self::Uuid(id) => entry.id.eq_ignore_ascii_case(id),
            Self::Name(name) => decrypted.name.eq_ignore_ascii_case(name),
        }
    }

    fn find_entry(
        &self,
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
    ) -> anyhow::Result<(rbw::db::Entry, DecryptedSearchCipher)> {
        let matches: Vec<(rbw::db::Entry, DecryptedSearchCipher)> = entries
            .iter()
            .filter(|(entry, decrypted)| self.matches_entry(entry, decrypted))
            .cloned()
            .collect();

        if matches.is_empty() {
            anyhow::bail!(
                "no entry found for item {} '{}'",
                self.kind(),
                self.as_str()
            );
        } else if matches.len() == 1 {
            Ok(matches[0].clone())
        } else {
            let entries: Vec<String> = matches
                .iter()
                .map(|(_, decrypted)| decrypted.display_name())
                .collect();
            match self {
                Self::Name(name) => anyhow::bail!(
                    "multiple entries found for item name '{}': {}; use bw://<uuid> instead",
                    name,
                    entries.join(", ")
                ),
                Self::Uuid(id) => anyhow::bail!(
                    "multiple entries found for item id '{}': {}",
                    id,
                    entries.join(", ")
                ),
            }
        }
    }

    fn is_valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.chars().all(|ch| {
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
            })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct InjectReference {
    id: String,
    target: InjectReferenceTarget,
    field: Option<String>,
}

impl InjectReference {
    fn parse(reference: &str) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(reference).with_context(|| {
            format!("invalid inject reference '{reference}'")
        })?;
        if parsed.scheme() != "bw" {
            anyhow::bail!(
                "invalid inject reference scheme '{}'",
                parsed.scheme()
            );
        }
        if parsed.fragment().is_some() {
            anyhow::bail!("inject references do not support fragments");
        }
        if !parsed.username().is_empty() {
            anyhow::bail!("inject references do not support usernames");
        }
        if parsed.password().is_some() {
            anyhow::bail!("inject references do not support passwords");
        }
        if parsed.port().is_some() {
            anyhow::bail!("inject references do not support ports");
        }
        if !parsed.path().is_empty() {
            anyhow::bail!("inject references do not support paths");
        }

        let raw_target = parsed
            .host_str()
            .context("inject reference is missing an item id or name")?;
        let target = InjectReferenceTarget::parse(raw_target)?;

        let mut field = None;
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "field" => {
                    if field.replace(value.into_owned()).is_some() {
                        anyhow::bail!(
                            "inject reference has multiple field parameters"
                        );
                    }
                }
                _ => anyhow::bail!(
                    "unsupported inject query parameter '{key}'"
                ),
            }
        }

        let field = field
            .map(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    anyhow::bail!(
                        "inject field query parameter cannot be empty"
                    );
                }
                Ok(trimmed.to_string())
            })
            .transpose()?;

        Ok(Self {
            id: target.as_str().to_string(),
            target,
            field,
        })
    }

    fn parse_braced(expr: &str) -> anyhow::Result<Option<Self>> {
        let expr = expr.trim();
        let expr = if expr.starts_with('"') {
            match serde_json::from_str::<String>(expr) {
                Ok(expr) => expr,
                Err(_) => return Ok(None),
            }
        } else {
            expr.to_string()
        };
        if !expr.starts_with("bw://") {
            return Ok(None);
        }
        Self::parse(&expr).map(Some)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum InjectMarker {
    Braced,
    Raw,
}

struct InjectTemplate<'a> {
    src: &'a str,
}

impl<'a> InjectTemplate<'a> {
    fn new(src: &'a str) -> Self {
        Self { src }
    }

    fn render<F>(&self, mut resolver: F) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        self.render_with_variable_resolver(
            lookup_inject_template_variable,
            |reference| resolver(reference),
        )
    }

    fn render_with_variable_resolver<F, G>(
        &self,
        mut lookup_variable: G,
        mut resolver: F,
    ) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
        G: FnMut(&str) -> Option<String>,
    {
        let expanded =
            self.expand_variables_with_lookup(&mut lookup_variable)?;
        InjectTemplate::new(&expanded)
            .render_secret_references(|reference| resolver(reference))
    }

    fn render_secret_references<F>(
        &self,
        mut resolver: F,
    ) -> anyhow::Result<String>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let mut rendered = String::with_capacity(self.src.len());
        let mut start = 0;
        while let Some((idx, marker)) = self.next_marker(start) {
            rendered.push_str(
                self.src
                    .get(start..idx)
                    .expect("marker range should be valid"),
            );
            start = match marker {
                InjectMarker::Braced => {
                    self.render_braced(idx, &mut rendered, &mut resolver)?
                }
                InjectMarker::Raw => {
                    self.render_raw(idx, &mut rendered, &mut resolver)?
                }
            };
        }
        rendered.push_str(
            self.src
                .get(start..)
                .expect("template tail range should be valid"),
        );
        Ok(rendered)
    }

    fn expand_variables_with_lookup<G>(
        &self,
        lookup_variable: &mut G,
    ) -> anyhow::Result<String>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let mut rendered = String::with_capacity(self.src.len());
        let mut start = 0;
        while let Some(offset) = self
            .src
            .get(start..)
            .expect("variable search start should be valid")
            .find('$')
        {
            let idx = start + offset;
            rendered.push_str(
                self.src
                    .get(start..idx)
                    .expect("variable prefix range should be valid"),
            );
            if let Some((value, next_start)) =
                self.resolve_variable_at(idx, lookup_variable)?
            {
                rendered.push_str(&value);
                start = next_start;
            } else {
                rendered.push('$');
                start = idx + '$'.len_utf8();
            }
        }
        rendered.push_str(
            self.src
                .get(start..)
                .expect("variable tail range should be valid"),
        );
        Ok(rendered)
    }

    fn take_braced_expression(
        &self,
        idx: usize,
    ) -> anyhow::Result<(&'a str, usize)> {
        let rest = self
            .src
            .get(idx..)
            .expect("braced expression start should be valid")
            .strip_prefix("{{")
            .expect("braced expression must start with '{{'");
        let Some((expr, tail)) = rest.split_once("}}") else {
            anyhow::bail!("unterminated inject template expression");
        };
        Ok((expr, self.src.len() - tail.len()))
    }

    fn render_braced<F>(
        &self,
        idx: usize,
        out: &mut String,
        resolver: &mut F,
    ) -> anyhow::Result<usize>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let (expr, next_start) = self.take_braced_expression(idx)?;
        if let Some(reference) = InjectReference::parse_braced(expr)? {
            out.push_str(&resolver(&reference)?);
        } else {
            out.push_str("{{");
            out.push_str(expr);
            out.push_str("}}");
        }
        Ok(next_start)
    }

    fn render_raw<F>(
        &self,
        idx: usize,
        out: &mut String,
        resolver: &mut F,
    ) -> anyhow::Result<usize>
    where
        F: FnMut(&InjectReference) -> anyhow::Result<String>,
    {
        let end = self.raw_reference_end(idx);
        let candidate = self
            .src
            .get(idx..end)
            .expect("raw reference range should be valid");
        let reference = InjectReference::parse(candidate)?;
        out.push_str(&resolver(&reference)?);
        Ok(end)
    }

    fn resolve_variable_at<G>(
        &self,
        idx: usize,
        lookup_variable: &mut G,
    ) -> anyhow::Result<Option<(String, usize)>>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let rest = self
            .src
            .get(idx + '$'.len_utf8()..)
            .expect("variable suffix range should be valid");
        match rest.chars().next() {
            Some('{') => self.resolve_braced_variable(idx, lookup_variable),
            Some(ch) if Self::is_valid_variable_start(ch) => {
                let name_len = rest
                    .char_indices()
                    .take_while(|(_, ch)| {
                        Self::is_valid_variable_continue(*ch)
                    })
                    .last()
                    .map_or(0, |(offset, ch)| offset + ch.len_utf8());
                let name = rest
                    .get(..name_len)
                    .expect("raw variable name range should be valid");
                if let Some(value) = lookup_variable(name) {
                    Ok(Some((value, idx + '$'.len_utf8() + name_len)))
                } else {
                    anyhow::bail!(
                        "inject template variable '{name}' is not set"
                    );
                }
            }
            _ => Ok(None),
        }
    }

    fn resolve_braced_variable<G>(
        &self,
        idx: usize,
        lookup_variable: &mut G,
    ) -> anyhow::Result<Option<(String, usize)>>
    where
        G: FnMut(&str) -> Option<String>,
    {
        let expr_start = idx + "${".len();
        let rest = self
            .src
            .get(expr_start..)
            .expect("braced variable start should be valid");
        let mut depth = 1usize;
        let mut end = None;
        let mut offset = 0;
        while offset < rest.len() {
            let tail = rest
                .get(offset..)
                .expect("braced variable tail range should be valid");
            if tail.starts_with("\\}") {
                offset += "\\}".len();
                continue;
            }
            if tail.starts_with("${") {
                depth += 1;
                offset += "${".len();
                continue;
            }
            let ch = tail
                .chars()
                .next()
                .expect("braced variable tail should not be empty");
            if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    end = Some(expr_start + offset);
                    break;
                }
            }
            offset += ch.len_utf8();
        }
        let end = end.context("unterminated inject template variable")?;
        let expr = self
            .src
            .get(expr_start..end)
            .expect("braced variable expression range should be valid");
        let (name, default) = match expr.split_once(":-") {
            Some((name, default)) => (name.trim(), Some(default)),
            None => (expr.trim(), None),
        };
        if !Self::is_valid_variable_name(name) {
            return Ok(None);
        }
        let value = if let Some(value) = lookup_variable(name) {
            value
        } else if let Some(default) = default {
            InjectTemplate::new(default)
                .expand_variables_with_lookup(lookup_variable)?
        } else {
            anyhow::bail!("inject template variable '{name}' is not set");
        };
        Ok(Some((value, end + '}'.len_utf8())))
    }

    fn next_marker(&self, start: usize) -> Option<(usize, InjectMarker)> {
        let rest = self
            .src
            .get(start..)
            .expect("marker search start should be valid");
        let braced = rest
            .find("{{")
            .map(|offset| (start + offset, InjectMarker::Braced));
        let raw = rest
            .match_indices("bw://")
            .map(|(offset, _)| start + offset)
            .find(|&idx| Self::raw_reference_can_start(self.src, idx))
            .map(|idx| (idx, InjectMarker::Raw));

        match (braced, raw) {
            (Some(braced), Some(raw)) => {
                Some(if braced.0 <= raw.0 { braced } else { raw })
            }
            (Some(braced), None) => Some(braced),
            (None, Some(raw)) => Some(raw),
            (None, None) => None,
        }
    }

    fn raw_reference_end(&self, start: usize) -> usize {
        let mut end = start + "bw://".len();
        let mut seen_query = false;
        let mut seen_query_equals = false;
        for (offset, ch) in self
            .src
            .get(end..)
            .expect("raw reference start should be valid")
            .char_indices()
        {
            let is_allowed = if ch.is_ascii_alphanumeric()
                || matches!(ch, '-' | '_')
                || (seen_query_equals && matches!(ch, '.' | '%' | '+'))
            {
                true
            } else if ch == '?' && !seen_query {
                seen_query = true;
                true
            } else if ch == '=' && seen_query && !seen_query_equals {
                seen_query_equals = true;
                true
            } else {
                false
            };
            if !is_allowed {
                break;
            }
            end = start + "bw://".len() + offset + ch.len_utf8();
        }
        end
    }

    fn raw_reference_can_start(template: &str, idx: usize) -> bool {
        template
            .get(..idx)
            .and_then(|prefix| prefix.chars().next_back())
            .is_none_or(|ch| {
                !ch.is_ascii_alphanumeric()
                    && !matches!(ch, '-' | '+' | '\\' | '.')
            })
    }

    fn is_valid_variable_name(name: &str) -> bool {
        let mut chars = name.chars();
        matches!(chars.next(), Some(ch) if Self::is_valid_variable_start(ch))
            && chars.all(Self::is_valid_variable_continue)
    }

    fn is_valid_variable_start(ch: char) -> bool {
        ch.is_ascii_alphabetic() || ch == '_'
    }

    fn is_valid_variable_continue(ch: char) -> bool {
        ch.is_ascii_alphanumeric() || ch == '_'
    }
}

fn lookup_inject_template_variable(name: &str) -> Option<String> {
    std::env::vars().find_map(|(key, value)| {
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

fn read_inject_template(
    input: Option<&std::path::Path>,
) -> anyhow::Result<String> {
    let mut template = String::new();
    match input {
        Some(path) => {
            std::fs::File::open(path)
                .with_context(|| {
                    format!("failed to open template {}", path.display())
                })?
                .read_to_string(&mut template)
                .with_context(|| {
                    format!("failed to read template {}", path.display())
                })?;
        }
        None => {
            std::io::stdin()
                .read_to_string(&mut template)
                .context("failed to read template from stdin")?;
        }
    }
    Ok(template)
}

fn parse_run_env_file<F>(
    template: &str,
    mut resolver: F,
) -> anyhow::Result<Vec<(String, String)>>
where
    F: FnMut(&InjectReference) -> anyhow::Result<String>,
{
    dotenvy::from_read_iter(std::io::Cursor::new(template))
        .map(|item| {
            let (key, value) = item.map_err(anyhow::Error::from)?;
            InjectTemplate::new(&value)
                .render_secret_references(|reference| resolver(reference))
                .map(|rendered| (key, rendered))
        })
        .collect()
}

fn build_inject_run_command(
    command: &[OsString],
    env_bindings: &[(String, String)],
) -> anyhow::Result<std::process::Command> {
    let Some(program) = command.first() else {
        anyhow::bail!("missing child command");
    };

    let mut child = std::process::Command::new(program);
    child.args(&command[1..]);
    child.stdin(std::process::Stdio::inherit());
    child.stdout(std::process::Stdio::inherit());
    child.stderr(std::process::Stdio::inherit());
    for (key, value) in env_bindings {
        child.env(key, value);
    }
    Ok(child)
}

fn run_inject_command(
    command: &[OsString],
    env_bindings: &[(String, String)],
) -> anyhow::Result<std::process::ExitStatus> {
    let mut child = build_inject_run_command(command, env_bindings)?;
    child.status().with_context(|| {
        let program = command.first().map_or_else(
            || "<missing command>".to_string(),
            |program| program.to_string_lossy().into_owned(),
        );
        format!("failed to run child command '{program}'")
    })
}

fn resolve_inject_value(
    cipher: &DecryptedCipher,
    field: Option<&str>,
) -> anyhow::Result<String> {
    let normalized = field
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .map(str::to_lowercase);
    match normalized.as_deref() {
        None | Some("password") => match &cipher.data {
            DecryptedData::Login {
                password: Some(password),
                ..
            } => Ok(password.clone()),
            DecryptedData::Login { .. } => {
                anyhow::bail!("entry '{}' has no password", cipher.name)
            }
            _ => {
                anyhow::bail!("entry '{}' is not a login entry", cipher.name)
            }
        },
        Some("username" | "user") => match &cipher.data {
            DecryptedData::Login {
                username: Some(username),
                ..
            } => Ok(username.clone()),
            DecryptedData::Login { .. } => {
                anyhow::bail!("entry '{}' has no username", cipher.name)
            }
            _ => {
                anyhow::bail!("entry '{}' is not a login entry", cipher.name)
            }
        },
        Some(field) => cipher
            .fields
            .iter()
            .find(|custom| {
                custom
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(field))
            })
            .and_then(|custom| custom.value.clone())
            .with_context(|| {
                format!(
                    "entry '{}' has no field named '{}'",
                    cipher.name, field
                )
            }),
    }
}

fn write_rendered_template_file(
    path: &std::path::Path,
    rendered: &str,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "rendered template target '{}' must not be a symlink",
                        path.display()
                    );
                }
                if !metadata.file_type().is_file() {
                    anyhow::bail!(
                        "rendered template target '{}' is not a regular file",
                        path.display()
                    );
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect rendered template {}",
                        path.display()
                    )
                });
            }
        }

        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => std::path::Path::new("."),
        };
        let mut file = tempfile::Builder::new()
            .prefix(".rbw-rendered-template.")
            .tempfile_in(parent)
            .with_context(|| {
                format!(
                    "failed to open temporary rendered template near {}",
                    path.display()
                )
            })?;
        file.as_file_mut()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to set secure permissions on {}",
                    path.display()
                )
            })?;
        file.write_all(rendered.as_bytes()).with_context(|| {
            format!("failed to write rendered template {}", path.display())
        })?;
        file.as_file_mut().sync_all().with_context(|| {
            format!("failed to sync rendered template {}", path.display())
        })?;
        file.persist(path)
            .map_err(|err| err.error)
            .with_context(|| {
                format!(
                    "failed to persist rendered template {}",
                    path.display()
                )
            })?;
        std::fs::File::open(parent)
            .with_context(|| {
                format!(
                    "failed to sync rendered template directory {}",
                    parent.display()
                )
            })?
            .sync_all()
            .with_context(|| {
                format!(
                    "failed to sync rendered template directory {}",
                    parent.display()
                )
            })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, rendered).with_context(|| {
            format!("failed to write rendered template {}", path.display())
        })?;
        Ok(())
    }
}

// This function exists for the sake of making the generate_totp function less
// densely packed and more readable
fn generate_totp_algorithm_type(
    alg: &str,
) -> anyhow::Result<totp_rs::Algorithm> {
    match alg {
        "SHA1" => Ok(totp_rs::Algorithm::SHA1),
        "SHA256" => Ok(totp_rs::Algorithm::SHA256),
        "SHA512" => Ok(totp_rs::Algorithm::SHA512),
        "STEAM" => Ok(totp_rs::Algorithm::Steam),
        _ => Err(anyhow::anyhow!(format!("{alg} is not a valid algorithm"))),
    }
}

fn generate_totp(secret: &str) -> anyhow::Result<String> {
    let totp_params = parse_totp_secret(secret)?;
    let alg = totp_params.algorithm.as_str();

    match alg {
        "SHA1" | "SHA256" | "SHA512" => Ok(totp_rs::TOTP::new_unchecked(
            generate_totp_algorithm_type(alg)?,
            totp_params.digits,
            1, // the library docs say this should be a 1
            totp_params.period,
            totp_params.secret,
        )
        .generate_current()?),
        "STEAM" => Ok(totp_rs::TOTP::new_steam(totp_params.secret)
            .generate_current()?),
        _ => Err(anyhow::anyhow!(format!(
            "{alg} is not a valid totp algorithm"
        ))),
    }
}

fn display_field(name: &str, field: Option<&str>, clipboard: bool) -> bool {
    field.map_or_else(
        || false,
        |field| {
            val_display_or_store(
                clipboard,
                &format!("{}: {field}", format_label(name)),
            )
        },
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_attachment_metadata_serializes_attachment_count() {
        let metadata = AttachmentMetadata::new("cipher-id", 2);

        assert_eq!(
            serde_json::to_value(&metadata).unwrap(),
            serde_json::json!({
                "attachment_count": 2
            })
        );
    }

    #[test]
    fn test_attachment_metadata_omits_empty_json_fields() {
        let metadata = AttachmentMetadata::new("cipher-id", 0);

        assert_eq!(
            serde_json::to_value(&metadata).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn test_list_field_accepts_uid_alias() {
        let field = "uid".to_string();

        assert!(matches!(
            ListField::try_from(&field).unwrap(),
            ListField::Id
        ));
    }

    #[test]
    fn test_format_ambiguous_entry_renders_multiline_details() {
        let rendered = format_ambiguous_entry(&DecryptedSearchCipher {
            id: "cipher-id".to_string(),
            entry_type: "Login".to_string(),
            folder: Some("mail".to_string()),
            name: "google.com".to_string(),
            user: Some("alice@example.com".to_string()),
            uris: vec![],
            fields: vec![],
            notes: None,
            attachment_count: 2,
            sensitive_fields: vec![],
            password: None,
        });

        assert_eq!(
            rendered,
            "  - google.com (uid: cipher-id | username: alice@example.com | folder: mail | attachments: 2)"
        );
    }

    #[test]
    fn test_search_match_respects_with_attachments_filter() {
        let entry = DecryptedSearchCipher {
            id: "cipher-id".to_string(),
            entry_type: "Login".to_string(),
            folder: None,
            name: "example".to_string(),
            user: None,
            uris: vec![],
            fields: vec![],
            notes: None,
            attachment_count: 0,
            sensitive_fields: vec![],
            password: None,
        };

        assert!(entry.search_match("exa", None, false));
        assert!(!entry.search_match("exa", None, true));
    }

    #[test]
    fn test_render_table_row_aligns_columns_with_padding() {
        let row =
            vec!["UID".to_string(), "NAME".to_string(), "USER".to_string()];
        let widths = vec![5, 10, 4];

        let rendered =
            render_table_row(&row, &widths, |_, cell| cell.to_string());

        assert_eq!(rendered, "UID    NAME        USER");
    }

    #[test]
    fn test_available_attachments_error_lists_candidates() {
        let error = available_attachments_error(
            "example",
            &[DecryptedAttachment {
                id: "id-1".to_string(),
                file_name: Some("invoice.pdf".to_string()),
                size: None,
                size_name: Some("1 KB".to_string()),
            }],
            "attachment 'foo' was not found",
        );

        let message = error.to_string();
        assert!(message.contains("attachment 'foo' was not found"));
        assert!(message.contains("Available attachments for 'example':"));
        assert!(message.contains("id-1\tinvoice.pdf\t1 KB"));
    }

    #[test]
    fn test_find_entry() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry("gitter", Some("baz"), None, &[]),
            make_entry("git", Some("foo"), None, &[]),
            make_entry("bitwarden", None, None, &[]),
            make_entry("github", Some("foo"), Some("websites"), &[]),
            make_entry("github", Some("foo"), Some("ssh"), &[]),
            make_entry("github", Some("root"), Some("ssh"), &[]),
            make_entry("codeberg", Some("foo"), None, &[]),
            make_entry("codeberg", None, None, &[]),
            make_entry("1password", Some("foo"), None, &[]),
            make_entry("1password", None, Some("foo"), &[]),
        ];

        assert!(
            one_match(entries, "github", Some("foo"), None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), None, 0, true),
            "foo@GITHUB"
        );
        assert!(one_match(entries, "github", None, None, 0, false), "github");
        assert!(one_match(entries, "GITHUB", None, None, 0, true), "GITHUB");
        assert!(
            one_match(entries, "gitlab", Some("foo"), None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, "GITLAB", Some("foo"), None, 1, true),
            "foo@GITLAB"
        );
        assert!(
            one_match(entries, "git", Some("bar"), None, 2, false),
            "bar@git"
        );
        assert!(
            one_match(entries, "GIT", Some("bar"), None, 2, true),
            "bar@GIT"
        );
        assert!(
            one_match(entries, "gitter", Some("ba"), None, 3, false),
            "ba@gitter"
        );
        assert!(
            one_match(entries, "GITTER", Some("ba"), None, 3, true),
            "ba@GITTER"
        );
        assert!(
            one_match(entries, "git", Some("foo"), None, 4, false),
            "foo@git"
        );
        assert!(
            one_match(entries, "GIT", Some("foo"), None, 4, true),
            "foo@GIT"
        );
        assert!(one_match(entries, "git", None, None, 4, false), "git");
        assert!(one_match(entries, "GIT", None, None, 4, true), "GIT");
        assert!(
            one_match(entries, "bitwarden", None, None, 5, false),
            "bitwarden"
        );
        assert!(
            one_match(entries, "BITWARDEN", None, None, 5, true),
            "BITWARDEN"
        );
        assert!(
            one_match(
                entries,
                "github",
                Some("foo"),
                Some("websites"),
                6,
                false
            ),
            "websites/foo@github"
        );
        assert!(
            one_match(
                entries,
                "GITHUB",
                Some("foo"),
                Some("websites"),
                6,
                true
            ),
            "websites/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("foo"), Some("ssh"), 7, false),
            "ssh/foo@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("foo"), Some("ssh"), 7, true),
            "ssh/foo@GITHUB"
        );
        assert!(
            one_match(entries, "github", Some("root"), None, 8, false),
            "ssh/root@github"
        );
        assert!(
            one_match(entries, "GITHUB", Some("root"), None, 8, true),
            "ssh/root@GITHUB"
        );

        assert!(
            no_matches(entries, "gitlab", Some("baz"), None, false),
            "baz@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("baz"), None, true),
            "baz@"
        );
        assert!(
            no_matches(entries, "bitbucket", Some("foo"), None, false),
            "foo@bitbucket"
        );
        assert!(
            no_matches(entries, "BITBUCKET", Some("foo"), None, true),
            "foo@BITBUCKET"
        );
        assert!(
            no_matches(entries, "github", Some("foo"), Some("bar"), false),
            "bar/foo@github"
        );
        assert!(
            no_matches(entries, "GITHUB", Some("foo"), Some("bar"), true),
            "bar/foo@"
        );
        assert!(
            no_matches(entries, "gitlab", Some("foo"), Some("bar"), false),
            "bar/foo@gitlab"
        );
        assert!(
            no_matches(entries, "GITLAB", Some("foo"), Some("bar"), true),
            "bar/foo@GITLAB"
        );

        assert!(many_matches(entries, "gitlab", None, None, false), "gitlab");
        assert!(many_matches(entries, "gitlab", None, None, true), "GITLAB");
        assert!(
            many_matches(entries, "gi", Some("foo"), None, false),
            "foo@gi"
        );
        assert!(
            many_matches(entries, "GI", Some("foo"), None, true),
            "foo@GI"
        );
        assert!(
            many_matches(entries, "git", Some("ba"), None, false),
            "ba@git"
        );
        assert!(
            many_matches(entries, "GIT", Some("ba"), None, true),
            "ba@GIT"
        );
        assert!(
            many_matches(entries, "github", Some("foo"), Some("s"), false),
            "s/foo@github"
        );
        assert!(
            many_matches(entries, "GITHUB", Some("foo"), Some("s"), true),
            "s/foo@GITHUB"
        );

        assert!(
            one_match(entries, "codeberg", Some("foo"), None, 9, false),
            "foo@codeberg"
        );
        assert!(
            one_match(entries, "codeberg", None, None, 10, false),
            "codeberg"
        );
        assert!(
            no_matches(entries, "codeberg", Some("bar"), None, false),
            "bar@codeberg"
        );

        assert!(
            many_matches(entries, "1password", None, None, false),
            "1password"
        );
    }

    #[test]
    fn test_find_by_uuid() {
        let entries = &[
            make_entry("github", Some("foo"), None, &[]),
            make_entry("gitlab", Some("foo"), None, &[]),
            make_entry("gitlab", Some("bar"), None, &[]),
            make_entry(
                "12345678-1234-1234-1234-1234567890ab",
                None,
                None,
                &[],
            ),
            make_entry(
                "12345678-1234-1234-1234-1234567890AC",
                None,
                None,
                &[],
            ),
            make_entry("123456781234123412341234567890AD", None, None, &[]),
        ];

        assert!(
            one_match(entries, &entries[0].0.id, None, None, 0, false),
            "foo@github"
        );
        assert!(
            one_match(entries, &entries[1].0.id, None, None, 1, false),
            "foo@gitlab"
        );
        assert!(
            one_match(entries, &entries[2].0.id, None, None, 2, false),
            "bar@gitlab"
        );

        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_uppercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );
        assert!(
            one_match(
                entries,
                &entries[0].0.id.to_lowercase(),
                None,
                None,
                0,
                false
            ),
            "foo@github"
        );

        assert!(one_match(entries, &entries[3].0.id, None, None, 3, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890ab",
            None,
            None,
            3,
            false
        ));
        assert!(no_matches(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            false
        ));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AB",
            None,
            None,
            3,
            true
        ));
        assert!(one_match(entries, &entries[4].0.id, None, None, 4, false));
        assert!(one_match(
            entries,
            "12345678-1234-1234-1234-1234567890AC",
            None,
            None,
            4,
            false
        ));
        assert!(one_match(entries, &entries[5].0.id, None, None, 5, false));
        assert!(one_match(
            entries,
            "123456781234123412341234567890AD",
            None,
            None,
            5,
            false
        ));
    }

    #[test]
    fn test_find_by_url_default() {
        let entries = &[
            make_entry("one", None, None, &[("https://one.com/", None)]),
            make_entry("two", None, None, &[("https://two.com/login", None)]),
            make_entry(
                "three",
                None,
                None,
                &[("https://login.three.com/", None)],
            ),
            make_entry("four", None, None, &[("four.com", None)]),
            make_entry(
                "five",
                None,
                None,
                &[("https://five.com:8080/", None)],
            ),
            make_entry("six", None, None, &[("six.com:8080", None)]),
            make_entry("seven", None, None, &[("192.168.0.128:8080", None)]),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(
                entries,
                "https://login.one.com/",
                None,
                None,
                0,
                false
            ),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_domain() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Domain))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[(
                    "192.168.0.128:8080",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(
                entries,
                "https://login.one.com/",
                None,
                None,
                0,
                false
            ),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_host() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Host),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Host))],
            ),
            make_entry(
                "seven",
                None,
                None,
                &[("192.168.0.128:8080", Some(rbw::api::UriMatchType::Host))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/other-page",
                None,
                None,
                1,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );

        assert!(
            one_match(
                entries,
                "https://five.com:8080/",
                None,
                None,
                4,
                false
            ),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            one_match(entries, "https://six.com:8080/", None, None, 5, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
        assert!(
            one_match(
                entries,
                "https://192.168.0.128:8080/",
                None,
                None,
                6,
                false
            ),
            "seven"
        );
        assert!(
            no_matches(entries, "https://192.168.0.128/", None, None, false),
            "seven"
        );
    }

    #[test]
    fn test_find_by_url_starts_with() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    "https://one.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::StartsWith),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                1,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_exact() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Exact))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Exact),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("https://four.com", Some(rbw::api::UriMatchType::Exact))],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com/foo", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );
        assert!(
            one_match(entries, "https://four.com/", None, None, 3, false),
            "four"
        );
        assert!(
            one_match(entries, "https://four.com", None, None, 3, false),
            "four"
        );
        assert!(
            no_matches(entries, "https://four.com/foo", None, None, false),
            "four"
        );
    }

    #[test]
    fn test_find_by_url_regex() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[(
                    r"^https://one\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    r"^https://two\.com/(login|start)",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    r"^https://(login\.)?three\.com/$",
                    Some(rbw::api::UriMatchType::RegularExpression),
                )],
            ),
        ];

        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            one_match(entries, "https://one.com:443/", None, None, 0, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            one_match(entries, "https://two.com/login", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(entries, "https://two.com/start", None, None, 1, false),
            "two"
        );
        assert!(
            one_match(
                entries,
                "https://two.com/login/sso",
                None,
                None,
                1,
                false
            ),
            "two"
        );
        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            one_match(
                entries,
                "https://login.three.com/",
                None,
                None,
                2,
                false
            ),
            "three"
        );
        assert!(
            one_match(entries, "https://three.com/", None, None, 2, false),
            "three"
        );
        assert!(
            no_matches(entries, "https://www.three.com/", None, None, false),
            "three"
        );
    }

    #[test]
    fn test_find_by_url_never() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[("https://one.com/", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "three",
                None,
                None,
                &[(
                    "https://login.three.com/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "four",
                None,
                None,
                &[("four.com", Some(rbw::api::UriMatchType::Never))],
            ),
            make_entry(
                "five",
                None,
                None,
                &[(
                    "https://five.com:8080/",
                    Some(rbw::api::UriMatchType::Never),
                )],
            ),
            make_entry(
                "six",
                None,
                None,
                &[("six.com:8080", Some(rbw::api::UriMatchType::Never))],
            ),
        ];

        assert!(
            no_matches(entries, "https://one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://login.one.com/", None, None, false),
            "one"
        );
        assert!(
            no_matches(entries, "https://one.com:443/", None, None, false),
            "one"
        );
        assert!(no_matches(entries, "one.com", None, None, false), "one");
        assert!(no_matches(entries, "https", None, None, false), "one");
        assert!(no_matches(entries, "com", None, None, false), "one");
        assert!(
            no_matches(entries, "https://com/", None, None, false),
            "one"
        );

        assert!(
            no_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
        assert!(
            no_matches(
                entries,
                "https://two.com/other-page",
                None,
                None,
                false
            ),
            "two"
        );

        assert!(
            no_matches(
                entries,
                "https://login.three.com/",
                None,
                None,
                false
            ),
            "three"
        );
        assert!(
            no_matches(entries, "https://three.com/", None, None, false),
            "three"
        );

        assert!(
            no_matches(entries, "https://four.com/", None, None, false),
            "four"
        );

        assert!(
            no_matches(entries, "https://five.com:8080/", None, None, false),
            "five"
        );
        assert!(
            no_matches(entries, "https://five.com/", None, None, false),
            "five"
        );

        assert!(
            no_matches(entries, "https://six.com:8080/", None, None, false),
            "six"
        );
        assert!(
            no_matches(entries, "https://six.com/", None, None, false),
            "six"
        );
    }

    #[test]
    fn test_find_with_multiple_urls() {
        let entries = &[
            make_entry(
                "one",
                None,
                None,
                &[
                    (
                        "https://one.com/",
                        Some(rbw::api::UriMatchType::Domain),
                    ),
                    (
                        "https://two.com/",
                        Some(rbw::api::UriMatchType::Domain),
                    ),
                ],
            ),
            make_entry(
                "two",
                None,
                None,
                &[(
                    "https://two.com/login",
                    Some(rbw::api::UriMatchType::Domain),
                )],
            ),
        ];

        assert!(
            no_matches(entries, "https://zero.com/", None, None, false),
            "zero"
        );
        assert!(
            one_match(entries, "https://one.com/", None, None, 0, false),
            "one"
        );
        assert!(
            many_matches(entries, "https://two.com/", None, None, false),
            "two"
        );
    }

    #[test]
    fn test_decode_totp_secret() {
        let decoded = decode_totp_secret("NBSW Y3DP EB3W 64TM MQQQ").unwrap();
        let want = b"hello world!".to_vec();
        assert!(decoded == want, "strips spaces");
    }

    #[track_caller]
    fn one_match(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        idx: usize,
        ignore_case: bool,
    ) -> bool {
        entries_eq(
            &find_entry_raw(
                entries,
                &[parse_needle(needle).unwrap()],
                username,
                folder,
                ignore_case,
            )
            .unwrap(),
            &entries[idx],
        )
    }

    #[track_caller]
    fn no_matches(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &[parse_needle(needle).unwrap()],
            username,
            folder,
            ignore_case,
        );
        if let Err(e) = res {
            format!("{e}").contains("no entry found")
        } else {
            false
        }
    }

    #[track_caller]
    fn many_matches(
        entries: &[(rbw::db::Entry, DecryptedSearchCipher)],
        needle: &str,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
    ) -> bool {
        let res = find_entry_raw(
            entries,
            &[parse_needle(needle).unwrap()],
            username,
            folder,
            ignore_case,
        );
        if let Err(e) = res {
            format!("{e}").contains("multiple entries found")
        } else {
            false
        }
    }

    #[track_caller]
    fn entries_eq(
        a: &(rbw::db::Entry, DecryptedSearchCipher),
        b: &(rbw::db::Entry, DecryptedSearchCipher),
    ) -> bool {
        a.0 == b.0 && a.1 == b.1
    }

    fn make_entry(
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
        uris: &[(&str, Option<rbw::api::UriMatchType>)],
    ) -> (rbw::db::Entry, DecryptedSearchCipher) {
        let id = uuid::Uuid::new_v4();
        (
            rbw::db::Entry {
                id: id.to_string(),
                org_id: None,
                folder: folder.map(|_| "encrypted folder name".to_string()),
                folder_id: None,
                name: "this is the encrypted name".to_string(),
                data: rbw::db::EntryData::Login {
                    username: username.map(|_| {
                        "this is the encrypted username".to_string()
                    }),
                    password: None,
                    uris: uris
                        .iter()
                        .map(|(_, match_type)| rbw::db::Uri {
                            uri: "this is the encrypted uri".to_string(),
                            match_type: *match_type,
                        })
                        .collect(),
                    totp: None,
                },
                fields: vec![],
                notes: None,
                history: vec![],
                key: None,
                master_password_reprompt: rbw::api::CipherRepromptType::None,
                collection_ids: vec![],
                attachments: vec![],
            },
            DecryptedSearchCipher {
                id: id.to_string(),
                entry_type: "Login".to_string(),
                folder: folder.map(std::string::ToString::to_string),
                name: name.to_string(),
                user: username.map(std::string::ToString::to_string),
                uris: uris
                    .iter()
                    .map(|(uri, match_type)| {
                        ((*uri).to_string(), *match_type)
                    })
                    .collect(),
                fields: vec![],
                notes: None,
                attachment_count: 0,
                sensitive_fields: vec![],
                password: None,
            },
        )
    }
    mod inject_tests {
        use super::*;

        fn render_inject_template<F>(
            template: &str,
            resolver: F,
        ) -> anyhow::Result<String>
        where
            F: FnMut(&InjectReference) -> anyhow::Result<String>,
        {
            InjectTemplate::new(template).render(resolver)
        }

        fn render_inject_template_with_env<F>(
            template: &str,
            env: &[(&str, &str)],
            resolver: F,
        ) -> anyhow::Result<String>
        where
            F: FnMut(&InjectReference) -> anyhow::Result<String>,
        {
            InjectTemplate::new(template).render_with_variable_resolver(
                |name| {
                    env.iter().find_map(|(key, value)| {
                        key.eq_ignore_ascii_case(name)
                            .then(|| (*value).to_string())
                    })
                },
                resolver,
            )
        }

        #[test]
        fn test_take_braced_inject_expression_returns_expression_and_tail() {
            let template = InjectTemplate::new(
                "{{ bw://some-api-key?field=username }} and more",
            );
            let (expr, next_start) =
                template.take_braced_expression(0).unwrap();

            assert_eq!(expr, " bw://some-api-key?field=username ");
            assert_eq!(template.src.get(next_start..).unwrap(), " and more");
        }

        #[test]
        fn test_parse_braced_inject_reference_trims_and_parses_bw_urls() {
            let reference = InjectReference::parse_braced(
                " bw://some-api-key?field=username ",
            )
            .unwrap()
            .unwrap();

            assert_eq!(
                reference.target,
                InjectReferenceTarget::Name("some-api-key".to_string())
            );
            assert_eq!(reference.field.as_deref(), Some("username"));
        }

        #[test]
        fn test_parse_braced_inject_reference_ignores_non_bw_expressions() {
            let reference =
                InjectReference::parse_braced(" not-a-reference ").unwrap();

            assert_eq!(reference, None);
        }

        #[test]
        fn test_render_inject_template_replaces_braced_and_raw_refs() {
            let password_id = uuid::Uuid::new_v4();
            let username_id = uuid::Uuid::new_v4();
            let template = format!(
                "password={{{{ bw://{password_id} }}}}\nuser=bw://{username_id}?field=username"
            );

            let rendered = render_inject_template(&template, |reference| {
                match (reference.id.as_str(), reference.field.as_deref()) {
                    (id, None) if id == password_id.to_string() => {
                        Ok("hunter2".to_string())
                    }
                    (id, Some("username"))
                        if id == username_id.to_string() =>
                    {
                        Ok("alice".to_string())
                    }
                    _ => Err(anyhow::anyhow!("unexpected reference")),
                }
            })
            .unwrap();

            assert_eq!(rendered, "password=hunter2\nuser=alice");
        }

        #[test]
        fn test_render_inject_template_supports_name_refs() {
            let template = "token=bw://some-api-key";

            let rendered = render_inject_template(template, |reference| {
                assert_eq!(
                    reference.target,
                    InjectReferenceTarget::Name("some-api-key".to_string())
                );
                assert_eq!(reference.field, None);
                Ok("secret".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "token=secret");
        }

        #[test]
        fn test_render_inject_template_supports_name_refs_with_field_query() {
            let template = "user=bw://some-api-key?field=username";

            let rendered = render_inject_template(template, |reference| {
                assert_eq!(
                    reference.target,
                    InjectReferenceTarget::Name("some-api-key".to_string())
                );
                assert_eq!(reference.field.as_deref(), Some("username"));
                Ok("alice".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "user=alice");
        }

        #[test]
        fn test_render_inject_template_expands_variables_before_resolving_refs(
        ) {
            let template =
                "user=bw://${ ITEM_NAME }?field=${FIELD:-username}";

            let rendered = render_inject_template_with_env(
                template,
                &[("item_name", "some-api-key")],
                |reference| {
                    assert_eq!(
                        reference.target,
                        InjectReferenceTarget::Name(
                            "some-api-key".to_string()
                        )
                    );
                    assert_eq!(reference.field.as_deref(), Some("username"));
                    Ok("alice".to_string())
                },
            )
            .unwrap();

            assert_eq!(rendered, "user=alice");
        }

        #[test]
        fn test_render_inject_template_supports_nested_default_variables() {
            let template = "${ITEM_NAME:-${FALLBACK_ITEM:-some-api-key}}";

            let rendered =
                render_inject_template_with_env(template, &[], |_| {
                    anyhow::bail!("unexpected inject reference")
                })
                .unwrap();
            assert_eq!(rendered, "some-api-key");

            let rendered = render_inject_template_with_env(
                template,
                &[("fallback_item", "fallback-key")],
                |_| anyhow::bail!("unexpected inject reference"),
            )
            .unwrap();
            assert_eq!(rendered, "fallback-key");
        }

        #[test]
        fn test_render_inject_template_treats_invalid_variable_tags_as_literals(
        ) {
            let template = "$1BAD ${foo-bar} cost=$5";

            let rendered =
                render_inject_template_with_env(template, &[], |_| {
                    anyhow::bail!("unexpected inject reference")
                })
                .unwrap();

            assert_eq!(rendered, template);
        }

        #[test]
        fn test_render_inject_template_supports_quoted_braced_refs() {
            let template =
                r#"password={{ "bw://some-api-key?field=db.password" }}"#;

            let rendered = render_inject_template(template, |reference| {
                assert_eq!(
                    reference.target,
                    InjectReferenceTarget::Name("some-api-key".to_string())
                );
                assert_eq!(reference.field.as_deref(), Some("db.password"));
                Ok("hunter2".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "password=hunter2");
        }

        #[test]
        fn test_render_inject_template_preserves_quoted_non_reference_expressions(
        ) {
            let template = r#"before {{ "not-a-reference" + "x" }} after"#;

            let rendered = render_inject_template(template, |_| {
                anyhow::bail!("unexpected inject reference")
            })
            .unwrap();

            assert_eq!(rendered, template);
        }

        #[test]
        fn test_render_inject_template_respects_op_inject_raw_start_boundaries(
        ) {
            let entry_id = uuid::Uuid::new_v4();

            let rendered = render_inject_template(
                &format!("prefix_bw://{entry_id}"),
                |reference| {
                    assert_eq!(reference.id, entry_id.to_string());
                    Ok("secret".to_string())
                },
            )
            .unwrap();
            assert_eq!(rendered, "prefix_secret");

            for template in [
                format!("prefix+bw://{entry_id}"),
                format!(r"prefix\bw://{entry_id}"),
                format!("prefix.bw://{entry_id}"),
            ] {
                let rendered = render_inject_template(&template, |_| {
                    Ok("secret".to_string())
                })
                .unwrap();
                assert_eq!(rendered, template);
            }
        }

        #[test]
        fn test_render_inject_template_preserves_trailing_punctuation() {
            let entry_id = uuid::Uuid::new_v4();
            for (template, resolved, expected) in [
                (
                    format!("dsn=bw://{entry_id}, done."),
                    "postgres://db",
                    "dsn=postgres://db, done.".to_string(),
                ),
                (
                    format!(
                        "token=bw://{entry_id}. wow! alert=bw://{entry_id}!"
                    ),
                    "secret",
                    "token=secret. wow! alert=secret!".to_string(),
                ),
            ] {
                let rendered =
                    render_inject_template(&template, |reference| {
                        assert_eq!(reference.id, entry_id.to_string());
                        assert_eq!(reference.field, None);
                        Ok(resolved.to_string())
                    })
                    .unwrap();

                assert_eq!(rendered, expected);
            }
        }

        #[test]
        fn test_render_inject_template_treats_special_characters_as_raw_reference_boundaries(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            for (template, expected, field) in [
                (
                    format!("dsn=bw://{entry_id}/extra"),
                    "dsn=secret/extra".to_string(),
                    None,
                ),
                (
                    format!("dsn=bw://{entry_id}#prod"),
                    "dsn=secret#prod".to_string(),
                    None,
                ),
                (
                    format!("value=bw://{entry_id}:5432"),
                    "value=secret:5432".to_string(),
                    None,
                ),
                (
                    format!("value=bw://{entry_id}@host"),
                    "value=secret@host".to_string(),
                    None,
                ),
                (
                    format!("value=bw://{entry_id}=suffix"),
                    "value=secret=suffix".to_string(),
                    None,
                ),
                (
                    format!("bw://{entry_id}?field=username&field=password"),
                    "alice&field=password".to_string(),
                    Some("username"),
                ),
                (
                    format!("bw://{entry_id}?field=username&bogus=1"),
                    "alice&bogus=1".to_string(),
                    Some("username"),
                ),
            ] {
                let rendered =
                    render_inject_template(&template, |reference| {
                        assert_eq!(reference.id, entry_id.to_string());
                        assert_eq!(reference.field.as_deref(), field);
                        Ok(if field.is_some() { "alice" } else { "secret" }
                            .to_string())
                    })
                    .unwrap();

                assert_eq!(rendered, expected);
            }
        }

        #[test]
        fn test_render_inject_template_supports_raw_field_names_with_periods()
        {
            let entry_id = uuid::Uuid::new_v4();
            let template =
                format!("token=bw://{entry_id}?field=db.password, done");

            let rendered = render_inject_template(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                assert_eq!(reference.field.as_deref(), Some("db.password"));
                Ok("secret".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "token=secret, done");
        }

        #[test]
        fn test_render_inject_template_supports_encoded_raw_field_queries() {
            let entry_id = uuid::Uuid::new_v4();
            for template in [
                format!("token=bw://{entry_id}?field=API%20Token"),
                format!("token=bw://{entry_id}?field=API+Token"),
            ] {
                let rendered =
                    render_inject_template(&template, |reference| {
                        assert_eq!(reference.id, entry_id.to_string());
                        assert_eq!(
                            reference.field.as_deref(),
                            Some("API Token")
                        );
                        Ok("secret".to_string())
                    })
                    .unwrap();

                assert_eq!(rendered, "token=secret");
            }
        }

        #[test]
        fn test_render_inject_template_rejects_empty_field_query() {
            let entry_id = uuid::Uuid::new_v4();
            let template = format!("token=bw://{entry_id}?field=");

            let err = render_inject_template(&template, |_| {
                Ok("secret".to_string())
            })
            .unwrap_err();

            assert!(format!("{err}").contains("empty"));
        }

        #[test]
        fn test_render_inject_template_supports_raw_refs_in_dsn_and_query_contexts(
        ) {
            let dsn_id = uuid::Uuid::new_v4();
            let query_id = uuid::Uuid::new_v4();
            let template = format!(
                "postgres://user:bw://{dsn_id}@db.example/app?token=bw://{query_id}&mode=ro"
            );

            let rendered =
                render_inject_template(
                    &template,
                    |reference| match reference.id.as_str() {
                        id if id == dsn_id.to_string() => {
                            Ok("pw".to_string())
                        }
                        id if id == query_id.to_string() => {
                            Ok("token".to_string())
                        }
                        _ => Err(anyhow::anyhow!("unexpected reference")),
                    },
                )
                .unwrap();

            assert_eq!(
                rendered,
                "postgres://user:pw@db.example/app?token=token&mode=ro"
            );
        }

        #[test]
        fn test_render_inject_template_supports_raw_field_refs_in_outer_query_contexts(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            let template = format!(
                "https://example.test?user=bw://{entry_id}?field=username&mode=ro"
            );

            let rendered = render_inject_template(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                assert_eq!(reference.field.as_deref(), Some("username"));
                Ok("alice".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "https://example.test?user=alice&mode=ro");
        }

        #[test]
        fn test_render_inject_template_supports_raw_field_refs_in_dsn_username_contexts(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            let template = format!(
                "postgres://bw://{entry_id}?field=username@db.example/app"
            );

            let rendered = render_inject_template(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                assert_eq!(reference.field.as_deref(), Some("username"));
                Ok("alice".to_string())
            })
            .unwrap();

            assert_eq!(rendered, "postgres://alice@db.example/app");
        }

        #[test]
        fn test_render_inject_template_replaces_unenclosed_refs_in_structured_text(
        ) {
            let entry_id = uuid::Uuid::new_v4();
            for (template, expected) in [
                (
                    format!(
                        "apiVersion: v1\nkind: Secret\nstringData:\n  password: \"{{{{ bw://{entry_id} }}}}\"\n  note: \"bw://{entry_id}\"\n"
                    ),
                    "apiVersion: v1\nkind: Secret\nstringData:\n  password: \"hunter2\"\n  note: \"hunter2\"\n"
                        .to_string(),
                ),
                (
                    format!(
                        "{{\n  \"password\": \"{{{{ bw://{entry_id} }}}}\",\n  \"note\": \"bw://{entry_id}\"\n}}\n"
                    ),
                    "{\n  \"password\": \"hunter2\",\n  \"note\": \"hunter2\"\n}\n"
                        .to_string(),
                ),
            ] {
                let rendered = render_inject_template(&template, |reference| {
                    assert_eq!(reference.id, entry_id.to_string());
                    Ok("hunter2".to_string())
                })
                .unwrap();

                assert_eq!(rendered, expected);
            }
        }

        #[test]
        fn test_find_inject_entry_raw_matches_name_refs_exactly_ignoring_case(
        ) {
            let entries = &[
                make_entry("some-api-key", None, None, &[]),
                make_entry("some-api-key-prod", None, None, &[]),
            ];

            let (entry, _) =
                InjectReferenceTarget::Name("SOME-API-KEY".to_string())
                    .find_entry(entries)
                    .unwrap();

            assert_eq!(entry.id, entries[0].0.id);
        }

        #[test]
        fn test_find_inject_entry_raw_rejects_duplicate_name_refs() {
            let entries = &[
                make_entry("some-api-key", Some("alice"), None, &[]),
                make_entry("some-api-key", Some("bob"), None, &[]),
            ];

            let err = InjectReferenceTarget::Name("some-api-key".to_string())
                .find_entry(entries)
                .unwrap_err();

            assert!(format!("{err}").contains("multiple entries found"));
            assert!(format!("{err}").contains("use bw://<uuid> instead"));
        }

        #[test]
        fn test_find_inject_entry_raw_does_not_fuzzy_match_name_refs() {
            let entries = &[make_entry("some-api-key-prod", None, None, &[])];

            let err = InjectReferenceTarget::Name("some-api-key".to_string())
                .find_entry(entries)
                .unwrap_err();

            assert!(format!("{err}").contains("no entry found"));
        }

        #[test]
        fn test_parse_inject_reference_rejects_userinfo_ports_and_paths() {
            let entry_id = uuid::Uuid::new_v4();

            for reference in [
                format!("bw://user@{entry_id}"),
                format!("bw://user:pass@{entry_id}"),
                format!("bw://{entry_id}:5432"),
                format!("bw://{entry_id}/"),
            ] {
                assert!(
                    InjectReference::parse(&reference).is_err(),
                    "{reference} should be rejected"
                );
            }
        }

        #[test]
        fn test_parse_run_env_matches_dotenvy_parsing_rules() {
            let pairs = parse_run_env_file(
                concat!(
                    "BACKSLASH='a\\\\b'\n",
                    "PATH='C:\\temp\\logs\\q'\n",
                    r#"ESCAPED="contains \"quote\" and slash \\ and newline \n""#,
                    "\n",
                    "HASH=# comment\n",
                    "MULTILINE=\"line 1\nline 2\"\n",
                ),
                |_| anyhow::bail!("unexpected inject reference"),
            )
            .unwrap();

            assert_eq!(
                pairs,
                vec![
                    ("BACKSLASH".to_string(), r"a\\b".to_string()),
                    ("PATH".to_string(), r"C:\temp\logs\q".to_string()),
                    (
                        "ESCAPED".to_string(),
                        "contains \"quote\" and slash \\ and newline \n"
                            .to_string()
                    ),
                    ("HASH".to_string(), String::new()),
                    ("MULTILINE".to_string(), "line 1\nline 2".to_string()),
                ]
            );
        }

        #[test]
        fn test_parse_run_env_expands_then_resolves_raw_references() {
            use std::sync::{Mutex, OnceLock};

            static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

            let _guard =
                ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
            let host_var = "RBW_TEST_HOST_VAR";
            std::env::set_var(host_var, "expanded-by-host");

            let entry_id = uuid::Uuid::new_v4();
            let template = format!(
                "RAW=bw://{entry_id}\nQUOTED=\"bw://{entry_id}\"\nCOPY=$RAW\nHOST=${{{host_var}}}\nMIXED=${{{host_var}}}:$RAW\nLITERAL=__RBW_RUN_BRACED_REF_0__\nEXPANDED=${{LITERAL}}\n"
            );

            let pairs = parse_run_env_file(&template, |reference| {
                assert_eq!(reference.id, entry_id.to_string());
                Ok("secret".to_string())
            })
            .unwrap();

            std::env::remove_var(host_var);

            assert_eq!(
                pairs,
                vec![
                    ("RAW".to_string(), "secret".to_string()),
                    ("QUOTED".to_string(), "secret".to_string()),
                    ("COPY".to_string(), "secret".to_string()),
                    ("HOST".to_string(), "expanded-by-host".to_string()),
                    (
                        "MIXED".to_string(),
                        "expanded-by-host:secret".to_string()
                    ),
                    (
                        "LITERAL".to_string(),
                        "__RBW_RUN_BRACED_REF_0__".to_string()
                    ),
                    (
                        "EXPANDED".to_string(),
                        "__RBW_RUN_BRACED_REF_0__".to_string()
                    ),
                ]
            );
        }

        #[test]
        fn test_parse_run_env_preserves_injected_values_verbatim() {
            let token_id = uuid::Uuid::new_v4().to_string();
            let secret_id = uuid::Uuid::new_v4().to_string();
            let multiline_id = uuid::Uuid::new_v4().to_string();
            let template = format!(
                "TOKEN=bw://{token_id}\nSECRET='bw://{secret_id}'\nMULTILINE=\"bw://{multiline_id}\"\n"
            );

            let pairs = parse_run_env_file(&template, |reference| {
                match reference.id.as_str() {
                    id if id == token_id => {
                        Ok("abc#not-a-comment".to_string())
                    }
                    id if id == secret_id => {
                        Ok("value with \"double\" and 'single' quotes"
                            .to_string())
                    }
                    id if id == multiline_id => {
                        Ok("line 1\nline 2  ".to_string())
                    }
                    _ => anyhow::bail!(
                        "unexpected inject reference '{}'",
                        reference.id
                    ),
                }
            })
            .unwrap();

            assert_eq!(
                pairs,
                vec![
                    ("TOKEN".to_string(), "abc#not-a-comment".to_string()),
                    (
                        "SECRET".to_string(),
                        "value with \"double\" and 'single' quotes"
                            .to_string()
                    ),
                    ("MULTILINE".to_string(), "line 1\nline 2  ".to_string()),
                ]
            );
        }

        #[test]
        fn test_build_inject_run_command_overrides_inherited_env_bindings() {
            let env_bindings = vec![
                ("API_KEY".to_string(), "new-secret".to_string()),
                ("EXTRA".to_string(), "value".to_string()),
            ];
            let command = build_inject_run_command(
                &[std::ffi::OsString::from("env")],
                &env_bindings,
            )
            .unwrap();

            let envs = command
                .get_envs()
                .map(|(key, value)| {
                    (
                        key.to_os_string(),
                        value.map(std::ffi::OsStr::to_os_string),
                    )
                })
                .collect::<std::collections::BTreeMap<
                    std::ffi::OsString,
                    Option<std::ffi::OsString>,
                >>();

            assert_eq!(
                envs.get(std::ffi::OsStr::new("API_KEY")),
                Some(&Some(std::ffi::OsString::from("new-secret")))
            );
            assert_eq!(
                envs.get(std::ffi::OsStr::new("EXTRA")),
                Some(&Some(std::ffi::OsString::from("value")))
            );
        }

        #[test]
        #[cfg(unix)]
        fn test_inject_run_passes_values_without_shell_evaluation() {
            use std::process::Stdio;

            let env_bindings =
                parse_run_env_file("VALUE='$(echo still-literal)'\n", |_| {
                    anyhow::bail!("unexpected inject reference")
                })
                .unwrap();
            let mut command = build_inject_run_command(
                &[
                    std::ffi::OsString::from("printenv"),
                    std::ffi::OsString::from("VALUE"),
                ],
                &env_bindings,
            )
            .unwrap();
            command.stdout(Stdio::piped());

            let output = command.output().unwrap();

            assert!(output.status.success());
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                "$(echo still-literal)\n"
            );
        }

        #[test]
        #[cfg(unix)]
        fn test_run_inject_command_returns_child_exit_status() {
            let status =
                run_inject_command(&[std::ffi::OsString::from("false")], &[])
                    .unwrap();

            assert_eq!(status.code(), Some(1));
        }

        #[test]
        fn test_resolve_inject_value_uses_password_username_and_custom_fields(
        ) {
            let cipher = DecryptedCipher {
                id: uuid::Uuid::new_v4().to_string(),
                folder: None,
                name: "example".to_string(),
                data: DecryptedData::Login {
                    username: Some("alice".to_string()),
                    password: Some("hunter2".to_string()),
                    totp: None,
                    uris: None,
                },
                fields: [("api-token", "xyz"), ("deployment", "prod")]
                    .iter()
                    .map(|(name, value)| DecryptedField {
                        name: Some((*name).to_string()),
                        value: Some((*value).to_string()),
                        ty: None,
                    })
                    .collect(),
                notes: None,
                history: vec![],
                attachments: vec![],
                attachment_metadata: AttachmentMetadata::new("example-id", 0),
            };

            assert_eq!(
                resolve_inject_value(&cipher, None).unwrap(),
                "hunter2"
            );
            assert_eq!(
                resolve_inject_value(&cipher, Some("username")).unwrap(),
                "alice"
            );
            assert_eq!(
                resolve_inject_value(&cipher, Some("api-token")).unwrap(),
                "xyz"
            );
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_replaces_existing_file_atomically(
        ) {
            use std::os::unix::fs::MetadataExt as _;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("secret.txt");
            std::fs::write(&path, "existing").unwrap();
            let original_inode = std::fs::metadata(&path).unwrap().ino();

            write_rendered_template_file(&path, "hunter2").unwrap();

            assert_eq!(std::fs::read_to_string(&path).unwrap(), "hunter2");
            let updated_inode = std::fs::metadata(&path).unwrap().ino();
            assert_ne!(updated_inode, original_inode);
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_accepts_bare_relative_paths() {
            use std::os::unix::fs::PermissionsExt as _;

            struct CwdGuard(std::path::PathBuf);

            impl Drop for CwdGuard {
                fn drop(&mut self) {
                    let _ = std::env::set_current_dir(&self.0);
                }
            }

            let dir = tempfile::tempdir().unwrap();
            let cwd = std::env::current_dir().unwrap();
            let _guard = CwdGuard(cwd);
            std::env::set_current_dir(dir.path()).unwrap();

            let path = std::path::Path::new("secret.txt");
            write_rendered_template_file(path, "hunter2").unwrap();

            assert_eq!(std::fs::read_to_string(path).unwrap(), "hunter2");
            let mode =
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_uses_owner_only_permissions() {
            use std::os::unix::fs::PermissionsExt as _;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("secret.txt");
            write_rendered_template_file(&path, "hunter2").unwrap();

            let mode = std::fs::metadata(&path).unwrap().permissions().mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_rejects_symlinks() {
            use std::os::unix::fs::symlink;

            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("target.txt");
            std::fs::write(&target, "existing").unwrap();
            let link = dir.path().join("secret.txt");
            symlink(&target, &link).unwrap();

            let err =
                write_rendered_template_file(&link, "hunter2").unwrap_err();
            assert!(format!("{err}").contains("must not be a symlink"));
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "existing");
        }

        #[test]
        #[cfg(unix)]
        fn test_write_rendered_template_file_rejects_non_regular_files() {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt as _;
            use std::os::unix::fs::OpenOptionsExt as _;

            let dir = tempfile::tempdir().unwrap();
            let fifo = dir.path().join("secret.fifo");
            let fifo_cstr =
                CString::new(fifo.as_os_str().as_bytes()).unwrap();
            let status = unsafe { libc::mkfifo(fifo_cstr.as_ptr(), 0o600) };
            assert_eq!(status, 0);

            let _reader = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
                .unwrap();

            let err =
                write_rendered_template_file(&fifo, "hunter2").unwrap_err();
            assert!(format!("{err}").contains("regular file"));
        }
    }

    #[test]
    fn test_editable_cipher_yaml_roundtrip() {
        let cipher = EditableCipher {
            name: "test entry".to_string(),
            folder: None,
            notes: Some("some notes".to_string()),
            data: EditableData::Login {
                username: Some("user@example.com".to_string()),
                password: Some("hunter2".to_string()),
                uris: vec![EditableUri {
                    uri: "https://example.com".to_string(),
                    match_type: Some("domain".to_string()),
                }],
                totp: None,
            },
            fields: vec![],
        };

        let yaml = serde_yaml::to_string(&cipher).unwrap();
        eprintln!("YAML output:\n{yaml}");
        assert!(!yaml.is_empty(), "YAML output should not be empty");
        assert!(yaml.contains("test entry"), "should contain name");
        assert!(yaml.contains("login"), "should contain type tag");

        let parsed: EditableCipher = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.name, "test entry");
        if let EditableData::Login { username, .. } = parsed.data {
            assert_eq!(username.as_deref(), Some("user@example.com"));
        } else {
            panic!("expected Login variant");
        }
    }
}
