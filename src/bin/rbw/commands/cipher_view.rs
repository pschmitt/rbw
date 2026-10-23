use super::*;

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedAttachment {
    pub id: String,
    pub file_name: Option<String>,
    pub size: Option<String>,
    pub size_name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AttachmentMetadata {
    #[serde(skip_serializing_if = "is_zero")]
    pub attachment_count: usize,
}

impl AttachmentMetadata {
    pub(super) fn new(_entry_id: &str, attachment_count: usize) -> Self {
        Self { attachment_count }
    }

    pub(super) fn has_attachments(&self) -> bool {
        self.attachment_count > 0
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct DecryptedCipher {
    pub id: String,
    pub folder: Option<String>,
    pub name: String,
    pub data: DecryptedData,
    pub fields: Vec<DecryptedField>,
    pub notes: Option<String>,
    pub history: Vec<DecryptedHistoryEntry>,
    pub attachments: Vec<DecryptedAttachment>,
    #[serde(flatten)]
    pub attachment_metadata: AttachmentMetadata,
    pub archived: bool,
    pub deleted: bool,
    // Server-side last-modified timestamp (RFC 3339); `None` for entries
    // synced by an older rbw and for `--from-file` exports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_date: Option<String>,
    // Set when this entry was merged in from a non-active account (multi-
    // account `list`/`search`); omitted otherwise so single-account output is
    // unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

// Where a plain `rbw get` value was resolved from — surfaced by --verbose.
pub(super) enum SecretSource {
    Password,
    Field(String),
    Notes,
}

impl SecretSource {
    pub(super) fn field(field: &DecryptedField) -> Self {
        Self::Field(field.name.clone().unwrap_or_else(|| "(unnamed)".into()))
    }

    pub(super) fn label(&self) -> String {
        match self {
            Self::Password => "password".to_string(),
            Self::Field(name) => format!("field '{name}'"),
            Self::Notes => "notes".to_string(),
        }
    }
}

impl DecryptedCipher {
    // The item's "default" secret for a plain `rbw get NAME`: the login
    // password, else a custom password/passphrase/pass/passwd field, else the
    // notes, else a lone custom field. This keeps the resolution logic in one
    // place (here) instead of every consumer reimplementing it. The second
    // tuple element records *where* the value came from (for --verbose).
    pub(super) fn default_secret(&self) -> Option<(String, SecretSource)> {
        const FIELD_NAMES: [&str; 4] =
            ["password", "passphrase", "pass", "passwd"];

        if let DecryptedData::Login {
            password: Some(password),
            ..
        } = &self.data
        {
            return Some((password.clone(), SecretSource::Password));
        }

        if let Some(field) = self.fields.iter().find(|field| {
            field.name.as_deref().is_some_and(|name| {
                FIELD_NAMES.contains(&name.to_lowercase().as_str())
            })
        }) {
            if let Some(value) = &field.value {
                return Some((value.clone(), SecretSource::field(field)));
            }
        }

        if let Some(notes) = &self.notes {
            return Some((notes.clone(), SecretSource::Notes));
        }

        if let [field] = self.fields.as_slice() {
            if let Some(value) = &field.value {
                return Some((value.clone(), SecretSource::field(field)));
            }
        }

        None
    }

    pub(super) fn display_short(&self, desc: &str, clipboard: bool) -> bool {
        match &self.data {
            DecryptedData::Login { .. } => self.default_secret().map_or_else(
                || {
                    eprintln!("entry for '{desc}' had no password");
                    false
                },
                |(password, _)| val_display_or_store(clipboard, &password),
            ),
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
            DecryptedData::SecureNote => self.default_secret().map_or_else(
                || {
                    eprintln!("entry for '{desc}' had no notes");
                    false
                },
                |(value, _)| val_display_or_store(clipboard, &value),
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

    pub(super) fn display_field(
        &self,
        desc: &str,
        field: &str,
        clipboard: bool,
    ) {
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

    /// This implementation mirror the `fn display_fied` method on which field to list
    pub(super) fn display_fields_list(&self) {
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

    pub(super) fn display_structured(
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

    // `mask` replaces every secret value (password, TOTP seed, card
    // number/CVV, SSN, SSH private key, hidden fields) with a fixed run of
    // dots, so neither the value nor its length is shown.
    pub(super) fn display_show(&self, mask: bool) {
        let c = stdout_supports_color();
        let lbl = |s: &str| style::label(&format!("{s:<12}"), c);
        let dim = |s: &str| {
            if mask {
                style::secret(MASKED_SECRET, c)
            } else {
                style::dim(s, c)
            }
        };
        let secret =
            |s: &str| style::secret(if mask { MASKED_SECRET } else { s }, c);
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
                fido2_credentials,
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
                    for (i, uri_entry) in uris.iter().enumerate() {
                        // Only label the first URI; align the rest under it
                        // so the "URI" label isn't repeated for every value.
                        let label =
                            if i == 0 { lbl("URI") } else { " ".repeat(12) };
                        print!("{} {}", label, style::uri(&uri_entry.uri, c));
                        if let Some(mt) = uri_entry.match_type {
                            print!("  {}", dim(&format!("[{mt}]")));
                        }
                        println!();
                    }
                }
                // Never prints the raw key material -- just enough to
                // confirm a passkey is present and which relying party/
                // account it's for.
                for (i, cred) in fido2_credentials.iter().enumerate() {
                    let label = if i == 0 {
                        lbl("Passkey")
                    } else {
                        " ".repeat(12)
                    };
                    let rp =
                        cred.rp_name.as_deref().unwrap_or("(unknown rp)");
                    let user = cred
                        .user_display_name
                        .as_deref()
                        .or(cred.user_name.as_deref());
                    match user {
                        Some(user) => println!("{label} {rp} ({user})"),
                        None => println!("{label} {rp}"),
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
                for addr in
                    [address1, address2, address3].into_iter().flatten()
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
                    println!("{} {}", lbl("Fingerprint"), style::dim(fp, c));
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
                let is_hidden =
                    matches!(field.ty, Some(rbw::api::FieldType::Hidden));
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
                let fname = att.file_name.as_deref().unwrap_or(&att.id);
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
