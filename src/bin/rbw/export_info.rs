use std::collections::HashSet;

use anyhow::Context as _;

type Result<T> = anyhow::Result<T>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum Format {
    Auto,
    Rbw,
    BitwardenJson,
    BitwardenEncryptedJson,
    BitwardenZip,
    BitwardenCsv,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetectedFormat {
    Rbw,
    BitwardenJson,
    BitwardenEncryptedJson,
    BitwardenZip,
    BitwardenCsv,
}

impl DetectedFormat {
    fn name(self) -> &'static str {
        match self {
            Self::Rbw => "rbw",
            Self::BitwardenJson => "bitwarden-json",
            Self::BitwardenEncryptedJson => "bitwarden-encrypted-json",
            Self::BitwardenZip => "bitwarden-zip",
            Self::BitwardenCsv => "bitwarden-csv",
        }
    }
}

#[derive(Debug, Default, serde::Serialize, PartialEq, Eq)]
pub struct Info {
    pub format: String,
    pub entries: usize,
    pub logins: usize,
    pub secure_notes: usize,
    pub cards: usize,
    pub identities: usize,
    pub ssh_keys: usize,
    pub other_entries: usize,
    pub entries_with_notes: usize,
    pub passkeys: usize,
    pub collections: usize,
    pub folders: usize,
    pub attachments: usize,
    pub custom_fields: usize,
    pub password_history: usize,
    pub uris: usize,
    pub archived: usize,
    pub deleted: usize,
}

impl Info {
    fn new(format: DetectedFormat) -> Self {
        Self {
            format: format.name().to_string(),
            ..Self::default()
        }
    }

    fn add_type(&mut self, ty: &str) {
        match ty {
            "Login" | "login" => self.logins += 1,
            "SecureNote" | "note" | "secure_note" => self.secure_notes += 1,
            "Card" | "card" => self.cards += 1,
            "Identity" | "identity" => self.identities += 1,
            "SshKey" | "sshKey" | "ssh_key" => self.ssh_keys += 1,
            _ => self.other_entries += 1,
        }
    }

    fn finish_entry(&mut self) {
        self.entries += 1;
    }
}

pub fn run(
    file: Option<&std::path::Path>,
    format: Format,
    decrypt: bool,
    decrypt_passphrase: Option<&str>,
    json: bool,
) -> Result<()> {
    let passphrase = crate::commands::resolve_import_passphrase(
        decrypt,
        decrypt_passphrase,
    )?;
    let raw = crate::commands::read_import_input(file)?;
    let detected = detect_format(&raw, format)?;
    let info = summarize(&raw, detected, passphrase.as_deref())?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&info)
                .context("failed to serialize export information")?
        );
    } else {
        print_human(&info);
    }
    Ok(())
}

fn detect_format(raw: &[u8], requested: Format) -> Result<DetectedFormat> {
    if requested != Format::Auto {
        return Ok(match requested {
            Format::Auto => unreachable!(),
            Format::Rbw => DetectedFormat::Rbw,
            Format::BitwardenJson => DetectedFormat::BitwardenJson,
            Format::BitwardenEncryptedJson => {
                DetectedFormat::BitwardenEncryptedJson
            }
            Format::BitwardenZip => DetectedFormat::BitwardenZip,
            Format::BitwardenCsv => DetectedFormat::BitwardenCsv,
        });
    }

    if raw.starts_with(b"PK\x03\x04") || raw.starts_with(b"PK\x05\x06") {
        return Ok(DetectedFormat::BitwardenZip);
    }

    if let Ok(text) = std::str::from_utf8(raw) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            let object = value.as_object().context(
                "couldn't recognize the export: expected a JSON object",
            )?;
            if object.contains_key("entries") {
                return Ok(DetectedFormat::Rbw);
            }
            if object.contains_key("encrypted") && object.contains_key("data")
            {
                return Ok(DetectedFormat::BitwardenEncryptedJson);
            }
            if object.contains_key("items") || object.contains_key("folders")
            {
                return Ok(DetectedFormat::BitwardenJson);
            }
        } else if is_csv(text)? {
            return Ok(DetectedFormat::BitwardenCsv);
        }
    }

    // The only non-JSON export format is rbw's gpg-encrypted archive. Keep
    // auto-detection aligned with `rbw import`: a passphrase is required for
    // it, but the bytes cannot be distinguished from arbitrary binary data.
    Ok(DetectedFormat::Rbw)
}

fn summarize(
    raw: &[u8],
    format: DetectedFormat,
    passphrase: Option<&str>,
) -> Result<Info> {
    match format {
        DetectedFormat::Rbw => {
            let text = crate::commands::load_import_json(raw, passphrase)?;
            summarize_rbw(&text)
        }
        DetectedFormat::BitwardenJson => {
            let text = std::str::from_utf8(raw)
                .context("Bitwarden JSON export is not valid UTF-8")?;
            let vault = crate::import_bitwarden::parse_bitwarden_json(text)?;
            Ok(summarize_bitwarden(vault, 0, DetectedFormat::BitwardenJson))
        }
        DetectedFormat::BitwardenEncryptedJson => {
            let passphrase = passphrase.context(
                "this looks like a Bitwarden \"Encrypted JSON\" export; \
                 pass --decrypt or --decrypt-passphrase",
            )?;
            let text = crate::import_bitwarden::decrypt_encrypted_json(
                raw, passphrase,
            )?;
            let vault = crate::import_bitwarden::parse_bitwarden_json(&text)?;
            Ok(summarize_bitwarden(
                vault,
                0,
                DetectedFormat::BitwardenEncryptedJson,
            ))
        }
        DetectedFormat::BitwardenZip => {
            let (vault, attachments) =
                crate::import_bitwarden::parse_zip(raw)?;
            let attachment_count = attachments.values().map(Vec::len).sum();
            Ok(summarize_bitwarden(
                vault,
                attachment_count,
                DetectedFormat::BitwardenZip,
            ))
        }
        DetectedFormat::BitwardenCsv => summarize_csv(raw),
    }
}

fn summarize_rbw(text: &str) -> Result<Info> {
    let value: serde_json::Value = serde_json::from_str(text)
        .context("failed to parse import data (expected the JSON shape produced by `rbw export`)")?;
    let object = value.as_object().context(
        "failed to parse import data (expected an rbw export object)",
    )?;
    let entries = object
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .context("rbw export is missing its entries array")?;
    let mut info = Info::new(DetectedFormat::Rbw);
    info.collections = object
        .get("collections")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);

    for entry in entries {
        let object = entry
            .as_object()
            .context("rbw export contains an entry that is not an object")?;
        info.add_type(
            object.get("type").and_then(|v| v.as_str()).unwrap_or(""),
        );
        if has_text(object.get("notes")) {
            info.entries_with_notes += 1;
        }
        info.custom_fields += object
            .get("fields")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        info.password_history += object
            .get("history")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        info.attachments += object
            .get("attachments")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        if object
            .get("archived")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            info.archived += 1;
        }
        if object
            .get("deleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            info.deleted += 1;
        }

        if object.get("type").and_then(|v| v.as_str()) == Some("Login") {
            info.uris += object
                .get("uris")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            info.passkeys += object
                .get("fido2_credentials")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
        }
        info.finish_entry();
    }
    Ok(info)
}

fn summarize_bitwarden(
    vault: crate::import_bitwarden::BwVault,
    attachments: usize,
    format: DetectedFormat,
) -> Info {
    let mut info = Info::new(format);
    info.collections = vault.collections.len();
    info.folders = vault.folders.len();
    info.attachments = attachments;
    for item in vault.items {
        info.add_type(match item.ty {
            1 => "Login",
            2 => "SecureNote",
            3 => "Card",
            4 => "Identity",
            5 => "SshKey",
            _ => "",
        });
        if has_text(item.notes.as_ref().map(|s| s.as_str())) {
            info.entries_with_notes += 1;
        }
        info.custom_fields += item.fields.len();
        info.password_history += item.password_history.len();
        if let Some(login) = item.login {
            info.uris += login.uris.len();
            info.passkeys += login.fido2_credentials.len();
        }
        info.finish_entry();
    }
    info
}

fn summarize_csv(raw: &[u8]) -> Result<Info> {
    let mut reader = csv::Reader::from_reader(raw);
    let headers = reader
        .headers()
        .context("failed to read CSV headers")?
        .clone();
    let column = |name: &str| {
        headers
            .iter()
            .position(|header| header.eq_ignore_ascii_case(name))
    };
    let type_column = column("type").context(
        "couldn't recognize the CSV export: missing the `type` column",
    )?;
    let name_column = column("name").context(
        "couldn't recognize the CSV export: missing the `name` column",
    )?;
    let notes_column = column("notes");
    let fields_column = column("fields");
    let uri_column = column("login_uri");
    let folder_column = column("folder");
    let mut info = Info::new(DetectedFormat::BitwardenCsv);
    let mut folders = HashSet::new();

    for record in reader.records() {
        let record =
            record.context("failed to read a row from the CSV export")?;
        let ty = record.get(type_column).unwrap_or_default();
        match ty.to_ascii_lowercase().as_str() {
            "login" => info.logins += 1,
            "note" | "securenote" | "secure_note" => info.secure_notes += 1,
            _ => info.other_entries += 1,
        }
        if notes_column
            .and_then(|index| record.get(index))
            .is_some_and(|notes| !notes.trim().is_empty())
        {
            info.entries_with_notes += 1;
        }
        if let Some(fields) =
            fields_column.and_then(|index| record.get(index))
        {
            info.custom_fields += fields
                .lines()
                .filter(|field| !field.trim().is_empty())
                .count();
        }
        if uri_column
            .and_then(|index| record.get(index))
            .is_some_and(|uri| !uri.trim().is_empty())
        {
            info.uris += 1;
        }
        if let Some(folder) = folder_column
            .and_then(|index| record.get(index))
            .filter(|folder| !folder.trim().is_empty())
        {
            folders.insert(folder.to_string());
        }
        // Keep `name` as a required column even though it is not displayed;
        // this prevents arbitrary CSV files with a coincidental `type`
        // header from being reported as vault exports.
        let _ = record
            .get(name_column)
            .context("CSV row is missing its name")?;
        info.finish_entry();
    }
    info.folders = folders.len();
    Ok(info)
}

fn is_csv(text: &str) -> Result<bool> {
    let mut reader = csv::Reader::from_reader(text.as_bytes());
    let Ok(headers) = reader.headers() else {
        return Ok(false);
    };
    Ok(headers
        .iter()
        .any(|header| header.eq_ignore_ascii_case("type"))
        && headers
            .iter()
            .any(|header| header.eq_ignore_ascii_case("name")))
}

fn has_text(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

fn print_human(info: &Info) {
    println!("format: {}", info.format);
    println!("entries: {}", info.entries);
    println!("  logins: {}", info.logins);
    println!("  secure notes: {}", info.secure_notes);
    println!("  cards: {}", info.cards);
    println!("  identities: {}", info.identities);
    println!("  SSH keys: {}", info.ssh_keys);
    println!("  other entries: {}", info.other_entries);
    println!("entries with notes: {}", info.entries_with_notes);
    println!("passkeys: {}", info.passkeys);
    println!("collections: {}", info.collections);
    println!("folders: {}", info.folders);
    println!("attachments: {}", info.attachments);
    println!("custom fields: {}", info.custom_fields);
    println!("password history entries: {}", info.password_history);
    println!("URIs: {}", info.uris);
    println!("archived: {}", info.archived);
    println!("deleted: {}", info.deleted);
}

#[cfg(test)]
mod test {
    use super::*;

    const RBW_JSON: &str = r#"{
        "entries": [
            {
                "name": "login",
                "type": "Login",
                "uris": [{"uri": "https://example.test"}],
                "fido2_credentials": [{"credential_id": "key"}],
                "fields": [{"name": "env", "value": "prod"}],
                "notes": "remember",
                "history": [{"password": "old"}],
                "attachments": [{"id": "attachment"}],
                "archived": true
            },
            {"name": "note", "type": "SecureNote", "notes": null}
        ],
        "collections": [{"id": "collection", "org_id": "org", "name": "Work"}]
    }"#;

    const BITWARDEN_JSON: &str = r#"{
        "folders": [{"id": "folder", "name": "Work"}],
        "collections": [{"id": "collection", "organizationId": "org", "name": "Work"}],
        "items": [
            {
                "type": 1,
                "name": "login",
                "notes": "remember",
                "login": {
                    "uris": [{"uri": "https://example.test"}],
                    "fido2Credentials": [{"credentialId": "key"}]
                },
                "fields": [{"name": "env", "value": "prod"}],
                "passwordHistory": [{"password": "old"}]
            },
            {"type": 2, "name": "note"}
        ]
    }"#;

    fn assert_common(info: &Info, format: &str) {
        assert_eq!(info.format, format);
        assert_eq!(info.entries, 2);
        assert_eq!(info.logins, 1);
        assert_eq!(info.secure_notes, 1);
        assert_eq!(info.entries_with_notes, 1);
        assert_eq!(info.passkeys, 1);
        assert_eq!(info.collections, 1);
        assert_eq!(info.custom_fields, 1);
        assert_eq!(info.password_history, 1);
        assert_eq!(info.uris, 1);
    }

    #[test]
    fn rbw_json_reports_native_counts() {
        let info = summarize_rbw(RBW_JSON).unwrap();
        assert_common(&info, "rbw");
        assert_eq!(info.attachments, 1);
        assert_eq!(info.archived, 1);
    }

    #[test]
    fn bitwarden_json_reports_counts() {
        let vault =
            crate::import_bitwarden::parse_bitwarden_json(BITWARDEN_JSON)
                .unwrap();
        let info =
            summarize_bitwarden(vault, 0, DetectedFormat::BitwardenJson);
        assert_common(&info, "bitwarden-json");
        assert_eq!(info.folders, 1);
    }

    #[test]
    fn encrypted_json_reports_counts_after_decryption() {
        let encrypted = crate::import_bitwarden::encrypt_encrypted_json(
            BITWARDEN_JSON,
            "password",
            rbw::api::KdfType::Pbkdf2,
            100_000,
            None,
            None,
        )
        .unwrap();
        let info = summarize(
            encrypted.as_bytes(),
            DetectedFormat::BitwardenEncryptedJson,
            Some("password"),
        )
        .unwrap();
        assert_common(&info, "bitwarden-encrypted-json");
    }

    #[test]
    fn zip_reports_attachment_count() {
        let zip = crate::import_bitwarden::write_zip(
            BITWARDEN_JSON,
            &[(
                "login".to_string(),
                "file.txt".to_string(),
                b"data".to_vec(),
            )],
        )
        .unwrap();
        let info =
            summarize(&zip, DetectedFormat::BitwardenZip, None).unwrap();
        assert_common(&info, "bitwarden-zip");
        assert_eq!(info.attachments, 1);
    }

    #[test]
    fn csv_reports_supported_counts() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp\nWork,false,login,login,remember,env: prod,0,,https://example.test,user,password,,\n,false,note,note,,,,0,,,,\n";
        let info = summarize_csv(csv.as_bytes()).unwrap();
        assert_eq!(info.format, "bitwarden-csv");
        assert_eq!(info.entries, 2);
        assert_eq!(info.logins, 1);
        assert_eq!(info.secure_notes, 1);
        assert_eq!(info.folders, 1);
        assert_eq!(info.entries_with_notes, 1);
        assert_eq!(info.custom_fields, 1);
        assert_eq!(info.uris, 1);
    }

    #[test]
    fn auto_detects_csv_and_json_shapes() {
        assert_eq!(
            detect_format(RBW_JSON.as_bytes(), Format::Auto).unwrap(),
            DetectedFormat::Rbw
        );
        assert_eq!(
            detect_format(BITWARDEN_JSON.as_bytes(), Format::Auto).unwrap(),
            DetectedFormat::BitwardenJson
        );
        assert_eq!(
            detect_format(
                b"folder,type,name\n,login,example\n",
                Format::Auto
            )
            .unwrap(),
            DetectedFormat::BitwardenCsv
        );
    }
}
