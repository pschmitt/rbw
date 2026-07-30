//! Native integration with Termux:API's Android Keystore commands.
//!
//! The private key never leaves Android Keystore. rbw uses a signature over a
//! random challenge as key material for an HKDF-derived AES-GCM key; the
//! signature itself is not stored or treated as a secret at rest.

use aes_gcm::{aead::Aead as _, aead::KeyInit as _, Aes256Gcm, Nonce};
use anyhow::Context as _;
use hkdf::Hkdf;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use zeroize::Zeroize as _;

const BUNDLE_VERSION: u8 = 1;
const AAD: &[u8] = b"rbw/termux-keystore/v1";
const CHALLENGE_LEN: usize = 32;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

pub fn default_key_alias(account_name: &str) -> String {
    format!("rbw-{}", safe_component(account_name))
}

pub fn default_bundle_path(account_name: &str) -> std::path::PathBuf {
    crate::dirs::config_file()
        .parent()
        .expect("rbw config path has a parent")
        .join("termux")
        .join(format!("{}.bundle", safe_component(account_name)))
}

fn safe_component(value: &str) -> String {
    let component: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric()
                || matches!(character, '.' | '_' | '-')
            {
                character
            } else {
                '_'
            }
        })
        .collect();
    if component.is_empty() {
        "default".to_string()
    } else {
        component
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Bundle {
    version: u8,
    challenge: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize)]
struct KeyInfo {
    alias: String,
    inside_secure_hardware: bool,
    user_authentication: UserAuthentication,
}

#[derive(Debug, Deserialize)]
struct UserAuthentication {
    required: bool,
    enforced_by_secure_hardware: bool,
    validity_duration_seconds: u64,
}

fn command_output(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> anyhow::Result<std::process::Output> {
    let mut command = std::process::Command::new(program);
    command.args(args);
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command.stdin(if stdin.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {program}"))?;
    if let Some(stdin_data) = stdin {
        child
            .stdin
            .take()
            .expect("stdin was requested")
            .write_all(stdin_data)
            .with_context(|| format!("failed to write to {program}"))?;
    }
    child
        .wait_with_output()
        .with_context(|| format!("failed to wait for {program}"))
}

fn run_keystore(
    args: &[&str],
    stdin: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let output = command_output("termux-keystore", args, stdin)?;
    if !output.status.success() {
        anyhow::bail!(
            "termux-keystore {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if output.stdout.is_empty() {
        Ok(output.stderr)
    } else {
        Ok(output.stdout)
    }
}

fn sign(
    key_alias: &str,
    algorithm: &str,
    challenge: &[u8],
) -> anyhow::Result<Vec<u8>> {
    ensure_key_is_authenticated(key_alias)?;
    run_keystore(&["sign", key_alias, algorithm], Some(challenge))
}

fn key_infos() -> anyhow::Result<Vec<KeyInfo>> {
    let output = run_keystore(&["list", "-d"], None)?;
    serde_json::from_slice(&output)
        .context("termux-keystore returned invalid key metadata")
}

fn ensure_key_is_authenticated(key_alias: &str) -> anyhow::Result<()> {
    let keys = key_infos()?;
    let Some(key) = keys.into_iter().find(|key| key.alias == key_alias)
    else {
        anyhow::bail!("Termux Keystore key {key_alias:?} was not found");
    };
    if !key.inside_secure_hardware
        || !key.user_authentication.required
        || !key.user_authentication.enforced_by_secure_hardware
        || key.user_authentication.validity_duration_seconds == 0
    {
        anyhow::bail!(
            "Termux Keystore key {key_alias:?} is not hardware-backed and \
             authentication-gated"
        );
    }
    Ok(())
}

fn derive_key(signature: &[u8], salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), signature);
    let mut key = [0_u8; 32];
    hk.expand(AAD, &mut key)
        .map_err(|_| anyhow::anyhow!("failed to derive Termux unlock key"))?;
    Ok(key)
}

fn decode_field(name: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    crate::base64::decode(value)
        .with_context(|| format!("Termux bundle has invalid {name} base64"))
}

fn decrypt_bundle(
    bundle: &Bundle,
    signature: &[u8],
) -> anyhow::Result<String> {
    if bundle.version != BUNDLE_VERSION {
        anyhow::bail!(
            "unsupported Termux unlock bundle version {}",
            bundle.version
        );
    }
    let salt = decode_field("salt", &bundle.salt)?;
    let nonce = decode_field("nonce", &bundle.nonce)?;
    let ciphertext = decode_field("ciphertext", &bundle.ciphertext)?;
    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN {
        anyhow::bail!("invalid Termux unlock bundle parameters");
    }

    let mut key = derive_key(signature, &salt)?;
    let result = Aes256Gcm::new_from_slice(&key)
        .expect("AES-256-GCM keys are always 32 bytes")
        .decrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext.as_ref(),
                aad: AAD,
            },
        )
        .map_err(|_| {
            anyhow::anyhow!("failed to decrypt Termux unlock bundle")
        });
    key.zeroize();
    let plaintext = result?;
    let password = String::from_utf8(plaintext)
        .context("Termux unlock bundle does not contain UTF-8")?;
    Ok(password)
}

pub fn unlock(
    config: &crate::config::TermuxKeystoreUnlock,
) -> anyhow::Result<String> {
    let bundle_data = std::fs::read(&config.file).with_context(|| {
        format!("failed to read {}", config.file.display())
    })?;
    let bundle: Bundle =
        serde_json::from_slice(&bundle_data).with_context(|| {
            format!("failed to parse {}", config.file.display())
        })?;
    let challenge = decode_field("challenge", &bundle.challenge)?;
    if challenge.len() != CHALLENGE_LEN {
        anyhow::bail!("invalid Termux unlock bundle challenge");
    }
    let mut signature =
        sign(&config.key_alias, &config.algorithm, &challenge)?;
    let result = decrypt_bundle(&bundle, &signature);
    signature.zeroize();
    result
}

pub fn enroll(
    file: &std::path::Path,
    key_alias: &str,
    algorithm: &str,
    mut password: Vec<u8>,
) -> anyhow::Result<()> {
    let result = enroll_inner(file, key_alias, algorithm, &password);
    password.zeroize();
    result
}

fn enroll_inner(
    file: &std::path::Path,
    key_alias: &str,
    algorithm: &str,
    password: &[u8],
) -> anyhow::Result<()> {
    if password.is_empty() {
        anyhow::bail!("the master password must not be empty");
    }
    let mut challenge = [0_u8; CHALLENGE_LEN];
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut challenge);
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);

    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create {}", parent.display())
        })?;
        std::fs::set_permissions(
            parent,
            std::fs::Permissions::from_mode(0o700),
        )
        .with_context(|| format!("failed to protect {}", parent.display()))?;
    }

    let mut signature = sign(key_alias, algorithm, &challenge)?;
    let mut key = derive_key(&signature, &salt)?;
    let result = Aes256Gcm::new_from_slice(&key)
        .expect("AES-256-GCM keys are always 32 bytes")
        .encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: password,
                aad: AAD,
            },
        )
        .map_err(|_| {
            anyhow::anyhow!("failed to encrypt Termux unlock bundle")
        });
    key.zeroize();
    signature.zeroize();
    let ciphertext = result?;

    let bundle = Bundle {
        version: BUNDLE_VERSION,
        challenge: crate::base64::encode(challenge),
        salt: crate::base64::encode(salt),
        nonce: crate::base64::encode(nonce),
        ciphertext: crate::base64::encode(ciphertext),
    };
    let json = serde_json::to_vec_pretty(&bundle)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file)
        .with_context(|| format!("failed to create {}", file.display()))?;
    output.write_all(&json)?;
    output.write_all(b"\n")?;
    Ok(())
}

pub fn delete(key_alias: &str) -> anyhow::Result<()> {
    run_keystore(&["delete", key_alias], None).map(|_| ())
}

pub fn generate(
    key_alias: &str,
    algorithm: &str,
    size: Option<u32>,
    validity: u32,
) -> anyhow::Result<()> {
    let algorithm = algorithm.to_ascii_uppercase();
    let mut args = vec!["generate", key_alias, "-a", &algorithm, "-u"];
    let validity = validity.to_string();
    args.push(&validity);
    let size = size.map(|size| size.to_string());
    if let Some(size) = size.as_deref() {
        args.extend(["-s", size]);
    }
    run_keystore(&args, None)?;
    Ok(())
}

pub fn status(key_alias: Option<&str>) -> anyhow::Result<()> {
    let keys = key_infos()?;
    for key in keys {
        if key_alias.is_none() || key_alias == Some(key.alias.as_str()) {
            println!(
                "{}: hardware={}, authentication_required={}, hardware_enforced={}, validity={}s",
                key.alias,
                key.inside_secure_hardware,
                key.user_authentication.required,
                key.user_authentication.enforced_by_secure_hardware,
                key.user_authentication.validity_duration_seconds,
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_round_trip() {
        let signature = b"test signature".to_vec();
        let mut challenge = [0_u8; CHALLENGE_LEN];
        let mut salt = [0_u8; SALT_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut challenge);
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);
        let key = derive_key(&signature, &salt).unwrap();
        let ciphertext = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: b"master password",
                    aad: AAD,
                },
            )
            .unwrap();
        let bundle = Bundle {
            version: BUNDLE_VERSION,
            challenge: crate::base64::encode(challenge),
            salt: crate::base64::encode(salt),
            nonce: crate::base64::encode(nonce),
            ciphertext: crate::base64::encode(ciphertext),
        };
        assert_eq!(
            decrypt_bundle(&bundle, &signature).unwrap(),
            "master password"
        );
    }
}
