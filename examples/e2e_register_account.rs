// Test-only tool: creates a brand new Bitwarden/Vaultwarden account
// (email + master password) against a given server, doing the client-side
// crypto Bitwarden's own registration flow requires (KDF-derive a master
// key, generate a fresh vault symmetric key, generate an RSA keypair, wrap
// both, POST to `/identity/accounts/register`).
//
// Neither `rbw` nor the official `bw` CLI expose this -- `rbw register`
// and `bw login`/`unlock` all assume the account already exists server-
// side. This exists purely to bootstrap a throwaway test account for the
// e2e CI job against a disposable Vaultwarden container; it is not wired
// into the `rbw` binary or any real user-facing command.
//
// Usage: cargo run --example e2e_register_account -- \
//   --base-url http://localhost:8000 --email test@example.com \
//   --password 'Some Password123!' --name "rbw e2e"

use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    let args: std::vec::Vec<String> = std::env::args().collect();
    let base_url = arg(&args, "--base-url")
        .expect("--base-url is required")
        .trim_end_matches('/')
        .to_string();
    let email = arg(&args, "--email").expect("--email is required");
    let password = arg(&args, "--password").expect("--password is required");
    let name = arg(&args, "--name").unwrap_or_else(|| "rbw e2e".to_string());
    let kdf_iterations: u32 = arg(&args, "--kdf-iterations")
        .map_or(600_000, |s| {
            s.parse().expect("--kdf-iterations must be a number")
        });
    // Test-only escape hatch to exercise the Argon2id KDF path too (default
    // stays PBKDF2 to match every existing caller's expectations).
    let use_argon2 = arg(&args, "--kdf").as_deref() == Some("argon2id");
    let argon2_memory = 64_u32; // MiB (matches Identity::new's MB-input convention)
    let argon2_parallelism = 4_u32;

    let mut password_vec = rbw::locked::Vec::new();
    password_vec.extend(password.as_bytes().iter().copied());
    let password = rbw::locked::Password::new(password_vec);

    let identity = if use_argon2 {
        rbw::identity::Identity::new(
            &email,
            &password,
            rbw::api::KdfType::Argon2id,
            3, // iterations (argon2 "time cost", not pbkdf2 iterations)
            Some(argon2_memory),
            Some(argon2_parallelism),
        )
        .expect("failed to derive master key")
    } else {
        rbw::identity::Identity::new(
            &email,
            &password,
            rbw::api::KdfType::Pbkdf2,
            kdf_iterations,
            None,
            None,
        )
        .expect("failed to derive master key")
    };

    // The vault's own symmetric key -- randomly generated, then wrapped
    // ("protected") under the master-password-derived key above. This
    // (not the master key) is what actually encrypts/decrypts every
    // cipher in the vault.
    let mut user_key_vec = rbw::locked::Vec::new();
    let mut random_key = [0u8; 64];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut random_key);
    user_key_vec.extend(random_key.iter().copied());
    let user_keys = rbw::locked::Keys::new(user_key_vec.clone());

    let protected_key = rbw::cipherstring::CipherString::encrypt_symmetric(
        &identity.keys,
        user_key_vec.data(),
    )
    .expect("failed to wrap generated vault key");

    // RSA keypair used for org-invite encryption -- every account needs
    // one, wrapped under the vault key (not the master key). `rsa` pulls
    // in `rand_core` 0.6.x, which `rand` 0.9's `OsRng` doesn't implement
    // -- `rand_8` (rand 0.8.5) is already a dependency for exactly this
    // mismatch (see `cipherstring.rs`'s own RSA-adjacent code).
    let mut rng = rand_8::rngs::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .expect("failed to generate RSA keypair");
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let private_key_der = private_key
        .to_pkcs8_der()
        .expect("failed to encode RSA private key");
    let public_key_der = public_key
        .to_public_key_der()
        .expect("failed to encode RSA public key");

    let encrypted_private_key =
        rbw::cipherstring::CipherString::encrypt_symmetric(
            &user_keys,
            private_key_der.as_bytes(),
        )
        .expect("failed to wrap RSA private key");

    let body = serde_json::json!({
        "name": name,
        "email": email,
        "masterPasswordHash": rbw::base64::encode(identity.master_password_hash.hash()),
        "masterPasswordHint": serde_json::Value::Null,
        "key": protected_key.to_string(),
        "keys": {
            "publicKey": rbw::base64::encode(public_key_der.as_bytes()),
            "encryptedPrivateKey": encrypted_private_key.to_string(),
        },
        "kdf": i32::from(use_argon2),
        "kdfIterations": if use_argon2 { 3 } else { kdf_iterations },
        "kdfMemory": if use_argon2 {
            serde_json::Value::from(argon2_memory)
        } else {
            serde_json::Value::Null
        },
        "kdfParallelism": if use_argon2 {
            serde_json::Value::from(argon2_parallelism)
        } else {
            serde_json::Value::Null
        },
    });

    let client = reqwest::blocking::Client::new();
    let res = client
        .post(format!("{base_url}/identity/accounts/register"))
        .json(&body)
        .send()
        .expect("registration request failed to send");
    let status = res.status();
    let text = res.text().unwrap_or_default();
    if status.is_success() {
        eprintln!("registered {email} successfully");
    } else {
        eprintln!("registration failed ({status}): {text}");
        std::process::exit(1);
    }
}
