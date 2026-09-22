// Support for Bitwarden's "Encryption V2": CipherString type 7
// (`CoseEncrypt0B64`), a COSE_Encrypt0 structure (RFC 9052) encrypting its
// payload with XChaCha20-Poly1305 under a private-use COSE algorithm id,
// rather than the classic AES-256-CBC-HMAC-SHA256 scheme every other
// CipherString type uses (see `cipherstring.rs`). Reference:
// https://github.com/bitwarden/sdk-internal, crates/bitwarden-crypto/src/cose/.
//
// Scope: read-only decrypt of the account's own user key and private key
// (both wrapped, independently, as their own CoseEncrypt0 CipherStrings --
// see `actions::unlock`). rbw never needs to produce a V2 CipherString of
// its own.

use crate::prelude::*;

use chacha20poly1305::{
    aead::{Aead as _, KeyInit as _, Payload},
    XChaCha20Poly1305,
};
use coset::CborSerializable as _;

// Standard ChaCha20-Poly1305's 96-bit nonce is too small to safely generate
// randomly at Bitwarden's volume; XChaCha20's 192-bit nonce avoids that.
// Below the IANA-assigned algorithm range, so it's a COSE "private use" id
// rather than a registered one -- the protected header carries it directly,
// making a CoseEncrypt0 message self-describing about which algorithm
// decrypts it.
const XCHACHA20_POLY1305: i64 = -70_000;

const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;

// Decrypts a COSE_Encrypt0 CipherString (the contents of a type-7 string,
// already base64-decoded) using a 32-byte XChaCha20-Poly1305 key.
//
// `key` is expected to be exactly 32 bytes. Callers unwrapping an account's
// V2 user/private key pass `wrapping_key.enc_key()` (the first 32 bytes of
// the existing `locked::Keys` shape) rather than a new key type, on the
// (unconfirmed against a real V2-migrated account -- see this repo's
// AGENTS.md) assumption that a V2 account's decrypted user key is itself a
// native 32-byte key rather than the legacy 64-byte AES-key+HMAC-key split.
// If that assumption is wrong, this fails loudly with `Error::CoseDecrypt`
// (an AEAD authentication-tag mismatch) rather than silently producing
// incorrect plaintext -- that's what AEAD decryption guarantees regardless
// of which specific bytes were fed in as the key.
pub fn decrypt(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let msg = coset::CoseEncrypt0::from_slice(bytes)
        .map_err(|source| Error::CoseParse { source })?;

    match &msg.protected.header.alg {
        Some(coset::RegisteredLabelWithPrivate::PrivateUse(
            XCHACHA20_POLY1305,
        )) => {}
        other => {
            return Err(Error::CoseUnsupportedAlgorithm {
                alg: format!("{other:?}"),
            });
        }
    }

    let nonce = &msg.unprotected.iv;
    if nonce.len() != NONCE_SIZE {
        return Err(Error::CoseUnsupportedAlgorithm {
            alg: format!(
                "expected a {NONCE_SIZE}-byte nonce, got {}",
                nonce.len()
            ),
        });
    }
    let nonce = chacha20poly1305::XNonce::try_from(nonce.as_slice())
        .map_err(|_| Error::CoseUnsupportedAlgorithm {
            alg: "invalid nonce".to_string(),
        })?;

    let key = chacha20poly1305::Key::try_from(key).map_err(|_| {
        Error::CoseUnsupportedAlgorithm {
            alg: format!("expected a {KEY_SIZE}-byte key"),
        }
    })?;
    let cipher = XChaCha20Poly1305::new(&key);

    msg.decrypt_ciphertext(
        &[],
        || Error::CoseDecrypt,
        |ciphertext, aad| {
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| Error::CoseDecrypt)
        },
    )
}

#[cfg(test)]
fn encrypt(plaintext: &[u8], key: &[u8; KEY_SIZE]) -> Vec<u8> {
    use rand::Rng as _;

    let mut nonce_bytes = [0_u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce =
        chacha20poly1305::XNonce::try_from(nonce_bytes.as_slice()).unwrap();

    let key = chacha20poly1305::Key::try_from(key.as_slice()).unwrap();
    let cipher = XChaCha20Poly1305::new(&key);
    let mut protected = coset::HeaderBuilder::new().build();
    protected.alg = Some(coset::RegisteredLabelWithPrivate::PrivateUse(
        XCHACHA20_POLY1305,
    ));
    let unprotected =
        coset::HeaderBuilder::new().iv(nonce_bytes.to_vec()).build();

    let msg = coset::CoseEncrypt0Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .create_ciphertext(plaintext, &[], |data, aad| {
            cipher.encrypt(&nonce, Payload { msg: data, aad }).unwrap()
        })
        .build();

    msg.to_vec().unwrap()
}

#[test]
fn test_roundtrip() {
    let key = [0x42_u8; KEY_SIZE];
    let plaintext = b"a v2-wrapped account key, for testing";

    let bytes = encrypt(plaintext, &key);
    let decrypted = decrypt(&bytes, &key).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_wrong_key_fails_closed() {
    let key = [0x42_u8; KEY_SIZE];
    let wrong_key = [0x43_u8; KEY_SIZE];
    let plaintext = b"a v2-wrapped account key, for testing";

    let bytes = encrypt(plaintext, &key);
    assert!(matches!(
        decrypt(&bytes, &wrong_key),
        Err(Error::CoseDecrypt)
    ));
}

#[test]
fn test_malformed_cose_bytes() {
    let key = [0x42_u8; KEY_SIZE];
    assert!(matches!(
        decrypt(b"not a cose message", &key),
        Err(Error::CoseParse { .. })
    ));
}

#[test]
fn test_wrong_key_length() {
    let key = [0x42_u8; KEY_SIZE];
    let bytes = encrypt(b"plaintext", &key);
    assert!(matches!(
        decrypt(&bytes, &key[..16]),
        Err(Error::CoseUnsupportedAlgorithm { .. })
    ));
}
