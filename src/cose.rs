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
use zeroize::Zeroize as _;

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
// already base64-decoded) using a 32-byte XChaCha20-Poly1305 key. `key`
// must be exactly 32 bytes -- see `unwrap_symmetric_key` for how callers
// get a correctly-shaped key out of whatever they decrypted the *previous*
// layer into, since a wrapping key isn't always already in this shape.
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

// A decrypted "key" CipherString -- e.g. the account's user key, decrypted
// from `profile.key` -- is either the legacy shape rbw has always
// understood (64 raw bytes, enc_key || mac_key -- see `locked::Keys`), or,
// on an account whose user key has itself been upgraded to a native
// XChaCha20-Poly1305 key, a COSE_Key (RFC 9052) structure PKCS7-padded to
// at least 65 bytes so its length alone distinguishes it from the legacy
// shapes (see bitwarden-crypto's `SymmetricCryptoKey::to_encoded()` /
// `TryFrom<&BitwardenLegacyKeyBytes>`). This normalizes either shape into
// something `locked::Keys` can hold: the legacy 64 bytes unchanged, or the
// unwrapped 32-byte native key zero-padded to fill the same container
// (nothing downstream reads the unused upper half unless the CipherString
// it's wrapping turns out to be type 2 after all, which would be a real
// bug to surface elsewhere, not paper over here).
pub fn unwrap_symmetric_key(
    plaintext: &crate::locked::Vec,
) -> Result<crate::locked::Keys> {
    let data = plaintext.data();
    if data.len() <= 64 {
        let mut res = crate::locked::Vec::new();
        res.extend(data.iter().copied());
        return Ok(crate::locked::Keys::new(res));
    }

    let unpadded =
        crate::cipherstring::pkcs7_unpad(data).ok_or(Error::Padding)?;
    let cose_key = coset::CoseKey::from_slice(unpadded)
        .map_err(|source| Error::CoseParse { source })?;

    let key_param = coset::Label::Int(coset::iana::EnumI64::to_i64(
        &coset::iana::SymmetricKeyParameter::K,
    ));
    let mut key_bytes = cose_key
        .params
        .into_iter()
        .find_map(|(label, value)| match (label == key_param, value) {
            (true, coset::cbor::Value::Bytes(bytes)) => Some(bytes),
            _ => None,
        })
        .ok_or_else(|| Error::CoseUnsupportedAlgorithm {
            alg: "COSE key missing symmetric key parameter".to_string(),
        })?;

    let mut res = crate::locked::Vec::new();
    res.extend(key_bytes.iter().copied());
    res.extend(std::iter::repeat_n(
        0_u8,
        64_usize.saturating_sub(res.data().len()),
    ));
    key_bytes.zeroize();
    Ok(crate::locked::Keys::new(res))
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

#[test]
fn test_unwrap_symmetric_key_legacy() {
    // A legacy (V1) decrypted user key is passed through unchanged: 64
    // raw bytes, no COSE framing.
    let mut plaintext = crate::locked::Vec::new();
    plaintext.extend(0_u8..64);

    let keys = unwrap_symmetric_key(&plaintext).unwrap();
    assert_eq!(
        keys.enc_key(),
        &(0_u8..32).collect::<std::vec::Vec<_>>()[..]
    );
    assert_eq!(
        keys.mac_key(),
        &(32_u8..64).collect::<std::vec::Vec<_>>()[..]
    );
}

#[test]
fn test_unwrap_symmetric_key_cose() {
    // A V2 decrypted user key is a COSE_Key, PKCS7-padded to be
    // unambiguously longer than the legacy 64-byte shape.
    let raw_key = [0x77_u8; KEY_SIZE];
    let cose_key =
        coset::CoseKeyBuilder::new_symmetric_key(raw_key.to_vec()).build();
    let mut bytes = cose_key.to_vec().unwrap();

    let target_len = bytes.len().max(64) + 1;
    let pad_len = target_len - bytes.len();
    bytes
        .extend(std::iter::repeat_n(u8::try_from(pad_len).unwrap(), pad_len));

    let mut plaintext = crate::locked::Vec::new();
    plaintext.extend(bytes.iter().copied());

    let keys = unwrap_symmetric_key(&plaintext).unwrap();
    assert_eq!(keys.enc_key(), &raw_key[..]);
}

// Real cross-compatibility check, not just a self-roundtrip: this exact
// COSE_Encrypt0 blob was generated by Bitwarden's own `bitwarden-crypto`
// Rust crate (github.com/bitwarden/sdk-internal), encrypting the plaintext
// below under an all-zero 32-byte XChaCha20-Poly1305 key, following the
// generator-test pattern documented in that repo's own
// `.claude/skills/create-testvectors/SKILL.md`. Proves this module's COSE
// parsing/algorithm-id validation/AEAD decrypt actually matches real
// Bitwarden wire output, not just our own encrypt/decrypt agreeing with
// itself.
//
// Encrypted via their high-level string API, which pads UTF-8 content to
// 32-byte blocks before encrypting (see the module doc comment) -- Phase
// 1's actual use (account user/private keys) doesn't go through that
// content type and never needs to strip this padding, so the assertion
// below only checks the decrypted plaintext *starts with* the known
// string rather than unpadding it.
#[test]
fn test_real_bitwarden_crypto_vector() {
    let key = [0_u8; KEY_SIZE];
    let plaintext = b"rbw cross-compatibility test vector, all-zero key";
    let encoded = "g1g/owE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLnV0ZjgtcGFkZGVkBFAAAAAAAAAAAAAAAAAAAAAAoQVYGF6c5j7Xwx+9+WnLMclfRTqiMz6siaWhhFhQfuI6kSK3v19JIlisPjsT/j65ivnEajqfrBrrfqGCgHZ1G17UqR6pKR+3jaAhfTyNW5Vlb8XHkUPrC9KmaePufSp1qHTMHqIlrcB5w2NHx30=";

    let bytes = crate::base64::decode(encoded).unwrap();
    let decrypted = decrypt(&bytes, &key).unwrap();

    assert!(decrypted.starts_with(plaintext));
}
