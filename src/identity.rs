use crate::prelude::*;

use sha1::Digest as _;

pub struct Identity {
    pub email: String,
    pub keys: crate::locked::Keys,
    pub master_password_hash: crate::locked::PasswordHash,
}

impl Identity {
    pub fn new(
        email: &str,
        password: &crate::locked::Password,
        kdf: crate::api::KdfType,
        iterations: u32,
        memory: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self> {
        let email = email.trim().to_lowercase();

        let iterations = std::num::NonZeroU32::new(iterations)
            .ok_or(Error::Pbkdf2ZeroIterations)?;

        let mut keys = crate::locked::Vec::new();
        keys.extend(std::iter::repeat_n(0, 64));

        let enc_key = &mut keys.data_mut()[0..32];

        match kdf {
            crate::api::KdfType::Pbkdf2 => {
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                    password.password(),
                    email.as_bytes(),
                    iterations.get(),
                    enc_key,
                )
                .map_err(|_| Error::Pbkdf2)?;
            }

            crate::api::KdfType::Argon2id => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(email.as_bytes());
                let salt = hasher.finalize();

                let argon2_config = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    argon2::Params::new(
                        memory.unwrap() * 1024,
                        iterations.get(),
                        parallelism.unwrap(),
                        Some(32),
                    )
                    .unwrap(),
                );
                argon2::Argon2::hash_password_into(
                    &argon2_config,
                    password.password(),
                    &salt,
                    enc_key,
                )
                .map_err(|_| Error::Argon2)?;
            }
        }

        let mut hash = crate::locked::Vec::new();
        hash.extend(std::iter::repeat_n(0, 32));
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            enc_key,
            password.password(),
            1,
            hash.data_mut(),
        )
        .map_err(|_| Error::Pbkdf2)?;

        let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(enc_key)
            .map_err(|_| Error::HkdfExpand)?;
        hkdf.expand(b"enc", enc_key)
            .map_err(|_| Error::HkdfExpand)?;
        let mac_key = &mut keys.data_mut()[32..64];
        hkdf.expand(b"mac", mac_key)
            .map_err(|_| Error::HkdfExpand)?;

        let keys = crate::locked::Keys::new(keys);
        let master_password_hash = crate::locked::PasswordHash::new(hash);

        Ok(Self {
            email: email.clone(),
            keys,
            master_password_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use hmac::{KeyInit as _, Mac as _};
    use sha2::Digest as _;

    fn decode_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // Fixed answers from an independent implementation (Python/OpenSSL).
    // Round trips alone would miss a consistently incorrect hash backend.
    #[test]
    fn sha256_known_answers_cover_short_and_multiple_blocks() {
        for (input, expected) in [
            (b"abc".to_vec(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (vec![b'a'; 1_000_000], "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        ] {
            assert_eq!(sha2::Sha256::digest(&input).as_slice(), decode_hex(expected));
        }
    }

    #[test]
    fn hmac_and_pbkdf2_sha256_match_independent_answers() {
        let mut mac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(&[0x0b; 20]).unwrap();
        mac.update(b"Hi There");
        assert_eq!(mac.finalize().into_bytes().as_slice(), decode_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
        let mut derived = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            b"password",
            b"salt",
            4096,
            &mut derived,
        )
        .unwrap();
        assert_eq!(derived.as_slice(), decode_hex("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));
    }
}
