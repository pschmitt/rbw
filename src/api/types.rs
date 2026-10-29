#![allow(clippy::as_conversions)]

use crate::prelude::*;

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

impl std::fmt::Display for UriMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::enum_glob_use)]
        use UriMatchType::*;
        let s = match self {
            Domain => "domain",
            Host => "host",
            StartsWith => "starts_with",
            Exact => "exact",
            RegularExpression => "regular_expression",
            Never => "never",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

impl TwoFactorProviderType {
    pub fn message(&self) -> &str {
        match *self {
            Self::Authenticator => "Enter the 6 digit verification code from your authenticator app.",
            Self::Yubikey => "Insert your Yubikey and push the button.",
            Self::Email => "Enter the PIN you received via email.",
            _ => "Enter the code."
        }
    }

    pub fn header(&self) -> &str {
        match *self {
            Self::Authenticator => "Authenticator App",
            Self::Yubikey => "Yubikey",
            Self::Email => "Email Code",
            _ => "Two Factor Authentication",
        }
    }

    pub fn grab(&self) -> bool {
        !matches!(self, Self::Email)
    }
}

impl<'de> serde::Deserialize<'de> for TwoFactorProviderType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TwoFactorProviderTypeVisitor;
        impl serde::de::Visitor<'_> for TwoFactorProviderTypeVisitor {
            type Value = TwoFactorProviderType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("two factor provider id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(TwoFactorProviderTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for TwoFactorProviderType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::Yubikey),
            4 => Ok(Self::U2f),
            5 => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            7 => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for TwoFactorProviderType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Authenticator),
            "1" => Ok(Self::Email),
            "2" => Ok(Self::Duo),
            "3" => Ok(Self::Yubikey),
            "4" => Ok(Self::U2f),
            "5" => Ok(Self::Remember),
            "6" => Ok(Self::OrganizationDuo),
            "7" => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider { ty: ty.to_string() }),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl KdfType {
    // The number Bitwarden's API uses for it.
    pub fn number(self) -> u8 {
        match self {
            Self::Pbkdf2 => 0,
            Self::Argon2id => 1,
        }
    }
}

impl<'de> serde::Deserialize<'de> for KdfType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KdfTypeVisitor;
        impl serde::de::Visitor<'_> for KdfTypeVisitor {
            type Value = KdfType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("kdf id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(KdfTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for KdfType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Pbkdf2),
            1 => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for KdfType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Pbkdf2),
            "1" => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType { ty: ty.to_string() }),
        }
    }
}

impl serde::Serialize for KdfType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::Pbkdf2 => "0",
            Self::Argon2id => "1",
        };
        serializer.serialize_str(s)
    }
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum CipherRepromptType {
    None = 0,
    Password = 1,
}
