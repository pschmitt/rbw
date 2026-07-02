use rand::seq::IteratorRandom as _;

use crate::config::PasswordGenPolicy;

const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const NUMBERS: &[u8] = b"0123456789";
const LETTERS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NONCONFUSABLES: &[u8] = b"34678abcdefhjkmnpqrtuwxy";

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Type {
    AllChars,
    NoSymbols,
    Numbers,
    NonConfusables,
    Diceware,
}

pub fn pwgen(ty: Type, len: usize) -> String {
    let mut rng = rand::rng();

    let alphabet = match ty {
        Type::AllChars => {
            let mut v = vec![];
            v.extend(SYMBOLS.iter().copied());
            v.extend(NUMBERS.iter().copied());
            v.extend(LETTERS.iter().copied());
            v
        }
        Type::NoSymbols => {
            let mut v = vec![];
            v.extend(NUMBERS.iter().copied());
            v.extend(LETTERS.iter().copied());
            v
        }
        Type::Numbers => {
            let mut v = vec![];
            v.extend(NUMBERS.iter().copied());
            v
        }
        Type::NonConfusables => {
            let mut v = vec![];
            v.extend(NONCONFUSABLES.iter().copied());
            v
        }
        Type::Diceware => {
            return diceware(&mut rng, len);
        }
    };

    let mut pass = vec![];
    pass.extend(
        std::iter::repeat_with(|| alphabet.iter().choose(&mut rng).unwrap())
            .take(len),
    );
    // unwrap is safe because the method of generating passwords guarantees
    // valid utf8
    String::from_utf8(pass).unwrap()
}

// Password-generation flags, independent of where they came from (an
// explicit CLI flag, or the configured default policy). `resolve` layers a
// CLI-sourced instance over a config-sourced one over these hardcoded
// fallbacks, so `rbw gen` and `rbw create --generate` share one priority
// order.
#[derive(Debug, Clone, Copy, Default)]
pub struct GenFlags {
    pub length: Option<usize>,
    pub no_symbols: bool,
    pub only_numbers: bool,
    pub nonconfusables: bool,
    pub diceware: bool,
}

impl GenFlags {
    fn ty(self) -> Option<Type> {
        if self.no_symbols {
            Some(Type::NoSymbols)
        } else if self.only_numbers {
            Some(Type::Numbers)
        } else if self.nonconfusables {
            Some(Type::NonConfusables)
        } else if self.diceware {
            Some(Type::Diceware)
        } else {
            None
        }
    }
}

impl From<&PasswordGenPolicy> for GenFlags {
    fn from(policy: &PasswordGenPolicy) -> Self {
        Self {
            length: policy.length,
            no_symbols: policy.no_symbols,
            only_numbers: policy.only_numbers,
            nonconfusables: policy.nonconfusables,
            diceware: policy.diceware,
        }
    }
}

// Hardcoded fallback length, used only when neither an explicit CLI flag nor
// the configured policy sets one.
pub const DEFAULT_LEN: usize = 20;

// The length/type to actually generate with: an explicit `cli` flag wins,
// then the configured default `policy`, then `DEFAULT_LEN`/`Type::AllChars`.
pub fn resolve(cli: GenFlags, policy: GenFlags) -> (usize, Type) {
    let len = cli.length.or(policy.length).unwrap_or(DEFAULT_LEN);
    let ty = cli.ty().or_else(|| policy.ty()).unwrap_or(Type::AllChars);
    (len, ty)
}

fn diceware(rng: &mut impl rand::RngCore, len: usize) -> String {
    let mut words = vec![];
    for _ in 0..len {
        // unwrap is safe because choose only returns None for an empty slice
        words.push(*crate::wordlist::EFF_LONG.iter().choose(rng).unwrap());
    }
    words.join(" ")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pwgen() {
        let pw = pwgen(Type::AllChars, 50);
        assert_eq!(pw.len(), 50);
        // technically this could fail, but the chances are incredibly low
        // (around 0.000009%)
        assert_duplicates(&pw);

        let pw = pwgen(Type::AllChars, 100);
        assert_eq!(pw.len(), 100);
        assert_duplicates(&pw);

        let pw = pwgen(Type::NoSymbols, 100);
        assert_eq!(pw.len(), 100);
        assert_duplicates(&pw);

        let pw = pwgen(Type::Numbers, 100);
        assert_eq!(pw.len(), 100);
        assert_duplicates(&pw);

        let pw = pwgen(Type::NonConfusables, 100);
        assert_eq!(pw.len(), 100);
        assert_duplicates(&pw);
    }

    #[track_caller]
    fn assert_duplicates(s: &str) {
        let mut set = std::collections::HashSet::new();
        for c in s.chars() {
            set.insert(c);
        }
        assert!(set.len() < s.len());
    }
}
