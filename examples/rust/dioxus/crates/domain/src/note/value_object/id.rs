use candid::CandidType;
use derive_more::{AsRef, Display, From, FromStr};
use serde::{Deserialize, Serialize};

/// Identifier for notes should be unique and incrementing
#[derive(
    CandidType,
    Serialize,
    Deserialize,
    Debug,
    Hash,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Copy,
    Clone,
    AsRef,
    Display,
    From,
    FromStr,
)]
pub struct NoteId(u32);

impl NoteId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn increment(&self) -> Self {
        Self(self.0 + 1)
    }
}

#[cfg(feature = "ic-stable")]
mod ic_stable {
    use super::*;
    use ic_stable_structures::storable::{Bound, Storable};
    use std::borrow::Cow;

    impl Storable for NoteId {
        fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
            self.0.to_bytes()
        }

        fn into_bytes(self) -> Vec<u8> {
            self.0.into_bytes()
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            NoteId(u32::from_bytes(Cow::Borrowed(&bytes[0..4])))
        }

        const BOUND: Bound = Bound::Bounded {
            max_size: 4,
            is_fixed_size: true,
        };
    }
}
