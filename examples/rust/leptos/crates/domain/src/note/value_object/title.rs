use candid::CandidType;
use derive_more::{AsRef, Display};
use serde::{Deserialize, Serialize};

/// Title for notes should be 50 characters or less
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
    Clone,
    AsRef,
    Display,
)]
pub struct NoteTitle(String);

impl NoteTitle {
    const MAX_LEN: usize = 50;

    pub fn new(name: String) -> Result<Self, NoteTitleError> {
        let len = name.chars().count();

        if len > Self::MAX_LEN {
            return Err(NoteTitleError::TooLong);
        }
        Ok(Self(name))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(
    thiserror::Error, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy,
)]
pub enum NoteTitleError {
    #[error("Title is too long")]
    TooLong,
}

#[cfg(feature = "ic-stable")]
mod ic_stable {
    use super::*;
    use ic_stable_structures::storable::{Bound, Storable};
    use std::borrow::Cow;

    impl Storable for NoteTitle {
        fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
            self.0.to_bytes()
        }

        fn into_bytes(self) -> Vec<u8> {
            self.0.into_bytes()
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            NoteTitle(String::from_bytes(bytes))
        }

        const BOUND: Bound = Bound::Bounded {
            max_size: NoteTitle::MAX_LEN as u32 * 4,
            is_fixed_size: false,
        };
    }
}
