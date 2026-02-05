use candid::CandidType;
use serde::{Deserialize, Serialize};

mod v1;
pub(crate) use v1::V1;

#[derive(CandidType, Clone, Serialize, Deserialize, Debug)]
pub struct NoteDao {
    pub(crate) version: NoteDaoVersion,
}

#[cfg(feature = "ic-stable")]
mod ic_stable {
    use super::*;
    use ic_stable_structures::storable::{Bound, Storable};
    use std::borrow::Cow;

    impl Storable for NoteDao {
        fn to_bytes(&'_ self) -> Cow<'_, [u8]> {
            Cow::Owned(candid::encode_one(self).expect("Failed to encode NoteDao"))
        }

        fn into_bytes(self) -> Vec<u8> {
            candid::encode_one(self).expect("Failed to encode NoteDao")
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            candid::decode_one(&bytes).expect("Failed to decode NoteDao")
        }

        const BOUND: Bound = Bound::Unbounded;
    }
}

#[derive(CandidType, Clone, Serialize, Deserialize, Debug)]
pub(crate) enum NoteDaoVersion {
    V1(V1),
}
