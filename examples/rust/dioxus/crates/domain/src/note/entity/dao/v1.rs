use super::super::super::NoteTitle;
use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(CandidType, Clone, Serialize, Deserialize, Debug)]
pub struct V1 {
    pub(crate) title: NoteTitle,
    pub(crate) content: String,
}
