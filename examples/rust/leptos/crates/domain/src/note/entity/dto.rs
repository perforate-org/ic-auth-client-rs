use super::super::{NoteId, NoteTitle};
use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(
    CandidType, Deserialize, Serialize, Debug, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
pub struct Note {
    pub id: NoteId,
    pub title: NoteTitle,
    pub content: String,
}

#[cfg(feature = "entity")]
mod model {
    use super::{super::model, Note};

    impl From<model::Note> for Note {
        fn from(note: model::Note) -> Self {
            Self {
                id: note.id,
                title: note.title,
                content: note.content,
            }
        }
    }

    impl From<Note> for model::Note {
        fn from(note: Note) -> Self {
            Self {
                id: note.id,
                title: note.title,
                content: note.content,
            }
        }
    }
}
