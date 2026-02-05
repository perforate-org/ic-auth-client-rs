use super::{
    super::{NoteId, NoteTitle},
    dao::{NoteDao, NoteDaoVersion, V1},
};

#[derive(Debug, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Note {
    pub id: NoteId,
    pub title: NoteTitle,
    pub content: String,
}

impl Note {
    pub fn from_dao(id: NoteId, dao: NoteDao) -> Self {
        match dao.version {
            NoteDaoVersion::V1(v1) => Note {
                id,
                title: v1.title,
                content: v1.content,
            },
        }
    }
}

impl From<Note> for NoteDao {
    fn from(note: Note) -> Self {
        NoteDao {
            version: NoteDaoVersion::V1(V1 {
                title: note.title,
                content: note.content,
            }),
        }
    }
}
