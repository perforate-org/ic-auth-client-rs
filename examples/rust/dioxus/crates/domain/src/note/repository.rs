use super::{entity::model::Note, NoteId, NoteTitle};

pub trait NoteRepository {
    fn get(&self, key: &NoteId) -> Option<Note>;
    fn contains(&self, key: &NoteId) -> bool;
    fn insert(&mut self, value: Note) -> Option<Note>;
    fn remove(&mut self, key: &NoteId) -> Option<Note>;
    fn list(&self) -> Vec<(NoteId, NoteTitle)>;
}
