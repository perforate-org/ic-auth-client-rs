use super::{entity::model::Note, repository::NoteRepository, NoteId, NoteTitle};

pub struct NoteService<R: NoteRepository> {
    repository: R,
}

impl<R: NoteRepository> NoteService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn get(&self, id: &NoteId) -> Option<Note> {
        self.repository.get(id)
    }

    pub fn set(&mut self, note: Note) {
        self.repository.insert(note);
    }

    pub fn delete(&mut self, id: &NoteId) -> Result<(), NoteServiceError> {
        match self.repository.remove(id) {
            Some(_) => Ok(()),
            None => Err(NoteServiceError::NotFound),
        }
    }

    pub fn list(&self) -> Vec<(NoteId, NoteTitle)> {
        self.repository.list()
    }
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteServiceError {
    #[error("Note not found")]
    NotFound,
}
