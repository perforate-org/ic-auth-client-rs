use crate::use_case::note::NoteUseCase;
use domain::note::{entity::dto::Note, repository::NoteRepository, NoteId, NoteTitle};

pub struct NoteController<R: NoteRepository> {
    use_case: NoteUseCase<R>,
}

impl<R: NoteRepository> NoteController<R> {
    pub fn new(repository: R) -> Self {
        Self {
            use_case: NoteUseCase::new(repository),
        }
    }

    pub fn get(&self, id: &NoteId) -> Option<Note> {
        self.use_case.get(id).map(|note| note.into())
    }

    pub fn set(&mut self, note: Note) {
        self.use_case.set(note.into());
    }

    pub fn delete(&mut self, id: &NoteId) -> Result<(), String> {
        self.use_case.delete(id).map_err(|e| e.to_string())
    }

    pub fn list(&self) -> Vec<(NoteId, NoteTitle)> {
        self.use_case.list()
    }
}
