use domain::note::{
    entity::model::Note,
    repository::NoteRepository,
    service::{NoteService, NoteServiceError},
    NoteId, NoteTitle,
};

pub struct NoteUseCase<R: NoteRepository> {
    service: NoteService<R>,
}

impl<R: NoteRepository> NoteUseCase<R> {
    pub fn new(repository: R) -> Self {
        Self {
            service: NoteService::new(repository),
        }
    }

    pub fn get(&self, id: &NoteId) -> Option<Note> {
        self.service.get(id)
    }

    pub fn set(&mut self, note: Note) {
        self.service.set(note)
    }

    pub fn delete(&mut self, id: &NoteId) -> Result<(), NoteServiceError> {
        self.service.delete(id)
    }

    pub fn list(&self) -> Vec<(NoteId, NoteTitle)> {
        self.service.list()
    }
}
