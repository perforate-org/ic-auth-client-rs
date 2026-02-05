use crate::{
    controller::note::NoteController, infrastructure::note::repository::StableNoteRepository,
};
use domain::note::{entity::Note, NoteId, NoteTitle};
use ic_cdk_macros::*;

fn controller() -> NoteController<StableNoteRepository> {
    NoteController::new(StableNoteRepository::new())
}

#[query]
fn fetch_note(key: NoteId) -> Option<Note> {
    let controller = controller();
    controller.get(&key)
}

#[query]
fn fetch_note_list() -> Vec<(NoteId, NoteTitle)> {
    let controller = controller();
    controller.list()
}

#[update]
fn post_note(value: Note) {
    let mut controller = controller();
    controller.set(value)
}

#[update]
fn delete_note(key: NoteId) -> Result<(), String> {
    let mut controller = controller();
    controller.delete(&key)
}
