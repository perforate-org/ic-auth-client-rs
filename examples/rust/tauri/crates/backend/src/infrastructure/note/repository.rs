use super::super::STATE;
use domain::note::{entity::model::Note, repository::NoteRepository, NoteId, NoteTitle};
use ic_cdk::api::msg_caller;
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
pub struct StableNoteRepository;

impl StableNoteRepository {
    /// Creates a new instance of `StableNoteRepository`.
    pub fn new() -> Self {
        StableNoteRepository {}
    }
}

impl NoteRepository for StableNoteRepository {
    fn get(&self, key: &NoteId) -> Option<Note> {
        let dao = STATE.with_borrow(|state| state.notes.get(&(msg_caller(), *key)))?;

        Some(Note::from_dao(*key, dao))
    }

    fn contains(&self, key: &NoteId) -> bool {
        STATE.with_borrow(|state| {
            state
                .note_lists
                .get(&msg_caller())
                .is_some_and(|list| list.contains(key))
        })
    }

    fn insert(&mut self, value: Note) -> Option<Note> {
        let id = value.id;
        let dao = STATE.with_borrow_mut(|state| {
            // Check if caller exists in state.note_lists, add if not, then add NoteId to the value
            let note_map = state.note_lists.entry(msg_caller()).or_default();
            note_map.insert(id);
            state.notes.insert((msg_caller(), id), value.into())
        })?;

        Some(Note::from_dao(id, dao))
    }

    fn remove(&mut self, key: &NoteId) -> Option<Note> {
        let dao = STATE.with_borrow_mut(|state| {
            let note_map = state.note_lists.entry(msg_caller()).or_default();
            note_map.remove(key);
            state.notes.remove(&(msg_caller(), *key))
        })?;

        Some(Note::from_dao(*key, dao))
    }

    fn list(&self) -> Vec<(NoteId, NoteTitle)> {
        let caller = msg_caller();
        STATE.with_borrow(|state| {
            let ids: Vec<NoteId> = match state.note_lists.get(&caller) {
                Some(list) => list.clone(),
                None => BTreeSet::new(),
            }
            .into_iter()
            .collect();
            ids.into_iter()
                .map(|id| {
                    let dao = state.notes.get(&(caller, id)).unwrap();
                    (id, Note::from_dao(id, dao).title.clone())
                })
                .collect()
        })
    }
}
