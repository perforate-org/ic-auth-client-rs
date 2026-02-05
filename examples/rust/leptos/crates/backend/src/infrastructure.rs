use crate::log::Log;
use candid::Principal;
use domain::note::{entity::dao::NoteDao, NoteId};
use ic_stable_structures::{StableBTreeMap, StableLog};
use no_panic::no_panic;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

pub mod log;
mod memory;
pub mod note;
mod post_upgrade;
mod pre_upgrade;

use memory::*;
use post_upgrade::post_upgrade as post_upgrade_inner;
use pre_upgrade::pre_upgrade as pre_upgrade_inner;

#[derive(Serialize, Deserialize)]
struct State {
    note_lists: BTreeMap<Principal, BTreeSet<NoteId>>,
    #[serde(skip, default = "init_stable_log")]
    log: StableLog<Log, Memory, Memory>,
    #[serde(skip, default = "init_notes")]
    notes: StableBTreeMap<(Principal, NoteId), NoteDao, Memory>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            note_lists: BTreeMap::new(),
            log: init_stable_log(),
            notes: init_notes(),
        }
    }
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

#[ic_cdk::pre_upgrade]
#[no_panic]
fn pre_upgrade() {
    pre_upgrade_inner()
}

#[ic_cdk::post_upgrade]
#[no_panic]
fn post_upgrade() {
    post_upgrade_inner()
}
