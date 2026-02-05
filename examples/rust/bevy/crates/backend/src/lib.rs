use candid::{CandidType, Decode, Encode, Principal};
use ic_cdk::{query, update};
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap, StableCell,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::{Bound, Storable},
};
use serde::Deserialize;
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static SCORE_HISTORY: RefCell<StableBTreeMap<u64, ScoreEntry, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))))
    );

    static NEXT_SCORE_ID: RefCell<StableCell<u64, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
            0
        )
    );
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ScoreEntry {
    pub player: Principal,
    pub score: u32,
}

impl Storable for ScoreEntry {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).expect("Failed to encode ScoreEntry"))
    }

    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).expect("Failed to encode ScoreEntry")
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Decode!(&bytes, ScoreEntry).expect("Failed to decode ScoreEntry")
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 128,
        is_fixed_size: false,
    };
}

/// Stores the caller's score history and returns their best score.
#[update]
pub fn submit_score(score: u32) -> ScoreEntry {
    let player = ic_cdk::api::msg_caller();
    let entry = ScoreEntry { player, score };

    let score_id = NEXT_SCORE_ID.with(|counter| {
        let mut counter = counter.borrow_mut();
        let id = *counter.get();
        counter.set(id + 1);
        id
    });

    SCORE_HISTORY.with(|scores| {
        scores.borrow_mut().insert(score_id, entry);
    });

    let best = SCORE_HISTORY.with(|scores| {
        scores
            .borrow()
            .iter()
            .filter(|item| item.value().player == player)
            .map(|item| item.value().score)
            .max()
            .unwrap_or(score)
    });

    ScoreEntry {
        player,
        score: best,
    }
}

/// Returns the stored high score for the requested player, if any exists.
#[query]
pub fn get_score(player: Principal) -> Option<ScoreEntry> {
    let best = SCORE_HISTORY.with(|scores| {
        scores
            .borrow()
            .iter()
            .filter(|item| item.value().player == player)
            .map(|item| item.value().score)
            .max()
    })?;

    Some(ScoreEntry {
        player,
        score: best,
    })
}

/// Returns the leaderboard ordered by score (descending).
#[query]
pub fn get_leaderboard(limit: Option<u32>) -> Vec<ScoreEntry> {
    let limit = limit.unwrap_or(10).clamp(1, 100) as usize;
    let mut entries = SCORE_HISTORY.with(|scores| {
        scores
            .borrow()
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>()
    });

    entries.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.player.as_slice().cmp(b.player.as_slice()))
    });
    entries.truncate(limit);
    entries
}

ic_cdk::export_candid!();
