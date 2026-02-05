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

    static TODO_ITEMS: RefCell<StableBTreeMap<u64, TodoItem, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))))
    );

    static NEXT_TODO_ID: RefCell<StableCell<u64, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
            0
        )
    );
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct TodoItem {
    pub id: u64,
    pub owner: Principal,
    pub text: String,
    pub completed: bool,
    pub created_at: u64,
}

impl Storable for TodoItem {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(Encode!(self).expect("Failed to encode TodoItem"))
    }

    fn into_bytes(self) -> Vec<u8> {
        Encode!(&self).expect("Failed to encode TodoItem")
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Decode!(&bytes, TodoItem).expect("Failed to decode TodoItem")
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 2048,
        is_fixed_size: false,
    };
}

#[update]
pub fn add_todo(text: String) -> TodoItem {
    let owner = ic_cdk::api::msg_caller();
    let now = ic_cdk::api::time();
    let text = text.trim().to_string();
    if text.is_empty() {
        ic_cdk::trap("todo text must not be empty");
    }

    let id = NEXT_TODO_ID.with(|counter| {
        let mut counter = counter.borrow_mut();
        let id = *counter.get();
        counter.set(id + 1);
        id
    });

    let item = TodoItem {
        id,
        owner,
        text,
        completed: false,
        created_at: now,
    };

    TODO_ITEMS.with(|items| {
        items.borrow_mut().insert(id, item.clone());
    });

    item
}

#[query]
pub fn list_todos() -> Vec<TodoItem> {
    let owner = ic_cdk::api::msg_caller();
    TODO_ITEMS.with(|items| {
        items
            .borrow()
            .iter()
            .filter(|entry| entry.value().owner == owner)
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>()
    })
}

#[update]
pub fn toggle_todo(id: u64) -> Option<TodoItem> {
    let owner = ic_cdk::api::msg_caller();

    TODO_ITEMS.with(|items| {
        let mut items = items.borrow_mut();
        let mut item = items.get(&id)?;
        if item.owner != owner {
            return None;
        }
        item.completed = !item.completed;
        items.insert(id, item.clone());
        Some(item)
    })
}

#[update]
pub fn delete_todo(id: u64) -> bool {
    let owner = ic_cdk::api::msg_caller();

    TODO_ITEMS.with(|items| {
        let mut items = items.borrow_mut();
        let item = items.get(&id);
        match item {
            Some(item) if item.owner == owner => items.remove(&id).is_some(),
            _ => false,
        }
    })
}

ic_cdk::export_candid!();
