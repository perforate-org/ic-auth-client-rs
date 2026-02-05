use crate::contexts::auth::{AuthStore, use_auth};
use dioxus::prelude::*;
use domain::note::{NoteId, NoteTitle, entity::Note};
use std::collections::BTreeMap;
use wasm_bindgen::JsCast;

const TITLE_INPUT_ID: &str = "note-title-input";
const CONTENT_INPUT_ID: &str = "note-content-input";

#[derive(Clone, Copy)]
pub struct Backend(AuthStore);

impl Backend {
    pub fn new(auth_store: AuthStore) -> Self {
        Backend(auth_store)
    }
}

#[component]
pub fn NoteComponent() -> Element {
    let auth = use_auth();
    let mut list = use_signal(BTreeMap::<NoteId, NoteTitle>::new);
    let mut active_note_id = use_signal(|| None::<NoteId>);
    let mut is_init = use_signal(|| true);
    let mut note = use_signal(|| None::<Note>);
    let is_saving = use_signal(|| false);
    let mut title_input = use_signal(String::new);
    let mut content_input = use_signal(String::new);
    let title_invalid = use_signal(|| false);
    let mut dirty_note_id = use_signal(|| None::<NoteId>);

    use_effect(move || {
        let backend_actor = auth.read().backend.clone();
        if let Some(backend_actor) = backend_actor {
            is_init.set(true);
            spawn(async move {
                let notes = backend_actor.fetch_note_list().await;
                let mut map = BTreeMap::new();
                for (id, title) in notes {
                    map.insert(id, title);
                }
                list.set(map);
                is_init.set(false);
            });
        } else {
            list.set(BTreeMap::new());
            active_note_id.set(None);
            note.set(None);
            is_init.set(true);
        }
    });

    use_effect(move || {
        let backend_actor = auth.read().backend.clone();
        let active_id = *active_note_id.read();
        let Some(backend_actor) = backend_actor else {
            return;
        };
        let Some(active_id) = active_id else {
            return;
        };
        spawn(async move {
            let fetched = backend_actor.fetch_note(active_id).await;
            if let Some(fetched) = fetched {
                title_input.set(fetched.title.as_str().to_string());
                content_input.set(fetched.content.clone());
                note.set(Some(fetched));
            } else {
                content_input.set(String::new());
                note.set(None);
            }
            dirty_note_id.set(None);
        });
    });

    rsx! {
        article { class: "rounded-box flex border border-stone-300 dark:border-stone-600 w-full h-full",
            NoteList {
                list,
                active_note_id,
                note,
                title_input,
                content_input,
                title_invalid,
                is_init,
                is_saving,
                dirty_note_id,
            }
            NoteEditor {
                list,
                active_note_id,
                note,
                title_input,
                content_input,
                title_invalid,
                is_init,
                is_saving,
                dirty_note_id,
            }
        }
    }
}

#[derive(Props, Clone)]
struct NoteListProps {
    list: Signal<BTreeMap<NoteId, NoteTitle>>,
    active_note_id: Signal<Option<NoteId>>,
    note: Signal<Option<Note>>,
    title_input: Signal<String>,
    content_input: Signal<String>,
    title_invalid: Signal<bool>,
    is_init: Signal<bool>,
    is_saving: Signal<bool>,
    dirty_note_id: Signal<Option<NoteId>>,
}

impl PartialEq for NoteListProps {
    fn eq(&self, other: &Self) -> bool {
        self.list == other.list
            && self.active_note_id == other.active_note_id
            && self.note == other.note
            && self.title_input == other.title_input
            && self.content_input == other.content_input
            && self.title_invalid == other.title_invalid
            && self.is_init == other.is_init
            && self.is_saving == other.is_saving
            && self.dirty_note_id == other.dirty_note_id
    }
}

#[component]
fn NoteList(props: NoteListProps) -> Element {
    let NoteListProps {
        list,
        mut active_note_id,
        note,
        mut title_input,
        mut content_input,
        mut title_invalid,
        is_init,
        is_saving,
        mut dirty_note_id,
    } = props;
    let backend = use_context::<Backend>();

    let button_class = if *is_init.read() {
        "btn btn-sm py-[0.125rem] px-4 mb-2 w-full text-stone-500 dark:text-stone-600 bg-stone-200 dark:bg-stone-800"
    } else {
        "btn btn-sm py-[0.125rem] px-4 mb-2 w-full border-stone-300 text-stone-700 dark:border-stone-600 dark:text-stone-400 hover:bg-stone-200 dark:hover:bg-stone-800 active:bg-stone-300 dark:active:bg-stone-900"
    };

    let list_snapshot = list.read().clone();
    let list_items = list_snapshot.iter().rev().map(|(id, title)| {
        let id = *id;
        let title_value = title.clone();
        let title_for_click = title_value.clone();
        let is_active = *active_note_id.read() == Some(id);
        let base_class = "px-2 w-full text-sm text-left rounded py-[0.125rem] text-stone-700 truncate dark:text-stone-400 dark:hover:bg-stone-800 dark:active:bg-stone-900 hover:bg-stone-200 active:bg-stone-300";
        let active_class = if is_active { " bg-stone-200 dark:bg-stone-800" } else { "" };
        let class_name = format!("{base_class}{active_class}");

        rsx! {
            li { key: "{id}",
                button {
                    class: class_name,
                    onclick: move |_| {
                        let old_active_note_id = *active_note_id.read();
                        if old_active_note_id != Some(id) {
                            if let Some(old_id) = old_active_note_id && note.read().is_some() {
                                dispatch_note_from_inputs(
                                    backend,
                                    old_id,
                                    note,
                                    title_input,
                                    content_input,
                                    is_saving,
                                    dirty_note_id,
                                    true,
                                );
                            }

                            active_note_id.set(Some(id));
                            title_input.set(title_for_click.as_str().to_string());
                            content_input.set(String::new());
                            title_invalid.set(false);
                        }
                    },
                    if title_value.is_empty() {
                        span { class: "text-stone-400 dark:text-stone-600", "Untitled" }
                    } else {
                        "{title_value}"
                    }
                }
            }
        }
    });

    rsx! {
        div { class: "p-2 h-full text-left border-r border-stone-300 gap-[0.125rem] bg-stone-200/25 dark:border-stone-600 dark:bg-stone-800/25",
            button {
                class: button_class,
                disabled: *is_init.read(),
                onclick: move |_| {
                    let old_active_note_id = *active_note_id.read();
                    if let Some(old_id) = old_active_note_id && note.read().is_some() {
                        dispatch_note_from_inputs(
                            backend,
                            old_id,
                            note,
                            title_input,
                            content_input,
                            is_saving,
                            dirty_note_id,
                            true,
                        );
                    }

                    create_new_note(list, active_note_id);
                    title_input.set(String::new());
                    content_input.set(String::new());
                    title_invalid.set(false);
                    dirty_note_id.set(None);
                },
                "New Note"
            }
            div { class: "overflow-y-auto h-[calc(100dvh-16rem)]",
                ul { class: "flex flex-col-reverse w-[12rem] gap-[2px]",
                    {list_items}
                }
            }
        }
    }
}

#[derive(Props, Clone)]
struct NoteEditorProps {
    list: Signal<BTreeMap<NoteId, NoteTitle>>,
    active_note_id: Signal<Option<NoteId>>,
    note: Signal<Option<Note>>,
    title_input: Signal<String>,
    content_input: Signal<String>,
    title_invalid: Signal<bool>,
    is_init: Signal<bool>,
    is_saving: Signal<bool>,
    dirty_note_id: Signal<Option<NoteId>>,
}

impl PartialEq for NoteEditorProps {
    fn eq(&self, other: &Self) -> bool {
        self.list == other.list
            && self.active_note_id == other.active_note_id
            && self.note == other.note
            && self.title_input == other.title_input
            && self.content_input == other.content_input
            && self.title_invalid == other.title_invalid
            && self.is_init == other.is_init
            && self.is_saving == other.is_saving
            && self.dirty_note_id == other.dirty_note_id
    }
}

#[component]
fn NoteEditor(props: NoteEditorProps) -> Element {
    let NoteEditorProps {
        mut list,
        active_note_id,
        note,
        mut title_input,
        mut content_input,
        mut title_invalid,
        is_init,
        is_saving,
        mut dirty_note_id,
    } = props;
    let backend = use_context::<Backend>();

    let active_id = *active_note_id.read();

    if active_id.is_none() {
        let message = if *is_init.read() {
            "Loading..."
        } else if list.read().is_empty() {
            "Press \"New Note\" to create a note"
        } else {
            "Select a note to start editing"
        };

        return rsx! {
            div { class: "w-full h-full",
                div { class: "justify-center items-center w-full h-full flex pointer-events-none",
                    p { class: "text-stone-500 dark:text-stone-400", "{message}" }
                }
            }
        };
    }

    let readonly = *is_saving.read();
    let is_title_invalid = *title_invalid.read();
    let submit_class = if is_title_invalid {
        "btn btn-primary btn-sm px-6 bg-stone-300 dark:bg-stone-600 cursor-not-allowed"
    } else {
        "btn btn-primary btn-sm px-6 cursor-pointer"
    };

    rsx! {
        div { class: "w-full h-full",
            form {
                method: "POST",
                class: "flex-col gap-2 w-full h-full flex",
                onsubmit: move |ev| {
                    ev.prevent_default();
                    if let Some(active_id) = *active_note_id.read() {
                        dispatch_note_from_inputs(
                            backend,
                            active_id,
                            note,
                            title_input,
                            content_input,
                            is_saving,
                            dirty_note_id,
                            false,
                        );
                    }
                },
                div { class: "flex items-center gap-2 p-2 border-b border-stone-300 dark:border-stone-600",
                    input {
                        r#type: "text",
                        id: TITLE_INPUT_ID,
                        class: "p-2 w-full bg-transparent rounded outline-0 outline-red-500",
                        readonly: readonly,
                        value: title_input.read().clone(),
                        placeholder: "Untitled",
                        oninput: move |ev| {
                            let value = ev.value();
                            let (title, invalid) = parse_title(&value);
                            title_input.set(value);
                            title_invalid.set(invalid);

                            if let Some(active_id) = *active_note_id.read() {
                                list.write().insert(active_id, title);
                                dirty_note_id.set(Some(active_id));
                            }
                        },
                    }
                    div {
                        class: "absolute px-2 ml-1 bg-red-500 rounded py-[0.125rem] mt-[-0.9rem]",
                        style: format!(
                            "display: {}",
                            if is_title_invalid { "block" } else { "none" }
                        ),
                        p { class: "text-xs text-stone-100", "Title is up to 50 characters long" }
                    }
                    input {
                        r#type: "submit",
                        class: submit_class,
                        disabled: readonly || is_title_invalid,
                        value: "Save",
                    }
                }
                textarea {
                    id: CONTENT_INPUT_ID,
                    class: "flex-grow py-2 px-4 w-full bg-transparent rounded resize-none outline-0",
                    readonly: readonly,
                    value: content_input.read().clone(),
                    oninput: move |ev| {
                        content_input.set(ev.value());
                        if let Some(active_id) = *active_note_id.read() {
                            dirty_note_id.set(Some(active_id));
                        }
                    }
                }
            }
        }
    }
}

fn create_new_note(
    mut list: Signal<BTreeMap<NoteId, NoteTitle>>,
    mut active_note_id: Signal<Option<NoteId>>,
) {
    let new_note_id = match list.read().keys().max() {
        Some(last_note_id) => last_note_id.increment(),
        None => NoteId::new(0),
    };

    list.write().insert(
        new_note_id,
        NoteTitle::new(String::new()).expect("Empty title should be valid"),
    );
    active_note_id.set(Some(new_note_id));
}

fn dispatch_note_from_inputs(
    backend: Backend,
    note_id: NoteId,
    mut note_signal: Signal<Option<Note>>,
    title_input: Signal<String>,
    content_input: Signal<String>,
    mut is_saving: Signal<bool>,
    mut dirty_note_id: Signal<Option<NoteId>>,
    only_if_dirty: bool,
) {
    if only_if_dirty && *dirty_note_id.peek() != Some(note_id) {
        return;
    }

    let note_value = note_from_dom(note_id).unwrap_or_else(|| {
        let raw_title = title_input.read().trim().to_string();
        let title_value = raw_title.chars().take(50).collect::<String>();
        let title = NoteTitle::new(title_value).unwrap_or_else(|_| {
            NoteTitle::new(String::new()).expect("Empty title should be valid")
        });
        let content = content_input.read().trim().to_string();

        Note {
            id: note_id,
            title,
            content,
        }
    });

    if note_signal.peek().as_ref() == Some(&note_value) {
        dirty_note_id.set(None);
        return;
    }

    note_signal.set(Some(note_value.clone()));
    dirty_note_id.set(None);
    let Some(backend_actor) = backend.0.read().backend.clone() else {
        return;
    };
    is_saving.set(true);
    spawn(async move {
        backend_actor.post_note(note_value).await;
        is_saving.set(false);
    });
}

fn note_from_dom(note_id: NoteId) -> Option<Note> {
    let window = web_sys::window()?;
    let document = window.document()?;
    let title = document
        .get_element_by_id(TITLE_INPUT_ID)?
        .dyn_into::<web_sys::HtmlInputElement>()
        .ok()?
        .value();
    let content = document
        .get_element_by_id(CONTENT_INPUT_ID)?
        .dyn_into::<web_sys::HtmlTextAreaElement>()
        .ok()?
        .value();

    let raw_title = title.trim().to_string();
    let title_value = raw_title.chars().take(50).collect::<String>();
    let title = NoteTitle::new(title_value)
        .unwrap_or_else(|_| NoteTitle::new(String::new()).expect("Empty title should be valid"));
    let content = content.trim().to_string();

    Some(Note {
        id: note_id,
        title,
        content,
    })
}

fn parse_title(value: &str) -> (NoteTitle, bool) {
    let len = value.chars().count();
    let invalid = len > 50;
    let trimmed = value.chars().take(50).collect::<String>();
    let title = NoteTitle::new(trimmed)
        .unwrap_or_else(|_| NoteTitle::new(String::new()).expect("Empty title should be valid"));

    (title, invalid)
}
