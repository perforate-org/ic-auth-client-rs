use anyhow::Result;
use gpui::prelude::*;
use gpui::{
    App, Application, Context, Entity, Render, WeakEntity, Window, WindowOptions, div, px, rems,
};
use gpui_component::button::ButtonVariants;
use gpui_component::{
    ActiveTheme, Root, Sizable, StyledExt,
    button::Button,
    checkbox::Checkbox,
    h_flex,
    input::{Input, InputState},
    scroll::ScrollableElement,
    v_flex,
};
use keyring::set_default_credential_builder;
use tracing_subscriber::EnvFilter;

mod auth;

use auth::{Auth, AuthSignal, AuthState, TodoItem};

fn main() {
    if util::dfx_network::is_local_dfx() {
        set_default_credential_builder(keyring::mock::default_credential_builder());
    }
    if let Err(err) = run() {
        eprintln!("gpui example failed: {err}");
    }
}

fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    Application::new().run(|cx: &mut App| {
        gpui_component::init(cx);
        let window_bounds =
            gpui::WindowBounds::centered(gpui::Size::new(800.0.into(), 600.0.into()), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(window_bounds),
                ..WindowOptions::default()
            },
            |window, cx| {
                let app_view = cx.new(|cx| TodoApp::new(window, cx));
                app_view.update(cx, |view, cx| view.start_signal_listener(cx));
                cx.new(|cx| Root::new(app_view, window, cx))
            },
        )
        .expect("Failed to open window");
        cx.activate(true);
    });

    Ok(())
}

struct TodoApp {
    auth: Auth,
    todos: Vec<TodoItem>,
    draft_input: Entity<InputState>,
    status: String,
    error: Option<String>,
    needs_focus: bool,
    window_handle: gpui::AnyWindowHandle,
}

impl TodoApp {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let auth = Auth::new().expect("Failed to initialize auth client");
        let draft_input = cx.new(|cx| InputState::new(window, cx).placeholder("Add a new todo"));
        let window_handle = window.window_handle();
        Self {
            auth,
            todos: Vec::new(),
            draft_input,
            status: "Ready".to_string(),
            error: None,
            needs_focus: false,
            window_handle,
        }
    }

    fn start_signal_listener(&mut self, cx: &mut Context<Self>) {
        if matches!(&self.auth.state, AuthState::Authenticated(_)) {
            self.refresh_todos(cx);
        }
        let signal_rx = self.auth.signal_receiver();
        let window_handle = self.window_handle;
        cx.spawn(async move |this: WeakEntity<Self>, cx| {
            while let Ok(signal) = signal_rx.recv_async().await {
                this.update(cx, |view, cx| match signal {
                    AuthSignal::LoginComplete => {
                        view.auth.update_state();
                        view.needs_focus = true;
                        view.refresh_todos(cx);
                    }
                    AuthSignal::LoginFailed => {
                        view.auth.state = AuthState::Unauthenticated;
                        view.status = "Login failed".to_string();
                    }
                })
                .ok();

                let _ = window_handle.update(cx, |_, window, cx| {
                    cx.activate(true);
                    window.activate_window();
                    window.refresh();
                });
            }
        })
        .detach();
    }

    fn refresh_todos(&mut self, cx: &mut Context<Self>) {
        let backend = self.auth.backend.clone();
        self.status = "Loading todos...".to_string();
        self.error = None;

        cx.spawn(async move |this: WeakEntity<Self>, cx| {
            let result = backend.list_todos().await;
            this.update(cx, |view, _cx| match result {
                Ok(items) => {
                    view.todos = items;
                    view.status = "Loaded".to_string();
                }
                Err(err) => {
                    view.error = Some(format!("Failed to load todos: {err}"));
                    view.status = "Error".to_string();
                }
            })
            .ok();
        })
        .detach();
    }

    fn login(&mut self, _cx: &mut Context<Self>) {
        self.status = "Opening Internet Identity...".to_string();
        if let Err(err) = self.auth.login() {
            self.error = Some(format!("Login failed: {err}"));
            self.status = "Error".to_string();
        }
    }

    fn logout(&mut self) {
        if let Err(err) = self.auth.logout() {
            self.error = Some(format!("Logout failed: {err}"));
            self.status = "Error".to_string();
        } else {
            self.status = "Logged out".to_string();
            self.todos.clear();
        }
    }

    fn add_todo(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.draft_input.read(cx).value().to_string();
        let text = text.trim().to_string();
        if text.is_empty() {
            self.error = Some("Todo text cannot be empty".to_string());
            return;
        }

        let backend = self.auth.backend.clone();
        self.draft_input.update(cx, |input, cx| {
            input.set_value("", window, cx);
        });
        self.status = "Adding todo...".to_string();
        self.error = None;

        cx.spawn(async move |this: WeakEntity<Self>, cx| {
            let result = backend.add_todo(text).await;
            this.update(cx, |view, _cx| match result {
                Ok(item) => {
                    view.todos.push(item);
                    view.status = "Saved".to_string();
                }
                Err(err) => {
                    view.error = Some(format!("Failed to add todo: {err}"));
                    view.status = "Error".to_string();
                }
            })
            .ok();
        })
        .detach();
    }

    fn toggle_todo(&mut self, cx: &mut Context<Self>, id: u64) {
        let backend = self.auth.backend.clone();
        self.status = "Updating todo...".to_string();
        self.error = None;

        cx.spawn(async move |this: WeakEntity<Self>, cx| {
            let result = backend.toggle_todo(id).await;
            this.update(cx, |view, _cx| match result {
                Ok(Some(updated)) => {
                    if let Some(item) = view.todos.iter_mut().find(|item| item.id == id) {
                        *item = updated;
                    }
                    view.status = "Updated".to_string();
                }
                Ok(None) => {
                    view.error = Some("Todo not found".to_string());
                    view.status = "Error".to_string();
                }
                Err(err) => {
                    view.error = Some(format!("Failed to update todo: {err}"));
                    view.status = "Error".to_string();
                }
            })
            .ok();
        })
        .detach();
    }

    fn delete_todo(&mut self, cx: &mut Context<Self>, id: u64) {
        let backend = self.auth.backend.clone();
        self.status = "Deleting todo...".to_string();
        self.error = None;

        cx.spawn(async move |this: WeakEntity<Self>, cx| {
            let result = backend.delete_todo(id).await;
            this.update(cx, |view, _cx| match result {
                Ok(true) => {
                    view.todos.retain(|item| item.id != id);
                    view.status = "Deleted".to_string();
                }
                Ok(false) => {
                    view.error = Some("Todo not found".to_string());
                    view.status = "Error".to_string();
                }
                Err(err) => {
                    view.error = Some(format!("Failed to delete todo: {err}"));
                    view.status = "Error".to_string();
                }
            })
            .ok();
        })
        .detach();
    }

    fn render_todo_row(&self, cx: &Context<Self>, item: &TodoItem) -> impl gpui::IntoElement {
        let id = item.id;
        let completed = item.completed;
        let text = item.text.clone();
        let text_label = div().child(text).flex_grow().when(completed, |this| {
            this.text_color(cx.theme().muted_foreground).line_through()
        });

        h_flex()
            .gap_2()
            .w_full()
            .rounded(cx.theme().radius)
            .border_1()
            .border_color(cx.theme().border)
            .p_2()
            .child(
                Checkbox::new(("todo", id))
                    .checked(completed)
                    .on_click(cx.listener(move |view, _checked, _window, cx| {
                        view.toggle_todo(cx, id);
                    })),
            )
            .child(text_label)
            .child(
                Button::new("delete")
                    .label("Delete")
                    .xsmall()
                    .danger()
                    .on_click(cx.listener(move |view, _event, _window, cx| {
                        view.delete_todo(cx, id);
                    })),
            )
    }
}

impl Render for TodoApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl gpui::IntoElement {
        if self.needs_focus {
            self.needs_focus = false;
            cx.activate(true);
            window.activate_window();
        }

        let header = div()
            .text_3xl()
            .font_semibold()
            .text_center()
            .child("ic-auth-client for Rust Example");
        let status = div()
            .text_xs()
            .text_color(cx.theme().muted_foreground)
            .child(self.status.clone());
        let error = self.error.as_ref().map(|err| {
            div()
                .text_sm()
                .text_color(cx.theme().danger_foreground)
                .child(err.clone())
        });

        let auth_controls = match &self.auth.state {
            AuthState::Authenticated(principal) => v_flex()
                .gap_2()
                .items_center()
                .child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child(format!("You're logged in: {principal}")),
                )
                .child(Button::new("logout").label("Logout").on_click(cx.listener(
                    |view, _event, _window, _cx| {
                        view.logout();
                    },
                ))),
            AuthState::Unauthenticated | AuthState::Authenticating => v_flex()
                .gap_2()
                .items_center()
                .child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child("You're NOT logged in"),
                )
                .child(
                    Button::new("login")
                        .label("Log in with II")
                        .info()
                        .on_click(cx.listener(|view, _event, _window, cx| view.login(cx))),
                ),
        };

        let todo_panel = if matches!(&self.auth.state, AuthState::Authenticated(_)) {
            let window_height = f32::from(window.bounds().size.height);
            let list_max_height = px((window_height - 320.0).max(160.0));
            let input_row =
                h_flex()
                    .gap_2()
                    .w_full()
                    .child(Input::new(&self.draft_input).flex_grow())
                    .child(Button::new("add").label("Add").info().on_click(
                        cx.listener(|view, _event, window, cx| view.add_todo(window, cx)),
                    ));

            let todo_list = v_flex().gap_2().w_full().children(
                self.todos
                    .iter()
                    .map(|item| self.render_todo_row(cx, item))
                    .collect::<Vec<_>>(),
            );
            let todo_list = div()
                .w_full()
                .max_h(list_max_height)
                .child(todo_list)
                .overflow_y_scrollbar();

            Some(
                v_flex()
                    .gap_3()
                    .w_full()
                    .border_1()
                    .border_color(cx.theme().border)
                    .bg(cx.theme().muted.opacity(0.25))
                    .rounded(cx.theme().radius)
                    .p_4()
                    .child(input_row)
                    .child(todo_list)
                    .child(status)
                    .when_some(error, |this, error| this.child(error)),
            )
        } else {
            None
        };

        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .gap_6()
            .p_8()
            .child(header)
            .child(
                v_flex()
                    .gap_4()
                    .items_center()
                    .text_center()
                    .w_full()
                    .max_w(rems(60.))
                    .child(auth_controls)
                    .when_some(todo_panel, |this, panel| this.child(panel)),
            )
    }
}
