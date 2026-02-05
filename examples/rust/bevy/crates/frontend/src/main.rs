// Portions of this file are adapted from bevy-tetris (GPLv3).
// Copyright (C) corbamico@163.com
// Modifications for this example are licensed under GPLv3.
// See LICENSE and NOTICE.md.

//! This example demonstrates how to use the `ic-auth-client` with the Bevy game engine.
//! It features a simple UI that allows users to log in and log out, displaying their principal ID when authenticated.

#![windows_subsystem = "windows"]

mod auth;
mod bricks;
mod consts;

use bevy::{
    asset::AssetPlugin,
    log::{Level, LogPlugin},
    prelude::*,
    tasks::{AsyncComputeTaskPool, Task},
    text::{Justify, TextLayout},
    window::PrimaryWindow,
};
use futures_lite::future;
use ic_agent::export::Principal;
//use bevy::state::app::AppExtStates as _;

use auth::{Auth, AuthState, BackendActor, ScoreEntry};
use bricks::{Board, Brick, BrickShape, Dot};
use consts::*;
use std::{env, time::Duration};

#[cfg(not(any(feature = "storage-keyring", feature = "storage-pem")))]
compile_error!(
    "Enable one storage feature: storage-keyring or storage-pem (use --no-default-features as needed)."
);

#[cfg(feature = "storage-keyring")]
use keyring::set_default_credential_builder;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Hash, States)]
enum GameState {
    #[default]
    Login,
    Playing,
    GameOver,
}

const LEADERBOARD_DISPLAY_COUNT: usize = 5;

fn transition_to_playing(mut app_state: ResMut<NextState<GameState>>, auth_state: Res<AuthState>) {
    if matches!(&*auth_state, AuthState::Authenticated(_)) {
        app_state.set(GameState::Playing);
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "storage-keyring")]
    if util::dfx_network::is_local_dfx() {
        set_default_credential_builder(keyring::mock::default_credential_builder());
    }

    let runtime = tokio::runtime::Runtime::new()?;
    let _enter = runtime.enter();

    let auth = Auth::new()?;
    let initial_auth_state = auth.state.clone();

    App::new()
        .add_plugins(
            DefaultPlugins
                .set(AssetPlugin {
                    file_path: format!("{}/assets", env!("CARGO_MANIFEST_DIR")),
                    processed_file_path: format!("{}/assets", env!("CARGO_MANIFEST_DIR")),
                    ..default()
                })
                .set(WindowPlugin {
                    primary_window: Some(Window {
                        title: "Tetris".to_string(),
                        resizable: false,
                        resolution: (360, 443).into(),
                        ..default()
                    }),
                    ..default()
                })
                .set(LogPlugin {
                    filter: default_log_filter(),
                    level: Level::DEBUG,
                    ..default()
                }),
        )
        .insert_resource(GameData::default())
        .insert_resource(HighScoreState::default())
        .insert_resource(initial_auth_state)
        .insert_resource(auth)
        .add_systems(PreStartup, setup_screen)
        .init_state::<GameState>()
        .add_systems(Update, login_overlay_visibility_system)
        .add_systems(Update, logout_button_visibility_system)
        .add_systems(
            Update,
            (
                login_button_system,
                login_button_state_system,
                login_status_text_system,
            )
                .run_if(not(in_state(GameState::Playing))),
        )
        .add_systems(Update, logout_button_system)
        .add_systems(Update, auth_state_sync_system)
        .add_systems(Update, principal_text_system)
        .add_systems(Update, leaderboard_prefetch_system)
        .add_systems(Update, gameover_submit_pending_score_system)
        .add_systems(
            Update,
            transition_to_playing.run_if(in_state(GameState::Login)),
        )
        .add_systems(OnEnter(GameState::Playing), newgame_system)
        .add_systems(OnEnter(GameState::Playing), focus_primary_window)
        .add_systems(
            Update,
            (
                keyboard_system,
                movebrick_systrem,
                freezebrick_system,
                scoreboard_system,
            )
                .chain()
                .run_if(in_state(GameState::Playing)),
        )
        .add_systems(
            OnEnter(GameState::GameOver),
            (gameover_setup, gameover_fetch_scores),
        )
        .add_systems(
            Update,
            (gameover_system, poll_high_score_tasks, update_high_score_ui)
                .run_if(in_state(GameState::GameOver)),
        )
        .run();

    Ok(())
}
fn default_log_filter() -> String {
    env::var("RUST_LOG").unwrap_or_else(|_| {
        "info,wgpu=error,naga=warn,frontend=debug,ic_auth_client=trace,ic_agent=trace".to_string()
    })
}

fn setup_screen(mut commands: Commands, asset_server: Res<AssetServer>) {
    commands.spawn(Camera2d);

    commands.spawn(Sprite {
        image: asset_server.load("screen.png"),
        ..default()
    });
    commands
        .spawn(init_text(
            "000000",
            TEXT_SCORE_X,
            TEXT_SCORE_Y,
            &asset_server,
        ))
        .insert(ScoreText);
    commands
        .spawn(init_text(
            "000000",
            TEXT_LINES_X,
            TEXT_LINES_Y,
            &asset_server,
        ))
        .insert(LinesText);
    commands
        .spawn(init_text("00", TEXT_LEVEL_X, TEXT_LEVEL_Y, &asset_server))
        .insert(LevelText);
    commands
        .spawn(init_text_with_layout_justify(
            "",
            TEXT_PRINCIPAL_RIGHT,
            TEXT_PRINCIPAL_BOTTOM,
            12.0,
            Justify::Right,
            &asset_server,
        ))
        .insert(PrincipalText);
}

fn login_overlay_visibility_system(
    mut commands: Commands,
    asset_server: Res<AssetServer>,
    auth_state: Res<AuthState>,
    game_state: Res<State<GameState>>,
    query: Query<Entity, With<LoginUiRoot>>,
    children: Query<&Children>,
) {
    let should_show = !matches!(&*auth_state, AuthState::Authenticated(_))
        && *game_state.get() != GameState::Playing;
    if should_show {
        if query.is_empty() {
            spawn_login_overlay(&mut commands, &asset_server, &auth_state);
        }
    } else if !query.is_empty() {
        teardown_login_overlay(&mut commands, &query, &children);
    }
}

fn logout_button_visibility_system(
    mut commands: Commands,
    asset_server: Res<AssetServer>,
    auth_state: Res<AuthState>,
    query: Query<Entity, With<LogoutUiRoot>>,
    children: Query<&Children>,
) {
    let should_show = matches!(&*auth_state, AuthState::Authenticated(_));
    if should_show {
        if query.is_empty() {
            spawn_logout_button(&mut commands, &asset_server);
        }
    } else if !query.is_empty() {
        teardown_logout_button(&mut commands, &query, &children);
    }
}

fn focus_primary_window(mut windows: Query<&mut Window, With<PrimaryWindow>>) {
    if let Ok(mut window) = windows.single_mut() {
        window.focused = true;
    }
}

#[derive(Component)]
struct BoardBundle;

#[derive(Component)]
struct BrickBoardBundle;

#[derive(Component)]
struct BrickNextBundle;

#[derive(Component)]
struct ScoreText;

#[derive(Component)]
struct LinesText;

#[derive(Component)]
struct LevelText;

#[derive(Component)]
struct LoginText;

#[derive(Component)]
struct LoginUiRoot;

#[derive(Component)]
struct LoginButton;

#[derive(Component)]
struct LoginButtonLabel;

#[derive(Component)]
struct LogoutUiRoot;

#[derive(Component)]
struct LogoutButton;

#[derive(Component)]
struct PrincipalText;

#[derive(Component)]
struct GameOverUi;

#[derive(Component)]
struct LeaderboardEntryText {
    index: usize,
}

#[derive(Component)]
struct LeaderboardStatusText;

fn spawn_login_overlay(
    commands: &mut Commands,
    asset_server: &Res<AssetServer>,
    auth_state: &AuthState,
) {
    let font = asset_server.load("digital7mono.ttf");
    let status_message = login_status_message(auth_state);

    commands
        .spawn((
            Node {
                width: Val::Percent(100.0),
                height: Val::Percent(100.0),
                justify_content: JustifyContent::Center,
                align_items: AlignItems::Center,
                position_type: PositionType::Absolute,
                ..default()
            },
            BackgroundColor(Color::srgba(0.0, 0.0, 0.0, 0.45)),
            ZIndex(10),
            LoginUiRoot,
        ))
        .with_children(|root| {
            root.spawn((
                Node {
                    width: Val::Px(320.0),
                    padding: UiRect::axes(Val::Px(24.0), Val::Px(24.0)),
                    flex_direction: FlexDirection::Column,
                    row_gap: Val::Px(16.0),
                    align_items: AlignItems::Center,
                    border_radius: BorderRadius::all(Val::Px(18.0)),
                    overflow: Overflow::clip(),
                    ..default()
                },
                BackgroundColor(Color::srgba(0.0, 0.0, 0.0, 0.85)),
            ))
            .with_children(|panel| {
                panel.spawn((
                    Text("INTERNET IDENTITY".to_string()),
                    TextFont {
                        font: font.clone(),
                        font_size: 28.0,
                        ..default()
                    },
                    TextColor(Color::WHITE),
                    Node {
                        width: Val::Percent(100.0),
                        justify_content: JustifyContent::Center,
                        ..default()
                    },
                ));

                panel.spawn((
                    Text(status_message),
                    TextFont {
                        font: font.clone(),
                        font_size: 18.0,
                        ..default()
                    },
                    TextColor(Color::WHITE),
                    LoginText,
                    Node {
                        width: Val::Percent(100.0),
                        justify_content: JustifyContent::Center,
                        ..default()
                    },
                ));

                panel
                    .spawn((
                        Button,
                        LoginButton,
                        Node {
                            width: Val::Percent(100.0),
                            height: Val::Px(48.0),
                            justify_content: JustifyContent::Center,
                            align_items: AlignItems::Center,
                            border_radius: BorderRadius::all(Val::Px(10.0)),
                            ..default()
                        },
                        BackgroundColor(Color::srgb_u8(58, 116, 248)),
                    ))
                    .with_children(|button| {
                        button.spawn((
                            Text("LOGIN".to_string()),
                            TextFont {
                                font: font.clone(),
                                font_size: 22.0,
                                ..default()
                            },
                            TextColor(Color::WHITE),
                            LoginButtonLabel,
                        ));
                    });

                panel.spawn((
                    Text("THE GAME STARTS AFTER LOGIN".to_string()),
                    TextFont {
                        font,
                        font_size: 16.0,
                        ..default()
                    },
                    TextColor(Color::srgb_u8(160, 160, 160)),
                    Node {
                        width: Val::Percent(100.0),
                        justify_content: JustifyContent::Center,
                        ..default()
                    },
                ));
            });
        });
}

fn spawn_logout_button(commands: &mut Commands, asset_server: &Res<AssetServer>) {
    let font = asset_server.load("digital7mono.ttf");

    commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                right: Val::Px(consts::LOGOUT_BUTTON_RIGHT),
                bottom: Val::Px(consts::LOGOUT_BUTTON_BOTTOM),
                ..default()
            },
            LogoutUiRoot,
        ))
        .with_children(|root| {
            root.spawn((
                Button,
                LogoutButton,
                Node {
                    width: Val::Px(108.0),
                    height: Val::Px(30.0),
                    justify_content: JustifyContent::Center,
                    align_items: AlignItems::Center,
                    border_radius: BorderRadius::all(Val::Px(8.0)),
                    ..default()
                },
                BackgroundColor(Color::srgb_u8(90, 90, 90)),
            ))
            .with_children(|button| {
                button.spawn((
                    Text("LOGOUT".to_string()),
                    TextFont {
                        font,
                        font_size: 16.0,
                        ..default()
                    },
                    TextColor(Color::WHITE),
                ));
            });
        });
}

fn teardown_login_overlay(
    commands: &mut Commands,
    query: &Query<Entity, With<LoginUiRoot>>,
    children: &Query<&Children>,
) {
    for entity in query {
        despawn_ui_node(entity, commands, children);
    }
}

fn teardown_logout_button(
    commands: &mut Commands,
    query: &Query<Entity, With<LogoutUiRoot>>,
    children: &Query<&Children>,
) {
    for entity in query {
        despawn_ui_node(entity, commands, children);
    }
}

fn despawn_ui_node(entity: Entity, commands: &mut Commands, children_query: &Query<&Children>) {
    if let Ok(children) = children_query.get(entity) {
        for child in children.iter() {
            despawn_ui_node(child, commands, children_query);
        }
    }
    commands.entity(entity).despawn();
}

type LoginButtonQueryFilter = (Changed<Interaction>, With<LoginButton>);

fn login_button_system(
    mut query: Query<(&Interaction, &mut BackgroundColor), LoginButtonQueryFilter>,
    mut auth: ResMut<Auth>,
    auth_state: Res<AuthState>,
) {
    for (interaction, mut color) in &mut query {
        if matches!(&*auth_state, AuthState::Authenticated(_)) {
            *color = BackgroundColor(Color::srgb_u8(90, 90, 90));
            continue;
        }
        match *interaction {
            Interaction::Pressed => {
                *color = BackgroundColor(Color::srgb_u8(44, 96, 220));
                if let Err(err) = auth.login() {
                    error!("Failed to start Internet Identity login: {err:?}");
                }
            }
            Interaction::Hovered => {
                *color = BackgroundColor(Color::srgb_u8(82, 140, 255));
            }
            Interaction::None => {
                *color = BackgroundColor(Color::srgb_u8(58, 116, 248));
            }
        }
    }
}

fn login_button_state_system(
    auth_state: Res<AuthState>,
    mut button_query: Query<&mut BackgroundColor, With<LoginButton>>,
    label_query: Query<Entity, With<LoginButtonLabel>>,
    mut writer: TextUiWriter,
) {
    if !auth_state.is_changed() {
        return;
    }
    let Ok(mut color) = button_query.single_mut() else {
        return;
    };
    let Ok(label_entity) = label_query.single() else {
        return;
    };
    match &*auth_state {
        AuthState::Unauthenticated => {
            *color = BackgroundColor(Color::srgb_u8(58, 116, 248));
            *writer.text(label_entity, 0) = "LOGIN".to_string();
        }
        AuthState::Authenticating => {
            *color = BackgroundColor(Color::srgb_u8(58, 116, 248));
            *writer.text(label_entity, 0) = "RETRY LOGIN".to_string();
        }
        AuthState::Authenticated(_) => {
            *color = BackgroundColor(Color::srgb_u8(70, 70, 70));
            *writer.text(label_entity, 0) = "LOGGED IN".to_string();
        }
    }
}

type LogoutButtonQueryFilter = (Changed<Interaction>, With<LogoutButton>);

fn logout_button_system(
    mut query: Query<(&Interaction, &mut BackgroundColor), LogoutButtonQueryFilter>,
    mut auth: ResMut<Auth>,
) {
    for (interaction, mut color) in &mut query {
        match *interaction {
            Interaction::Pressed => {
                *color = BackgroundColor(Color::srgb_u8(70, 70, 70));
                if let Err(err) = auth.logout() {
                    error!("Failed to log out: {err:?}");
                }
            }
            Interaction::Hovered => {
                *color = BackgroundColor(Color::srgb_u8(110, 110, 110));
            }
            Interaction::None => {
                *color = BackgroundColor(Color::srgb_u8(90, 90, 90));
            }
        }
    }
}

fn login_status_text_system(
    auth_state: Res<AuthState>,
    mut writer: TextUiWriter,
    query: Query<Entity, With<LoginText>>,
) {
    if !auth_state.is_changed() {
        return;
    }
    if let Ok(entity) = query.single() {
        *writer.text(entity, 0) = login_status_message(&auth_state);
    }
}

fn auth_state_sync_system(mut auth: ResMut<Auth>, mut auth_state: ResMut<AuthState>) {
    auth.update_state_signal();
    let is_authenticated = auth.is_authenticated();
    match (&auth.state, is_authenticated) {
        (AuthState::Authenticated(_), false) => {
            auth.state = AuthState::Unauthenticated;
        }
        (AuthState::Unauthenticated, true) | (AuthState::Authenticating, true) => {
            auth.update_state();
        }
        _ => {}
    }
    if *auth_state != auth.state {
        *auth_state = auth.state.clone();
    }
}

fn login_status_message(state: &AuthState) -> String {
    match state {
        AuthState::Unauthenticated => "PRESS THE BUTTON BELOW".to_string(),
        AuthState::Authenticating => "LOGGING IN...".to_string(),
        AuthState::Authenticated(principal) => format!("Principal: {}", principal),
    }
}

fn principal_text_system(
    auth_state: Res<AuthState>,
    mut writer: TextUiWriter,
    query: Query<Entity, With<PrincipalText>>,
) {
    let Ok(entity) = query.single() else {
        return;
    };

    let text = match &*auth_state {
        AuthState::Authenticated(principal) => shorten_principal(principal),
        _ => String::new(),
    };
    *writer.text(entity, 0) = text;
}

/// keyboard_system only handle keyboard input
/// dont handle tick-tick falling
fn keyboard_system(
    mut commands: Commands,
    keyboard_input: Res<ButtonInput<KeyCode>>,
    mut game: ResMut<GameData>,
    time: Res<Time>,
    mut query: Query<(Entity, &mut Transform), With<BrickBoardBundle>>,
) {
    let ticked = game.keyboard_timer.tick(time.delta()).is_finished();
    if ticked && let Ok((moving_entity, mut transform)) = query.single_mut() {
        if keyboard_input.pressed(KeyCode::ArrowLeft)
            && game
                .board
                .valid_brickshape(&game.moving_brick, &game.moving_orig.left())
        {
            game.moving_orig.move_left();
            transform.translation.x -= consts::DOT_WIDTH_PX;
        }

        if keyboard_input.pressed(KeyCode::ArrowRight)
            && game
                .board
                .valid_brickshape(&game.moving_brick, &game.moving_orig.right())
        {
            game.moving_orig.move_right();
            transform.translation.x += consts::DOT_WIDTH_PX;
        }

        if keyboard_input.pressed(KeyCode::ArrowUp) {
            let rotated = game.moving_brick.rotate();
            if game.board.valid_brickshape(&rotated, &game.moving_orig) {
                spawn_brick_board(&mut commands, rotated.into(), game.moving_orig);
                game.moving_brick = rotated;
                game.update_moving_brick_metrics();
                commands.entity(moving_entity).despawn();
            }
        }
        if keyboard_input.pressed(KeyCode::Space) {
            while game
                .board
                .valid_brickshape(&game.moving_brick, &game.moving_orig.down())
            {
                game.moving_orig.move_down();
                transform.translation.y -= consts::DOT_WIDTH_PX;
            }
        }
    }
}

/// movebrick_systrem only handle tick-tick falling
/// dont handle keyboard input
fn movebrick_systrem(
    //commands: Commands,
    mut game: ResMut<GameData>,
    time: Res<Time>,
    mut query: Query<&mut Transform, With<BrickBoardBundle>>,
) {
    let ticked = game.falling_timer.tick(time.delta()).is_finished();
    if ticked && let Ok(mut transform) = query.single_mut() {
        if game
            .board
            .valid_brickshape(&game.moving_brick, &game.moving_orig.down())
        {
            //after ticking, brick falling one line.
            game.moving_orig.move_down();
            transform.translation.y -= consts::DOT_WIDTH_PX;
        } else {
            //there is no space to falling, so freeze the brick.
            let frozon_brick = game.moving_brick;
            let frozon_orig = game.moving_orig;
            game.board.occupy_brickshape(&frozon_brick, &frozon_orig);
            game.freeze = true;
            //if we destory moving brick here.
            //there is flash, when destory brick ,and re-draw board.
            //commands.entity(entity).despawn();
        }
    }
}

fn freezebrick_system(
    mut commands: Commands,
    mut game: ResMut<GameData>,
    mut brick: Query<Entity, With<BrickBoardBundle>>,
    mut board: Query<Entity, With<BoardBundle>>,
) {
    if game.freeze {
        //step 1. check: we can clean one line?
        game.deleted_lines = game.board.clean_lines();

        //destory moving brick
        if let Ok(entity) = brick.single_mut() {
            commands.entity(entity).despawn();
        }
        //destory board
        if let Ok(entity) = board.single_mut() {
            commands.entity(entity).despawn();
        }
        //redraw board
        spawn_board(&mut commands, &game.board);
    }
}

#[allow(clippy::type_complexity)]
fn scoreboard_system(
    mut commands: Commands,
    mut state: ResMut<NextState<GameState>>,
    mut game: ResMut<GameData>,
    mut next_brick: Query<Entity, With<BrickNextBundle>>,
    mut writer: TextUiWriter,
    mut query: ParamSet<(
        Query<Entity, With<ScoreText>>,
        Query<Entity, With<LinesText>>,
        Query<Entity, With<LevelText>>,
    )>,
) {
    if game.deleted_lines > 0 {
        game.score += get_score(game.level, game.deleted_lines);
        game.lines += game.deleted_lines;
        game.deleted_lines = 0;

        let level = get_level(game.lines);
        if game.level != level {
            game.level = level;
            game.falling_timer
                .set_duration(Duration::from_secs_f32(get_speed(level)));
        }
        if let Ok(text) = query.p0().single() {
            //text.sections[0].value = format!("{:06}", game.score);
            *writer.text(text, 0) = format!("{:06}", game.score);
        }
        if let Ok(text) = query.p1().single() {
            //text.sections[0].value = format!("{:06}", game.lines);
            *writer.text(text, 0) = format!("{:06}", game.lines);
        }
        if let Ok(text) = query.p2().single() {
            //text.sections[0].value = format!("{:02}", game.level);
            *writer.text(text, 0) = format!("{:02}", game.level);
        }
    }

    //next moving brick
    //step 1. generate new brick(using next_brick, and rand generate new next_brick)
    //game.freeze = false;
    if game.freeze {
        game.freeze = false;
        game.score += SCORE_PER_DROP;
        if let Ok(text) = query.p0().single_mut() {
            //text.sections[0].value = format!("{:06}", game.score);
            *writer.text(text, 0) = format!("{:06}", game.score);
        }

        game.moving_orig = consts::BRICK_START_DOT;
        game.moving_brick = game.next_brick;
        game.update_moving_brick_metrics();
        game.next_brick = BrickShape::rand();

        if game
            .board
            .valid_brickshape(&game.moving_brick, &BRICK_START_DOT)
        {
            //step 2.2 destory next_brick
            if let Ok(entity) = next_brick.single_mut() {
                commands.entity(entity).despawn();
            }

            //step 3.1 draw new one in start point
            spawn_brick_board(
                &mut commands,
                game.moving_brick.into(),
                consts::BRICK_START_DOT,
            );
            //step 3.3 draw new next_brick
            spawn_brick_next(&mut commands, game.next_brick.into());
        } else {
            //game over!
            //let _ = state.set(GameState::GameOver);
            state.set(GameState::GameOver);
        }
    }
}

fn gameover_setup(
    mut commands: Commands,
    asset_server: Res<AssetServer>,
    mut board: Query<Entity, With<BoardBundle>>,
    mut next_brick: Query<Entity, With<BrickNextBundle>>,
) {
    //destory board
    if let Ok(entity) = board.single_mut() {
        commands.entity(entity).despawn();
    }
    //destory next brick
    if let Ok(entity) = next_brick.single_mut() {
        commands.entity(entity).despawn();
    }
    //show GameOver
    commands
        .spawn(init_text(
            STRING_GAME_OVER,
            TEXT_GAME_X,
            TEXT_GAME_Y,
            &asset_server,
        ))
        .insert(GameOverUi);

    commands
        .spawn(init_text(
            "HIGH SCORES",
            TEXT_HIGHSCORES_TITLE_X,
            TEXT_HIGHSCORES_TITLE_Y,
            &asset_server,
        ))
        .insert(GameOverUi);

    for index in 0..LEADERBOARD_DISPLAY_COUNT {
        let label = format!("{:>2}. ---\n------", index + 1);
        commands
            .spawn(init_text_with_layout(
                &label,
                TEXT_HIGHSCORES_TITLE_X,
                TEXT_HIGHSCORES_TITLE_Y + TEXT_HIGHSCORES_LINE_HEIGHT * (index as f32 + 1.0),
                16.0,
                140.0,
                &asset_server,
            ))
            .insert(GameOverUi)
            .insert(LeaderboardEntryText { index });
    }

    commands
        .spawn(init_text(
            "",
            TEXT_HIGHSCORES_TITLE_X,
            TEXT_HIGHSCORES_STATUS_Y,
            &asset_server,
        ))
        .insert(GameOverUi)
        .insert(LeaderboardStatusText);
}

fn gameover_fetch_scores(
    auth_state: Res<AuthState>,
    auth: Res<Auth>,
    game: Res<GameData>,
    mut high_scores: ResMut<HighScoreState>,
) {
    high_scores.entries.clear();
    high_scores.visible = true;
    high_scores.pending_score = Some(game.score);
    high_scores.submit_task = None;
    let score = game.score;

    match &*auth_state {
        AuthState::Unauthenticated => {
            high_scores.task = None;
            high_scores.status_message = Some("LOG IN TO SAVE HIGH SCORES".to_string());
        }
        AuthState::Authenticating => {
            high_scores.task = None;
            high_scores.status_message = Some("LOGGING IN...".to_string());
        }
        AuthState::Authenticated(principal) => {
            if !high_scores.prefetched_entries.is_empty() {
                apply_prefetched_leaderboard(
                    &mut high_scores,
                    auth.backend.clone(),
                    *principal,
                    score,
                );
            } else if high_scores.prefetch_task.is_some() {
                high_scores.task = None;
                high_scores.status_message = Some("LOADING...".to_string());
            } else {
                let backend = auth.backend.clone();
                start_high_score_task(&mut high_scores, backend, *principal, score);
            }
        }
    }
}

fn gameover_submit_pending_score_system(
    auth_state: Res<AuthState>,
    auth: Res<Auth>,
    mut high_scores: ResMut<HighScoreState>,
    game_state: Res<State<GameState>>,
) {
    if *game_state.get() != GameState::GameOver {
        return;
    }
    let AuthState::Authenticated(principal) = &*auth_state else {
        return;
    };
    if high_scores.task.is_some() {
        return;
    }
    let Some(score) = high_scores.pending_score else {
        return;
    };
    if !high_scores.prefetched_entries.is_empty() {
        apply_prefetched_leaderboard(&mut high_scores, auth.backend.clone(), *principal, score);
        return;
    }
    if high_scores.prefetch_task.is_some() {
        return;
    }
    let backend = auth.backend.clone();
    start_high_score_task(&mut high_scores, backend, *principal, score);
}

fn gameover_system(
    mut commands: Commands,
    mut state: ResMut<NextState<GameState>>,
    mut game: ResMut<GameData>,
    mut gameover: Query<Entity, With<GameOverUi>>,
    mut high_scores: ResMut<HighScoreState>,
    keyboard_input: Res<ButtonInput<KeyCode>>,
) {
    if keyboard_input.just_pressed(KeyCode::Space) {
        game.reset();

        for entity in &mut gameover {
            commands.entity(entity).despawn();
        }

        high_scores.reset();
        state.set(GameState::Playing);
    }
}

fn poll_high_score_tasks(mut high_scores: ResMut<HighScoreState>, auth: Res<Auth>) {
    let Some(task) = high_scores.task.as_mut() else {
        if let Some(submit_task) = high_scores.submit_task.as_mut()
            && future::block_on(future::poll_once(submit_task)).is_some()
        {
            high_scores.submit_task = None;
        }
        return;
    };

    if let Some(result) = future::block_on(future::poll_once(task)) {
        high_scores.task = None;
        match result {
            Ok(HighScorePayload {
                mut leaderboard,
                should_submit,
                score,
            }) => {
                leaderboard.truncate(LEADERBOARD_DISPLAY_COUNT);

                high_scores.entries = leaderboard;
                high_scores.status_message = Some(format!("SCORE\n{:06}", score));
                high_scores.pending_score = None;

                if should_submit {
                    start_score_submit_task(&mut high_scores, auth.backend.clone(), score);
                }
            }
            Err(message) => {
                high_scores.entries.clear();
                high_scores.status_message = Some(message);
                high_scores.pending_score = None;
            }
        }
    }

    if let Some(submit_task) = high_scores.submit_task.as_mut()
        && future::block_on(future::poll_once(submit_task)).is_some()
    {
        high_scores.submit_task = None;
    }
}

fn leaderboard_prefetch_system(
    game_state: Res<State<GameState>>,
    auth_state: Res<AuthState>,
    auth: Res<Auth>,
    game: Res<GameData>,
    time: Res<Time>,
    mut high_scores: ResMut<HighScoreState>,
) {
    if let Some(task) = high_scores.prefetch_task.as_mut()
        && let Some(result) = future::block_on(future::poll_once(task))
    {
        high_scores.prefetch_task = None;
        if let Ok(mut leaderboard) = result {
            leaderboard.truncate(LEADERBOARD_DISPLAY_COUNT);
            high_scores.prefetched_entries = leaderboard;
        } else {
            high_scores.prefetched_entries.clear();
        }
    }

    let game_state = *game_state.get();

    if game_state != GameState::Playing {
        if game_state == GameState::GameOver
            && high_scores.entries.is_empty()
            && high_scores.pending_score.is_some()
            && let AuthState::Authenticated(principal) = &*auth_state
            && !high_scores.prefetched_entries.is_empty()
        {
            let score = high_scores.pending_score.unwrap_or_default();
            apply_prefetched_leaderboard(&mut high_scores, auth.backend.clone(), *principal, score);
        }
        high_scores.prefetch_timer.reset();
        return;
    }

    if !matches!(&*auth_state, AuthState::Authenticated(_)) {
        return;
    }
    if !game.is_near_game_over() {
        high_scores.prefetch_timer.reset();
        return;
    }

    high_scores.prefetch_timer.tick(time.delta());
    let should_fetch = high_scores.prefetch_task.is_none()
        && (high_scores.prefetched_entries.is_empty()
            || high_scores.prefetch_timer.just_finished());
    if !should_fetch {
        return;
    }

    let backend = auth.backend.clone();
    let limit = LEADERBOARD_DISPLAY_COUNT as u32;
    high_scores.prefetch_timer.reset();
    high_scores.prefetch_task = Some(AsyncComputeTaskPool::get().spawn(async move {
        let mut leaderboard = backend
            .get_leaderboard(Some(limit))
            .await
            .map_err(|e| format!("FAILED TO FETCH LEADERBOARD: {e}"))?;
        leaderboard.truncate(LEADERBOARD_DISPLAY_COUNT);
        Ok(leaderboard)
    }));
}

fn update_high_score_ui(
    high_scores: Res<HighScoreState>,
    status_query: Query<Entity, With<LeaderboardStatusText>>,
    mut entry_query: Query<(Entity, &LeaderboardEntryText)>,
    mut writer: TextUiWriter,
) {
    if !high_scores.visible {
        return;
    }

    if let Ok(entity) = status_query.single() {
        let message = high_scores.status_message.clone().unwrap_or_default();
        *writer.text(entity, 0) = message;
    }

    for (entity, entry) in &mut entry_query {
        let text = high_scores
            .entries
            .get(entry.index)
            .map(|score_entry| format_leaderboard_entry(entry.index, score_entry))
            .unwrap_or_else(|| format!("{:>2}. ---\n------", entry.index + 1));
        *writer.text(entity, 0) = text;
    }
}

fn start_high_score_task(
    high_scores: &mut HighScoreState,
    backend: BackendActor,
    player: Principal,
    score: u32,
) {
    let display_count = LEADERBOARD_DISPLAY_COUNT;
    let limit = display_count as u32;
    let task = AsyncComputeTaskPool::get().spawn(async move {
        let mut leaderboard = backend
            .get_leaderboard(Some(limit))
            .await
            .map_err(|e| format!("FAILED TO FETCH LEADERBOARD: {e}"))?;
        leaderboard.truncate(display_count);
        let (entries, should_submit) = local_leaderboard_for_score(&leaderboard, player, score);
        leaderboard = entries;
        Ok(HighScorePayload {
            leaderboard,
            should_submit,
            score,
        })
    });

    high_scores.task = Some(task);
    high_scores.status_message = Some("LOADING...".to_string());
    high_scores.pending_score = Some(score);
}

fn apply_prefetched_leaderboard(
    high_scores: &mut HighScoreState,
    backend: BackendActor,
    player: Principal,
    score: u32,
) {
    let (entries, should_submit) =
        local_leaderboard_for_score(&high_scores.prefetched_entries, player, score);
    high_scores.entries = entries;
    high_scores.status_message = Some(format!("SCORE\n{:06}", score));
    high_scores.pending_score = None;
    high_scores.prefetched_entries.clear();

    if should_submit {
        start_score_submit_task(high_scores, backend, score);
    }
}

fn local_leaderboard_for_score(
    leaderboard: &[ScoreEntry],
    player: Principal,
    score: u32,
) -> (Vec<ScoreEntry>, bool) {
    let mut updated = leaderboard.to_vec();
    updated.push(ScoreEntry { player, score });
    updated.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.player.as_slice().cmp(b.player.as_slice()))
    });
    updated.truncate(LEADERBOARD_DISPLAY_COUNT);
    let should_submit = updated
        .iter()
        .any(|candidate| candidate.player == player && candidate.score == score);
    let entries = if should_submit {
        updated
    } else {
        leaderboard.to_vec()
    };
    (entries, should_submit)
}

fn start_score_submit_task(high_scores: &mut HighScoreState, backend: BackendActor, score: u32) {
    high_scores.submit_task = Some(AsyncComputeTaskPool::get().spawn(async move {
        if let Err(err) = backend.submit_score(score).await {
            error!("Failed to submit score: {err}");
        }
    }));
}

fn format_leaderboard_entry(rank: usize, entry: &ScoreEntry) -> String {
    let player = shorten_principal(&entry.player);
    format!("{:>2}. {}\n{:06}", rank + 1, player, entry.score)
}

fn shorten_principal(principal: &Principal) -> String {
    let text = principal.to_text();
    const MAX_LEN: usize = 9;
    if text.len() <= MAX_LEN {
        return text;
    }
    let mut shortened: String = text.chars().take(MAX_LEN - 1).collect();
    shortened.push('…');
    shortened
}

#[allow(clippy::type_complexity)]
fn newgame_system(
    mut commands: Commands,
    game: ResMut<GameData>,
    mut writer: TextUiWriter,
    mut query: ParamSet<(
        Query<Entity, With<ScoreText>>,
        Query<Entity, With<LinesText>>,
        Query<Entity, With<LevelText>>,
    )>,
) {
    let moving_brick = game.moving_brick;
    let next_brick = game.next_brick;
    spawn_brick_board(&mut commands, moving_brick.into(), BRICK_START_DOT);
    spawn_brick_next(&mut commands, next_brick.into());

    if let Ok(text) = query.p0().single_mut() {
        //text.sections[0].value = format!("{:06}", game.score);
        *writer.text(text, 0) = format!("{:06}", game.score);
    }
    if let Ok(text) = query.p1().single_mut() {
        //text.sections[0].value = format!("{:06}", game.lines);
        *writer.text(text, 0) = format!("{:06}", game.lines);
    }
    if let Ok(text) = query.p2().single_mut() {
        //text.sections[0].value = format!("{:02}", game.level);
        *writer.text(text, 0) = format!("{:02}", game.level);
    }
}

fn spawn_brick_next(commands: &mut Commands, brick: Brick) {
    commands
        .spawn((
            Sprite {
                color: Color::NONE,
                ..default()
            },
            Transform::from_xyz(
                consts::NEXT_BRICK_LEFT_PX - consts::WINDOWS_WIDTH / 2.0,
                consts::NEXT_BRICK_BOTTOM_PX - consts::WINDOWS_HEIGHT / 2.0,
                0.0, //zero,which one pixel behind the UI-screen png; cannot be seen in screen
            ),
        ))
        .insert(BrickNextBundle)
        .with_children(|parent| {
            (0..4).for_each(|i| {
                spawn_dot_as_child(parent, dot_to_vec2(&brick.dots[i]));
            });
        });
}

fn spawn_board(commands: &mut Commands, board: &Board) {
    commands
        .spawn((
            Sprite {
                color: Color::NONE,
                ..default()
            },
            Transform::from_xyz(
                10.0 - consts::WINDOWS_WIDTH / 2.0 + consts::BOARD_LEFT_PX,
                10.0 - consts::WINDOWS_HEIGHT / 2.0 + consts::BOARD_BOTTOM_PX,
                0.0, //zero,which one pixel behind the UI-screen png; cannot be seen in screen
            ),
        ))
        .insert(BoardBundle)
        .with_children(|parent| {
            (0..consts::BOARD_X)
                .flat_map(|a| (0..consts::BOARD_Y).map(move |b| Dot(a, b)))
                .filter(|dot| board.occupied_dot(dot))
                .for_each(|dot| spawn_dot_as_child(parent, dot_to_vec2(&dot)));
        });
}

fn spawn_brick_board(commands: &mut Commands, brick: Brick, dot_in_board: Dot) {
    commands
        .spawn((
            Sprite {
                color: Color::NONE,
                ..default()
            },
            Transform::from_xyz(
                dot_in_board.0 as f32 * consts::DOT_WIDTH_PX + 10.0 - consts::WINDOWS_WIDTH / 2.0
                    + consts::BOARD_LEFT_PX,
                dot_in_board.1 as f32 * consts::DOT_WIDTH_PX + 10.0 - consts::WINDOWS_HEIGHT / 2.0
                    + consts::BOARD_BOTTOM_PX,
                0.0, //zero,which one pixel behind the UI-screen png; cannot be seen in screen
            ),
        ))
        .insert(BrickBoardBundle)
        .with_children(|parent| {
            (0..4).for_each(|i| {
                spawn_dot_as_child(parent, dot_to_vec2(&brick.dots[i]));
            });
        });
}

fn spawn_dot_as_child(commands: &mut ChildSpawnerCommands, trans: Vec2) {
    commands
        .spawn(sprit_bundle(20., Color::BLACK, trans))
        .with_children(|parent| {
            parent
                .spawn(sprit_bundle(16., consts::BACKGROUND, Vec2::default()))
                .with_children(|parent| {
                    parent.spawn(sprit_bundle(12., Color::BLACK, Vec2::default()));
                });
        });
}

#[inline]
fn sprit_bundle(width: f32, color: Color, trans: Vec2) -> impl Bundle {
    (
        Sprite {
            color,
            custom_size: Some(Vec2::new(width, width)),
            ..default()
        },
        Transform {
            translation: Vec3::new(trans.x, trans.y, 0.1),
            ..default()
        },
    )
}
#[inline]
fn init_text(msg: &str, x: f32, y: f32, asset_server: &Res<AssetServer>) -> impl Bundle {
    init_text_with_size(msg, x, y, 24.0, asset_server)
}

#[inline]
fn init_text_with_size(
    msg: &str,
    x: f32,
    y: f32,
    font_size: f32,
    asset_server: &Res<AssetServer>,
) -> impl Bundle {
    (
        Text(msg.to_string()),
        TextFont {
            // This font is loaded and will be used instead of the default font.
            font: asset_server.load("digital7mono.ttf"),
            font_size,
            ..default()
        },
        TextColor(Color::BLACK),
        Node {
            align_self: AlignSelf::FlexEnd,
            position_type: PositionType::Absolute,
            left: Val::Px(x),
            top: Val::Px(y),
            ..default()
        },
    )
}

#[inline]
fn init_text_with_layout(
    msg: &str,
    x: f32,
    y: f32,
    font_size: f32,
    width: f32,
    asset_server: &Res<AssetServer>,
) -> impl Bundle {
    (
        Text(msg.to_string()),
        TextFont {
            font: asset_server.load("digital7mono.ttf"),
            font_size,
            ..default()
        },
        TextColor(Color::BLACK),
        TextLayout::new_with_justify(Justify::Center),
        Node {
            align_self: AlignSelf::FlexEnd,
            position_type: PositionType::Absolute,
            left: Val::Px(x),
            top: Val::Px(y),
            width: Val::Px(width),
            ..default()
        },
    )
}

#[inline]
fn init_text_with_layout_justify(
    msg: &str,
    right: f32,
    bottom: f32,
    font_size: f32,
    justify: Justify,
    asset_server: &Res<AssetServer>,
) -> impl Bundle {
    (
        Text(msg.to_string()),
        TextFont {
            font: asset_server.load("digital7mono.ttf"),
            font_size,
            ..default()
        },
        TextColor(Color::BLACK),
        TextLayout::new_with_justify(justify),
        Node {
            align_self: AlignSelf::FlexEnd,
            position_type: PositionType::Absolute,
            right: Val::Px(right),
            bottom: Val::Px(bottom),
            ..default()
        },
    )
}

#[derive(Resource)]
struct HighScoreState {
    task: Option<Task<Result<HighScorePayload, String>>>,
    entries: Vec<ScoreEntry>,
    status_message: Option<String>,
    visible: bool,
    pending_score: Option<u32>,
    submit_task: Option<Task<()>>,
    prefetch_task: Option<Task<Result<Vec<ScoreEntry>, String>>>,
    prefetched_entries: Vec<ScoreEntry>,
    prefetch_timer: Timer,
}

impl HighScoreState {
    fn reset(&mut self) {
        self.task = None;
        self.entries.clear();
        self.status_message = None;
        self.visible = false;
        self.pending_score = None;
        self.submit_task = None;
        self.prefetch_task = None;
        self.prefetched_entries.clear();
        self.prefetch_timer.reset();
    }
}

impl Default for HighScoreState {
    fn default() -> Self {
        Self {
            task: None,
            entries: Vec::new(),
            status_message: None,
            visible: false,
            pending_score: None,
            submit_task: None,
            prefetch_task: None,
            prefetched_entries: Vec::new(),
            prefetch_timer: Timer::from_seconds(10.0, TimerMode::Repeating),
        }
    }
}

struct HighScorePayload {
    leaderboard: Vec<ScoreEntry>,
    should_submit: bool,
    score: u32,
}

#[derive(Resource)]
pub struct GameData {
    board: Board,
    moving_brick: BrickShape,
    moving_orig: Dot,
    moving_brick_max_local_y: i8,
    moving_brick_height: i8,
    next_brick: BrickShape,
    freeze: bool,
    deleted_lines: u32,
    score: u32,
    lines: u32,
    level: u32,
    keyboard_timer: Timer,
    falling_timer: Timer,
}

impl GameData {
    fn reset(&mut self) {
        self.board.clear();
        self.freeze = false;
        self.deleted_lines = 0;
        self.score = 0;
        self.lines = 0;
        self.level = 0;
        self.keyboard_timer = Timer::from_seconds(consts::TIMER_KEY_SECS, TimerMode::Repeating);
        self.falling_timer = Timer::from_seconds(consts::TIMER_FALLING_SECS, TimerMode::Repeating);
        self.update_moving_brick_metrics();
    }

    fn is_near_game_over(&self) -> bool {
        let top_y = self.moving_orig.1 + self.moving_brick_max_local_y;
        let headroom = BOARD_Y_VALIDE - 1 - top_y;
        headroom <= 1 || headroom < self.moving_brick_height
    }

    fn update_moving_brick_metrics(&mut self) {
        let (max_local_y, height) = Self::brick_metrics(self.moving_brick);
        self.moving_brick_max_local_y = max_local_y;
        self.moving_brick_height = height;
    }

    fn brick_metrics(shape: BrickShape) -> (i8, i8) {
        let brick = Brick::from(shape);
        let (min_local_y, max_local_y) = brick
            .dots
            .iter()
            .fold((i8::MAX, i8::MIN), |(min_y, max_y), dot| {
                (min_y.min(dot.1), max_y.max(dot.1))
            });
        let height = max_local_y - min_local_y + 1;
        (max_local_y, height)
    }
}
impl Default for GameData {
    fn default() -> Self {
        let moving_brick = BrickShape::rand();
        let (moving_brick_max_local_y, moving_brick_height) = GameData::brick_metrics(moving_brick);
        Self {
            board: Board::default(),
            moving_brick,
            moving_orig: consts::BRICK_START_DOT,
            moving_brick_max_local_y,
            moving_brick_height,
            next_brick: BrickShape::rand(),
            freeze: false,
            keyboard_timer: Timer::from_seconds(consts::TIMER_KEY_SECS, TimerMode::Repeating),
            falling_timer: Timer::from_seconds(consts::TIMER_FALLING_SECS, TimerMode::Repeating),
            deleted_lines: 0,
            score: 0,
            lines: 0,
            level: 0,
        }
    }
}

#[inline]
fn dot_to_vec2(dot: &Dot) -> Vec2 {
    Vec2::new(DOT_WIDTH_PX * dot.0 as f32, DOT_WIDTH_PX * dot.1 as f32)
}

///tetris speeding
///delay = 725 * .85 ^ level + level (ms)
///use formula from dwhacks, http://gist.github.com/dwhacks/8644250
#[inline]
pub fn get_speed(level: u32) -> f32 {
    consts::TIMER_FALLING_SECS * (0.85_f32).powi(level as i32) + level as f32 / 1000.0
}

///tetris scoring
///use as [Original Nintendo Scoring System]
///https://tetris.fandom.com/wiki/Scoring
#[inline]
pub fn get_score(level: u32, erase_lines: u32) -> u32 {
    assert!(0 < erase_lines);
    assert!(erase_lines <= 4);
    vec![40, 100, 300, 1200][(erase_lines - 1) as usize] * (level + 1)
}

///level
///increase level every 10 lines.
#[inline]
pub fn get_level(total_lines: u32) -> u32 {
    (total_lines / 10).min(99)
}
