mod app_mode;
mod app_state;
mod handlers;
mod password_request;
mod protocols;

use std::sync::Mutex;

use clap::Subcommand;
use tauri::Manager;
use tokio::sync::oneshot;

use crate::app::app_mode::AppMode;
use crate::app::app_state::AppState;
use crate::app::protocols::pinentry::{PinentryHandler, PinentryServer, PinentryState};
use crate::app::protocols::ssh_askpass::{AskPassState, SshAskpassHandler};

const STD_DELAY: std::time::Duration = tokio::time::Duration::from_millis(200);

#[derive(Subcommand, Debug, Clone)]
pub enum AxoAppCommand {
    #[command(hide = true)]
    Pinentry,

    #[command(hide = true)]
    SshAskpass { prompt: String },
}

fn run_pinentry_mode(app_handle: tauri::AppHandle) {
    let state = PinentryState::default();
    state.set_app_handle(app_handle.clone());
    app_handle.manage(state.clone());

    let (exit_tx, exit_rx) = oneshot::channel();

    // Start pinentry server in background thread
    tauri::async_runtime::spawn(async move {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();

        // Give the app time to start
        tokio::time::sleep(STD_DELAY).await;

        let mut handler = PinentryHandler::new(state, exit_tx);
        let mut server = PinentryServer::new(stdin, stdout)
            .await
            .expect("Failed to create pinentry server");

        if let Err(e) = server.run(&mut handler).await {
            log::error!("Pinentry server error: {e}");
        }
    });

    // Monitor the exit signal and close the window when it's received
    tauri::async_runtime::spawn(async move {
        let _ = exit_rx.await;
        tokio::time::sleep(STD_DELAY).await;
        log::debug!("Exiting app after pinentry completion");
        app_handle.exit(0);
    });
}

fn run_ssh_askpass_mode(app_handle: tauri::AppHandle, prompt: String) {
    let state = AskPassState::default();
    state.set_app_handle(app_handle.clone());
    app_handle.manage(state.clone());

    let (exit_tx, exit_rx) = oneshot::channel();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(STD_DELAY).await;
        let handler = SshAskpassHandler::new(state, exit_tx);
        if let Err(e) = handler.run(prompt).await {
            log::error!("SSH askpass handler error: {e}");
            std::process::exit(1);
        }
    });

    // Monitor the exit signal and close the window when it's received
    tauri::async_runtime::spawn(async move {
        let _ = exit_rx.await;
        tokio::time::sleep(STD_DELAY).await;
        log::debug!("Exiting app after SSH askpass completion");
        app_handle.exit(0);
    });
}

pub fn run(cmd: Option<AxoAppCommand>) {
    let mut log_plugin = tauri_plugin_log::Builder::new()
        .clear_targets()
        .target(tauri_plugin_log::Target::new(
            tauri_plugin_log::TargetKind::LogDir {
                file_name: Some("frittata".to_string()),
            },
        ))
        .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepSome(7))
        .timezone_strategy(tauri_plugin_log::TimezoneStrategy::UseLocal)
        .level(log::LevelFilter::Debug);

    if std::env::var("FRITTATA_DEBUG").is_ok() || cfg!(debug_assertions) {
        log_plugin = log_plugin.target(tauri_plugin_log::Target::new(
            tauri_plugin_log::TargetKind::Stderr,
        ));
    }

    tauri::Builder::default()
        .plugin(log_plugin.build())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_cli::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(move |app| {
            match cmd {
                Some(AxoAppCommand::Pinentry) => {
                    log::debug!("Running in pinentry mode");
                    app.handle().manage(AppMode::Pinentry);
                    run_pinentry_mode(app.handle().clone());
                },
                Some(AxoAppCommand::SshAskpass { prompt }) => {
                    log::debug!("Running in SSH askpass mode");
                    app.handle().manage(AppMode::SshAskpass);
                    run_ssh_askpass_mode(app.handle().clone(), prompt);
                },
                None => {
                    app.handle().manage(AppMode::App);
                    app.handle().manage(Mutex::new(AppState::new()));
                },
            }

            let app_mode = app.handle().state::<AppMode>();
            if let Some(window) = app.get_webview_window("main") {
                if matches!(&*app_mode, AppMode::Pinentry | AppMode::SshAskpass) {
                    // In pinentry/SSH askpass mode: compact fixed size, non-resizable
                    let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize {
                        width: 350.0,
                        height: 500.0,
                    }));

                    let _ = window.set_resizable(false);
                    let _ = window.show();
                    let _ = window.set_focus();
                    let _ = window
                        .center()
                        .inspect_err(|err| log::error!("err center: {err}"));

                    let mut pos = window
                        .outer_position()
                        .unwrap()
                        .to_logical::<f64>(window.scale_factor()?);
                    pos.x -= 300.0;
                    window.set_position(pos)?;
                } else {
                    // In app mode: larger size (800x700), resizable
                    let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize {
                        width: 800.0,
                        height: 700.0,
                    }));
                    window.set_min_size(Some(tauri::Size::Logical(tauri::LogicalSize {
                        width: 600.0,
                        height: 400.0,
                    })))?;

                    let _ = window.set_resizable(true);
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_mode::get_mode,
            handlers::passwords::list_passwords,
            handlers::passwords::delete_password,
            handlers::user_authorization::send_pinentry_response,
            handlers::user_authorization::send_askpass_response,
            handlers::settings::get_app_settings,
            handlers::vault::update_vault::update_vault,
            handlers::vault::delete_vault::delete_vault,
            handlers::vault::new_vault::new_vault,
            handlers::vault::get_vault::get_vault,
            handlers::vault::get_vault::list_vaults,
            handlers::vault::get_decrypted_credential::get_decrypted_credential,
            handlers::vault::add_item::add_item,
            handlers::vault::delete_item::delete_item,
            handlers::vault::update_item::update_item,
            handlers::vault::add_credential::add_credential,
            handlers::vault::delete_credential::delete_credential,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
