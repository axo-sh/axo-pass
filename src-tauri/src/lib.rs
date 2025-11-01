mod app;
mod cli;
mod la_context;
mod password_request;
mod pinentry;
mod pinentry_handler;
mod secrets;
mod ssh_askpass_handler;

use std::sync::OnceLock;

use tauri::Manager;
use tauri_plugin_cli::CliExt;
use tokio::sync::oneshot;

use crate::app::AppMode;
use crate::cli::{get_arg, run_cli_command};
use crate::pinentry_handler::{PinentryHandler, PinentryState};
use crate::ssh_askpass_handler::AskPassState;

// Global static to store the app mode
static APP_MODE: OnceLock<AppMode> = OnceLock::new();
const STD_DELAY: std::time::Duration = tokio::time::Duration::from_millis(200);

fn run_pinentry_mode(app_handle: tauri::AppHandle, state: PinentryState) {
    let (exit_tx, exit_rx) = oneshot::channel();

    // Start pinentry server in background thread
    tauri::async_runtime::spawn(async move {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();

        // Give the app time to start
        tokio::time::sleep(STD_DELAY).await;

        let mut handler = PinentryHandler::new(state, exit_tx);
        let mut server = pinentry::PinentryServer::new(stdin, stdout)
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

fn run_ssh_askpass_mode(app_handle: tauri::AppHandle, state: AskPassState, prompt: String) {
    let (exit_tx, exit_rx) = oneshot::channel();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(STD_DELAY).await;
        let handler = ssh_askpass_handler::SshAskpassHandler::new(state, exit_tx);
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

pub fn run() {
    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::new()
                .clear_targets()
                .target(tauri_plugin_log::Target::new(
                    tauri_plugin_log::TargetKind::Stderr,
                ))
                .target(tauri_plugin_log::Target::new(
                    tauri_plugin_log::TargetKind::LogDir {
                        file_name: Some("frittata".to_string()),
                    },
                ))
                .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepSome(7))
                .timezone_strategy(tauri_plugin_log::TimezoneStrategy::UseLocal)
                .level(log::LevelFilter::Debug)
                .build(),
        )
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_cli::init())
        .setup(move |app| {
            let cli_matches = app.cli().matches().ok();

            if let Some(subcommand) = cli_matches.as_ref().and_then(|m| m.subcommand.as_deref()) {
                match subcommand.name.as_str() {
                    "pinentry" => {
                        let pinentry_state = PinentryState::default();
                        pinentry_state.set_app_handle(app.handle().clone());
                        app.manage(pinentry_state.clone());
                        log::debug!("Running in pinentry mode");
                        APP_MODE
                            .set(AppMode::Pinentry)
                            .expect("APP_MODE already set");
                        run_pinentry_mode(app.handle().clone(), pinentry_state.clone());
                    },
                    "ssh-askpass" => {
                        log::debug!("Running in SSH askpass mode");
                        let askpass_state = ssh_askpass_handler::AskPassState::default();
                        askpass_state.set_app_handle(app.handle().clone());
                        app.manage(askpass_state.clone());
                        APP_MODE
                            .set(AppMode::SshAskpass)
                            .expect("APP_MODE already set");
                        let prompt = get_arg(subcommand, "prompt")?;
                        run_ssh_askpass_mode(app.handle().clone(), askpass_state.clone(), prompt);
                    },
                    command => {
                        log::debug!("Running in cli mode");
                        APP_MODE.set(AppMode::CLI).expect("APP_MODE already set");
                        run_cli_command(app.handle().clone(), subcommand, command);
                        return Ok(());
                    },
                }
            } else {
                APP_MODE.set(AppMode::App).expect("APP_MODE already set");
            }

            if let Some(window) = app.get_webview_window("main") {
                if matches!(
                    APP_MODE.get(),
                    Some(AppMode::Pinentry) | Some(AppMode::SshAskpass)
                ) {
                    // In pinentry/SSH askpass mode: compact fixed size, non-resizable
                    let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize {
                        width: 350.0,
                        height: 500.0,
                    }));
                    let _ = window.set_resizable(false);
                } else {
                    // In app mode: larger size (800x700), resizable
                    let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize {
                        width: 800.0,
                        height: 700.0,
                    }));
                    let _ = window.set_resizable(true);
                }

                let _ = window.show();
                let _ = window.set_focus();
                let _ = window
                    .center()
                    .inspect_err(|err| log::error!("err center: {err}"));
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app::get_mode,
            app::list_passwords,
            app::send_pinentry_response,
            app::send_askpass_response,
            app::get_vault,
            app::init_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
