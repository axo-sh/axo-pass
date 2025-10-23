mod app;
mod keychain;
mod pinentry;
mod pinentry_handler;

use std::sync::OnceLock;

use serde_json::Value;
use tauri::Manager;
use tauri_plugin_cli::CliExt;
use tokio::sync::oneshot;

use crate::app::{AppMode, AppState, PinentryState};
use crate::pinentry_handler::TauriPinentryHandler;

// Global static to store the app mode
static APP_MODE: OnceLock<AppMode> = OnceLock::new();

/// Detect if the app was started in pinentry mode by checking for the arg or
/// the presence of an open stdin pipe
pub fn detect_pinentry_mode(args: Option<&tauri_plugin_cli::Matches>) -> bool {
    args.and_then(|m| m.args.get("pinentry"))
        .map(|arg| arg.value == Value::Bool(true))
        .unwrap_or(false)
}

fn run_pinentry_mode(state: PinentryState, app_handle: tauri::AppHandle) {
    let (exit_tx, exit_rx) = oneshot::channel();

    // Start pinentry server in background thread
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let stdin = tokio::io::stdin();
            let stdout = tokio::io::stdout();

            // Give the app time to start
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            let mut handler = TauriPinentryHandler::new(state, exit_tx);
            let mut server = pinentry::PinentryServer::new(stdin, stdout)
                .await
                .expect("Failed to create pinentry server");

            if let Err(e) = server.run(&mut handler).await {
                log::error!("Pinentry server error: {e}");
            }
        });
    });

    // Monitor the exit signal and close the window when it's received
    std::thread::spawn(move || {
        // Block on the oneshot receiver
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let _ = exit_rx.await;

            // Give a moment for the response to be sent back through pinentry
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            log::debug!("Exiting app after pinentry completion");
            app_handle.exit(0);
        });
    });
}

pub fn run() {
    let state = PinentryState::default();

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
        .manage(state.clone())
        .setup(move |app| {
            // Store the app handle in the state for event emission
            state.set_app_handle(app.handle().clone());
            let args = app.cli().matches().ok();
            let mode = if detect_pinentry_mode(args.as_ref()) {
                log::debug!("Running in pinentry mode");
                AppMode::Pinentry
            } else {
                log::debug!("Running in app mode");
                AppMode::App(AppState {
                    pinentry_program_path: app
                        .path()
                        .resource_dir()
                        .map(|p| p.join("frittata-pinentry"))
                        .ok(),
                })
            };

            let is_pinentry = mode.is_pinentry();
            APP_MODE.set(mode).expect("APP_MODE already set");

            // Setup based on mode
            if is_pinentry {
                run_pinentry_mode(state.clone(), app.handle().clone());
            }

            if let Some(window) = app.get_webview_window("main") {
                // Configure window based on mode
                if is_pinentry {
                    // In pinentry mode: compact fixed size, non-resizable
                    let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize {
                        width: 350.0,
                        height: 500.0,
                    }));
                    let _ = window.set_resizable(false);
                    let _ = window.center();
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
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app::get_mode,
            app::list_passwords,
            app::send_pinentry_response
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
