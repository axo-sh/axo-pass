mod app;
mod pinentry;
mod pinentry_handler;
mod secrets;

use std::sync::OnceLock;

use serde_json::Value;
use tauri::Manager;
use tauri_plugin_cli::CliExt;
use tokio::sync::oneshot;

use crate::app::{AppMode, AppState, PinentryState};
use crate::pinentry_handler::TauriPinentryHandler;
use crate::secrets::vault::read_vault;

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
            let cli_matches = app.cli().matches().ok();

            log::debug!("CLI matches: {:?}", cli_matches);
            if let Some(sc_matches) = cli_matches
                .as_ref()
                .and_then(|m| m.subcommand.clone())
                .iter()
                .find(|sc| sc.name == "get")
            {
                let Some(item_url) = sc_matches.matches.args.get("item_url").cloned() else {
                    panic!("Missing required argument: item_url");
                };

                let get_item_url = item_url
                    .value
                    .as_str()
                    .ok_or_else(|| format!("Invalid item_url argument: {:?}", item_url.value))?
                    .to_string();

                log::debug!("Getting item for URL: {}", get_item_url);
                let u = url::Url::parse(&get_item_url)
                    .map_err(|e| format!("Invalid URL '{get_item_url}': {e}"))?;
                if u.scheme() != "axo" {
                    panic!("Unsupported URL scheme: {}", u.scheme())
                }
                let vault_name = u
                    .host_str()
                    .ok_or_else(|| format!("URL missing host: {}", get_item_url))?;

                let mut vault = read_vault(&app.path().app_data_dir()?, Some(vault_name))
                    .expect("Failed to read vault");

                vault.unlock().expect("Failed to unlock vault");

                let res = vault
                    .get_secret_by_url(u)
                    .expect("Failed to get item by URL");
                println!("{}", res.unwrap_or_else(|| "<not found>".to_string()));
                // get_item_url
                app.handle().exit(0);
                return Ok(());
            }

            let mode = if detect_pinentry_mode(cli_matches.as_ref()) {
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
            app::get_vault,
            app::init_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
