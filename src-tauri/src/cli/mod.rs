pub mod commands;
pub mod shell_integration;

use std::io;

use clap::{CommandFactory, Parser, Subcommand, command};
use clap_complete::{Shell, generate};
use fork::daemon;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt, reload};

use crate::cli::commands::age::AgeCommand;
use crate::cli::commands::inject::InjectCommand;
use crate::cli::commands::item::{ItemCommand, ItemReference};
use crate::cli::commands::keychain::KeychainCommand;
use crate::cli::commands::ssh_agent::SshAgentCommand;
use crate::cli::commands::vault::VaultCommand;
use crate::core::build_sha;
use crate::core::dirs::{log_data_dir, vaults_dir};

#[derive(Parser, Debug)]
pub struct AxoPassCli {
    #[command(subcommand)]
    pub command: Option<AxoPassCommand>,
}

#[derive(Subcommand, Debug)]
pub enum AxoPassCommand {
    /// Commands for managing vaults
    Vault(VaultCommand),

    /// Commands for managing items and credentials
    Item(ItemCommand),

    /// Get a item credential's secret
    Read {
        item_reference: ItemReference,
    },

    /// Inject secrets into a file
    Inject(InjectCommand),

    /// Commands for managing items stored in keychain
    Keychain(KeychainCommand),

    /// Commands for age encryption
    Age(AgeCommand),

    /// Show version and build
    Info,

    SshAgent(SshAgentCommand),

    #[command(hide = true)]
    Shellenv {
        #[arg(value_enum)]
        shell: Shell,
    },
}

impl AxoPassCommand {
    pub fn execute(&self) {
        let reload_log = if std::env::var("FRITTATA_DEBUG").is_ok() || cfg!(debug_assertions) {
            let filter = EnvFilter::new("debug,ssh_agent_lib=error");
            let layer: fmt::Layer<_, _, _, fn() -> Box<dyn io::Write>> = fmt::layer()
                .with_ansi(true)
                .with_writer(|| -> Box<dyn io::Write> { Box::new(io::stderr()) });
            let (layer, reload_layer) = reload::Layer::new(layer);
            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .init();
            Some(reload_layer)
        } else {
            None
        };

        if let AxoPassCommand::SshAgent(ssh_agent) = self
            && ssh_agent.should_detach()
        {
            ssh_agent.pre_run();

            log::debug!("Daemonizing SSH agent process...");
            // if we're not in debug mode, we should detach the ssh process:
            // do that here before tokio is initialized, otherwise bad things happen:
            // https://github.com/tokio-rs/tokio/issues/4301
            if let Err(e) = daemon(false, false) {
                // original process exits here
                log::error!("Failed to daemonize SSH agent: {e}");
                std::process::exit(1);
            }

            // daemonized process begins here are, process is detached.
            // modify the logger to log to a file instead.
            if let Some(reload_log) = reload_log {
                let _ = reload_log
                    .modify(|layer| {
                        layer.set_ansi(false);
                        *layer.writer_mut() = || -> Box<dyn io::Write> {
                            //  ~/Library/Logs/Axo Pass/agent.log
                            let log_appender = RollingFileAppender::builder()
                                .max_log_files(7)
                                .rotation(Rotation::DAILY)
                                .filename_prefix("agent.log")
                                .build(log_data_dir())
                                .unwrap();
                            Box::new(log_appender)
                        };
                    })
                    .inspect_err(|e| {
                        log::warn!("Failed to modify log destination: {e}");
                    });
            }
            log::info!("SSH agent daemonized successfully.");
        }

        // Initialize tokio runtime
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                self.execute_async().await;
            });
    }

    async fn execute_async(&self) {
        match self {
            AxoPassCommand::Keychain(keychain) => keychain.execute().await,
            AxoPassCommand::Vault(vault) => vault.execute().await,
            AxoPassCommand::Item(item) => item.execute().await,
            AxoPassCommand::Read { item_reference } => {
                ItemCommand::cmd_read(item_reference, None).unwrap();
            },
            AxoPassCommand::Inject(inject) => inject.execute().await,
            AxoPassCommand::Age(age) => age.execute().await,
            AxoPassCommand::Info => {
                println!("ap {}", env!("CARGO_PKG_VERSION"));
                println!("Built at: {}", build_sha::BUILT_AT.unwrap_or("not set"));
                println!("Build: {}", build_sha::BUILD_SHA.unwrap_or("not set"));
                println!("Vault dir: {}", vaults_dir().display());
            },
            AxoPassCommand::SshAgent(ssh_agent) => ssh_agent.run().await,
            AxoPassCommand::Shellenv { shell } => {
                // add the following to ~/.zshrc:
                // source <(ap shellenv zsh)

                // add completions
                let mut cmd = AxoPassCli::command();
                generate(*shell, &mut cmd, "ap", &mut io::stdout());

                // add ssh agent environment setup (only zsh supported)
                // todo: add config flag
                if matches!(shell, Shell::Zsh) {
                    println!("{}", include_str!("commands/ssh_agent/ssh_agent.zsh"));
                }
            },
        }
    }
}
