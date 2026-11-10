use anyhow::{Context, anyhow};
use axo_pass_core::core::app_broker::browser_manifest::{
    BrowserManifests, ManifestState, ManifestStatus,
};
use axo_pass_core::core::app_broker::browsers::Browser;
use clap::{Parser, Subcommand};
use clml::cprintln;

/// Native messaging manifests for the browser extension. Both subcommands use
/// the `AxoPassBrowserHost` beside this `ap`, so a development `ap` points the
/// browsers at the development host. The app rewrites the manifests to its own
/// host on its next launch.
#[derive(Parser, Debug)]
pub struct BrowserCommand {
    #[command(subcommand)]
    pub command: BrowserSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum BrowserSubcommand {
    /// Show the native messaging manifest state for each browser
    Status,

    /// Write native messaging manifests naming the host beside this `ap`
    Install {
        /// Browsers to install for (chrome, firefox). Defaults to every
        /// installed browser.
        #[arg(value_parser = parse_browser)]
        browsers: Vec<Browser>,
    },
}

fn parse_browser(id: &str) -> Result<Browser, String> {
    Browser::from_id(id).ok_or_else(|| {
        let ids: Vec<_> = Browser::ALL.iter().map(|b| b.id()).collect();
        format!(
            "Unknown browser {id:?}. Expected one of: {}",
            ids.join(", ")
        )
    })
}

impl BrowserCommand {
    pub async fn execute(&self) {
        if let Err(e) = self.run() {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }

    fn run(&self) -> anyhow::Result<()> {
        let manifests = BrowserManifests::for_current_user()
            .context("Could not resolve the home directory or the ap executable")?;
        cprintln!("<dim>Host: {}</dim>", manifests.host().display());
        match &self.command {
            BrowserSubcommand::Status => {
                for status in manifests.statuses() {
                    print_status(&status);
                }
                Ok(())
            },
            BrowserSubcommand::Install { browsers } => {
                let browsers: Vec<Browser> = if browsers.is_empty() {
                    let installed: Vec<_> = manifests
                        .statuses()
                        .into_iter()
                        .filter(|s| s.browser_installed)
                        .map(|s| s.browser)
                        .collect();
                    if installed.is_empty() {
                        return Err(anyhow!("No supported browser is installed"));
                    }
                    installed
                } else {
                    browsers.clone()
                };
                let mut failed = false;
                for browser in browsers {
                    match manifests.install(browser) {
                        Ok(status) => print_status(&status),
                        Err(e) => {
                            failed = true;
                            cprintln!("<red>{}</red>: {e}", browser.name());
                        },
                    }
                }
                if failed {
                    return Err(anyhow!("Some manifests were not installed"));
                }
                Ok(())
            },
        }
    }
}

fn print_status(status: &ManifestStatus) {
    let name = status.browser.name();
    let path = status.manifest_path.display();
    if !status.browser_installed && status.state == ManifestState::NotInstalled {
        cprintln!("{name}: <dim>browser not installed</dim>");
        return;
    }
    match &status.state {
        ManifestState::NotInstalled => cprintln!("{name}: <yellow>manifest not installed</yellow>"),
        ManifestState::Current => cprintln!("{name}: <green>current</green>"),
        ManifestState::PointsElsewhere { path: Some(other) } => {
            cprintln!(
                "{name}: <yellow>points elsewhere</yellow> ({})",
                other.display()
            )
        },
        ManifestState::PointsElsewhere { path: None } => {
            cprintln!("{name}: <yellow>names no host</yellow>")
        },
        ManifestState::Outdated => cprintln!("{name}: <yellow>outdated</yellow>"),
        ManifestState::Foreign { name: other } => {
            cprintln!("{name}: <red>names another host</red> ({other})")
        },
        ManifestState::Unreadable { reason } => {
            cprintln!("{name}: <red>unreadable</red> ({reason})")
        },
    }
    cprintln!("  <dim>{path}</dim>");
}
