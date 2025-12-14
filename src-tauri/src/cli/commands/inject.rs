use std::io::{self, Write};
use std::path::PathBuf;

use clap::Parser;
use regex::Regex;

use crate::core::read_input::read_file_or_stdin;
use crate::secrets::vaults::VaultsManager;

#[derive(Parser, Debug)]
pub struct InjectCommand {
    #[arg(long = "input", short = 'i')]
    pub input_file: Option<PathBuf>,

    #[arg(long = "output", short = 'o')]
    pub output_file: Option<PathBuf>,
}

impl InjectCommand {
    pub async fn execute(&self) {
        let input_data = match read_file_or_stdin(&self.input_file) {
            Ok(data) => String::from_utf8_lossy(&data).to_string(),
            Err(e) => {
                log::error!("{e}");
                return;
            },
        };

        let output_data = interpolate_secrets(&input_data);
        if let Some(output_path) = &self.output_file {
            if let Err(e) = std::fs::write(output_path, output_data) {
                log::error!("Failed to write output file {}: {e}", output_path.display());
            }
        } else {
            match io::stdout().write_all(output_data.as_bytes()) {
                Ok(_) => {
                    let _ = io::stdout().flush();
                },
                Err(e) => {
                    log::error!("Failed to write to stdout: {}", e);
                },
            }
        }
    }
}

fn interpolate_secrets(input: &str) -> String {
    let axo_url_re =
        Regex::new(r"\baxo://(?P<vault>[a-zA-Z0-9-_]+)/(?P<item>[a-zA-Z0-9-_]+)/(?P<credential>[a-zA-Z0-9-_]+\b)").unwrap();
    let mut vaults = VaultsManager::new();
    let result = axo_url_re.replace_all(input, |caps: &regex::Captures| {
        let item_url = &caps[0];
        log::debug!("Found reference {item_url}");
        match vaults.get_secret_by_url(item_url) {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                log::warn!("Secret not found for reference: {}", item_url);
                "NOT_FOUND".to_string()
            },
            Err(e) => {
                log::error!("Error fetching secret for reference {}: {:?}", item_url, e);
                "ERROR".to_string()
            },
        }
    });
    result.to_string()
}
