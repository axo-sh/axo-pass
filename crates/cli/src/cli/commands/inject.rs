use std::io::{self, Write};
use std::path::PathBuf;

use axo_pass_core::core::app_broker::ResolvePurpose;
use axo_pass_core::core::interpolate::{find_refs, interpolate_secrets};
use axo_pass_core::core::read_input::read_file_or_stdin;
use clap::Parser;

use super::secret_resolver::BrokerSecretResolver;

#[derive(Parser, Debug)]
pub struct InjectCommand {
    /// Input file path. If not provided, the input will be read from stdin.
    #[arg(long = "input", short = 'i')]
    pub input_file: Option<PathBuf>,

    /// Output file path. If not provided, the result will be printed to stdout.
    #[arg(long = "output", short = 'o')]
    pub output_file: Option<PathBuf>,
}

impl InjectCommand {
    pub async fn execute(&self) {
        let input_data = match read_file_or_stdin(&self.input_file) {
            Ok(data) => String::from_utf8_lossy(&data).to_string(),
            Err(e) => {
                eprintln!("error: {e}");
                return;
            },
        };

        let mut resolver = BrokerSecretResolver::new(ResolvePurpose::Inject);
        let output_data = match resolver
            .prepare(&find_refs(&input_data))
            .and_then(|()| interpolate_secrets(&input_data, &mut resolver))
        {
            Ok(data) => data,
            Err(e) => {
                eprintln!("error: {e}");
                return;
            },
        };
        if let Some(output_path) = &self.output_file {
            if let Err(e) = std::fs::write(output_path, output_data) {
                eprintln!(
                    "error: Failed to write output file {}: {e}",
                    output_path.display()
                );
            }
        } else {
            match io::stdout().write_all(output_data.as_bytes()) {
                Ok(_) => {
                    let _ = io::stdout().flush();
                },
                Err(e) => {
                    eprintln!("error:Failed to write to stdout: {}", e);
                },
            }
        }
    }
}
