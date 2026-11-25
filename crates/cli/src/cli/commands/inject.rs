use std::io::{self, Write};
use std::path::PathBuf;

use axo_pass_core::core::app_broker::ResolvePurpose;
use axo_pass_core::core::interpolate::{escape_json, find_refs, interpolate_secrets_escaped};
use axo_pass_core::core::read_input::read_file_or_stdin;
use clap::{Parser, ValueEnum};

use super::secret_resolver::BrokerSecretResolver;

/// Escaping applied to injected secret values.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum EscapeFormat {
    /// Escape for the body of a JSON string. Surrounding quotes are not added.
    Json,
}

impl EscapeFormat {
    fn escape(self, value: &str) -> String {
        match self {
            EscapeFormat::Json => escape_json(value),
        }
    }
}

#[derive(Parser, Debug)]
pub struct InjectCommand {
    /// Input file path. If not provided, the input will be read from stdin.
    #[arg(long = "input", short = 'i')]
    pub input_file: Option<PathBuf>,

    /// Output file path. If not provided, the result will be printed to stdout.
    #[arg(long = "output", short = 'o')]
    pub output_file: Option<PathBuf>,

    /// Escape secret values for a target format. Values are inserted raw by
    /// default.
    #[arg(long = "escape", value_enum)]
    pub escape: Option<EscapeFormat>,

    /// Exit with an error and write no output if any reference is not found or
    /// fails to resolve.
    #[arg(long = "strict")]
    pub strict: bool,
}

impl InjectCommand {
    pub async fn execute(&self) {
        if let Err(message) = self.run() {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    }

    fn run(&self) -> Result<(), String> {
        let data = read_file_or_stdin(&self.input_file).map_err(|e| e.to_string())?;
        let input_data = String::from_utf8_lossy(&data).to_string();

        let mut resolver = BrokerSecretResolver::new(ResolvePurpose::Inject);
        resolver.prepare(&find_refs(&input_data))?;

        let escape = |value: &str| match self.escape {
            Some(format) => format.escape(value),
            None => value.to_string(),
        };
        let interpolation = interpolate_secrets_escaped(&input_data, &mut resolver, &escape)?;

        if self.strict && !interpolation.unresolved.is_empty() {
            return Err(format!(
                "could not resolve: {}",
                interpolation.unresolved.join(", ")
            ));
        }
        for url in &interpolation.unresolved {
            eprintln!("warning: could not resolve {url}");
        }

        if let Some(output_path) = &self.output_file {
            std::fs::write(output_path, interpolation.text)
                .map_err(|e| format!("Failed to write output file {}: {e}", output_path.display()))
        } else {
            let mut stdout = io::stdout();
            stdout
                .write_all(interpolation.text.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| format!("Failed to write to stdout: {e}"))
        }
    }
}
