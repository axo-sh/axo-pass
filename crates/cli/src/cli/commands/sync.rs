use std::env;

use axo_pass_core::secrets::vaults::sync::transport::s3::credentials::default_credential_store;
use axo_pass_core::secrets::vaults::sync::transport::s3::{S3Config, test_connection};
use clap::{Args, Parser, Subcommand};
use clml::cprintln;
use inquire::Password;
use secrecy::SecretString;

/// Environment variable that holds the secret access key. If it is not set,
/// the command prompts for the key.
const SECRET_ENV: &str = "AP_S3_SECRET_ACCESS_KEY";

#[derive(Parser, Debug)]
#[command(flatten_help = true, help_template = "{usage-heading} {usage}")]
pub struct SyncCommand {
    #[command(subcommand)]
    subcommand: SyncSubcommand,
}

#[derive(Subcommand, Debug)]
enum SyncSubcommand {
    /// Test an S3-compatible bucket and save it as a sync location
    AddS3(AddS3Command),
}

#[derive(Args, Debug)]
struct AddS3Command {
    /// Endpoint URL, such as https://s3.us-east-1.amazonaws.com. Plain HTTP
    /// is accepted only for localhost.
    #[arg(long)]
    endpoint: String,

    #[arg(long)]
    region: String,

    #[arg(long)]
    bucket: String,

    /// Key prefix for every object. Default: the root of the bucket.
    #[arg(long, default_value = "")]
    prefix: String,

    #[arg(long)]
    access_key_id: String,

    /// Name to save the location under
    #[arg(long, default_value = "default")]
    name: String,

    /// Run the connection test and do not save the location
    #[arg(long)]
    test_only: bool,
}

impl SyncCommand {
    pub async fn execute(&self) -> ! {
        let result = match &self.subcommand {
            SyncSubcommand::AddS3(add) => add.execute(),
        };
        if let Err(e) = result {
            cprintln!("<red>Error:</red> {e}");
            std::process::exit(1);
        }
        std::process::exit(0);
    }
}

impl AddS3Command {
    fn execute(&self) -> Result<(), String> {
        let config = S3Config::new(
            &self.access_key_id,
            Self::secret()?,
            &self.endpoint,
            &self.region,
            &self.bucket,
            &self.prefix,
        )
        .map_err(|e| e.to_string())?;

        let report = test_connection(&config).map_err(|e| e.to_string())?;
        cprintln!("<green>Connection test passed.</green>");
        if report.list_attempts > 1 {
            println!(
                "The listing showed the test object after {} reads.",
                report.list_attempts
            );
        }
        if self.test_only {
            return Ok(());
        }

        let Some(store) = default_credential_store() else {
            return Err(
                "This platform has no credential store yet. The location was not saved."
                    .to_string(),
            );
        };
        store.save(&self.name, &config).map_err(|e| e.to_string())?;
        println!("Saved S3 location {}.", self.name);
        Ok(())
    }

    /// Secret access key from the environment, or from a prompt that does
    /// not echo.
    fn secret() -> Result<SecretString, String> {
        if let Ok(secret) = env::var(SECRET_ENV) {
            return Ok(SecretString::from(secret));
        }
        Password::new("Secret access key:")
            .without_confirmation()
            .prompt()
            .map(SecretString::from)
            .map_err(|e| e.to_string())
    }
}
