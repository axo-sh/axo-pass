use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{anyhow, bail};
use clap::Parser;
use glob::glob;
use itertools::Itertools;

use crate::core::interpolate::interpolate_secrets;
use crate::secrets::vaults::VaultsManager;

#[derive(Parser, Debug)]
pub struct ExecCommand {
    /// dotenv-style file(s) to load with interpolation.
    /// Glob patterns are supported and matches are loaded in sorted order.
    /// Repeat the flag for multiple paths/patterns.
    #[arg(long = "env-file", short = 'e')]
    pub env_files: Vec<String>,

    /// Command to execute with interpolated environment.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub command: Vec<String>,
}

impl ExecCommand {
    // ways to test this:
    // FOO='axo://...' ap exec -- printenv FOO
    // FOO='axo://...' ap exec -- sh -c 'echo $FOO'
    // ap exec --env-file /tmp/test.env -- printenv FOO
    pub async fn execute(&self) -> ! {
        let env = self.try_prepare_env().await.unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });

        let (program, args) = self.command.split_first().unwrap();
        let mut command = Command::new(program);
        command.args(args);

        // clear env and use the prepared env (which includes the existing env with
        // interpolated values from env files)
        command.env_clear().envs(&env);

        // exec the command, replacing this process.
        let err = command.exec();

        // only reachable if exec fails
        eprintln!("error: failed to execute '{program}': {err}");
        std::process::exit(1);
    }

    pub async fn try_prepare_env(&self) -> Result<HashMap<String, String>, anyhow::Error> {
        let mut env_vars: HashMap<String, String> = std::env::vars().collect();
        for pattern in &self.env_files {
            let paths = glob(pattern).map_err(|e| anyhow!("invalid pattern '{pattern}': {e}"))?;
            // partition so we can check for all GlobErrors upfront and then sort the paths
            // before reading the files so the read order is deterministic.
            let (mut paths, errors): (Vec<_>, Vec<_>) = paths.partition_result();
            if !errors.is_empty() {
                let err_list = errors.into_iter().map(|e| e.to_string()).join("\n");
                bail!("failed to execute pattern '{pattern}', got {err_list}");
            }

            paths.sort();
            for path in &paths {
                let display_path = path.display();
                let env_iter = dotenvy::from_path_iter(path)
                    .map_err(|e| anyhow!("failed to read env file {display_path}: {e}"))?;
                let vars = env_iter
                    .collect::<Result<Vec<(String, String)>, _>>()
                    .map_err(|e| anyhow!("failed to read env file {display_path}: {e}"))?;
                env_vars.extend(vars);
            }
        }

        // Interpolate axo:// references in every environment value
        let mut vaults = VaultsManager::new();
        let interpolated_env: HashMap<String, String> = env_vars
            .into_iter()
            .map(|(k, v)| (k, interpolate_secrets(&v, &mut vaults)))
            .collect();

        Ok(interpolated_env)
    }
}
