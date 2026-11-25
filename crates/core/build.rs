//! Build id of the crate: `{version}+{commit}`, with `-dirty` if a tracked
//! file differs from the commit, or `{version}+unknown` outside a git tree.
//! Sync compares it with `stopped_build` and `override_build`.
//!
//! Also defines the platform cfg aliases `macos`, `ios`, `linux`, `apple`,
//! `sim_keys`, and `secure_enclave`.

use std::path::Path;
use std::process::Command;

use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        macos: { target_os = "macos" },
        ios: { target_os = "ios" },
        linux: { target_os = "linux" },
        apple: { target_vendor = "apple" },
        // Simulator builds that keep device keys in software, since the
        // simulator has no Secure Enclave. Release builds never have them.
        sim_keys: { all(ios, target_abi = "sim", debug_assertions) },
        secure_enclave: { all(apple, not(sim_keys)) },
    }

    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let commit = git(&["rev-parse", "HEAD"]);
    let (build, sha) = match &commit {
        Some(commit) => {
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                .is_none_or(|status| !status.is_empty());
            let suffix = if dirty { "-dirty" } else { "" };
            (
                format!("{version}+{commit}{suffix}"),
                Some(format!("{commit}{suffix}")),
            )
        },
        None => (format!("{version}+unknown"), None),
    };
    println!("cargo:rustc-env=AXO_BUILD_ID={build}");

    // Values shown by `ap info`. An existing environment value takes
    // precedence, so CI can set them.
    if std::env::var_os("APP_BUILD_SHA").is_none()
        && let Some(sha) = sha
    {
        println!("cargo:rustc-env=APP_BUILD_SHA={sha}");
    }
    if std::env::var_os("APP_BUILT_AT").is_none()
        && let Some(now) = utc_now()
    {
        println!("cargo:rustc-env=APP_BUILT_AT={now}");
    }
    println!("cargo:rerun-if-env-changed=APP_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=APP_BUILT_AT");

    // Run again if the sources, the commit, or the index change.
    println!("cargo:rerun-if-changed=src");
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        let git_dir = Path::new(&git_dir);
        for path in ["HEAD", "index", "refs", "packed-refs"] {
            println!("cargo:rerun-if-changed={}", git_dir.join(path).display());
        }
    }
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`, or `None` if `date` fails.
fn utc_now() -> Option<String> {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}

/// Trimmed output of `git` with `args`, or `None` if it fails to run or
/// exits with an error.
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}
