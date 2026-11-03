//! Build id of the crate: `{version}+{commit}`, with `-dirty` if a tracked
//! file differs from the commit, or `{version}+unknown` outside a git tree.
//! Sync compares it with `stopped_build` and `override_build`.

use std::path::Path;
use std::process::Command;

fn main() {
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let commit = git(&["rev-parse", "HEAD"]);
    let build = match &commit {
        Some(commit) => {
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                .is_none_or(|status| !status.is_empty());
            let suffix = if dirty { "-dirty" } else { "" };
            format!("{version}+{commit}{suffix}")
        },
        None => format!("{version}+unknown"),
    };
    println!("cargo:rustc-env=AXO_BUILD_ID={build}");

    // Run again if the sources, the commit, or the index change.
    println!("cargo:rerun-if-changed=src");
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        let git_dir = Path::new(&git_dir);
        for path in ["HEAD", "index", "refs", "packed-refs"] {
            println!("cargo:rerun-if-changed={}", git_dir.join(path).display());
        }
    }
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
