//! `AxoPassBrowserHost`, the native messaging host for the browser extensions.
//! See `axo_pass_core::core::app_broker::browser_host`.

fn main() -> std::process::ExitCode {
    axo_pass_core::core::app_broker::browser_host::run()
}
