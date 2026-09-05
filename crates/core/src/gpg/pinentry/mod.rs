//! The pinentry gpg-agent talks to.
//!
//! gpg-agent runs `pinentry-program` whenever it needs a passphrase and speaks
//! assuan to it over stdin/stdout. [`server`] implements that protocol and
//! [`handler`] answers it by asking the app, which owns both the keychain
//! entitlement and the biometric prompt.

mod handler;
mod server;

pub use handler::BrokerPinentryHandler;
pub use server::{PinentryServer, PinentryServerHandler};
