//! Optional framework bindings and bounded line framing.
#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "reqwest")]
pub mod reqwest;
pub mod stdio;

pub mod http_hook;
#[cfg(feature = "tokio-process")]
pub mod process;

/// Lazy owned registration transports.
pub mod registered;
