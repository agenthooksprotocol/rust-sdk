//! Agent Hooks Protocol models and structural codecs.

mod canonical;
pub mod generated;

pub mod interop;

pub mod lineage;

pub mod registration;

pub mod elicitation;

pub mod observation;

pub mod compaction;

/// Explicit opt-in runtime integrations and bounded stdio framing.
pub mod adapters;
/// Scoped immutable raw-byte upload binding.
pub mod content;
/// Validated protocol callbacks, shared by all server adapters.
pub mod server;
/// Runtime-neutral HTTP request and response interfaces.
pub mod transport;

/// Lazy typed protocol boundaries; application execution policy remains userland.
pub mod client;

// Semantic model modules are generated from the canonical schema, not curated aliases.
pub use generated::{capabilities, common, effect, event, mcp_elicitation, subscription};

/// Lazy complete-event boundaries for every canonical event family.
pub mod runtime;

/// Registration-driven harness with explicit capabilities and owned shutdown.
pub mod hooks;
pub use hooks::Hooks;
/// Owned async body inputs with bounded spooling.
pub mod body;
mod hooks_content;
