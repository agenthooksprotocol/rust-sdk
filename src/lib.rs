//! Agent Hooks Protocol models and structural codecs.

mod canonical;
// Canonical constructors expose each required schema field.
#[allow(clippy::too_many_arguments)]
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

// Models, codecs, and semantic aliases come from the canonical generated API.
// Explicit handwritten modules take precedence over glob-imported aliases.
pub use generated::*;
/// Canonical effect models and shared-metadata ergonomic constructors.
pub mod effect {
    pub use crate::generated::effect::*;
    pub use crate::generated::effects::*;
}

/// Lazy complete-event boundaries for every canonical event family.
pub mod runtime;

/// Registration-driven harness with explicit capabilities and owned shutdown.
pub mod hooks;
pub use hooks::Hooks;
/// Owned async body inputs with bounded spooling.
pub mod body;
mod hooks_content;
