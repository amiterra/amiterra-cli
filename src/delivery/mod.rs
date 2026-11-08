//! Catalog-to-cluster delivery: signed intents, verify-don't-trust apply,
//! local door (`ami topology` / `ami apply`) and the agent write path
//! (Design Doc 0026, ADR 0014, Design 0020/0021).
//!
//! The single write path into the fleet repository is the agent: every change
//! arrives as a signed `TopologyChange` intent, is re-compiled locally and
//! committed only when the recomputed `tree_hash` matches the reviewed one.
//! The SaaS/API door and the local door produce the **same bundle** — one code
//! base (`amispec-core`) serves both.

pub mod agent;
pub mod channel;
pub mod cli;
pub mod drift;
pub mod intent;
