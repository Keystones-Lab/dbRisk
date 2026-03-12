//! SchemaRisk v2 — library crate.
//!
//! Re-exports every public module so that integration tests and downstream
//! tools can depend on `schema-risk` as a library.

pub mod ci;
pub mod db;
pub mod drift;
pub mod engine;
pub mod error;
pub mod graph;
pub mod impact;
pub mod loader;
pub mod locks;
pub mod output;
pub mod parser;
pub mod recommendation;
pub mod simulation {
    // Placeholder — reserved for future simulation module.
}
pub mod types;
