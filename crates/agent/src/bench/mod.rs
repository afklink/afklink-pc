//! The bench device: what replaces capture and input, where its identity lives, and what it says on
//! stdout for the harness. The flags that start it: `crate::cli::help_text`.
//!
//! Everything here is CLI-only: the desktop app links none of it.

pub mod corpus_capture;
pub mod data_dir;
pub mod noop_input;
pub mod stdout;
