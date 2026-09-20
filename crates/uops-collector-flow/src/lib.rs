//! The flow collector — M7, specified in `docs/M7-flow.md`.
//!
//! One UDP listener per tenant, four protocols on each, and rows into `ClickHouse`.
//! `uops-flow` does the decoding and has no I/O in it; this crate is the sockets, the
//! tenancy and the writing.
//!
//! The two decisions worth knowing before reading further are in [`config`]: a datagram's
//! tenant comes from the socket it arrived on and never from its contents, and an
//! exporter nobody has registered is resolved rather than refused.

pub mod config;
pub mod run;
pub mod shutdown;

pub use config::Config;
pub use run::{Stats, run};
