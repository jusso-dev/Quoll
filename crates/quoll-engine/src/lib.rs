//! Scan orchestration for Quoll.
//!
//! This is the crate that decides what a scan *means*: it walks the tree, indexes the
//! graph, schedules plugins, normalises their output, correlates hypotheses, optionally
//! investigates with a model, verifies locations and writes the report.
//!
//! ```no_run
//! use quoll_core::config::Config;
//! use quoll_engine::{run_scan, ScanOptions};
//!
//! # async fn demo() -> quoll_core::Result<()> {
//! let config = Config::discover(std::path::Path::new("."))?;
//! let outcome = run_scan(ScanOptions::from_config(&config)).await?;
//! println!("{}", outcome.report.summary());
//! # Ok(())
//! # }
//! ```

pub mod baseline;
pub mod classify;
pub mod correlate;
pub mod normalize;
pub mod scan;
pub mod store;
pub mod suppress;

pub use baseline::{apply_baseline, load_baseline, Baseline};
pub use classify::classify_raw;
pub use correlate::correlate;
pub use normalize::normalize;
pub use scan::{run_scan, ScanOptions, ScanOutcome, ScanPhase};
pub use store::{load_last_scan, save_last_scan, StoredScan};
pub use suppress::apply_suppressions;
