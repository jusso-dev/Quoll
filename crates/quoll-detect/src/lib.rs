//! What is this repository built on?
//!
//! Everything downstream depends on the answer. Policy packs bind to a framework, an auth
//! library and an ORM; scanner plugins decide relevance from languages and ecosystems; the
//! code graph needs to know which directory convention marks an HTTP entry point.
//!
//! Three signals feed a detection, in decreasing order of authority:
//!
//! 1. **Package manifests.** A runtime dependency is close to proof, and the only signal
//!    that carries a version.
//! 2. **File conventions.** Layout facts a manifest cannot express — most importantly which
//!    Next.js router is in use, which `package.json` never says.
//! 3. **Imports.** Corroboration, and a safety net for monorepos where the manifest that
//!    declares a package sits outside the scanned tree.
//!
//! Two independent signals for the same component raise confidence rather than producing
//! two detections, and every detection records why it fired. A detection with no stated
//! reason cannot be argued with, and `quoll doctor` exists so a user can see exactly why
//! Quoll believes what it believes.
//!
//! ```no_run
//! use quoll_detect::Detector;
//! use quoll_graph::Walker;
//!
//! let files = Walker::new(".").discover()?.files;
//! let detection = Detector::new(".").detect(&files)?;
//!
//! println!("{}", detection.summary());
//! if let Some(auth) = detection.auth() {
//!     println!("auth: {} ({})", auth.name, auth.evidence.join("; "));
//! }
//! # Ok::<(), quoll_core::Error>(())
//! ```

pub mod ci;
pub mod component;
pub mod detector;
pub mod manifest;
pub mod rules;

pub use ci::{CiDetection, CiProvider};
pub use component::{Component, Role};
pub use detector::{Detection, Detector};
pub use manifest::Manifest;
pub use rules::Rule;
