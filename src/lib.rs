//! A parser for Tor docs.
//!
//! This crate implements parsing of Tor documents as specified in
//! [dir-spec](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/dir-spec.txt).
//! For now, this crate only parses consensus documents (`@type network-status-consensus-3`)
//! and full relay descriptors (`@type server-descriptor`).
//! Also, only a very limited subset of data is parsed.
//!
//! Please be aware that the API is currently _very_ unfinished and will likely
//! change soon in an incompatible way.

pub mod consensus;
#[doc(inline)]
pub use consensus::Consensus;

pub mod descriptor;
#[doc(inline)]
pub use descriptor::Descriptor;

pub mod error;

mod meta;

// Solely for private use
mod seeded_rand;

// // other local modules
// mod error;
// pub use error::DocumentCombiningError;
// pub use error::DocumentParseError;

// mod meta;
// pub use meta::{Document, Fingerprint};

// pub mod consensus;
// use consensus::ConsensusDocument;

// pub mod descriptor;
// use descriptor::Descriptor;

// pub fn parse_consensus(text: &str) -> Result<ConsensusDocument, DocumentParseError> {
//     ConsensusDocument::from_str(text)
// }

// pub fn parse_descriptors(text: &str) -> Result<Vec<Descriptor>, DocumentParseError> {
//     let docs = Document::parse_many(text)?;
//     let descriptors = docs
//         .into_iter()
//         .map(Descriptor::from_doc)
//         .collect::<Result<_, _>>()?;
//     Ok(descriptors)
// }
