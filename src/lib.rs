//! holokeep: a content-addressed repository of blocks, kept by
//! structure across volumes; see the README. `hk` is its command line.

// A library for one binary and its tests, so far: its errors are its
// error types', and nothing's lost by ignoring a result it returns
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc, clippy::must_use_candidate)]

pub mod cid;
pub mod car;
pub mod claim;
pub mod grants;
pub mod keys;
pub mod account;
pub mod vault;
pub mod block;
pub mod chunker;
pub mod varint;
pub mod multihash;
pub mod pb;
pub mod unixfs;
pub mod dag;
pub mod hamt;
pub mod import;
pub mod links;
pub mod delta;
pub mod git;
pub mod export;
#[cfg(feature = "fuse")]
pub mod mount;
pub mod model;
pub mod store;
#[cfg(feature = "net")]
pub mod net;
#[cfg(test)]
mod codec_fixtures;
#[cfg(test)]
mod differential;
#[cfg(test)]
mod testutil;
// Generic IPLD/serde layer, not needed by the importer yet
//mod dagpb;
pub mod canon;
//mod ipld;
pub mod dagcbor;
pub mod dagjson;
pub mod serde;
