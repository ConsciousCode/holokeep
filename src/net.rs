//! The private mesh: the nodes of a repository, linked by libp2p. See the
//! README's replication and transport; this is its private tier.

// A node runs on one thread, with the catalog's database, which isn't
// `Send`; so are the futures which use them
#![allow(clippy::future_not_send)]

pub mod blocks;
pub mod mesh;
pub mod node;
pub mod daemon;
