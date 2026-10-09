//! Atem Memory — shared memory and skills across coding agents and machines.
//! See designs/atem-memory.md.
pub mod model;
pub mod secrets;
pub mod project;
pub mod block;
pub mod gitguard;
pub mod harvest;
pub mod skills_fs;
pub mod store;
pub mod adapters;
pub mod api;
pub mod sync;
pub mod cmd;
pub mod crypto;
pub mod encoding;
pub mod statements;
pub mod device_keys;
pub mod verification;
pub mod trust;
pub mod grant;
pub mod storage_key;
pub mod key_agent;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod kat_tests;
#[cfg(test)]
mod fake_astation;
