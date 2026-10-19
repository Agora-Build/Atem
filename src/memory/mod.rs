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
pub mod cred_agent;
pub mod account_keys;
pub mod project_names;
pub mod credential_projects;
pub mod unlock;
pub mod migration;
#[cfg(unix)]
pub mod agent_socket;

#[cfg(test)]
pub(crate) mod e2e_tests;
#[cfg(test)]
mod kat_tests;
#[cfg(test)]
pub(crate) mod fake_astation;
#[cfg(test)]
mod k_agent_tests;
