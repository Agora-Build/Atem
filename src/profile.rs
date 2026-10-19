//! This user's profile: where its files are (`paths.rs` is the layout) and
//! its settings, the `Sources` every command reads.
use anyhow::Result;
#[cfg(test)]
use std::path::Path;

use crate::config::AtemConfig;
use crate::paths::{CredPaths, ProfilePaths};

impl ProfilePaths {
    /// This user's profile.
    pub fn default_paths() -> Self {
        Self::in_dir(&AtemConfig::config_dir())
    }
}

impl CredPaths {
    /// This user's cred directory.
    pub fn default_paths() -> Self {
        Self::in_dir(&AtemConfig::config_dir())
    }
}

/// A profile: its settings and files, and which running processes may be
/// asked about it. `current()` is this user's profile;
/// `in_dir` a profile directory (tests).
#[derive(Debug, Clone)]
pub struct Sources {
    /// Connection settings (`pair` and `pair verify` connect with them).
    pub config: AtemConfig,
    /// Every file of the profile.
    pub paths: ProfilePaths,
    /// Ask an already running cred agent whether the keys are unlocked
    /// (never starts one). Off in tests, so they never reach the user's agent.
    pub query_agent: bool,
    /// Ask an already running `atem runtime` here for its link and sessions
    /// (never starts one). `None` in tests unless they set it.
    pub runtime: Option<crate::runtime::client::Locator>,
}

impl Sources {
    /// This user's profile: `config.toml` with its env overrides and the
    /// profile's files.
    pub fn current() -> Result<Self> {
        Ok(Self {
            config: AtemConfig::load()?,
            paths: ProfilePaths::default_paths(),
            query_agent: true,
            runtime: Some(crate::runtime::client::Locator::default_paths()),
        })
    }

    /// A profile directory: its `config.toml` (no env overrides), and every
    /// file in it. Never queries a cred agent.
    #[cfg(test)]
    pub fn in_dir(dir: &Path) -> Self {
        let paths = ProfilePaths::in_dir(dir);
        let config = std::fs::read_to_string(&paths.config)
            .ok()
            .and_then(|content| toml::from_str(&content).ok())
            .unwrap_or_default();
        Self {
            config,
            paths,
            query_agent: false,
            runtime: None,
        }
    }
}
