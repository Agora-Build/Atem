//! Addressing only: labels and selectors never grant permission to execute work.
use std::{collections::BTreeSet, str::FromStr};

use super::wire::is_opaque_id;

pub const MAX_SELECTORS: usize = 16;
pub const MAX_AGENTS: u32 = 32;
pub const NAME_PROBLEM: &str = "names are 1-32 of a-z, 0-9 and -";
pub const MAX_ATEM_ID_CHARS: usize = 64;

/// An instance's `atem_id`: 1-64 characters, no whitespace or control
/// characters, and none of the selector's own `:`, `/` and `+`. Relay
/// identities keep non-ASCII letters (CJK host names), so this is not the
/// ASCII-only opaque id; it accepts every id the relay identity builds.
pub fn is_atem_id(id: &str) -> bool {
    (1..=MAX_ATEM_ID_CHARS).contains(&id.chars().count())
        && !id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, ':' | '/' | '+'))
}

/// Each variant retains the canonical, prefixed label for lossless display.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Label {
    Project(String),
    Tag(String),
    SelfTag(String),
}

impl Label {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Project(s) | Self::Tag(s) | Self::SelfTag(s) => s,
        }
    }
    pub fn owner(&self) -> bool {
        !matches!(self, Self::SelfTag(_))
    }
}

impl FromStr for Label {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kind, name) = value
            .split_once(':')
            .ok_or("labels are project:, tag: or self:")?;
        if name.is_empty()
            || name.len() > 32
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(NAME_PROBLEM);
        }
        match kind {
            "project" => Ok(Self::Project(value.into())),
            "tag" => Ok(Self::Tag(value.into())),
            "self" => Ok(Self::SelfTag(value.into())),
            _ => Err("labels are project:, tag: or self:"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    All(Vec<Label>),
    Instance {
        atem_id: String,
        route_id: Option<String>,
    },
}

pub struct AgentLabels<'a> {
    pub atem_id: &'a str,
    pub route_id: &'a str,
    pub labels: &'a BTreeSet<Label>,
}

impl FromStr for Selector {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(instance) = value.strip_prefix("atem:") {
            let (atem_id, route_id) = match instance.split_once('/') {
                Some((id, route)) => (id, Some(route)),
                None => (instance, None),
            };
            if !is_atem_id(atem_id) {
                return Err(
                    "atem ids are 1-64 characters without spaces, controls, `:`, `/` or `+`",
                );
            }
            if route_id.is_some_and(|r| !is_opaque_id(r)) {
                return Err(
                    "route ids are letters, digits, `.`, `_`, `:` and `-` (at most 128 bytes)",
                );
            }
            Ok(Self::Instance {
                atem_id: atem_id.into(),
                route_id: route_id.map(str::to_owned),
            })
        } else {
            let terms: Vec<_> = value.split('+').collect();
            if terms.len() > MAX_SELECTORS {
                return Err("at most 16 labels per selector");
            }
            Ok(Self::All(
                terms
                    .into_iter()
                    .map(str::parse)
                    .collect::<Result<_, _>>()?,
            ))
        }
    }
}

impl Selector {
    pub fn matches(&self, agent: &AgentLabels<'_>) -> bool {
        match self {
            Self::All(labels) => {
                !labels.is_empty() && labels.iter().all(|l| agent.labels.contains(l))
            }
            Self::Instance { atem_id, route_id } => {
                atem_id == agent.atem_id && route_id.as_ref().is_none_or(|r| r == agent.route_id)
            }
        }
    }
}

/// Why a `to` list and budget are not acceptable, naming the first bad
/// selector by its 1-based position.
pub fn selectors_problem(selectors: &[String], budget: u32) -> Option<String> {
    if !(1..=MAX_SELECTORS).contains(&selectors.len()) {
        return Some(format!("a message needs 1 to {MAX_SELECTORS} selectors"));
    }
    if !(1..=MAX_AGENTS).contains(&budget) {
        return Some(format!("the budget is 1 to {MAX_AGENTS} agents"));
    }
    selectors.iter().enumerate().find_map(|(index, selector)| {
        selector
            .parse::<Selector>()
            .err()
            .map(|reason| format!("selector {}: {reason}", index + 1))
    })
}

pub fn valid_selectors(selectors: &[String], budget: u32) -> bool {
    selectors_problem(selectors, budget).is_none()
}
