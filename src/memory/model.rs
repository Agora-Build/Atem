//! Canonical memory/skill types shared by the store, relay API, and adapters.
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    #[default]
    Global,
    Project,
    Machine,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Global => "global",
            Scope::Project => "project",
            Scope::Machine => "machine",
        }
    }

    pub fn parse(s: &str) -> Result<Scope> {
        match s.trim().to_ascii_lowercase().as_str() {
            "global" => Ok(Scope::Global),
            "project" => Ok(Scope::Project),
            "machine" => Ok(Scope::Machine),
            other => Err(anyhow!("unknown scope '{}': expected global, project, or machine", other)),
        }
    }
}

/// One memory. On the wire (and in queued ops) it round-trips through
/// `MemoryWire`, which still carries `deleted: bool` for older atems/relays.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(from = "MemoryWire", into = "MemoryWire")]
pub struct Memory {
    pub id: String,
    pub scope: Scope,
    pub project: String,
    pub machine: String,
    pub content: String,
    pub content_hash: String,
    pub confidence: String,
    pub source_agent: String,
    pub source_machine: String,
    pub created_at: i64,
    /// When it was deleted (a deletion also clears the text). `None` = not deleted.
    pub deleted_at: Option<i64>,
    /// When the fact became true. `None` = `created_at`.
    pub valid_at: Option<i64>,
    /// When it stopped being true. `None` = still valid. Final once set.
    pub invalid_at: Option<i64>,
    /// The memory that replaced it, if any.
    pub superseded_by: Option<String>,
    pub seq: i64,
}

impl Memory {
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Not deleted and not invalidated: the facts that get injected.
    pub fn is_valid(&self) -> bool {
        self.deleted_at.is_none() && self.invalid_at.is_none()
    }

    /// When the fact became true.
    pub fn valid_from(&self) -> i64 {
        self.valid_at.unwrap_or(self.created_at)
    }
}

/// The wire/queue shape of `Memory`. Rows without the 1.1 fields (an older
/// relay, or ops queued by an older atem) parse with them unset; a legacy
/// `deleted: true` without `deleted_at` counts as deleted now.
#[derive(Serialize, Deserialize)]
struct MemoryWire {
    id: String,
    scope: Scope,
    #[serde(default)]
    project: String,
    #[serde(default)]
    machine: String,
    content: String,
    content_hash: String,
    confidence: String,
    source_agent: String,
    source_machine: String,
    created_at: i64,
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    deleted_at: Option<i64>,
    #[serde(default)]
    valid_at: Option<i64>,
    #[serde(default)]
    invalid_at: Option<i64>,
    #[serde(default)]
    superseded_by: Option<String>,
    #[serde(default)]
    seq: i64,
}

impl From<MemoryWire> for Memory {
    fn from(w: MemoryWire) -> Memory {
        Memory {
            deleted_at: w.deleted_at.or_else(|| w.deleted.then(now_secs)),
            id: w.id, scope: w.scope, project: w.project, machine: w.machine,
            content: w.content, content_hash: w.content_hash, confidence: w.confidence,
            source_agent: w.source_agent, source_machine: w.source_machine, created_at: w.created_at,
            valid_at: w.valid_at, invalid_at: w.invalid_at, superseded_by: w.superseded_by, seq: w.seq,
        }
    }
}

impl From<Memory> for MemoryWire {
    fn from(m: Memory) -> MemoryWire {
        MemoryWire {
            deleted: m.deleted_at.is_some(),
            id: m.id, scope: m.scope, project: m.project, machine: m.machine,
            content: m.content, content_hash: m.content_hash, confidence: m.confidence,
            source_agent: m.source_agent, source_machine: m.source_machine, created_at: m.created_at,
            deleted_at: m.deleted_at, valid_at: m.valid_at, invalid_at: m.invalid_at,
            superseded_by: m.superseded_by, seq: m.seq,
        }
    }
}

/// One skill version. `files` maps a relative path to raw bytes and is
/// serialized as `{path: base64}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Skill {
    pub scope: Scope,
    #[serde(default)]
    pub project: String,
    pub name: String,
    pub version: i64,
    #[serde(with = "b64map")]
    pub files: BTreeMap<String, Vec<u8>>,
    pub content_hash: String,
    pub source_agent: String,
    pub source_machine: String,
    pub created_at: i64,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub seq: i64,
}

/// Trim, collapse runs of whitespace, lowercase. Used only for hashing.
pub fn normalize_content(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// sha256 (hex) of the normalized content — the dedup key.
pub fn content_hash(s: &str) -> String {
    format!("{:x}", Sha256::digest(normalize_content(s).as_bytes()))
}

/// sha256 (hex) over sorted (path, length, bytes).
pub fn skill_hash(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut h = Sha256::new();
    for (path, bytes) in files {
        h.update(path.as_bytes());
        h.update([0u8]);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    format!("{:x}", h.finalize())
}

pub fn new_memory_id() -> String {
    format!("mem_{}", uuid::Uuid::new_v4().simple())
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The short id shown in the Codex block: the first 8 characters after `mem_`.
pub fn short_id(id: &str) -> &str {
    let rest = id.strip_prefix("mem_").unwrap_or(id);
    match rest.char_indices().nth(8) {
        Some((i, _)) => &rest[..i],
        None => rest,
    }
}

/// Characters of the id's end shown after the short id in listings.
pub const ID_TAIL_LEN: usize = 4;

/// The id as listings show it: the short id, `…`, and the last
/// `ID_TAIL_LEN` characters (`8245ecf6…e6fe`). Ids too short to abbreviate
/// are shown whole, without `mem_`. Commands that take an id accept this form.
pub fn display_id(id: &str) -> String {
    let rest = id.strip_prefix("mem_").unwrap_or(id);
    let n = rest.chars().count();
    let head = short_id(id);
    if n <= head.chars().count() + ID_TAIL_LEN + 1 {
        return rest.to_string();
    }
    let tail: String = rest.chars().skip(n - ID_TAIL_LEN).collect();
    format!("{}…{}", head, tail)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of `days_from_civil`: (year, month, day).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// The one date parser for `--valid-at` / `--at`: `YYYY-MM-DD` (midnight
/// UTC) or unix seconds. The result must be after the epoch.
pub fn parse_date(s: &str) -> Result<i64> {
    let t = s.trim();
    let bad = || anyhow!("invalid date {:?}: use YYYY-MM-DD (UTC) or unix seconds", s);
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
    let secs = if digits(t) {
        t.parse::<i64>().map_err(|_| bad())?
    } else {
        let parts: Vec<&str> = t.split('-').collect();
        if parts.len() != 3 {
            return Err(bad());
        }
        let (y, m, d) = (parts[0], parts[1], parts[2]);
        if y.len() != 4 || m.len() != 2 || d.len() != 2 || !digits(y) || !digits(m) || !digits(d) {
            return Err(bad());
        }
        let (y, m, d): (i64, i64, i64) = (y.parse()?, m.parse()?, d.parse()?);
        if !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m) {
            return Err(bad());
        }
        days_from_civil(y, m, d) * 86_400
    };
    if secs <= 0 {
        return Err(bad());
    }
    Ok(secs)
}

/// `YYYY-MM-DD` (UTC).
pub fn format_date(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// `YYYY-MM-DD HH:MM` (UTC).
pub fn format_datetime(secs: i64) -> String {
    let s = secs.rem_euclid(86_400);
    format!("{} {:02}:{:02}", format_date(secs), s / 3600, (s % 3600) / 60)
}

/// Sort key: high (0) before medium (1) before anything else (2).
pub fn confidence_rank(c: &str) -> u8 {
    match c {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}

pub fn parse_confidence(s: &str) -> Result<String> {
    let c = s.trim().to_ascii_lowercase();
    match c.as_str() {
        "high" | "medium" | "low" => Ok(c),
        _ => Err(anyhow!("confidence must be high, medium, or low")),
    }
}

/// serde helper: `BTreeMap<String, Vec<u8>>` ⇄ `{path: base64}`.
pub mod b64map {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S: Serializer>(m: &BTreeMap<String, Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let enc: BTreeMap<&String, String> = m.iter().map(|(k, v)| (k, STANDARD.encode(v))).collect();
        enc.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<String, Vec<u8>>, D::Error> {
        let enc = BTreeMap::<String, String>::deserialize(d)?;
        enc.into_iter()
            .map(|(k, v)| STANDARD.decode(v).map(|b| (k, b)).map_err(D::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_is_eight_chars_after_prefix() {
        assert_eq!(short_id("mem_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"), "1a2b3c4d");
        assert_eq!(short_id("mem_abc"), "abc");
        assert_eq!(short_id("xyz123456789"), "xyz12345");
    }

    #[test]
    fn display_id_shows_the_short_id_and_the_end() {
        assert_eq!(display_id("mem_8245ecf61c944756afcca86b8c16e6fe"), "8245ecf6…e6fe");
        assert_eq!(display_id("mem_1a2b3c4d5e6f7"), "1a2b3c4d5e6f7");
        assert_eq!(display_id("mem_abc"), "abc");
    }

    #[test]
    fn dates_parse_as_utc_midnight_or_unix_seconds() {
        assert_eq!(parse_date("2026-09-30").unwrap(), 1_790_726_400);
        assert_eq!(parse_date("2024-02-29").unwrap(), 1_709_164_800);
        assert_eq!(parse_date("2000-03-01").unwrap(), 951_868_800);
        assert_eq!(parse_date(" 1790000000 ").unwrap(), 1_790_000_000);
        for bad in ["", "2026-13-01", "2026-02-30", "2025-02-29", "26-09-30", "2026/09/30", "1970-01-01", "0", "-5", "soon"] {
            assert!(parse_date(bad).is_err(), "{bad:?}");
        }
        assert_eq!(format_date(1_790_726_400), "2026-09-30");
        assert_eq!(format_datetime(1_791_036_600), "2026-10-03 14:10");
        for s in ["2026-10-02", "2024-02-29", "2000-03-01", "1999-12-31"] {
            assert_eq!(format_date(parse_date(s).unwrap()), s);
        }
    }

    #[test]
    fn memory_wire_keeps_deleted_flag_and_new_fields() {
        let m = Memory {
            id: "mem_1".into(), content: "x".into(), created_at: 5, deleted_at: Some(9),
            valid_at: Some(3), invalid_at: Some(8), superseded_by: Some("mem_2".into()), seq: 4,
            ..Default::default()
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["deleted"], true);
        assert_eq!((v["deleted_at"].clone(), v["valid_at"].clone(), v["invalid_at"].clone()), (serde_json::json!(9), serde_json::json!(3), serde_json::json!(8)));
        assert_eq!(v["superseded_by"], "mem_2");
        assert_eq!(v["scope"], "global");
        let back: Memory = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn legacy_memory_json_still_parses() {
        let row = |deleted: bool| serde_json::json!({
            "id": "mem_1", "scope": "project", "project": "p", "content": "x", "content_hash": "h",
            "confidence": "high", "source_agent": "cli", "source_machine": "m", "created_at": 5,
            "deleted": deleted, "seq": 2,
        });
        let m: Memory = serde_json::from_value(row(false)).unwrap();
        assert!(m.is_valid() && !m.is_deleted() && m.valid_at.is_none() && m.superseded_by.is_none());
        assert_eq!(m.valid_from(), 5);
        let gone: Memory = serde_json::from_value(row(true)).unwrap();
        assert!(gone.is_deleted() && !gone.is_valid());
        let mut invalid = m.clone();
        invalid.invalid_at = Some(6);
        assert!(!invalid.is_valid() && !invalid.is_deleted());
    }

    #[test]
    fn normalize_collapses_whitespace_and_case() {
        assert_eq!(normalize_content("  DialF  uses\n TCP\t8765 "), "dialf uses tcp 8765");
    }

    #[test]
    fn hash_ignores_case_and_spacing() {
        assert_eq!(content_hash("DialF uses TCP 8765"), content_hash("dialf  uses tcp 8765\n"));
        assert_ne!(content_hash("a"), content_hash("b"));
        assert_eq!(content_hash("x").len(), 64);
    }

    #[test]
    fn scope_parse_and_str() {
        assert_eq!(Scope::parse("Project").unwrap(), Scope::Project);
        assert!(Scope::parse("team").is_err());
        assert_eq!(Scope::Machine.as_str(), "machine");
    }

    #[test]
    fn memory_id_shape() {
        let id = new_memory_id();
        assert!(id.starts_with("mem_"));
        assert_eq!(id.len(), 36);
        assert_ne!(id, new_memory_id());
    }

    #[test]
    fn skill_hash_depends_on_paths_and_bytes() {
        let mut a = BTreeMap::new();
        a.insert("SKILL.md".to_string(), b"hi".to_vec());
        let mut b = a.clone();
        b.insert("x.sh".to_string(), b"".to_vec());
        let mut c = BTreeMap::new();
        c.insert("SKILL.md".to_string(), b"hj".to_vec());
        assert_ne!(skill_hash(&a), skill_hash(&b));
        assert_ne!(skill_hash(&a), skill_hash(&c));
        assert_eq!(skill_hash(&a), skill_hash(&a.clone()));
    }

    #[test]
    fn skill_files_serialize_as_base64() {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"hello".to_vec());
        let s = Skill {
            scope: Scope::Global, project: String::new(), name: "demo".into(), version: 1,
            content_hash: skill_hash(&files), files,
            source_agent: "cli".into(), source_machine: "m".into(),
            created_at: 1, deleted: false, seq: 0,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["files"]["SKILL.md"], "aGVsbG8=");
        assert_eq!(v["scope"], "global");
        let back: Skill = serde_json::from_value(v).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn confidence_parse_and_rank() {
        assert_eq!(parse_confidence("HIGH").unwrap(), "high");
        assert!(parse_confidence("sure").is_err());
        assert!(confidence_rank("high") < confidence_rank("medium"));
        assert!(confidence_rank("medium") < confidence_rank("low"));
    }
}
