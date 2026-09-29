# Atem Memory (atem-side) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `atem sync`, `atem memory …`, and `atem skill …` so coding
agents **learn memory and skills from each other**, **across agents**
(Claude ↔ Codex), and **across machines** (any network, via the relay), as
specified in [atem-memory.md](atem-memory.md).

**Architecture:** A new `src/memory/` module tree. Pure pieces are unit
tested offline: types, the secret detector, project keys, the managed-block
splice, Claude-memory harvesting, and skill directory I/O. A SQLite store
keeps each machine's copy plus a queue of pending changes. A thin `reqwest`
client talks to the relay's `/api/memory` and `/api/skills` endpoints, using
the SSO token from `atem login`. `sync.rs` runs harvest, push, pull, and
apply, and `cmd.rs` wires it to the CLI.

**Tech Stack:** Rust, clap (derive), rusqlite 0.32 (bundled), sha2, uuid,
base64 0.21, serde/serde_json, toml 0.8, reqwest 0.11, tokio, dirs, tempfile
(tests). **No new crates.**

**Spec:** [designs/atem-memory.md](atem-memory.md)

## Global Constraints

- **A credential value never leaves the machine.** Everything headed for the
  store passes `secrets::find_secrets` / `check_bytes`. Text that can't be
  checked counts as a finding.
- **Never write into a file tracked by git** unless `--allow-tracked` is
  passed. Anything atem creates in a repo is added to `.git/info/exclude`,
  never to `.gitignore`.
- **Never change text outside the managed markers**, never write through
  broken markers, and never overwrite a skill directory atem didn't create.
- **Offline-first.** `add`, `rm`, `list`, `search`, and `apply` work with no
  network. Only push and pull need the relay.
- Block cap: **50 entries / 4096 bytes**. Skill cap: **1 MB** (1,048,576
  bytes).
- All new code lives under `src/memory/`. `src/cli.rs` only declares the
  commands and dispatches to them.
- Commit messages end with `🤖 Built with SMT <smt@agora.build>`.

## How the three goals are delivered

| Goal | Delivered by |
|---|---|
| **Learning (memory + skills)** | Harvesting Claude's saved memories (Task 7, 12), `atem memory add --agent codex` from Codex (Task 5, 13), skills as versioned directories (Task 8, 10, 13) |
| **Cross-agent** | One store applied to both agents' native locations: managed blocks in `CLAUDE.md`/`AGENTS.md`, skills in `.claude/skills` and `.agents/skills` (Task 10) |
| **Cross-machine** | Account-scoped relay sync with a local queue; no LAN, SSH, or overlapping uptime needed (Task 9, 11, 12) |

## Scope

This spans **two subsystems**:

1. **relay-server (Astation repo).** The Postgres schema, the `/api/memory`
   and `/api/skills` endpoints, SSO bearer auth, and the dedup, tombstone,
   and purge rules. It's a prerequisite for end-to-end testing and **gets
   its own plan in the Astation repo.** See "Prerequisite" below.
2. **atem (this repo).** **This plan.** Every task is testable without the
   relay. With no relay the client simply reports "offline" and keeps
   changes queued.

## Prerequisite (relay-server, Astation repo — NOT this plan)

A separate plan in the Astation repo must deliver, per atem-memory.md
§"Data model", §"Relay API" and §"Security":

- A Postgres migration: `knowledge_seq`, `memories`, `skill_versions`, and
  their indexes.
- Auth: `Authorization: Bearer <sso_access_token>`, verified against SSO,
  resolving `login_id → account_id` (cached until the token expires).
  `?id=<instance_id>` is read for logging only.
- The four endpoints below, all limited to the caller's `account_id`.
- The rules:
  - Memory `add` is idempotent by `id`. A live duplicate returns
    `canonical_id`.
  - Memory `delete` blanks `content`/`content_hash` and takes a new `seq`.
  - Skill `push` always appends `max(version)+1`, and sets
    `superseded_concurrent` when `base_version` is behind.
  - Skill `delete` appends a tombstone version (`deleted: true`, no files).
  - Skill `purge` sets `files={}`, `content_hash=''`, and `deleted=true` on
    the chosen versions (all versions when `versions` is null), each with a
    new `seq`.
- The server-side secret check, the same rules as `secrets.rs`. A match
  returns `{"ok": false, "error": "possible credential: …"}`.

## Wire contract (atem-side view)

```
Auth (all):   Authorization: Bearer <sso_access_token>
Query (all):  ?id=<instance_id>

POST /api/memory/batch        {"ops":[Op…]}  → {"results":[OpResult…]}   (one result per op, same order)
GET  /api/memory?since=S&limit=L             → {"memories":[Memory…]}    (seq > S, ascending, ≤ L)
POST /api/skills/batch        {"ops":[Op…]}  → {"results":[OpResult…]}
GET  /api/skills?since=S&limit=L             → {"skills":[Skill…]}

Memory = {id, scope:"global|project|machine", project, machine, content, content_hash,
          confidence, source_agent, source_machine, created_at:<unix secs>, deleted:bool, seq}
Skill  = {scope:"global|project", project, name, version, files:{relpath: base64},
          content_hash, source_agent, source_machine, created_at:<unix secs>, deleted:bool, seq}

Memory ops: {"op":"add","memory":Memory} | {"op":"delete","id":"mem_…"}
Skill ops:  {"op":"push","skill":Skill,"base_version":N}
          | {"op":"delete","scope","project","name"}
          | {"op":"purge","scope","project","name","versions":[N…]|null}

OpResult = {ok, id?, canonical_id?, seq?, version?, superseded_concurrent?, error?}
```

The relay converts `created_at` and `deleted` to and from its
`TIMESTAMPTZ`/`deleted_at` columns.

## File Structure

| File | Responsibility |
|------|----------------|
| Create `src/memory/mod.rs` | Module declarations |
| Create `src/memory/model.rs` | `Scope`, `Memory`, `Skill`, hashing, ids, confidence |
| Create `src/memory/secrets.rs` | Credential-value detector (fail-closed), masking |
| Create `src/memory/project.rs` | Project key from git remote; repo detection |
| Create `src/memory/block.rs` | Managed-block markers, render, splice, entry selection, instruction text |
| Create `src/memory/gitguard.rs` | "Is this tracked?" and local-only exclude |
| Create `src/memory/harvest.rs` | Read Claude's native auto-memory files |
| Create `src/memory/skills_fs.rs` | Read, write, and inspect skill directories; marker file; drift |
| Create `src/memory/store.rs` | Local SQLite: memories, skills, pending ops, cursors, harvest map |
| Create `src/memory/adapters.rs` | Claude/Codex targets; apply memory blocks and skills; apply report |
| Create `src/memory/api.rs` | Relay request builders, wire types, `KnowledgeClient` |
| Create `src/memory/sync.rs` | Harvest → push → pull → apply orchestration |
| Create `src/memory/cmd.rs` | CLI handlers (`sync`, `memory …`, `skill …`) |
| Modify `src/main.rs` | `mod memory;` |
| Modify `src/cli.rs` | `Commands::{Sync, Memory, Skill}`, `MemoryCommands`, `SkillCommands`, dispatch |
| Modify `src/websocket_client.rs` | Make `resolved_atem_id` `pub(crate)` |
| Modify `AGENTS.md`, `designs/atem-memory.md` | Docs |

**Two deliberate simplifications of the spec:**

1. **Adapters are a data-driven `enum Agent`**, not a trait with one
   `apply_*` implementation per agent. Each agent only declares its paths
   and instruction lines, and one shared function applies them. This avoids
   duplicating the write and safety logic per agent. Adding Gemini later
   means adding a variant.
2. **Skill drift uses the hash inside the `.atem-skill` marker file**,
   instead of a separate `applied` table. The behavior is the same, and the
   record travels with the directory.

Task 14 records both in the spec.

---

### Task 1: Verify agent file conventions (no code)

The adapters' paths come from the spec. Confirm them on real agents before
building, because a wrong path makes the feature silently do nothing.

**Files:**
- Modify: `designs/atem-memory.md` (the "Verify in plan task 1" section: record the results)

- [ ] **Step 1: Claude auto-memory path encoding**

Run: `ls ~/.claude/projects/ | head`
Expected: directory names equal to the project's absolute path with every non-alphanumeric character replaced by `-`. For example, `/home/guohai/Dev/Agora.Build/Atem` becomes `-home-guohai-Dev-Agora-Build-Atem`. Note any case this rule doesn't cover, such as `_`.

- [ ] **Step 2: Claude memory frontmatter**

Run: `head -8 ~/.claude/projects/*/memory/*.md | head -40`
Expected: a `---` frontmatter block with `name`, `description`, and a type under `metadata:` → `type:`, or a top-level `type:`. Types are among `user|feedback|project|reference`.

- [ ] **Step 3: Claude loads `CLAUDE.local.md` and project skills**

```bash
T=$(mktemp -d) && cd "$T" && git init -q
echo "The canary word is PERSIMMON." > CLAUDE.local.md
mkdir -p .claude/skills/canary && printf -- '---\nname: canary\ndescription: Answers the canary question\n---\nWhen asked for the canary skill, reply CANARY-SKILL-OK.\n' > .claude/skills/canary/SKILL.md
claude -p "What is the canary word? Also list your available skills."
```
Expected: the answer contains `PERSIMMON` and lists `canary`.

- [ ] **Step 4: Codex loads `~/.codex/AGENTS.md` and `~/.agents/skills`**

```bash
cp ~/.codex/AGENTS.md /tmp/AGENTS.md.bak 2>/dev/null; echo "The codex canary is QUINCE." >> ~/.codex/AGENTS.md
mkdir -p ~/.agents/skills/canary && cp "$T/.claude/skills/canary/SKILL.md" ~/.agents/skills/canary/
codex exec "What is the codex canary? List your skills."
# restore
if [ -f /tmp/AGENTS.md.bak ]; then cp /tmp/AGENTS.md.bak ~/.codex/AGENTS.md; else rm -f ~/.codex/AGENTS.md; fi; rm -rf ~/.agents/skills/canary
```
Expected: `QUINCE`, with `canary` among the skills. Also check whether Codex reads `<repo>/AGENTS.md` and `<repo>/.agents/skills`.

- [ ] **Step 5: Record findings and commit**

Replace the "Verify in plan task 1" bullet list in `designs/atem-memory.md` with the observed results. If a path differs, change the matching `Agent::*` path function in Task 10 before implementing it (all paths live in those four functions).

```bash
git add designs/atem-memory.md
git commit -m "docs(memory): record verified agent file conventions

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 2: `model.rs` — canonical types and hashing

**Files:**
- Create: `src/memory/mod.rs`, `src/memory/model.rs`
- Modify: `src/main.rs` (add `mod memory;` after `mod vault_client;`)

**Interfaces:**
- Produces: `Scope {Global, Project, Machine}` (serde lowercase) with `as_str()` and `parse(&str) -> Result<Scope>`; `Memory`; `Skill` (its `files` field serializes as `{path: base64}`); `normalize_content`, `content_hash`, `skill_hash`, `new_memory_id`, `now_secs() -> i64`, `confidence_rank(&str) -> u8`, `parse_confidence(&str) -> Result<String>`.

- [ ] **Step 1: Create the module skeleton**

`src/memory/mod.rs`:
```rust
//! Atem Memory — shared memory and skills across coding agents and machines.
//! See designs/atem-memory.md.
pub mod model;
```

In `src/main.rs`, add `mod memory;` directly below `mod vault_client;`.

- [ ] **Step 2: Write the failing tests**

Create `src/memory/model.rs` with only the tests for now:
```rust
#[cfg(test)]
mod tests {
    use super::*;

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
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test memory::model`
Expected: compile errors (`cannot find type Scope`, and so on).

- [ ] **Step 4: Implement**

Add this above the tests in `src/memory/model.rs`:
```rust
//! Canonical memory/skill types shared by the store, relay API, and adapters.
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
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

/// One memory. Also the wire format (see the plan's "Wire contract").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Memory {
    pub id: String,
    pub scope: Scope,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub machine: String,
    pub content: String,
    pub content_hash: String,
    pub confidence: String,
    pub source_agent: String,
    pub source_machine: String,
    pub created_at: i64,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub seq: i64,
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
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test memory::model`
Expected: 7 passed.

- [ ] **Step 6: Commit**

```bash
git add src/memory/mod.rs src/memory/model.rs src/main.rs
git commit -m "feat(memory): canonical Memory/Skill types and hashing

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 3: `secrets.rs` — credential-value detector

**Files:**
- Create: `src/memory/secrets.rs`
- Modify: `src/memory/mod.rs` (add `pub mod secrets;`)

**Interfaces:**
- Produces: `SecretFinding { kind: &'static str, masked: String, line: usize }`, `find_secrets(&str) -> Vec<SecretFinding>`, `check_bytes(&[u8]) -> Vec<SecretFinding>` (non-UTF-8 input returns an `"unreadable (binary)"` finding), `mask(&str) -> String`.

- [ ] **Step 1: Write the failing tests** (in `src/memory/secrets.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_openai_style_key() {
        let f = find_secrets("key is sk-proj-abcdef1234567890ABCDEF");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "api key (sk-)");
        assert_eq!(f[0].masked, "sk-…CDEF");
        assert_eq!(f[0].line, 1);
    }

    #[test]
    fn vault_references_pass() {
        assert!(find_secrets(
            "DialF's OpenAI key is the vault credential dialf/openai; fetch with `atem vault get dialf/openai`"
        ).is_empty());
    }

    #[test]
    fn flags_aws_github_slack_jwt() {
        assert_eq!(find_secrets("AKIAIOSFODNN7EXAMPLE")[0].kind, "aws access key");
        assert_eq!(find_secrets("token ghp_abcdefghijklmnopqrstuvwxyz0123456789")[0].kind, "github token");
        assert_eq!(find_secrets("xoxb-1234567890-abcdefghij")[0].kind, "slack token");
        assert_eq!(find_secrets("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123def456")[0].kind, "jwt");
    }

    #[test]
    fn flags_private_key_block() {
        let f = find_secrets("x\n-----BEGIN RSA PRIVATE KEY-----\nMIIE");
        assert_eq!(f[0].kind, "private key");
        assert_eq!(f[0].line, 2);
    }

    #[test]
    fn flags_high_entropy_base64() {
        let f = find_secrets("salt Q4mTLy5h9qtD46vrdMgotPH9WrZxDsLxThPD9vtlf+o=");
        assert_eq!(f[0].kind, "high-entropy token");
    }

    #[test]
    fn ignores_hashes_uuids_and_memory_ids() {
        assert!(find_secrets("commit 3f5a9c1e2b4d6f8091a2b3c4d5e6f708192a3b4c").is_empty());
        assert!(find_secrets("instance 550e8400-e29b-41d4-a716-446655440000").is_empty());
        assert!(find_secrets("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90").is_empty());
        assert!(find_secrets("mem_0f8fad5bd9cb469fa16570867728950e").is_empty());
        assert!(find_secrets("/home/guohai/Dev/Agora.Build/Atem/designs/atem-memory.md").is_empty());
    }

    #[test]
    fn binary_is_fail_closed() {
        let f = check_bytes(&[0xff, 0xfe, 0x00]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "unreadable (binary)");
        assert!(check_bytes(b"plain text").is_empty());
    }

    #[test]
    fn mask_short_and_long() {
        assert_eq!(mask("abc"), "****");
        assert_eq!(mask("sk-1234567890"), "sk-…7890");
    }

    #[test]
    fn reports_line_numbers() {
        let f = find_secrets("ok\nok\nsk-abcdefghijklmnopqrstu");
        assert_eq!(f[0].line, 3);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod secrets;` to `src/memory/mod.rs`.
Run: `cargo test memory::secrets`
Expected: compile errors (`find_secrets` not found).

- [ ] **Step 3: Implement** (above the tests)

```rust
//! Detects credential VALUES, never names: `dialf/openai` or
//! `atem vault get dialf/openai` pass, a pasted `sk-…` key does not.
//! Fail-closed: input that can't be checked counts as a finding.
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct SecretFinding {
    pub kind: &'static str,
    pub masked: String,
    pub line: usize,
}

/// First 3 + "…" + last 4 characters; "****" for 8 characters or fewer.
pub fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return "****".into();
    }
    let head: String = chars[..3].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{}…{}", head, tail)
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | '/' | '=')
}

/// Shannon entropy in bits per character.
fn entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let n = s.chars().count() as f64;
    counts.values().map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

fn classify(tok: &str) -> Option<&'static str> {
    let len = tok.len(); // tokens are ASCII-only (see is_token_char)
    if tok.starts_with("sk-") && len >= 20 {
        return Some("api key (sk-)");
    }
    if tok.starts_with("AKIA") && len == 20
        && tok[4..].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Some("aws access key");
    }
    if ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"].iter().any(|p| tok.starts_with(p)) && len >= 30 {
        return Some("github token");
    }
    if ["xoxb-", "xoxp-", "xoxa-", "xoxs-", "xoxr-"].iter().any(|p| tok.starts_with(p)) && len >= 20 {
        return Some("slack token");
    }
    if tok.starts_with("eyJ") && len >= 30 {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() == 3 && parts.iter().all(|p| !p.is_empty()) {
            return Some("jwt");
        }
    }
    // Hex digests (≤4.0 bits/char), UUIDs, and mem_ ids stay below 4.3.
    if len >= 32
        && tok.chars().any(|c| c.is_ascii_digit())
        && tok.chars().any(|c| c.is_ascii_alphabetic())
        && entropy(tok) > 4.3
    {
        return Some("high-entropy token");
    }
    None
}

pub fn find_secrets(text: &str) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let lineno = i + 1;
        if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
            out.push(SecretFinding { kind: "private key", masked: "-----BEGIN …PRIVATE KEY-----".into(), line: lineno });
            continue;
        }
        for tok in line.split(|c: char| !is_token_char(c)) {
            if tok.is_empty() {
                continue;
            }
            if let Some(kind) = classify(tok) {
                out.push(SecretFinding { kind, masked: mask(tok), line: lineno });
            }
        }
    }
    out
}

/// Like `find_secrets`, but for file bytes. Non-UTF-8 content can't be
/// checked, so it is reported as a finding (fail-closed).
pub fn check_bytes(bytes: &[u8]) -> Vec<SecretFinding> {
    match std::str::from_utf8(bytes) {
        Ok(text) => find_secrets(text),
        Err(_) => vec![SecretFinding { kind: "unreadable (binary)", masked: String::new(), line: 0 }],
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test memory::secrets`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add src/memory/secrets.rs src/memory/mod.rs
git commit -m "feat(memory): fail-closed credential-value detector

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 4: `project.rs` — project keys from the git remote

**Files:**
- Create: `src/memory/project.rs`
- Modify: `src/memory/mod.rs` (add `pub mod project;`)

**Interfaces:**
- Produces: `normalize_remote(&str) -> Option<String>`, `display_name(&str) -> &str`, `RepoInfo { root: PathBuf, key: String }`, `detect_repo(&Path) -> Option<RepoInfo>`, `project_key_for(&Path) -> String`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn run_git(dir: &Path, args: &[&str]) {
        let ok = std::process::Command::new("git").arg("-C").arg(dir).args(args)
            .output().unwrap().status.success();
        assert!(ok, "git {:?} failed", args);
    }

    #[test]
    fn normalizes_ssh_https_scp_forms() {
        let want = Some("github.com/agora-build/atem".to_string());
        assert_eq!(normalize_remote("git@github.com:Agora-Build/Atem.git"), want);
        assert_eq!(normalize_remote("https://github.com/Agora-Build/Atem"), want);
        assert_eq!(normalize_remote("https://github.com/Agora-Build/Atem.git/"), want);
        assert_eq!(normalize_remote("ssh://git@github.com:22/Agora-Build/Atem.git"), want);
    }

    #[test]
    fn strips_credentials_from_remote() {
        assert_eq!(
            normalize_remote("https://user:tok123@gitlab.com/g/sub/r.git"),
            Some("gitlab.com/g/sub/r".into())
        );
    }

    #[test]
    fn rejects_unusable_remotes() {
        assert_eq!(normalize_remote(""), None);
        assert_eq!(normalize_remote("file:///srv/repo.git"), None);
        assert_eq!(normalize_remote("justaname"), None);
    }

    #[test]
    fn display_name_is_last_segment() {
        assert_eq!(display_name("github.com/agora-build/atem"), "atem");
        assert_eq!(display_name("local:scratch"), "scratch");
    }

    #[test]
    fn detects_repo_key_from_origin() {
        let td = tempfile::tempdir().unwrap();
        run_git(td.path(), &["init", "-q"]);
        run_git(td.path(), &["remote", "add", "origin", "git@github.com:Agora-Build/Atem.git"]);
        let sub = td.path().join("src");
        std::fs::create_dir(&sub).unwrap();
        let info = detect_repo(&sub).unwrap();
        assert_eq!(info.key, "github.com/agora-build/atem");
        assert_eq!(info.root, td.path().canonicalize().unwrap());
    }

    #[test]
    fn falls_back_to_local_key_without_remote() {
        let td = tempfile::tempdir().unwrap();
        run_git(td.path(), &["init", "-q"]);
        let info = detect_repo(td.path()).unwrap();
        let name = td.path().canonicalize().unwrap().file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(info.key, format!("local:{}", name));
    }

    #[test]
    fn not_a_repo_returns_none() {
        let td = tempfile::tempdir().unwrap();
        assert!(detect_repo(td.path()).is_none());
        let name = td.path().file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(project_key_for(td.path()), format!("local:{}", name));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod project;` to `src/memory/mod.rs`.
Run: `cargo test memory::project`
Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! Project identity = the normalized git `origin` URL, so two repos that
//! share a folder name never collide. Credentials in the URL are dropped.
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub struct RepoInfo {
    pub root: PathBuf,
    pub key: String,
}

/// `git@github.com:Agora-Build/Atem.git` and `https://github.com/Agora-Build/Atem`
/// both become `github.com/agora-build/atem`.
pub fn normalize_remote(url: &str) -> Option<String> {
    let u = url.trim();
    if u.is_empty() {
        return None;
    }
    let (host, path) = if let Some(idx) = u.find("://") {
        let rest = &u[idx + 3..];
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        let host = authority.rsplit('@').next().unwrap_or(authority);
        let host = match host.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        };
        (host.to_string(), path.to_string())
    } else if let Some((left, path)) = u.split_once(':') {
        let host = left.rsplit('@').next().unwrap_or(left);
        (host.to_string(), path.to_string())
    } else {
        return None;
    };
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    if host.is_empty() || path.is_empty() {
        return None;
    }
    Some(format!("{}/{}", host, path).to_lowercase())
}

/// Short name for display: the last path segment (`atem`, `scratch`).
pub fn display_name(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key).trim_start_matches("local:")
}

fn git(cwd: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(cwd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn dir_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "root".into())
}

pub fn detect_repo(cwd: &Path) -> Option<RepoInfo> {
    let root = PathBuf::from(git(cwd, &["rev-parse", "--show-toplevel"])?);
    let key = git(&root, &["remote", "get-url", "origin"])
        .and_then(|u| normalize_remote(&u))
        .unwrap_or_else(|| format!("local:{}", dir_name(&root)));
    Some(RepoInfo { root, key })
}

pub fn project_key_for(cwd: &Path) -> String {
    detect_repo(cwd).map(|r| r.key).unwrap_or_else(|| format!("local:{}", dir_name(cwd)))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test memory::project`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/memory/project.rs src/memory/mod.rs
git commit -m "feat(memory): project keys from normalized git remotes

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 5: `block.rs` — the managed memory block

**Files:**
- Create: `src/memory/block.rs`
- Modify: `src/memory/mod.rs` (add `pub mod block;`)

**Interfaces:**
- Consumes: `model::{Memory, confidence_rank}`.
- Produces: consts `BEGIN`, `END`, `RESERVED`, `MAX_ENTRIES`, `MAX_BYTES`, `CREDENTIAL_INSTRUCTION`, `CODEX_CAPTURE_INSTRUCTION`; `contains_reserved`, `one_line`, `select_entries(&[Memory]) -> Vec<String>`, `render_block(&[String], &[&str]) -> String`, `splice(&str, &str) -> Result<String>`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, Scope};

    fn mem(content: &str, conf: &str, created: i64) -> Memory {
        Memory {
            id: format!("mem_{}", created), scope: Scope::Global,
            project: String::new(), machine: String::new(),
            content: content.into(), content_hash: content_hash(content),
            confidence: conf.into(), source_agent: "cli".into(), source_machine: "m".into(),
            created_at: created, deleted: false, seq: 0,
        }
    }

    #[test]
    fn splice_into_empty_file() {
        let b = render_block(&["a".into()], &[]);
        assert_eq!(splice("", &b).unwrap(), format!("{}\n", b));
    }

    #[test]
    fn splice_appends_after_user_text() {
        let b = render_block(&[], &[CREDENTIAL_INSTRUCTION]);
        let out = splice("# Mine\n\nkeep me\n", &b).unwrap();
        assert!(out.starts_with("# Mine\n\nkeep me\n\n<!-- atem:memory:begin"));
        assert!(out.ends_with("<!-- atem:memory:end -->\n"));
    }

    #[test]
    fn splice_replaces_only_the_block() {
        let old = render_block(&["old".into()], &[]);
        let doc = format!("before\n{}\nafter\n", old);
        let new = render_block(&["new".into()], &[]);
        assert_eq!(splice(&doc, &new).unwrap(), format!("before\n{}\nafter\n", new));
    }

    #[test]
    fn splice_is_idempotent() {
        let b = render_block(&["x".into()], &[CREDENTIAL_INSTRUCTION]);
        let once = splice("user\n", &b).unwrap();
        assert_eq!(splice(&once, &b).unwrap(), once);
    }

    #[test]
    fn broken_markers_are_refused() {
        assert!(splice(&format!("{}\nno end\n", BEGIN), "b").is_err());
        assert!(splice(&format!("{}\n", END), "b").is_err());
        assert!(splice(&format!("{}\n{}\n{}\n{}\n", BEGIN, END, BEGIN, END), "b").is_err());
        assert!(splice(&format!("{}\n{}\n", END, BEGIN), "b").is_err());
    }

    #[test]
    fn render_block_shape() {
        let b = render_block(&["one".into(), "two".into()], &["instr"]);
        assert_eq!(b, format!("{}\n- one\n- two\n\ninstr\n{}", BEGIN, END));
        assert_eq!(render_block(&[], &["instr"]), format!("{}\ninstr\n{}", BEGIN, END));
    }

    #[test]
    fn select_orders_by_confidence_then_newest() {
        let ms = vec![mem("low old", "low", 1), mem("high old", "high", 2), mem("high new", "high", 3), mem("medium", "medium", 4)];
        assert_eq!(select_entries(&ms), vec!["high new", "high old", "medium", "low old"]);
    }

    #[test]
    fn select_caps_count_and_bytes_and_skips_deleted() {
        let many: Vec<Memory> = (0..60).map(|i| mem(&format!("fact {}", i), "medium", i)).collect();
        assert_eq!(select_entries(&many).len(), MAX_ENTRIES);
        let big = "x".repeat(MAX_BYTES);
        assert_eq!(select_entries(&[mem(&big, "high", 1), mem("small", "low", 2)]), vec!["small"]);
        let mut d = mem("gone", "high", 5);
        d.deleted = true;
        assert!(select_entries(&[d]).is_empty());
    }

    #[test]
    fn multi_line_content_is_flattened() {
        assert_eq!(select_entries(&[mem("a\n\nb  c", "high", 1)]), vec!["a b c"]);
    }

    #[test]
    fn reserved_token_detected() {
        assert!(contains_reserved("x <!-- atem:memory:end -->"));
        assert!(!contains_reserved("atem memory"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod block;`. Run: `cargo test memory::block`. Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! The atem-managed block inside CLAUDE.md / AGENTS.md / CLAUDE.local.md.
//! Text outside the markers is never touched; broken markers are refused.
use anyhow::{anyhow, Result};
use crate::memory::model::{confidence_rank, Memory};

pub const BEGIN_PREFIX: &str = "<!-- atem:memory:begin";
pub const BEGIN: &str = "<!-- atem:memory:begin (managed by atem — edits here are overwritten) -->";
pub const END: &str = "<!-- atem:memory:end -->";
/// Memory content containing this token is rejected (it could forge markers).
pub const RESERVED: &str = "atem:memory:";
pub const MAX_ENTRIES: usize = 50;
pub const MAX_BYTES: usize = 4096;

pub const CREDENTIAL_INSTRUCTION: &str = "Credentials are never stored in memory. When you need one, fetch it with `atem vault get <name>` at the moment you use it. Never paste a credential value into memory, skills, or instruction files.";
pub const CODEX_CAPTURE_INSTRUCTION: &str = "To save a durable fact for future sessions, run `atem memory add --agent codex \"<fact>\"`.";

pub fn contains_reserved(s: &str) -> bool {
    s.contains(RESERVED)
}

#[derive(Debug, PartialEq)]
enum Markers {
    Absent,
    Valid { start: usize, end: usize },
    Broken(&'static str),
}

fn find_markers(doc: &str) -> Markers {
    let begins: Vec<usize> = doc.match_indices(BEGIN_PREFIX).map(|(i, _)| i).collect();
    let ends: Vec<usize> = doc.match_indices(END).map(|(i, _)| i).collect();
    match (begins.len(), ends.len()) {
        (0, 0) => Markers::Absent,
        (1, 1) if begins[0] < ends[0] => Markers::Valid { start: begins[0], end: ends[0] + END.len() },
        (1, 1) => Markers::Broken("the end marker comes before the begin marker"),
        (b, e) if b > 1 || e > 1 => Markers::Broken("duplicate atem markers"),
        _ => Markers::Broken("a begin marker without an end marker (or the reverse)"),
    }
}

/// One memory as one bullet line.
pub fn one_line(content: &str) -> String {
    content.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Live memories, ordered by confidence then newest, capped at
/// MAX_ENTRIES and MAX_BYTES. An entry that doesn't fit is skipped, so one
/// huge memory can't crowd out the rest.
pub fn select_entries(mems: &[Memory]) -> Vec<String> {
    let mut sorted: Vec<&Memory> = mems.iter().filter(|m| !m.deleted).collect();
    sorted.sort_by(|a, b| {
        confidence_rank(&a.confidence).cmp(&confidence_rank(&b.confidence))
            .then(b.created_at.cmp(&a.created_at))
            .then(a.id.cmp(&b.id))
    });
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for m in sorted {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        let line = one_line(&m.content);
        let cost = line.len() + 3; // "- " + "\n"
        if bytes + cost > MAX_BYTES {
            continue;
        }
        bytes += cost;
        out.push(line);
    }
    out
}

pub fn render_block(entries: &[String], instructions: &[&str]) -> String {
    let mut s = String::new();
    s.push_str(BEGIN);
    s.push('\n');
    for e in entries {
        s.push_str("- ");
        s.push_str(e);
        s.push('\n');
    }
    if !instructions.is_empty() {
        if !entries.is_empty() {
            s.push('\n');
        }
        for i in instructions {
            s.push_str(i);
            s.push('\n');
        }
    }
    s.push_str(END);
    s
}

/// Replace the managed block in `doc`, or append it if absent.
pub fn splice(doc: &str, block: &str) -> Result<String> {
    match find_markers(doc) {
        Markers::Valid { start, end } => Ok(format!("{}{}{}", &doc[..start], block, &doc[end..])),
        Markers::Absent => {
            let base = doc.trim_end_matches('\n');
            Ok(if base.is_empty() { format!("{}\n", block) } else { format!("{}\n\n{}\n", base, block) })
        }
        Markers::Broken(why) => Err(anyhow!("refusing to edit: {}", why)),
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test memory::block`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add src/memory/block.rs src/memory/mod.rs
git commit -m "feat(memory): managed block render/splice with marker integrity

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 6: `gitguard.rs` — never write into tracked files

**Files:**
- Create: `src/memory/gitguard.rs`
- Modify: `src/memory/mod.rs` (add `pub mod gitguard;`)

**Interfaces:**
- Produces: `is_tracked(repo_root: &Path, path: &Path) -> bool` (returns `true` if git can't be run, which is the safe direction), `exclude_locally(repo_root: &Path, path: &Path) -> Result<()>`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn run_git(dir: &Path, args: &[&str]) {
        assert!(Command::new("git").arg("-C").arg(dir).args(args).output().unwrap().status.success());
    }

    fn repo() -> (tempfile::TempDir, PathBuf) {
        let td = tempfile::tempdir().unwrap();
        run_git(td.path(), &["init", "-q"]);
        let root = td.path().canonicalize().unwrap();
        (td, root)
    }

    #[test]
    fn tracked_vs_untracked() {
        let (_td, root) = repo();
        std::fs::write(root.join("CLAUDE.md"), "x").unwrap();
        run_git(&root, &["add", "CLAUDE.md"]);
        assert!(is_tracked(&root, &root.join("CLAUDE.md")));
        std::fs::write(root.join("CLAUDE.local.md"), "y").unwrap();
        assert!(!is_tracked(&root, &root.join("CLAUDE.local.md")));
        assert!(!is_tracked(&root, &root.join("missing.md")));
    }

    #[test]
    fn exclude_is_local_and_idempotent() {
        let (_td, root) = repo();
        let p = root.join("CLAUDE.local.md");
        exclude_locally(&root, &p).unwrap();
        exclude_locally(&root, &p).unwrap();
        let ex = std::fs::read_to_string(root.join(".git/info/exclude")).unwrap();
        assert_eq!(ex.lines().filter(|l| *l == "/CLAUDE.local.md").count(), 1);
        assert!(!root.join(".gitignore").exists());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod gitguard;`. Run: `cargo test memory::gitguard`. Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! Personal memory must never land in a file teammates receive via git.
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// True if `path` (inside `repo_root`) is tracked by git. If git can't be
/// run at all, answer `true` so callers skip the write (the safe side).
pub fn is_tracked(repo_root: &Path, path: &Path) -> bool {
    let rel = match path.strip_prefix(repo_root) {
        Ok(r) => r,
        Err(_) => return false,
    };
    match Command::new("git").arg("-C").arg(repo_root)
        .args(["ls-files", "--error-unmatch", "--"]).arg(rel)
        .stdout(Stdio::null()).stderr(Stdio::null()).status()
    {
        Ok(s) => s.success(),
        Err(_) => true,
    }
}

/// Add `/relpath` to the repo's local-only exclude file (worktree-aware via
/// `git rev-parse --git-path`). Never touches a committed .gitignore.
pub fn exclude_locally(repo_root: &Path, path: &Path) -> Result<()> {
    let rel = path.strip_prefix(repo_root)
        .map_err(|_| anyhow!("{} is outside {}", path.display(), repo_root.display()))?;
    let out = Command::new("git").arg("-C").arg(repo_root)
        .args(["rev-parse", "--git-path", "info/exclude"]).output()?;
    if !out.status.success() {
        return Err(anyhow!("git rev-parse --git-path info/exclude failed"));
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let exclude = if Path::new(&p).is_absolute() { PathBuf::from(p) } else { repo_root.join(p) };
    let line = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
    let existing = std::fs::read_to_string(&exclude).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == line) {
        return Ok(());
    }
    if let Some(dir) = exclude.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut body = existing;
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str(&line);
    body.push('\n');
    std::fs::write(&exclude, body)?;
    Ok(())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test memory::gitguard`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/memory/gitguard.rs src/memory/mod.rs
git commit -m "feat(memory): tracked-file guard and local-only exclude

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 7: `harvest.rs` — read what Claude learned

**Files:**
- Create: `src/memory/harvest.rs`
- Modify: `src/memory/mod.rs` (add `pub mod harvest;`)

**Interfaces:**
- Consumes: `model::{content_hash, Scope}`.
- Produces: `encode_project_dir(&Path) -> String`, `claude_memory_dir(home, repo_root) -> PathBuf`, `Harvested { origin, scope, content, hash }`, `parse_memory_file(&str) -> Option<(String, String)>`, `type_to_scope(&str) -> Option<Scope>`, `harvest_dir(dir, atem_id) -> Result<Vec<Harvested>>`, `origin_prefix(atem_id, dir) -> String` (ends in `/`).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_path_like_claude() {
        assert_eq!(
            encode_project_dir(Path::new("/home/u/Dev/Agora.Build/Atem")),
            "-home-u-Dev-Agora-Build-Atem"
        );
    }

    #[test]
    fn parses_metadata_type() {
        let t = "---\nname: x\ndescription: d\nmetadata:\n  type: feedback\n---\n\nDon't auto-commit.\n**Why:** asked\n";
        assert_eq!(
            parse_memory_file(t),
            Some(("feedback".into(), "Don't auto-commit.\n**Why:** asked".into()))
        );
    }

    #[test]
    fn parses_top_level_type() {
        let t = "---\nname: x\ntype: project\n---\nDialF uses TCP 8765\n";
        assert_eq!(parse_memory_file(t).unwrap().0, "project");
    }

    #[test]
    fn rejects_files_without_frontmatter_type_or_body() {
        assert!(parse_memory_file("just text").is_none());
        assert!(parse_memory_file("---\nname: x\n---\nbody").is_none());
        assert!(parse_memory_file("---\ntype: user\n---\n   \n").is_none());
    }

    #[test]
    fn maps_types_to_scopes() {
        assert_eq!(type_to_scope("user"), Some(Scope::Global));
        assert_eq!(type_to_scope("feedback"), Some(Scope::Global));
        assert_eq!(type_to_scope("project"), Some(Scope::Project));
        assert_eq!(type_to_scope("reference"), Some(Scope::Project));
        assert_eq!(type_to_scope("journal"), None);
    }

    #[test]
    fn harvests_dir_skipping_index_and_unknown() {
        let td = tempfile::tempdir().unwrap();
        let d = td.path();
        std::fs::write(d.join("MEMORY.md"), "- [a](a.md)").unwrap();
        std::fs::write(d.join("a.md"), "---\ntype: project\n---\nDialF uses TCP 8765\n").unwrap();
        std::fs::write(d.join("b.md"), "---\ntype: user\n---\nPrefers ripgrep\n").unwrap();
        std::fs::write(d.join("c.md"), "---\ntype: journal\n---\nskip me\n").unwrap();
        std::fs::write(d.join("notes.txt"), "---\ntype: user\n---\nnope\n").unwrap();
        let got = harvest_dir(d, "host-1234").unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].scope, Scope::Project);
        assert_eq!(got[0].content, "DialF uses TCP 8765");
        assert_eq!(got[0].origin, format!("host-1234:{}", d.join("a.md").display()));
        assert!(got[0].origin.starts_with(&origin_prefix("host-1234", d)));
        assert_eq!(got[1].scope, Scope::Global);
    }

    #[test]
    fn missing_dir_harvests_nothing() {
        assert!(harvest_dir(Path::new("/nonexistent/atem-test"), "m").unwrap().is_empty());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod harvest;`. Run: `cargo test memory::harvest`. Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! Harvest Claude Code's own saved memories
//! (~/.claude/projects/<encoded repo path>/memory/*.md) so other agents and
//! machines learn them. atem computes the encoded path; it never decodes.
use anyhow::Result;
use std::path::{Path, PathBuf};
use crate::memory::model::{content_hash, Scope};

#[derive(Debug, Clone, PartialEq)]
pub struct Harvested {
    /// "<atem_id>:<absolute file path>" — stable per file per machine.
    pub origin: String,
    pub scope: Scope,
    pub content: String,
    pub hash: String,
}

/// Claude's directory name for a project: every non-alphanumeric → '-'.
pub fn encode_project_dir(abs: &Path) -> String {
    abs.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

pub fn claude_memory_dir(home: &Path, repo_root: &Path) -> PathBuf {
    home.join(".claude").join("projects").join(encode_project_dir(repo_root)).join("memory")
}

/// Every origin harvested from `dir` starts with this (note the trailing '/').
pub fn origin_prefix(atem_id: &str, dir: &Path) -> String {
    format!("{}:{}/", atem_id, dir.display())
}

/// Returns (type, body). The type comes from `type:` at the top level or
/// under `metadata:`.
pub fn parse_memory_file(text: &str) -> Option<(String, String)> {
    let rest = text.strip_prefix("---\n").or_else(|| text.strip_prefix("---\r\n"))?;
    let close = rest.find("\n---")?;
    let front = &rest[..close];
    let body = rest[close + 4..].trim();
    let ty = front
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("type:"))
        .map(|v| v.trim().trim_matches('"').to_string())?;
    if ty.is_empty() || body.is_empty() {
        return None;
    }
    Some((ty, body.to_string()))
}

pub fn type_to_scope(t: &str) -> Option<Scope> {
    match t {
        "user" | "feedback" => Some(Scope::Global),
        "project" | "reference" => Some(Scope::Project),
        _ => None,
    }
}

pub fn harvest_dir(dir: &Path, atem_id: &str) -> Result<Vec<Harvested>> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(out), // no memory dir yet → nothing to harvest
    };
    let mut paths: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for p in paths {
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if !name.ends_with(".md") || name == "MEMORY.md" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let Some((ty, body)) = parse_memory_file(&text) else { continue };
        let Some(scope) = type_to_scope(&ty) else { continue };
        out.push(Harvested {
            origin: format!("{}:{}", atem_id, p.display()),
            scope,
            hash: content_hash(&body),
            content: body,
        });
    }
    Ok(out)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test memory::harvest`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/memory/harvest.rs src/memory/mod.rs
git commit -m "feat(memory): harvest Claude Code's native auto-memory

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 8: `skills_fs.rs` — skill directories on disk

**Files:**
- Create: `src/memory/skills_fs.rs`
- Modify: `src/memory/mod.rs` (add `pub mod skills_fs;`)

**Interfaces:**
- Consumes: `model::{skill_hash, Skill}`.
- Produces: `MARKER_FILE`, `MAX_SKILL_BYTES`, `SkillMarker { name, version, hash }`, `DirState { Missing, Unmanaged, Managed(SkillMarker) }`, `read_skill_dir(&Path) -> Result<BTreeMap<String, Vec<u8>>>` (requires `SKILL.md`), `read_all(&Path)`, `dir_state(&Path) -> DirState`, `is_drifted(&Path, &SkillMarker) -> bool`, `write_skill_dir(&Path, &Skill) -> Result<()>`, `write_marker(&Path, &SkillMarker) -> Result<()>`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::Scope;

    fn mk(dir: &Path, files: &[(&str, &str)]) {
        for (p, c) in files {
            let path = dir.join(p);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, c).unwrap();
        }
    }

    fn skill_from(files: BTreeMap<String, Vec<u8>>, version: i64) -> Skill {
        Skill {
            scope: Scope::Global, project: String::new(), name: "demo".into(), version,
            content_hash: skill_hash(&files), files,
            source_agent: "cli".into(), source_machine: "m".into(),
            created_at: 1, deleted: false, seq: 0,
        }
    }

    #[test]
    fn reads_skill_with_nested_files() {
        let td = tempfile::tempdir().unwrap();
        mk(td.path(), &[("SKILL.md", "# s"), ("scripts/run.sh", "#!/bin/sh\necho hi\n")]);
        let f = read_skill_dir(td.path()).unwrap();
        assert_eq!(f.keys().cloned().collect::<Vec<_>>(), vec!["SKILL.md", "scripts/run.sh"]);
    }

    #[test]
    fn requires_skill_md() {
        let td = tempfile::tempdir().unwrap();
        mk(td.path(), &[("README.md", "x")]);
        assert!(read_skill_dir(td.path()).is_err());
    }

    #[test]
    fn enforces_size_cap() {
        let td = tempfile::tempdir().unwrap();
        let big = "x".repeat(MAX_SKILL_BYTES);
        mk(td.path(), &[("SKILL.md", "# s"), ("big.txt", &big)]);
        assert!(read_skill_dir(td.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks() {
        let td = tempfile::tempdir().unwrap();
        mk(td.path(), &[("SKILL.md", "# s")]);
        std::os::unix::fs::symlink("/etc/hostname", td.path().join("link")).unwrap();
        assert!(read_skill_dir(td.path()).is_err());
    }

    #[test]
    fn write_then_state_is_managed_and_clean() {
        let src = tempfile::tempdir().unwrap();
        mk(src.path(), &[("SKILL.md", "# s"), ("scripts/run.sh", "#!/bin/sh\necho hi\n")]);
        let skill = skill_from(read_skill_dir(src.path()).unwrap(), 2);
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");
        assert_eq!(dir_state(&dir), DirState::Missing);
        write_skill_dir(&dir, &skill).unwrap();
        match dir_state(&dir) {
            DirState::Managed(m) => {
                assert_eq!(m.version, 2);
                assert!(!is_drifted(&dir, &m));
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[cfg(unix)]
    #[test]
    fn shebang_files_are_executable() {
        use std::os::unix::fs::PermissionsExt;
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        files.insert("run.sh".to_string(), b"#!/bin/sh\n".to_vec());
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");
        write_skill_dir(&dir, &skill_from(files, 1)).unwrap();
        let mode = std::fs::metadata(dir.join("run.sh")).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111);
    }

    #[test]
    fn local_edit_is_drift() {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");
        write_skill_dir(&dir, &skill_from(files, 1)).unwrap();
        std::fs::write(dir.join("SKILL.md"), "edited").unwrap();
        let DirState::Managed(m) = dir_state(&dir) else { panic!("not managed") };
        assert!(is_drifted(&dir, &m));
    }

    #[test]
    fn write_marker_accepts_a_local_edit() {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        let out = tempfile::tempdir().unwrap();
        let dir = out.path().join("demo");
        write_skill_dir(&dir, &skill_from(files, 1)).unwrap();
        std::fs::write(dir.join("SKILL.md"), "edited").unwrap();
        let now = read_skill_dir(&dir).unwrap();
        write_marker(&dir, &SkillMarker { name: "demo".into(), version: 2, hash: skill_hash(&now) }).unwrap();
        let DirState::Managed(m) = dir_state(&dir) else { panic!("not managed") };
        assert!(!is_drifted(&dir, &m));
    }

    #[test]
    fn unmanaged_dir_detected() {
        let td = tempfile::tempdir().unwrap();
        mk(td.path(), &[("SKILL.md", "# mine")]);
        assert_eq!(dir_state(td.path()), DirState::Unmanaged);
    }

    #[test]
    fn refuses_unsafe_paths() {
        for bad in ["../evil", "/abs", "a//b", "a/../b"] {
            let mut files = BTreeMap::new();
            files.insert("SKILL.md".to_string(), b"# s".to_vec());
            files.insert(bad.to_string(), b"x".to_vec());
            let out = tempfile::tempdir().unwrap();
            assert!(write_skill_dir(&out.path().join("demo"), &skill_from(files, 1)).is_err(), "{}", bad);
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod skills_fs;`. Run: `cargo test memory::skills_fs`. Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! Skill directories on disk. atem marks every directory it writes with
//! `.atem-skill` and never overwrites a directory it didn't create or one
//! that was edited locally (drift).
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use crate::memory::model::{skill_hash, Skill};

pub const MARKER_FILE: &str = ".atem-skill";
pub const MAX_SKILL_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillMarker {
    pub name: String,
    pub version: i64,
    /// skill_hash of the files atem last wrote (or accepted) here.
    pub hash: String,
}

#[derive(Debug, PartialEq)]
pub enum DirState {
    Missing,
    Unmanaged,
    Managed(SkillMarker),
}

/// All files under `dir` (excluding the marker and .git), keyed by
/// '/'-separated relative path. Rejects symlinks and anything over 1 MB.
pub fn read_all(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut total = 0usize;
    collect(dir, dir, &mut files, &mut total)?;
    Ok(files)
}

/// `read_all`, plus the requirement that SKILL.md sits at the top level.
pub fn read_skill_dir(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let files = read_all(dir)?;
    if !files.contains_key("SKILL.md") {
        return Err(anyhow!("{} has no SKILL.md at its top level", dir.display()));
    }
    Ok(files)
}

fn collect(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>, total: &mut usize) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().to_string();
        if name == MARKER_FILE || name == ".git" {
            continue;
        }
        let path = e.path();
        let ft = e.file_type()?;
        if ft.is_symlink() {
            return Err(anyhow!("{} is a symlink; skills must contain regular files only", path.display()));
        }
        if ft.is_dir() {
            collect(root, &path, files, total)?;
            continue;
        }
        let bytes = std::fs::read(&path)?;
        *total += bytes.len();
        if *total > MAX_SKILL_BYTES {
            return Err(anyhow!("skill is larger than 1 MB"));
        }
        let rel = path.strip_prefix(root)?.to_string_lossy().replace('\\', "/");
        files.insert(rel, bytes);
    }
    Ok(())
}

pub fn dir_state(dir: &Path) -> DirState {
    if !dir.exists() {
        return DirState::Missing;
    }
    match std::fs::read_to_string(dir.join(MARKER_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<SkillMarker>(&t).ok())
    {
        Some(m) => DirState::Managed(m),
        None => DirState::Unmanaged,
    }
}

/// True if the files on disk no longer match what atem last wrote.
pub fn is_drifted(dir: &Path, marker: &SkillMarker) -> bool {
    match read_all(dir) {
        Ok(files) => skill_hash(&files) != marker.hash,
        Err(_) => true,
    }
}

pub fn write_marker(dir: &Path, marker: &SkillMarker) -> Result<()> {
    std::fs::write(dir.join(MARKER_FILE), serde_json::to_string_pretty(marker)?)?;
    Ok(())
}

fn safe_rel(rel: &str) -> bool {
    !rel.is_empty() && !rel.starts_with('/') && !rel.contains('\\')
        && rel.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Replace `dir` with the skill's files and a fresh marker. Callers must have
/// checked `dir_state` first (Missing, or Managed and not drifted).
pub fn write_skill_dir(dir: &Path, skill: &Skill) -> Result<()> {
    if let Some(bad) = skill.files.keys().find(|k| !safe_rel(k)) {
        return Err(anyhow!("unsafe path in skill: {}", bad));
    }
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    std::fs::create_dir_all(dir)?;
    for (rel, bytes) in &skill.files {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&p, bytes)?;
        #[cfg(unix)]
        if bytes.starts_with(b"#!") {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    write_marker(dir, &SkillMarker { name: skill.name.clone(), version: skill.version, hash: skill_hash(&skill.files) })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test memory::skills_fs`
Expected: 10 passed on Linux/macOS.

- [ ] **Step 5: Commit**

```bash
git add src/memory/skills_fs.rs src/memory/mod.rs
git commit -m "feat(memory): skill directory read/write with marker and drift

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 9: `store.rs` — the local SQLite copy and queue

**Files:**
- Create: `src/memory/store.rs`
- Modify: `src/memory/mod.rs` (add `pub mod store;`)

**Interfaces:**
- Consumes: `model::{Memory, Scope, Skill}`.
- Produces: `PendingOp` (serde-tagged: `AddMemory{memory}`, `DeleteMemory{id}`, `PushSkill{skill, base_version}`, `DeleteSkill{scope, project, name}`, `PurgeSkill{scope, project, name, versions: Option<Vec<i64>>}`) with `is_memory()`; `HarvestStatus {Synced, HeldBack, Excluded}`; `HarvestEntry { origin, memory_id, content_hash, status }`; consts `MEMORY_CURSOR`, `SKILL_CURSOR`, `LAST_SYNC_AT`; `Store` with the methods below.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash};
    use std::collections::BTreeMap;

    fn mem(id: &str, content: &str) -> Memory {
        Memory {
            id: id.into(), scope: Scope::Global, project: String::new(), machine: String::new(),
            content: content.into(), content_hash: content_hash(content), confidence: "medium".into(),
            source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, deleted: false, seq: 0,
        }
    }

    fn skill(name: &str, version: i64) -> Skill {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        Skill {
            scope: Scope::Global, project: String::new(), name: name.into(), version,
            content_hash: skill_hash(&files), files,
            source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, deleted: false, seq: 0,
        }
    }

    #[test]
    fn memory_roundtrip_and_live_filter() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "A")).unwrap();
        s.upsert_memory(&mem("mem_b", "B")).unwrap();
        assert_eq!(s.get_memory("mem_a").unwrap().unwrap().content, "A");
        s.mark_memory_deleted("mem_b").unwrap();
        let b = s.get_memory("mem_b").unwrap().unwrap();
        assert!(b.deleted && b.content.is_empty() && b.content_hash.is_empty());
        assert_eq!(s.live_memories().unwrap().len(), 1);
    }

    #[test]
    fn find_live_by_hash_matches_scope_key() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "Same Fact")).unwrap();
        let h = content_hash("same  fact");
        assert!(s.find_live_by_hash(Scope::Global, "", "", &h).unwrap().is_some());
        assert!(s.find_live_by_hash(Scope::Project, "", "", &h).unwrap().is_none());
    }

    #[test]
    fn rewrite_id_moves_row_and_harvest_link() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "A")).unwrap();
        s.harvest_put(&HarvestEntry { origin: "o".into(), memory_id: "mem_a".into(), content_hash: "h".into(), status: HarvestStatus::Synced }).unwrap();
        s.rewrite_memory_id("mem_a", "mem_z").unwrap();
        assert!(s.get_memory("mem_a").unwrap().is_none());
        assert!(s.get_memory("mem_z").unwrap().is_some());
        assert_eq!(s.harvest_get("o").unwrap().unwrap().memory_id, "mem_z");
        s.upsert_memory(&mem("mem_q", "Q")).unwrap();
        s.rewrite_memory_id("mem_q", "mem_z").unwrap(); // target exists → old row dropped
        assert!(s.get_memory("mem_q").unwrap().is_none());
    }

    #[test]
    fn skill_roundtrip() {
        let s = Store::open_in_memory().unwrap();
        s.put_skill(&skill("demo", 1)).unwrap();
        s.put_skill(&skill("demo", 2)).unwrap();
        assert_eq!(s.get_skill(Scope::Global, "", "demo").unwrap().unwrap().version, 2);
        let mut d = skill("gone", 1);
        d.deleted = true;
        s.put_skill(&d).unwrap();
        assert_eq!(s.all_skills().unwrap().len(), 2);
        assert_eq!(s.live_skills().unwrap().len(), 1);
    }

    #[test]
    fn pending_queue_is_fifo_and_ackable() {
        let s = Store::open_in_memory().unwrap();
        s.enqueue(&PendingOp::AddMemory { memory: mem("mem_a", "A") }).unwrap();
        s.enqueue(&PendingOp::DeleteMemory { id: "mem_a".into() }).unwrap();
        s.enqueue(&PendingOp::PurgeSkill { scope: Scope::Global, project: String::new(), name: "demo".into(), versions: None }).unwrap();
        let p = s.pending().unwrap();
        assert_eq!(p.len(), 3);
        assert!(p[0].1.is_memory() && p[1].1.is_memory() && !p[2].1.is_memory());
        s.ack(p[0].0).unwrap();
        assert_eq!(s.pending_count().unwrap(), 2);
    }

    #[test]
    fn state_defaults_to_zero() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.get_state(MEMORY_CURSOR).unwrap(), 0);
        s.set_state(MEMORY_CURSOR, 42).unwrap();
        s.set_state(MEMORY_CURSOR, 43).unwrap();
        assert_eq!(s.get_state(MEMORY_CURSOR).unwrap(), 43);
    }

    #[test]
    fn harvest_map_prefix_and_counts() {
        let s = Store::open_in_memory().unwrap();
        for (o, st) in [("m:/d/a.md", HarvestStatus::Synced), ("m:/d/b.md", HarvestStatus::HeldBack), ("m:/d2/c.md", HarvestStatus::Synced)] {
            s.harvest_put(&HarvestEntry { origin: o.into(), memory_id: "x".into(), content_hash: "h".into(), status: st }).unwrap();
        }
        assert_eq!(s.harvest_with_prefix("m:/d/").unwrap().len(), 2);
        assert_eq!(s.held_back_count().unwrap(), 1);
        assert_eq!(s.harvest_by_memory("x").unwrap().is_some(), true);
        s.harvest_remove("m:/d/a.md").unwrap();
        assert!(s.harvest_get("m:/d/a.md").unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn db_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("sub/knowledge.db");
        Store::open(&p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod store;`. Run: `cargo test memory::store`. Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! Each machine's local copy (offline-first) plus the outbound queue.
//! `~/.config/atem/knowledge.db`, mode 0600. Holds no secrets by construction.
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::memory::model::{Memory, Scope, Skill};

pub const MEMORY_CURSOR: &str = "memory_cursor";
pub const SKILL_CURSOR: &str = "skill_cursor";
pub const LAST_SYNC_AT: &str = "last_sync_at";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PendingOp {
    AddMemory { memory: Memory },
    DeleteMemory { id: String },
    PushSkill { skill: Skill, base_version: i64 },
    DeleteSkill { scope: Scope, project: String, name: String },
    PurgeSkill { scope: Scope, project: String, name: String, versions: Option<Vec<i64>> },
}

impl PendingOp {
    pub fn is_memory(&self) -> bool {
        matches!(self, PendingOp::AddMemory { .. } | PendingOp::DeleteMemory { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarvestStatus {
    Synced,
    HeldBack,
    Excluded,
}

impl HarvestStatus {
    fn as_str(&self) -> &'static str {
        match self {
            HarvestStatus::Synced => "synced",
            HarvestStatus::HeldBack => "held_back",
            HarvestStatus::Excluded => "excluded",
        }
    }
    fn parse(s: &str) -> HarvestStatus {
        match s {
            "held_back" => HarvestStatus::HeldBack,
            "excluded" => HarvestStatus::Excluded,
            _ => HarvestStatus::Synced,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HarvestEntry {
    pub origin: String,
    pub memory_id: String,
    pub content_hash: String,
    pub status: HarvestStatus,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS memories (
  id TEXT PRIMARY KEY, scope TEXT NOT NULL, project TEXT NOT NULL, machine TEXT NOT NULL,
  content TEXT NOT NULL, content_hash TEXT NOT NULL, confidence TEXT NOT NULL,
  source_agent TEXT NOT NULL, source_machine TEXT NOT NULL, created_at INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0, seq INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS skills (
  scope TEXT NOT NULL, project TEXT NOT NULL, name TEXT NOT NULL,
  version INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL,
  PRIMARY KEY (scope, project, name));
CREATE TABLE IF NOT EXISTS pending_ops (n INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sync_state (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS harvest_map (
  origin TEXT PRIMARY KEY, memory_id TEXT NOT NULL, content_hash TEXT NOT NULL, status TEXT NOT NULL);
";

const MEM_COLS: &str = "id, scope, project, machine, content, content_hash, confidence, source_agent, source_machine, created_at, deleted, seq";

fn row_to_memory(r: &rusqlite::Row) -> rusqlite::Result<Memory> {
    let scope: String = r.get(1)?;
    Ok(Memory {
        id: r.get(0)?,
        scope: Scope::parse(&scope).unwrap_or(Scope::Global),
        project: r.get(2)?,
        machine: r.get(3)?,
        content: r.get(4)?,
        content_hash: r.get(5)?,
        confidence: r.get(6)?,
        source_agent: r.get(7)?,
        source_machine: r.get(8)?,
        created_at: r.get(9)?,
        deleted: r.get::<_, i64>(10)? != 0,
        seq: r.get(11)?,
    })
}

fn row_to_harvest(r: &rusqlite::Row) -> rusqlite::Result<HarvestEntry> {
    let status: String = r.get(3)?;
    Ok(HarvestEntry { origin: r.get(0)?, memory_id: r.get(1)?, content_hash: r.get(2)?, status: HarvestStatus::parse(&status) })
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Store> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Store> {
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn })
    }

    // ── memories ────────────────────────────────────────────────────────
    pub fn upsert_memory(&self, m: &Memory) -> Result<()> {
        self.conn.execute(
            "INSERT INTO memories (id, scope, project, machine, content, content_hash, confidence, source_agent, source_machine, created_at, deleted, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(id) DO UPDATE SET scope=excluded.scope, project=excluded.project, machine=excluded.machine,
               content=excluded.content, content_hash=excluded.content_hash, confidence=excluded.confidence,
               source_agent=excluded.source_agent, source_machine=excluded.source_machine,
               created_at=excluded.created_at, deleted=excluded.deleted, seq=excluded.seq",
            params![m.id, m.scope.as_str(), m.project, m.machine, m.content, m.content_hash, m.confidence,
                    m.source_agent, m.source_machine, m.created_at, m.deleted as i64, m.seq],
        )?;
        Ok(())
    }

    pub fn get_memory(&self, id: &str) -> Result<Option<Memory>> {
        Ok(self.conn
            .query_row(&format!("SELECT {} FROM memories WHERE id = ?1", MEM_COLS), params![id], row_to_memory)
            .optional()?)
    }

    pub fn live_memories(&self) -> Result<Vec<Memory>> {
        let mut stmt = self.conn.prepare(&format!("SELECT {} FROM memories WHERE deleted = 0 ORDER BY created_at, id", MEM_COLS))?;
        let rows = stmt.query_map([], row_to_memory)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn find_live_by_hash(&self, scope: Scope, project: &str, machine: &str, hash: &str) -> Result<Option<Memory>> {
        Ok(self.conn
            .query_row(
                &format!("SELECT {} FROM memories WHERE deleted = 0 AND scope = ?1 AND project = ?2 AND machine = ?3 AND content_hash = ?4 LIMIT 1", MEM_COLS),
                params![scope.as_str(), project, machine, hash],
                row_to_memory,
            )
            .optional()?)
    }

    /// Tombstone: also clears the text so it doesn't linger locally.
    pub fn mark_memory_deleted(&self, id: &str) -> Result<()> {
        self.conn.execute("UPDATE memories SET deleted = 1, content = '', content_hash = '' WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn set_memory_seq(&self, id: &str, seq: i64) -> Result<()> {
        self.conn.execute("UPDATE memories SET seq = ?2 WHERE id = ?1", params![id, seq])?;
        Ok(())
    }

    /// The relay deduped our add to an existing id.
    pub fn rewrite_memory_id(&self, old: &str, new: &str) -> Result<()> {
        if old == new {
            return Ok(());
        }
        let exists: bool = self.conn.query_row("SELECT EXISTS(SELECT 1 FROM memories WHERE id = ?1)", params![new], |r| r.get(0))?;
        if exists {
            self.conn.execute("DELETE FROM memories WHERE id = ?1", params![old])?;
        } else {
            self.conn.execute("UPDATE memories SET id = ?2 WHERE id = ?1", params![old, new])?;
        }
        self.conn.execute("UPDATE harvest_map SET memory_id = ?2 WHERE memory_id = ?1", params![old, new])?;
        Ok(())
    }

    // ── skills (latest version per scope/project/name) ─────────────────
    pub fn put_skill(&self, s: &Skill) -> Result<()> {
        let data = serde_json::to_string(s)?;
        self.conn.execute(
            "INSERT INTO skills (scope, project, name, version, deleted, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(scope, project, name) DO UPDATE SET version=excluded.version, deleted=excluded.deleted, data=excluded.data",
            params![s.scope.as_str(), s.project, s.name, s.version, s.deleted as i64, data],
        )?;
        Ok(())
    }

    pub fn get_skill(&self, scope: Scope, project: &str, name: &str) -> Result<Option<Skill>> {
        let data: Option<String> = self.conn
            .query_row("SELECT data FROM skills WHERE scope = ?1 AND project = ?2 AND name = ?3",
                       params![scope.as_str(), project, name], |r| r.get(0))
            .optional()?;
        data.map(|d| serde_json::from_str(&d).map_err(anyhow::Error::from)).transpose()
    }

    /// Includes deleted skills (apply uses them to remove directories).
    pub fn all_skills(&self) -> Result<Vec<Skill>> {
        let mut stmt = self.conn.prepare("SELECT data FROM skills ORDER BY scope, project, name")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    pub fn live_skills(&self) -> Result<Vec<Skill>> {
        Ok(self.all_skills()?.into_iter().filter(|s| !s.deleted).collect())
    }

    // ── pending ops ─────────────────────────────────────────────────────
    pub fn enqueue(&self, op: &PendingOp) -> Result<()> {
        self.conn.execute("INSERT INTO pending_ops (payload) VALUES (?1)", params![serde_json::to_string(op)?])?;
        Ok(())
    }

    pub fn pending(&self) -> Result<Vec<(i64, PendingOp)>> {
        let mut stmt = self.conn.prepare("SELECT n, payload FROM pending_ops ORDER BY n")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (n, p) = row?;
            out.push((n, serde_json::from_str(&p)?));
        }
        Ok(out)
    }

    pub fn ack(&self, n: i64) -> Result<()> {
        self.conn.execute("DELETE FROM pending_ops WHERE n = ?1", params![n])?;
        Ok(())
    }

    pub fn pending_count(&self) -> Result<usize> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM pending_ops", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    // ── sync state ──────────────────────────────────────────────────────
    pub fn get_state(&self, key: &str) -> Result<i64> {
        Ok(self.conn
            .query_row("SELECT value FROM sync_state WHERE key = ?1", params![key], |r| r.get(0))
            .optional()?
            .unwrap_or(0))
    }

    pub fn set_state(&self, key: &str, value: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sync_state (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ── harvest map ─────────────────────────────────────────────────────
    pub fn harvest_get(&self, origin: &str) -> Result<Option<HarvestEntry>> {
        Ok(self.conn
            .query_row("SELECT origin, memory_id, content_hash, status FROM harvest_map WHERE origin = ?1", params![origin], row_to_harvest)
            .optional()?)
    }

    pub fn harvest_put(&self, e: &HarvestEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO harvest_map (origin, memory_id, content_hash, status) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(origin) DO UPDATE SET memory_id=excluded.memory_id, content_hash=excluded.content_hash, status=excluded.status",
            params![e.origin, e.memory_id, e.content_hash, e.status.as_str()],
        )?;
        Ok(())
    }

    /// Exact prefix match (no LIKE wildcards).
    pub fn harvest_with_prefix(&self, prefix: &str) -> Result<Vec<HarvestEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT origin, memory_id, content_hash, status FROM harvest_map WHERE substr(origin, 1, length(?1)) = ?1 ORDER BY origin",
        )?;
        let rows = stmt.query_map(params![prefix], row_to_harvest)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn harvest_by_memory(&self, memory_id: &str) -> Result<Option<HarvestEntry>> {
        Ok(self.conn
            .query_row("SELECT origin, memory_id, content_hash, status FROM harvest_map WHERE memory_id = ?1 LIMIT 1", params![memory_id], row_to_harvest)
            .optional()?)
    }

    pub fn harvest_remove(&self, origin: &str) -> Result<()> {
        self.conn.execute("DELETE FROM harvest_map WHERE origin = ?1", params![origin])?;
        Ok(())
    }

    pub fn held_back_count(&self) -> Result<usize> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM harvest_map WHERE status = 'held_back'", [], |r| r.get(0))?;
        Ok(n as usize)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test memory::store`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add src/memory/store.rs src/memory/mod.rs
git commit -m "feat(memory): local SQLite store, pending queue, harvest map

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 10: `adapters.rs` — apply to Claude and Codex (cross-agent)

**Files:**
- Create: `src/memory/adapters.rs`
- Modify: `src/memory/mod.rs` (add `pub mod adapters;`)

**Interfaces:**
- Consumes: `block::*`, `gitguard::*`, `skills_fs::*`, `project::RepoInfo`, `model::{Memory, Scope, Skill}`.
- Produces: `Mark {Applied, Skipped, Clash}` with `symbol()`; `ReportLine { mark, target, detail }` with `render()`; `Ctx { home, repo: Option<RepoInfo>, atem_id, allow_tracked }`; `Agent {Claude, Codex}` with `all()`, `name()`, `discover(&Ctx)`, `global_memory_file(&Ctx)`, `project_memory_file(&Path)`, `skills_root(&Ctx, Scope) -> Option<PathBuf>`, `instructions()`, `skips_echo(&Memory, &Ctx)`; `valid_skill_name(&str) -> bool`; `apply_memory(Agent, &Ctx, &[Memory]) -> Vec<ReportLine>`; `apply_skills(Agent, &Ctx, &[Skill]) -> Vec<ReportLine>`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash};
    use std::collections::BTreeMap;
    use std::process::Command;

    fn run_git(dir: &Path, args: &[&str]) {
        assert!(Command::new("git").arg("-C").arg(dir).args(args).output().unwrap().status.success());
    }

    fn setup() -> (tempfile::TempDir, Ctx) {
        let td = tempfile::tempdir().unwrap();
        let base = td.path().canonicalize().unwrap();
        let home = base.join("home");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        let root = base.join("repo");
        std::fs::create_dir_all(&root).unwrap();
        run_git(&root, &["init", "-q"]);
        let ctx = Ctx {
            home,
            repo: Some(RepoInfo { root, key: "github.com/acme/dialf".into() }),
            atem_id: "nixps-0001".into(),
            allow_tracked: false,
        };
        (td, ctx)
    }

    fn m(scope: Scope, project: &str, machine: &str, content: &str, agent: &str, src: &str) -> Memory {
        Memory {
            id: format!("mem_{}", content_hash(content)), scope, project: project.into(), machine: machine.into(),
            content: content.into(), content_hash: content_hash(content), confidence: "medium".into(),
            source_agent: agent.into(), source_machine: src.into(), created_at: 1, deleted: false, seq: 0,
        }
    }

    fn sk(scope: Scope, project: &str, name: &str, version: i64, body: &str) -> Skill {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), body.as_bytes().to_vec());
        Skill {
            scope, project: project.into(), name: name.into(), version,
            content_hash: skill_hash(&files), files,
            source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, deleted: false, seq: 0,
        }
    }

    fn read(p: PathBuf) -> String {
        std::fs::read_to_string(p).unwrap_or_default()
    }

    #[test]
    fn scopes_route_to_the_right_files() {
        let (_td, ctx) = setup();
        let mems = vec![
            m(Scope::Global, "", "", "Run tests before committing", "cli", "x"),
            m(Scope::Machine, "", "nixps-0001", "nixps runs NixOS + Niri", "cli", "x"),
            m(Scope::Machine, "", "hal-0002", "HAL9000 has the GPU", "cli", "x"),
            m(Scope::Project, "github.com/acme/dialf", "", "DialF uses TCP 8765", "cli", "x"),
            m(Scope::Project, "github.com/acme/other", "", "Other uses 9999", "cli", "x"),
        ];
        apply_memory(Agent::Claude, &ctx, &mems);
        let global = read(ctx.home.join(".claude/CLAUDE.md"));
        assert!(global.contains("Run tests before committing") && global.contains("nixps runs NixOS"));
        assert!(!global.contains("HAL9000") && !global.contains("TCP 8765"));
        let local = read(ctx.repo.as_ref().unwrap().root.join("CLAUDE.local.md"));
        assert!(local.contains("DialF uses TCP 8765") && !local.contains("9999"));
    }

    #[test]
    fn instructions_per_agent() {
        let (_td, ctx) = setup();
        apply_memory(Agent::Claude, &ctx, &[]);
        apply_memory(Agent::Codex, &ctx, &[]);
        let claude = read(ctx.home.join(".claude/CLAUDE.md"));
        let codex = read(ctx.home.join(".codex/AGENTS.md"));
        assert!(claude.contains(CREDENTIAL_INSTRUCTION) && !claude.contains(CODEX_CAPTURE_INSTRUCTION));
        assert!(codex.contains(CREDENTIAL_INSTRUCTION) && codex.contains(CODEX_CAPTURE_INSTRUCTION));
    }

    #[test]
    fn claude_does_not_see_its_own_harvest_twice() {
        let (_td, ctx) = setup();
        let mems = vec![m(Scope::Global, "", "", "Prefers ripgrep", "claude", "nixps-0001")];
        apply_memory(Agent::Claude, &ctx, &mems);
        apply_memory(Agent::Codex, &ctx, &mems);
        assert!(!read(ctx.home.join(".claude/CLAUDE.md")).contains("Prefers ripgrep"));
        assert!(read(ctx.home.join(".codex/AGENTS.md")).contains("Prefers ripgrep"));
    }

    #[test]
    fn tracked_project_file_is_skipped_unless_allowed() {
        let (_td, mut ctx) = setup();
        let root = ctx.repo.as_ref().unwrap().root.clone();
        std::fs::write(root.join("AGENTS.md"), "team file\n").unwrap();
        run_git(&root, &["add", "AGENTS.md"]);
        let mems = vec![m(Scope::Project, "github.com/acme/dialf", "", "DialF uses TCP 8765", "cli", "x")];
        let report = apply_memory(Agent::Codex, &ctx, &mems);
        let line = report.iter().find(|l| l.target.ends_with("AGENTS.md") && !l.target.starts_with('~')).unwrap();
        assert_eq!(line.mark, Mark::Skipped);
        assert!(line.detail.contains("tracked"));
        assert_eq!(read(root.join("AGENTS.md")), "team file\n");
        ctx.allow_tracked = true;
        apply_memory(Agent::Codex, &ctx, &mems);
        assert!(read(root.join("AGENTS.md")).contains("TCP 8765"));
    }

    #[test]
    fn created_project_file_is_excluded_locally() {
        let (_td, ctx) = setup();
        apply_memory(Agent::Claude, &ctx, &[]);
        let root = &ctx.repo.as_ref().unwrap().root;
        assert!(read(root.join(".git/info/exclude")).lines().any(|l| l == "/CLAUDE.local.md"));
    }

    #[test]
    fn user_text_kept_and_broken_markers_refused() {
        let (_td, ctx) = setup();
        let f = ctx.home.join(".claude/CLAUDE.md");
        std::fs::write(&f, "# mine\n").unwrap();
        apply_memory(Agent::Claude, &ctx, &[]);
        assert!(read(f.clone()).starts_with("# mine\n"));
        let broken = format!("# mine\n{}\n", crate::memory::block::BEGIN);
        std::fs::write(&f, &broken).unwrap();
        let report = apply_memory(Agent::Claude, &ctx, &[]);
        assert_eq!(report[0].mark, Mark::Skipped);
        assert_eq!(read(f), broken);
    }

    #[test]
    fn skills_written_for_both_agents() {
        let (_td, ctx) = setup();
        let skills = vec![sk(Scope::Global, "", "deploy-check", 3, "# deploy")];
        let r1 = apply_skills(Agent::Claude, &ctx, &skills);
        let r2 = apply_skills(Agent::Codex, &ctx, &skills);
        assert_eq!(r1[0].mark, Mark::Applied);
        assert_eq!(r2[0].mark, Mark::Applied);
        assert!(ctx.home.join(".claude/skills/deploy-check/SKILL.md").exists());
        assert!(ctx.home.join(".agents/skills/deploy-check/SKILL.md").exists());
    }

    #[test]
    fn unmanaged_skill_is_a_clash() {
        let (_td, ctx) = setup();
        let dir = ctx.home.join(".claude/skills/review");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "# mine").unwrap();
        let r = apply_skills(Agent::Claude, &ctx, &[sk(Scope::Global, "", "review", 1, "# theirs")]);
        assert_eq!(r[0].mark, Mark::Clash);
        assert_eq!(read(dir.join("SKILL.md")), "# mine");
    }

    #[test]
    fn drifted_skill_is_not_overwritten_or_removed() {
        let (_td, ctx) = setup();
        apply_skills(Agent::Claude, &ctx, &[sk(Scope::Global, "", "demo", 1, "# v1")]);
        let f = ctx.home.join(".claude/skills/demo/SKILL.md");
        std::fs::write(&f, "# my edit").unwrap();
        let r = apply_skills(Agent::Claude, &ctx, &[sk(Scope::Global, "", "demo", 2, "# v2")]);
        assert_eq!(r[0].mark, Mark::Skipped);
        assert!(r[0].detail.contains("atem skill add"));
        let mut gone = sk(Scope::Global, "", "demo", 3, "");
        gone.deleted = true;
        apply_skills(Agent::Claude, &ctx, &[gone]);
        assert_eq!(read(f), "# my edit");
    }

    #[test]
    fn deleted_managed_skill_is_removed() {
        let (_td, ctx) = setup();
        apply_skills(Agent::Claude, &ctx, &[sk(Scope::Global, "", "demo", 1, "# v1")]);
        let mut gone = sk(Scope::Global, "", "demo", 2, "");
        gone.deleted = true;
        let r = apply_skills(Agent::Claude, &ctx, &[gone]);
        assert_eq!(r[0].detail, "removed");
        assert!(!ctx.home.join(".claude/skills/demo").exists());
    }

    #[test]
    fn project_skill_only_in_matching_repo_and_excluded() {
        let (_td, ctx) = setup();
        let r = apply_skills(Agent::Claude, &ctx, &[
            sk(Scope::Project, "github.com/acme/dialf", "dialf-run", 1, "# run"),
            sk(Scope::Project, "github.com/acme/other", "other-run", 1, "# other"),
        ]);
        assert_eq!(r.len(), 1);
        let root = &ctx.repo.as_ref().unwrap().root;
        assert!(root.join(".claude/skills/dialf-run/SKILL.md").exists());
        assert!(read(root.join(".git/info/exclude")).lines().any(|l| l == "/.claude/skills/dialf-run"));
    }

    #[test]
    fn invalid_skill_names_are_rejected() {
        assert!(valid_skill_name("deploy-check_2.0"));
        for bad in ["", ".", "..", "a/b", "../x", "a b"] {
            assert!(!valid_skill_name(bad), "{}", bad);
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod adapters;`. Run: `cargo test memory::adapters`. Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! Cross-agent apply: one canonical store, written into each agent's native
//! locations. Agents only declare paths and instruction lines; one shared
//! code path does the writing and the safety checks.
use std::path::{Path, PathBuf};
use crate::memory::block::{self, CODEX_CAPTURE_INSTRUCTION, CREDENTIAL_INSTRUCTION};
use crate::memory::gitguard;
use crate::memory::model::{Memory, Scope, Skill};
use crate::memory::project::RepoInfo;
use crate::memory::skills_fs::{self, DirState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Applied,
    Skipped,
    Clash,
}

impl Mark {
    pub fn symbol(&self) -> &'static str {
        match self {
            Mark::Applied => "✓",
            Mark::Skipped => "◐",
            Mark::Clash => "✗",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReportLine {
    pub mark: Mark,
    pub target: String,
    pub detail: String,
}

impl ReportLine {
    pub fn render(&self) -> String {
        format!("{} {:<44} {}", self.mark.symbol(), self.target, self.detail)
    }
}

#[derive(Debug, Clone)]
pub struct Ctx {
    pub home: PathBuf,
    pub repo: Option<RepoInfo>,
    pub atem_id: String,
    pub allow_tracked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Codex,
}

impl Agent {
    pub fn all() -> [Agent; 2] {
        [Agent::Claude, Agent::Codex]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
        }
    }

    pub fn discover(&self, ctx: &Ctx) -> bool {
        match self {
            Agent::Claude => ctx.home.join(".claude").is_dir(),
            Agent::Codex => ctx.home.join(".codex").is_dir(),
        }
    }

    pub fn global_memory_file(&self, ctx: &Ctx) -> PathBuf {
        match self {
            Agent::Claude => ctx.home.join(".claude").join("CLAUDE.md"),
            Agent::Codex => ctx.home.join(".codex").join("AGENTS.md"),
        }
    }

    pub fn project_memory_file(&self, repo_root: &Path) -> PathBuf {
        match self {
            Agent::Claude => repo_root.join("CLAUDE.local.md"),
            Agent::Codex => repo_root.join("AGENTS.md"),
        }
    }

    pub fn skills_root(&self, ctx: &Ctx, scope: Scope) -> Option<PathBuf> {
        let dot = match self {
            Agent::Claude => ".claude",
            Agent::Codex => ".agents",
        };
        match scope {
            Scope::Global => Some(ctx.home.join(dot).join("skills")),
            Scope::Project => ctx.repo.as_ref().map(|r| r.root.join(dot).join("skills")),
            Scope::Machine => None,
        }
    }

    pub fn instructions(&self) -> Vec<&'static str> {
        match self {
            Agent::Claude => vec![CREDENTIAL_INSTRUCTION],
            Agent::Codex => vec![CODEX_CAPTURE_INSTRUCTION, CREDENTIAL_INSTRUCTION],
        }
    }

    /// Claude already has memories it harvested itself on this machine.
    pub fn skips_echo(&self, m: &Memory, ctx: &Ctx) -> bool {
        *self == Agent::Claude && m.source_agent == "claude" && m.source_machine == ctx.atem_id
    }
}

pub fn valid_skill_name(n: &str) -> bool {
    !n.is_empty() && n != "." && n != ".."
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn display_path(p: &Path, ctx: &Ctx) -> String {
    match p.strip_prefix(&ctx.home) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => p.display().to_string(),
    }
}

fn line(mark: Mark, target: String, detail: impl Into<String>) -> ReportLine {
    ReportLine { mark, target, detail: detail.into() }
}

pub fn apply_memory(agent: Agent, ctx: &Ctx, mems: &[Memory]) -> Vec<ReportLine> {
    let visible: Vec<Memory> = mems.iter().filter(|m| !m.deleted && !agent.skips_echo(m, ctx)).cloned().collect();
    let global: Vec<Memory> = visible.iter()
        .filter(|m| m.scope == Scope::Global || (m.scope == Scope::Machine && m.machine == ctx.atem_id))
        .cloned().collect();
    let instr = agent.instructions();
    let mut report = vec![write_block(&agent.global_memory_file(ctx), None, &global, &instr, ctx)];
    if let Some(repo) = &ctx.repo {
        let proj: Vec<Memory> = visible.iter()
            .filter(|m| m.scope == Scope::Project && m.project == repo.key)
            .cloned().collect();
        report.push(write_block(&agent.project_memory_file(&repo.root), Some(&repo.root), &proj, &instr, ctx));
    }
    report
}

fn write_block(path: &Path, repo_root: Option<&Path>, mems: &[Memory], instr: &[&str], ctx: &Ctx) -> ReportLine {
    let target = display_path(path, ctx);
    if let Some(root) = repo_root {
        if !ctx.allow_tracked && gitguard::is_tracked(root, path) {
            return line(Mark::Skipped, target, "skipped: tracked by git");
        }
    }
    let existed = path.exists();
    let current = if existed {
        match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => return line(Mark::Skipped, target, format!("skipped: unreadable ({})", e)),
        }
    } else {
        String::new()
    };
    let entries = block::select_entries(mems);
    let rendered = block::render_block(&entries, instr);
    let next = match block::splice(&current, &rendered) {
        Ok(n) => n,
        Err(e) => return line(Mark::Skipped, target, format!("skipped: {}", e)),
    };
    if next != current {
        if let Some(dir) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                return line(Mark::Skipped, target, format!("skipped: {}", e));
            }
        }
        if let Err(e) = std::fs::write(path, &next) {
            return line(Mark::Skipped, target, format!("skipped: {}", e));
        }
    }
    if let (Some(root), false) = (repo_root, existed) {
        let _ = gitguard::exclude_locally(root, path);
    }
    line(Mark::Applied, target, format!("{} memories", entries.len()))
}

pub fn apply_skills(agent: Agent, ctx: &Ctx, skills: &[Skill]) -> Vec<ReportLine> {
    let mut report = Vec::new();
    for s in skills {
        if s.scope == Scope::Project && ctx.repo.as_ref().map(|r| r.key != s.project).unwrap_or(true) {
            continue;
        }
        let Some(root) = agent.skills_root(ctx, s.scope) else { continue };
        if !valid_skill_name(&s.name) {
            report.push(line(Mark::Clash, display_path(&root, ctx), format!("skipped: invalid skill name {:?}", s.name)));
            continue;
        }
        let dir = root.join(&s.name);
        let repo_root = if s.scope == Scope::Project { ctx.repo.as_ref().map(|r| r.root.clone()) } else { None };
        if let Some(l) = apply_one_skill(&dir, repo_root.as_deref(), s, ctx) {
            report.push(l);
        }
    }
    report
}

fn apply_one_skill(dir: &Path, repo_root: Option<&Path>, s: &Skill, ctx: &Ctx) -> Option<ReportLine> {
    let target = display_path(dir, ctx);
    if let Some(root) = repo_root {
        if !ctx.allow_tracked && gitguard::is_tracked(root, dir) {
            return Some(line(Mark::Skipped, target, "skipped: tracked by git"));
        }
    }
    match skills_fs::dir_state(dir) {
        DirState::Unmanaged => Some(line(Mark::Clash, target, "skipped: unmanaged skill with same name")),
        DirState::Managed(marker) => {
            if skills_fs::is_drifted(dir, &marker) {
                return Some(line(Mark::Skipped, target,
                    format!("skipped: edited locally — run `atem skill add {}` to push the edit", dir.display())));
            }
            if s.deleted {
                return Some(match std::fs::remove_dir_all(dir) {
                    Ok(()) => line(Mark::Applied, target, "removed"),
                    Err(e) => line(Mark::Skipped, target, format!("skipped: {}", e)),
                });
            }
            if marker.hash == s.content_hash && marker.version == s.version {
                return Some(line(Mark::Applied, target, format!("v{} (unchanged)", s.version)));
            }
            Some(match skills_fs::write_skill_dir(dir, s) {
                Ok(()) => line(Mark::Applied, target, format!("v{}", s.version)),
                Err(e) => line(Mark::Skipped, target, format!("skipped: {}", e)),
            })
        }
        DirState::Missing => {
            if s.deleted {
                return None;
            }
            Some(match skills_fs::write_skill_dir(dir, s) {
                Ok(()) => {
                    if let Some(root) = repo_root {
                        let _ = gitguard::exclude_locally(root, dir);
                    }
                    line(Mark::Applied, target, format!("v{}", s.version))
                }
                Err(e) => line(Mark::Skipped, target, format!("skipped: {}", e)),
            })
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test memory::adapters`
Expected: 12 passed.

- [ ] **Step 5: Commit**

```bash
git add src/memory/adapters.rs src/memory/mod.rs
git commit -m "feat(memory): Claude + Codex adapters for memory blocks and skills

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 11: `api.rs` — the relay client (cross-machine)

**Files:**
- Create: `src/memory/api.rs`
- Modify: `src/memory/mod.rs` (add `pub mod api;`)

**Interfaces:**
- Consumes: `model::{Memory, Skill}`, `store::PendingOp`.
- Produces: `PULL_LIMIT: u32 = 200`; `ApiRequest { method, url, body }`; `op_to_wire(&PendingOp) -> Value`; `memory_batch_request`, `memory_pull_request`, `skills_batch_request`, `skills_pull_request`; `OpResult` (with `Default`); `ApiError {Offline(String), Http(u16, String), Decode(String)}`; `KnowledgeClient::new(base, client_id, token)` with `push(&[&PendingOp], memory: bool)`, `pull_memories(since)`, `pull_skills(since)`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash, Scope};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn sample() -> Memory {
        Memory {
            id: "mem_1".into(), scope: Scope::Project, project: "github.com/acme/dialf".into(), machine: String::new(),
            content: "DialF uses TCP 8765".into(), content_hash: content_hash("DialF uses TCP 8765"),
            confidence: "high".into(), source_agent: "claude".into(), source_machine: "nixps-0001".into(),
            created_at: 1700000000, deleted: false, seq: 0,
        }
    }

    #[test]
    fn pull_request_urls() {
        let r = memory_pull_request("https://relay.example/", "inst 1", 42, 200);
        assert_eq!(r.method, "GET");
        assert_eq!(r.url, "https://relay.example/api/memory?id=inst%201&since=42&limit=200");
        assert!(r.body.is_none());
        assert_eq!(skills_pull_request("https://relay.example", "i", 0, 5).url, "https://relay.example/api/skills?id=i&since=0&limit=5");
    }

    #[test]
    fn memory_batch_body() {
        let add = PendingOp::AddMemory { memory: sample() };
        let del = PendingOp::DeleteMemory { id: "mem_x".into() };
        let r = memory_batch_request("https://relay.example", "inst", &[&add, &del]);
        assert_eq!(r.method, "POST");
        assert_eq!(r.url, "https://relay.example/api/memory/batch?id=inst");
        let body = r.body.unwrap();
        assert_eq!(body["ops"][0]["op"], "add");
        assert_eq!(body["ops"][0]["memory"]["id"], "mem_1");
        assert_eq!(body["ops"][0]["memory"]["scope"], "project");
        assert_eq!(body["ops"][1], json!({"op": "delete", "id": "mem_x"}));
    }

    #[test]
    fn skill_ops_wire() {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"hello".to_vec());
        let skill = Skill {
            scope: Scope::Global, project: String::new(), name: "demo".into(), version: 2,
            content_hash: skill_hash(&files), files,
            source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, deleted: false, seq: 0,
        };
        let push = op_to_wire(&PendingOp::PushSkill { skill, base_version: 1 });
        assert_eq!(push["op"], "push");
        assert_eq!(push["base_version"], 1);
        assert_eq!(push["skill"]["files"]["SKILL.md"], "aGVsbG8=");
        let del = op_to_wire(&PendingOp::DeleteSkill { scope: Scope::Global, project: String::new(), name: "demo".into() });
        assert_eq!(del, json!({"op": "delete", "scope": "global", "project": "", "name": "demo"}));
        let purge_all = op_to_wire(&PendingOp::PurgeSkill { scope: Scope::Global, project: String::new(), name: "demo".into(), versions: None });
        assert_eq!(purge_all["versions"], serde_json::Value::Null);
        let purge_one = op_to_wire(&PendingOp::PurgeSkill { scope: Scope::Global, project: String::new(), name: "demo".into(), versions: Some(vec![2]) });
        assert_eq!(purge_one["versions"], json!([2]));
    }

    #[test]
    fn op_result_defaults() {
        let r: OpResult = serde_json::from_value(json!({"ok": true})).unwrap();
        assert!(r.ok && r.canonical_id.is_none() && !r.superseded_concurrent);
    }

    #[test]
    fn api_error_display() {
        assert!(ApiError::Offline("x".into()).to_string().contains("unreachable"));
        assert!(ApiError::Http(403, "no".into()).to_string().contains("403"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod api;`. Run: `cargo test memory::api`. Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! Relay client for /api/memory and /api/skills. Request building is pure
//! (unit-tested); `KnowledgeClient` only sends. Auth = the SSO token from
//! `atem login`, so any logged-in machine on any network can sync.
use serde::Deserialize;
use serde_json::{json, Value};
use crate::memory::model::{Memory, Skill};
use crate::memory::store::PendingOp;

pub const PULL_LIMIT: u32 = 200;

#[derive(Debug, Clone, PartialEq)]
pub struct ApiRequest {
    pub method: &'static str,
    pub url: String,
    pub body: Option<Value>,
}

fn base_trim(b: &str) -> &str {
    b.trim_end_matches('/')
}

fn enc(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

pub fn op_to_wire(op: &PendingOp) -> Value {
    match op {
        PendingOp::AddMemory { memory } => json!({"op": "add", "memory": memory}),
        PendingOp::DeleteMemory { id } => json!({"op": "delete", "id": id}),
        PendingOp::PushSkill { skill, base_version } => json!({"op": "push", "skill": skill, "base_version": base_version}),
        PendingOp::DeleteSkill { scope, project, name } => json!({"op": "delete", "scope": scope, "project": project, "name": name}),
        PendingOp::PurgeSkill { scope, project, name, versions } => json!({"op": "purge", "scope": scope, "project": project, "name": name, "versions": versions}),
    }
}

fn batch(base: &str, client_id: &str, kind: &str, ops: &[&PendingOp]) -> ApiRequest {
    ApiRequest {
        method: "POST",
        url: format!("{}/api/{}/batch?id={}", base_trim(base), kind, enc(client_id)),
        body: Some(json!({"ops": ops.iter().map(|o| op_to_wire(o)).collect::<Vec<_>>()})),
    }
}

fn pull(base: &str, client_id: &str, kind: &str, since: i64, limit: u32) -> ApiRequest {
    ApiRequest {
        method: "GET",
        url: format!("{}/api/{}?id={}&since={}&limit={}", base_trim(base), kind, enc(client_id), since, limit),
        body: None,
    }
}

pub fn memory_batch_request(base: &str, client_id: &str, ops: &[&PendingOp]) -> ApiRequest {
    batch(base, client_id, "memory", ops)
}
pub fn skills_batch_request(base: &str, client_id: &str, ops: &[&PendingOp]) -> ApiRequest {
    batch(base, client_id, "skills", ops)
}
pub fn memory_pull_request(base: &str, client_id: &str, since: i64, limit: u32) -> ApiRequest {
    pull(base, client_id, "memory", since, limit)
}
pub fn skills_pull_request(base: &str, client_id: &str, since: i64, limit: u32) -> ApiRequest {
    pull(base, client_id, "skills", since, limit)
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct OpResult {
    pub ok: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub canonical_id: Option<String>,
    #[serde(default)]
    pub seq: Option<i64>,
    #[serde(default)]
    pub version: Option<i64>,
    #[serde(default)]
    pub superseded_concurrent: bool,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Deserialize)]
struct BatchResponse {
    results: Vec<OpResult>,
}
#[derive(Deserialize)]
struct MemoryPage {
    memories: Vec<Memory>,
}
#[derive(Deserialize)]
struct SkillPage {
    skills: Vec<Skill>,
}

#[derive(Debug)]
pub enum ApiError {
    /// Network failure: changes stay queued and sync next time.
    Offline(String),
    Http(u16, String),
    Decode(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Offline(e) => write!(f, "relay unreachable: {}", e),
            ApiError::Http(code, body) => write!(f, "relay returned {}: {}", code, body),
            ApiError::Decode(e) => write!(f, "unexpected relay response: {}", e),
        }
    }
}

impl std::error::Error for ApiError {}

pub struct KnowledgeClient {
    base: String,
    client_id: String,
    token: String,
    http: reqwest::Client,
}

impl KnowledgeClient {
    pub fn new(base: String, client_id: String, token: String) -> Self {
        Self {
            base,
            client_id,
            token,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    async fn send(&self, req: ApiRequest) -> Result<reqwest::Response, ApiError> {
        let mut rb = match req.method {
            "POST" => self.http.post(&req.url),
            _ => self.http.get(&req.url),
        };
        rb = rb.header("Authorization", format!("Bearer {}", self.token));
        if let Some(b) = req.body {
            rb = rb.json(&b);
        }
        let resp = rb.send().await.map_err(|e| ApiError::Offline(e.to_string()))?;
        if !resp.status().is_success() {
            let code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError::Http(code, body));
        }
        Ok(resp)
    }

    pub async fn push(&self, ops: &[&PendingOp], memory: bool) -> Result<Vec<OpResult>, ApiError> {
        let req = if memory {
            memory_batch_request(&self.base, &self.client_id, ops)
        } else {
            skills_batch_request(&self.base, &self.client_id, ops)
        };
        let resp: BatchResponse = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(resp.results)
    }

    pub async fn pull_memories(&self, since: i64) -> Result<Vec<Memory>, ApiError> {
        let req = memory_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
        let page: MemoryPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.memories)
    }

    pub async fn pull_skills(&self, since: i64) -> Result<Vec<Skill>, ApiError> {
        let req = skills_pull_request(&self.base, &self.client_id, since, PULL_LIMIT);
        let page: SkillPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.skills)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test memory::api`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/memory/api.rs src/memory/mod.rs
git commit -m "feat(memory): relay client for /api/memory and /api/skills

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 12: `sync.rs` — harvest → push → pull → apply (learning loop)

**Files:**
- Create: `src/memory/sync.rs`
- Modify: `src/memory/mod.rs` (add `pub mod sync;`)

**Interfaces:**
- Consumes: everything above.
- Produces: `HarvestSummary { added, removed, held_back: Vec<String> }`, `harvest_into_store(&Store, &[Harvested], prefix, project_key, atem_id) -> Result<HarvestSummary>`, `apply_push_results(&Store, &[(i64, PendingOp)], &[OpResult]) -> Result<Vec<String>>`, `apply_pulled_memories(&Store, &[Memory]) -> Result<i64>`, `apply_pulled_skills(&Store, &[Skill]) -> Result<i64>`, `apply_all(&Store, &Ctx) -> Result<Vec<ReportLine>>`, `SyncOptions { harvest }`, `SyncOutcome { harvest, pushed, pulled, notes, offline, report }`, `run_sync(&Store, Option<&KnowledgeClient>, &Ctx, &SyncOptions) -> Result<SyncOutcome>` (`None` client = offline).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash};
    use std::collections::BTreeMap;

    const P: &str = "m1:/home/u/.claude/projects/x/memory/";

    fn h(file: &str, scope: Scope, content: &str) -> Harvested {
        Harvested { origin: format!("{}{}", P, file), scope, content: content.into(), hash: content_hash(content) }
    }

    fn harvest(s: &Store, items: &[Harvested]) -> HarvestSummary {
        harvest_into_store(s, items, P, "github.com/acme/dialf", "m1").unwrap()
    }

    #[test]
    fn new_harvest_adds_and_queues() {
        let s = Store::open_in_memory().unwrap();
        let sum = harvest(&s, &[h("a.md", Scope::Project, "DialF uses TCP 8765")]);
        assert_eq!(sum.added, 1);
        let live = s.live_memories().unwrap();
        assert_eq!(live[0].project, "github.com/acme/dialf");
        assert_eq!(live[0].source_agent, "claude");
        assert!(matches!(s.pending().unwrap()[0].1, PendingOp::AddMemory { .. }));
    }

    #[test]
    fn unchanged_harvest_is_a_noop() {
        let s = Store::open_in_memory().unwrap();
        let items = [h("a.md", Scope::Global, "Prefers ripgrep")];
        harvest(&s, &items);
        let sum = harvest(&s, &items);
        assert_eq!((sum.added, sum.removed), (0, 0));
        assert_eq!(s.pending_count().unwrap(), 1);
    }

    #[test]
    fn changed_file_replaces_its_memory() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "v1 fact")]);
        let sum = harvest(&s, &[h("a.md", Scope::Global, "v2 fact")]);
        assert_eq!((sum.added, sum.removed), (1, 1));
        let live = s.live_memories().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].content, "v2 fact");
        assert_eq!(s.pending_count().unwrap(), 3); // add, delete, add
    }

    #[test]
    fn credential_is_held_back_once() {
        let s = Store::open_in_memory().unwrap();
        let items = [h("k.md", Scope::Project, "OpenAI key sk-abcdefghijklmnopqrstuvwx")];
        let sum = harvest(&s, &items);
        assert_eq!(sum.held_back.len(), 1);
        assert!(sum.held_back[0].contains("sk-…"));
        assert!(s.live_memories().unwrap().is_empty());
        assert_eq!(s.pending_count().unwrap(), 0);
        assert_eq!(s.held_back_count().unwrap(), 1);
        assert!(harvest(&s, &items).held_back.is_empty()); // not re-reported until the file changes
    }

    #[test]
    fn deleted_file_removes_its_memory() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        let sum = harvest(&s, &[]);
        assert_eq!(sum.removed, 1);
        assert!(s.live_memories().unwrap().is_empty());
        assert!(matches!(s.pending().unwrap().last().unwrap().1, PendingOp::DeleteMemory { .. }));
        assert!(s.harvest_with_prefix(P).unwrap().is_empty());
    }

    #[test]
    fn duplicate_content_reuses_existing_memory() {
        let s = Store::open_in_memory().unwrap();
        let existing = Memory {
            id: "mem_old".into(), scope: Scope::Global, project: String::new(), machine: String::new(),
            content: "Prefers ripgrep".into(), content_hash: content_hash("Prefers ripgrep"), confidence: "high".into(),
            source_agent: "cli".into(), source_machine: "m2".into(), created_at: 1, deleted: false, seq: 3,
        };
        s.upsert_memory(&existing).unwrap();
        let sum = harvest(&s, &[h("a.md", Scope::Global, "prefers  RIPGREP")]);
        assert_eq!(sum.added, 0);
        assert_eq!(s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id, "mem_old");
    }

    #[test]
    fn excluded_file_is_not_reharvested_until_changed() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "leaked thing")]);
        let origin = format!("{}a.md", P);
        let mut e = s.harvest_get(&origin).unwrap().unwrap();
        s.mark_memory_deleted(&e.memory_id).unwrap();
        e.status = HarvestStatus::Excluded;
        s.harvest_put(&e).unwrap();
        assert_eq!(harvest(&s, &[h("a.md", Scope::Global, "leaked thing")]).added, 0);
        assert_eq!(harvest(&s, &[h("a.md", Scope::Global, "cleaned thing")]).added, 1);
    }

    #[test]
    fn push_results_rewrite_canonical_id_and_ack() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        let sent = s.pending().unwrap();
        let PendingOp::AddMemory { memory } = &sent[0].1 else { panic!() };
        let local_id = memory.id.clone();
        let results = vec![OpResult { ok: true, canonical_id: Some("mem_canon".into()), seq: Some(9), ..Default::default() }];
        let notes = apply_push_results(&s, &sent, &results).unwrap();
        assert!(notes.is_empty());
        assert!(s.get_memory(&local_id).unwrap().is_none());
        assert_eq!(s.get_memory("mem_canon").unwrap().unwrap().seq, 9);
        assert_eq!(s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id, "mem_canon");
        assert_eq!(s.pending_count().unwrap(), 0);
    }

    #[test]
    fn refused_add_is_dropped_locally() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "something")]);
        let sent = s.pending().unwrap();
        let results = vec![OpResult { ok: false, error: Some("possible credential: jwt".into()), ..Default::default() }];
        let notes = apply_push_results(&s, &sent, &results).unwrap();
        assert!(notes[0].contains("possible credential"));
        assert!(s.live_memories().unwrap().is_empty());
        assert_eq!(s.pending_count().unwrap(), 0);
    }

    #[test]
    fn result_count_mismatch_is_an_error() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "x fact")]);
        assert!(apply_push_results(&s, &s.pending().unwrap(), &[]).is_err());
        assert_eq!(s.pending_count().unwrap(), 1);
    }

    #[test]
    fn pulled_memories_upsert_and_tombstone() {
        let s = Store::open_in_memory().unwrap();
        let mut a = Memory {
            id: "mem_a".into(), scope: Scope::Global, project: String::new(), machine: String::new(),
            content: "A".into(), content_hash: content_hash("A"), confidence: "medium".into(),
            source_agent: "codex".into(), source_machine: "hal".into(), created_at: 1, deleted: false, seq: 5,
        };
        let mut b = a.clone();
        b.id = "mem_b".into();
        b.seq = 7;
        b.deleted = true;
        assert_eq!(apply_pulled_memories(&s, &[a.clone(), b]).unwrap(), 7);
        let got_b = s.get_memory("mem_b").unwrap().unwrap();
        assert!(got_b.deleted && got_b.content.is_empty());
        a.seq = 8;
        apply_pulled_memories(&s, &[a]).unwrap();
        assert_eq!(s.live_memories().unwrap().len(), 1);
    }

    #[test]
    fn pulled_skills_follow_versions() {
        let s = Store::open_in_memory().unwrap();
        let mk = |v: i64, deleted: bool| {
            let mut files = BTreeMap::new();
            files.insert("SKILL.md".to_string(), format!("v{}", v).into_bytes());
            Skill {
                scope: Scope::Global, project: String::new(), name: "demo".into(), version: v,
                content_hash: skill_hash(&files), files,
                source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, deleted, seq: v * 10,
            }
        };
        apply_pulled_skills(&s, &[mk(2, false)]).unwrap();
        apply_pulled_skills(&s, &[mk(1, true)]).unwrap(); // older version (e.g. purged) → ignored
        assert_eq!(s.get_skill(Scope::Global, "", "demo").unwrap().unwrap().version, 2);
        assert_eq!(apply_pulled_skills(&s, &[mk(3, false)]).unwrap(), 30);
        apply_pulled_skills(&s, &[mk(3, true)]).unwrap(); // latest purged → deleted
        assert!(s.get_skill(Scope::Global, "", "demo").unwrap().unwrap().deleted);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod sync;`. Run: `cargo test memory::sync`. Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! The learning loop: harvest what Claude learned → push local changes →
//! pull what other agents/machines learned → apply to every agent here.
use anyhow::{anyhow, Result};
use std::collections::HashSet;
use crate::memory::adapters::{apply_memory, apply_skills, Agent, Ctx, ReportLine};
use crate::memory::api::{ApiError, KnowledgeClient, OpResult, PULL_LIMIT};
use crate::memory::block::contains_reserved;
use crate::memory::harvest::{claude_memory_dir, harvest_dir, origin_prefix, Harvested};
use crate::memory::model::{new_memory_id, now_secs, Memory, Scope, Skill};
use crate::memory::secrets::find_secrets;
use crate::memory::store::{HarvestEntry, HarvestStatus, PendingOp, Store, LAST_SYNC_AT, MEMORY_CURSOR, SKILL_CURSOR};

const PUSH_CHUNK: usize = 50;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct HarvestSummary {
    pub added: usize,
    pub removed: usize,
    pub held_back: Vec<String>,
}

fn drop_memory(store: &Store, id: &str) -> Result<()> {
    store.mark_memory_deleted(id)?;
    store.enqueue(&PendingOp::DeleteMemory { id: id.to_string() })
}

pub fn harvest_into_store(store: &Store, items: &[Harvested], prefix: &str, project_key: &str, atem_id: &str) -> Result<HarvestSummary> {
    let mut sum = HarvestSummary::default();
    let seen: HashSet<&str> = items.iter().map(|h| h.origin.as_str()).collect();
    for h in items {
        let prev = store.harvest_get(&h.origin)?;
        if let Some(p) = &prev {
            if p.content_hash == h.hash {
                continue; // unchanged (synced, held back, or excluded)
            }
            if p.status == HarvestStatus::Synced && !p.memory_id.is_empty() {
                drop_memory(store, &p.memory_id)?;
                sum.removed += 1;
            }
        }
        let findings = find_secrets(&h.content);
        if !findings.is_empty() || contains_reserved(&h.content) {
            let why = if findings.is_empty() {
                "contains the reserved token atem:memory:".to_string()
            } else {
                findings.iter().map(|f| format!("{} {}", f.kind, f.masked)).collect::<Vec<_>>().join(", ")
            };
            store.harvest_put(&HarvestEntry { origin: h.origin.clone(), memory_id: String::new(), content_hash: h.hash.clone(), status: HarvestStatus::HeldBack })?;
            sum.held_back.push(format!("{} — {}", h.origin, why));
            continue;
        }
        let project = if h.scope == Scope::Project { project_key.to_string() } else { String::new() };
        let id = match store.find_live_by_hash(h.scope, &project, "", &h.hash)? {
            Some(existing) => existing.id,
            None => {
                let m = Memory {
                    id: new_memory_id(), scope: h.scope, project, machine: String::new(),
                    content: h.content.clone(), content_hash: h.hash.clone(), confidence: "medium".into(),
                    source_agent: "claude".into(), source_machine: atem_id.to_string(),
                    created_at: now_secs(), deleted: false, seq: 0,
                };
                store.upsert_memory(&m)?;
                store.enqueue(&PendingOp::AddMemory { memory: m.clone() })?;
                sum.added += 1;
                m.id
            }
        };
        store.harvest_put(&HarvestEntry { origin: h.origin.clone(), memory_id: id, content_hash: h.hash.clone(), status: HarvestStatus::Synced })?;
    }
    for e in store.harvest_with_prefix(prefix)? {
        if seen.contains(e.origin.as_str()) {
            continue;
        }
        if e.status == HarvestStatus::Synced && !e.memory_id.is_empty() {
            drop_memory(store, &e.memory_id)?;
            sum.removed += 1;
        }
        store.harvest_remove(&e.origin)?;
    }
    Ok(sum)
}

fn describe(op: &PendingOp) -> String {
    match op {
        PendingOp::AddMemory { memory } => format!("memory {}", memory.id),
        PendingOp::DeleteMemory { id } => format!("delete of {}", id),
        PendingOp::PushSkill { skill, .. } => format!("skill {} v{}", skill.name, skill.version),
        PendingOp::DeleteSkill { name, .. } => format!("delete of skill {}", name),
        PendingOp::PurgeSkill { name, .. } => format!("purge of skill {}", name),
    }
}

/// Apply one batch's results. Every op is acked: successes are done, and
/// refusals (e.g. the server's secret check) must not retry forever.
pub fn apply_push_results(store: &Store, sent: &[(i64, PendingOp)], results: &[OpResult]) -> Result<Vec<String>> {
    if results.len() != sent.len() {
        return Err(anyhow!("relay returned {} results for {} changes", results.len(), sent.len()));
    }
    let mut notes = Vec::new();
    for ((n, op), r) in sent.iter().zip(results) {
        if r.ok {
            match op {
                PendingOp::AddMemory { memory } => {
                    let id = match &r.canonical_id {
                        Some(c) if c != &memory.id => {
                            store.rewrite_memory_id(&memory.id, c)?;
                            c.clone()
                        }
                        _ => memory.id.clone(),
                    };
                    if let Some(seq) = r.seq {
                        store.set_memory_seq(&id, seq)?;
                    }
                }
                PendingOp::PushSkill { skill, .. } => {
                    if let (Some(v), Some(cur)) = (r.version, store.get_skill(skill.scope, &skill.project, &skill.name)?) {
                        if cur.version == skill.version && v != skill.version {
                            let mut s = cur.clone();
                            s.version = v;
                            s.seq = r.seq.unwrap_or(s.seq);
                            store.put_skill(&s)?;
                        }
                    }
                    if r.superseded_concurrent {
                        notes.push(format!(
                            "skill {}: another machine pushed an edit at the same time; both versions are kept and v{} is now the latest",
                            skill.name, r.version.unwrap_or(skill.version)
                        ));
                    }
                }
                _ => {}
            }
        } else {
            notes.push(format!("relay refused {}: {}", describe(op), r.error.clone().unwrap_or_else(|| "unknown error".into())));
            if let PendingOp::AddMemory { memory } = op {
                store.mark_memory_deleted(&memory.id)?;
            }
        }
        store.ack(*n)?;
    }
    Ok(notes)
}

/// Returns the highest seq seen (the next cursor).
pub fn apply_pulled_memories(store: &Store, items: &[Memory]) -> Result<i64> {
    let mut max = 0;
    for m in items {
        max = max.max(m.seq);
        let mut row = m.clone();
        if row.deleted {
            row.content.clear();
            row.content_hash.clear();
        }
        store.upsert_memory(&row)?;
    }
    Ok(max)
}

/// Keeps the highest version per skill. An equal version replaces the local
/// copy (the server is authoritative, e.g. a purge tombstone).
pub fn apply_pulled_skills(store: &Store, items: &[Skill]) -> Result<i64> {
    let mut max = 0;
    for s in items {
        max = max.max(s.seq);
        match store.get_skill(s.scope, &s.project, &s.name)? {
            Some(cur) if s.version < cur.version => {}
            _ => store.put_skill(s)?,
        }
    }
    Ok(max)
}

pub fn apply_all(store: &Store, ctx: &Ctx) -> Result<Vec<ReportLine>> {
    let mems = store.live_memories()?;
    let skills = store.all_skills()?;
    let mut report = Vec::new();
    for agent in Agent::all() {
        if agent.discover(ctx) {
            report.extend(apply_memory(agent, ctx, &mems));
            report.extend(apply_skills(agent, ctx, &skills));
        }
    }
    Ok(report)
}

#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub harvest: bool,
}

#[derive(Debug, Default)]
pub struct SyncOutcome {
    pub harvest: Option<HarvestSummary>,
    pub pushed: usize,
    pub pulled: usize,
    pub notes: Vec<String>,
    pub offline: bool,
    pub report: Vec<ReportLine>,
}

async fn push_all(store: &Store, client: &KnowledgeClient, out: &mut SyncOutcome) -> Result<()> {
    let pending = store.pending()?;
    let (mem_ops, skill_ops): (Vec<_>, Vec<_>) = pending.into_iter().partition(|(_, op)| op.is_memory());
    for (group, is_mem) in [(mem_ops, true), (skill_ops, false)] {
        for chunk in group.chunks(PUSH_CHUNK) {
            if out.offline {
                return Ok(());
            }
            let refs: Vec<&PendingOp> = chunk.iter().map(|(_, op)| op).collect();
            match client.push(&refs, is_mem).await {
                Ok(results) => {
                    out.notes.extend(apply_push_results(store, chunk, &results)?);
                    out.pushed += chunk.len();
                }
                Err(ApiError::Offline(_)) => out.offline = true,
                Err(e) => {
                    out.notes.push(e.to_string());
                    break; // leave this group queued; try again next sync
                }
            }
        }
    }
    Ok(())
}

async fn pull_all(store: &Store, client: &KnowledgeClient, out: &mut SyncOutcome) -> Result<()> {
    loop {
        let since = store.get_state(MEMORY_CURSOR)?;
        match client.pull_memories(since).await {
            Ok(page) => {
                if page.is_empty() {
                    break;
                }
                let max = apply_pulled_memories(store, &page)?;
                store.set_state(MEMORY_CURSOR, max.max(since))?;
                out.pulled += page.len();
                if page.len() < PULL_LIMIT as usize {
                    break;
                }
            }
            Err(ApiError::Offline(_)) => {
                out.offline = true;
                return Ok(());
            }
            Err(e) => {
                out.notes.push(e.to_string());
                return Ok(());
            }
        }
    }
    loop {
        let since = store.get_state(SKILL_CURSOR)?;
        match client.pull_skills(since).await {
            Ok(page) => {
                if page.is_empty() {
                    break;
                }
                let max = apply_pulled_skills(store, &page)?;
                store.set_state(SKILL_CURSOR, max.max(since))?;
                out.pulled += page.len();
                if page.len() < PULL_LIMIT as usize {
                    break;
                }
            }
            Err(ApiError::Offline(_)) => {
                out.offline = true;
                return Ok(());
            }
            Err(e) => {
                out.notes.push(e.to_string());
                return Ok(());
            }
        }
    }
    Ok(())
}

/// `client = None` means offline: harvest and apply still run locally.
pub async fn run_sync(store: &Store, client: Option<&KnowledgeClient>, ctx: &Ctx, opts: &SyncOptions) -> Result<SyncOutcome> {
    let mut out = SyncOutcome::default();
    if opts.harvest {
        if let Some(repo) = &ctx.repo {
            let dir = claude_memory_dir(&ctx.home, &repo.root);
            let items = harvest_dir(&dir, &ctx.atem_id)?;
            out.harvest = Some(harvest_into_store(store, &items, &origin_prefix(&ctx.atem_id, &dir), &repo.key, &ctx.atem_id)?);
        }
    }
    match client {
        Some(c) => {
            push_all(store, c, &mut out).await?;
            if !out.offline {
                pull_all(store, c, &mut out).await?;
            }
            if !out.offline {
                store.set_state(LAST_SYNC_AT, now_secs())?;
            }
        }
        None => out.offline = true,
    }
    out.report = apply_all(store, ctx)?;
    Ok(out)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test memory::sync`
Expected: 12 passed.

- [ ] **Step 5: Commit**

```bash
git add src/memory/sync.rs src/memory/mod.rs
git commit -m "feat(memory): sync loop — harvest, push, pull, apply

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 13: CLI — `atem sync`, `atem memory …`, `atem skill …`

**Files:**
- Create: `src/memory/cmd.rs`
- Modify: `src/memory/mod.rs` (add `pub mod cmd;`)
- Modify: `src/cli.rs` (add `Sync`, `Memory`, `Skill` to `Commands`; the two new enums; three dispatch arms in `handle_cli_command`)
- Modify: `src/websocket_client.rs:1128` (`fn resolved_atem_id` → `pub(crate) fn resolved_atem_id`)

**Interfaces:**
- Consumes: all `memory::*` modules; `crate::config::AtemConfig::{load, config_dir, config_path, ensure_instance_id}`, `AtemConfig::astation_relay_url()`, `AtemConfig::effective_sso_url()`, `crate::sso_auth::valid_token(None, sso_url)`, `crate::credentials::CredentialStore::load()`, `crate::auth::get_hostname()`, `crate::websocket_client::resolved_atem_id(&str)`.
- Produces: `cmd::handle_sync(no_harvest, allow_tracked)`, `cmd::handle_memory(MemoryCommands)`, `cmd::handle_skill(SkillCommands)`.

- [ ] **Step 1: Add the command definitions to `src/cli.rs`**

Inside `pub enum Commands`, after the `Vault { … }` variant:
```rust
    /// Sync memory and skills across agents and machines (see designs/atem-memory.md)
    Sync {
        /// Don't harvest Claude's saved memories this run
        #[arg(long)]
        no_harvest: bool,
        /// Allow writing into files tracked by git
        #[arg(long)]
        allow_tracked: bool,
    },
    /// Shared memory for coding agents (see designs/atem-memory.md)
    Memory {
        #[command(subcommand)]
        command: MemoryCommands,
    },
    /// Shared skills for coding agents (see designs/atem-memory.md)
    Skill {
        #[command(subcommand)]
        command: SkillCommands,
    },
```

After `pub enum VaultCommands { … }`:
```rust
#[derive(clap::Subcommand, Debug)]
pub enum MemoryCommands {
    /// Add a memory (a short, durable fact)
    Add {
        /// The fact to remember
        content: String,
        /// global | project | machine (default: project inside a git repo, else global)
        #[arg(long)]
        scope: Option<String>,
        /// Project key (default: the current repo's normalized git remote)
        #[arg(long)]
        project: Option<String>,
        /// high | medium | low
        #[arg(long, default_value = "medium")]
        confidence: String,
        /// Which agent is saving this (claude, codex, …)
        #[arg(long, default_value = "cli")]
        agent: String,
        /// Store even though it looks like a credential (only if it is not one)
        #[arg(long)]
        force: bool,
    },
    /// List memories (global, this machine, and the current project unless --all)
    List {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Search memories on this machine
    Search {
        text: String,
    },
    /// Remove a memory everywhere
    Rm {
        id: String,
    },
    /// Remove a memory that contained a credential, everywhere, and stop re-harvesting it
    Purge {
        id: String,
    },
    /// Rewrite the managed memory blocks and skills from the local store
    Apply {
        #[arg(long)]
        allow_tracked: bool,
    },
    /// Account, machine, pending changes, held-back memories, credential findings
    Status,
}

#[derive(clap::Subcommand, Debug)]
pub enum SkillCommands {
    /// Add (or update) a skill from a directory containing SKILL.md
    Add {
        dir: String,
        /// global (default) | project
        #[arg(long)]
        scope: Option<String>,
        /// Skill name (default: the directory name)
        #[arg(long)]
        name: Option<String>,
    },
    /// List skills
    List,
    /// Remove a skill everywhere
    Rm {
        name: String,
        #[arg(long, default_value = "global")]
        scope: String,
    },
    /// Erase skill versions that contained a credential
    Purge {
        name: String,
        #[arg(long, default_value = "global")]
        scope: String,
        #[arg(long)]
        version: Option<i64>,
        #[arg(long)]
        all_versions: bool,
    },
}
```

In `handle_cli_command`, next to `Commands::Vault { command } => handle_vault_command(command).await,`:
```rust
        Commands::Sync { no_harvest, allow_tracked } => crate::memory::cmd::handle_sync(no_harvest, allow_tracked).await,
        Commands::Memory { command } => crate::memory::cmd::handle_memory(command).await,
        Commands::Skill { command } => crate::memory::cmd::handle_skill(command).await,
```
If the compiler reports other non-exhaustive `match`es on `Commands` (for example in `main.rs`), add the three variants to the same arm the `Vault` variant uses there.

In `src/websocket_client.rs`, change `fn resolved_atem_id(hostname: &str) -> String {` to `pub(crate) fn resolved_atem_id(hostname: &str) -> String {`.

- [ ] **Step 2: Write the failing tests for the pure helpers** (in `src/memory/cmd.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scope_depends_on_repo() {
        assert_eq!(default_scope(true), Scope::Project);
        assert_eq!(default_scope(false), Scope::Global);
    }

    #[test]
    fn findings_message_is_masked_and_actionable() {
        let msg = findings_message(&crate::memory::secrets::find_secrets("sk-abcdefghijklmnopqrstuvwx"));
        assert!(msg.contains("sk-…uvwx"));
        assert!(!msg.contains("abcdefghijklmnop"));
        assert!(msg.contains("vault credential"));
    }

    #[test]
    fn harvest_switch_defaults_on() {
        assert!(harvest_enabled_in(""));
        assert!(!harvest_enabled_in("[memory]\nharvest_claude = false\n"));
        assert!(harvest_enabled_in("[memory]\nharvest_claude = true\n"));
    }

    #[test]
    fn truncate_keeps_short_text() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate(&"x".repeat(20), 10), format!("{}…", "x".repeat(9)));
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Add `pub mod cmd;`. Run: `cargo test memory::cmd`. Expected: compile errors.

- [ ] **Step 4: Implement `src/memory/cmd.rs`** (above the tests)

```rust
//! CLI handlers for `atem sync`, `atem memory …`, `atem skill …`.
use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};
use crate::cli::{MemoryCommands, SkillCommands};
use crate::memory::adapters::{valid_skill_name, Agent, Ctx};
use crate::memory::api::KnowledgeClient;
use crate::memory::block::{contains_reserved, one_line};
use crate::memory::harvest::claude_memory_dir;
use crate::memory::model::{content_hash, new_memory_id, now_secs, parse_confidence, skill_hash, Memory, Scope, Skill};
use crate::memory::project::{detect_repo, display_name};
use crate::memory::secrets::{check_bytes, find_secrets, SecretFinding};
use crate::memory::skills_fs::{self, DirState, SkillMarker};
use crate::memory::store::{HarvestStatus, PendingOp, Store, LAST_SYNC_AT};
use crate::memory::sync::{self, SyncOptions, SyncOutcome};

const ROTATE_WARNING: &str = "⚠ Rotate the credential: it may already be on other machines' disks or backups, so treat it as exposed.";

pub fn store_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("knowledge.db")
}

fn default_scope(in_repo: bool) -> Scope {
    if in_repo { Scope::Project } else { Scope::Global }
}

fn findings_message(findings: &[SecretFinding]) -> String {
    let list = findings.iter().map(|f| format!("  line {}: {} {}", f.line, f.kind, f.masked)).collect::<Vec<_>>().join("\n");
    format!(
        "This looks like a credential, so it was not stored:\n{}\nName the vault credential instead, e.g. \"DialF's OpenAI key is the vault credential dialf/openai\".",
        list
    )
}

fn harvest_enabled_in(config_toml: &str) -> bool {
    config_toml.parse::<toml::Value>().ok()
        .and_then(|v| v.get("memory")?.get("harvest_claude")?.as_bool())
        .unwrap_or(true)
}

fn harvest_enabled() -> bool {
    harvest_enabled_in(&std::fs::read_to_string(crate::config::AtemConfig::config_path()).unwrap_or_default())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    format!("{}…", s.chars().take(max - 1).collect::<String>())
}

/// Offline check: a stored login is enough. Network only matters for sync.
fn require_login() -> Result<()> {
    if crate::credentials::CredentialStore::load().entries.is_empty() {
        bail!("Not logged in. Run `atem login` first — memory and skills sync to your Agora account.");
    }
    Ok(())
}

fn build_ctx(allow_tracked: bool) -> Result<Ctx> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("cannot find the home directory"))?;
    let cwd = std::env::current_dir()?;
    Ok(Ctx {
        home,
        repo: detect_repo(&cwd),
        atem_id: crate::websocket_client::resolved_atem_id(&crate::auth::get_hostname()),
        allow_tracked,
    })
}

/// None when the token can't be obtained (e.g. offline and expired).
async fn client() -> Option<KnowledgeClient> {
    let config = crate::config::AtemConfig::load().ok()?;
    let token = crate::sso_auth::valid_token(None, config.effective_sso_url()).await.ok()?;
    Some(KnowledgeClient::new(
        config.astation_relay_url().to_string(),
        crate::config::AtemConfig::ensure_instance_id(),
        token,
    ))
}

fn print_outcome(out: &SyncOutcome) {
    if let Some(h) = &out.harvest {
        println!("Harvested from Claude: {} new, {} removed", h.added, h.removed);
        for hb in &h.held_back {
            println!("  held back (possible credential): {}", hb);
        }
    }
    if out.offline {
        println!("Relay unreachable — changes stay queued and sync next time.");
    } else {
        println!("Pushed {} change(s), pulled {} update(s).", out.pushed, out.pulled);
    }
    for n in &out.notes {
        println!("note: {}", n);
    }
    for line in &out.report {
        println!("{}", line.render());
    }
}

/// After a local change: push/pull/apply without harvesting; quiet offline.
async fn best_effort_sync(store: &Store, ctx: &Ctx) {
    let c = client().await;
    match sync::run_sync(store, c.as_ref(), ctx, &SyncOptions { harvest: false }).await {
        Ok(out) => {
            for n in &out.notes {
                eprintln!("note: {}", n);
            }
        }
        Err(e) => eprintln!("note: {}", e),
    }
}

fn project_for_scope(scope: Scope, ctx: &Ctx, explicit: Option<String>) -> Result<String> {
    if scope != Scope::Project {
        return Ok(String::new());
    }
    explicit
        .or_else(|| ctx.repo.as_ref().map(|r| r.key.clone()))
        .ok_or_else(|| anyhow!("--scope project needs a git repo (or --project <key>)"))
}

fn where_label(m: &Memory) -> String {
    match m.scope {
        Scope::Global => "global".into(),
        Scope::Machine => format!("machine:{}", m.machine),
        Scope::Project => format!("project:{}", display_name(&m.project)),
    }
}

fn print_memories(ms: &[Memory]) {
    if ms.is_empty() {
        println!("(no memories)");
    }
    for m in ms {
        println!("{}  {:<24} {:<6} {}", m.id, where_label(m), m.confidence, truncate(&one_line(&m.content), 90));
    }
}

fn files_under(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() && depth > 0 {
            files_under(&e.path(), depth - 1, out);
        } else if ft.is_file() {
            out.push(e.path());
        }
    }
}

/// Credentials sitting in files atem reads or writes. Reported, never uploaded.
fn credential_findings(ctx: &Ctx) -> Vec<String> {
    let mut files = Vec::new();
    for agent in Agent::all() {
        if !agent.discover(ctx) {
            continue;
        }
        files.push(agent.global_memory_file(ctx));
        if let Some(r) = &ctx.repo {
            files.push(agent.project_memory_file(&r.root));
        }
        for scope in [Scope::Global, Scope::Project] {
            if let Some(root) = agent.skills_root(ctx, scope) {
                files_under(&root, 4, &mut files);
            }
        }
    }
    if let Some(r) = &ctx.repo {
        files_under(&claude_memory_dir(&ctx.home, &r.root), 0, &mut files);
    }
    let mut out = Vec::new();
    for f in files {
        let Ok(bytes) = std::fs::read(&f) else { continue };
        let Ok(text) = std::str::from_utf8(&bytes) else { continue };
        for s in find_secrets(text) {
            out.push(format!("{}:{}  {} {}", f.display(), s.line, s.kind, s.masked));
        }
    }
    out
}

pub async fn handle_sync(no_harvest: bool, allow_tracked: bool) -> Result<()> {
    require_login()?;
    let ctx = build_ctx(allow_tracked)?;
    let store = Store::open(&store_path())?;
    let c = client().await;
    let opts = SyncOptions { harvest: !no_harvest && harvest_enabled() };
    let out = sync::run_sync(&store, c.as_ref(), &ctx, &opts).await?;
    print_outcome(&out);
    Ok(())
}

pub async fn handle_memory(command: MemoryCommands) -> Result<()> {
    require_login()?;
    match command {
        MemoryCommands::Add { content, scope, project, confidence, agent, force } => {
            let ctx = build_ctx(false)?;
            if contains_reserved(&content) {
                bail!("The text contains the reserved token `atem:memory:`.");
            }
            let findings = find_secrets(&content);
            if !findings.is_empty() && !force {
                bail!(findings_message(&findings));
            }
            let scope = match scope {
                Some(s) => Scope::parse(&s)?,
                None => default_scope(ctx.repo.is_some()),
            };
            let project = project_for_scope(scope, &ctx, project)?;
            let machine = if scope == Scope::Machine { ctx.atem_id.clone() } else { String::new() };
            let confidence = parse_confidence(&confidence)?;
            let store = Store::open(&store_path())?;
            let hash = content_hash(&content);
            if let Some(existing) = store.find_live_by_hash(scope, &project, &machine, &hash)? {
                println!("Already stored as {}", existing.id);
                return Ok(());
            }
            let m = Memory {
                id: new_memory_id(), scope, project, machine, content, content_hash: hash, confidence,
                source_agent: agent, source_machine: ctx.atem_id.clone(), created_at: now_secs(), deleted: false, seq: 0,
            };
            store.upsert_memory(&m)?;
            store.enqueue(&PendingOp::AddMemory { memory: m.clone() })?;
            println!("Added {} ({})", m.id, where_label(&m));
            best_effort_sync(&store, &ctx).await;
        }
        MemoryCommands::List { scope, project, all } => {
            let ctx = build_ctx(false)?;
            let store = Store::open(&store_path())?;
            let scope_f = scope.map(|s| Scope::parse(&s)).transpose()?;
            let key = ctx.repo.as_ref().map(|r| r.key.clone());
            let shown: Vec<Memory> = store.live_memories()?.into_iter().filter(|m| {
                if let Some(sf) = scope_f {
                    if m.scope != sf {
                        return false;
                    }
                }
                if let Some(p) = &project {
                    return &m.project == p;
                }
                if all {
                    return true;
                }
                match m.scope {
                    Scope::Global => true,
                    Scope::Machine => m.machine == ctx.atem_id,
                    Scope::Project => Some(&m.project) == key.as_ref(),
                }
            }).collect();
            print_memories(&shown);
        }
        MemoryCommands::Search { text } => {
            let store = Store::open(&store_path())?;
            let needle = text.to_lowercase();
            let hits: Vec<Memory> = store.live_memories()?.into_iter()
                .filter(|m| m.content.to_lowercase().contains(&needle)).collect();
            print_memories(&hits);
        }
        MemoryCommands::Rm { id } => {
            let ctx = build_ctx(false)?;
            let store = Store::open(&store_path())?;
            store.get_memory(&id)?.filter(|m| !m.deleted).ok_or_else(|| anyhow!("No memory {}", id))?;
            store.mark_memory_deleted(&id)?;
            store.enqueue(&PendingOp::DeleteMemory { id: id.clone() })?;
            println!("Removed {}", id);
            best_effort_sync(&store, &ctx).await;
        }
        MemoryCommands::Purge { id } => {
            let ctx = build_ctx(false)?;
            let store = Store::open(&store_path())?;
            store.get_memory(&id)?.ok_or_else(|| anyhow!("No memory {}", id))?;
            store.mark_memory_deleted(&id)?;
            store.enqueue(&PendingOp::DeleteMemory { id: id.clone() })?;
            if let Some(mut e) = store.harvest_by_memory(&id)? {
                e.status = HarvestStatus::Excluded;
                store.harvest_put(&e)?;
            }
            println!("Purged {}. Its text is removed from the relay and from other machines at their next sync.", id);
            println!("{}", ROTATE_WARNING);
            best_effort_sync(&store, &ctx).await;
        }
        MemoryCommands::Apply { allow_tracked } => {
            let ctx = build_ctx(allow_tracked)?;
            let store = Store::open(&store_path())?;
            for line in sync::apply_all(&store, &ctx)? {
                println!("{}", line.render());
            }
        }
        MemoryCommands::Status => {
            let ctx = build_ctx(false)?;
            let store = Store::open(&store_path())?;
            let creds = crate::credentials::CredentialStore::load();
            let account = creds.find_sso().and_then(|e| e.login_id.clone())
                .or_else(|| creds.entries.iter().find_map(|e| e.login_id.clone()))
                .unwrap_or_else(|| "(logged in)".into());
            let last = store.get_state(LAST_SYNC_AT)?;
            println!("Account:    {}", account);
            println!("Machine:    {}", ctx.atem_id);
            println!("Project:    {}", ctx.repo.as_ref().map(|r| r.key.as_str()).unwrap_or("(not in a git repo)"));
            println!("Memories:   {} live", store.live_memories()?.len());
            println!("Skills:     {} live", store.live_skills()?.len());
            println!("Pending:    {} change(s) waiting to sync", store.pending_count()?);
            println!("Last sync:  {}", if last == 0 { "never".to_string() } else { format!("{}s ago", now_secs() - last) });
            println!("Held back:  {} harvested memory file(s) (possible credentials)", store.held_back_count()?);
            for agent in Agent::all() {
                println!("Agent:      {} {}", agent.name(), if agent.discover(&ctx) { "(found)" } else { "(not installed)" });
            }
            let findings = credential_findings(&ctx);
            if findings.is_empty() {
                println!("Credential findings: none");
            } else {
                println!("Credential findings (never uploaded — move them to the vault):");
                for f in findings {
                    println!("  {}", f);
                }
            }
        }
    }
    Ok(())
}

pub async fn handle_skill(command: SkillCommands) -> Result<()> {
    require_login()?;
    let ctx = build_ctx(false)?;
    let store = Store::open(&store_path())?;
    match command {
        SkillCommands::Add { dir, scope, name } => {
            let dir = PathBuf::from(dir);
            let files = skills_fs::read_skill_dir(&dir)?;
            let mut problems = Vec::new();
            for (path, bytes) in &files {
                for f in check_bytes(bytes) {
                    problems.push(format!("{}:{}  {} {}", path, f.line, f.kind, f.masked));
                }
            }
            if !problems.is_empty() {
                bail!(
                    "Refusing to add the skill — possible credentials (or unreadable files) found:\n  {}\nKeep credentials in the vault and read them at run time, e.g. `atem vault get <name>`.",
                    problems.join("\n  ")
                );
            }
            let scope = match scope {
                Some(s) => Scope::parse(&s)?,
                None => Scope::Global,
            };
            if scope == Scope::Machine {
                bail!("Skills support --scope global or project.");
            }
            let project = project_for_scope(scope, &ctx, None)?;
            let name = name
                .or_else(|| dir.canonicalize().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())))
                .ok_or_else(|| anyhow!("Could not determine the skill name; pass --name"))?;
            if !valid_skill_name(&name) {
                bail!("Invalid skill name {:?}: use letters, digits, '-', '_' or '.'", name);
            }
            let base_version = store.get_skill(scope, &project, &name)?.map(|s| s.version).unwrap_or(0);
            let hash = skill_hash(&files);
            let skill = Skill {
                scope, project, name: name.clone(), version: base_version + 1, content_hash: hash.clone(), files,
                source_agent: "cli".into(), source_machine: ctx.atem_id.clone(), created_at: now_secs(), deleted: false, seq: 0,
            };
            store.put_skill(&skill)?;
            store.enqueue(&PendingOp::PushSkill { skill: skill.clone(), base_version })?;
            // Pushing an edit made inside a managed directory: accept it there.
            if let DirState::Managed(_) = skills_fs::dir_state(&dir) {
                skills_fs::write_marker(&dir, &SkillMarker { name, version: skill.version, hash })?;
            }
            println!("Added skill {} v{} ({})", skill.name, skill.version, scope.as_str());
            best_effort_sync(&store, &ctx).await;
        }
        SkillCommands::List => {
            let skills = store.live_skills()?;
            if skills.is_empty() {
                println!("(no skills)");
            }
            for s in skills {
                let where_ = if s.scope == Scope::Project { format!("project:{}", display_name(&s.project)) } else { "global".into() };
                println!("{:<28} v{:<4} {:<24} {} file(s)", s.name, s.version, where_, s.files.len());
            }
        }
        SkillCommands::Rm { name, scope } => {
            let scope = Scope::parse(&scope)?;
            let project = project_for_scope(scope, &ctx, None)?;
            let cur = store.get_skill(scope, &project, &name)?.filter(|s| !s.deleted)
                .ok_or_else(|| anyhow!("No skill {} ({})", name, scope.as_str()))?;
            let mut t = cur.clone();
            t.deleted = true;
            t.version += 1;
            t.files.clear();
            t.content_hash.clear();
            store.put_skill(&t)?;
            store.enqueue(&PendingOp::DeleteSkill { scope, project, name: name.clone() })?;
            println!("Removed skill {}", name);
            best_effort_sync(&store, &ctx).await;
        }
        SkillCommands::Purge { name, scope, version, all_versions } => {
            let scope = Scope::parse(&scope)?;
            let project = project_for_scope(scope, &ctx, None)?;
            let versions = if all_versions {
                None
            } else {
                Some(vec![version.ok_or_else(|| anyhow!("Pass --version <n> or --all-versions"))?])
            };
            if let Some(cur) = store.get_skill(scope, &project, &name)? {
                let hits_latest = versions.as_ref().map(|v| v.contains(&cur.version)).unwrap_or(true);
                if hits_latest {
                    let mut t = cur.clone();
                    t.deleted = true;
                    t.files.clear();
                    t.content_hash.clear();
                    store.put_skill(&t)?;
                }
            }
            store.enqueue(&PendingOp::PurgeSkill { scope, project, name: name.clone(), versions })?;
            println!("Purged skill {}. Other machines remove it at their next sync (locally edited copies are reported, not deleted).", name);
            println!("{}", ROTATE_WARNING);
            best_effort_sync(&store, &ctx).await;
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Run the tests and the build**

Run: `cargo test memory::cmd && cargo build`
Expected: 4 passed; the build succeeds with no errors.

- [ ] **Step 6: Smoke-test offline with an isolated HOME**

```bash
T=$(mktemp -d); mkdir -p "$T/.config/atem" "$T/.claude" "$T/.codex"
cp ~/.config/atem/credentials.enc "$T/.config/atem/"   # same machine → decryptable
cd "$(mktemp -d)" && git init -q && git remote add origin git@github.com:acme/dialf.git
B=/home/guohai/Dev/Agora.Build/Atem/target/debug/atem
HOME="$T" $B memory add "DialF uses TCP 8765" --confidence high
HOME="$T" $B memory add --scope global "Run tests before committing"
HOME="$T" $B memory add "key sk-abcdefghijklmnopqrstuvwx" ; echo "exit=$?"
HOME="$T" $B memory list
HOME="$T" $B memory apply
cat "$T/.claude/CLAUDE.md" CLAUDE.local.md "$T/.codex/AGENTS.md"
grep CLAUDE.local.md .git/info/exclude
HOME="$T" $B memory status
```
Expected:
- The first two `add`s print `Added mem_…` (plus a quiet offline note if the relay endpoints don't exist yet).
- The `sk-` add fails with the masked credential message (`exit=1`).
- `list` shows both memories.
- `CLAUDE.md` has the global fact and the credential instruction. `CLAUDE.local.md` has the DialF fact. `AGENTS.md` also has the Codex capture line.
- The exclude file lists `/CLAUDE.local.md`.
- `status` shows 2 live memories.

- [ ] **Step 7: Commit**

```bash
git add src/memory/cmd.rs src/memory/mod.rs src/cli.rs src/websocket_client.rs
git commit -m "feat(memory): atem sync / memory / skill commands

🤖 Built with SMT <smt@agora.build>"
```

---

### Task 14: Docs and full verification

**Files:**
- Modify: `AGENTS.md`, `designs/atem-memory.md`

- [ ] **Step 1: AGENTS.md**

In the Source Structure tree, after `vault_client.rs`:
```
├── memory/              # Atem Memory: shared memory + skills across agents and machines
│   ├── model.rs         #   Memory/Skill types, hashing
│   ├── secrets.rs       #   credential-value detector (fail-closed)
│   ├── project.rs       #   project key = normalized git remote
│   ├── block.rs         #   managed <!-- atem:memory --> block
│   ├── gitguard.rs      #   never write tracked files; .git/info/exclude
│   ├── harvest.rs       #   read Claude Code's auto-memory
│   ├── skills_fs.rs     #   skill dirs, .atem-skill marker, drift
│   ├── store.rs         #   local SQLite (~/.config/atem/knowledge.db) + queue
│   ├── adapters.rs      #   Claude/Codex targets + apply report
│   ├── api.rs           #   relay /api/memory, /api/skills client
│   ├── sync.rs          #   harvest → push → pull → apply
│   └── cmd.rs           #   CLI handlers
```
In the designs list add `├── atem-memory.md` and `└── atem-memory-implementation-plan.md` (changing the previous last entry's `└──` to `├──`). Under "Core Components" add:

```markdown
**Atem Memory** (`src/memory/`): `atem sync`, `atem memory …`, `atem skill …`. Agents learn from each other across agents and machines. Claude's saved memories are harvested, Codex saves facts with `atem memory add --agent codex`, and skills are versioned directories. Everything is synced through the relay (`/api/memory`, `/api/skills`, SSO bearer auth) with an offline SQLite store, then applied as a managed block in `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, and `<repo>/CLAUDE.local.md`, and as skills in `.claude/skills` and `.agents/skills`. Credential values are never stored: names only, fetched via `atem vault get <name>`. Tracked files are never written. See `designs/atem-memory.md`.
```

- [ ] **Step 2: Record the plan's decisions in the spec**

In `designs/atem-memory.md`:
- In §Adapters, replace the `trait AgentAdapter` block with a one-paragraph description of the `enum Agent` (paths plus instructions per agent, one shared apply).
- In §Local, replace the `applied` bullet with: "Drift is detected with the hash stored in each skill's `.atem-skill` marker."
- In the Codex capture row, the instruction becomes `atem memory add --agent codex "<fact>"`.

- [ ] **Step 3: Full test suite and lint**

Run: `cargo test 2>&1 | grep "test result"` and `cargo clippy --all-targets 2>&1 | grep -E "^(warning|error).*memory" | head`
Expected: all tests pass (the known `agent_visualize` parallel-fs flake, if it appears, passes with `cargo test agent_visualize -- --test-threads=1`). No clippy errors in `src/memory/`.

- [ ] **Step 4: Commit**

```bash
git add AGENTS.md designs/atem-memory.md
git commit -m "docs(memory): document Atem Memory; record plan decisions in spec

🤖 Built with SMT <smt@agora.build>"
```

---

## Verification (end-to-end, once the relay prerequisite is deployed)

Two isolated configs on one machine stand in for two machines. They get
different `atem_id`s and share one login.

```bash
B=/home/guohai/Dev/Agora.Build/Atem/target/debug/atem
for M in A Bm; do
  mkdir -p /tmp/mem-$M/.config/atem /tmp/mem-$M/.claude /tmp/mem-$M/.codex
  cp ~/.config/atem/credentials.enc ~/.config/atem/config.toml /tmp/mem-$M/.config/atem/
  sed -i '/^instance_id/d;/^atem_id/d' /tmp/mem-$M/.config/atem/config.toml   # distinct identities
done
REPO=$(mktemp -d); git -C $REPO init -q; git -C $REPO remote add origin git@github.com:acme/dialf.git
ENC=$(echo "$REPO" | sed 's/[^A-Za-z0-9]/-/g')

# 1. Claude on "machine A" learns a project fact (its native auto-memory)
mkdir -p /tmp/mem-A/.claude/projects/$ENC/memory
printf -- '---\nname: dialf-port\ndescription: port\nmetadata:\n  type: project\n---\nDialF advertises _dialfd._tcp and listens on TCP 8765.\n' \
  > /tmp/mem-A/.claude/projects/$ENC/memory/dialf-port.md
(cd $REPO && HOME=/tmp/mem-A $B sync)                # harvest → push

# 2. "Machine B" (a different network is fine) syncs in the same project
REPO_B=$(mktemp -d); git -C $REPO_B init -q; git -C $REPO_B remote add origin https://github.com/acme/dialf
(cd $REPO_B && HOME=/tmp/mem-Bm $B sync)             # pull → apply
grep "TCP 8765" $REPO_B/CLAUDE.local.md /tmp/mem-Bm/.codex/AGENTS.md $REPO_B/AGENTS.md

# 3. A skill from B reaches Claude on A
mkdir -p /tmp/skill/deploy-check && printf -- '---\nname: deploy-check\ndescription: pre-deploy checks\n---\nRun make check.\n' > /tmp/skill/deploy-check/SKILL.md
HOME=/tmp/mem-Bm $B skill add /tmp/skill/deploy-check
(cd $REPO && HOME=/tmp/mem-A $B sync)
ls /tmp/mem-A/.claude/skills/deploy-check/SKILL.md /tmp/mem-A/.agents/skills/deploy-check/SKILL.md
```

Expected:
- **Learning:** Claude's native memory on A reaches both agents on B, and B's skill reaches A.
- **Cross-agent:** Codex on B (`AGENTS.md`) receives Claude's fact.
- **Cross-machine:** the two repos, one SSH remote and one HTTPS remote, resolve to the same project key. Sync goes through the relay only.
- A does not get its own fact echoed into `CLAUDE.local.md`.

## Notes for the implementer

- **Binary files in skills are refused** (fail-closed secret check). That's
  intended for the MVP.
- If a skill needs non-text assets, that's a follow-up: a per-file
  binary-allowlist.
- `rm` and `purge` on a harvested memory: `rm` keeps the harvest link, so the
  memory isn't re-added unless the file changes. `purge` marks it
  `excluded`.
- `atem memory add` from Codex passes `--agent codex` (the instruction line
  in Codex's block says so), so `source_agent` is accurate.
- The relay's JSON field names must match the wire contract exactly. If they
  differ, change only `api.rs`.
