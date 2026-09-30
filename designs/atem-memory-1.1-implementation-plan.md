# Atem Memory 1.1 (Fact validity, Search, Skill history) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build phase 1.1 of Atem Memory: facts are **replaced or invalidated**
instead of deleted, and the history is kept. Only valid facts are injected.
Search runs **locally** with FTS5 (trigram, BM25). **Skill history and
restore** read old versions from the relay.

**Architecture:** The relay is built and deployed first (Tasks 1–3). It gets
two migrations: 0004 replaces `memories.deleted` with `deleted_at` and adds
`valid_at`, `invalid_at` and `superseded_by`; 0005 adds `skill_versions.purged`.
It also gets a final, idempotent `invalidate` memory op, `valid_at` on `add`,
and two read-only skill-history endpoints. The wire format stays compatible
both ways: the relay still sends `deleted: bool`, computed from `deleted_at`,
and atem accepts rows that don't have the new fields. atem then gets the
following (Tasks 4–9):

- An idempotent `knowledge.db` migration, plus an external-content FTS5 table
  kept in step by triggers.
- A `Memory` type whose serde round-trips through a wire struct.
- `replace`/`invalidate` commands built on a new `PendingOp::InvalidateMemory`
  (replace queues the add, then the invalidate).
- Harvest turns edits into replacements and deleted files into invalidations.
- A Codex block that shows short ids, and a "N more facts" line.
- `memory search`, `memory list --history`, and `skill history`/`restore`.

**Tech Stack:**

- Relay: Rust 2021, axum 0.7, sqlx 0.7.4 (Postgres, runtime-checked queries),
  async-trait, chrono.
- Atem: Rust 2024 (let-chains OK), clap 4 derive, rusqlite 0.32 with bundled
  libsqlite3-sys 0.30.1 (SQLite 3.46.0, `-DSQLITE_ENABLE_FTS5`), serde,
  reqwest 0.11, tokio.
- No new crates in either repo. atem has no `chrono`, so dates are parsed and
  formatted by hand.

**Spec:** [designs/atem-memory.md](atem-memory.md), the sections marked
*planned*: "Fact validity", "Search", and "Skill history and restore", plus
the planned lines in Data model, Relay API, CLI, Sync algorithm, Size cap,
Harvesting, Codex capture, and Testing. Out of scope: "Future: binary files",
"Future: semantic search", and `memory restore`.

## Global Constraints

- **Order:** Tasks 1–3 (Astation relay) ship and deploy before Tasks 4–9
  (atem). An old relay answers the unknown `invalidate` op with 400, and the
  batch stays queued until the relay is updated.
- **Wire compatibility.** Memory rows keep `deleted: bool` (derived from
  `deleted_at`) and add `deleted_at`, `valid_at`, `invalid_at` and
  `superseded_by`. Old atems ignore unknown fields. atem accepts rows without
  the new fields (serde default). Skill rows are unchanged on the wire:
  `purged` is `#[serde(skip)]` on `SkillRow` and appears only in the
  `versions` listing.
- **Invalidation is final.** Once `invalid_at` is set it never changes. A
  repeat is an ok no-op, and so is an unknown, deleted, or other-account id.
  An invalidation never changes `content`.
- **A credential value never leaves the machine.** Replace, harvest and
  restore run the same secret checks as add and `skill add`.
- Memory block cap stays **50 entries / 4096 bytes**.
- Relay code is edition 2021: **no let-chains** there. Atem code may use them.
- **Don't run `cargo fmt`** over existing files in either repo (they aren't
  rustfmt-clean; formatting would bury the diff). Match the surrounding style.
- Branches: Atem `feat/memory-1.1` off `main`; Astation
  `feat/memory-1.1-relay` off `main`. This plan file is untracked on Atem
  `main`. Leave it uncommitted unless asked.
- Every commit message ends with the line `🤖 Built with SMT <smt@agora.build>`.
- Tests:
  - Atem: `cargo test` (if the known `agent_visualize` flake fails, re-run
    with `cargo test -- --test-threads=1`).
  - Relay: `cd relay-server && cargo test`, plus the `#[ignore]`d Postgres
    suites against a throwaway `postgres:16` container that is always
    removed (script in Task 1, Step 8).

## Pre-flight notes (design vs. real code)

1. **"Purged" can't be derived from the current schema.** `purge_skill` sets
   `files = {}`, `content_hash = ''` and `deleted = true`. `delete_skill`
   appends a marker with exactly the same shape. Seq ordering doesn't
   separate them either: purge renumbers rows in version order, so a purged
   run looks like normal appends. **Resolution:** a separate migration,
   `0005_skill_purged.sql`, adds `skill_versions.purged BOOLEAN NOT NULL
   DEFAULT false`, and `purge` sets it. 0004 stays exactly as the design's
   SQL. Precise definition: *purged = the row's `purged` column is true*, set
   only by `purge` (including when `purge` hits a delete marker). Versions
   purged before 0005 report as `deleted`. That's harmless: both kinds have no
   files, and `restore` refuses both. `SkillRow.purged` is `#[serde(skip)]`,
   so the skill wire format doesn't change.
2. **"Facts with more than one valid successor" can't come from
   `superseded_by` alone.** Invalidation is final, so the relay keeps only the
   *first* replacement's `superseded_by`. The second replacement's link is
   never stored anywhere. **Resolution:** a local-only table
   `replacements(new_id PRIMARY KEY, old_id)`, written by `replace` and by
   harvest. `memory status` reports the union of `superseded_by` links and
   local `replacements` whose successor is still valid. Only the machine whose
   replacement lost sees the fork. The design text is updated in Task 9.
3. **Canonical-id dedup vs. a queued invalidate.** If the relay dedups
   `replace`'s add onto another id, the invalidate's `superseded_by` would
   name an id the relay never stored, and finality means it can't be fixed
   later. **Resolution:**
   - The relay maps `sent id → canonical_id` within one batch and rewrites a
     later `invalidate`/`delete` in the same batch (Task 2).
   - atem's `rewrite_memory_id` rewrites still-queued ops plus local
     `superseded_by`/`replacements` (Task 5).
   - Accepted edge case: if the relay *refuses* the add (server secret check),
     the old fact stays invalidated with a dangling successor. atem runs the
     same check first, so this is very unlikely.
4. **Pull could undo a pending local invalidation.** If push stops on a
   stuck op but pull still runs, the pulled (stale) row would overwrite the
   local invalidation. **Resolution:** `upsert_memory` keeps a local
   `invalid_at`/`superseded_by` when the incoming row has no `invalid_at`. The
   relay's value wins when it has one.
5. **Relay `MemoryRow` keeps `deleted: bool`.** Postgres computes it in
   `MEMORY_COLS` as `(deleted_at IS NOT NULL) AS deleted` (sqlx `FromRow`).
   The in-memory store sets both fields. This keeps the dozens of existing
   `r.deleted` test assertions valid. **atem's `Memory` drops `deleted`** for
   `deleted_at: Option<i64>` and uses `#[serde(from/into = "MemoryWire")]`,
   which still emits `deleted`. Legacy JSON (an old relay, or `pending_ops`
   payloads queued by the MVP) with `deleted: true` and no `deleted_at`
   parses as `deleted_at = now`.
6. **Where harvest actually lives.** Harvest logic is in
   `sync.rs::harvest_into_store`, not `harvest.rs`. `release_memory` becomes
   `owns_memory` (the same guard) plus `invalidate_and_queue`. An edited file
   that now looks like a credential used to delete the old memory. Now the
   old memory is invalidated with no successor, and the file is held back.
7. **Names kept to limit churn.** `Store::live_memories()` now means *valid*
   (not deleted and not invalid), so apply, `list` and `status` keep working.
   The new `history_memories()` returns everything that isn't deleted.
   `find_live_by_hash` also matches valid rows only, so re-adding an invalid
   fact creates a new memory, matching the relay's new dedup index.
8. **SQLite facts, verified in a scratch crate against the bundled 3.46.0:**
   - trigram FTS5 matches CJK substrings ("端口是");
   - `bm25(memories_fts)` works with an unaliased join on `rowid`;
   - external-content triggers follow `INSERT … ON CONFLICT DO UPDATE`, id
     rewrites, and deletes;
   - `ALTER TABLE … DROP COLUMN` works inside a transaction;
   - a quoted phrase with `""` escaping is injection-safe.

   `memories` is `id TEXT PRIMARY KEY` without `WITHOUT ROWID`, so it has an
   implicit rowid (verified). **`VACUUM` may renumber such rowids**, which
   would desync the external-content index. atem never VACUUMs. The code
   comment says to run `'rebuild'` if it ever does.
9. **Postgres test databases.** 0002's `CREATE UNIQUE INDEX IF NOT EXISTS
   memories_dedup … WHERE NOT deleted` fails if it re-runs on a database
   where 0004 already dropped `deleted`. Postgres resolves the predicate
   before the IF NOT EXISTS check. This can only happen when a test drops
   `_sqlx_migrations` but not `memories`. The new legacy-migration test ends
   with `fresh_pg()` so the shared container is always left fully migrated.
   Production is unaffected.
10. **The design's history sample marks "← concurrent push".** No endpoint
    field records that, so it's omitted. Times print in UTC (atem has no tz
    library).
11. **Validation details.** The relay's existing "id checks" are NUL checks
    only. `invalidate` refuses (per op, `invalid memory`): `invalid_at <= 0`,
    or a NUL in `id` or `superseded_by`. `add` refuses a `valid_at <= 0`.
    atem's single date parser (`YYYY-MM-DD` = UTC midnight, or unix seconds)
    rejects results `<= 0`, for example `1970-01-01`.
12. **The concurrent-push note.** It gains the exact design text. For a
    project-scope skill it also appends ` --scope project`, so the command it
    suggests actually finds the skill.
13. **Deployment.**
    - nginx (`Astation/webapp/nginx.conf`) needs **no change**: the new GET
      routes fall under `location /api/`. `client_max_body_size` limits
      request bodies only, and version responses (≤ ~1.4 MB of base64) are
      proxied with normal buffering.
    - `/api/memory/batch` keeps its 2 MB / 64-op caps. atem still sends at
      most 50 ops per chunk, and `replace` adds 2.

## File Structure

**Astation** (`/home/guohai/Dev/Agora.Build/Astation`):

| File | Change |
|---|---|
| `relay-server/migrations/0004_memory_validity.sql` | **Create.** The design's SQL, verbatim |
| `relay-server/migrations/0005_skill_purged.sql` | **Create.** `skill_versions.purged` |
| `relay-server/src/knowledge_store.rs` | `MemoryRow` validity fields; `invalidate_memory`; `deleted_at` in every Pg memory query; `SkillRow.purged`; `SkillVersionInfo`; `skill_versions`/`skill_version`; scenarios + Pg tests |
| `relay-server/src/knowledge_routes.rs` | `invalidate` op, `valid_at` check, per-batch canonical map; `skill_versions_handler`/`skill_version_handler`; tests; `FailingStore` |
| `relay-server/src/main.rs` | Mount `GET /api/skills/versions` and `GET /api/skills/version` |
| `relay-server/README.md` | Document the invalidate op, validity fields, and history endpoints |

**Atem** (`/home/guohai/Dev/Agora.Build/Atem`):

| File | Change |
|---|---|
| `src/memory/model.rs` | `Memory` validity fields + `MemoryWire`; `short_id`; `parse_date`/`format_date`/`format_datetime` |
| `src/memory/store.rs` | Schema + migration + FTS5; `PendingOp::InvalidateMemory`; `invalidate_memory`, `replacements`, `resolve_memory_id`, `multi_successors`, `history_memories`, `search_memories` |
| `src/memory/api.rs` | `invalidate` wire op; skill history requests; `SkillVersionInfo` |
| `src/memory/sync.rs` | `invalidate_and_queue`, `replace_memory`; harvest → replace/invalidate; `restore_skill`; concurrent-push note |
| `src/memory/block.rs` | `Selection` (entries + omitted); short ids; "N more facts" line; `CODEX_REPLACE_INSTRUCTION` |
| `src/memory/adapters.rs` | Apply only valid facts; Codex shows ids + replace line |
| `src/memory/secrets.rs` | `skill_file_problems` helper |
| `src/memory/cmd.rs` | `replace`, `invalidate`, `add --valid-at`, `list --history`, `search`, `status` forks, `skill history`/`restore` |
| `src/cli.rs` | New `MemoryCommands`/`SkillCommands` variants and flags |
| `AGENTS.md`, `designs/atem-memory.md` | Docs (Task 9) |

---

## Task 1 [Astation]: R1 — migration 0004 + store validity, deleted_at, invalidate

**Files:**
- Create: `relay-server/migrations/0004_memory_validity.sql`
- Modify: `relay-server/src/knowledge_store.rs`
- Modify: `relay-server/src/knowledge_routes.rs` (test `FailingStore` only)

**Interfaces:**
- Consumes: `lock_account`, `db_err`, `now_secs`, `KnowledgeState::next_seq`, the `scenarios` + `in_memory_tests!`/`pg_tests!` harness, `fresh_pg`, `PG_LOCK`.
- Produces:
  - `MemoryRow` gains `pub deleted_at: Option<i64>`, `pub valid_at: Option<i64>`, `pub invalid_at: Option<i64>`, `pub superseded_by: Option<String>` (all `#[serde(default)]`; `deleted: bool` stays, derived).
  - `KnowledgeStore::invalidate_memory(&self, account: &str, id: &str, invalid_at: i64, superseded_by: Option<&str>) -> Result<i64, KnowledgeError>` (new seq, or `0` = no change).

- [ ] **Step 1: Branch**

```bash
cd /home/guohai/Dev/Agora.Build/Astation && git checkout main && git pull --ff-only && git checkout -b feat/memory-1.1-relay
```

- [ ] **Step 2: Write the failing tests** (in `knowledge_store.rs` `mod tests`)

Update the `mem` fixture:

```rust
    fn mem(id: &str, content: &str) -> MemoryRow {
        MemoryRow {
            id: id.to_string(),
            scope: "global".to_string(),
            project: String::new(),
            machine: String::new(),
            content: content.to_string(),
            content_hash: format!("h:{}", content),
            confidence: "medium".to_string(),
            source_agent: "claude".to_string(),
            source_machine: "m1".to_string(),
            created_at: 1_700_000_000,
            deleted: false,
            deleted_at: None,
            valid_at: None,
            invalid_at: None,
            superseded_by: None,
            seq: 0,
        }
    }
```

Add these scenarios inside `pub(super) mod scenarios` (after `concurrent_dedup_adds_converge`):

```rust
        pub async fn invalidate_is_final_and_keeps_content(s: &dyn KnowledgeStore) {
            let a = s.add_memory(A, mem("mem_1", "port 8765")).await.unwrap();
            let b = s.add_memory(A, mem("mem_2", "port 9000")).await.unwrap();
            let i = s
                .invalidate_memory(A, "mem_1", 1_790_000_000, Some("mem_2"))
                .await
                .unwrap();
            assert!(i > a.seq && i > b.seq);
            let rows = s.pull_memories(A, 0, 100).await.unwrap();
            let r1 = rows.iter().find(|r| r.id == "mem_1").unwrap().clone();
            assert_eq!(r1.content, "port 8765");
            assert_eq!(r1.content_hash, "h:port 8765");
            assert_eq!(
                (r1.invalid_at, r1.superseded_by.as_deref(), r1.seq),
                (Some(1_790_000_000), Some("mem_2"), i)
            );
            assert!(!r1.deleted && r1.deleted_at.is_none());
            // Final: a repeat (with any values) changes nothing and takes no seq.
            assert_eq!(
                s.invalidate_memory(A, "mem_1", 1_800_000_000, Some("mem_3")).await.unwrap(),
                0
            );
            assert_eq!(s.invalidate_memory(A, "mem_1", 1_800_000_000, None).await.unwrap(), 0);
            let again = s.pull_memories(A, 0, 100).await.unwrap();
            assert_eq!(again.iter().find(|r| r.id == "mem_1").unwrap(), &r1);
            // A cursor past mem_2's add sees exactly the invalidation.
            let after = s.pull_memories(A, b.seq, 100).await.unwrap();
            assert_eq!(after.len(), 1);
            assert_eq!(after[0].id, "mem_1");
            // Without a successor.
            let j = s.invalidate_memory(A, "mem_2", 1_790_000_100, None).await.unwrap();
            assert!(j > i);
            let r2 = s.pull_memories(A, i, 100).await.unwrap();
            assert_eq!((r2[0].invalid_at, r2[0].superseded_by.clone()), (Some(1_790_000_100), None));
        }

        pub async fn invalidate_unknown_deleted_or_foreign_is_a_noop(s: &dyn KnowledgeStore) {
            s.add_memory(A, mem("mem_1", "a")).await.unwrap();
            s.add_memory(A, mem("mem_2", "b")).await.unwrap();
            let d = s.delete_memory(A, "mem_2").await.unwrap();
            assert_eq!(s.invalidate_memory(A, "mem_nope", 5, None).await.unwrap(), 0);
            assert_eq!(s.invalidate_memory(A, "mem_2", 5, None).await.unwrap(), 0);
            assert_eq!(s.invalidate_memory(B, "mem_1", 5, None).await.unwrap(), 0);
            let rows = s.pull_memories(A, 0, 100).await.unwrap();
            assert!(rows.iter().all(|r| r.invalid_at.is_none()));
            assert_eq!(rows.iter().map(|r| r.seq).max().unwrap(), d);
            assert!(s.pull_memories(B, 0, 100).await.unwrap().is_empty());
        }

        pub async fn dedup_ignores_invalid_rows(s: &dyn KnowledgeStore) {
            let o1 = s.add_memory(A, mem("mem_1", "port 8765")).await.unwrap();
            s.invalidate_memory(A, "mem_1", 10, None).await.unwrap();
            // The fact became true again: a new memory, not a dedup onto the invalid one.
            let o2 = s.add_memory(A, mem("mem_2", "port 8765")).await.unwrap();
            assert_eq!(o2.canonical_id, None);
            assert!(o2.seq > o1.seq);
            // Now the valid mem_2 is the dedup target.
            let o3 = s.add_memory(A, mem("mem_3", "port 8765")).await.unwrap();
            assert_eq!(o3.canonical_id.as_deref(), Some("mem_2"));
            // Idempotent by id still holds for an invalid row.
            let again = s.add_memory(A, mem("mem_1", "port 8765")).await.unwrap();
            assert_eq!((again.id.as_str(), again.canonical_id), ("mem_1", None));
        }

        pub async fn add_keeps_valid_at_and_ignores_client_state(s: &dyn KnowledgeStore) {
            let mut m = mem("mem_1", "port 8765");
            m.valid_at = Some(1_700_000_500);
            m.deleted = true;
            m.deleted_at = Some(9);
            m.invalid_at = Some(9);
            m.superseded_by = Some("mem_x".into());
            s.add_memory(A, m).await.unwrap();
            let r = s.pull_memories(A, 0, 100).await.unwrap().remove(0);
            assert_eq!(r.valid_at, Some(1_700_000_500));
            assert!(!r.deleted);
            assert_eq!((r.deleted_at, r.invalid_at, r.superseded_by), (None, None, None));
        }

        pub async fn delete_records_deleted_at(s: &dyn KnowledgeStore) {
            s.add_memory(A, mem("mem_1", "x")).await.unwrap();
            let before = chrono::Utc::now().timestamp();
            s.delete_memory(A, "mem_1").await.unwrap();
            let r = s.pull_memories(A, 0, 100).await.unwrap().remove(0);
            let at = r.deleted_at.expect("deleted_at set");
            assert!(r.deleted && at >= before && at <= before + 5);
            // A repeat delete keeps the first deletion time.
            s.delete_memory(A, "mem_1").await.unwrap();
            assert_eq!(s.pull_memories(A, 0, 100).await.unwrap()[0].deleted_at, Some(at));
            // Deleting an invalidated fact clears its text too.
            s.add_memory(A, mem("mem_2", "y")).await.unwrap();
            s.invalidate_memory(A, "mem_2", 7, None).await.unwrap();
            s.delete_memory(A, "mem_2").await.unwrap();
            let r2 = s
                .pull_memories(A, 0, 100)
                .await
                .unwrap()
                .into_iter()
                .find(|r| r.id == "mem_2")
                .unwrap();
            assert!(r2.deleted && r2.content.is_empty() && r2.deleted_at.is_some());
        }
```

In `seq_is_global_and_monotonic`, add an invalidation to the monotonic list.
Replace

```rust
            seqs.push(s.add_memory(A, mem("m3", "three")).await.unwrap().seq);
            assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
```

with

```rust
            seqs.push(s.add_memory(A, mem("m3", "three")).await.unwrap().seq);
            seqs.push(s.invalidate_memory(A, "m3", 5, None).await.unwrap());
            assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
```

Add the five new names to **both** `in_memory_tests!(…)` and `pg_tests!(…)`
lists (after `seq_is_global_and_monotonic,`):

```rust
        invalidate_is_final_and_keeps_content,
        invalidate_unknown_deleted_or_foreign_is_a_noop,
        dedup_ignores_invalid_rows,
        add_keeps_valid_at_and_ignores_client_state,
        delete_records_deleted_at,
```

In `wire_rows_match_client_json`, change the memory assertions to:

```rust
        assert_eq!(
            (m.project.as_str(), m.machine.as_str(), m.deleted, m.seq),
            ("", "", false, 0)
        );
        assert_eq!(
            (m.deleted_at, m.valid_at, m.invalid_at, m.superseded_by.clone()),
            (None, None, None, None)
        );
        let v = serde_json::to_value(&m).unwrap();
        let mut keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "confidence",
                "content",
                "content_hash",
                "created_at",
                "deleted",
                "deleted_at",
                "id",
                "invalid_at",
                "machine",
                "project",
                "scope",
                "seq",
                "source_agent",
                "source_machine",
                "superseded_by",
                "valid_at"
            ]
        );
```

Add the legacy-migration Postgres test after the `pg_tests!(…);` invocation:

```rust
    /// 0004 on pre-1.1 data: deleted rows get `deleted_at` (the migration
    /// time), live rows stay NULL, `deleted` is gone, and the dedup index
    /// only covers valid, undeleted rows.
    #[tokio::test]
    #[ignore]
    async fn pg_migration_0004_backfills_deleted_at_and_drops_deleted() {
        use sqlx::Executor;
        let _g = PG_LOCK.lock().await;
        let url = std::env::var("KNOWLEDGE_TEST_DATABASE_URL")
            .expect("set KNOWLEDGE_TEST_DATABASE_URL to run the Postgres tests");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        for stmt in [
            "DROP TABLE IF EXISTS memories",
            "DROP TABLE IF EXISTS skill_versions",
            "DROP SEQUENCE IF EXISTS knowledge_seq",
        ] {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }
        pool.execute(include_str!("../migrations/0002_knowledge.sql")).await.unwrap();
        pool.execute(
            "INSERT INTO memories (id, account_id, scope, content, content_hash, source_agent, \
             source_machine, created_at, deleted) VALUES \
             ('m_live', 'acct', 'global', 'x', 'hx', 'cli', 'm', 1, false), \
             ('m_gone', 'acct', 'global', '', '', 'cli', 'm', 1, true)",
        )
        .await
        .unwrap();
        let before = chrono::Utc::now().timestamp();
        pool.execute(include_str!("../migrations/0004_memory_validity.sql")).await.unwrap();
        let rows: Vec<(String, Option<i64>, Option<i64>, Option<i64>, Option<String>)> =
            sqlx::query_as(
                "SELECT id, deleted_at, valid_at, invalid_at, superseded_by FROM memories ORDER BY id",
            )
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows[0].0, "m_gone");
        assert!(rows[0].1.unwrap() >= before - 5, "{:?}", rows[0]);
        assert_eq!(rows[1], ("m_live".to_string(), None, None, None, None));
        let has_deleted: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM information_schema.columns \
             WHERE table_name = 'memories' AND column_name = 'deleted')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!has_deleted);
        let pred: String = sqlx::query_scalar(
            "SELECT pg_get_expr(indpred, indrelid) FROM pg_index \
             WHERE indexrelid = 'memories_dedup'::regclass",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            pred.contains("deleted_at IS NULL") && pred.contains("invalid_at IS NULL"),
            "{pred}"
        );
        drop(pool);
        // Leave the shared database fully migrated for the other suites.
        fresh_pg().await;
    }
```

In `relay-server/src/knowledge_routes.rs` `FailingStore`, add (next to `delete_memory`):

```rust
        async fn invalidate_memory(&self, _: &str, _: &str, _: i64, _: Option<&str>) -> Result<i64, KnowledgeError> {
            Err(KnowledgeError::Db("connection reset".into()))
        }
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /home/guohai/Dev/Agora.Build/Astation/relay-server && cargo test knowledge_store 2>&1 | tail -20`
Expected: compile errors (`no field deleted_at on MemoryRow`, `no method invalidate_memory`).

- [ ] **Step 4: Create `relay-server/migrations/0004_memory_validity.sql`** (the design's SQL, verbatim)

```sql
-- Atem Memory 1.1: fact validity. `deleted` becomes `deleted_at`; facts can
-- be invalidated (kept, not injected) and point at the memory that replaced them.
ALTER TABLE memories ADD COLUMN deleted_at    BIGINT;
UPDATE memories SET deleted_at = extract(epoch FROM now())::bigint
    WHERE deleted;                                              -- real time unknown
ALTER TABLE memories ADD COLUMN valid_at      BIGINT;          -- NULL means created_at
ALTER TABLE memories ADD COLUMN invalid_at    BIGINT;
ALTER TABLE memories ADD COLUMN superseded_by TEXT;
DROP INDEX memories_dedup;
CREATE UNIQUE INDEX memories_dedup ON memories
    (account_id, scope, project, machine, content_hash)
    WHERE deleted_at IS NULL AND invalid_at IS NULL;
ALTER TABLE memories DROP COLUMN deleted;
```

- [ ] **Step 5: Implement in `knowledge_store.rs`**

Replace the `MemoryRow` doc comment and struct:

```rust
/// One memory. Also the wire `Memory`. The client's `seq`, `deleted`,
/// `deleted_at`, `invalid_at` and `superseded_by` are ignored on input
/// (`valid_at` is kept). `deleted` is derived from `deleted_at` (Postgres
/// computes it in `MEMORY_COLS`) and stays on the wire for older atems.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
pub struct MemoryRow {
    pub id: String,
    pub scope: String,
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
    /// When it was deleted (unix seconds); `None` = not deleted.
    #[serde(default)]
    pub deleted_at: Option<i64>,
    /// When the fact became true; `None` = `created_at`.
    #[serde(default)]
    pub valid_at: Option<i64>,
    /// When it stopped being true; `None` = still valid. Final once set.
    #[serde(default)]
    pub invalid_at: Option<i64>,
    /// The memory that replaced it, if any.
    #[serde(default)]
    pub superseded_by: Option<String>,
    #[serde(default)]
    pub seq: i64,
}
```

In the trait, update the `add_memory`/`delete_memory` docs and add `invalidate_memory` after `delete_memory`:

```rust
    /// Idempotent by id; dedups onto a valid, undeleted row with the same
    /// `(account, scope, project, machine, content_hash)`; else inserts
    /// (keeping the client's `valid_at`).
    async fn add_memory(
        &self,
        account: &str,
        m: MemoryRow,
    ) -> Result<MemoryAddOutcome, KnowledgeError>;

    /// Blank + tombstone the memory (`deleted_at`, first deletion time kept),
    /// returning its new seq. Unknown id, or an id owned by another account →
    /// `Ok(0)` (no change, no existence oracle).
    async fn delete_memory(&self, account: &str, id: &str) -> Result<i64, KnowledgeError>;

    /// Mark a valid memory invalid (never touches `content`), returning its
    /// new seq. Final: an id that is already invalid, deleted, unknown, or
    /// owned by another account → `Ok(0)`, no change.
    async fn invalidate_memory(
        &self,
        account: &str,
        id: &str,
        invalid_at: i64,
        superseded_by: Option<&str>,
    ) -> Result<i64, KnowledgeError>;
```

In-memory `add_memory`: change the dedup predicate `&& !r.deleted` to

```rust
                && r.deleted_at.is_none()
                && r.invalid_at.is_none()
```

and the pushed row to

```rust
            MemoryRow {
                deleted: false,
                deleted_at: None,
                invalid_at: None,
                superseded_by: None,
                seq,
                ..m
            },
```

In-memory `delete_memory`: replace the body after the `idx` lookup with

```rust
        let now = now_secs();
        let seq = st.next_seq();
        let row = &mut st.memories[idx].1;
        row.content.clear();
        row.content_hash.clear();
        row.deleted = true;
        row.deleted_at.get_or_insert(now);
        row.seq = seq;
        Ok(seq)
```

Add the in-memory `invalidate_memory` after `delete_memory`:

```rust
    async fn invalidate_memory(
        &self,
        account: &str,
        id: &str,
        invalid_at: i64,
        superseded_by: Option<&str>,
    ) -> Result<i64, KnowledgeError> {
        let mut st = self.state.lock().await;
        let idx = match st.memories.iter().position(|(acct, r)| {
            acct == account && r.id == id && r.deleted_at.is_none() && r.invalid_at.is_none()
        }) {
            None => return Ok(0),
            Some(i) => i,
        };
        let seq = st.next_seq();
        let row = &mut st.memories[idx].1;
        row.invalid_at = Some(invalid_at);
        row.superseded_by = superseded_by.map(str::to_string);
        row.seq = seq;
        Ok(seq)
    }
```

Postgres: replace `MEMORY_COLS`:

```rust
const MEMORY_COLS: &str = "id, scope, project, machine, content, content_hash, confidence, \
     source_agent, source_machine, created_at, (deleted_at IS NOT NULL) AS deleted, deleted_at, \
     valid_at, invalid_at, superseded_by, seq";
```

In `existing_memory_outcome`, change the dedup query's `AND NOT deleted` to `AND deleted_at IS NULL AND invalid_at IS NULL`:

```rust
    let dup: Option<(String, i64)> = sqlx::query_as(
        "SELECT id, seq FROM memories WHERE account_id = $1 AND scope = $2 AND project = $3 \
         AND machine = $4 AND content_hash = $5 AND deleted_at IS NULL AND invalid_at IS NULL",
    )
```

In Pg `add_memory`, replace the insert:

```rust
        let inserted: Result<i64, sqlx::Error> = sqlx::query_scalar(
            "INSERT INTO memories (id, account_id, scope, project, machine, content, content_hash, \
             confidence, source_agent, source_machine, created_at, valid_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING seq",
        )
        .bind(&m.id)
        .bind(account)
        .bind(&m.scope)
        .bind(&m.project)
        .bind(&m.machine)
        .bind(&m.content)
        .bind(&m.content_hash)
        .bind(&m.confidence)
        .bind(&m.source_agent)
        .bind(&m.source_machine)
        .bind(m.created_at)
        .bind(m.valid_at)
        .fetch_one(&mut *tx)
        .await;
```

Pg `delete_memory` query:

```rust
        let seq: Option<i64> = sqlx::query_scalar(
            "UPDATE memories SET content = '', content_hash = '', \
             deleted_at = COALESCE(deleted_at, $3), seq = nextval('knowledge_seq') \
             WHERE id = $1 AND account_id = $2 RETURNING seq",
        )
        .bind(id)
        .bind(account)
        .bind(now_secs())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
```

Pg `invalidate_memory` (after `delete_memory`):

```rust
    async fn invalidate_memory(
        &self,
        account: &str,
        id: &str,
        invalid_at: i64,
        superseded_by: Option<&str>,
    ) -> Result<i64, KnowledgeError> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        lock_account(&mut tx, account).await?;
        // Final and account-scoped: an invalid, deleted, unknown or foreign id
        // matches no row → Ok(0).
        let seq: Option<i64> = sqlx::query_scalar(
            "UPDATE memories SET invalid_at = $3, superseded_by = $4, \
             seq = nextval('knowledge_seq') \
             WHERE id = $1 AND account_id = $2 AND deleted_at IS NULL AND invalid_at IS NULL \
             RETURNING seq",
        )
        .bind(id)
        .bind(account)
        .bind(invalid_at)
        .bind(superseded_by)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(seq.unwrap_or(0))
    }
```

- [ ] **Step 6: Run the in-memory tests to verify they pass**

Run: `cd /home/guohai/Dev/Agora.Build/Astation/relay-server && cargo test knowledge 2>&1 | tail -20`
Expected: all `knowledge_store` and `knowledge_routes` tests pass (Pg ones listed as ignored).

- [ ] **Step 7: Run the whole relay suite**

Run: `cd /home/guohai/Dev/Agora.Build/Astation/relay-server && cargo test 2>&1 | grep -E "^test result|FAILED|panicked"`
Expected: every `test result: ok`.

- [ ] **Step 8: Run the Postgres suites against a throwaway postgres:16 (always removed)**

Run as a single command:

```bash
cd /home/guohai/Dev/Agora.Build/Astation/relay-server && \
docker rm -f relay-test-pg >/dev/null 2>&1; \
trap 'docker rm -f relay-test-pg >/dev/null 2>&1' EXIT; \
docker run --rm -d --name relay-test-pg -e POSTGRES_PASSWORD=pw -p 55433:5432 postgres:16 >/dev/null && \
until docker exec relay-test-pg psql -U postgres -h 127.0.0.1 -c 'select 1' >/dev/null 2>&1; do sleep 1; done && \
KNOWLEDGE_TEST_DATABASE_URL=postgres://postgres:pw@localhost:55433/postgres cargo test knowledge_store -- --ignored 2>&1 | grep -E "^test |test result" && \
IDENTITY_TEST_DATABASE_URL=postgres://postgres:pw@localhost:55433/postgres cargo test identity_store -- --ignored 2>&1 | grep -E "test result"; \
docker rm -f relay-test-pg >/dev/null 2>&1; docker ps -a --filter name=relay-test-pg --format '{{.Names}}'
```

Expected: `test result: ok` for both suites (including `pg_migration_0004_backfills_deleted_at_and_drops_deleted` and every `pg::…` scenario), and the final `docker ps` prints nothing.

- [ ] **Step 9: Commit**

```bash
cd /home/guohai/Dev/Agora.Build/Astation && git add relay-server/migrations/0004_memory_validity.sql relay-server/src/knowledge_store.rs relay-server/src/knowledge_routes.rs && git commit -m "$(cat <<'EOF'
feat(relay): memory validity — deleted_at, valid_at, invalidate (migration 0004)

Replaces memories.deleted with deleted_at (backfilled), adds valid_at,
invalid_at and superseded_by, and narrows the dedup index to valid rows.
KnowledgeStore::invalidate_memory is final and account-scoped. The wire
row keeps `deleted`, computed from deleted_at.

🤖 Built with SMT <smt@agora.build>
EOF
)"
```

---

## Task 2 [Astation]: R2 — `invalidate` op, `valid_at` on add, per-batch canonical map

**Files:**
- Modify: `relay-server/src/knowledge_routes.rs`

**Interfaces:**
- Consumes: `KnowledgeStore::invalidate_memory` (Task 1), `MemoryRow.valid_at`.
- Produces:
  - Wire op `{"op":"invalidate","id":String,"invalid_at":i64,"superseded_by":String|null}` → result `{"ok":true,"id":<sent id>,"seq":i64}` (`seq` 0 = no change).
  - `MemoryOp::Invalidate { id, invalid_at, superseded_by }`.
  - `async fn apply_memory_op(state: &AppState, account: &str, op: MemoryOp, canon: &mut HashMap<String, String>) -> Result<Value, ErrResp>`.

- [ ] **Step 1: Write the failing tests** (append to `mod tests` in `knowledge_routes.rs`)

```rust
    // ─────────────────────────── invalidate + validity ───────────────────────────

    async fn call(app: &Router, method: &str, uri: &str, session: &str, body: Option<Value>) -> (StatusCode, Value) {
        let b = body.map(|v| v.to_string()).unwrap_or_default();
        let resp = app.clone().oneshot(req(method, uri, session, &b)).await.unwrap();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    fn add_op(id: &str, content: &str) -> Value {
        json!({"op": "add", "memory": sample_memory(id, content)})
    }

    async fn pull_row(app: &Router, sess: &str, id: &str) -> Value {
        let (_, v) = call(app, "GET", "/api/memory?id=a", sess, None).await;
        v["memories"].as_array().unwrap().iter().find(|r| r["id"] == id).cloned().unwrap_or(Value::Null)
    }

    const MEM_BATCH: &str = "/api/memory/batch?id=a";

    #[tokio::test]
    async fn invalidate_marks_fact_invalid_and_keeps_content() {
        let (state, sess) = test_state("ws-1").await;
        let app = app(state);
        call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [add_op("mem_old", "port 8765"), add_op("mem_new", "port 9000")]}))).await;
        let (st, v) = call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [
            {"op": "invalidate", "id": "mem_old", "invalid_at": 1_790_000_000, "superseded_by": "mem_new"},
        ]}))).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["results"][0]["ok"], true, "{v}");
        assert!(v["results"][0]["seq"].as_i64().unwrap() > 0);
        let row = pull_row(&app, &sess, "mem_old").await;
        assert_eq!(row["content"], "port 8765");
        assert_eq!(row["invalid_at"], 1_790_000_000);
        assert_eq!(row["superseded_by"], "mem_new");
        assert_eq!(row["deleted"], false);
        assert_eq!(row["deleted_at"], Value::Null);
        assert_eq!(pull_row(&app, &sess, "mem_new").await["invalid_at"], Value::Null);
    }

    #[tokio::test]
    async fn invalidate_is_final_and_unknown_or_foreign_ids_are_ok() {
        let (state, sess) = test_state("ws-1").await;
        let sess2 = bind_session(&state, "ws-2").await;
        let app = app(state);
        call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [add_op("mem_1", "x")]}))).await;
        let inv = |id: &str, at: i64| json!({"op": "invalidate", "id": id, "invalid_at": at});
        let (_, v) = call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [inv("mem_1", 100), inv("mem_1", 200), inv("mem_unknown", 100)]}))).await;
        let r = v["results"].as_array().unwrap();
        assert!(r.iter().all(|x| x["ok"] == true), "{v}");
        assert!(r[0]["seq"].as_i64().unwrap() > 0);
        assert_eq!((r[1]["seq"].clone(), r[2]["seq"].clone()), (json!(0), json!(0)));
        // Another account can't touch it, and can't tell that it exists.
        let (_, v2) = call(&app, "POST", MEM_BATCH, &sess2, Some(json!({"ops": [inv("mem_1", 300)]}))).await;
        assert_eq!(v2["results"][0], json!({"ok": true, "id": "mem_1", "seq": 0}));
        assert_eq!(pull_row(&app, &sess, "mem_1").await["invalid_at"], 100);
    }

    #[tokio::test]
    async fn invalidate_input_problems_are_refused_per_op() {
        let (state, sess) = test_state("ws-1").await;
        let app = app(state);
        call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [add_op("mem_1", "x")]}))).await;
        let (st, v) = call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [
            {"op": "invalidate", "id": "mem_1", "invalid_at": 0},
            {"op": "invalidate", "id": "mem_1", "invalid_at": -5},
            {"op": "invalidate", "id": "mem\u{0}1", "invalid_at": 5},
            {"op": "invalidate", "id": "mem_1", "invalid_at": 5, "superseded_by": "mem\u{0}2"},
        ]}))).await;
        assert_eq!(st, StatusCode::OK);
        for x in v["results"].as_array().unwrap() {
            assert_eq!(x, &json!({"ok": false, "error": "invalid memory"}));
        }
        assert_eq!(pull_row(&app, &sess, "mem_1").await["invalid_at"], Value::Null);
        // A missing invalid_at is a malformed op: the whole batch is 400.
        let (st, _) = call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [{"op": "invalidate", "id": "mem_1"}]}))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalidate_follows_a_canonical_id_from_the_same_batch() {
        let (state, sess) = test_state("ws-1").await;
        let app = app(state);
        call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [add_op("mem_old", "port 8765"), add_op("mem_canon", "port 9000")]}))).await;
        // Another machine replaced mem_old with the same text mem_canon already has.
        let (_, v) = call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [
            add_op("mem_new", "port 9000"),
            {"op": "invalidate", "id": "mem_old", "invalid_at": 5, "superseded_by": "mem_new"},
        ]}))).await;
        assert_eq!(v["results"][0]["canonical_id"], "mem_canon");
        assert_eq!(v["results"][1]["ok"], true);
        assert_eq!(pull_row(&app, &sess, "mem_old").await["superseded_by"], "mem_canon");
    }

    #[tokio::test]
    async fn add_carries_valid_at_and_refuses_non_positive() {
        let (state, sess) = test_state("ws-1").await;
        let app = app(state);
        let mut m = sample_memory("mem_1", "x");
        m["valid_at"] = json!(1_690_000_000);
        let mut bad = sample_memory("mem_2", "y");
        bad["valid_at"] = json!(0);
        let (_, v) = call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [
            {"op": "add", "memory": m}, {"op": "add", "memory": bad},
        ]}))).await;
        assert_eq!(v["results"][0]["ok"], true);
        assert_eq!(v["results"][1], json!({"ok": false, "error": "invalid memory"}));
        assert_eq!(pull_row(&app, &sess, "mem_1").await["valid_at"], 1_690_000_000);
        assert_eq!(pull_row(&app, &sess, "mem_2").await, Value::Null);
    }

    #[tokio::test]
    async fn deleted_rows_carry_deleted_at_and_the_legacy_flag() {
        let (state, sess) = test_state("ws-1").await;
        let app = app(state);
        call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [add_op("mem_1", "x")]}))).await;
        call(&app, "POST", MEM_BATCH, &sess, Some(json!({"ops": [{"op": "delete", "id": "mem_1"}]}))).await;
        let row = pull_row(&app, &sess, "mem_1").await;
        assert_eq!(row["deleted"], true);
        assert!(row["deleted_at"].as_i64().unwrap() > 1_700_000_000);
        assert_eq!(row["content"], "");
    }
```

In `store_failure_fails_the_whole_batch_with_503`, add to `cases`:

```rust
            ("/api/memory/batch?id=a", json!({"ops": [{"op": "invalidate", "id": "mem_1", "invalid_at": 5}]})),
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/guohai/Dev/Agora.Build/Astation/relay-server && cargo test knowledge_routes 2>&1 | tail -20`
Expected: the new invalidate tests fail with 400 (unknown op `invalidate`), and `add_carries_valid_at_and_refuses_non_positive` fails because `valid_at: 0` is accepted.

- [ ] **Step 3: Implement**

At the top, add `use std::collections::HashMap;`.

In the module doc, change "delete/purge are idempotent" to "delete/invalidate/purge are idempotent".

Replace `MemoryOp`, `apply_memory_op` and the loop in `memory_batch_handler`:

```rust
/// One `/api/memory/batch` op. Unknown `op` values fail deserialization (400).
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum MemoryOp {
    Add { memory: MemoryRow },
    Delete { id: String },
    /// Final and idempotent; never changes content.
    Invalidate {
        id: String,
        invalid_at: i64,
        #[serde(default)]
        superseded_by: Option<String>,
    },
}

/// `canon` maps an id the client sent to the canonical id an earlier `add`
/// in the same batch was deduplicated onto, so a later `delete`/`invalidate`
/// in the batch (as `id` or `superseded_by`) names a row that exists.
async fn apply_memory_op(
    state: &AppState,
    account: &str,
    op: MemoryOp,
    canon: &mut HashMap<String, String>,
) -> Result<Value, ErrResp> {
    let mapped = |canon: &HashMap<String, String>, id: &str| canon.get(id).cloned().unwrap_or_else(|| id.to_string());
    match op {
        MemoryOp::Add { memory } => {
            if !is_valid_memory_scope(&memory.scope)
                || memory_has_nul(&memory)
                || memory.valid_at.is_some_and(|v| v <= 0)
            {
                return Ok(op_err("invalid memory"));
            }
            if contains_reserved(&memory.content) {
                return Ok(op_err("reserved token"));
            }
            if let Some(f) = find_secrets(&memory.content).first() {
                return Ok(op_err(format!("possible credential: {}", f.kind)));
            }
            let r = state.knowledge.add_memory(account, memory).await;
            if let Ok(o) = &r {
                if let Some(cid) = &o.canonical_id {
                    canon.insert(o.id.clone(), cid.clone());
                }
            }
            store_result(r, |o| {
                let mut v = json!({ "ok": true, "id": o.id, "seq": o.seq });
                if let Some(cid) = o.canonical_id {
                    v["canonical_id"] = json!(cid);
                }
                v
            })
        }
        MemoryOp::Delete { id } => {
            if has_nul(&[&id]) {
                return Ok(op_err("invalid memory"));
            }
            let target = mapped(canon, &id);
            store_result(state.knowledge.delete_memory(account, &target).await, |seq| {
                json!({ "ok": true, "id": id, "seq": seq })
            })
        }
        MemoryOp::Invalidate { id, invalid_at, superseded_by } => {
            if invalid_at <= 0
                || has_nul(&[&id])
                || superseded_by.as_deref().is_some_and(|s| s.contains('\0'))
            {
                return Ok(op_err("invalid memory"));
            }
            let target = mapped(canon, &id);
            let successor = superseded_by.map(|s| mapped(canon, &s));
            store_result(
                state
                    .knowledge
                    .invalidate_memory(account, &target, invalid_at, successor.as_deref())
                    .await,
                |seq| json!({ "ok": true, "id": id, "seq": seq }),
            )
        }
    }
}
```

In `memory_batch_handler`:

```rust
    let mut results = Vec::with_capacity(ops.len());
    let mut canon = HashMap::new();
    for op in ops {
        results.push(apply_memory_op(&state, &caller.work_session_id, op, &mut canon).await?);
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/guohai/Dev/Agora.Build/Astation/relay-server && cargo test knowledge 2>&1 | grep -E "test result|FAILED|panicked"`
Expected: `test result: ok`.

- [ ] **Step 5: Commit**

```bash
cd /home/guohai/Dev/Agora.Build/Astation && git add relay-server/src/knowledge_routes.rs && git commit -m "$(cat <<'EOF'
feat(relay): memory invalidate op and valid_at on add

{"op":"invalidate","id","invalid_at","superseded_by"?} is final and
idempotent (unknown/deleted/foreign ids are an ok no-op). invalid_at and
valid_at must be positive. A delete/invalidate that names an id deduped
earlier in the same batch follows its canonical_id.

🤖 Built with SMT <smt@agora.build>
EOF
)"
```

---

## Task 3 [Astation]: R3 — skill history endpoints (+ migration 0005), README

**Files:**
- Create: `relay-server/migrations/0005_skill_purged.sql`
- Modify: `relay-server/src/knowledge_store.rs`
- Modify: `relay-server/src/knowledge_routes.rs`
- Modify: `relay-server/src/main.rs`
- Modify: `relay-server/README.md`

**Interfaces:**
- Consumes: `SKILL_KEY`, `SKILL_COLS`, `PgSkillRow`, `skill_key_matches`, `resolve_caller`, `unavailable`, `is_valid_skill_scope`, `has_nul`, and the test helper `call` (Task 2).
- Produces:
  - `SkillRow.purged: bool` (`#[serde(skip)]`).
  - `pub struct SkillVersionInfo { version: i64, created_at: i64, source_agent: String, source_machine: String, file_count: i64, deleted: bool, purged: bool }` (Serialize, FromRow).
  - `KnowledgeStore::skill_versions(&self, account: &str, scope: &str, project: &str, name: &str) -> Result<Vec<SkillVersionInfo>, KnowledgeError>` (newest first).
  - `KnowledgeStore::skill_version(&self, account: &str, scope: &str, project: &str, name: &str, version: i64) -> Result<Option<SkillRow>, KnowledgeError>`.
  - `GET /api/skills/versions?id=&scope=&project=&name=` → 200 `{"versions":[SkillVersionInfo]}`.
  - `GET /api/skills/version?id=&scope=&project=&name=&version=` → 200 `{"skill": SkillRow}` | 404 `{"error":"no such skill version"}` | 410 `{"error":"skill version purged"}`.
  - A bad key → 400 `{"error":"invalid skill"}`; a missing version → 400 `{"error":"missing version"}`.

- [ ] **Step 1: Write the failing store tests** (`knowledge_store.rs`)

Update the `skill` fixture: add `purged: false,` after `deleted: false,`.

In `purge_selected_and_all_versions`, inside `for r in &rows {`, add `assert!(r.purged);`. After `assert!(!v2.deleted);`, add `assert!(!v2.purged);`.

Add these scenarios:

```rust
        pub async fn skill_versions_list_newest_first_without_files(s: &dyn KnowledgeStore) {
            for v in 1..=3 {
                s.push_skill(A, skill("x", &format!("v{v}")), v - 1).await.unwrap();
            }
            s.delete_skill(A, "global", "", "x").await.unwrap(); // v4: delete marker
            s.purge_skill(A, "global", "", "x", Some(vec![1])).await.unwrap();
            s.push_skill(B, skill("x", "b"), 0).await.unwrap();
            let vs = s.skill_versions(A, "global", "", "x").await.unwrap();
            let got: Vec<(i64, i64, bool, bool)> =
                vs.iter().map(|v| (v.version, v.file_count, v.deleted, v.purged)).collect();
            assert_eq!(
                got,
                vec![(4, 0, true, false), (3, 1, false, false), (2, 1, false, false), (1, 0, true, true)]
            );
            assert_eq!(
                (vs[1].source_agent.as_str(), vs[1].source_machine.as_str(), vs[1].created_at),
                ("claude", "m1", 1_700_000_000)
            );
            assert!(s.skill_versions(A, "global", "", "nope").await.unwrap().is_empty());
            assert!(s.skill_versions(A, "project", "", "x").await.unwrap().is_empty());
            assert_eq!(s.skill_versions(B, "global", "", "x").await.unwrap().len(), 1);
        }

        pub async fn skill_version_returns_one_version(s: &dyn KnowledgeStore) {
            s.push_skill(A, skill("x", "v1"), 0).await.unwrap();
            s.push_skill(A, skill("x", "v2"), 1).await.unwrap();
            s.delete_skill(A, "global", "", "x").await.unwrap(); // v3
            s.purge_skill(A, "global", "", "x", Some(vec![1])).await.unwrap();
            let v2 = s.skill_version(A, "global", "", "x", 2).await.unwrap().unwrap();
            assert_eq!((v2.version, v2.deleted, v2.purged), (2, false, false));
            assert_eq!(v2.files, json!({"SKILL.md": "v2"}));
            let v1 = s.skill_version(A, "global", "", "x", 1).await.unwrap().unwrap();
            assert!(v1.purged && v1.deleted && v1.files == json!({}));
            let v3 = s.skill_version(A, "global", "", "x", 3).await.unwrap().unwrap();
            assert!(v3.deleted && !v3.purged && v3.files == json!({}));
            assert!(s.skill_version(A, "global", "", "x", 9).await.unwrap().is_none());
            assert!(s.skill_version(B, "global", "", "x", 2).await.unwrap().is_none());
        }
```

Add both names to `in_memory_tests!` and `pg_tests!`:

```rust
        skill_versions_list_newest_first_without_files,
        skill_version_returns_one_version,
```

In `wire_rows_match_client_json`, after the skill key assertion, add:

```rust
        assert!(!s.purged, "purged is never read from the wire");
```

- [ ] **Step 2: Write the failing route tests** (`knowledge_routes.rs` `mod tests`)

Add `SkillVersionInfo` to the `use crate::knowledge_store::{…}` line in tests. In `fn app`, add:

```rust
            .route("/api/skills/versions", get(skill_versions_handler))
            .route("/api/skills/version", get(skill_version_handler))
```

`FailingStore` additions:

```rust
        async fn skill_versions(&self, _: &str, _: &str, _: &str, _: &str) -> Result<Vec<SkillVersionInfo>, KnowledgeError> {
            Err(KnowledgeError::Db("connection reset".into()))
        }
        async fn skill_version(&self, _: &str, _: &str, _: &str, _: &str, _: i64) -> Result<Option<SkillRow>, KnowledgeError> {
            Err(KnowledgeError::Db("connection reset".into()))
        }
```

In `store_failure_fails_the_whole_batch_with_503`, extend the GET loop:

```rust
        for uri in [
            "/api/memory?id=a",
            "/api/skills?id=a",
            "/api/skills/versions?id=a&scope=global&name=x",
            "/api/skills/version?id=a&scope=global&name=x&version=1",
        ] {
```

New tests:

```rust
    // ─────────────────────────── skill history ───────────────────────────

    async fn skill_op(app: &Router, sess: &str, op: Value) {
        let (st, v) = call(app, "POST", "/api/skills/batch?id=a", sess, Some(json!({"ops": [op]}))).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["results"][0]["ok"], true, "{v}");
    }

    fn push_op(name: &str, body: &str) -> Value {
        json!({"op": "push", "skill": sample_skill(name, json!({"SKILL.md": b64(body)})), "base_version": 0})
    }

    const X_KEY: &str = "scope=global&project=&name=x";

    #[tokio::test]
    async fn skill_versions_lists_history_without_files() {
        let (state, sess) = test_state("ws-1").await;
        let sess2 = bind_session(&state, "ws-2").await;
        let app = app(state);
        skill_op(&app, &sess, push_op("x", "v1")).await;
        skill_op(&app, &sess, push_op("x", "v2")).await;
        skill_op(&app, &sess, json!({"op": "delete", "scope": "global", "project": "", "name": "x"})).await;
        skill_op(&app, &sess, json!({"op": "purge", "scope": "global", "project": "", "name": "x", "versions": [1]})).await;
        let (st, v) = call(&app, "GET", &format!("/api/skills/versions?id=a&{X_KEY}"), &sess, None).await;
        assert_eq!(st, StatusCode::OK);
        let vs = v["versions"].as_array().unwrap();
        let got: Vec<(i64, bool, bool, i64)> = vs.iter().map(|r| (
            r["version"].as_i64().unwrap(), r["deleted"].as_bool().unwrap(),
            r["purged"].as_bool().unwrap(), r["file_count"].as_i64().unwrap(),
        )).collect();
        assert_eq!(got, vec![(3, true, false, 0), (2, false, false, 1), (1, true, true, 0)]);
        assert!(vs.iter().all(|r| r.get("files").is_none()));
        assert_eq!(vs[1]["source_agent"], "claude");
        assert_eq!(vs[1]["source_machine"], "m1");
        assert_eq!(vs[1]["created_at"], 1_700_000_000);
        // Another account sees an empty history.
        let (st2, v2) = call(&app, "GET", &format!("/api/skills/versions?id=a&{X_KEY}"), &sess2, None).await;
        assert_eq!((st2, v2), (StatusCode::OK, json!({"versions": []})));
    }

    #[tokio::test]
    async fn skill_version_returns_files_404_and_410() {
        let (state, sess) = test_state("ws-1").await;
        let sess2 = bind_session(&state, "ws-2").await;
        let app = app(state);
        skill_op(&app, &sess, push_op("x", "v1")).await;
        skill_op(&app, &sess, push_op("x", "v2")).await;
        skill_op(&app, &sess, json!({"op": "delete", "scope": "global", "project": "", "name": "x"})).await;
        skill_op(&app, &sess, json!({"op": "purge", "scope": "global", "project": "", "name": "x", "versions": [1]})).await;
        let get = |v: i64| format!("/api/skills/version?id=a&{X_KEY}&version={v}");
        let (st, v) = call(&app, "GET", &get(2), &sess, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["skill"]["version"], 2);
        assert_eq!(v["skill"]["files"], json!({"SKILL.md": b64("v2")}));
        assert!(v["skill"].get("purged").is_none());
        let (st, v) = call(&app, "GET", &get(3), &sess, None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!((v["skill"]["deleted"].clone(), v["skill"]["files"].clone()), (json!(true), json!({})));
        let (st, v) = call(&app, "GET", &get(1), &sess, None).await;
        assert_eq!((st, v), (StatusCode::GONE, json!({"error": "skill version purged"})));
        let (st, v) = call(&app, "GET", &get(9), &sess, None).await;
        assert_eq!((st, v), (StatusCode::NOT_FOUND, json!({"error": "no such skill version"})));
        let (st, _) = call(&app, "GET", &get(2), &sess2, None).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn skill_history_bad_queries_are_400_and_auth_is_required() {
        let (state, sess) = test_state("ws-1").await;
        let app = app(state);
        for uri in [
            "/api/skills/versions?id=a&scope=machine&name=x",
            "/api/skills/versions?id=a&scope=global",
            "/api/skills/versions?id=a&scope=global&name=x%00y",
            "/api/skills/version?id=a&scope=global&name=x",
            "/api/skills/version?id=a&scope=global&name=x&version=abc",
        ] {
            let (st, _) = call(&app, "GET", uri, &sess, None).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{uri}");
        }
        let resp = app
            .oneshot(req_no_auth("GET", "/api/skills/versions?id=a&scope=global&name=x", ""))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn skill_history_routes_are_mounted_in_the_production_router() {
        let (state, sess) = test_state("ws-1").await;
        let app = crate::router(state);
        let get = |uri: &str| {
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", format!("session {}", sess))
                .header("x-forwarded-for", "203.0.113.50")
                .body(Body::empty())
                .unwrap()
        };
        let resp = app.clone().oneshot(get("/api/skills/versions?id=a&scope=global&name=x")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = app.oneshot(get("/api/skills/version?id=a&scope=global&name=x&version=1")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(resp).await, json!({"error": "no such skill version"}));
    }
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /home/guohai/Dev/Agora.Build/Astation/relay-server && cargo test knowledge 2>&1 | tail -20`
Expected: compile errors (`no field purged`, `SkillVersionInfo` / handlers not found).

- [ ] **Step 4: Create `relay-server/migrations/0005_skill_purged.sql`**

```sql
-- Skill history needs to tell a purged version (its files were erased) from a
-- delete marker (never had files): both are stored as deleted = true,
-- files = {}, content_hash = ''. `purge` now sets this flag. Versions purged
-- before this migration can't be told apart and stay false (shown as deleted).
ALTER TABLE skill_versions ADD COLUMN purged BOOLEAN NOT NULL DEFAULT false;
```

- [ ] **Step 5: Implement the store** (`knowledge_store.rs`)

`SkillRow`: add after `deleted`:

```rust
    /// Set by `purge`: this version's files were erased. Not on the wire.
    #[serde(skip)]
    pub purged: bool,
```

Add after `SkillPushOutcome`:

```rust
/// One entry of a skill's history (`GET /api/skills/versions`). No files.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow)]
pub struct SkillVersionInfo {
    pub version: i64,
    pub created_at: i64,
    pub source_agent: String,
    pub source_machine: String,
    pub file_count: i64,
    pub deleted: bool,
    pub purged: bool,
}
```

Trait additions (after `pull_skills`):

```rust
    /// Every version of one skill, newest first, without files. An unknown
    /// skill (or another account's) → empty.
    async fn skill_versions(
        &self,
        account: &str,
        scope: &str,
        project: &str,
        name: &str,
    ) -> Result<Vec<SkillVersionInfo>, KnowledgeError>;

    /// One version with its files; `None` when it doesn't exist (or is
    /// another account's).
    async fn skill_version(
        &self,
        account: &str,
        scope: &str,
        project: &str,
        name: &str,
        version: i64,
    ) -> Result<Option<SkillRow>, KnowledgeError>;
```

In-memory:
- In `push_skill`'s pushed `SkillRow { version, deleted: false, seq, ..s }`, add `purged: false,`.
- In the `delete_skill` literal, add `purged: false,` after `deleted: true,`.
- In `purge_skill`'s loop, add `row.purged = true;` after `row.deleted = true;`.
- Add the two new methods:

```rust
    async fn skill_versions(
        &self,
        account: &str,
        scope: &str,
        project: &str,
        name: &str,
    ) -> Result<Vec<SkillVersionInfo>, KnowledgeError> {
        let st = self.state.lock().await;
        let mut out: Vec<SkillVersionInfo> = st
            .skills
            .iter()
            .filter(|(acct, r)| skill_key_matches(acct, r, account, scope, project, name))
            .map(|(_, r)| SkillVersionInfo {
                version: r.version,
                created_at: r.created_at,
                source_agent: r.source_agent.clone(),
                source_machine: r.source_machine.clone(),
                file_count: r.files.as_object().map_or(0, |o| o.len() as i64),
                deleted: r.deleted,
                purged: r.purged,
            })
            .collect();
        out.sort_by(|a, b| b.version.cmp(&a.version));
        Ok(out)
    }

    async fn skill_version(
        &self,
        account: &str,
        scope: &str,
        project: &str,
        name: &str,
        version: i64,
    ) -> Result<Option<SkillRow>, KnowledgeError> {
        let st = self.state.lock().await;
        Ok(st
            .skills
            .iter()
            .find(|(acct, r)| {
                skill_key_matches(acct, r, account, scope, project, name) && r.version == version
            })
            .map(|(_, r)| r.clone()))
    }
```

Postgres:
- `SKILL_COLS` becomes `"scope, project, name, version, files::text AS files, content_hash, source_agent, source_machine, created_at, deleted, purged, seq"` (keep the existing line-continuation style).
- `PgSkillRow` gets `purged: bool,` after `deleted`, and `TryFrom` maps `purged: r.purged,`.
- In `purge_skill`'s UPDATE, `deleted = true, seq = renum.new_seq` becomes `deleted = true, purged = true, seq = renum.new_seq`.
- Add the two new methods:

```rust
    async fn skill_versions(
        &self,
        account: &str,
        scope: &str,
        project: &str,
        name: &str,
    ) -> Result<Vec<SkillVersionInfo>, KnowledgeError> {
        sqlx::query_as::<_, SkillVersionInfo>(&format!(
            "SELECT version, created_at, source_agent, source_machine, \
             (SELECT count(*) FROM jsonb_object_keys(files))::bigint AS file_count, \
             deleted, purged FROM skill_versions WHERE {SKILL_KEY} ORDER BY version DESC"
        ))
        .bind(account)
        .bind(scope)
        .bind(project)
        .bind(name)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)
    }

    async fn skill_version(
        &self,
        account: &str,
        scope: &str,
        project: &str,
        name: &str,
        version: i64,
    ) -> Result<Option<SkillRow>, KnowledgeError> {
        let row: Option<PgSkillRow> = sqlx::query_as(&format!(
            "SELECT {SKILL_COLS} FROM skill_versions WHERE {SKILL_KEY} AND version = $5"
        ))
        .bind(account)
        .bind(scope)
        .bind(project)
        .bind(name)
        .bind(version)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(SkillRow::try_from).transpose()
    }
```

- [ ] **Step 6: Implement the routes** (`knowledge_routes.rs`, after `skills_pull_handler`)

```rust
// ─────────────────────────── skill history ───────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct SkillKeyQuery {
    id: Option<String>,
    scope: Option<String>,
    #[serde(default)]
    project: String,
    name: Option<String>,
    version: Option<i64>,
}

/// `(scope, project, name)` from the query, or 400 `invalid skill`.
fn skill_key(q: &SkillKeyQuery) -> Result<(String, String, String), ErrResp> {
    let scope = q.scope.clone().unwrap_or_default();
    let name = q.name.clone().unwrap_or_default();
    if !is_valid_skill_scope(&scope) || name.is_empty() || has_nul(&[&q.project, &name]) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid skill"));
    }
    Ok((scope, q.project.clone(), name))
}

/// GET /api/skills/versions ?scope&project&name -> {versions:[…]} (newest first, no files)
pub async fn skill_versions_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SkillKeyQuery>,
) -> Result<Json<Value>, ErrResp> {
    let caller = resolve_caller(&state, &headers, query.id.as_deref()).await?;
    let (scope, project, name) = skill_key(&query)?;
    let versions = state
        .knowledge
        .skill_versions(&caller.work_session_id, &scope, &project, &name)
        .await
        .map_err(unavailable)?;
    Ok(Json(json!({ "versions": versions })))
}

/// GET /api/skills/version ?scope&project&name&version -> {skill} | 404 | 410 (purged)
pub async fn skill_version_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SkillKeyQuery>,
) -> Result<Json<Value>, ErrResp> {
    let caller = resolve_caller(&state, &headers, query.id.as_deref()).await?;
    let (scope, project, name) = skill_key(&query)?;
    let version = query
        .version
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing version"))?;
    match state
        .knowledge
        .skill_version(&caller.work_session_id, &scope, &project, &name, version)
        .await
        .map_err(unavailable)?
    {
        None => Err(err(StatusCode::NOT_FOUND, "no such skill version")),
        Some(row) if row.purged => Err(err(StatusCode::GONE, "skill version purged")),
        Some(row) => Ok(Json(json!({ "skill": row }))),
    }
}
```

`relay-server/src/main.rs`: after `.route("/api/skills", get(knowledge_routes::skills_pull_handler))`, add:

```rust
        .route("/api/skills/versions", get(knowledge_routes::skill_versions_handler))
        .route("/api/skills/version", get(knowledge_routes::skill_version_handler))
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd /home/guohai/Dev/Agora.Build/Astation/relay-server && cargo test 2>&1 | grep -E "^test result|FAILED|panicked"`
Expected: every `test result: ok`. Note the total test count printed. Step 8 needs it.

Then run the Postgres suites with the exact script from Task 1 Step 8.
Expected: both suites `ok` (including `pg::skill_versions_list_newest_first_without_files` and `pg::skill_version_returns_one_version`), and no leftover container.

- [ ] **Step 8: Document in `relay-server/README.md`**

Replace the memory batch bullet:

```
- `POST /api/memory/batch {ops: [...]}` → `{"results": [OpResult]}` - Batch add/delete memory ops (body limit 2 MB, at most 64 ops)
```

with

```
- `POST /api/memory/batch {ops: [...]}` → `{"results": [OpResult]}` - Batch add/delete/invalidate memory ops (body limit 2 MB, at most 64 ops)
```

After the `GET /api/skills` bullet, insert:

```
- `GET /api/skills/versions?scope=&project=&name=` → `{"versions": [{version, created_at, source_agent, source_machine, file_count, deleted, purged}]}` - One skill's history, newest first, no file contents (unknown skill → empty list)
- `GET /api/skills/version?scope=&project=&name=&version=<n>` → `{"skill": SkillRow}` - One version with its files. 404 `no such skill version` (unknown, or another account's), 410 `skill version purged`; a delete marker comes back as `deleted: true` with `files: {}`. A bad scope/name → 400 `invalid skill`, no `version` → 400 `missing version`

Memory ops and validity (Atem Memory 1.1, migration 0004):

- `{"op":"add","memory":MemoryRow}` — the row may carry `valid_at` (when the fact became true; must be > 0). The client's `deleted`, `deleted_at`, `invalid_at`, `superseded_by` and `seq` are ignored.
- `{"op":"delete","id"}` — blanks the text and sets `deleted_at` (the first deletion time is kept).
- `{"op":"invalidate","id","invalid_at","superseded_by"?}` — marks a fact outdated without touching its text; `invalid_at` must be > 0. **Final:** once set it never changes. A repeat, or an unknown, deleted or other-account id, is `{ok:true, seq:0}` (no change). A change takes a new `seq`, so every atem pulls it.
- Within one batch, a `delete`/`invalidate` whose `id` or `superseded_by` names an id an earlier `add` was deduplicated onto is rewritten to that `canonical_id`.
- Memory rows carry `deleted` (computed from `deleted_at`, for older atems), `deleted_at`, `valid_at`, `invalid_at` and `superseded_by`. The dedup index covers only rows that are neither deleted nor invalid, so a fact that becomes true again is a new memory.
- `purge` also sets `skill_versions.purged` (migration 0005); that's the `purged` flag in skill history. Versions purged before 0005 report as `deleted`.
```

In the per-op refusal list, replace

```
- an invalid scope, or a NUL (`\u0000`, which Postgres can't store) in any
  memory string field → `invalid memory`; in a skill's name/project/source/
  hash or a file relpath → `invalid skill`;
```

with

```
- an invalid scope, or a NUL (`\u0000`, which Postgres can't store) in any
  memory string field, an invalidate `id`/`superseded_by`, an `invalid_at`
  or `valid_at` that isn't positive → `invalid memory`; in a skill's
  name/project/source/hash or a file relpath → `invalid skill`;
```

In "A 503 is transient…", change `delete/purge are idempotent` to `delete/invalidate/purge are idempotent`.

After `Production nginx (...) raises its 1 MB body cap to 16 MB for` `/api/skills/batch` `and 2 MB for` `/api/memory/batch only.`, add:

```
The skill-history GETs need no nginx change: they fall under `location /api/`, and the body cap applies to requests only.
```

In the Testing block, replace `266` in `cargo test  # 266 tests` with the total printed in Step 7.

- [ ] **Step 9: Commit**

```bash
cd /home/guohai/Dev/Agora.Build/Astation && git add relay-server/migrations/0005_skill_purged.sql relay-server/src/knowledge_store.rs relay-server/src/knowledge_routes.rs relay-server/src/main.rs relay-server/README.md && git commit -m "$(cat <<'EOF'
feat(relay): skill history endpoints and purged flag (migration 0005)

GET /api/skills/versions lists a skill's versions newest first without
files; GET /api/skills/version returns one version (404 unknown, 410
purged). Purge now sets skill_versions.purged, since a purged version and a
delete marker were otherwise stored identically. README documents the
invalidate op, the validity fields and the new endpoints.

🤖 Built with SMT <smt@agora.build>
EOF
)"
```

> **Deploy gate:** push the branch, open the Astation PR, and deploy the relay
> before merging the atem work (Tasks 4–9). Don't push or open the PR without
> the user's go-ahead.

---

## Task 4 [Atem]: A1 — `Memory` validity fields, store migration + FTS5, apply only valid facts

**Files:**
- Modify: `src/memory/model.rs`, `src/memory/store.rs`, `src/memory/sync.rs`, `src/memory/adapters.rs`, `src/memory/block.rs`, `src/memory/cmd.rs`, `src/memory/api.rs` (test fixture only)

**Interfaces:**
- Consumes: the relay rows from Tasks 1–2.
- Produces:
  - `Memory` (now `Default`): the `deleted: bool` field is replaced by `pub deleted_at: Option<i64>`, and it gains `pub valid_at: Option<i64>`, `pub invalid_at: Option<i64>`, `pub superseded_by: Option<String>`.
  - Methods: `Memory::is_deleted(&self) -> bool`, `Memory::is_valid(&self) -> bool`, `Memory::valid_from(&self) -> i64`.
  - `Store::live_memories()` now returns valid facts only; `Store::history_memories(&self) -> Result<Vec<Memory>>` returns everything not deleted.
  - `Store::find_live_by_hash` matches valid facts only.
  - The `memories_fts` FTS5 table and its triggers.

- [ ] **Step 1: Branch**

```bash
cd /home/guohai/Dev/Agora.Build/Atem && git checkout main && git pull --ff-only && git checkout -b feat/memory-1.1
```

- [ ] **Step 2: Write the failing tests**

`model.rs` `mod tests`:

```rust
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
```

`store.rs` `mod tests`: change `memory_roundtrip_and_live_filter`'s assertion to
`assert!(b.is_deleted() && b.content.is_empty() && b.content_hash.is_empty());`.
Then add:

```rust
    fn ids(ms: Vec<Memory>) -> Vec<String> {
        ms.into_iter().map(|m| m.id).collect()
    }

    fn fts_hits(s: &Store, q: &str) -> Vec<String> {
        let mut st = s.conn.prepare(
            "SELECT m.id FROM memories_fts JOIN memories m ON m.rowid = memories_fts.rowid WHERE memories_fts MATCH ?1 ORDER BY m.id",
        ).unwrap();
        st.query_map(params![q], |r| r.get(0)).unwrap().map(|x| x.unwrap()).collect()
    }

    #[test]
    fn legacy_db_is_migrated_once() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("knowledge.db");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch("CREATE TABLE memories (
              id TEXT PRIMARY KEY, scope TEXT NOT NULL, project TEXT NOT NULL, machine TEXT NOT NULL,
              content TEXT NOT NULL, content_hash TEXT NOT NULL, confidence TEXT NOT NULL,
              source_agent TEXT NOT NULL, source_machine TEXT NOT NULL, created_at INTEGER NOT NULL,
              deleted INTEGER NOT NULL DEFAULT 0, seq INTEGER NOT NULL DEFAULT 0);
            INSERT INTO memories VALUES ('mem_live','global','','','DialF uses TCP 8765','h1','medium','cli','m',1,0,4);
            INSERT INTO memories VALUES ('mem_gone','global','','','','','medium','cli','m',1,1,5);").unwrap();
        }
        let before = crate::memory::model::now_secs();
        let s = Store::open(&p).unwrap();
        let cols = memory_columns(&s.conn).unwrap();
        for c in ["deleted_at", "valid_at", "invalid_at", "superseded_by"] {
            assert!(cols.iter().any(|x| x == c), "{c}");
        }
        assert!(!cols.iter().any(|x| x == "deleted"));
        let gone = s.get_memory("mem_gone").unwrap().unwrap();
        assert!(gone.deleted_at.unwrap() >= before);
        let live = s.get_memory("mem_live").unwrap().unwrap();
        assert_eq!((live.deleted_at, live.valid_at, live.invalid_at, live.superseded_by.clone(), live.seq), (None, None, None, None, 4));
        assert_eq!(fts_hits(&s, "\"tcp 876\""), vec!["mem_live"]); // rebuilt over existing rows
        drop(s);
        let s = Store::open(&p).unwrap(); // idempotent
        assert_eq!(s.get_memory("mem_gone").unwrap().unwrap().deleted_at, gone.deleted_at);
        assert_eq!(ids(s.live_memories().unwrap()), vec!["mem_live"]);
        assert_eq!(fts_hits(&s, "\"tcp 876\""), vec!["mem_live"]);
    }

    #[test]
    fn fts_index_follows_inserts_updates_and_deletes() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "DialF uses TCP 8765")).unwrap();
        assert_eq!(fts_hits(&s, "\"8765\""), vec!["mem_a"]);
        s.upsert_memory(&mem("mem_a", "DialF uses TCP 9000")).unwrap();
        assert!(fts_hits(&s, "\"8765\"").is_empty());
        assert_eq!(fts_hits(&s, "\"9000\""), vec!["mem_a"]);
        s.rewrite_memory_id("mem_a", "mem_b").unwrap();
        assert_eq!(fts_hits(&s, "\"9000\""), vec!["mem_b"]);
        s.mark_memory_deleted("mem_b").unwrap();
        assert!(fts_hits(&s, "\"9000\"").is_empty());
    }

    #[test]
    fn live_means_valid_and_history_keeps_invalid() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "A")).unwrap();
        let mut b = mem("mem_b", "B");
        b.invalid_at = Some(10);
        b.superseded_by = Some("mem_a".into());
        s.upsert_memory(&b).unwrap();
        s.upsert_memory(&mem("mem_c", "C")).unwrap();
        s.mark_memory_deleted("mem_c").unwrap();
        assert_eq!(ids(s.live_memories().unwrap()), vec!["mem_a"]);
        assert_eq!(ids(s.history_memories().unwrap()), vec!["mem_a", "mem_b"]);
        // An invalid fact is not a dedup target: re-adding it makes a new memory.
        assert!(s.find_live_by_hash(Scope::Global, "", "", &content_hash("B")).unwrap().is_none());
        let c = s.get_memory("mem_c").unwrap().unwrap();
        assert!(c.is_deleted() && c.content.is_empty());
    }

    #[test]
    fn pulled_row_without_invalidation_keeps_a_local_one() {
        let s = Store::open_in_memory().unwrap();
        let mut a = mem("mem_a", "A");
        a.invalid_at = Some(10);
        a.superseded_by = Some("mem_b".into());
        s.upsert_memory(&a).unwrap();
        // The relay hasn't seen the invalidation yet.
        let mut stale = mem("mem_a", "A");
        stale.seq = 9;
        s.upsert_memory(&stale).unwrap();
        let got = s.get_memory("mem_a").unwrap().unwrap();
        assert_eq!((got.invalid_at, got.superseded_by.as_deref(), got.seq), (Some(10), Some("mem_b"), 9));
        // The relay's invalidation wins when it has one.
        let mut server = mem("mem_a", "A");
        server.invalid_at = Some(7);
        server.superseded_by = Some("mem_c".into());
        s.upsert_memory(&server).unwrap();
        let got = s.get_memory("mem_a").unwrap().unwrap();
        assert_eq!((got.invalid_at, got.superseded_by.as_deref()), (Some(7), Some("mem_c")));
    }
```

`adapters.rs` `mod tests`:

```rust
    #[test]
    fn invalid_facts_are_not_applied() {
        let (_td, ctx) = setup();
        let mut old = m(Scope::Global, "", "", "DialF listens on TCP 8765", "cli", "x");
        old.invalid_at = Some(5);
        let new = m(Scope::Global, "", "", "DialF listens on TCP 9000", "cli", "x");
        apply_memory(Agent::Claude, &ctx, &[old, new]);
        let text = read(ctx.home.join(".claude/CLAUDE.md"));
        assert!(text.contains("TCP 9000") && !text.contains("TCP 8765"));
    }
```

`sync.rs` `mod tests` (the design's headline 1.1 E2E, on B's side):

```rust
    #[tokio::test]
    async fn pulled_replacement_leaves_the_block_but_stays_in_history() {
        let s = Store::open_in_memory().unwrap();
        let (base, _log) = stub_relay(Box::new(|m, p, _| {
            if m == "GET" && p.starts_with("/api/memory?") && p.contains("since=0&") {
                let row = |id: &str, content: &str, invalid_at: serde_json::Value, superseded_by: serde_json::Value, seq: i64| serde_json::json!({
                    "id": id, "scope": "global", "project": "", "machine": "", "content": content,
                    "content_hash": content_hash(content), "confidence": "high", "source_agent": "cli",
                    "source_machine": "m2", "created_at": 1, "deleted": false, "deleted_at": null,
                    "valid_at": null, "invalid_at": invalid_at, "superseded_by": superseded_by, "seq": seq,
                });
                return (200, serde_json::json!({"memories": [
                    row("mem_new", "DialF listens on TCP 9000", serde_json::Value::Null, serde_json::Value::Null, 2),
                    row("mem_old", "DialF listens on TCP 8765", serde_json::json!(1_790_000_000), serde_json::json!("mem_new"), 3),
                ]}));
            }
            empty_pulls(m, p).unwrap()
        })).await;
        let (_td, ctx) = test_ctx();
        std::fs::create_dir_all(ctx.home.join(".claude")).unwrap();
        run_sync(&s, Some(&client(&base, "ast-a")), &ctx, &NO_HARVEST).await.unwrap();
        let text = std::fs::read_to_string(ctx.home.join(".claude/CLAUDE.md")).unwrap();
        assert!(text.contains("TCP 9000") && !text.contains("TCP 8765"), "{text}");
        let old = s.get_memory("mem_old").unwrap().unwrap();
        assert_eq!((old.invalid_at, old.superseded_by.as_deref()), (Some(1_790_000_000), Some("mem_new")));
        assert_eq!(s.history_memories().unwrap().len(), 2);
        assert_eq!(s.live_memories().unwrap().len(), 1);
    }
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo test memory:: 2>&1 | tail -20`
Expected: compile errors (`no field deleted_at`, `Memory: Default` not satisfied, `history_memories`/`memory_columns` not found).

- [ ] **Step 4: Implement `model.rs`**

Replace the `Memory` struct:

```rust
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
```

- [ ] **Step 5: Implement `store.rs`**

In the `SCHEMA` memories table, replace

```
  deleted INTEGER NOT NULL DEFAULT 0, seq INTEGER NOT NULL DEFAULT 0);
```

(the one in `CREATE TABLE IF NOT EXISTS memories`) with

```
  deleted_at INTEGER, valid_at INTEGER, invalid_at INTEGER, superseded_by TEXT,
  seq INTEGER NOT NULL DEFAULT 0);
```

Add after `SCHEMA`:

```rust
/// Full-text index over `memories.content`: external content, and trigram
/// so it matches inside CJK text too. Kept in step by triggers. `memories` is
/// a rowid table (TEXT PRIMARY KEY, not WITHOUT ROWID). Never VACUUM this
/// database without `INSERT INTO memories_fts(memories_fts) VALUES ('rebuild')`
/// afterwards: VACUUM may renumber those rowids.
const FTS_SCHEMA: &str = "
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
  content, content='memories', content_rowid='rowid', tokenize='trigram');
CREATE TRIGGER IF NOT EXISTS memories_fts_ai AFTER INSERT ON memories BEGIN
  INSERT INTO memories_fts(rowid, content) VALUES (new.rowid, new.content);
END;
CREATE TRIGGER IF NOT EXISTS memories_fts_ad AFTER DELETE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
END;
CREATE TRIGGER IF NOT EXISTS memories_fts_au AFTER UPDATE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
  INSERT INTO memories_fts(rowid, content) VALUES (new.rowid, new.content);
END;
";

fn memory_columns(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("PRAGMA table_info(memories)")?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    Ok(cols.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Bring a pre-1.1 `memories` table to the current shape: `deleted` →
/// `deleted_at` (deleted rows get "now"; the real time was never stored),
/// plus the validity columns. Idempotent; one transaction.
fn migrate_memories(conn: &Connection) -> Result<()> {
    let cols = memory_columns(conn)?;
    let has = |c: &str| cols.iter().any(|x| x == c);
    let wanted = ["deleted_at", "valid_at", "invalid_at", "superseded_by"];
    if !has("deleted") && wanted.iter().all(|c| has(c)) {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    if !has("deleted_at") {
        tx.execute_batch("ALTER TABLE memories ADD COLUMN deleted_at INTEGER")?;
        if has("deleted") {
            tx.execute("UPDATE memories SET deleted_at = ?1 WHERE deleted != 0", params![crate::memory::model::now_secs()])?;
        }
    }
    for (c, ty) in [("valid_at", "INTEGER"), ("invalid_at", "INTEGER"), ("superseded_by", "TEXT")] {
        if !has(c) {
            tx.execute_batch(&format!("ALTER TABLE memories ADD COLUMN {} {}", c, ty))?;
        }
    }
    if has("deleted") {
        tx.execute_batch("ALTER TABLE memories DROP COLUMN deleted")?;
    }
    tx.commit()?;
    Ok(())
}
```

Replace `MEM_COLS` and `row_to_memory`:

```rust
const MEM_COLS: &str = "id, scope, project, machine, content, content_hash, confidence, source_agent, source_machine, created_at, deleted_at, valid_at, invalid_at, superseded_by, seq";

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
        deleted_at: r.get(10)?,
        valid_at: r.get(11)?,
        invalid_at: r.get(12)?,
        superseded_by: r.get(13)?,
        seq: r.get(14)?,
    })
}
```

Replace `init`:

```rust
    fn init(conn: Connection) -> Result<Store> {
        conn.execute_batch(SCHEMA)?;
        migrate_memories(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let had_fts: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'memories_fts')", [], |r| r.get(0))?;
        tx.execute_batch(FTS_SCHEMA)?;
        if !had_fts {
            // Index the rows that existed before the index did.
            tx.execute_batch("INSERT INTO memories_fts(memories_fts) VALUES ('rebuild')")?;
        }
        tx.commit()?;
        Ok(Store { conn })
    }
```

Replace `upsert_memory`, `live_memories`, `find_live_by_hash` and `mark_memory_deleted`, and add `history_memories`:

```rust
    /// Insert or overwrite (the relay is authoritative), except that a local
    /// invalidation the incoming row doesn't have yet is kept. Invalidation
    /// is final, so it can only be "not yet pulled", never undone.
    pub fn upsert_memory(&self, m: &Memory) -> Result<()> {
        self.conn.execute(
            "INSERT INTO memories (id, scope, project, machine, content, content_hash, confidence, source_agent, source_machine, created_at, deleted_at, valid_at, invalid_at, superseded_by, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(id) DO UPDATE SET scope=excluded.scope, project=excluded.project, machine=excluded.machine,
               content=excluded.content, content_hash=excluded.content_hash, confidence=excluded.confidence,
               source_agent=excluded.source_agent, source_machine=excluded.source_machine,
               created_at=excluded.created_at, deleted_at=excluded.deleted_at, valid_at=excluded.valid_at,
               invalid_at=COALESCE(excluded.invalid_at, memories.invalid_at),
               superseded_by=CASE WHEN excluded.invalid_at IS NOT NULL THEN excluded.superseded_by ELSE memories.superseded_by END,
               seq=excluded.seq",
            params![m.id, m.scope.as_str(), m.project, m.machine, m.content, m.content_hash, m.confidence,
                    m.source_agent, m.source_machine, m.created_at, m.deleted_at, m.valid_at, m.invalid_at,
                    m.superseded_by, m.seq],
        )?;
        Ok(())
    }
```

```rust
    /// Valid facts: not deleted and not invalidated (what gets injected).
    pub fn live_memories(&self) -> Result<Vec<Memory>> {
        let mut stmt = self.conn.prepare(&format!("SELECT {} FROM memories WHERE deleted_at IS NULL AND invalid_at IS NULL ORDER BY created_at, id", MEM_COLS))?;
        let rows = stmt.query_map([], row_to_memory)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Everything not deleted, including invalidated facts (the history).
    pub fn history_memories(&self) -> Result<Vec<Memory>> {
        let mut stmt = self.conn.prepare(&format!("SELECT {} FROM memories WHERE deleted_at IS NULL ORDER BY created_at, id", MEM_COLS))?;
        let rows = stmt.query_map([], row_to_memory)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// A valid fact with this dedup key. Invalid facts never match, so a fact
    /// that becomes true again is added as a new memory.
    pub fn find_live_by_hash(&self, scope: Scope, project: &str, machine: &str, hash: &str) -> Result<Option<Memory>> {
        Ok(self.conn
            .query_row(
                &format!("SELECT {} FROM memories WHERE deleted_at IS NULL AND invalid_at IS NULL AND scope = ?1 AND project = ?2 AND machine = ?3 AND content_hash = ?4 LIMIT 1", MEM_COLS),
                params![scope.as_str(), project, machine, hash],
                row_to_memory,
            )
            .optional()?)
    }

    /// Tombstone: also clears the text so it doesn't linger locally. The
    /// first deletion time is kept.
    pub fn mark_memory_deleted(&self, id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE memories SET deleted_at = COALESCE(deleted_at, ?2), content = '', content_hash = '' WHERE id = ?1",
            params![id, crate::memory::model::now_secs()],
        )?;
        Ok(())
    }
```

- [ ] **Step 6: Mechanical call-site updates**

**Memory struct literals.** Replace `deleted: false, seq: N,` with
`seq: N, ..Default::default()`. There's no trailing comma after
`..Default::default()`, and the rest of each literal stays the same. The
sites:

| File | Line (approx.) | Literal |
|---|---|---|
| `src/memory/store.rs` | 352 | test `mem()` |
| `src/memory/api.rs` | 204 | test `sample()` |
| `src/memory/adapters.rs` | 320 | test `m()` |
| `src/memory/sync.rs` | 76 | harvest's new `Memory` (prod) |
| `src/memory/sync.rs` | 502, 520, 662, 791 | test memories (`seq: 3`, `seq: 3`, `seq: 5`, `seq: 0`) |
| `src/memory/block.rs` | 121 | test `mem()` |
| `src/memory/cmd.rs` | 317 | `memory add` (prod) |

The `Skill` literals (`model.rs:198`, `sync.rs:685`, `cmd.rs:446`,
`skills_fs.rs:221`, and so on) keep `deleted`.

**Memory `.deleted` uses:**

| File | Old | New |
|---|---|---|
| `sync.rs` `apply_pulled_memories` | `if row.deleted {` | `if row.is_deleted() {` |
| `sync.rs` tests (`changed_file_does_not_delete_shared_memory`, `deleted_file_keeps_memory_other_origin_references`) | `.deleted` on a `Memory` | `.is_deleted()` |
| `sync.rs` test `pulled_memories_upsert_and_tombstone` | `b.deleted = true;` / `got_b.deleted` | `b.deleted_at = Some(7);` / `got_b.is_deleted()` |
| `sync.rs` test `single_op_413_stays_queued_and_stops_its_group` | `is_some_and(\|m\| !m.deleted)` | `is_some_and(\|m\| !m.is_deleted())` |
| `cmd.rs` `MemoryCommands::Rm` | `.filter(\|m\| !m.deleted)` | `.filter(\|m\| !m.is_deleted())` |
| `adapters.rs` `apply_memory` | `.filter(\|m\| !m.deleted && !agent.skips_echo(m, ctx))` | `.filter(\|m\| m.is_valid() && !agent.skips_echo(m, ctx))` |
| `block.rs` `select_entries` | `.filter(\|m\| !m.deleted && …)` | `.filter(\|m\| m.is_valid() && …)` |
| `block.rs` test `select_caps_count_and_bytes_and_skips_deleted` | `d.deleted = true;` | `d.deleted_at = Some(5);` |

Update `select_entries`'s doc comment: "Live memories" → "Valid facts".
`sync::apply_all` already uses `live_memories()`, which now means valid,
so invalid facts are skipped with no further change.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo test memory:: 2>&1 | grep -E "test result|FAILED|panicked"`
Expected: `test result: ok`.

- [ ] **Step 8: Commit**

```bash
cd /home/guohai/Dev/Agora.Build/Atem && git add src/memory && git commit -m "$(cat <<'EOF'
feat(memory): validity fields, deleted_at and an FTS5 index in the local store

Memory gets deleted_at/valid_at/invalid_at/superseded_by (wire still carries
`deleted`; legacy rows parse). knowledge.db migrates in place (deleted →
deleted_at) and gains a trigram FTS5 index kept in step by triggers. Apply
and dedup see valid facts only; a pulled row never undoes a pending local
invalidation.

🤖 Built with SMT <smt@agora.build>
EOF
)"
```

---

## Task 5 [Atem]: A2 — replace, invalidate, `--valid-at`, `list --history`, short ids, status forks

**Files:**
- Modify: `src/memory/model.rs`, `src/memory/store.rs`, `src/memory/api.rs`, `src/memory/sync.rs`, `src/memory/cmd.rs`, `src/cli.rs`

**Interfaces:**
- Consumes: Task 4's `Memory`, `Store::{live_memories, history_memories, find_live_by_hash, upsert_memory}`.
- Produces:
  - model: `pub fn short_id(id: &str) -> &str`, `pub fn parse_date(s: &str) -> Result<i64>`, `pub fn format_date(secs: i64) -> String`, `pub fn format_datetime(secs: i64) -> String`.
  - `PendingOp::InvalidateMemory { id: String, invalid_at: i64, superseded_by: Option<String> }` → wire `{"op":"invalidate","id","invalid_at","superseded_by"}`.
  - `Store::invalidate_memory(&self, id: &str, invalid_at: i64, superseded_by: Option<&str>) -> Result<bool>`.
  - `Store::record_replacement(&self, new_id: &str, old_id: &str) -> Result<()>`.
  - `Store::resolve_memory_id(&self, input: &str) -> Result<String>`.
  - `Store::multi_successors(&self) -> Result<Vec<(String, Vec<String>)>>`.
  - `Store::replace_pending(&self, n: i64, op: &PendingOp) -> Result<()>`.
  - `sync::invalidate_and_queue(store: &Store, id: &str, invalid_at: i64, successor: Option<&str>) -> Result<bool>`.
  - `sync::replace_memory(store: &Store, old: &Memory, content: &str, valid_at: Option<i64>, source_agent: &str, source_machine: &str) -> Result<String>`.
  - CLI:
    - `memory replace <id> <content> [--valid-at]`
    - `memory invalidate <id> [--at]`
    - `memory add … [--valid-at]`
    - `memory list … [--history [<ID>]]`

- [ ] **Step 1: Write the failing tests**

`model.rs` `mod tests`:

```rust
    #[test]
    fn short_id_is_eight_chars_after_prefix() {
        assert_eq!(short_id("mem_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"), "1a2b3c4d");
        assert_eq!(short_id("mem_abc"), "abc");
        assert_eq!(short_id("xyz123456789"), "xyz12345");
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
```

`store.rs` `mod tests`:

```rust
    #[test]
    fn resolve_accepts_full_ids_and_unique_prefixes() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_1a2b3c4d5e", "A")).unwrap();
        s.upsert_memory(&mem("mem_1a2bffff", "B")).unwrap();
        s.upsert_memory(&mem("mem_9999", "C")).unwrap();
        s.mark_memory_deleted("mem_9999").unwrap();
        assert_eq!(s.resolve_memory_id("mem_1a2b3c4d5e").unwrap(), "mem_1a2b3c4d5e");
        assert_eq!(s.resolve_memory_id("1a2b3c4d").unwrap(), "mem_1a2b3c4d5e");
        assert_eq!(s.resolve_memory_id("mem_1a2bf").unwrap(), "mem_1a2bffff");
        assert!(s.resolve_memory_id("1a2b").unwrap_err().to_string().contains("more than one"));
        assert!(s.resolve_memory_id("9999").unwrap_err().to_string().contains("No memory"));
        assert!(s.resolve_memory_id("zz").is_err());
    }

    #[test]
    fn invalidate_is_final_locally() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "A")).unwrap();
        assert!(s.invalidate_memory("mem_a", 10, Some("mem_b")).unwrap());
        assert!(!s.invalidate_memory("mem_a", 20, None).unwrap());
        s.upsert_memory(&mem("mem_d", "D")).unwrap();
        s.mark_memory_deleted("mem_d").unwrap();
        assert!(!s.invalidate_memory("mem_d", 20, None).unwrap());
        let a = s.get_memory("mem_a").unwrap().unwrap();
        assert_eq!((a.invalid_at, a.superseded_by.as_deref(), a.content.as_str()), (Some(10), Some("mem_b"), "A"));
    }

    #[test]
    fn two_valid_successors_are_reported() {
        let s = Store::open_in_memory().unwrap();
        let mut x = mem("mem_x", "X");
        x.invalid_at = Some(5);
        x.superseded_by = Some("mem_a".into());
        s.upsert_memory(&x).unwrap();
        s.upsert_memory(&mem("mem_a", "A")).unwrap();
        s.upsert_memory(&mem("mem_b", "B")).unwrap();
        assert!(s.multi_successors().unwrap().is_empty());
        // This machine's replacement lost the race on the relay: only the local table knows.
        s.record_replacement("mem_b", "mem_x").unwrap();
        assert_eq!(s.multi_successors().unwrap(), vec![("mem_x".to_string(), vec!["mem_a".to_string(), "mem_b".to_string()])]);
        s.invalidate_memory("mem_b", 6, None).unwrap();
        assert!(s.multi_successors().unwrap().is_empty());
    }

    #[test]
    fn invalidate_op_is_a_memory_op() {
        let op = PendingOp::InvalidateMemory { id: "mem_a".into(), invalid_at: 5, superseded_by: None };
        assert!(op.is_memory());
        let s = Store::open_in_memory().unwrap();
        s.enqueue(&op).unwrap();
        assert_eq!(s.pending().unwrap()[0].1, op);
    }
```

`api.rs` `mod tests`:

```rust
    #[test]
    fn invalidate_wire() {
        let op = PendingOp::InvalidateMemory { id: "mem_old".into(), invalid_at: 1790000000, superseded_by: Some("mem_new".into()) };
        assert_eq!(op_to_wire(&op), json!({"op": "invalidate", "id": "mem_old", "invalid_at": 1790000000, "superseded_by": "mem_new"}));
        let bare = PendingOp::InvalidateMemory { id: "mem_old".into(), invalid_at: 5, superseded_by: None };
        assert_eq!(op_to_wire(&bare)["superseded_by"], serde_json::Value::Null);
        // A replace's add carries valid_at to the relay.
        let mut m = sample();
        m.valid_at = Some(1690000000);
        assert_eq!(op_to_wire(&PendingOp::AddMemory { memory: m })["memory"]["valid_at"], 1690000000);
    }
```

`sync.rs` `mod tests`:

```rust
    fn valid(id: &str, content: &str) -> Memory {
        Memory {
            id: id.into(), scope: Scope::Global, content: content.into(), content_hash: content_hash(content),
            confidence: "high".into(), source_agent: "cli".into(), source_machine: "m1".into(), created_at: 1,
            ..Default::default()
        }
    }

    #[test]
    fn replace_queues_add_then_invalidate() {
        let s = Store::open_in_memory().unwrap();
        let old = valid("mem_old", "DialF listens on TCP 8765");
        s.upsert_memory(&old).unwrap();
        let new_id = replace_memory(&s, &old, "DialF listens on TCP 9000", Some(1_790_000_000), "cli", "m1").unwrap();
        let ops: Vec<PendingOp> = s.pending().unwrap().into_iter().map(|(_, op)| op).collect();
        assert_eq!(ops.len(), 2);
        let PendingOp::AddMemory { memory } = &ops[0] else { panic!("{:?}", ops[0]) };
        assert_eq!(
            (memory.id.as_str(), memory.content.as_str(), memory.valid_at, memory.confidence.as_str()),
            (new_id.as_str(), "DialF listens on TCP 9000", Some(1_790_000_000), "high")
        );
        assert_eq!(ops[1], PendingOp::InvalidateMemory { id: "mem_old".into(), invalid_at: 1_790_000_000, superseded_by: Some(new_id.clone()) });
        let o = s.get_memory("mem_old").unwrap().unwrap();
        assert_eq!((o.invalid_at, o.superseded_by.as_deref(), o.content.as_str()), (Some(1_790_000_000), Some(new_id.as_str()), "DialF listens on TCP 8765"));
        let live: Vec<String> = s.live_memories().unwrap().into_iter().map(|m| m.id).collect();
        assert_eq!(live, vec![new_id]);
    }

    #[test]
    fn invalidate_and_queue_is_final() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&valid("mem_a", "A")).unwrap();
        assert!(invalidate_and_queue(&s, "mem_a", 10, None).unwrap());
        assert!(!invalidate_and_queue(&s, "mem_a", 20, Some("mem_b")).unwrap());
        assert!(!invalidate_and_queue(&s, "mem_nope", 20, None).unwrap());
        let a = s.get_memory("mem_a").unwrap().unwrap();
        assert_eq!((a.invalid_at, a.superseded_by), (Some(10), None));
        assert_eq!(s.pending_count().unwrap(), 1);
    }

    #[test]
    fn replace_reuses_an_existing_fact_and_refuses_the_same_fact() {
        let s = Store::open_in_memory().unwrap();
        let old = valid("mem_old", "port 8765");
        s.upsert_memory(&old).unwrap();
        s.upsert_memory(&valid("mem_9000", "port 9000")).unwrap();
        assert_eq!(replace_memory(&s, &old, "Port  9000", None, "cli", "m1").unwrap(), "mem_9000");
        let ops = s.pending().unwrap();
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0].1, PendingOp::InvalidateMemory { id, superseded_by: Some(sb), invalid_at } if id == "mem_old" && sb == "mem_9000" && *invalid_at > 0));
        let same = valid("mem_same", "same fact");
        s.upsert_memory(&same).unwrap();
        assert!(replace_memory(&s, &same, "SAME  fact", None, "cli", "m1").unwrap_err().to_string().contains("same fact as mem_same"));
    }

    #[test]
    fn canonical_rewrite_fixes_the_queued_invalidation() {
        let s = Store::open_in_memory().unwrap();
        let old = valid("mem_old", "port 8765");
        s.upsert_memory(&old).unwrap();
        replace_memory(&s, &old, "port 9000", None, "cli", "m1").unwrap();
        // Only the add went out (a chunk boundary fell between the two ops).
        let sent: Vec<_> = s.pending().unwrap().into_iter().take(1).collect();
        apply_push_results(&s, &sent, &[OpResult { ok: true, canonical_id: Some("mem_canon".into()), seq: Some(4), ..Default::default() }]).unwrap();
        let left = s.pending().unwrap();
        assert_eq!(left.len(), 1);
        assert!(matches!(&left[0].1, PendingOp::InvalidateMemory { id, superseded_by: Some(sb), .. } if id == "mem_old" && sb == "mem_canon"));
        assert_eq!(s.get_memory("mem_old").unwrap().unwrap().superseded_by.as_deref(), Some("mem_canon"));
    }
```

`cmd.rs` `mod tests`:

```rust
    fn hist(id: &str, content: &str, created: i64, invalid_at: Option<i64>, superseded_by: Option<&str>) -> Memory {
        Memory {
            id: id.into(), scope: Scope::Global, content: content.into(), content_hash: content_hash(content),
            confidence: "high".into(), source_agent: "cli".into(), source_machine: "m".into(), created_at: created,
            invalid_at, superseded_by: superseded_by.map(str::to_string), ..Default::default()
        }
    }

    #[test]
    fn history_chains_run_oldest_first() {
        let ms = vec![
            hist("mem_c", "port 9100", 30, None, None),
            hist("mem_x", "unrelated", 5, None, None),
            hist("mem_a", "port 8765", 10, Some(20), Some("mem_b")),
            hist("mem_b", "port 9000", 20, Some(30), Some("mem_c")),
        ];
        let chains: Vec<Vec<String>> = history_chains(&ms).into_iter().map(|c| c.into_iter().map(|m| m.id).collect()).collect();
        assert_eq!(chains, vec![vec!["mem_x".to_string()], vec!["mem_a".into(), "mem_b".into(), "mem_c".into()]]);
        let lines = render_history(&history_chains(&ms));
        assert!(lines[0].starts_with("  1. mem_x"), "{}", lines[0]);
        assert!(lines[1].starts_with("  2. mem_a") && lines[1].contains("1970-01-01 → 1970-01-01"), "{}", lines[1]);
        assert!(lines[2].starts_with("     mem_b"), "{}", lines[2]);
        assert!(lines[3].starts_with("     mem_c") && lines[3].contains("→ now"), "{}", lines[3]);
        assert_eq!(render_history(&[]), vec!["(no memories)".to_string()]);
    }

    #[test]
    fn validity_commands_parse() {
        use clap::Parser;
        let ok = |args: &[&str]| crate::cli::Cli::try_parse_from(args).is_ok();
        assert!(ok(&["atem", "memory", "replace", "1a2b3c4d", "new fact"]));
        assert!(ok(&["atem", "memory", "replace", "1a2b3c4d", "new fact", "--valid-at", "2026-09-30"]));
        assert!(ok(&["atem", "memory", "invalidate", "mem_x", "--at", "1790000000"]));
        assert!(ok(&["atem", "memory", "add", "x", "--valid-at", "2026-09-30"]));
        let history = |args: &[&str]| match crate::cli::Cli::try_parse_from(args).unwrap().command {
            Some(crate::cli::Commands::Memory { command: MemoryCommands::List { history, .. } }) => history,
            _ => panic!("not memory list"),
        };
        assert_eq!(history(&["atem", "memory", "list"]), None);
        assert_eq!(history(&["atem", "memory", "list", "--history"]), Some(None));
        assert_eq!(history(&["atem", "memory", "list", "--history", "1a2b"]), Some(Some("1a2b".to_string())));
        assert_eq!(history(&["atem", "memory", "list", "--history", "--all"]), Some(None));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo test memory:: 2>&1 | tail -20`
Expected: compile errors (`short_id`, `parse_date`, `InvalidateMemory`, `replace_memory`, `history_chains`, `List { history }` not found).

- [ ] **Step 3: Implement `model.rs`** (after `now_secs`)

```rust
/// The short id shown in the Codex block: the first 8 characters after `mem_`.
pub fn short_id(id: &str) -> &str {
    let rest = id.strip_prefix("mem_").unwrap_or(id);
    match rest.char_indices().nth(8) {
        Some((i, _)) => &rest[..i],
        None => rest,
    }
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
```

- [ ] **Step 4: Implement `store.rs`**

- Change the import `use anyhow::{Context, Result};` to `use anyhow::{bail, Context, Result};`.
- In `SCHEMA`, add a line before the closing `";`:

```
CREATE TABLE IF NOT EXISTS replacements (new_id TEXT PRIMARY KEY, old_id TEXT NOT NULL);
```

`PendingOp` and `is_memory`:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PendingOp {
    AddMemory { memory: Memory },
    DeleteMemory { id: String },
    InvalidateMemory { id: String, invalid_at: i64, superseded_by: Option<String> },
    PushSkill { skill: Skill, base_version: i64 },
    DeleteSkill { scope: Scope, project: String, name: String },
    PurgeSkill { scope: Scope, project: String, name: String, versions: Option<Vec<i64>> },
}

impl PendingOp {
    pub fn is_memory(&self) -> bool {
        matches!(self, PendingOp::AddMemory { .. } | PendingOp::DeleteMemory { .. } | PendingOp::InvalidateMemory { .. })
    }
}
```

Add after `mark_memory_deleted`:

```rust
    /// Set `invalid_at` (and `superseded_by`) on a memory that is neither
    /// deleted nor already invalid. Returns false when nothing changed:
    /// invalidation is final.
    pub fn invalidate_memory(&self, id: &str, invalid_at: i64, superseded_by: Option<&str>) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE memories SET invalid_at = ?2, superseded_by = ?3 WHERE id = ?1 AND deleted_at IS NULL AND invalid_at IS NULL",
            params![id, invalid_at, superseded_by],
        )?;
        Ok(n > 0)
    }

    /// Local-only note that `new_id` was written to replace `old_id`. The
    /// relay keeps only the first replacement of a fact (invalidation is
    /// final), so this is how a second, concurrent replacement is noticed.
    pub fn record_replacement(&self, new_id: &str, old_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO replacements (new_id, old_id) VALUES (?1, ?2) ON CONFLICT(new_id) DO UPDATE SET old_id = excluded.old_id",
            params![new_id, old_id],
        )?;
        Ok(())
    }

    /// A full id, or a unique prefix of one. Without `mem_`, the prefix is of
    /// the part after it (the short id shown in the Codex block). Deleted
    /// memories never match.
    pub fn resolve_memory_id(&self, input: &str) -> Result<String> {
        let input = input.trim();
        if input.is_empty() {
            bail!("Pass a memory id");
        }
        let prefix = if input.starts_with("mem_") { input.to_string() } else { format!("mem_{}", input) };
        let mut stmt = self.conn.prepare(
            "SELECT id FROM memories WHERE deleted_at IS NULL AND (id = ?1 OR substr(id, 1, length(?2)) = ?2) ORDER BY id",
        )?;
        let ids: Vec<String> = stmt.query_map(params![input, prefix], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        if let Some(exact) = ids.iter().find(|i| i.as_str() == input) {
            return Ok(exact.clone());
        }
        match ids.len() {
            0 => bail!("No memory {}", input),
            1 => Ok(ids[0].clone()),
            n => bail!("{} matches {} memories — use more characters of the id (more than one match)", input, n),
        }
    }

    /// Facts (not deleted) with more than one valid successor: `(old id,
    /// [successor ids])`. Links come from `superseded_by` and from this
    /// machine's `replacements`.
    pub fn multi_successors(&self) -> Result<Vec<(String, Vec<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT l.old_id, l.new_id FROM (
                 SELECT id AS old_id, superseded_by AS new_id FROM memories WHERE superseded_by IS NOT NULL
                 UNION SELECT old_id, new_id FROM replacements
             ) l
             JOIN memories o ON o.id = l.old_id
             JOIN memories s ON s.id = l.new_id
             WHERE o.deleted_at IS NULL AND s.deleted_at IS NULL AND s.invalid_at IS NULL
             ORDER BY l.old_id, l.new_id",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for row in rows {
            let (old, new) = row?;
            match out.last_mut() {
                Some((o, v)) if *o == old => v.push(new),
                _ => out.push((old, vec![new])),
            }
        }
        Ok(out.into_iter().filter(|(_, v)| v.len() > 1).collect())
    }
```

Add after `ack`:

```rust
    pub fn replace_pending(&self, n: i64, op: &PendingOp) -> Result<()> {
        self.conn.execute("UPDATE pending_ops SET payload = ?2 WHERE n = ?1", params![n, serde_json::to_string(op)?])?;
        Ok(())
    }
```

In `rewrite_memory_id`, after the `UPDATE harvest_map …` line and before `Ok(())`, add:

```rust
        self.conn.execute("UPDATE memories SET superseded_by = ?2 WHERE superseded_by = ?1", params![old, new])?;
        self.conn.execute("UPDATE OR REPLACE replacements SET new_id = ?2 WHERE new_id = ?1", params![old, new])?;
        self.conn.execute("UPDATE replacements SET old_id = ?2 WHERE old_id = ?1", params![old, new])?;
        // Queued ops that still name the old id (e.g. replace's invalidate,
        // when a chunk boundary fell after its add).
        for (n, op) in self.pending()? {
            let fixed = match op {
                PendingOp::InvalidateMemory { id, invalid_at, superseded_by }
                    if id == old || superseded_by.as_deref() == Some(old) =>
                {
                    PendingOp::InvalidateMemory {
                        id: if id == old { new.to_string() } else { id },
                        invalid_at,
                        superseded_by: superseded_by.map(|s| if s == old { new.to_string() } else { s }),
                    }
                }
                PendingOp::DeleteMemory { id } if id == old => PendingOp::DeleteMemory { id: new.to_string() },
                _ => continue,
            };
            self.replace_pending(n, &fixed)?;
        }
```

- [ ] **Step 5: Implement `api.rs` and `sync.rs`**

`api.rs` `op_to_wire`: add the arm after `DeleteMemory`:

```rust
        PendingOp::InvalidateMemory { id, invalid_at, superseded_by } => json!({"op": "invalidate", "id": id, "invalid_at": invalid_at, "superseded_by": superseded_by}),
```

`sync.rs`:
- Change the imports to `use anyhow::{bail, Result};` and `use crate::memory::model::{content_hash, new_memory_id, now_secs, Memory, Scope, Skill};`.
- In `describe`, add `PendingOp::InvalidateMemory { id, .. } => format!("invalidation of {}", id),`.
- Add after `release_memory`:

```rust
/// Invalidate `id` locally and queue the op; `successor` is recorded as its
/// replacement. Returns false, and queues nothing, when `id` is unknown,
/// deleted, or already invalid (invalidation is final).
pub fn invalidate_and_queue(store: &Store, id: &str, invalid_at: i64, successor: Option<&str>) -> Result<bool> {
    if !store.invalidate_memory(id, invalid_at, successor)? {
        return Ok(false);
    }
    if let Some(s) = successor {
        store.record_replacement(s, id)?;
    }
    store.enqueue(&PendingOp::InvalidateMemory {
        id: id.to_string(),
        invalid_at,
        superseded_by: successor.map(str::to_string),
    })?;
    Ok(true)
}

/// Replace `old` with `content`: same scope/project/machine/confidence. An
/// existing valid fact with the same text becomes the successor; otherwise
/// a new memory is added. The add is queued before the invalidate (same
/// batch unless a chunk boundary splits them). `old` stops being true when
/// the new fact starts (`valid_at`, else now). The caller has already run
/// the secret check on `content`. Returns the successor's id.
pub fn replace_memory(store: &Store, old: &Memory, content: &str, valid_at: Option<i64>, source_agent: &str, source_machine: &str) -> Result<String> {
    let hash = content_hash(content);
    if hash == old.content_hash {
        bail!("That is the same fact as {}; nothing to replace.", old.id);
    }
    let successor = match store.find_live_by_hash(old.scope, &old.project, &old.machine, &hash)? {
        Some(existing) => existing.id,
        None => {
            let m = Memory {
                id: new_memory_id(), scope: old.scope, project: old.project.clone(), machine: old.machine.clone(),
                content: content.to_string(), content_hash: hash, confidence: old.confidence.clone(),
                source_agent: source_agent.to_string(), source_machine: source_machine.to_string(),
                created_at: now_secs(), valid_at, ..Default::default()
            };
            store.upsert_memory(&m)?;
            store.enqueue(&PendingOp::AddMemory { memory: m.clone() })?;
            m.id
        }
    };
    invalidate_and_queue(store, &old.id, valid_at.unwrap_or_else(now_secs), Some(&successor))?;
    Ok(successor)
}
```

(`apply_push_results` needs no new arm. A successful invalidate falls into
`_ => {}`, and a refused one gets the generic "relay refused invalidation
of …" note.)

- [ ] **Step 6: Implement the CLI** (`src/cli.rs` `MemoryCommands`)

In `Add`, after `force: bool,`:

```rust
        /// When the fact became true: YYYY-MM-DD (UTC) or unix seconds (default: now)
        #[arg(long)]
        valid_at: Option<String>,
```

Replace `List`:

```rust
    /// List valid memories (global, this machine, and the current project unless --all)
    List {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        all: bool,
        /// Include outdated facts and show replacement chains, oldest first
        /// (with an id: just the chain containing it)
        #[arg(long, value_name = "ID", num_args = 0..=1)]
        history: Option<Option<String>>,
    },
```

Add after `Rm`:

```rust
    /// Replace an outdated fact: adds the new one and invalidates the old one
    Replace {
        /// Memory id (a unique prefix, or the short id shown in the Codex block)
        id: String,
        /// The fact as it is now
        content: String,
        /// When the new fact became true: YYYY-MM-DD (UTC) or unix seconds (default: now)
        #[arg(long)]
        valid_at: Option<String>,
    },
    /// Mark a fact outdated without a replacement (kept as history, no longer injected)
    Invalidate {
        /// Memory id (a unique prefix, or the short id shown in the Codex block)
        id: String,
        /// When it stopped being true: YYYY-MM-DD (UTC) or unix seconds (default: now)
        #[arg(long)]
        at: Option<String>,
    },
```

- [ ] **Step 7: Implement `cmd.rs`**

- Imports: `use crate::memory::adapters::{valid_skill_name, Agent, Ctx};` stays. Change the model import to `use crate::memory::model::{content_hash, format_date, new_memory_id, now_secs, parse_confidence, parse_date, skill_hash, Memory, Scope, Skill};`.
- Replace `print_memories`, and add the helpers after it:

```rust
fn print_memories(ms: &[Memory]) {
    if ms.is_empty() {
        println!("(no memories)");
    }
    for m in ms {
        let note = m.invalid_at.map(|t| format!("  (outdated since {})", format_date(t))).unwrap_or_default();
        println!("{}  {:<24} {:<6} {}{}", m.id, where_label(m), m.confidence, truncate(&one_line(&m.content), 90), note);
    }
}

/// `memory list`'s default view: global, this machine, and the current
/// project (or exactly `--scope` / `--project`; everything with `--all`).
fn in_view(m: &Memory, scope: Option<Scope>, project: Option<&str>, all: bool, ctx: &Ctx) -> bool {
    if let Some(sf) = scope
        && m.scope != sf {
        return false;
    }
    if let Some(p) = project {
        return m.project == p;
    }
    if all {
        return true;
    }
    match m.scope {
        Scope::Global => true,
        Scope::Machine => m.machine == ctx.atem_id,
        Scope::Project => ctx.repo.as_ref().is_some_and(|r| r.key == m.project),
    }
}

/// Replacement chains via `superseded_by`, each oldest first; chains ordered
/// by their first memory's creation time. A successor not in `mems` ends
/// the chain; a memory reached twice stays in the first chain.
fn history_chains(mems: &[Memory]) -> Vec<Vec<Memory>> {
    use std::collections::{HashMap, HashSet};
    let by_id: HashMap<&str, &Memory> = mems.iter().map(|m| (m.id.as_str(), m)).collect();
    let has_pred: HashSet<&str> = mems.iter()
        .filter_map(|m| m.superseded_by.as_deref())
        .filter(|s| by_id.contains_key(s))
        .collect();
    let mut order: Vec<&Memory> = mems.iter().collect();
    order.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    let mut seen: HashSet<String> = HashSet::new();
    let mut chains = Vec::new();
    // Heads first, then anything left (only a cycle, which the relay never makes).
    let heads = order.iter().filter(|m| !has_pred.contains(m.id.as_str()));
    let rest = order.iter().filter(|m| has_pred.contains(m.id.as_str()));
    for start in heads.chain(rest) {
        let mut chain = Vec::new();
        let mut cur = Some(*start);
        while let Some(m) = cur {
            if !seen.insert(m.id.clone()) {
                break;
            }
            chain.push(m.clone());
            cur = m.superseded_by.as_deref().and_then(|s| by_id.get(s).copied());
        }
        if !chain.is_empty() {
            chains.push(chain);
        }
    }
    chains.sort_by(|a, b| a[0].created_at.cmp(&b[0].created_at).then(a[0].id.cmp(&b[0].id)));
    chains
}

fn validity_span(m: &Memory) -> String {
    format!("{} → {}", format_date(m.valid_from()), m.invalid_at.map(format_date).unwrap_or_else(|| "now".into()))
}

/// One numbered block per chain; later links indented under the first.
fn render_history(chains: &[Vec<Memory>]) -> Vec<String> {
    if chains.is_empty() {
        return vec!["(no memories)".into()];
    }
    let mut out = Vec::new();
    for (i, chain) in chains.iter().enumerate() {
        for (j, m) in chain.iter().enumerate() {
            let lead = if j == 0 { format!("{:>3}. ", i + 1) } else { "     ".to_string() };
            out.push(format!("{}{}  {:<24} {:<25} {}", lead, m.id, where_label(m), validity_span(m), truncate(&one_line(&m.content), 80)));
        }
    }
    out
}
```

`MemoryCommands::Add`:
- Destructure `valid_at` too: `MemoryCommands::Add { content, scope, project, confidence, agent, force, valid_at } => {`.
- Right after `let ctx = build_ctx(false)?;`, add `let valid_at = valid_at.as_deref().map(parse_date).transpose()?;`.
- The `Memory` literal (already `seq: 0, ..Default::default()` from Task 4) becomes `created_at: now_secs(), valid_at, seq: 0, ..Default::default()`.

Replace the `MemoryCommands::List` arm:

```rust
        MemoryCommands::List { scope, project, all, history } => {
            let ctx = build_ctx(false)?;
            let store = Store::open(&store_path())?;
            let scope_f = scope.map(|s| Scope::parse(&s)).transpose()?;
            match history {
                None => {
                    let shown: Vec<Memory> = store.live_memories()?.into_iter()
                        .filter(|m| in_view(m, scope_f, project.as_deref(), all, &ctx)).collect();
                    print_memories(&shown);
                }
                Some(None) => {
                    let shown: Vec<Memory> = store.history_memories()?.into_iter()
                        .filter(|m| in_view(m, scope_f, project.as_deref(), all, &ctx)).collect();
                    for l in render_history(&history_chains(&shown)) {
                        println!("{}", l);
                    }
                }
                Some(Some(id)) => {
                    let id = store.resolve_memory_id(&id)?;
                    let chains: Vec<Vec<Memory>> = history_chains(&store.history_memories()?)
                        .into_iter().filter(|c| c.iter().any(|m| m.id == id)).collect();
                    for l in render_history(&chains) {
                        println!("{}", l);
                    }
                }
            }
        }
```

Add after the `Rm` arm:

```rust
        MemoryCommands::Replace { id, content, valid_at } => {
            let ctx = build_ctx(false)?;
            if contains_reserved(&content) {
                bail!("The text contains the reserved token `atem:memory:`.");
            }
            let findings = find_secrets(&content);
            if !findings.is_empty() {
                bail!(findings_message(&findings));
            }
            let valid_at = valid_at.as_deref().map(parse_date).transpose()?;
            let store = Store::open(&store_path())?;
            let old_id = store.resolve_memory_id(&id)?;
            let old = store.get_memory(&old_id)?.ok_or_else(|| anyhow!("No memory {}", id))?;
            if let Some(at) = old.invalid_at {
                bail!(
                    "{} is already outdated (since {}){}. See `atem memory list --history {}`.",
                    old.id, format_date(at),
                    old.superseded_by.as_deref().map(|s| format!(", replaced by {}", s)).unwrap_or_default(),
                    old.id
                );
            }
            let new_id = sync::replace_memory(&store, &old, &content, valid_at, "cli", &ctx.atem_id)?;
            println!("Replaced {} with {}", old.id, new_id);
            best_effort_sync(&store, &ctx).await;
        }
        MemoryCommands::Invalidate { id, at } => {
            let ctx = build_ctx(false)?;
            let at = at.as_deref().map(parse_date).transpose()?.unwrap_or_else(now_secs);
            let store = Store::open(&store_path())?;
            let id = store.resolve_memory_id(&id)?;
            if sync::invalidate_and_queue(&store, &id, at, None)? {
                println!("Marked {} outdated as of {}. It's kept in `atem memory list --history`.", id, format_date(at));
                best_effort_sync(&store, &ctx).await;
            } else {
                println!("{} is already outdated; nothing changed.", id);
            }
        }
```

In `MemoryCommands::Status`, replace the `Memories:` line with

```rust
            let valid = store.live_memories()?.len();
            let outdated = store.history_memories()?.len() - valid;
            println!("Memories:   {} valid, {} outdated (kept as history)", valid, outdated);
```

and after the `Held back:` line, add

```rust
            let forks = store.multi_successors()?;
            if !forks.is_empty() {
                println!("Replaced more than once (more than one valid successor — replace or invalidate all but one):");
                for (old, news) in forks {
                    println!("  {} → {}", old, news.join(", "));
                }
            }
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo test memory:: 2>&1 | grep -E "test result|FAILED|panicked"`
Expected: `test result: ok`.

- [ ] **Step 9: Commit**

```bash
cd /home/guohai/Dev/Agora.Build/Atem && git add src/memory src/cli.rs && git commit -m "$(cat <<'EOF'
feat(memory): replace, invalidate, --valid-at and list --history

`memory replace` queues the new fact's add and then the old one's
invalidate; `memory invalidate` is final. Ids accept a unique prefix or
the short id. `list --history` prints replacement chains oldest first, and
`status` lists facts with more than one valid successor (via a local
replacements table, since the relay keeps only the first). Canonical-id
rewrites also fix queued invalidations.

🤖 Built with SMT <smt@agora.build>
EOF
)"
```

---

## Task 6 [Atem]: A3 — harvest replace/invalidate, Codex short ids + replace line, "N more facts" line

**Files:**
- Modify: `src/memory/sync.rs`, `src/memory/block.rs`, `src/memory/adapters.rs`, `src/memory/cmd.rs`

**Interfaces:**
- Consumes: `invalidate_and_queue` (Task 5), `short_id` (Task 5), `Memory::is_valid`.
- Produces:
  - `HarvestSummary { added: usize, invalidated: usize, held_back: Vec<String> }` (`removed` is renamed to `invalidated`).
  - `pub struct Selection { pub entries: Vec<String>, pub omitted: usize }`.
  - `pub fn select_entries(mems: &[Memory], with_ids: bool) -> Selection`.
  - `pub fn render_block(sel: &Selection, instructions: &[&str]) -> String`.
  - `pub fn omitted_line(n: usize) -> String`.
  - `pub const CODEX_REPLACE_INSTRUCTION: &str`.
  - `Agent::shows_ids(&self) -> bool`.

- [ ] **Step 1: Write the failing tests**

`block.rs` `mod tests`. Add a helper, then update the existing tests to use it:

```rust
    fn sel(entries: &[&str]) -> Selection {
        Selection { entries: entries.iter().map(|s| s.to_string()).collect(), omitted: 0 }
    }
```

Existing call sites:
- `render_block(&["a".into()], &[])` → `render_block(&sel(&["a"]), &[])`.
  Do the same for every `render_block` call: `&[]` → `&sel(&[])`, and
  `&["one".into(), "two".into()]` → `&sel(&["one", "two"])`.
- `select_entries(X)` → `select_entries(X, false).entries`, including inside
  `.len()` and `is_empty()` asserts.

New tests:

```rust
    #[test]
    fn left_out_facts_are_counted_in_the_last_line() {
        let many: Vec<Memory> = (0..53).map(|i| mem(&format!("fact {}", i), "medium", i)).collect();
        let s = select_entries(&many, false);
        assert_eq!((s.entries.len(), s.omitted), (MAX_ENTRIES, 3));
        let b = render_block(&s, &[CREDENTIAL_INSTRUCTION]);
        let last = b.lines().rev().nth(1).unwrap(); // the line before END
        assert_eq!(last, "3 more facts are not shown here. To find them, run `atem memory search \"<query>\"`.");
        assert_eq!(omitted_line(1), "1 more fact is not shown here. To find it, run `atem memory search \"<query>\"`.");
        assert!(!render_block(&select_entries(&many[..2], false), &[]).contains("more fact"));
        // Skipped for the byte cap counts too.
        let big = "x".repeat(MAX_BYTES);
        assert_eq!(select_entries(&[mem(&big, "high", 1), mem("small", "low", 2)], false).omitted, 1);
    }

    #[test]
    fn invalid_facts_are_not_selected_or_counted() {
        let mut old = mem("old port", "high", 1);
        old.invalid_at = Some(2);
        let s = select_entries(&[old, mem("new port", "high", 3)], false);
        assert_eq!((s.entries, s.omitted), (vec!["new port".to_string()], 0));
    }

    #[test]
    fn ids_are_shown_when_asked() {
        let mut m = mem("DialF uses TCP 8765", "high", 1);
        m.id = "mem_1a2b3c4d5e6f".into();
        assert_eq!(select_entries(&[m.clone()], true).entries, vec!["[1a2b3c4d] DialF uses TCP 8765"]);
        assert_eq!(select_entries(&[m], false).entries, vec!["DialF uses TCP 8765"]);
    }

    #[test]
    fn replace_instruction_text() {
        assert_eq!(CODEX_REPLACE_INSTRUCTION, "If a saved fact is outdated, run `atem memory replace <id> \"<new fact>\"`.");
    }
```

`adapters.rs` `mod tests`:

```rust
    #[test]
    fn codex_block_shows_short_ids_and_replace_line() {
        let (_td, ctx) = setup();
        let mut f = m(Scope::Global, "", "", "Prefers ripgrep", "cli", "x");
        f.id = "mem_1a2b3c4d5e6f".into();
        apply_memory(Agent::Codex, &ctx, std::slice::from_ref(&f));
        apply_memory(Agent::Claude, &ctx, &[f]);
        let codex = read(ctx.home.join(".codex/AGENTS.md"));
        assert!(codex.contains("- [1a2b3c4d] Prefers ripgrep"), "{codex}");
        let (cap, rep, cred) = (
            codex.find(CODEX_CAPTURE_INSTRUCTION).unwrap(),
            codex.find(CODEX_REPLACE_INSTRUCTION).unwrap(),
            codex.find(CREDENTIAL_INSTRUCTION).unwrap(),
        );
        assert!(cap < rep && rep < cred);
        let claude = read(ctx.home.join(".claude/CLAUDE.md"));
        assert!(claude.contains("- Prefers ripgrep") && !claude.contains("[1a2b3c4d]") && !claude.contains(CODEX_REPLACE_INSTRUCTION));
    }
```

Change the adapters import to
`use crate::memory::block::{self, CODEX_CAPTURE_INSTRUCTION, CODEX_REPLACE_INSTRUCTION, CREDENTIAL_INSTRUCTION};`.

`sync.rs` `mod tests`: replace the harvest tests that assume delete.

```rust
    fn invalidations_queued_for(s: &Store, id: &str) -> usize {
        s.pending().unwrap().iter().filter(|(_, op)| matches!(op, PendingOp::InvalidateMemory { id: d, .. } if d == id)).count()
    }

    #[test]
    fn changed_file_replaces_its_memory() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "v1 fact")]);
        let old = s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id;
        let sum = harvest(&s, &[h("a.md", Scope::Global, "v2 fact")]);
        assert_eq!((sum.added, sum.invalidated), (1, 1));
        let live = s.live_memories().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].content, "v2 fact");
        let o = s.get_memory(&old).unwrap().unwrap();
        assert_eq!((o.content.as_str(), o.superseded_by.as_deref()), ("v1 fact", Some(live[0].id.as_str())));
        assert!(o.invalid_at.is_some());
        let kinds: Vec<&'static str> = s.pending().unwrap().iter().map(|(_, op)| match op {
            PendingOp::AddMemory { .. } => "add", PendingOp::InvalidateMemory { .. } => "invalidate", _ => "other",
        }).collect();
        assert_eq!(kinds, vec!["add", "add", "invalidate"]); // v1, v2, then v1's invalidation
        assert_eq!(s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id, live[0].id);
    }

    #[test]
    fn deleted_file_invalidates_its_memory() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        let id = s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id;
        let sum = harvest(&s, &[]);
        assert_eq!(sum.invalidated, 1);
        assert!(s.live_memories().unwrap().is_empty());
        assert!(matches!(&s.pending().unwrap().last().unwrap().1, PendingOp::InvalidateMemory { id: d, superseded_by: None, .. } if *d == id));
        assert_eq!(s.get_memory(&id).unwrap().unwrap().content, "Prefers ripgrep"); // kept as history
        assert!(s.harvest_with_prefix(P).unwrap().is_empty());
    }

    #[test]
    fn edit_to_a_credential_invalidates_the_old_fact_without_a_successor() {
        let s = Store::open_in_memory().unwrap();
        harvest(&s, &[h("a.md", Scope::Global, "Prefers ripgrep")]);
        let old = s.harvest_get(&format!("{}a.md", P)).unwrap().unwrap().memory_id;
        let sum = harvest(&s, &[h("a.md", Scope::Global, "key sk-abcdefghijklmnopqrstuvwx")]);
        assert_eq!((sum.added, sum.invalidated, sum.held_back.len()), (0, 1, 1));
        let m = s.get_memory(&old).unwrap().unwrap();
        assert!(m.invalid_at.is_some() && m.superseded_by.is_none());
    }
```

Update the rest:
- In `unchanged_harvest_is_a_noop`, change `(sum.added, sum.removed)` to `(sum.added, sum.invalidated)`.
- Rename `changed_file_does_not_delete_shared_memory` to `changed_file_does_not_invalidate_shared_memory`. Change `(sum.added, sum.removed)` to `(sum.added, sum.invalidated)`, `!…deleted` checks to `.is_valid()`, and `deletes_queued_for` to `invalidations_queued_for`.
- In `deleted_file_keeps_memory_other_origin_references`:
  - `sum.removed` → `sum.invalidated`;
  - `assert!(!s.get_memory(&id).unwrap().unwrap().is_deleted())` → `assert!(s.get_memory(&id).unwrap().unwrap().is_valid())`;
  - `harvest(&s, &[]).removed` → `harvest(&s, &[]).invalidated`;
  - `assert!(s.get_memory(&id).unwrap().unwrap().is_deleted())` → `assert!(!s.get_memory(&id).unwrap().unwrap().is_valid())`;
  - `deletes_queued_for` → `invalidations_queued_for`.
- Delete the old `deleted_file_removes_its_memory` test and the `deletes_queued_for` helper. The new tests above replace them.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo test memory:: 2>&1 | tail -20`
Expected: compile errors (`Selection`, `omitted_line`, `CODEX_REPLACE_INSTRUCTION`, `invalidated` not found).

- [ ] **Step 3: Implement `block.rs`**

Add after `CODEX_CAPTURE_INSTRUCTION`:

```rust
pub const CODEX_REPLACE_INSTRUCTION: &str = "If a saved fact is outdated, run `atem memory replace <id> \"<new fact>\"`.";

/// What goes into one block: the entry lines, and how many valid facts
/// didn't fit (found with `atem memory search`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Selection {
    pub entries: Vec<String>,
    pub omitted: usize,
}

/// The block's last line when facts were left out.
pub fn omitted_line(n: usize) -> String {
    if n == 1 {
        "1 more fact is not shown here. To find it, run `atem memory search \"<query>\"`.".to_string()
    } else {
        format!("{} more facts are not shown here. To find them, run `atem memory search \"<query>\"`.", n)
    }
}
```

Replace `select_entries` and `render_block`:

```rust
/// Valid facts, ordered by confidence then newest, capped at MAX_ENTRIES
/// and MAX_BYTES. An entry that doesn't fit is skipped (and counted in
/// `omitted`), so one huge memory can't crowd out the rest. Pulled content
/// that could forge markers or carries a credential is never written (and
/// not counted). `with_ids` prefixes each entry with `[<short id>] `.
pub fn select_entries(mems: &[Memory], with_ids: bool) -> Selection {
    let mut sorted: Vec<&Memory> = mems.iter()
        .filter(|m| m.is_valid() && !contains_reserved(&m.content) && find_secrets(&m.content).is_empty())
        .collect();
    sorted.sort_by(|a, b| {
        confidence_rank(&a.confidence).cmp(&confidence_rank(&b.confidence))
            .then(b.created_at.cmp(&a.created_at))
            .then(a.id.cmp(&b.id))
    });
    let eligible = sorted.len();
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for m in sorted {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        let text = one_line(&m.content);
        let line = if with_ids { format!("[{}] {}", short_id(&m.id), text) } else { text };
        let cost = line.len() + 3; // "- " + "\n"
        if bytes + cost > MAX_BYTES {
            continue;
        }
        bytes += cost;
        out.push(line);
    }
    Selection { omitted: eligible - out.len(), entries: out }
}

pub fn render_block(sel: &Selection, instructions: &[&str]) -> String {
    let mut s = String::new();
    s.push_str(BEGIN);
    s.push('\n');
    for e in &sel.entries {
        s.push_str("- ");
        s.push_str(e);
        s.push('\n');
    }
    if !instructions.is_empty() {
        if !sel.entries.is_empty() {
            s.push('\n');
        }
        for i in instructions {
            s.push_str(i);
            s.push('\n');
        }
    }
    if sel.omitted > 0 {
        if !sel.entries.is_empty() || !instructions.is_empty() {
            s.push('\n');
        }
        s.push_str(&omitted_line(sel.omitted));
        s.push('\n');
    }
    s.push_str(END);
    s
}
```

Change the model import to `use crate::memory::model::{confidence_rank, short_id, Memory};`.

- [ ] **Step 4: Implement `adapters.rs`**

- `instructions()`: the Codex arm becomes `Agent::Codex => vec![CODEX_CAPTURE_INSTRUCTION, CODEX_REPLACE_INSTRUCTION, CREDENTIAL_INSTRUCTION],`.
- Add after `instructions`:

```rust
    /// Codex's block shows each fact's short id so it can run `atem memory replace <id>`.
    pub fn shows_ids(&self) -> bool {
        *self == Agent::Codex
    }
```

- In `apply_memory`, drop `let instr = agent.instructions();`. The two
  `write_block(…, &instr, ctx)` calls become `write_block(…, agent, ctx)`.
- In `write_block`, change the signature to
  `fn write_block(path: &Path, repo_root: Option<&Path>, mems: &[Memory], agent: Agent, ctx: &Ctx) -> ReportLine`
  and replace the selection and render lines:

```rust
    let sel = block::select_entries(mems, agent.shows_ids());
    let rendered = block::render_block(&sel, &agent.instructions());
```

  The final line becomes
  `line(Mark::Applied, target, format!("{} memories", sel.entries.len()))`.

- [ ] **Step 5: Implement harvest in `sync.rs`**

Replace `HarvestSummary`, `release_memory` and `harvest_into_store`:

```rust
#[derive(Debug, Default, Clone, PartialEq)]
pub struct HarvestSummary {
    pub added: usize,
    /// Memories marked outdated because their file was edited (replaced)
    /// or deleted.
    pub invalidated: usize,
    pub held_back: Vec<String>,
}

/// Whether harvest may retire memory `id`, which is linked from `origin`:
/// this machine's Claude harvest created it, and no other harvested file
/// still points at it. A harvest can dedupe onto a CLI add, another
/// machine's memory, or a relay canonical id, and those must survive.
fn owns_memory(store: &Store, origin: &str, id: &str, atem_id: &str) -> Result<bool> {
    let ours = store.get_memory(id)?
        .map(|m| m.source_agent == "claude" && m.source_machine == atem_id)
        .unwrap_or(false);
    let shared = store.harvest_entries_for_memory(id)?.iter().any(|e| e.origin != origin);
    Ok(ours && !shared)
}

/// An edited file replaces its memory (the new fact is added, the old one
/// invalidated with `superseded_by`). A deleted file invalidates it. The
/// history is kept either way.
pub fn harvest_into_store(store: &Store, items: &[Harvested], prefix: &str, project_key: &str, atem_id: &str) -> Result<HarvestSummary> {
    let mut sum = HarvestSummary::default();
    let seen: HashSet<&str> = items.iter().map(|h| h.origin.as_str()).collect();
    for h in items {
        let prev = store.harvest_get(&h.origin)?;
        if prev.as_ref().is_some_and(|p| p.content_hash == h.hash) {
            continue; // unchanged (synced, held back, or excluded)
        }
        // The file changed: the memory it used to yield (if harvest owns it) is outdated.
        let outdated = match &prev {
            Some(p) if p.status == HarvestStatus::Synced && !p.memory_id.is_empty()
                && owns_memory(store, &h.origin, &p.memory_id, atem_id)? => Some(p.memory_id.clone()),
            _ => None,
        };
        let findings = find_secrets(&h.content);
        if !findings.is_empty() || contains_reserved(&h.content) {
            let why = if findings.is_empty() {
                "contains the reserved token atem:memory:".to_string()
            } else {
                findings.iter().map(|f| format!("{} {}", f.kind, f.masked)).collect::<Vec<_>>().join(", ")
            };
            // Nothing can replace it (the new text never leaves the machine).
            if let Some(old) = &outdated
                && invalidate_and_queue(store, old, now_secs(), None)? {
                sum.invalidated += 1;
            }
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
                    created_at: now_secs(), seq: 0, ..Default::default()
                };
                store.upsert_memory(&m)?;
                store.enqueue(&PendingOp::AddMemory { memory: m.clone() })?;
                sum.added += 1;
                m.id
            }
        };
        // Queued after the add, so both go out in order.
        if let Some(old) = &outdated
            && *old != id
            && invalidate_and_queue(store, old, now_secs(), Some(&id))? {
            sum.invalidated += 1;
        }
        store.harvest_put(&HarvestEntry { origin: h.origin.clone(), memory_id: id, content_hash: h.hash.clone(), status: HarvestStatus::Synced })?;
    }
    for e in store.harvest_with_prefix(prefix)? {
        if seen.contains(e.origin.as_str()) {
            continue;
        }
        if e.status == HarvestStatus::Synced && !e.memory_id.is_empty()
            && owns_memory(store, &e.origin, &e.memory_id, atem_id)?
            && invalidate_and_queue(store, &e.memory_id, now_secs(), None)? {
            sum.invalidated += 1;
        }
        store.harvest_remove(&e.origin)?;
    }
    Ok(sum)
}
```

`cmd.rs` `print_outcome`: the first line becomes
`println!("Harvested from Claude: {} new, {} outdated", h.added, h.invalidated);`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo test memory:: 2>&1 | grep -E "test result|FAILED|panicked"`
Expected: `test result: ok`.

- [ ] **Step 7: Commit**

```bash
cd /home/guohai/Dev/Agora.Build/Atem && git add src/memory && git commit -m "$(cat <<'EOF'
feat(memory): harvest replaces and invalidates; Codex block shows short ids

An edited Claude memory file now replaces its memory and a deleted one
invalidates it (same ownership guard), so the history is kept. The Codex
block prefixes each fact with its short id and adds the replace line. A
block that leaves facts out ends with "N more facts … atem memory search".

🤖 Built with SMT <smt@agora.build>
EOF
)"
```

---

## Task 7 [Atem]: A4 — `memory search` (FTS5 BM25, trigram; LIKE under 3 chars)

**Files:**
- Modify: `src/memory/store.rs`, `src/memory/cmd.rs`, `src/cli.rs`

**Interfaces:**
- Consumes: `memories_fts` (Task 4), `MEM_COLS`, `row_to_memory`.
- Produces:
  - `pub struct SearchQuery { pub text: String, pub scope: Option<Scope>, pub project: Option<String>, pub history: bool, pub limit: usize }`.
  - `Store::search_memories(&self, q: &SearchQuery) -> Result<Vec<Memory>>`.
  - `pub fn fts_phrase(text: &str) -> String`.
  - `pub fn like_pattern(text: &str) -> String`.
  - CLI `memory search <text> [--scope] [--project] [--history] [--limit <n>=20]`.

- [ ] **Step 1: Write the failing tests** (`store.rs` `mod tests`)

```rust
    fn q(text: &str) -> SearchQuery {
        SearchQuery { text: text.into(), limit: 20, ..Default::default() }
    }

    fn search_ids(s: &Store, query: &SearchQuery) -> Vec<String> {
        s.search_memories(query).unwrap().into_iter().map(|m| m.id).collect()
    }

    #[test]
    fn search_ranks_with_bm25_and_matches_cjk() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_once", "DialF listens on TCP 8765")).unwrap();
        s.upsert_memory(&mem("mem_many", "tcp tcp tcp port notes")).unwrap();
        s.upsert_memory(&mem("mem_cjk", "服务器端口是八七六五")).unwrap();
        s.upsert_memory(&mem("mem_pnpm", "Use pnpm not npm")).unwrap();
        assert_eq!(search_ids(&s, &q("tcp")), vec!["mem_many", "mem_once"]);
        assert_eq!(search_ids(&s, &q("TCP 87")), vec!["mem_once"]);
        assert_eq!(search_ids(&s, &q("端口是")), vec!["mem_cjk"]);
        // Shorter than a trigram: substring fallback.
        assert_eq!(search_ids(&s, &q("端口")), vec!["mem_cjk"]);
        assert_eq!(search_ids(&s, &q("pn")), vec!["mem_pnpm"]);
        // FTS5 syntax in the query is just text.
        assert!(search_ids(&s, &q("a\"b OR c*")).is_empty());
        // An FTS5 operator word is matched as text (case-insensitive), not parsed.
        assert_eq!(search_ids(&s, &q("NOT")), vec!["mem_pnpm"]);
        assert!(search_ids(&s, &q("  ")).is_empty());
        let mut one = q("tcp");
        one.limit = 1;
        assert_eq!(search_ids(&s, &one), vec!["mem_many"]);
    }

    #[test]
    fn search_filters_validity_scope_and_project() {
        let s = Store::open_in_memory().unwrap();
        let mut old = mem("mem_old", "port 8765");
        old.invalid_at = Some(5);
        s.upsert_memory(&old).unwrap();
        let mut proj = mem("mem_proj", "port 9000");
        proj.scope = Scope::Project;
        proj.project = "github.com/acme/dialf".into();
        s.upsert_memory(&proj).unwrap();
        s.upsert_memory(&mem("mem_gone", "port 1234")).unwrap();
        s.mark_memory_deleted("mem_gone").unwrap();
        assert_eq!(search_ids(&s, &q("port")), vec!["mem_proj"]);
        let mut hist = q("port");
        hist.history = true;
        let mut got = search_ids(&s, &hist);
        got.sort();
        assert_eq!(got, vec!["mem_old", "mem_proj"]);
        let mut scoped = q("port");
        scoped.scope = Some(Scope::Global);
        assert!(search_ids(&s, &scoped).is_empty());
        let mut other = q("port");
        other.project = Some("github.com/acme/other".into());
        assert!(search_ids(&s, &other).is_empty());
        let mut mine = q("po");
        mine.project = Some("github.com/acme/dialf".into());
        assert_eq!(search_ids(&s, &mine), vec!["mem_proj"]);
    }

    #[test]
    fn like_fallback_escapes_wildcards() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_pct", "5% off")).unwrap();
        s.upsert_memory(&mem("mem_num", "50 users")).unwrap();
        s.upsert_memory(&mem("mem_us", "a_b")).unwrap();
        assert_eq!(search_ids(&s, &q("5%")), vec!["mem_pct"]);
        assert_eq!(search_ids(&s, &q("_")), vec!["mem_us"]);
        assert_eq!(like_pattern("a%b_c\\"), "%a\\%b\\_c\\\\%");
        assert_eq!(fts_phrase("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
```

Add to `cmd.rs` tests:

```rust
    #[test]
    fn search_command_parses() {
        use clap::Parser;
        let ok = |args: &[&str]| crate::cli::Cli::try_parse_from(args).is_ok();
        assert!(ok(&["atem", "memory", "search", "tcp port"]));
        assert!(ok(&["atem", "memory", "search", "端口", "--scope", "project", "--project", "github.com/a/b", "--history", "--limit", "5"]));
        assert!(!ok(&["atem", "memory", "search", "x", "--limit", "many"]));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo test memory:: 2>&1 | tail -20`
Expected: compile errors (`SearchQuery`, `search_memories`, `like_pattern`, `fts_phrase` not found; unknown `--scope` on search).

- [ ] **Step 3: Implement `store.rs`**

Add after `HarvestEntry`:

```rust
/// `atem memory search`. `scope`/`project` = `None` means any; valid facts
/// only unless `history`.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub text: String,
    pub scope: Option<Scope>,
    pub project: Option<String>,
    pub history: bool,
    pub limit: usize,
}

/// The whole query as one FTS5 phrase (internal `"` doubled), so FTS5
/// syntax (`OR`, `NOT`, `*`, `:`…) in user text is matched literally.
pub fn fts_phrase(text: &str) -> String {
    format!("\"{}\"", text.replace('"', "\"\""))
}

/// A LIKE substring pattern with `\` as the escape character.
pub fn like_pattern(text: &str) -> String {
    format!("%{}%", text.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"))
}

fn prefixed_mem_cols(prefix: &str) -> String {
    MEM_COLS.split(", ").map(|c| format!("{}{}", prefix, c)).collect::<Vec<_>>().join(", ")
}
```

Add to `impl Store` after `history_memories`:

```rust
    /// Local search. Three or more characters: FTS5 trigram phrase match,
    /// ranked by BM25 (works for CJK). Shorter (trigram can't index it):
    /// case-insensitive substring match, newest first.
    pub fn search_memories(&self, q: &SearchQuery) -> Result<Vec<Memory>> {
        let text = q.text.trim();
        if text.is_empty() || q.limit == 0 {
            return Ok(Vec::new());
        }
        let validity = if q.history { "" } else { " AND m.invalid_at IS NULL" };
        let filters = format!("m.deleted_at IS NULL{} AND (?2 IS NULL OR m.scope = ?2) AND (?3 IS NULL OR m.project = ?3)", validity);
        let cols = prefixed_mem_cols("m.");
        let short = text.chars().count() < 3;
        let (sql, arg) = if short {
            (format!("SELECT {cols} FROM memories m WHERE m.content LIKE ?1 ESCAPE '\\' AND {filters} ORDER BY m.created_at DESC, m.id LIMIT ?4"),
             like_pattern(text))
        } else {
            (format!("SELECT {cols} FROM memories_fts JOIN memories m ON m.rowid = memories_fts.rowid WHERE memories_fts MATCH ?1 AND {filters} ORDER BY bm25(memories_fts), m.created_at DESC, m.id LIMIT ?4"),
             fts_phrase(text))
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![arg, q.scope.map(|s| s.as_str()), q.project, q.limit as i64], row_to_memory)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
```

- [ ] **Step 4: Implement the CLI + handler**

`src/cli.rs`: replace `Search`:

```rust
    /// Search memories on this machine (FTS5 + BM25; works for CJK; offline)
    Search {
        text: String,
        /// global | project | machine (default: any)
        #[arg(long)]
        scope: Option<String>,
        /// Only this project key
        #[arg(long)]
        project: Option<String>,
        /// Include outdated facts
        #[arg(long)]
        history: bool,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
```

`cmd.rs`:
- Change the store import to `use crate::memory::store::{HarvestStatus, PendingOp, SearchQuery, Store, LAST_SYNC_AT};`.
- Replace the `Search` arm:

```rust
        MemoryCommands::Search { text, scope, project, history, limit } => {
            let store = Store::open(&store_path())?;
            let scope = scope.map(|s| Scope::parse(&s)).transpose()?;
            let hits = store.search_memories(&SearchQuery { text, scope, project, history, limit })?;
            print_memories(&hits);
        }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo test memory:: 2>&1 | grep -E "test result|FAILED|panicked"`
Expected: `test result: ok`.

- [ ] **Step 6: Commit**

```bash
cd /home/guohai/Dev/Agora.Build/Atem && git add src/memory src/cli.rs && git commit -m "$(cat <<'EOF'
feat(memory): local search with FTS5 trigram + BM25

`atem memory search "<query>" [--scope] [--project] [--history] [--limit]`
runs on knowledge.db, offline. Queries are matched as one quoted phrase;
under 3 characters it falls back to an escaped substring match.

🤖 Built with SMT <smt@agora.build>
EOF
)"
```

---

## Task 8 [Atem]: A5 — `skill history`, `skill restore`, concurrent-push pointer

**Files:**
- Modify: `src/memory/api.rs`, `src/memory/sync.rs`, `src/memory/secrets.rs`, `src/memory/cmd.rs`, `src/cli.rs`

**Interfaces:**
- Consumes: the relay endpoints from Task 3, `KnowledgeClient::send`, `Store::{get_skill, put_skill, enqueue}`, `skill_hash`, `format_datetime` (Task 5).
- Produces:
  - `pub struct SkillVersionInfo { pub version: i64, pub created_at: i64, pub source_agent: String, pub source_machine: String, pub file_count: i64, pub deleted: bool, pub purged: bool }`.
  - `pub fn skill_versions_request(base: &str, client_id: &str, scope: Scope, project: &str, name: &str) -> ApiRequest`.
  - `pub fn skill_version_request(base: &str, client_id: &str, scope: Scope, project: &str, name: &str, version: i64) -> ApiRequest`.
  - `KnowledgeClient::skill_versions(&self, scope: Scope, project: &str, name: &str) -> Result<Vec<SkillVersionInfo>, ApiError>`.
  - `KnowledgeClient::skill_version(&self, scope: Scope, project: &str, name: &str, version: i64) -> Result<Skill, ApiError>`.
  - `pub fn secrets::skill_file_problems(files: &BTreeMap<String, Vec<u8>>) -> Vec<String>`.
  - `pub const sync::SKILL_HISTORY_OFFLINE: &str`.
  - `pub fn sync::skill_history_error(e: ApiError, name: &str, version: Option<i64>) -> anyhow::Error`.
  - `pub async fn sync::restore_skill(store: &Store, client: &KnowledgeClient, atem_id: &str, scope: Scope, project: &str, name: &str, version: i64) -> Result<Skill>`.
  - CLI `skill history <name> [--scope]` and `skill restore <name> --version <n> [--scope]`.

- [ ] **Step 1: Write the failing tests**

`api.rs` `mod tests`:

```rust
    #[test]
    fn skill_history_request_urls() {
        let r = skill_versions_request("https://relay.example/", "inst 1", Scope::Project, "github.com/a/b", "deploy check");
        assert_eq!(r.method, "GET");
        assert_eq!(r.url, "https://relay.example/api/skills/versions?id=inst%201&scope=project&project=github.com%2Fa%2Fb&name=deploy%20check");
        assert!(r.body.is_none());
        assert_eq!(
            skill_version_request("https://relay.example", "i", Scope::Global, "", "demo", 4).url,
            "https://relay.example/api/skills/version?id=i&scope=global&project=&name=demo&version=4"
        );
        let info: SkillVersionInfo = serde_json::from_value(json!({"version": 2, "created_at": 5})).unwrap();
        assert_eq!((info.file_count, info.deleted, info.purged, info.source_agent.as_str()), (0, false, false, ""));
    }
```

`secrets.rs` `mod tests`:

```rust
    #[test]
    fn skill_file_problems_are_masked_per_file() {
        let mut files = std::collections::BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# fine".to_vec());
        files.insert("creds.txt".to_string(), b"AKIAIOSFODNN7EXAMPLE".to_vec());
        files.insert("img.png".to_string(), vec![0xff, 0xfe, 0x00]);
        let p = skill_file_problems(&files);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p.iter().any(|l| l.starts_with("creds.txt:1") && !l.contains("IOSFODNN7")));
        assert!(p.iter().any(|l| l.starts_with("img.png:0") && l.contains("unreadable (binary)")));
    }
```

`sync.rs` `mod tests`:

```rust
    fn remote_skill(version: i64, body: &str, deleted: bool) -> serde_json::Value {
        let mut files = BTreeMap::new();
        if !deleted {
            files.insert("SKILL.md".to_string(), body.as_bytes().to_vec());
        }
        serde_json::to_value(Skill {
            scope: Scope::Global, project: String::new(), name: "demo".into(), version,
            content_hash: skill_hash(&files), files, source_agent: "codex".into(), source_machine: "m2".into(),
            created_at: 1_790_000_000, deleted, seq: version * 10,
        }).unwrap()
    }

    fn history_relay() -> Box<Handler> {
        Box::new(|m, p, body| {
            if m == "GET" && p.starts_with("/api/skills/versions?") {
                return (200, serde_json::json!({"versions": [
                    {"version": 5, "created_at": 1_791_036_600, "source_agent": "claude", "source_machine": "mac-mini", "file_count": 1, "deleted": false, "purged": false},
                    {"version": 4, "created_at": 1_791_036_540, "source_agent": "codex", "source_machine": "genie", "file_count": 1, "deleted": false, "purged": false},
                    {"version": 3, "created_at": 1_790_900_000, "source_agent": "cli", "source_machine": "genie", "file_count": 0, "deleted": true, "purged": false},
                    {"version": 2, "created_at": 1_790_800_000, "source_agent": "cli", "source_machine": "genie", "file_count": 1, "deleted": false, "purged": false},
                    {"version": 1, "created_at": 1_790_700_000, "source_agent": "claude", "source_machine": "genie", "file_count": 0, "deleted": true, "purged": true},
                ]}));
            }
            if m == "GET" && p.starts_with("/api/skills/version?") {
                let v = p.split('&').find_map(|kv| kv.strip_prefix("version=")).unwrap_or("");
                return match v {
                    "4" => (200, serde_json::json!({"skill": remote_skill(4, "# v4 body", false)})),
                    "3" => (200, serde_json::json!({"skill": remote_skill(3, "", true)})),
                    "2" => (200, serde_json::json!({"skill": remote_skill(2, "key AKIAIOSFODNN7EXAMPLE", false)})),
                    "1" => (410, serde_json::json!({"error": "skill version purged"})),
                    _ => (404, serde_json::json!({"error": "no such skill version"})),
                };
            }
            if let Some(r) = empty_pulls(m, p) {
                return r;
            }
            (200, ok_results(body))
        })
    }

    #[tokio::test]
    async fn restore_pushes_old_files_as_a_new_version() {
        let s = Store::open_in_memory().unwrap();
        let (base, _log) = stub_relay(history_relay()).await;
        let sk = restore_skill(&s, &client(&base, "ast-a"), "m1", Scope::Global, "", "demo", 4).await.unwrap();
        assert_eq!(sk.version, 6);
        assert_eq!(sk.files.get("SKILL.md").unwrap(), b"# v4 body");
        assert_eq!((sk.source_agent.as_str(), sk.source_machine.as_str(), sk.deleted), ("cli", "m1", false));
        let p = s.pending().unwrap();
        assert!(matches!(&p[0].1, PendingOp::PushSkill { skill, base_version: 5 } if skill.version == 6 && skill.content_hash == skill_hash(&skill.files)));
        assert_eq!(s.get_skill(Scope::Global, "", "demo").unwrap().unwrap().version, 6);
    }

    #[tokio::test]
    async fn restore_refuses_purged_deleted_secret_and_unknown_versions() {
        let s = Store::open_in_memory().unwrap();
        let (base, _log) = stub_relay(history_relay()).await;
        let c = client(&base, "ast-a");
        for (v, want) in [(1, "was purged"), (3, "delete marker"), (2, "possible credentials"), (9, "has no version 9")] {
            let err = restore_skill(&s, &c, "m1", Scope::Global, "", "demo", v).await.unwrap_err().to_string();
            assert!(err.contains(want), "{v}: {err}");
        }
        assert_eq!(s.pending_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn restore_offline_says_so_plainly() {
        let s = Store::open_in_memory().unwrap();
        let err = restore_skill(&s, &client("http://127.0.0.1:1", "ast-a"), "m1", Scope::Global, "", "demo", 4).await.unwrap_err();
        assert_eq!(err.to_string(), SKILL_HISTORY_OFFLINE);
    }

    #[test]
    fn concurrent_push_note_points_to_history() {
        let s = Store::open_in_memory().unwrap();
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        let mk = |scope: Scope, project: &str| Skill {
            scope, project: project.into(), name: "demo".into(), version: 2, content_hash: skill_hash(&files),
            files: files.clone(), source_agent: "cli".into(), source_machine: "m1".into(), created_at: 1, deleted: false, seq: 0,
        };
        s.enqueue(&PendingOp::PushSkill { skill: mk(Scope::Global, ""), base_version: 1 }).unwrap();
        s.enqueue(&PendingOp::PushSkill { skill: mk(Scope::Project, "github.com/a/b"), base_version: 1 }).unwrap();
        let sent = s.pending().unwrap();
        let r = OpResult { ok: true, version: Some(3), seq: Some(9), superseded_concurrent: true, ..Default::default() };
        let notes = apply_push_results(&s, &sent, &[r.clone(), r]).unwrap();
        assert_eq!(notes[0], "skill demo: another machine pushed an edit at the same time; both versions are kept and v3 is now the latest. See them with `atem skill history demo`.");
        assert!(notes[1].ends_with("See them with `atem skill history demo --scope project`."), "{}", notes[1]);
    }
```

`cmd.rs` `mod tests`:

```rust
    fn info(version: i64, machine: &str, agent: &str, files: i64, deleted: bool, purged: bool, at: i64) -> crate::memory::api::SkillVersionInfo {
        crate::memory::api::SkillVersionInfo {
            version, created_at: at, source_agent: agent.into(), source_machine: machine.into(), file_count: files, deleted, purged,
        }
    }

    #[test]
    fn skill_history_lines() {
        let lines = render_skill_history(&[
            info(5, "mac-mini", "claude", 4, false, false, 1_791_036_600),
            info(4, "genie", "codex", 1, false, false, 1_791_036_540),
            info(2, "mac-mini", "cli", 0, true, false, 1_790_000_000),
            info(1, "genie", "claude", 0, true, true, 1_789_000_000),
        ]);
        assert!(lines[0].starts_with("v5   latest   2026-10-03 14:10") && lines[0].contains("mac-mini") && lines[0].ends_with("4 files"), "{}", lines[0]);
        assert!(!lines[1].contains("latest") && lines[1].contains("2026-10-03 14:09") && lines[1].ends_with("1 file"), "{}", lines[1]);
        assert!(lines[2].contains("deleted") && !lines[2].contains("file"), "{}", lines[2]);
        assert!(lines[3].contains("purged") && !lines[3].contains("deleted"), "{}", lines[3]);
    }

    #[test]
    fn skill_history_commands_parse() {
        use clap::Parser;
        let ok = |args: &[&str]| crate::cli::Cli::try_parse_from(args).is_ok();
        assert!(ok(&["atem", "skill", "history", "demo"]));
        assert!(ok(&["atem", "skill", "history", "demo", "--scope", "project"]));
        assert!(ok(&["atem", "skill", "restore", "demo", "--version", "4"]));
        assert!(!ok(&["atem", "skill", "restore", "demo"]));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo test memory:: 2>&1 | tail -20`
Expected: compile errors (`skill_versions_request`, `SkillVersionInfo`, `skill_file_problems`, `restore_skill`, `render_skill_history` not found).

- [ ] **Step 3: Implement `api.rs`**

- Change the import to `use crate::memory::model::{Memory, Scope, Skill};`.
- Add after `skills_pull_request`:

```rust
fn skill_key_query(scope: Scope, project: &str, name: &str) -> String {
    format!("scope={}&project={}&name={}", scope.as_str(), enc(project), enc(name))
}

pub fn skill_versions_request(base: &str, client_id: &str, scope: Scope, project: &str, name: &str) -> ApiRequest {
    ApiRequest {
        method: "GET",
        url: format!("{}/api/skills/versions?id={}&{}", base_trim(base), enc(client_id), skill_key_query(scope, project, name)),
        body: None,
    }
}

pub fn skill_version_request(base: &str, client_id: &str, scope: Scope, project: &str, name: &str, version: i64) -> ApiRequest {
    ApiRequest {
        method: "GET",
        url: format!("{}/api/skills/version?id={}&{}&version={}", base_trim(base), enc(client_id), skill_key_query(scope, project, name), version),
        body: None,
    }
}

/// One entry of `GET /api/skills/versions` (no files).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SkillVersionInfo {
    pub version: i64,
    pub created_at: i64,
    #[serde(default)]
    pub source_agent: String,
    #[serde(default)]
    pub source_machine: String,
    #[serde(default)]
    pub file_count: i64,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub purged: bool,
}

#[derive(Deserialize)]
struct VersionsPage {
    versions: Vec<SkillVersionInfo>,
}
#[derive(Deserialize)]
struct VersionPage {
    skill: Skill,
}
```

Add to `impl KnowledgeClient`:

```rust
    /// A skill's history, newest first (no files).
    pub async fn skill_versions(&self, scope: Scope, project: &str, name: &str) -> Result<Vec<SkillVersionInfo>, ApiError> {
        let req = skill_versions_request(&self.base, &self.client_id, scope, project, name);
        let page: VersionsPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.versions)
    }

    /// One version with its files. 404 unknown, 410 purged (as `ApiError::Http`).
    pub async fn skill_version(&self, scope: Scope, project: &str, name: &str, version: i64) -> Result<Skill, ApiError> {
        let req = skill_version_request(&self.base, &self.client_id, scope, project, name, version);
        let page: VersionPage = self.send(req).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(page.skill)
    }
```

- [ ] **Step 4: Implement `secrets.rs`** (after `check_bytes`)

```rust
/// Every finding in a skill's files, as `path:line  kind masked`. Binary
/// (non-UTF-8) files can't be checked and are reported as unreadable.
pub fn skill_file_problems(files: &std::collections::BTreeMap<String, Vec<u8>>) -> Vec<String> {
    let mut out = Vec::new();
    for (path, bytes) in files {
        for f in check_bytes(bytes) {
            out.push(format!("{}:{}  {} {}", path, f.line, f.kind, f.masked));
        }
    }
    out
}
```

In `cmd.rs` `SkillCommands::Add`, replace the `let mut problems = Vec::new(); for (path, bytes) in &files { … }` block with
`let problems = crate::memory::secrets::skill_file_problems(&files);`
(the `if !problems.is_empty() { bail!(…) }` stays). Remove
`check_bytes` from the `secrets` import if it's now unused.

- [ ] **Step 5: Implement `sync.rs`**

- Change the imports:
  - `use anyhow::{anyhow, bail, Result};`
  - `use crate::memory::model::{content_hash, new_memory_id, now_secs, skill_hash, Memory, Scope, Skill};`
  - `use crate::memory::secrets::{find_secrets, skill_file_problems};`
- In `apply_push_results`, replace the concurrent note:

```rust
                    if r.superseded_concurrent {
                        let scope_flag = if skill.scope == Scope::Project { " --scope project" } else { "" };
                        notes.push(format!(
                            "skill {}: another machine pushed an edit at the same time; both versions are kept and v{} is now the latest. See them with `atem skill history {}{}`.",
                            skill.name, r.version.unwrap_or(skill.version), skill.name, scope_flag
                        ));
                    }
```

Add after `run_sync`:

```rust
pub const SKILL_HISTORY_OFFLINE: &str = "Skill history lives on the relay, which is unreachable right now. Try again when you're online.";

/// A skill-history request failed: say why, plainly.
pub fn skill_history_error(e: ApiError, name: &str, version: Option<i64>) -> anyhow::Error {
    match (e, version) {
        (ApiError::Offline(_), _) => anyhow!(SKILL_HISTORY_OFFLINE),
        (ApiError::Http(404, _), Some(v)) => anyhow!("Skill {} has no version {}. See `atem skill history {}`.", name, v, name),
        (ApiError::Http(410, _), Some(v)) => anyhow!("v{} of skill {} was purged: its files were erased, so it can't be restored.", v, name),
        (e, _) => anyhow!("{}", e),
    }
}

/// Push the files of version `version` as a new version on top of the
/// current latest (the relay's newest, or this machine's if it has an
/// unpushed newer one). History is never rewritten. Refuses purged versions
/// and delete markers, and re-runs the secret check like `skill add`. Queues
/// the push; the caller syncs.
pub async fn restore_skill(store: &Store, client: &KnowledgeClient, atem_id: &str, scope: Scope, project: &str, name: &str, version: i64) -> Result<Skill> {
    let old = client.skill_version(scope, project, name, version).await
        .map_err(|e| skill_history_error(e, name, Some(version)))?;
    if old.deleted {
        bail!("v{} of skill {} is a delete marker; it has no files to restore. See `atem skill history {}`.", version, name, name);
    }
    let problems = skill_file_problems(&old.files);
    if !problems.is_empty() {
        bail!(
            "Refusing to restore v{} of skill {} — possible credentials (or unreadable files) found:\n  {}\nKeep credentials in the vault and read them at run time, e.g. `atem vault get <name>`.",
            version, name, problems.join("\n  ")
        );
    }
    let relay_latest = client.skill_versions(scope, project, name).await
        .map_err(|e| skill_history_error(e, name, None))?
        .iter().map(|v| v.version).max().unwrap_or(0);
    let local_latest = store.get_skill(scope, project, name)?.map(|s| s.version).unwrap_or(0);
    let base_version = relay_latest.max(local_latest);
    let files = old.files;
    let skill = Skill {
        scope, project: project.to_string(), name: name.to_string(), version: base_version + 1,
        content_hash: skill_hash(&files), files,
        source_agent: "cli".into(), source_machine: atem_id.to_string(), created_at: now_secs(), deleted: false, seq: 0,
    };
    store.put_skill(&skill)?;
    store.enqueue(&PendingOp::PushSkill { skill: skill.clone(), base_version })?;
    Ok(skill)
}
```

- [ ] **Step 6: Implement the CLI + handlers**

`src/cli.rs` `SkillCommands`, add after `Rm`:

```rust
    /// Every version of a skill, newest first (asks the relay)
    History {
        name: String,
        #[arg(long, default_value = "global")]
        scope: String,
    },
    /// Re-push an old version's files as a new version (history is kept)
    Restore {
        name: String,
        #[arg(long)]
        version: i64,
        #[arg(long, default_value = "global")]
        scope: String,
    },
```

`cmd.rs`:
- Change the model import to also bring in `format_datetime`.
- Add after `ROTATE_WARNING`:

```rust
const NOT_PAIRED_HISTORY_MSG: &str = "Not paired with your Astation — run `atem pair`, then retry.";

fn skill_scope(s: &str) -> Result<Scope> {
    let scope = Scope::parse(s)?;
    if scope == Scope::Machine {
        bail!("Skills support --scope global or project.");
    }
    Ok(scope)
}

/// One line per version, newest first (times in UTC).
fn render_skill_history(versions: &[crate::memory::api::SkillVersionInfo]) -> Vec<String> {
    versions.iter().enumerate().map(|(i, v)| {
        let label = if v.purged { "purged" } else if v.deleted { "deleted" } else if i == 0 { "latest" } else { "" };
        let files = if v.deleted || v.purged {
            String::new()
        } else if v.file_count == 1 {
            "1 file".to_string()
        } else {
            format!("{} files", v.file_count)
        };
        format!("v{:<3} {:<7}  {}  {:<12} {:<7} {}", v.version, label, format_datetime(v.created_at), truncate(&v.source_machine, 12), v.source_agent, files)
            .trim_end().to_string()
    }).collect()
}
```

In `handle_skill`, add these arms after `Rm`:

```rust
        SkillCommands::History { name, scope } => {
            let scope = skill_scope(&scope)?;
            let project = project_for_scope(scope, &ctx, None)?;
            let c = client().await.map_err(|_| anyhow!(NOT_PAIRED_HISTORY_MSG))?;
            let versions = c.skill_versions(scope, &project, &name).await
                .map_err(|e| sync::skill_history_error(e, &name, None))?;
            if versions.is_empty() {
                println!("No history for skill {} ({}).", name, scope.as_str());
            }
            for l in render_skill_history(&versions) {
                println!("{}", l);
            }
        }
        SkillCommands::Restore { name, version, scope } => {
            let scope = skill_scope(&scope)?;
            let project = project_for_scope(scope, &ctx, None)?;
            let c = client().await.map_err(|_| anyhow!(NOT_PAIRED_HISTORY_MSG))?;
            let restored = sync::restore_skill(&store, &c, &ctx.atem_id, scope, &project, &name, version).await?;
            println!("Restored {} v{} as v{}.", name, version, restored.version);
            best_effort_sync(&store, &ctx).await;
        }
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo test memory:: 2>&1 | grep -E "test result|FAILED|panicked"`
Expected: `test result: ok`.

- [ ] **Step 8: Commit**

```bash
cd /home/guohai/Dev/Agora.Build/Atem && git add src/memory src/cli.rs && git commit -m "$(cat <<'EOF'
feat(skill): history and restore from the relay

`atem skill history <name>` lists every version (newest first, UTC);
`atem skill restore <name> --version <n>` re-checks the files for secrets
and pushes them as a new version on top of the latest. Purged versions and
delete markers are refused; offline says so. The concurrent-push note now
points at `atem skill history`.

🤖 Built with SMT <smt@agora.build>
EOF
)"
```

---

## Task 9 [Atem]: A6 — docs, full verification

**Files:**
- Modify: `AGENTS.md` (`CLAUDE.md` is a symlink to it), `designs/atem-memory.md`

**Interfaces:**
- Consumes: everything above.
- Produces: docs only.

- [ ] **Step 1: `AGENTS.md`, the Atem Memory paragraph**

Replace the paragraph that starts `**Atem Memory** (`src/memory/`): `atem sync`, …` with:

```
**Atem Memory** (`src/memory/`): `atem sync`, `atem memory …`, `atem skill …`. Agents learn from each other across agents and machines. Claude's saved memories are harvested (an edited file becomes a replacement, a deleted file an invalidation), Codex saves facts with `atem memory add --agent codex` and replaces outdated ones with `atem memory replace <id> "<new fact>"` (its block shows each fact's short id), and skills are versioned directories (`atem skill history`/`atem skill restore` read old versions from the relay). Facts are never edited in place: `memory replace`/`memory invalidate` keep the history (`valid_at`, `invalid_at`, `superseded_by`; see `memory list --history`), invalidation is final, and only valid facts are injected — a block that leaves facts out says how many and points to `atem memory search`, which is local FTS5 (trigram, BM25) over `knowledge.db`. Everything is synced through the relay (`/api/memory`, `/api/skills`, Astation pairing-session auth) with an offline SQLite store, then applied as a managed block in `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, and `<repo>/CLAUDE.local.md`, and as skills in `.claude/skills` and `.agents/skills`. Credential values are never stored: names only, fetched via `atem vault get <name>`. Tracked files are never written. See `designs/atem-memory.md`.
```

In the config table, replace the `knowledge.db` row's middle cell with:

```
Atem Memory local store: memories (with `deleted_at`/`valid_at`/`invalid_at`/`superseded_by`), the `memories_fts` FTS5 trigram search index, skills, harvest map, local `replacements`, and the pending-sync queue (SQLite, mode 0600; holds no secrets — credentials are refused before storing; migrated in place on open)
```

- [ ] **Step 2: `designs/atem-memory.md`, flip planned → built**

Apply these edits:

1. The status paragraph at the top (`Status: MVP built. …` through `Postgres).`) becomes:

```
Status: built. MVP: Atem #23, #24; relay Astation #19. Phase 1.1 (**Fact
validity**, **Search**, **Skill history and restore**): relay migrations
0004/0005 and atem `feat/memory-1.1`. Spans two repos: **Atem** (CLI, local
store, adapters, sync client) and **Astation** (relay-server `/api/memory`,
`/api/skills` + Postgres).
```

2. In the Codex capture row, change ` *Planned:* a second line telling Codex to run `atem memory replace` when a saved fact is outdated (see "Fact validity"). |` to ` A second line tells Codex to run `atem memory replace <id> "<new fact>"` when a saved fact is outdated; the block shows each fact's short id (see "Fact validity"). |`.

3. Replace the **Edits and deletes** bullet (`- **Edits and deletes:** …` through `` `invalidate`, so the history is kept (see "Fact validity"). ``) with:

```
- **Edits and deletes:** a local `harvest_map` maps
  `origin = <atem_id>:<file path>` to a memory id, a content hash, and a
  status (`synced`, `held_back`, or `excluded`). If the file's content
  changes, atem **replaces** the old memory: it adds the new one and
  invalidates the old one with `superseded_by` pointing at it. If the file
  is deleted, atem **invalidates** its memory. Either way the history is
  kept (see "Fact validity"). A memory is only invalidated this way when
  Claude on this machine created it and no other harvested file links to
  it; otherwise the file is just unlinked. An edit that now looks like a
  credential is held back, and the old memory is invalidated with no
  successor.
```

4. Change `` `relay-server/migrations/0002_knowledge.sql`. Times are unix seconds. `` to `` `relay-server/migrations/0002_knowledge.sql`, as changed by `0004_memory_validity.sql` and `0005_skill_purged.sql`. Times are unix seconds. ``.

5. In the `memories` SQL, replace the lines from `    deleted        BOOLEAN NOT NULL DEFAULT false,  -- tombstone; syncs like any other change` through `    -- PLANNED: ... WHERE deleted_at IS NULL AND invalid_at IS NULL` with:

```
    seq            BIGINT NOT NULL DEFAULT nextval('knowledge_seq'),
    -- added by 0004 (see "Fact validity"); the `deleted` boolean was dropped:
    deleted_at     BIGINT,                   -- tombstone time; NULL = not deleted
    valid_at       BIGINT,                   -- when the fact became true; NULL = created_at
    invalid_at     BIGINT,                   -- when it stopped being true; NULL = still valid
    superseded_by  TEXT                      -- id of the memory that replaced it
);
CREATE INDEX memories_account_seq ON memories (account_id, seq);
CREATE UNIQUE INDEX memories_dedup ON memories
    (account_id, scope, project, machine, content_hash)
    WHERE deleted_at IS NULL AND invalid_at IS NULL;
```

   (Remove the old `seq … nextval` line that sat above the PLANNED comment
   so `seq` appears once.) In `skill_versions`, add a line after its `seq`
   line: `    purged         BOOLEAN NOT NULL DEFAULT false,  -- added by 0005: files erased by purge`.

6. Change ``The tombstone sets `deleted = true` (*planned:* `deleted_at = <now>`),`` to ``The tombstone sets `deleted_at = <now>`,``.

7. Replace the local-store bullets (`- `memories` and `skills`: …` through `` skill, applied locally first. *Planned:* memory `invalidate`. ``) with:

```
- `memories` and `skills`: mirrors of the server rows (latest skill version
  only). `memories` has the same `deleted_at` and validity columns, plus the
  `memories_fts` search index (see "Search"). Opening an older
  `knowledge.db` migrates it in place (`deleted` → `deleted_at`).
- `replacements`: a local-only record of which memory this machine wrote
  to replace which (see "Two replacements of the same fact").
- `pending_ops`: an outbound queue of `add`/`delete`/`invalidate` memory and
  `push`/`delete`/`purge` skill, applied locally first.
```

8. Relay API table:
   - The batch row becomes `| `POST /api/memory/batch` | Push memory ops (`add`, `delete`, `invalidate`). Returns per-op results. |`.
   - The pull row becomes `| `GET /api/memory?since=<seq>&limit=<n>` | Pull memory rows (tombstones and invalidations included, with the validity fields) with `seq > since`. |`.
   - The planned row becomes `| `GET /api/skills/versions`, `GET /api/skills/version` | Skill history and one old version's files (see "Skill history and restore"). |`.
   - After the rule ending `two machines that added the same fact offline end up with one memory.`, add:

```
  Within one batch, a later `delete`/`invalidate` that names the
  deduplicated id (as `id` or `superseded_by`) is rewritten to the
  `canonical_id`; atem rewrites its still-queued ops the same way.
```

9. Replace the **Size cap** bullet and the Codex capture bullet after it with:

```
- **Size cap:** at most 50 entries and 4 KB per block. Sort by confidence,
  then newest first. Only valid facts are written. When facts are left
  out, the block's last line says how many and points the agent to
  `atem memory search "<query>"` (see "Search").
- For Codex, each entry starts with the fact's short id (the first 8
  characters after `mem_`, e.g. `- [1a2b3c4d] DialF uses TCP 8765`), and
  the block also includes the capture and replace instruction lines
  described earlier, placed just before the credential instruction.
```

10. Replace the fenced block under `## CLI` (from `atem sync [--no-harvest] …` through `# held-back memories, credential findings`) with:

```
atem sync [--no-harvest]            # harvest → push → pull → apply (memory + skills)

atem memory add "<content>" [--scope global|project|machine] [--project <key>]
                            [--confidence high|medium|low] [--valid-at <date>]
atem memory replace <id> "<new>" [--valid-at <date>]   # add new, invalidate old
atem memory invalidate <id> [--at <date>]
atem memory list   [--scope …] [--project <key>] [--all] [--history [<id>]]
atem memory search "<query>" [--scope …] [--project <key>] [--history] [--limit <n>]
                                    # FTS5 + BM25, trigram (works for CJK)
atem memory rm <id>

atem memory apply                   # rewrite the managed blocks from the local store

atem skill add <dir> [--scope global|project] [--name <n>]
atem skill list
atem skill rm <name> [--scope …]
atem skill history <name> [--scope …]              # every version (asks the relay)
atem skill restore <name> --version <n> [--scope …]  # re-push version n as a new version

atem memory purge <id>              # remove a leaked credential (see Security)
atem skill purge <name> [--version <n> | --all-versions]

atem memory status                  # account, machine, pending ops, last sync, targets,
                                    # held-back memories, credential findings,
                                    # facts with more than one valid successor
```

   and add this bullet under it: ``- `<date>` is `YYYY-MM-DD` (midnight UTC) or unix seconds. `<id>` for `replace`, `invalidate` and `list --history` is a full id or a unique prefix, with or without `mem_` (the Codex block's short id works).``

11. In "Sync algorithm", replace ``network or HTTP error. *Planned:* pulled invalidations set `invalid_at` `` … `` the report. *Planned:* invalid facts are skipped.`` with:

```
   network or HTTP error. Pulled invalidations set `invalid_at` and
   `superseded_by` locally (a local invalidation not yet on the relay is
   kept); the search index follows through triggers.
4. **Apply** memory blocks and skills to every discovered agent, and print
   the report. Invalid facts are skipped.
```

12. Change `- *Planned,* for Fact validity and Search:` to `- Phase 1.1 (Fact validity, Search, Skill history):`.

13. Change `Status: design, not built yet. Borrowed from Graphiti's` to `Status: built (phase 1.1). Borrowed from Graphiti's`. Then replace every other `Status: design, not built yet.` (Search, and Skill history and restore) with `Status: built (phase 1.1).` (use replace-all).

14. Replace the **Two replacements of the same fact** rule with:

```
- **Two replacements of the same fact** (two machines, both offline) leave
  two valid successors. Both survive. Because invalidation is final, the
  relay keeps only the first `superseded_by`; the machine whose replacement
  came second still knows its link from its local `replacements` table.
  `atem memory status` lists facts with more than one valid successor (from
  `superseded_by` plus that local table), so an agent or the user can
  replace one of them. Only that machine sees the fork.
```

15. In "Search", after the `memories_fts` SQL bullet's sentence `The bundled SQLite in `rusqlite` already includes FTS5, so this adds no dependency.`, add a bullet: ``- The index uses `memories`' implicit rowid, so `knowledge.db` is never `VACUUM`ed without an FTS `'rebuild'` afterwards.``

16. In "Skill history and restore":
    - Change `` `history` prints one line per version, newest first:`` to `` `history` prints one line per version, newest first (times in UTC; the relay doesn't record which pushes were concurrent):``.
    - In the sample, change `4 files   ← concurrent push` to `1 file`.
    - Before `The concurrent-push note gains a pointer:`, insert:

```
`purged` comes from `skill_versions.purged` (migration 0005), set by
`purge`. A purged version and a delete marker are otherwise stored the same
way (`deleted = true`, `files = {}`, `content_hash = ''`), so versions purged
before 0005 report as `deleted`. `version` returns a delete marker with
`deleted: true` and no files; `restore` refuses it.
```

    - Change `The concurrent-push note gains a pointer:` to `The concurrent-push note has a pointer (with ` --scope project` for project skills):`.

17. Phasing table:
    - `| **1 (MVP)** | Everything in this doc not marked *planned*. Built |` → `| **1 (MVP)** | Everything in this doc except the 1.1 items and the Future sections. Built |`.
    - `| **1.1** | Fact validity, local Search, and Skill history and restore (the *planned* items) |` → `| **1.1** | Fact validity, local Search, and Skill history and restore. Built |`.

Then check that no stale markers remain:

Run: `cd /home/guohai/Dev/Agora.Build/Atem && grep -n -i "planned" designs/atem-memory.md`
Expected: only "Not planned." lines in the two Future sections.

- [ ] **Step 3: Full verification**

Run: `cd /home/guohai/Dev/Agora.Build/Atem && cargo build 2>&1 | grep -E "^(warning|error)" | sort | uniq -c; cargo test 2>&1 | grep -E "^test result|FAILED|panicked"`
Expected: no errors (new warnings: none), every `test result: ok`. If only `agent_visualize` fails, re-run `cargo test -- --test-threads=1` and expect `ok`.

Smoke test (no relay needed; run in a scratch HOME so the real store isn't touched):

```bash
cd /home/guohai/Dev/Agora.Build/Atem && cargo build -q && T=$(mktemp -d) && \
HOME=$T ./target/debug/atem memory search "tcp" ; echo "exit=$?"; rm -rf "$T"
```

Expected: the pairing-gate message (Atem Memory requires pairing) and a non-zero exit. The command is wired and gated.

- [ ] **Step 4: Commit**

```bash
cd /home/guohai/Dev/Agora.Build/Atem && git add AGENTS.md designs/atem-memory.md && git commit -m "$(cat <<'EOF'
docs(memory): phase 1.1 built — validity, search, skill history

Flips the planned items in designs/atem-memory.md to built and records the
implementation choices (purged column in 0005, local replacements table for
forks, in-batch canonical mapping, UTC history). AGENTS.md describes
replace/invalidate, search and skill history/restore.

🤖 Built with SMT <smt@agora.build>
EOF
)"
```

> Don't push either branch or open PRs without the user's go-ahead. The
> relay PR (Tasks 1–3) must deploy before the atem PR merges.

---

## Self-review against the design

| Design item | Task |
|---|---|
| Migration 0004 (verbatim), `deleted_at` backfill, dedup index on valid rows | 1 |
| Relay `invalidate` op: final, idempotent, unknown/deleted/foreign ok, new seq, content untouched, account isolation | 1, 2 |
| `add` carries `valid_at`; wire keeps `deleted` + adds new fields | 1, 2 |
| Skill `versions`/`version` endpoints, newest first, no files, 404, 410, another account invisible | 3 |
| Local store migration, 3 validity columns + `deleted_at`, `memories_fts` + triggers | 4 |
| Pulled invalidations set fields locally; index follows via triggers | 4 |
| Apply skips invalid facts; E2E: replaced fact leaves B's block but stays in history | 4 |
| `replace` (add then invalidate), `invalidate`, `--valid-at`, `list --history` chains | 5 |
| Re-adding an invalid fact creates a new memory | 4 (store), 1 (relay) |
| Two valid successors listed by `memory status` | 5 |
| Harvest edit → replace, delete → invalidate (same ownership guard) | 6 |
| Codex short ids + replace line; "N more facts" line | 6 |
| Search: FTS5 BM25, trigram CJK, <3-char fallback, `--scope/--project/--history/--limit` | 7 |
| Skill history + restore: new version, history kept, purged/deleted refused, secret re-check, offline message | 8 |
| Concurrent-push note points at `skill history` | 8 |
| Docs: AGENTS.md, design status, relay README, nginx statement | 3, 9 |
