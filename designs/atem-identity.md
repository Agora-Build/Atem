# Atem Identity (`instance_id` + `atem_id`)

Status: implemented — 2026-05-29
Owner: Brent G

## Goal

Give every atem install a **stable, unique identity** that the relay can use to
tell multiple atems apart in a room, and that higher-level features (the vault's
`writer_list`, see [[vault]]) can use as a durable client id.

Before this, atem had no such identity: the relay `atem_id` was just the
sanitized **hostname**, so two machines named `mbp` collided, and the id changed
whenever the hostname changed.

## Two identifiers

| Id | Form | Purpose | Persisted |
|----|------|---------|-----------|
| `instance_id` | UUID v4 (e.g. `550e8400-e29b-41d4-a716-446655440000`) | canonical unique identity; the value `atem_id` is derived from; the vault client id | `config.toml` |
| `atem_id` | `<host:12>-<suffix:8>` (e.g. `MacBook-Prol-550e8400`) | relay room disambiguation + a human-readable id in relay logs / the instance list | `config.toml` |

Both are generated once and frozen, so they survive restarts. `atem_id` is also
frozen against hostname changes (it's stored, not recomputed each connect).

### `instance_id`

- `AtemConfig::ensure_instance_id()` — returns the stored UUID, or mints one
  (`uuid::Uuid::new_v4()`) and merges it into `config.toml`. Best-effort: if the
  file can't be written, a fresh id is still returned so connecting isn't blocked
  (it just won't be stable until a write succeeds).
- This is the **canonical** identity. The vault uses it directly as `client_id`
  (the `writer_list` key) — see [[vault]].

### `atem_id`

Derived once from hostname + `instance_id`, then stored (`store_atem_id` /
`stored_atem_id`). On connect: reuse the stored value if present, else build +
store.

**Shape:** `<host>-<suffix>`, 21 chars in the common case.

- **Host segment** — normalized to exactly **12 characters** (counted in chars,
  not bytes — CJK is multibyte). Truncated if longer, padded if shorter.
- **Suffix** — the first 8 alphanumerics of `instance_id` (the first UUID block,
  e.g. `550e8400`). This is what guarantees global uniqueness: two machines that
  share a hostname differ in the suffix.

**Charset:**

- **Non-ASCII** (Chinese / Japanese / Korean, etc.) is **kept as-is** in the host
  segment — hostnames stay readable.
- **ASCII** is restricted to `[A-Za-z0-9-]`. Dots, underscores, and other
  punctuation are dropped.

**Padding** for short hostnames is drawn from the `instance_id` pool (the chars
after the 8 used for the suffix), so it looks varied but is **stable** across
restarts rather than fresh-random.

Examples:

| Hostname | `atem_id` (suffix from `550e8400-…`) |
|----------|--------------------------------------|
| `MacBook-Pro.local` | `MacBook-Prol-550e8400` (dot dropped, truncated to 12) |
| `host-01.lan` | `host-01lanXX-550e8400` (digits kept, padded) |
| `mbp` | `mbpXXXXXXXXX-550e8400` (padded to 12) |
| `我的电脑` | `我的电脑XXXXXXXX-550e8400` (CJK kept, padded) |
| `私のパソコン端末` | `私のパソコン端末XXXX-550e8400` |
| `내컴퓨터` | `내컴퓨터XXXXXXXX-550e8400` |

(`X` = stable padding from the instance-id pool.)

## URL handling

`atem_id` may contain non-ASCII, but it travels in the relay WebSocket URL as a
query param:

```
wss://<relay>/ws?role=atem&code=<astation_id>&atem_id=<percent-encoded atem_id>
```

- The atem side **percent-encodes** `atem_id` (`urlencoding::encode`) so the URL
  is pure ASCII and valid URI syntax — the WS client (`connect_async` →
  `IntoClientRequest`) parses it. A raw non-ASCII URL is rejected by that parser,
  so encoding is load-bearing.
- The **relay must percent-decode** the query param to recover the canonical
  `atem_id`. Standard query extractors (axum's `Query`) do this automatically.

### Relay-side requirement (Astation repo)

The relay-server has its own `atem_id` sanitizer that previously stripped to
URL-safe ASCII. For non-ASCII ids to round-trip, that sanitizer must be updated
to match this rule (keep non-ASCII; ASCII → `[A-Za-z0-9-]`) and to percent-decode
the query param. If it keeps stripping non-ASCII, the relay's stored id won't
match atem's canonical id.

## Storage

`~/.config/atem/config.toml` (plaintext, non-sensitive):

```toml
instance_id = "550e8400-e29b-41d4-a716-446655440000"  # auto-generated, do not edit
atem_id     = "MacBook-Prol-550e8400"                 # auto-generated, do not edit
```

Both are surfaced (unmasked) by `atem config show`.

## Code map

| Piece | Location |
|-------|----------|
| `ensure_instance_id`, `stored_atem_id`, `store_atem_id`, `read_config_string`, `write_config_string` | `src/config.rs` |
| `build_atem_id(hostname, instance_id)` (pure) | `src/websocket_client.rs` |
| `relay_ws_url(relay_base, identity_code, atem_id)` (pure, percent-encodes) | `src/websocket_client.rs` |
| Orchestration (stored-or-build, then connect) | `src/websocket_client.rs::connect_relay_identity` |

## Tests

`src/websocket_client.rs` unit tests cover: ASCII truncation/padding, digits
kept, dots dropped, Chinese/Japanese/Korean preservation, char-vs-byte
truncation, stability, uniqueness, URL is-ASCII + parses via `IntoClientRequest`,
query round-trip, and that a raw non-ASCII URL is rejected.

## Open questions

1. **Multiple atem processes on one machine.** `instance_id` is per-install
   (one `config.toml`), so two atem processes sharing a config dir share an id.
   Fine today (one atem per host); revisit if we support concurrent atems per
   machine.
2. **Relay sanitizer alignment.** Tracked above — needs an Astation-repo change
   before non-ASCII ids round-trip in production.
