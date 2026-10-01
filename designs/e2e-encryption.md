# End-to-end encryption for memory, skills and vault

Status: design, for review (2026-10-01). Nothing built.
Owner: Brent G

## Problem

The relay (station.agora.build) stores memory, skill files and vault
entries as plain text in Postgres. Isolation between accounts holds: every
request is bound to one Astation account, and since Astation #26 vault reads
are same-account only. But anyone who can see the server's data can read
everything:

- whoever operates the server, Coolify, or the Postgres container;
- database backups and dumps;
- Cloudflare, which terminates TLS in front of the relay;
- an attacker who breaches any of the above.

Goal: these parties see only ciphertext. Only devices paired with the
account (its atems) can read content.

## Non-goals

- Hiding *that* data exists, its size, timing, or which atem wrote it.
- Protecting against a compromised paired device. It holds the key by
  design.
- Encrypting Astation's own relay traffic (pairing, voice, tasks). This
  covers stored data only.

## Design

### One key per account

Astation generates a random 256-bit **account data key** `K` when it first
needs one, and keeps it in the macOS Keychain. Astation never decrypts data
itself: its UI doesn't show memories, skills or vaults. It only stores `K`
and hands it to atems.

Each key has a short id (`kid`, 8 hex chars) so it can be rotated later.

### Getting the key to an atem

The relay forwards every message between atem and Astation, so `K` must not
travel in the clear:

1. Each atem keeps an X25519 key pair in `~/.config/atem/device_key`
   (mode 0600, created once).
2. When paired and connected, atem sends `keyRequest { atem_pubkey }` if it
   has no `K`.
3. Astation wraps `K` to that public key (X25519 + HKDF-SHA256 +
   ChaCha20-Poly1305, i.e. an HPKE-style seal) and replies
   `keyGrant { kid, wrapped_key }`. The relay sees only the wrapped key.
4. atem stores `K` in `~/.config/atem/data_keys.enc`, encrypted with the
   same machine-bound AES-256-GCM scheme as `credentials.enc`.

**Relay substitution.** A malicious relay could swap the atem's public key
during step 2 and keep `K`. To stop that, Astation's approval prompt shows a
short fingerprint of the atem's public key (for example `7F3A-91C2`), and
`atem pair` prints the same value. The user compares them once per device.
v1 could skip the comparison (trust on first use) and add it later; see
open question 1.

### What gets encrypted

| Data | Encrypted | Stays plain (the relay needs it) |
|---|---|---|
| Memory | `content` | id, scope, machine, confidence, source, timestamps, validity, seq |
| Memory | | `project`: keyed hash `HMAC(K, key)`; see below |
| Memory | | `content_hash` becomes `HMAC(K, content)` |
| Skill | every file's bytes, and file paths | name, scope, project (HMAC), version, timestamps |
| Vault | entry `content`, `summary` | vault id, entry number, version, writer, timestamps |

- **Format.** Each encrypted field is `e1.<kid>.<base64(nonce || ciphertext)>`,
  using XChaCha20-Poly1305 with a random 24-byte nonce. The associated data
  is the record's id plus the field name, so the server can't move a
  ciphertext to another record or field.
- **Project keys** reveal repo names (`github.com/agora-build/astation`).
  Sending `HMAC(K, key)` instead keeps per-project filtering working without
  revealing the name. atem keeps the hash → name mapping locally, since it
  computes both.
- **`content_hash`** is what the relay dedupes on. A plain SHA-256 of a short
  fact can be guessed and confirmed. A keyed HMAC keeps dedup within the
  account and leaks nothing.

### What changes on the relay

- **Accept ciphertext.** For fields starting with `e1.`, skip the credential
  scan. It can't read them. atem's local scan stays mandatory and fail-closed,
  and becomes the only check.
- **Refuse plain text** once an account has switched over (open question 3),
  so an old atem can't upload plain text by mistake.
- No schema change: the fields are already text, and ciphertext fits in them.

### What changes in atem

- `src/memory/crypto.rs`: seal/open fields, HMAC helpers, key storage.
- Encrypt in `api.rs` just before sending; decrypt right after pulling. The
  local `knowledge.db` stays plain text, so search and managed blocks are
  unchanged. It's already mode 0600 on the device.
- `vault_client.rs`: encrypt on write and set-summary, decrypt on read.
- With no key yet, atem queues changes locally and tells the user to connect
  to Astation to get one, rather than sending plain text.

### Moving existing data over

The relay already holds plain text. On first sync with a key, atem would:

1. push encrypted copies of every memory and skill it has (new rows with the
   same ids, or a new `reencrypt` op);
2. ask the relay to purge the plain-text versions, including skill history
   and old vault entry versions.

This needs a relay op that overwrites history. Today history is
append-only, so this is the one place the design bends that rule.

### Rotation and revocation

- **Removing a device** (`forget-key`, or a future "revoke device" button)
  stops its access to the relay. It still holds the old `K`, so it can read
  anything it already downloaded or any backup it obtains.
- To fully cut it off, rotate: Astation makes a new `K` with a new `kid` and
  grants it to the remaining devices, which re-encrypt and push again. Old
  ciphertext stays readable to holders of the old key until purged.

### Losing the key

If the Mac running Astation is lost and no atem still holds `K`, the data is
gone for good. That's the point of the design. Mitigations:

- every paired atem holds `K`, so any one of them can re-grant it to a new
  Astation (a new `keyOffer` message, approved on both sides);
- optional: Astation can export `K` as a recovery phrase for the user to
  keep offline.

## Costs

- The relay's credential scan stops for encrypted fields. Only atem's
  local scan protects against uploading a credential.
- Server-side features that read content become impossible: server-side
  search, a web view of memories, server-side ranking. Today none exist;
  vector search would have to run on the device.
- The relay operator can no longer debug content problems by looking at rows.
- About 3 files of new atem code, a new Swift key manager plus 2 messages,
  and a small relay change. Moving existing data requires the history purge
  described above.

## Open questions (decisions for the user)

1. **Fingerprint check at pairing**: required in v1, or trust on first use
   now and add it later?
2. **Recovery**: is "any paired atem can re-grant the key" enough, or should
   Astation also offer a recovery phrase?
3. **Plain text cut-over**: once an account has a key, should the relay
   refuse plain-text uploads from that account (safer), or accept both for a
   transition period (friendlier to atems that haven't upgraded)?
4. **History purge**: OK for the migration to delete plain-text history
   (old skill versions, old vault entry versions), which makes history
   shorter?
5. **Scope**: memory + skills + vault together, or vault first (smallest,
   no dedup or project hashing)?
