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

**Encryption is optional.** It is off by default, and the account owner turns
it on or off in Astation's settings. Off is the current behavior; with it on,
the relay can't read the data.

## Non-goals

- Hiding *that* data exists, its size, timing, or which atem wrote it.
- Protecting against a compromised paired device. It holds the key by
  design.
- Encrypting Astation's own relay traffic (pairing, voice, tasks). This
  covers stored data only.

## Design

### The Astation setting

Settings → **Security** → "End-to-end encrypt memory, skills and vault"
(off by default).

**Turning it on:**

1. Astation creates the account key `K` (below) and asks for Touch ID or the
   Mac password before showing anything.
2. It shows a notice the user must acknowledge:

   > **Save your recovery key offline.** Your memories, skills and vaults will
   > be encrypted with a key that only your paired devices hold. If you lose
   > this Mac and every paired atem, the data can't be recovered without this
   > key: not by you, and not by the server operator.
   >
   > `ABCD-EFGH-…` (the key, as groups of base32 characters)
   >
   > [Copy] [Save to file…]  ☐ I've saved my recovery key somewhere safe

   The **Turn on** button stays disabled until the box is checked.
3. Astation tells the relay the account is now encrypted:
   `relayEncryption { enabled: true, kid }`, sent over its verified relay
   connection, which proves it holds the account's relay key. The relay
   stores the flag per account.
4. Connected atems get `encryptionMode { enabled, kid }` and request the key
   (see below). Atems that connect later get the same message on connect.

**While it's on:**

- The relay **refuses plain-text uploads** from the account. An old atem that
  can't encrypt gets a clear error ("this account requires encryption;
  update atem") instead of silently uploading plain text.
- Settings shows "On since <date>", plus **Show recovery key…**, which asks for
  Touch ID or the password first.

**Turning it off** (confirmation required; it warns that the data goes back
to being readable on the server):

1. Astation sets the account to `disabling`. The relay then accepts both
   plain text and ciphertext.
2. Each atem that holds `K` pulls, decrypts, and re-uploads in plain text.
   The relay then deletes the ciphertext rows.
3. When no ciphertext remains, Astation sets the mode to off and deletes `K`
   from the Keychain.

**A new Astation** (lost Mac): during setup, or from Settings, the user can
choose **Restore from recovery key**, paste the key, and continue. Atems that
still hold `K` can also re-grant it (see "Losing the key").

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
- **Per-account mode** (`off` | `on` | `disabling`), set only by the
  account's verified Astation. When it's `on`, plain-text uploads are refused
  so an old atem can't upload plain text by mistake. When it's `disabling`,
  both are accepted.
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
- the **recovery key**, shown when encryption is turned on and saved offline
  by the user, covers losing every device at once.

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

## Decisions

Decided (2026-10-01):

- **Optional.** Off by default, and turned on or off in Astation's settings.
- **Recovery key.** Shown once when encryption is turned on (behind Touch ID
  or the Mac password), and the user must confirm saving it offline. Any
  paired atem can also re-grant the key.
- **Plain text cut-over.** While encryption is on, the relay refuses plain
  text. Turning it off goes through `disabling`.

Still open:

1. **Fingerprint check at pairing**: required in v1, or trust on first use
   now and add it later?
2. **History purge**: OK for turning encryption on to delete plain-text
   history (old skill versions, old vault entry versions)?
3. **Scope**: memory + skills + vault together, or vault first (smallest,
   no dedup or project hashing)?
