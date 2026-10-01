# Agora account grouping: one data account across Macs

Status: design, for review (2026-10-01). Nothing built.
Owner: Brent G

## Problem

The relay files memory, skills and vaults under the **Astation ID**. Each
Astation install creates its own random ID (`astation-<UUID>` in
`~/Library/Application Support/Astation/identity.txt`), and nothing ties
it to the user's Agora login. As a result:

- **Two Macs are two accounts.** Atems paired with Mac A see A's data, atems
  paired with Mac B see B's, and nothing is shared, even when both Astations
  are signed in to the same Agora account.
- **Reinstalling or losing the Mac loses the way in.** A new install makes a
  new, empty ID. Getting the old data back needs the old ID (the recovery kit,
  Astation #27) plus an operator running `forget-key`.

## Goal

Every Astation signed in to the same Agora account reaches the same memory,
skills and vaults, and a replacement Mac gets them back just by signing in.
Each Mac still proves its own device key, so knowing an ID is never enough.

## Non-goals

- Changing how atems pair or authenticate. Atems still pair with one Astation;
  only what the relay resolves their session to changes.
- Sharing between different Agora accounts (teams). That's a later design.
- Replacing the device key. It stays per Mac, in the Keychain.

## Design

### Two levels: devices and data accounts

| Level | Id | Proven by |
|---|---|---|
| Device | `astation-<UUID>` (unchanged) | the Mac's P-256 relay key (`relayAuth`, unchanged) |
| Data account | `agora:<stable Agora user id>` | an Agora SSO access token, checked once when the device links |

The relay keeps one new table:

```sql
CREATE TABLE account_devices (
    astation_id TEXT PRIMARY KEY,   -- a verified device
    account_id  TEXT NOT NULL,      -- 'agora:<user id>'
    label       TEXT NOT NULL,      -- e.g. the Mac's name, for the device list
    linked_at   TIMESTAMPTZ NOT NULL
);
```

An Astation that isn't linked keeps working exactly as today: its data
account is its own Astation ID. Linking is optional.

### Resolving a request

Today: session → `astation_id` → data is filed under `astation_id`.

New: session → `astation_id` → `account_devices.account_id`, if linked;
otherwise the `astation_id` itself. The result is the **data account**.
Memory, skills and vault all key on it. In the code, that's the value now
called `work_session_id`. `/api/memory`, `/api/skills` and `/api/vault` stay
the same; only `resolve_caller` changes. The mapping is cached in Valkey
alongside the session bindings.

### Linking a Mac to the Agora account

Settings → Security → **Link to my Agora account** (shown when signed in):

1. Astation sends `relayLinkAccount { sso_access_token, label }` over its
   **verified** relay connection. That proves the device; the token proves
   the person.
2. The relay calls `GET {sso}/api/v0/oauth/userinfo` with the token,
   server to server, and reads the stable user id. The token is not stored.
3. If the Agora account already has linked devices, the new device must be
   approved (see "Approving a new Mac"). Otherwise it links at once.
4. The relay moves this device's existing data into the account (below) and
   replies `relayAccountLinked { account_id, devices }`.

### Moving existing data

When a device links, everything filed under its Astation ID moves to the
account, in one transaction:

- **Memories:** ids are UUIDs, so rows just move. A memory with the same
  content as one already in the account is deduped by the existing
  `(scope, project, machine, content_hash)` rule.
- **Skills:** the same `(scope, project, name)` in both becomes one history:
  the moved versions are appended after the account's, so no version is lost.
- **Vaults:** vault ids are unique, so vaults just move.
- **Sequence numbers:** moved rows get new `seq` values, so every atem's next
  pull picks them up.

### Approving a new Mac

Linking with only an Agora login would mean anyone who gets into the Agora
account gets the data. So:

- **If the account has a linked device online**, that Astation shows "MacBook
  Pro (new) wants to join your account. Approve?". The new device links only
  after approval.
- **If no linked device is online for 10 minutes** (for example, the only Mac
  was lost), the link goes through after a **fresh** Agora sign-in (the
  token must be under 5 minutes old) and a 24-hour wait. All linked devices
  are notified, and any of them can cancel during the wait. See open
  question 2.

### Managing devices

Settings → Security lists the account's devices (label, linked date, last
seen), with **Remove** on each. Removing a device unlinks it and runs the same
key revocation as `forget-key`, so it disconnects at once. This replaces the
operator step for a lost Mac: remove it from the new Mac.

**Unlink this Mac** moves the device out of the account. The data stays with
the account, and this Mac starts over with an empty data account under its
own Astation ID.

### Atems

No atem change. An atem paired with any linked Astation sees the account's
data. A paired atem that was pairing with a lost Mac re-pairs with the new
Mac, and its memories and vaults are already there.

### With end-to-end encryption

The account key `K` (see `e2e-encryption.md`) belongs to the data account, not
the device. A newly linked Astation gets `K` from an approving device: wrapped
to the new Mac's device key, carried in the approval. Otherwise it comes from
any paired atem, or from the recovery key. Devices that are removed should
trigger a key rotation.

### What happens to the recovery kit (Astation #27)

For linked Macs, signing in replaces it: no ID to save, no `forget-key`. It
remains useful only for Astations that are never linked to an Agora account.
Options: merge it as the fallback for unlinked users, or drop it and make
linking the recovery path. See open question 4.

## Costs and risks

- **The relay depends on Agora SSO**, but only while linking, not per request.
  If SSO is down, existing devices keep working; new links wait.
- **An Agora account compromise** reaches the data only through the approval
  rule above. Without end-to-end encryption, the server operator can still
  read everything, as today.
- **Merging data** when a second Mac links is the riskiest step. It needs
  careful tests for skills that exist in both.
- **Work:**
  - Relay: a migration, the `account_devices` store, `resolve_caller`, link,
    approve, list and remove messages, the data move, and tests.
  - Astation: Settings UI plus the approval prompt.
  - Atem: none.

## Open questions

1. **Stable user id.** Which userinfo field is the permanent Agora user id
   (`sub`, `user_id`, …)? It must not be the email, which can change. This
   needs a look at a real userinfo response or the SSO docs.
2. **Approving when no device is online**: is a fresh sign-in plus a 24-hour
   wait with notifications right? Or would you prefer no automatic path
   (recovery only through the recovery kit or an operator)?
3. **Link by default**: should a signed-in Astation offer to link on first
   launch, or link only when the user chooses it in Settings?
4. **Recovery kit (#27)**: merge as the fallback for unlinked Astations, or
   close it in favor of linking?
