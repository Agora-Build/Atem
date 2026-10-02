# Agora account grouping: merge Astations under one Agora login

Status: design, for review (2026-10-01). Nothing built.
Owner: Brent G

## Problem

The relay files memory, skills and vaults under the **Astation ID**. Each
Astation install creates its own random ID (`astation-<UUID>` in
`~/Library/Application Support/Astation/identity.txt`), and nothing ties
it to the user's Agora login. As a result:

- **Two Macs can't share.** Atems paired with Mac A see A's data, and atems
  paired with Mac B see B's, even when both Astations are signed in to the
  same Agora account. There is no way to combine them.
- **A replacement Mac can't reach the old data** without the old ID (the
  recovery kit, Astation #27) and an operator running `forget-key`.

## Goal

- Each Astation keeps its **own ID and its own data by default**, exactly as
  today, even when several are signed in to the same Agora account.
- The Agora account lets the user **see their Astations** and **choose to
  merge** any of them, so they share one set of memory, skills and vaults.
- A replacement Mac gets the old data back by signing in and merging with the
  old (lost) Astation.
- Each Mac still proves its own device key, so knowing an ID is never enough.

## Non-goals

- Merging automatically. Nothing is combined unless the user chooses it.
- Changing how atems pair or authenticate.
- Sharing between different Agora accounts (teams). That's a later design.

## Design

### Three ids

| Id | What it is | Proven by |
|---|---|---|
| Astation ID `astation-<UUID>` | one install on one Mac (unchanged) | the Mac's P-256 relay key (`relayAuth`, unchanged) |
| Agora user | the person signed in on that Astation | an Agora SSO access token, checked when registering |
| Data account | where memory, skills and vaults are filed | — |

The data account is the Astation's own ID until the user merges it. After a
merge, every Astation in the group points at a shared group id
(`group-<UUID>`).

The relay keeps one new table:

```sql
CREATE TABLE astation_accounts (
    astation_id  TEXT PRIMARY KEY,   -- a verified device
    agora_user   TEXT NOT NULL,      -- stable Agora user id
    label        TEXT NOT NULL,      -- e.g. the Mac's name, for the list
    data_account TEXT NOT NULL,      -- = astation_id, or a group-<UUID>
    registered_at TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL
);
```

An Astation that never registers keeps working exactly as today (its data
account is its own ID, and it doesn't appear in anyone's list).

### Registering: making Astations visible to each other

When the user is signed in to Agora, Astation sends
`relayRegisterAccount { sso_access_token, label }` over its **verified**
relay connection. That proves the device; the token proves the person. The
relay calls `GET {sso}/api/v0/oauth/userinfo` with the token, server to
server, reads the stable user id, and records the row with
`data_account = astation_id`. The token is not stored.

Registering **changes nothing about data**. It only lets the user's other
Astations list this one.

### Resolving a request

Today: session → `astation_id` → data filed under `astation_id`.

New: session → `astation_id` → `astation_accounts.data_account` if the row
exists, else `astation_id`. Memory, skills and vault all key on that value. In
code, it's what is now called `work_session_id`. `/api/memory`, `/api/skills`
and `/api/vault` don't change; only `resolve_caller` does. The mapping is
cached in Valkey with the session bindings.

### Merging

Settings → Security → **Astations on your Agora account**:

```
This Mac   MacBook Pro         astation-4630…7279625   own data
           Mac mini (office)   astation-91AC…0C3F1B2   own data      [Merge…]
           MacBook Air (lost)  astation-77E2…5D9A0A1   last seen 3 weeks ago  [Merge…] [Remove]
```

**Merge…** with another Astation:

1. The other Astation must **approve**, if it's online: "MacBook Pro wants to
   merge its memories, skills and vaults with this Mac. Approve?"
2. If it hasn't been online for 10 minutes (lost or off), the merge needs a
   **fresh** Agora sign-in on this Mac (token under 5 minutes old) and goes
   through after a **24-hour wait**. Every registered Astation on the account
   is notified, and any of them can cancel during the wait. This is the
   lost-Mac path.
3. The relay creates `group-<UUID>`, or reuses the other side's group if it
   already has one. It moves both Astations' data into it in one
   transaction, and points both rows at it.

Merging a third Astation into an existing group works the same way: any
online member approves.

**Leave group**: this Astation's `data_account` goes back to its own ID and
starts empty. The group keeps all data, so leaving never deletes anything.

**Remove** (for a lost Mac): unregisters it, takes it out of its group, and
runs the same key revocation as `forget-key`, so it disconnects at once. No
operator step is needed.

### Moving data on merge

Everything filed under each side moves to the group:

- **Memories:** ids are UUIDs, so rows just move. A duplicate fact is deduped
  by the existing `(scope, project, machine, content_hash)` rule.
- **Skills:** the same `(scope, project, name)` on both sides becomes one
  history. The other side's versions are appended, so none is lost.
- **Vaults:** vault ids are unique, so vaults just move.
- **Sequence numbers:** moved rows get new `seq` values, so every atem's next
  pull picks them up.

### Atems

No atem change. An atem paired with any Astation in a group sees the group's
data on its next sync. Atems that paired with a lost Mac re-pair with the new
one; after the merge, their data is there.

### With end-to-end encryption

The encryption key `K` (see `e2e-encryption.md`) belongs to the data account.
In a merge, the approving side hands its `K` to the new member, wrapped to the
new member's device key. If both sides already have keys, the merged group
uses the approver's key, and the other side's atems re-encrypt what they
push. If the old Mac is lost, `K` comes from one of its paired atems or from
the recovery key.

### What happens to the recovery kit (Astation #27)

With registration, a lost Mac appears in the new Mac's list and can be merged
after sign-in, with no ID to save and no operator. The kit remains useful only
for Astations that are never registered (the user never signed in to Agora).

## Costs and risks

- **The relay depends on Agora SSO**, but only when registering and
  merging, not per request. If SSO is down, existing Astations keep working.
- **An Agora account compromise** can't merge silently: a merge needs an
  online member's approval, or a 24-hour, notified wait. Without end-to-end
  encryption, the server operator can still read everything, as today.
- **Merging data** is the riskiest step. It needs careful tests for skills
  present on both sides.
- **Work:**
  - Relay: a migration, the `astation_accounts` store, `resolve_caller`,
    register, list, merge, approve, leave and remove messages, the data move,
    and tests.
  - Astation: the Settings list plus the approval prompt.
  - Atem: none.

## Decisions

- **Separate by default; merge by choice** (2026-10-01). Astations under the
  same Agora account each keep their own Astation ID and data until the user
  merges them.

## Open questions

1. **Stable user id.** Which userinfo field is the permanent Agora user id
   (`sub`, `user_id`, …)? It must not be the email, which can change. This
   needs a look at a real userinfo response or the SSO docs.
2. **Merging when the other Astation is offline**: is a fresh sign-in plus a
   24-hour wait with notifications right?
3. **Registering**: automatic whenever Astation is signed in to Agora
   (recommended; it only makes the Mac visible to the user's own Astations),
   or an explicit opt-in?
4. **Recovery kit (#27)**: merge as the fallback for unregistered Astations,
   or close it?
