# Credential Project Discovery

The Credentials project field is an editable list: reported Git projects from
verified Atem devices, existing saved credential scopes, or a manually entered
Git remote. Suggestions never grant a device access to a credential. Agora App
projects and local filesystem paths are not credential project identities.

An updated, unlocked Atem reports its current Git remote and project names it
has remembered for the account. It reports after authenticated connection, right
after `atem cred unlock` succeeds (the report on connect was skipped because the
keys were still locked), and in response to `credentialProjectListRequest`. `atem cred projects` explicitly
publishes suggestions with a bounded connection/delivery wait. Locked or unverified clients
send no inventory and never trigger an unlock prompt just to fill this list.
An ephemeral CLI can send its report and exit; no persistent connection or
unbounded acknowledgment wait is required. Signing the report needs a key
agent from a build that knows the request: after updating atem, an agent
still unlocked from the older build keeps running it, and `atem cred lock`
followed by `atem cred unlock` picks up the new agent (a locked older agent
is replaced automatically).

`credentialProjectListResponse` carries a `report` with `signed`,
`encapped_key`, and `ciphertext`. The payload is a JSON array of canonical
project keys: lowercased `host/owner/repo`, with credentials and `.git` removed.
It contains at most 256 names and 64 KiB. Reports always use HPKE
X25519/HKDF-SHA256/ChaCha20-Poly1305, including when memory encryption is OFF.
The recipient is the Astation encryption key pinned during verification.

## Project spelling and compatibility

Project identity remains the lowercase canonical key. An updated CLI passes
the current repository's original-case `RepoInfo.label` to the cred agent.
The agent adds an optional encrypted `labels` envelope to the legacy report,
containing a JSON array of `{key, label}` for exactly the reported keys. Both
arrays together are limited to 64 KiB and 256 projects. Labels must be
sanitized names whose canonical lowercase identity equals the accompanying
key. Original spelling is display metadata; memory keys and hashes do not
change. Remembered lowercase names remain lowercase when their original
spelling is no longer known.
The account's known spellings are remembered as optional `labels` in the local
format-1 `project_names.json`; its existing hash-to-canonical-key mapping stays
unchanged. Updates use the same private atomic writes and file lock. Account
reset forgets both mappings. Labels are captured only after validating the
current unlocked device and verified Astation pin.

The extension has `signed`, `encapped_key` and `ciphertext` fields, using
`atem-credential-project-labels-info-v1` for HPKE info and
`atem-credential-project-labels-v1` for the signed statement, followed by the
same account/device/generation/time fields and its own ciphertext digest.
Astation verifies both envelopes against its current pin and requires the
same identity, timestamp and canonical project set. Malformed extensions
reject the report. Removing labels affects display only, never permissions.
Legacy Astation builds ignore this optional field and continue reading the
lowercase array; legacy cred agents omit the field. Both envelopes are sent in
one message, so ephemeral CLIs do not need another capability exchange or a
persistent connection. Unlocked older agents remain running until the user
runs `atem cred lock` and `atem cred unlock` with the updated binary.

Using the existing length-prefixed field encoding and big-endian u64 fields:

- HPKE info: `atem-credential-projects-info-v1`, account, device ID, signing
  generation (1), report time (Unix seconds).
- Device-signed statement: `atem-credential-projects-v1`, account, device ID,
  signing generation (1), report time, SHA-256 of the encoded encapsulated key
  and ciphertext.

Astation captures the authenticated route before dispatch. It verifies the
device signature against its current local pin, account/device binding,
generation, payload bounds, ciphertext digest and report time (at most five
minutes old or one minute ahead), then decrypts using its protected identity.
Revoked or replaced pins cannot supply suggestions. Duplicate reports are
idempotent; older reports cannot replace newer suggestions. Accepted reports
can finish after the sending CLI disconnects. Account changes and revocation
remove cached suggestions when the picker is refreshed. The cache is in
process memory; saved credential scopes remain available after restart.

The relay transports ciphertext only. It supplies neither authoritative device
identity nor project permissions. Refresh requests contain no secret or
project name; responses can only be encrypted to the locally pinned Astation.
Manual input remains available with no connected Atem. This reporting feature
does not implement Atem credential retrieval or the future scope-grant service.
