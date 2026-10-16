# Pairing, Device Keys and Project Suggestions

Atem can run on Linux or another Mac while Astation runs on your Mac. Pairing
provides an authenticated connection and account sign-in; device verification
establishes trust for keys, encryption and encrypted project reports. API keys
saved in Astation's Credentials editor are a separate local Keychain store.

## Use a current build

Install a published release with `npm install -g @agora-build/atem`, or use the
[installer and source build instructions](../README.md#install). The npm wrapper
downloads the binary matching its package version. Merging code or README
changes into GitHub `main` does not publish a new npm package or update the
README displayed on npmjs.com; those changes ship with a subsequent release.

Check the binary you are actually running:

```sh
atem --version
atem cred --help
```

If `cred projects` is missing, use a release that includes it or build current
`main`. For a source build, replace `atem` in this guide with the path to that
binary, for example `./target/release/atem`; building alone does not replace an
older global npm installation. An older unlocked key agent can also continue
running after the CLI has been updated; see the upgrade steps below.

## Pair from another machine

1. Run a current, provisioned Astation build on your Mac. Sign in and check
   that its account/relay connection is available. For a remote machine use
   the identity relay; a configured direct LAN endpoint is also supported.
2. On the Atem machine, run `atem pair`. Use `atem pair --save` if you want the
   shared sign-in credentials to remain usable when Astation disconnects.
   This preference does not unlock device keys indefinitely.
3. Approve pairing in Astation. Compare the complete safety code on both
   machines. Type `y` in Atem if it matches; on the Mac click **Codes Match**,
   then use Touch ID in the same window. Either side can finish first. Keep
   the pairing command open until it reports device verification.
4. If Astation asks you to save a recovery kit, save the complete kit and
   confirm. Finish any key-escrow/unlock approval requested by the pairing
   command, then run `atem status`.

The status must say the device is verified. **Connected** or **Paired with
Astation** alone confirms neither device verification nor key-agent unlock.
Without saved credentials, shared sign-in has a five-minute grace period
after disconnection. Saving credentials does not provide offline access to
the relay or remove the Mac approval required to unlock sealed device keys.

## Unlock and upgrade the key agent

```sh
atem status
atem cred unlock
```

Unlock approval happens on the home Astation Mac, not on the remote Linux
machine. Keep the unlock command open while you approve Touch ID on the Mac;
the approval wait is bounded to five minutes. The background key agent holds
the unlocked device and account keys, so later CLI commands can exit normally.

A status marked **started by another atem build** means the unlocked agent
runs a different executable: an older install, or another copy such as a
development build next to the npm one. With the atem you want to use, run:

```sh
atem cred lock
atem cred unlock
atem status
```

Lock wipes keys from memory and stops the agent. Unlock starts the current
agent and requests fresh Mac approval. An older locked agent is replaced
automatically; an older unlocked agent is retained until you perform these
steps. Reports from an older agent may omit original-case labels or lack
project discovery entirely.

## Add a Git project to Astation's picker

Run inside the repository with the verified device unlocked:

```sh
atem cred projects
```

An unlocked atem also reports on its own whenever it connects to Astation: the
TUI, `atem pair`, and right after `atem cred unlock` in the repository. Run
`atem cred projects` to send the report right away from another repository.

Open Settings > Credentials on the Mac, add a credential, select **Use project
scope**, and choose the reported project. Refresh the list if needed. You can
also enter another Git remote manually; no connected Atem is needed for that.

For `git@github.com:Agora-Build/Atem.git`, the displayed and saved scope is
`github.com/Agora-Build/Atem`. Its identity is `github.com/agora-build/atem`:
case variants share one scope and are deduplicated. URL credentials, protocol
prefixes and `.git` are removed from display labels. Previously stored
lowercase spellings stay lowercase until a remote or manual entry supplies
the original spelling; clients do not invent capitalization.

Projects come from the current Git remote and account-specific remembered
names. Filesystem paths and Agora App projects are not Git credential scopes.
Reports are signed by the verified device and encrypted to Astation even
when memory encryption is off. They can finish processing after Atem exits.
The picker caches accepted reports until Astation quits; saved scopes survive
relaunch. A suggestion does not grant access to a credential value.

## Complete an encryption migration

Astation controls the account's signed encryption state in Settings >
Security > End-to-End Encryption. When it displays **Turning on** or
**Turning off**, run this with a current, verified Atem build:

```sh
atem cred unlock
```

This also reconnects an already unlocked device to complete a pending
migration. `atem sync` alone does not contact Astation to finish the
transition. Let the command finish; if it is interrupted, run it again.
Astation commits a verified completion durably and supports retries, so the
CLI does not need to remain online after its completion message is accepted.

Field counts are progress information. For example, zero plaintext and zero
obsolete fields can still appear beside **Turning on** until Astation accepts
the authenticated completion. Confirm the final **On** or **Off** state in
Astation rather than relying on the counts or the CLI's connection status.

With encryption on, memory/skill/vault content is encrypted before reaching
the relay and project identities become keyed hashes. The relay still sees
routing identifiers and metadata, including timestamps and ciphertext sizes;
it cannot authorize a device or choose the encryption mode. Migration cannot
prove that a server erased old plaintext backups. Turning encryption off
migrates shared content to plaintext. The local `knowledge.db` remains
plaintext with mode 0600, and Astation's local credential Keychain is unchanged
by account-data encryption. See the [encryption design](../designs/e2e-encryption.md).

## Current availability

`atem status` and `atem cred unlock`, `lock` and `projects` are implemented. The
planned `atem cred get/list` service for retrieving values from Astation's
Credentials editor is not implemented. Use that editor on the Mac to add,
update, copy or delete its values with Touch ID. Memory and skills must contain
credential names only; the shared-notes vault is separate from this local
credential store.

See the [Astation credentials guide](https://github.com/Agora-Build/Astation/blob/main/docs/credentials.md)
and [encrypted reporting protocol](credential-project-reporting.md).
