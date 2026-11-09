# Skill file transport vectors

These vectors cover the skill file transport on the Station's skill routes (`/api/skills`,
`/api/skills/batch`, `/api/skills/versions`, `/api/skills/version`).
- A sealed skill file travels as the text of its `e1.` envelope (`files_encoding: "e1-text"`), and
  an empty file travels as `""`.
- Before this change, a sealed file travelled as base64 of that text, which encoded it twice. The
  change is F8 in [Atem #130](https://github.com/Agora-Build/Atem/issues/130).

The contract is Astation's `designs/protocol/skill-file-wire.md` in
[Astation PR #76](https://github.com/Agora-Build/Astation/pull/76), pinned at commit
`89a2d508bc5a0df3d4fdb85410d65682ce9bba1e`.
- The owner's decision: one set of routes, no `wire_version`, no compatibility path or fallback.
- A missing, unknown or non-string `files_encoding` is refused with 400 `unsupported skill files
  encoding; update Atem`.
- Malformed files are refused with 400 `invalid skill files encoding`.

See `designs/e2e-encryption.md` "Skill files on the wire". These files sit in a subdirectory because
every top-level `*.json` in `designs/protocol/fixtures/` is an atem-session scenario.

## `skill-file-wire.json`: Astation's vector

This is Astation's transport vector, copied byte for byte from commit
`89a2d508bc5a0df3d4fdb85410d65682ce9bba1e` (`designs/protocol/fixtures/skill-file-wire.json`, git
blob `8e5a3296b4829d739c6eaeb47030fda827a870bb`, SHA-256
`ceef7e9e428966d66e480272dd271e4ee547867a225e9fb5ec5dba109c8649b4`).
- It has two cases: a sealed row, and a sealed row with an empty file.
- Each case gives the row as it travels (`wire_skill`) and as the Station stores it
  (`stored_skill`).
- Its payloads are structural only: they are not valid ciphertext.

Don't edit this file. To move the pin:
1. Copy the file from Astation's new commit.
2. Update the commit and hashes above.

Test: `astations_vector_maps_both_representations` (`src/memory/skill_wire_tests.rs`). It checks,
both ways, that:
- the client's reader turns each `wire_skill` into the bytes its `stored_skill` carries;
- the client's writer turns those bytes back into `wire_skill`;
- the fake Station (`src/memory/fake_station_skills.rs`) does the same.

## Atem's vectors

These are public synthetic vectors for what Astation's vector doesn't cover. The key is
`07` × 32 under kid `0123abcd`, the nonces are fixed, and no file holds account material.
`print_skill_wire_vectors` (an ignored test in the same file) prints all three, the same every run:

    cargo test --bin atem print_skill_wire_vectors -- --ignored --nocapture

- **`atem-envelope.json`**: a real XChaCha20-Poly1305 `e1.` envelope for a skill path and for its
  file. Each comes with its plain text, field, nonce and legacy base64 form, and the file's
  associated data names the sealed path (`file:<sealed path>`). It also has a skill row as it
  travels and as it is stored (`wire_skill`, `stored_skill`), and the same row with an empty file
  (`empty_file_*`).
  - Test: `atems_envelope_vector_opens_and_maps_both_representations`.
  - The test seals each envelope again and opens it with Atem's own field code
    (`AccountKeys::crypt`), then maps the rows both ways through the client and the fake Station.
- **`atem-large-file.json`**: a representative large file, 1 MiB of one ASCII line repeated, sealed
  as above.
  - It records the envelope's SHA-256, the file value's size in each representation and one push
    body in each. Sizes against the raw file:

    | | `e1-text` | legacy (base64 of the e1 text) |
    |---|---|---|
    | file value | 1.3334× | 1.7779× |
    | push body | 1.3338× | 1.7783× |

    The push body adds a fixed overhead (envelope, path, JSON) to the value. The budget is
    "skill files at most 1.4× raw on the wire".
  - Test: `atems_large_file_vector_shows_the_wire_expansion`.
- **`atem-rows.json`**: rows the client and the Station both accept, with the stored legacy form,
  or both refuse, with the Station's 400 in `error`.
  - An accepted case with `served` is one the fake Station serves in another form of the same
    bytes.
  - Unsupported encodings: missing, unknown or non-string `files_encoding`.
  - Invalid files:
    - malformed, short, uppercase-kid and twice-encoded envelopes;
    - mixed plain and sealed entries, an empty path, and non-string values;
    - invalid or unpadded base64.
  - Accepted rows:
    - sealed rows, and the empty-file row;
    - tombstones, plain and binary `base64` rows;
    - a sealed row with an empty file sent as `base64`, served back as `e1-text`.

  Test: `atems_row_vectors_are_read_and_stored_alike`. The client's error is of the same kind as
  the Station's.

## The empty-file rule

An empty skill file is never sealed: its value stays `""`, with no `Crypt` op and no associated
data. In an `e1-text` row, each value is either a sealed envelope or exactly `""`, and the filename
must still be a sealed envelope. An envelope is never empty, and base64 of nothing is nothing, so
the stored row, its version, sequence and hashes are the same as under the legacy wire. This rule is
part of the contract at 89a2d50. Astation's vector has the row, and so do Atem's `empty_file_*`
vectors and the matching row case.
