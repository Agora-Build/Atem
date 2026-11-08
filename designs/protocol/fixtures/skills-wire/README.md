# Skill wire v2 vectors

Skill wire v2 is the Station's `/api/skills/v2` routes. A sealed skill file travels as the text of
its `e1.` envelope (`files_encoding: "e1-text"`). Before v2 it travelled as base64 of that text,
which encoded it twice. The change is F8 in [Atem #130](https://github.com/Agora-Build/Atem/issues/130).

The contract is Astation's `designs/protocol/skill-file-wire-v2.md` in
[Astation PR #76](https://github.com/Agora-Build/Astation/pull/76) (draft). Atem's client calls only
these routes; see `designs/e2e-encryption.md` "Skill files on the wire". These files sit in a
subdirectory because every top-level `*.json` in `designs/protocol/fixtures/` is an atem-session
scenario.

## `skill-file-wire-v2.json`: Astation's vector

This is Astation's transport vector, copied byte for byte. It is pinned to Astation commit
`963c74b813efc9926acf76c109fc0871da0925cf` (`designs/protocol/fixtures/skill-file-wire-v2.json`,
git blob `67a98aa7ea68bd19170dd26eeda3f7556f7bfe44`, SHA-256
`0b87014bc0b784a316555620e09e82a63c06b9a381918118df47e4d3a20e3440`). Its payloads are structural
only: they are not valid ciphertext.

Don't edit this file. To move the pin:
1. Copy the file from Astation's new commit.
2. Update the commit and hashes above.

Test: `astations_vector_maps_both_representations` (`src/memory/skill_wire_tests.rs`). It checks,
both ways, that:
- the client's reader turns `v2_skill` into the bytes `legacy_skill` carries;
- the client's writer turns those bytes back into `v2_skill`;
- the fake Station adapter (`src/memory/fake_station_skills.rs`) does the same.

## Atem's vectors

These are public synthetic vectors for what Astation's vector doesn't cover. The key is
`07` × 32 under kid `0123abcd`, the nonces are fixed, and no file holds account material.
`print_skill_wire_vectors` (an ignored test in the same file) prints all three, the same every run:

    cargo test --bin atem print_skill_wire_vectors -- --ignored --nocapture

- **`atem-envelope.json`**: a real XChaCha20-Poly1305 `e1.` envelope for a skill path and for its
  file. Each comes with its plain text, field, nonce and legacy base64 form, and the file's
  associated data names the sealed path (`file:<sealed path>`). It also has a skill row in both
  representations (`legacy_skill` and `v2_skill`), and the same row with an empty file
  (`empty_file_*`).
  - Test: `atems_envelope_vector_opens_and_maps_both_representations`.
  - The test seals each envelope again and opens it with Atem's own field code
    (`AccountKeys::crypt`), then maps the rows both ways through the client and the fake Station.
- **`atem-large-file.json`**: a representative large file, 1 MiB of one ASCII line repeated, sealed
  as above.
  - It records the envelope's SHA-256, the file value's size in each representation and one push
    body in each. Sizes against the raw file:

    | | v2 (`e1-text`) | legacy (base64 of the e1 text) |
    |---|---|---|
    | file value | 1.3334× | 1.7779× |
    | push body | 1.3338× | 1.7783× |

    The push body adds a fixed overhead (envelope, path, JSON) to the value. The budget is
    "skill files at most 1.4× raw on the wire".
  - Test: `atems_large_file_vector_shows_the_wire_expansion`.
- **`atem-rows.json`**: rows the client and the Station both accept (with the stored legacy form)
  or both refuse (`invalid skill files encoding`). The cases are:
  - missing, unknown and non-string encodings;
  - malformed, short, uppercase-kid and twice-encoded envelopes;
  - mixed plain and sealed entries, an empty path, and non-string values;
  - invalid or unpadded base64;
  - tombstones, plain and binary `base64` rows.

  Test: `atems_row_vectors_are_read_and_stored_alike`.

## The empty-file rule (pending Astation's next pin)

An empty skill file is never sealed: its value stays `""`, with no `Crypt` op and no associated
data. In an `e1-text` row, each value is either a sealed envelope or `""`. An envelope is never
empty, and base64 of nothing is nothing, so the stored row, its version, sequence and hashes are the
same as under the legacy wire. `""` is the only value allowed that isn't an envelope, and mixed
plain and sealed entries are still refused.

The owner chose this rule on Atem #130 and asked Astation for it. Astation's adapter at
`963c74b` refuses `""` in an `e1-text` row (`normalize_files` calls `envelope_kid` on every value),
and on reads it serves such rows as `base64`. Until Astation pins the rule:
- a sealed skill with an empty file, such as a `.gitkeep`, is refused by that adapter;
- the `empty_file_*` rows of `atem-envelope.json` and the matching case of `atem-rows.json` hold
  only against Atem's fake Station, which implements the rule.

When Astation's vector covers the rule, import it as above.
