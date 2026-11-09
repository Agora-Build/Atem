//! The skill file transport: the client's reader and writer against Astation's
//! transport vector (pinned at 89a2d50), Atem's synthetic vectors
//! (`designs/protocol/fixtures/skills-wire/`, see its README) and the fake
//! Station adapter (`fake_station_skills`).
use super::*;
use crate::memory::account_keys::{AccountKeys, CryptOp};
use crate::memory::crypto::{EncryptionContext, EncryptionMode};
use crate::memory::fake_astation::{ASTATION_ID, UnlockedDevice};
use crate::memory::fake_station_skills as station;
use crate::memory::model::skill_hash;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("designs/protocol/fixtures/skills-wire")
        .join(name);
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

/// A v2 row as the client reads it.
fn read(row: &Value) -> Result<Skill> {
    serde_json::from_value::<WireSkill>(row.clone())?.into_skill()
}

/// The stored (legacy) form of a skill: `Skill`'s own serde, what the old
/// wire carried and the Station keeps.
fn legacy(skill: &Skill) -> Value {
    serde_json::to_value(skill).unwrap()
}

/// What the Station stores for a v2 row (`Err` = it refuses the batch).
fn stored(row: &Value) -> std::result::Result<Value, &'static str> {
    let mut row = row.clone();
    station::normalize_files(&mut row).map(|()| row)
}

/// What the Station serves for a stored row.
fn served(stored: &Value) -> Value {
    let mut row = stored.clone();
    station::encode_row(&mut row);
    row
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// An `e1.` envelope made with a given nonce, as `account_keys::seal_field`
/// makes it with a random one: `e1.<kid>.<base64(nonce ‖ ciphertext)>`,
/// XChaCha20-Poly1305, associated data `"{record}\n{field}"`.
fn seal(key: &[u8], kid: &str, record: &str, field: &str, plain: &[u8], nonce: &[u8]) -> String {
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad = format!("{record}\n{field}");
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plain,
                aad: aad.as_bytes(),
            },
        )
        .unwrap();
    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&sealed);
    format!("e1.{kid}.{}", STANDARD.encode(payload))
}

/// Opens `envelope` with Atem's own field code (`AccountKeys::crypt`).
fn open(key: &[u8], kid: &str, record: &str, field: &str, envelope: &str) -> Vec<u8> {
    let mut keys = AccountKeys::default();
    keys.install(
        "synthetic-account",
        kid,
        zeroize::Zeroizing::new(key.try_into().unwrap()),
    );
    let mut out = keys
        .crypt(
            "synthetic-account",
            EncryptionMode::On,
            Some(kid),
            vec![CryptOp::open(record, field, envelope)],
        )
        .unwrap();
    out.remove(0).into_plain().unwrap().to_vec()
}

/// A structural envelope (not valid ciphertext) of `bytes` payload bytes.
fn shape(marker: u8, bytes: usize) -> String {
    format!("e1.0123abcd.{}", STANDARD.encode(vec![marker; bytes]))
}

// ─────────────── the client's own rules ───────────────

#[test]
fn an_envelope_is_e1_a_kid_and_at_least_a_nonce_and_a_tag() {
    assert!(is_envelope(&shape(1, 40)));
    assert!(is_envelope(&shape(1, 4096)));
    for value in [
        String::new(),
        "plaintext".into(),
        shape(1, 39),
        "e1.0123abcd.bad".into(),
        "e1.0123abcd.".into(),
        "e1.0123ABCD.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==".into(),
        "e1.0123abc.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==".into(),
        "e2.0123abcd.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==".into(),
        "h1.0123abcd.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==".into(),
        // Unpadded and non-canonical base64.
        "e1.0123abcd.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ".into(),
        "e1.0123abcd.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAR==".into(),
    ] {
        assert!(!is_envelope(&value), "{value:?}");
    }
}

#[test]
fn a_sealed_skill_is_never_sent_with_a_file_that_isnt_sealed() {
    let mut files = BTreeMap::from([(shape(1, 40), shape(2, 40).into_bytes())]);
    assert!(sealed_files(&files).is_ok());
    files.insert(shape(3, 40), Vec::new());
    assert!(sealed_files(&files).is_ok(), "an empty file stays empty");
    for (path, value) in [
        (shape(4, 40), b"plaintext".to_vec()),
        ("SKILL.md".to_string(), shape(5, 40).into_bytes()),
        (String::new(), Vec::new()),
        (shape(6, 40), vec![0xff, 0xfe]),
    ] {
        let mut bad = files.clone();
        bad.insert(path, value);
        let error = sealed_files(&bad).unwrap_err().to_string();
        assert!(error.contains(INVALID_ENCODING), "{error}");
        // The error never carries a value.
        assert!(!error.contains("plaintext"), "{error}");
    }
}

#[test]
fn plain_files_are_standard_padded_base64() {
    let files = BTreeMap::from([
        ("SKILL.md".to_string(), b"hello".to_vec()),
        ("asset.bin".to_string(), vec![0, 159, 146, 1]),
        ("empty.md".to_string(), Vec::new()),
    ]);
    assert_eq!(
        plain_files(&files),
        json!({"SKILL.md": "aGVsbG8=", "asset.bin": "AJ+SAQ==", "empty.md": ""})
    );
}

/// Ruling 2: the same sealed skill is the same stored row under both
/// encodings (what the old wire carried), and reads back as the same
/// bytes, so its hash, version and sequence don't change.
#[test]
fn the_same_skill_is_the_same_stored_row_and_hash_under_both_encodings() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, "0123abcd", [7; 32]);
    let context =
        EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone())
            .unwrap();
    let files = BTreeMap::from([
        (
            "SKILL.md".to_string(),
            b"# deploy\nrun the checks first\n".to_vec(),
        ),
        ("reference/notes.md".to_string(), vec![b'x'; 70_000]),
        ("asset.bin".to_string(), vec![0, 159, 146, 150, 255]),
        (".gitkeep".to_string(), Vec::new()),
    ]);
    let plain = Skill {
        scope: Scope::Global,
        project: String::new(),
        name: "deploy".into(),
        version: 3,
        content_hash: skill_hash(&files),
        files,
        source_agent: "cli".into(),
        source_machine: "m1".into(),
        created_at: 1_790_000_000,
        deleted: false,
        seq: 41,
    };
    let sealed = context.encrypt_skill(plain.clone()).unwrap();
    let v2 = sealed_skill(&sealed).unwrap();
    assert_eq!(v2["files_encoding"], "e1-text");
    // Stored: byte for byte what the old wire stored.
    assert_eq!(stored(&v2).unwrap(), legacy(&sealed));
    assert_eq!(
        serde_json::to_vec(&stored(&v2).unwrap()).unwrap(),
        serde_json::to_vec(&legacy(&sealed)).unwrap()
    );
    // Served back as e1-text and read as the same bytes.
    let back = served(&legacy(&sealed));
    assert_eq!(back, v2);
    let read_back = read(&back).unwrap();
    assert_eq!(read_back, sealed);
    let opened = context.decrypt_skill(read_back).unwrap();
    assert_eq!(opened, plain);
    assert_eq!(skill_hash(&opened.files), plain.content_hash);

    // Plain (the mode permits it): base64, the same stored row too.
    let row = plain_skill(&plain);
    assert_eq!(row["files_encoding"], "base64");
    assert_eq!(stored(&row).unwrap(), legacy(&plain));
    assert_eq!(read(&served(&legacy(&plain))).unwrap(), plain);
}

/// A tombstone (no files) is a valid row either way.
#[test]
fn a_tombstone_has_no_files_in_either_encoding() {
    let skill = Skill {
        scope: Scope::Global,
        project: String::new(),
        name: "gone".into(),
        version: 2,
        files: BTreeMap::new(),
        content_hash: String::new(),
        source_agent: "cli".into(),
        source_machine: "m1".into(),
        created_at: 1,
        deleted: true,
        seq: 9,
    };
    for row in [sealed_skill(&skill).unwrap(), plain_skill(&skill)] {
        assert_eq!(row["files"], json!({}));
        assert_eq!(stored(&row).unwrap(), legacy(&skill));
        assert_eq!(read(&row).unwrap(), skill);
    }
}

// ─────────────── Astation's vector (89a2d50) ───────────────

#[test]
fn astations_vector_maps_both_representations() {
    let vector = fixture("skill-file-wire.json");
    let cases = vector["cases"].as_array().unwrap();
    // A sealed row, and one with an empty file.
    assert_eq!(cases.len(), 2);
    for case in cases {
        let (wire, stored_row) = (&case["wire_skill"], &case["stored_skill"]);
        // The client reads the wire row as the bytes the stored row carries…
        let skill = read(wire).unwrap();
        assert_eq!(&legacy(&skill), stored_row);
        assert_eq!(
            serde_json::from_value::<Skill>(stored_row.clone()).unwrap(),
            skill
        );
        // …and writes the same skill as the wire row.
        assert_eq!(&sealed_skill(&skill).unwrap(), wire);
        // The fake Station agrees both ways.
        assert_eq!(&stored(wire).unwrap(), stored_row);
        assert_eq!(&served(stored_row), wire);
    }
}

// ─────────────── Atem's vectors ───────────────

#[test]
fn atems_envelope_vector_opens_and_maps_both_representations() {
    let vector = fixture("atem-envelope.json");
    let key = unhex(vector["key_hex"].as_str().unwrap());
    let kid = vector["kid"].as_str().unwrap();
    let record = vector["record"].as_str().unwrap();
    for part in ["path", "file"] {
        let part = &vector[part];
        let field = part["field"].as_str().unwrap();
        let plain = part["plain"].as_str().unwrap().as_bytes();
        let envelope = part["envelope"].as_str().unwrap();
        let nonce = unhex(part["nonce_hex"].as_str().unwrap());
        assert_eq!(seal(&key, kid, record, field, plain, &nonce), envelope);
        assert_eq!(open(&key, kid, record, field, envelope), plain);
        assert!(is_envelope(envelope));
        assert_eq!(
            part["legacy_base64"].as_str().unwrap(),
            STANDARD.encode(envelope)
        );
    }
    let path = vector["path"]["envelope"].as_str().unwrap();
    assert_eq!(vector["file"]["field"], format!("file:{path}"));
    for (stored_name, wire_name) in [
        ("stored_skill", "wire_skill"),
        ("empty_file_stored_skill", "empty_file_wire_skill"),
    ] {
        let (stored_row, wire) = (&vector[stored_name], &vector[wire_name]);
        let skill = read(wire).unwrap();
        assert_eq!(&legacy(&skill), stored_row, "{wire_name}");
        assert_eq!(&sealed_skill(&skill).unwrap(), wire, "{wire_name}");
        assert_eq!(&stored(wire).unwrap(), stored_row, "{wire_name}");
        assert_eq!(&served(stored_row), wire, "{wire_name}");
    }
}

/// The large file: built from the vector's description, sealed with its
/// nonces, then each representation's size against the raw file.
fn large_file(vector: &Value) -> (Vec<u8>, Skill) {
    let size = vector["file_bytes"].as_u64().unwrap() as usize;
    let line = vector["line"].as_str().unwrap().as_bytes();
    let file: Vec<u8> = line.iter().copied().cycle().take(size).collect();
    let key = unhex(vector["key_hex"].as_str().unwrap());
    let kid = vector["kid"].as_str().unwrap();
    let record = vector["record"].as_str().unwrap();
    let path = seal(
        &key,
        kid,
        record,
        "path",
        vector["path"].as_str().unwrap().as_bytes(),
        &unhex(vector["path_nonce_hex"].as_str().unwrap()),
    );
    let envelope = seal(
        &key,
        kid,
        record,
        &format!("file:{path}"),
        &file,
        &unhex(vector["file_nonce_hex"].as_str().unwrap()),
    );
    let mut skill: Skill = serde_json::from_value(vector["skill"].clone()).unwrap();
    skill.files = BTreeMap::from([(path, envelope.into_bytes())]);
    (file, skill)
}

#[test]
fn atems_large_file_vector_shows_the_wire_expansion() {
    let vector = fixture("atem-large-file.json");
    let (file, skill) = large_file(&vector);
    let envelope = skill.files.values().next().unwrap();
    let expect = |name: &str| vector["expect"][name].as_u64().unwrap() as usize;
    assert_eq!(
        hex(&Sha256::digest(envelope)),
        vector["expect"]["file_envelope_sha256"]
    );
    assert_eq!(envelope.len(), expect("e1_text_value_bytes"));
    assert_eq!(
        STANDARD.encode(envelope).len(),
        expect("legacy_value_bytes")
    );
    let v2 = serde_json::to_vec(&json!({"ops": [{"op": "push", "skill": sealed_skill(&skill).unwrap(), "base_version": 0}]}))
        .unwrap()
        .len();
    let old = serde_json::to_vec(
        &json!({"ops": [{"op": "push", "skill": legacy(&skill), "base_version": 0}]}),
    )
    .unwrap()
    .len();
    assert_eq!(
        (v2, old),
        (
            expect("push_body_e1_text_bytes"),
            expect("push_body_legacy_bytes")
        )
    );
    let raw = file.len() as f64;
    // About 1.33× instead of 1.78×, plus fixed overhead; the budget is 1.4×.
    assert!(
        envelope.len() as f64 / raw < 1.334,
        "{}",
        envelope.len() as f64 / raw
    );
    assert!((v2 as f64 / raw) < 1.4, "{}", v2 as f64 / raw);
    assert!((old as f64 / raw) > 1.77, "{}", old as f64 / raw);
}

#[test]
fn atems_row_vectors_are_read_and_stored_alike() {
    let vector = fixture("atem-rows.json");
    let cases = vector["cases"].as_array().unwrap();
    assert!(cases.len() >= 12);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let row = &case["row"];
        match case["expect"].as_str().unwrap() {
            "accept" => {
                let skill = read(row).unwrap_or_else(|e| panic!("{name}: {e:#}"));
                assert_eq!(legacy(&skill), case["stored"], "{name}");
                assert_eq!(stored(row).unwrap(), case["stored"], "{name}");
                // The fake Station serves the stored row as `row`, or (a
                // case's `served`) as another form of the same bytes.
                let served_row = case.get("served").unwrap_or(row);
                assert_eq!(&served(&case["stored"]), served_row, "{name}");
                assert_eq!(read(served_row).unwrap(), skill, "{name}");
            }
            "refuse" => {
                // The Station's refusal, and the client's of the same kind.
                let station_error = case["error"].as_str().unwrap();
                let kind = if station_error == station::UNSUPPORTED {
                    UNSUPPORTED_ENCODING
                } else {
                    INVALID_ENCODING
                };
                let error = read(row).expect_err(name);
                assert!(format!("{error:#}").contains(kind), "{name}: {error:#}");
                assert_eq!(stored(row), Err(station_error), "{name}");
            }
            other => panic!("{name}: unknown expectation {other}"),
        }
    }
}

// ─────────────── generating the vectors ───────────────

/// Prints Atem's vectors (`atem-envelope.json`, `atem-large-file.json`,
/// `atem-rows.json`): synthetic key and nonces, so the same every run.
/// `cargo test --bin atem print_skill_wire_vectors -- --ignored --nocapture`
#[test]
#[ignore]
fn print_skill_wire_vectors() {
    let key = [7u8; 32];
    let (kid, record) = ("0123abcd", "global:demo:1");
    let skill_row = |files: BTreeMap<String, Vec<u8>>| Skill {
        scope: Scope::Global,
        project: String::new(),
        name: "demo".into(),
        version: 1,
        files,
        content_hash: format!("h1.{kid}.{}", "a".repeat(64)),
        source_agent: "test".into(),
        source_machine: "synthetic".into(),
        created_at: 1_700_000_000,
        deleted: false,
        seq: 7,
    };
    let path_nonce = [0x11u8; 24];
    let file_nonce = [0x22u8; 24];
    let plain_file = "# demo\nA synthetic skill file.\n";
    let path = seal(&key, kid, record, "path", b"SKILL.md", &path_nonce);
    let file_field = format!("file:{path}");
    let file = seal(
        &key,
        kid,
        record,
        &file_field,
        plain_file.as_bytes(),
        &file_nonce,
    );
    let empty_path = seal(&key, kid, record, "path", b".gitkeep", &[0x33u8; 24]);
    let skill = skill_row(BTreeMap::from([(path.clone(), file.clone().into_bytes())]));
    let empty = skill_row(BTreeMap::from([
        (path.clone(), file.clone().into_bytes()),
        (empty_path, Vec::new()),
    ]));
    let envelope = json!({
        "description": "Atem's synthetic skill file transport vector: a real XChaCha20-Poly1305 e1 envelope under a synthetic key and fixed nonces, its legacy base64 form, and a skill row as it travels (wire) and as the Station stores it, also with an empty file.",
        "key_hex": hex(&key),
        "kid": kid,
        "record": record,
        "path": {"plain": "SKILL.md", "field": "path", "nonce_hex": hex(&path_nonce), "envelope": path, "legacy_base64": STANDARD.encode(&path)},
        "file": {"plain": plain_file, "field": file_field, "nonce_hex": hex(&file_nonce), "envelope": file, "legacy_base64": STANDARD.encode(&file)},
        "stored_skill": legacy(&skill),
        "wire_skill": sealed_skill(&skill).unwrap(),
        "empty_file_stored_skill": legacy(&empty),
        "empty_file_wire_skill": sealed_skill(&empty).unwrap(),
    });
    println!(
        "--- atem-envelope.json\n{}",
        serde_json::to_string_pretty(&envelope).unwrap()
    );

    let mut large = json!({
        "description": "A representative large skill file and its wire expansion: file_bytes bytes of `line` repeated, its path and file sealed under the synthetic key with the fixed nonces; the push bodies are one push op of `skill` with that file.",
        "key_hex": hex(&key),
        "kid": kid,
        "record": "global:large:1",
        "path": "reference/large.md",
        "path_nonce_hex": hex(&[0x44u8; 24]),
        "file_nonce_hex": hex(&[0x55u8; 24]),
        "file_bytes": 1 << 20,
        "line": "a sealed skill file travels as its e1 text, encoded only once.\n",
        "skill": legacy(&Skill { name: "large".into(), ..skill_row(BTreeMap::new()) }),
    });
    let (raw, sealed) = large_file(&large);
    let value = sealed.files.values().next().unwrap().clone();
    let body = |skill: Value| {
        serde_json::to_vec(&json!({"ops": [{"op": "push", "skill": skill, "base_version": 0}]}))
            .unwrap()
            .len()
    };
    let (v2, old) = (body(sealed_skill(&sealed).unwrap()), body(legacy(&sealed)));
    large["expect"] = json!({
        "file_envelope_sha256": hex(&Sha256::digest(&value)),
        "e1_text_value_bytes": value.len(),
        "legacy_value_bytes": STANDARD.encode(&value).len(),
        "push_body_e1_text_bytes": v2,
        "push_body_legacy_bytes": old,
        "ratio_e1_text_value": format!("{:.4}", value.len() as f64 / raw.len() as f64),
        "ratio_legacy_value": format!("{:.4}", STANDARD.encode(&value).len() as f64 / raw.len() as f64),
        "ratio_push_body_e1_text": format!("{:.4}", v2 as f64 / raw.len() as f64),
        "ratio_push_body_legacy": format!("{:.4}", old as f64 / raw.len() as f64),
    });
    println!(
        "--- atem-large-file.json\n{}",
        serde_json::to_string_pretty(&large).unwrap()
    );

    let base = |encoding: Option<&str>, files: Value| {
        let mut row = legacy(&skill_row(BTreeMap::new()));
        row["files"] = files;
        if let Some(encoding) = encoding {
            row["files_encoding"] = json!(encoding);
        }
        row
    };
    let accept = |name: &str, row: Value| {
        let stored = stored(&row).unwrap();
        json!({"name": name, "expect": "accept", "row": row, "stored": stored})
    };
    let refuse = |name: &str, row: Value| {
        let error = stored(&row).unwrap_err();
        json!({"name": name, "expect": "refuse", "row": row, "error": error})
    };
    let (p1, p2, f1) = (shape(1, 40), shape(3, 40), shape(2, 40));
    let cases = vec![
        accept(
            "e1-text: sealed paths and files",
            base(Some("e1-text"), json!({p1.clone(): f1.clone()})),
        ),
        accept(
            "e1-text: an empty file is \"\" (the empty-file rule)",
            base(
                Some("e1-text"),
                json!({p1.clone(): f1.clone(), p2.clone(): ""}),
            ),
        ),
        accept(
            "e1-text: a tombstone has no files",
            base(Some("e1-text"), json!({})),
        ),
        {
            // A sealed row with an empty file sent as `base64`: the same
            // bytes, which the Station serves as `e1-text`.
            let mut case = accept(
                "base64: a sealed row with an empty file",
                base(
                    Some("base64"),
                    json!({p1.clone(): STANDARD.encode(&f1), p2.clone(): ""}),
                ),
            );
            case["served"] = base(
                Some("e1-text"),
                json!({p1.clone(): f1.clone(), p2.clone(): ""}),
            );
            case
        },
        accept(
            "base64: a plain file",
            base(
                Some("base64"),
                json!({"SKILL.md": STANDARD.encode("# plain\n")}),
            ),
        ),
        accept(
            "base64: a binary file and an empty one",
            base(
                Some("base64"),
                json!({"asset.bin": STANDARD.encode([0u8, 159, 146, 255]), "empty.md": ""}),
            ),
        ),
        refuse(
            "no files_encoding",
            base(None, json!({p1.clone(): f1.clone()})),
        ),
        refuse(
            "an unknown files_encoding",
            base(Some("guess"), json!({p1.clone(): f1.clone()})),
        ),
        refuse("files_encoding not a string", {
            let mut row = base(None, json!({p1.clone(): f1.clone()}));
            row["files_encoding"] = json!(true);
            row
        }),
        refuse(
            "e1-text: a non-empty value that isn't sealed (mixed)",
            base(
                Some("e1-text"),
                json!({p1.clone(): f1.clone(), p2.clone(): "plaintext"}),
            ),
        ),
        refuse(
            "e1-text: a plain path (mixed)",
            base(
                Some("e1-text"),
                json!({p1.clone(): f1.clone(), "SKILL.md": f1.clone()}),
            ),
        ),
        refuse(
            "e1-text: an empty path",
            base(Some("e1-text"), json!({"": ""})),
        ),
        refuse(
            "e1-text: a malformed envelope",
            base(Some("e1-text"), json!({p1.clone(): "e1.0123abcd.bad"})),
        ),
        refuse(
            "e1-text: an envelope shorter than a nonce and a tag",
            base(Some("e1-text"), json!({p1.clone(): shape(2, 39)})),
        ),
        refuse(
            "e1-text: an uppercase kid",
            base(
                Some("e1-text"),
                json!({p1.clone(): f1.replace("0123abcd", "0123ABCD")}),
            ),
        ),
        refuse(
            "e1-text: base64 of an envelope (encoded twice)",
            base(Some("e1-text"), json!({p1.clone(): STANDARD.encode(&f1)})),
        ),
        refuse(
            "base64: invalid base64",
            base(Some("base64"), json!({"SKILL.md": "not base64!"})),
        ),
        refuse(
            "base64: unpadded base64",
            base(Some("base64"), json!({"SKILL.md": "aGVsbG8"})),
        ),
        refuse(
            "a file value that isn't a string",
            base(Some("base64"), json!({"SKILL.md": 5})),
        ),
    ];
    let rows = json!({
        "description": "Atem's synthetic skill rows: what the client and the Station accept (and store, in the legacy form) or refuse (`error`: the Station's 400). Envelopes are structural only, not valid ciphertext.",
        "cases": cases,
    });
    println!(
        "--- atem-rows.json\n{}",
        serde_json::to_string_pretty(&rows).unwrap()
    );
}
