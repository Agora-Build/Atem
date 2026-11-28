#!/usr/bin/env python3
"""Independent check of the r9 vectors (session-v1 R9.12).

Recomputes and verifies, with Python's standard library and the
`cryptography` package only (no code of this repository), the cryptographic
values `crates/atem-client` computed for the r9 vector files: canonical
JSON (RFC 8785 for the subset the vectors use: objects, arrays, strings,
integers, booleans), `enc` (a 4-byte big-endian length before every field),
hashes, key derivations, every Ed25519 and P-256 signature (P-256 as
64-byte r||s, low S required), a host's `enc_sig` included, and the sealed
parts of the push hints and of the envelopes and results between hosts
(RFC 9180 base mode, written here: opened, and sealed again from the
ephemeral to the same bytes). It derives no verifier's verdict, but for
`r9-vectors-host-envelope`, whose every check's verdict and reason it
derives from the bytes, and `r9-vectors-host-route`'s refusals across the
two kinds of proof (relay and proxy), which follow from a proof's type and
signature, and its relay replies and `service_suspended` notices, read with
readers written here from R9.7b and the delegated host-work design III.5,
the device list and the receiver (II.4.2's checks 1
to 6 and II.4.4's, written here from host-work-v1 §11.5), and
`r9-vectors-mailbox-calls`, whose refusal codes and scenario outcomes,
answers and states it derives with readers and a model of the Station's
mailbox written here from host-work-v1 §11.5 ("The mailbox calls"), not
from the shared core's reference mailbox, and
`r9-vectors-verifier-report`, whose every challenge reading, report code
(in the agreed order) or verified fields, builder outcome and request
finish it derives from that file's rules (session-v1 R9.2, Astation #101),
and `r9-vectors-signer-report`, the same for a native manager's signer
report, its exported records read with a control-record reader written
here and its set hashes recomputed from the journal's bodies (host-work-v1
§11.1 "The signer report", Astation #114), and
`r9-vectors-station-binding`, the same for a native manager's Station
binding proof (delegated host-work III.5 (b); its orders Atem's proposal,
#120 comment 7207827118, agreed with Astation, Atem #210 comment
7209922243), Astation's three
posted examples included (their digests and both signatures).
The other files'
`expect` and each `reason` are checked by the Rust runner
(`crates/atem-client/tests/vectors.rs`) and the binding suites.
It also recomputes every Station report id of the acknowledgment fixtures
(`r9-control-ack-*`, host-work-v1 §11.4): the known answers of the
reference ledger's `report_id`, and derives their `expect_counts` (the
ledger's counts) and their reports (every report each step makes, in
order, a final's `not_before` included, what the Station sends at each
`expect_report`, and each `expect_start`: a revocation's start from the
own revoke's `revoked_at_ms` or `issued_at`, lowered by every learned
date) from the steps; from host-work-v1 §11.1 ("Resets"), the
snapshot checker's answers and the stops in force of
`r9-vectors-host-work-control`'s `snapshots` (each record's verdict taken
from its `checks`, as the bound and O1 take each step's result); and, from host-work-v1 §4 and §11.2, the
verdicts of `host-work/requests-v1`'s requests that name a task (the
owner's ops naming a host sender's selector task among them), of its `work`
and `reply` results and of its `answers` correlation.

Usage: python3 -I scripts/check-r9-vectors.py designs/protocol/fixtures

Prints one line per case and exits non-zero on any mismatch. Each vectors
file has its own checker in CHECKERS; a file without one isn't checked here
yet (`crates/atem-client/tests/vectors.rs` runs every file or names its
runner: `r9-vectors-required-verifier`, which holds no cryptographic value,
runs in `crates/atem-client/tests/required_verifier.rs`).
"""

import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ED25519_P = 2**255 - 19
MAX_BODY_BYTES = 4096


# ------------------------------------------------------------------ encoding


class NotStrict(ValueError):
    pass


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise NotStrict(f"duplicate key {key!r}")
        out[key] = value
    return out


def _no_float(text):
    raise NotStrict(f"not an integer: {text}")


def _no_constant(text):
    raise NotStrict(f"not JSON: {text}")


def load_strict(path):
    """Strict I-JSON: no duplicate keys, integers only, no NaN/Infinity."""
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_no_duplicates,
        parse_float=_no_float,
        parse_constant=_no_constant,
    )


def _jcs_string(text):
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value):
    """RFC 8785 for objects, arrays, strings, integers and booleans; `null`
    and non-integers are refused (strict I-JSON, R9.1)."""
    if value is None:
        raise NotStrict("null")
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise NotStrict(f"integer out of range: {value}")
        return str(value)
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(value[k]) for k in keys) + "}"
    raise NotStrict(f"not in the canonical domain: {type(value).__name__}")


def enc(fields):
    out = bytearray()
    for field in fields:
        if isinstance(field, str):
            field = field.encode("utf-8")
        out += len(field).to_bytes(4, "big") + field
    return bytes(out)


def u64(n):
    return n.to_bytes(8, "big")


def sha256(data):
    return hashlib.sha256(data).digest()


def b64u_decode(text):
    """Base64url without padding, strictly (R9.1)."""
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError(f"not base64url: {text!r}")
    if len(text) % 4 == 1:
        raise ValueError(f"bad base64url length: {text!r}")
    import base64

    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != text:
        raise ValueError(f"non-canonical base64url: {text!r}")
    return raw


def unhex(text):
    if not re.fullmatch(r"(?:[0-9a-f]{2})*", text):
        raise ValueError(f"not lowercase hex: {text!r}")
    return bytes.fromhex(text)


# ---------------------------------------------------------------------- keys


def ed25519_public(seed):
    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def x25519_public(secret):
    return (
        x25519.X25519PrivateKey.from_private_bytes(secret)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def p256_public(secret):
    key = ec.derive_private_key(int.from_bytes(secret, "big"), ec.SECP256R1())
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def ed25519_to_x25519(public):
    """The Montgomery u of an Edwards point: u = (1 + y) / (1 - y) mod p."""
    y = int.from_bytes(public, "little") & ((1 << 255) - 1)
    u = (1 + y) * pow((1 - y) % ED25519_P, ED25519_P - 2, ED25519_P) % ED25519_P
    return u.to_bytes(32, "little")


def hkdf32(ikm, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info.encode()).derive(ikm)


def test_key(label):
    """secret = SHA-256(enc(["atem-r9-test-key", label])) (schema.md)."""
    return sha256(enc(["atem-r9-test-key", label]))


def enc_kid(public):
    """R9.9's enc_kid: the first 8 bytes of SHA-256(enc(["atem-enc-kid-v1", pub]))."""
    return sha256(enc(["atem-enc-kid-v1", public]))[:8].hex()


def verify(alg, public, signature, message):
    """True when the signature verifies (P-256: 64-byte r||s, low S only)."""
    if alg == "ed25519":
        if len(public) != 32 or len(signature) != 64:
            return False
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
            return True
        except InvalidSignature:
            return False
    if alg == "p256":
        if len(public) != 65 or len(signature) != 64:
            return False
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        if not (0 < r < P256_N and 0 < s <= P256_N // 2):
            return False
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
        try:
            key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
    raise ValueError(f"no signatures with {alg}")


# -------------------------------------------------------------------- report


class Report:
    def __init__(self):
        self.cases = 0
        self.failures = 0

    def case(self, file, name):
        return Case(self, file, name)


class Case:
    """One line of output: what was checked, or what didn't match."""

    def __init__(self, report, file, name):
        self.report, self.file, self.name = report, file, name
        self.done, self.bad = [], []

    def check(self, ok, what, why=""):
        if ok:
            self.done.append(what)
        else:
            self.bad.append(f"{what}{': ' + why if why else ''}")
        return ok

    def equal(self, got, want, what):
        return self.check(got == want, what, f"got {got!r}, want {want!r}")

    def fail(self, why):
        self.bad.append(why)

    def __enter__(self):
        return self

    def __exit__(self, kind, error, _tb):
        if error is not None:
            self.bad.append(f"{kind.__name__}: {error}")
        self.report.cases += 1
        if self.bad:
            self.report.failures += 1
            print(f"FAIL {self.file} {self.name}: " + "; ".join(self.bad))
        else:
            print(f"ok   {self.file} {self.name}: " + ", ".join(self.done))
        return True


# --------------------------------------------------------- r9-vectors-keys

# The published labels (schema.md): `<name>/<part>` -> label.
KEY_LABELS = {
    "dev-evil/auth": "dev-evil auth",
    "dev-evil/enc": "dev-evil enc",
    "dev-ipad/auth": "dev-ipad auth",
    "dev-ipad/enc": "dev-ipad enc",
    "dev-mac/auth": "dev-mac auth",
    "dev-mac/enc": "dev-mac enc",
    "dev-newmac/auth": "dev-newmac auth",
    "dev-newmac/enc": "dev-newmac enc",
    "dev-phone/auth": "dev-phone auth",
    "dev-phone/enc": "dev-phone enc",
    "host-a/host_key": "host-a host_channel_key",
    "host-evil/host_key": "host-evil host_key",
    "svc-discord/auth": "svc-discord auth",
    "browser/": "browser key",
    "K-gen-3/": "K-gen-3",
    "K-evil/": "K-evil",
    "not-recovery/": "not the recovery key",
    # The verifier-report vectors' Ed25519 native (R9.2).
    "dev-desk/auth": "dev-desk auth",
    "dev-desk/enc": "dev-desk enc",
    "recovery/R": "recovery kit R",
    "recovery-2/R": "recovery-kit-2",
    # The delegated host-work actions (II.2.2, II.3.1, II.4.1).
    "host-a-enc-1/enc": "host-a host_enc_key 1",
    "host-a-enc-2/enc": "host-a host_enc_key 2",
    "host-a-enc-3/enc": "host-a host_enc_key 3",
    "host-a-gen-2/host_key": "host-a host_channel_key gen 2",
    "host-a-gen-3/host_key": "host-a host_channel_key gen 3",
    "host-b/host_key": "host-b host_channel_key",
    "host-b-enc-1/enc": "host-b host_enc_key 1",
    "host-b-enc-2/enc": "host-b host_enc_key 2",
    "host-b-gen-2/host_key": "host-b host_channel_key gen 2",
}


class Keys:
    """The test keys by name and part, and every public key by its bytes."""

    def __init__(self, keys):
        self.keys = keys
        self.by_public = {}
        for name, entry in keys.items():
            if name == "note":
                continue
            for part in ("auth", "enc", "host_key"):
                if part in entry:
                    self.by_public[unhex(entry[part]["pub_hex"])] = f"{name}/{part}"
            if "pub_hex" in entry:
                self.by_public[unhex(entry["pub_hex"])] = f"{name}/"
            if "sign_pub_hex" in entry:
                self.by_public[unhex(entry["sign_pub_hex"])] = f"{name}/sign"

    def public(self, name, part):
        entry = self.keys[name]
        if part == "sign":
            return unhex(entry["sign_pub_hex"])
        return unhex(entry[part]["pub_hex"])

    def name_of(self, public):
        return self.by_public.get(public)


def check_keys(file, data, report, context):
    keys = data["keys"]
    context["keys"] = Keys(keys)
    labels = dict(KEY_LABELS)
    for name, entry in keys.items():
        if name == "note":
            continue
        with report.case(file, name) as case:
            if "R_hex" in entry:
                r = unhex(entry["R_hex"])
                seed = hkdf32(r, "atem-recovery-sign-v1")
                case.equal(seed.hex(), entry["sign_seed_hex"], "sign_seed = HKDF(R)")
                case.equal(ed25519_public(seed).hex(), entry["sign_pub_hex"], "recovery key")
                x_secret = hashlib.sha512(seed).digest()[:32]
                case.equal(x_secret.hex(), entry["x25519_secret_hex"], "X25519 secret")
                case.equal(x25519_public(x_secret).hex(), entry["x25519_pub_hex"], "X25519 public")
                case.equal(
                    ed25519_to_x25519(unhex(entry["sign_pub_hex"])).hex(),
                    entry["x25519_pub_hex"],
                    "Montgomery form of the recovery key",
                )
                genesis = context.get("genesis_hash")
                if genesis is not None:
                    tag = hmac.new(
                        hkdf32(r, "atem-recovery-kit-tag-v1"),
                        enc(["atem-recovery-kit-v2", "acct-test-1", genesis]),
                        hashlib.sha256,
                    ).digest()[:16]
                    case.equal(tag.hex(), entry["kit_tag_hex"], "kit_tag")
                label = labels.get(f"{name}/R")
                if label is not None:
                    case.equal(test_key(label).hex(), entry["R_hex"], f"R from label {label!r}")
                continue
            parts = [(p, entry[p]) for p in ("auth", "enc", "host_key") if p in entry]
            if "secret_hex" in entry:
                parts.append(("", entry))
            case.check(bool(parts), "has a key")
            for part, key in parts:
                secret = unhex(key["secret_hex"])
                alg = key.get("alg", "x25519" if part == "enc" else None)
                if alg == "p256":
                    case.equal(p256_public(secret).hex(), key["pub_hex"], f"{part or name} p256 public")
                elif alg == "ed25519":
                    case.equal(ed25519_public(secret).hex(), key["pub_hex"], f"{part or name} ed25519 public")
                elif alg == "x25519":
                    case.equal(x25519_public(secret).hex(), key["pub_hex"], f"{part} x25519 public")
                else:
                    case.equal(len(key.get("kid", "")), 8, "an account key K: an 8-character kid")
                label = labels.get(f"{name}/{part}")
                if label is not None:
                    case.equal(test_key(label).hex(), key["secret_hex"], f"secret from label {label!r}")
                    note = entry.get("note", "")
                    if "label" in note:
                        case.check(f'"{label}"' in note, "label published in its note")


# ----------------------------------------------- r9-vectors-membership-log

# Arrays of signed entries (R9.2 "Arrays"): set paths (sorted by bytes, no
# duplicates) and sequence paths (no duplicates, never reordered).
SET_PATHS = {
    ("member", "roles"),
    ("roles",),
    ("member", "scope", "hosts"),
    ("member", "scope", "projects"),
    ("member", "scope", "sessions"),
    ("member", "scope", "ops"),
    ("scope", "hosts"),
    ("scope", "projects"),
    ("scope", "sessions"),
    ("scope", "ops"),
    ("project", "hosts"),
    ("project", "ops"),
}
SEQUENCE_PATHS = {("k_backup", "kids")}

# Signatures that must NOT verify with the key the chain names for their
# signer: a corrupted signature, a body signed by another Ed25519 key, and a
# recovery_add signed by the replaced recovery key (kit 1 after K7_current).
BAD_SIGNATURES = {
    "X8_badsig": "the signature is corrupted",
    "R7_wrong_key": "signed by another Ed25519 key",
    "R8_oldkit": "signed by the replaced recovery key",
}


def check_arrays(case, value, path=(), out_of_order=None):
    """Every array is at a set or sequence path and canonical for it. With
    `out_of_order` (a vector refused `array_not_canonical`), a set out of
    order is collected there instead of failing."""
    if isinstance(value, dict):
        for key, inner in value.items():
            check_arrays(case, inner, path + (key,), out_of_order)
    elif isinstance(value, list):
        if path in SET_PATHS:
            raw = [v.encode() for v in value]
            canonical = raw == sorted(set(raw))
            if out_of_order is None:
                case.check(canonical, f"{'.'.join(path)} a canonical set")
            elif not canonical:
                out_of_order.append(".".join(path))
        elif path in SEQUENCE_PATHS:
            case.check(len(value) == len(set(value)), f"{'.'.join(path)} without duplicates")
        else:
            case.fail(f"{'.'.join(path)}: no array is allowed there")
        for inner in value:
            check_arrays(case, inner, path + ("[]",), out_of_order)


def host_key_name(host_id, host_trust_gen):
    return host_id if host_trust_gen == 1 else f"{host_id}-gen-{host_trust_gen}"


class Replay:
    """The keys a chain names, replayed from its genesis: members' keys, the
    current recovery key (a `kit: "current"` replacement takes effect at
    once, a `kit: "lost"` one is still pending), and hosts' keys by
    generation. Authority (roles, removals, waits) is the verifier's."""

    def __init__(self, bodies):
        self.members, self.hosts, self.recovery = {}, {}, None
        for body in bodies:
            action = body["action"]
            if action in ("genesis", "add", "recovery_add"):
                member = body["member"]
                self.members[member["device_id"]] = member["auth_key"]
            if action == "genesis":
                self.recovery = body["recovery_key"]
            if action == "set_recovery_key" and body["kit"] == "current":
                self.recovery = body["recovery_key"]
            if action == "add_host":
                host = body["host"]
                self.hosts[(host["host_id"], host["host_trust_gen"])] = host["host_key"]

    def signer_key(self, signer):
        return self.recovery if signer == "recovery" else self.members.get(signer)


def check_membership_log(file, data, report, context):
    keys = context["keys"]
    context["membership_log"] = data
    vectors = data["log"] + data["others"]
    by_label = {}
    by_hash = {}
    for vector in vectors:
        label = vector["label"]
        if label in by_label:
            with report.case(file, label) as case:
                case.fail("label used twice")
        by_label[label] = vector
        by_hash.setdefault(vector["entry_hash"], vector)
    genesis_hash = data["genesis_hash"]
    context["genesis_hash"] = unhex(genesis_hash)
    geneses = {v["entry_hash"] for v in vectors if v["entry"]["body"]["action"] == "genesis"}
    log_labels = [v["label"] for v in data["log"]]

    def ancestry(body):
        """The bodies before `body`, genesis first (through prev_hash)."""
        chain = []
        while body["seq"] > 1:
            prev = by_hash.get(body["prev_hash"])
            if prev is None or prev["entry"]["body"]["seq"] != body["seq"] - 1:
                raise ValueError(f"prev_hash {body['prev_hash'][:12]}… names no entry at seq {body['seq'] - 1}")
            body = prev["entry"]["body"]
            chain.append(body)
        return list(reversed(chain))

    for vector in vectors:
        label = vector["label"]
        with report.case(file, label) as case:
            wire = vector["entry"]
            case.check(set(wire) <= {"body", "sig", "kit_sig"} and {"body", "sig"} <= set(wire), "wire {body, sig[, kit_sig]}")
            body = wire["body"]
            case.equal((body.get("type"), body.get("v")), ("atem-membership-entry", 1), "type and v")
            case.equal(body["account_id"], data["account_id"], "account_id")
            text = jcs(body)
            if "jcs" in vector:
                case.equal(text, vector["jcs"], "jcs")
            else:
                case.check(True, "jcs computed")
            case.check(len(text.encode()) <= MAX_BODY_BYTES, "body within 4096 bytes")
            if vector.get("reason") == "array_not_canonical":
                out_of_order = []
                check_arrays(case, body, out_of_order=out_of_order)
                case.check(bool(out_of_order), f"{', '.join(out_of_order) or 'no set'} out of order (array_not_canonical)")
            else:
                check_arrays(case, body)
            signing_input = enc(["atem-membership-entry-v1", text])
            if "signing_input_hex" in vector:
                case.equal(signing_input.hex(), vector["signing_input_hex"], "signing input")
            case.equal(sha256(enc(["atem-membership-hash-v1", text])).hex(), vector["entry_hash"], "entry_hash")

            # Where it sits: genesis, or after an entry of the file.
            if body["action"] == "genesis":
                case.check("genesis_hash" not in body and body["seq"] == 1 and body["prev_hash"] == "0" * 64, "genesis position")
            else:
                case.check(body.get("genesis_hash") in geneses, "genesis_hash names a genesis of the file")
            before = ancestry(body)
            if before:
                case.equal(before[0].get("genesis_hash"), None, "chains back to a genesis")
                genesis_body = before[0]
                case.equal(
                    sha256(enc(["atem-membership-hash-v1", jcs(genesis_body)])).hex(),
                    body.get("genesis_hash"),
                    "chains back to its genesis_hash",
                )
            if "chain" in vector:
                labels = log_labels + vector["chain"]
                for index, (a, b) in enumerate(zip(labels, labels[1:])):
                    if by_label[b]["entry"]["body"]["prev_hash"] != by_label[a]["entry_hash"]:
                        case.fail(f"chain: {b} doesn't follow {a}")
                case.equal(body["prev_hash"], by_label[labels[-1]]["entry_hash"], "follows L + chain")
                case.equal(body["seq"], len(labels) + 1, "seq after L + chain")
            replay = Replay(before)

            # The keys it carries are test keys.
            carried = []
            if "member" in body:
                carried.append((body["member"]["auth_key"], body["member"]["device_id"] + "/auth"))
                if "enc_key" in body["member"]:
                    carried.append((body["member"]["enc_key"], body["member"]["device_id"] + "/enc"))
            if "host" in body:
                host = body["host"]
                expected = f"{host_key_name(host['host_id'], host['host_trust_gen'])}/host_key"
                carried.append((host["host_key"], expected))
            if body["action"] == "host_enc_key":
                carried.append((body["enc_key"], None))
            for key in ("recovery_key",):
                if key in body:
                    carried.append((body[key], None))
            for key, expected in carried:
                name = keys.name_of(b64u_decode(key["pub"]))
                case.check(name is not None, f"{key['alg']} key is a test key ({name})")
                # A device or host with keys of its own in r9-vectors-keys
                # carries them in log L's chain (others reuse, e.g., dev-evil's).
                own = expected is not None and expected.split("/")[0] in keys.keys
                if own and body.get("genesis_hash", vector["entry_hash"]) == genesis_hash:
                    case.equal(name, expected, "the key of its device or host")

            # The signature, with the key the chain names for the signer.
            signer_key = replay.signer_key(body["signer"]) if body["action"] != "genesis" else body["member"]["auth_key"]
            if signer_key is None:
                case.fail(f"no key for signer {body['signer']}")
            else:
                ok = verify(signer_key["alg"], b64u_decode(signer_key["pub"]), b64u_decode(wire["sig"]), signing_input)
                if label in BAD_SIGNATURES:
                    case.check(not ok, f"{signer_key['alg']} signature refused ({BAD_SIGNATURES[label]})")
                    case.equal(vector.get("valid"), False, "valid: false")
                else:
                    case.check(ok, f"{signer_key['alg']} signature by {body['signer']}")
            if label == "R8_oldkit":
                case.check(
                    verify("ed25519", keys.public("recovery", "sign"), b64u_decode(wire["sig"]), signing_input),
                    "it verifies with kit 1's key",
                )
            if label == "E7_retry":
                case.check(wire["sig"] != by_label["E7"]["entry"]["sig"], "another signature than E7's")
                case.equal(vector["entry_hash"], by_label["E7"]["entry_hash"], "the same entry as E7")

            # The recovery key's co-signature (R9.5).
            if "kit_sig" in wire:
                cosign_input = enc(["atem-recovery-cosign-v1", text])
                case.equal(cosign_input.hex(), vector.get("kit_signing_input_hex"), "kit signing input")
                case.check(
                    body["action"] == "set_recovery_key" and body["kit"] == "current", "kit_sig only on kit current"
                )
                case.check(
                    verify("ed25519", b64u_decode(replay.recovery["pub"]), b64u_decode(wire["kit_sig"]), cosign_input),
                    "kit_sig by the current recovery key",
                )

            # The host's enc_sig over its encryption key (II.4.1), wherever
            # the binding's own fields parse (`enc_sig_input_hex` given).
            if body["action"] == "host_enc_key" and "enc_sig_input_hex" not in vector:
                gen = body["host_trust_gen"]
                broken = (
                    not isinstance(gen, int)
                    or gen < 1
                    or body["enc_key"].get("alg") != "x25519"
                    or len(b64u_decode(body["enc_key"]["pub"])) != 32
                    or len(b64u_decode(body["enc_sig"])) != 64
                )
                case.check(broken, "no enc_sig input: its binding's fields don't parse")
                case.check(vector.get("reason") in ("malformed", "wrong_alg"), "refused for the binding's shape")
            elif body["action"] == "host_enc_key":
                enc_pub = b64u_decode(body["enc_key"]["pub"])
                enc_input = enc(
                    [
                        "atem-host-enc-key-v1",
                        body["account_id"],
                        unhex(body["genesis_hash"]),
                        body["host_id"],
                        u64(body["host_trust_gen"]),
                        enc_pub,
                    ]
                )
                case.equal(enc_input.hex(), vector.get("enc_sig_input_hex"), "enc_sig input")
                host_key = replay.hosts.get((body["host_id"], body["host_trust_gen"]))
                if host_key is not None:
                    host_pub = b64u_decode(host_key["pub"])
                else:  # the host isn't in the chain: its test key
                    host_pub = keys.public(host_key_name(body["host_id"], body["host_trust_gen"]), "host_key")
                ok = verify("ed25519", host_pub, b64u_decode(body["enc_sig"]), enc_input)
                if vector.get("reason") == "bad_enc_sig":
                    case.check(not ok, "enc_sig refused (bad_enc_sig)")
                else:
                    case.check(ok, "enc_sig by the host_key of its generation")
                # A reused key replays the very binding an earlier entry of
                # its chain carried (bodies are public).
                if vector.get("reason") == "enc_key_reused":
                    earlier = [
                        b["seq"]
                        for b in before
                        if b["action"] == "host_enc_key"
                        and b["host_id"] == body["host_id"]
                        and b["host_trust_gen"] == body["host_trust_gen"]
                        and b["enc_key"] == body["enc_key"]
                        and b["enc_sig"] == body["enc_sig"]
                    ]
                    case.check(bool(earlier), f"replays the enc_sig of seq {earlier[0] if earlier else '?'}")

            # What a verifier derives: key ids, and keys as their entries set them.
            for host_id, state in vector.get("expect", {}).get("host_enc_keys", {}).items():
                after = before + [body]
                for which in ("current", "previous"):
                    if which not in state:
                        continue
                    info = state[which]
                    public = b64u_decode(info["pub"])
                    case.equal(enc_kid(public), info["enc_kid"], f"{host_id} {which} enc_kid")
                    setter = after[info["seq"] - 1]
                    case.check(
                        setter["action"] == "host_enc_key"
                        and setter["host_id"] == host_id
                        and setter["enc_key"]["pub"] == info["pub"]
                        and setter["host_trust_gen"] == info["host_trust_gen"],
                        f"{host_id} {which} key set at seq {info['seq']}",
                    )

            if vector.get("valid") is False:
                # Not derived here: the verdict and its reason are checked
                # by the Rust runner and the binding suites (R9.12).
                case.check(True, f"refused ({vector.get('reason', 'see note')}; verdict not derived here)")

    with report.case(file, "log L") as case:
        case.equal(by_label["E1"]["entry_hash"], genesis_hash, "genesis_hash = E1's entry_hash")
        case.equal(data["head"], {"seq": 6, "hash": by_label["E6"]["entry_hash"]}, "head = (6, E6)")
        case.equal(log_labels, ["E1", "E2", "E3", "E4", "E5", "E6"], "E1..E6 in order")


# ------------------------------------------- r9-vectors-host-work-control

LOG_L = ["E1", "E2", "E3", "E4", "E5", "E6"]
# The most counted record ids a principal's part keeps (ControlState, decision 19).
MAX_RECORD_IDS = 256
# The control vectors' records by label, for the sequence checks.
CONTROL_BY_LABEL = {}


def by_label_of(label):
    return CONTROL_BY_LABEL[label]


def signer_key_in(replay, signer):
    """The key a chain names for a record's `signer` (`member:<id>`,
    `service:<id>`, `host:<id>`: the newest generation's host key), or None
    when the chain doesn't hold it."""
    kind, _, name = signer.partition(":")
    if kind in ("member", "service"):
        return replay.members.get(name)
    if kind == "host":
        gens = [gen for (host_id, gen) in replay.hosts if host_id == name]
        return replay.hosts[(name, max(gens))] if gens else None
    return None


def test_key_of(keys, name):
    """The `auth` key, or the `host_key`, of a test key name: (alg, public)."""
    entry = keys.keys[name]
    part = "auth" if "auth" in entry else "host_key"
    return entry[part].get("alg", "ed25519"), unhex(entry[part]["pub_hex"])


def check_host_work_control(file, data, report, context):
    """Control records (delegated host-work I.5.3): every body's jcs, its
    signing input and signature (by the test key named, and that key is the
    one the chain names for the body's signer wherever the chain holds
    it), each service record's principal_key against the r9_svc of the
    principal's auth_key, each step's position against the stations, and
    the record digests a sequence's state keeps (by principal, then
    record_id: the SHA-256 of a body of that principal with that id), each
    `why` (of its kind, and on each effect exactly when it isn't in force),
    and, from the steps alone, the bound (derive_bound) and O1's signed-time
    rule (derive_hold_time). Verdicts and other per-effect results are the
    Rust runner's and the binding suites' (R9.12)."""
    keys = context["keys"]
    mlog = context["membership_log"]
    entries = {v["label"]: v["entry"]["body"] for v in mlog["log"] + mlog["others"]}

    def replay(chain):
        return Replay([entries[label] for label in LOG_L + list(chain)])

    with report.case(file, "account") as case:
        case.equal(data["account_id"], mlog["account_id"], "log L's account_id")
        case.equal(data["genesis_hash"], mlog["genesis_hash"], "log L's genesis_hash")
    with report.case(file, "services") as case:
        replay_l = replay([])
        for name, service in data["services"].items():
            public = b64u_decode(service["auth_key"]["pub"])
            case.equal(sha256(public).hex(), service["r9_svc"], f"{name} r9_svc = SHA-256 of its auth_key")
            case.equal(service["auth_key"], replay_l.members.get(name), f"{name}'s auth_key in log L")
            case.equal(entries[LOG_L[service["seq"] - 1]]["member"]["device_id"], name, f"enrolled at seq {service['seq']}")

    context["host_work_control"] = data
    by_label = {}
    jcs_by_record_id = {}
    stations = {(station["origin"], station["feed_id"]) for station in data["stations"].values()}
    for vector in data["records"]:
        label = vector["label"]
        by_label[label] = vector
        with report.case(file, label) as case:
            wire = vector["record"]
            case.equal(sorted(wire), ["body", "sig"], "wire {body, sig}")
            body = wire["body"]
            case.equal((body.get("type"), body.get("v")), ("atem-host-work-control", 1), "type and v")
            text = jcs(body)
            case.equal(text, vector["jcs"], "jcs")
            case.check(len(text.encode()) <= MAX_BODY_BYTES, "body within 4096 bytes")
            jcs_by_record_id.setdefault((body["principal"], body["record_id"]), set()).add(text)
            signing_input = enc(["atem-host-work-control-v1", text])
            case.equal(signing_input.hex(), vector["signing_input_hex"], "signing input")

            # The signature, by the test key named.
            checks = vector.get("checks", [])
            reasons = {c.get("reason") for c in checks}
            alg, public = test_key_of(keys, vector["signed_with"])
            ok = verify(alg, public, b64u_decode(wire["sig"]), signing_input)
            if "bad_signature" in reasons:
                case.check(not ok, f"{alg} signature refused (bad_signature)")
            else:
                case.check(ok, f"{alg} signature by {vector['signed_with']}")
            # That key is the one each chain names for the signer, where it holds one.
            for chain in [c["chain"] for c in checks] or [[]]:
                named = signer_key_in(replay(chain), body["signer"])
                if named is None:
                    case.check(True, f"{body['signer']} not in L + {chain}")
                else:
                    case.equal(
                        (named["alg"], b64u_decode(named["pub"])),
                        (alg, public),
                        f"{body['signer']}'s key in L + {chain}",
                    )

            # A service record's principal_key beside its key's r9_svc.
            if "r9_svc" in vector:
                kind, _, name = body["principal"].partition(":")
                key = replay([]).members.get(name)
                case.check(kind == "service" and key is not None, "a service of log L")
                r9_svc = sha256(b64u_decode(key["pub"])).hex()
                case.equal(r9_svc, vector["r9_svc"], "r9_svc = SHA-256 of the principal's auth_key")
                if "key_mismatch" in reasons:
                    case.check(body["principal_key"] != r9_svc, "principal_key names another key (key_mismatch)")
                else:
                    case.equal(body["principal_key"], r9_svc, "principal_key = r9_svc")
            if "wrong_account" in reasons:
                case.check(
                    (body["account_id"], body["genesis_hash"]) != (data["account_id"], data["genesis_hash"]),
                    "another account or genesis (wrong_account)",
                )
            if "parse_error" in vector:
                case.check(True, f"refused at parse ({vector['parse_error']}; not derived here)")

    CONTROL_BY_LABEL.clear()
    CONTROL_BY_LABEL.update(by_label)

    def check_state(case, state, fill, what):
        """A state (v2: one part per principal): its account, each part's
        device list (the file's account and genesis), its records (one to
        256 [record_id, digest, issued_at] triples, each id once, the
        revocation's record and the coverage's cover among them), an
        evicted floor only with the records full, one feed per origin in
        `order`, and each record: the SHA-256 of a record body of that
        principal with that id and its issued_at, or, for an id no record of
        the file has, of the record `fill`'s body under that id."""
        case.equal(state["v"], 2, f"{what}: v 2")
        case.equal((state["account_id"], state["genesis_hash"]), (data["account_id"], data["genesis_hash"]), f"{what}: the account")
        for principal, part in state["principals"].items():
            case.equal((part["account_id"], part["genesis_hash"]), (data["account_id"], data["genesis_hash"]), f"{what} {principal}: its device list")
            records = part["records"]
            ids = [record[0] for record in records]
            case.check(
                1 <= len(records) <= MAX_RECORD_IDS and len(set(ids)) == len(ids) and all(len(r) == 3 for r in records),
                f"{what} {principal}: 1 to {MAX_RECORD_IDS} [record_id, digest, issued_at], each id once",
            )
            for pin in [part.get("revoked_by"), part.get("coverage", {}).get("cover", {}).get("record_id")]:
                case.check(pin is None or pin in ids, f"{what} {principal}: its revocation's and cover's records kept")
            if "evicted_floor" in part:
                case.equal(len(records), MAX_RECORD_IDS, f"{what} {principal}: an evicted floor, its records full")
            if principal.startswith("host:"):
                case.check("hold_issued_at" not in part, f"{what} {principal}: a host principal's part keeps no hold's time")
            else:
                at = part.get("hold_issued_at")
                case.check(
                    (at is None or (isinstance(at, int) and 0 <= at <= SAFE_MAX)) and (at is not None or not part["held"]),
                    f"{what} {principal}: hold_issued_at a safe integer, present whenever held",
                )
            case.check(all(len(feeds) == 1 for feeds in part.get("order", {}).values()), f"{what} {principal}: one feed per origin in order")
            copies, wrong = 0, []
            for record_id, digest, issued_at in records:
                texts = jcs_by_record_id.get((principal, record_id), set())
                if texts:
                    bodies = {sha256(t.encode()).hex(): json.loads(t) for t in texts}
                    case.check(
                        digest in bodies and bodies[digest]["issued_at"] == issued_at,
                        f"{what} {principal} {record_id[-4:]}: the SHA-256 and issued_at of a record body of that principal with that id",
                    )
                    continue
                body = dict(by_label[fill]["record"]["body"]) if fill in by_label else {}
                body["record_id"] = record_id
                copies += 1
                if body.get("principal") != principal or sha256(jcs(body).encode()).hex() != digest or body.get("issued_at") != issued_at:
                    wrong.append(record_id)
            if copies:
                case.check(
                    not wrong,
                    f"{what} {principal}: {copies} ids no record of the file has, each the SHA-256 and issued_at of {fill}'s body under that id"
                    + (f" (not: {', '.join(wrong)})" if wrong else ""),
                )

    def standing_of(state, principal):
        """What the state's part of `principal` has in force, as a step's
        `standing` writes it."""
        part = state["principals"].get(principal, {})
        if principal.startswith("host:"):
            interrupted = sorted(str(seq) for seq in part.get("interrupted", []))
        else:
            interrupted = [part["revoked_by"]] if part.get("interrupted") else []
        out = {"held": part.get("held", False), "interrupted": interrupted}
        if "revoked_by" in part:
            out["revoked"] = part["revoked_by"]
        if "coverage" in part:
            out["coverage"] = {"origin": part["coverage"]["origin"], "feed_id": part["coverage"]["feed_id"]}
        return out

    o1_seen = set()
    for sequence in data["sequences"]:
        with report.case(file, sequence["label"]) as case:
            for step in sequence["steps"]:
                case.check(step["record"] in by_label, f"{step['record']} is a record of the file")
                if "pos" in step:
                    pos = step["pos"]
                    case.equal(sorted(pos), ["feed_id", "feed_seq", "origin"], "a position {origin, feed_id, feed_seq}")
                    case.check((pos["origin"], pos["feed_id"]) in stations, "a position in a station's feed")
                standing = step["standing"]
                case.check(
                    {"held", "interrupted"} <= set(standing) <= {"held", "interrupted", "revoked", "coverage"},
                    "a standing {held, interrupted, revoked?, coverage?}",
                )
            fill = sequence.get("fill")
            if "initial" in sequence:
                case.check(fill in by_label, f"fill {fill} is a record of the file")
                check_state(case, sequence["initial"], fill, "initial")
                full = [len(part["records"]) for part in sequence["initial"]["principals"].values()]
                case.check(MAX_RECORD_IDS in full, "initial: a principal's records full")
            else:
                case.check(fill is None, "no fill without an initial state")
            check_state(case, sequence["state"], fill, "state")
            last = sequence["steps"][-1]
            principal = by_label[last["record"]]["record"]["body"]["principal"]
            case.equal(last["standing"], standing_of(sequence["state"], principal), "the last step's standing is the state's")
            check_why(case, sequence)
            counted_before = derive_bound(case, sequence)
            o1_seen.update(derive_hold_time(case, sequence, counted_before))
    with report.case(file, "O1 coverage") as case:
        # The sequences must exercise the signed-time rule (O1), derived above.
        for kind, what in [
            ("tie", "a release issued at the hold's time, refused"),
            ("lift", "a release issued strictly after the hold, lifting it"),
            ("initial", "a hold's time from a stored initial state refusing a release"),
            ("another_feed", "a hold read from another feed than the release's refusing it"),
            ("no_position", "a hold read at no position refusing a release"),
            ("colliding_id", "a hold under a counted id (evidence) refusing a release"),
        ]:
            case.check(kind in o1_seen, what)

    answers = set()
    for snap in data.get("snapshots", []):
        with report.case(file, snap["label"]) as case:
            answers.add(derive_snapshot(case, snap, by_label, entries))
    with report.case(file, "snapshot codes") as case:
        case.check(
            answers == set(SNAPSHOT_CODES) | {"consistent"},
            "the snapshot cases give every inconsistency code and a consistent answer",
            f"got {sorted(answers)}",
        )


# check_snapshot_consistency's codes, in the order its checks run.
SNAPSHOT_CODES = [
    "invalid_retained", "invalid_record", "wrong_origin", "not_signed_anew", "not_candidate_feed",
    "cover_not_first", "uncovered_cover", "not_above_mark", "stop_lost",
    "stop_not_resigned",
]


def snapshot_stops(labels, verdict, by_label, entry_at):
    """The stops in force after the records `labels`, applied in order at
    the list's head with each record left pending applied again after the
    rest (no state machine): a service is revoked by its first valid
    `revoke`, and interrupted once revoked when any valid record of it
    carries an interrupt (a `revoke` with `interrupt_running`, or an
    `interrupt_running`); a host principal's valid interrupt is in force at
    its `revoke_seq` (a valid one names a revoke at or below the head)
    unless that device-list revoke carried `interrupt_running: true`
    itself, which interrupted with the entry. As each standing writes it:
    `{revoked?, interrupted}`, only principals with one."""
    revoked, interrupting, hosts = {}, set(), {}
    for label in labels:
        if verdict(label)["verdict"] != "valid":
            continue
        body = by_label[label]["record"]["body"]
        p, action = body["principal"], body["action"]
        if p.startswith("host:"):
            entry = entry_at(body["revoke_seq"])
            if not entry.get("interrupt_running"):
                hosts.setdefault(p, set()).add(str(body["revoke_seq"]))
            continue
        if action == "revoke":
            revoked.setdefault(p, body["record_id"])
        if (action == "revoke" and body["interrupt_running"]) or action == "interrupt_running":
            interrupting.add(p)
    out = {}
    for p, by in revoked.items():
        out[p] = {"interrupted": [by] if p in interrupting else [], "revoked": by}
    for p, seqs in hosts.items():
        out[p] = {"interrupted": sorted(seqs)}
    return out


def derive_snapshot(case, snap, by_label, entries):
    """A snapshot case (Astation #114, items 2 and 6), derived from the file
    alone: each record's verdict is its `checks` on the case's chain (the
    Rust runner and the suites pin those). First the retained records:
    invalid_retained for the first that isn't valid (reason: the
    verdict's; index: its position in retained), a removed manager's stop
    excepted. Then record by record in publication order: invalid_record (not valid; reason: the verdict's), wrong_origin
    (a service's record naming another origin), not_signed_anew (a cover,
    hold or release whose wire record, body and sig, is a retained one's),
    not_candidate_feed (a record signed anew with the service's own key,
    signer = principal, naming another feed than the candidate; a current
    manager's stop may name any feed of the origin, and so may a retained
    revoke or interrupt_running carried unchanged, whoever signed it),
    cover_not_first (a covered principal's first record isn't its cover, or
    a hold or release before its principal's cover), uncovered_cover,
    not_above_mark (signed anew with the service's own key, issued at or
    below its principal's mark or with no mark). Then, at index the
    snapshot's length, cover_not_first for a covered principal with no
    cover; then each effect of each retained revoke or interrupt_running
    (valid, or a removed manager's), in the retained order (the revocation, then
    the interrupt), not in force after the snapshot alone (snapshot_stops;
    a service's interrupt is due once its principal is revoked by a
    retained revoke or after the snapshot; one not yet due needs an
    interrupt_running of its principal in the snapshot, which a new host
    holds pending; a host principal's is in force too when its device-list
    revoke carried interrupt_running): stop_lost
    when that stop is valid at the head, stop_not_resigned (reason
    removed_manager) when a removed manager signed it, record_id that
    stop. The answer must be
    `expect`, and `in_force` the stops derived after the retained records,
    the snapshot alone and both in order; a host that read the old feed
    keeps every stop. Returns the answer's code, or `consistent`."""
    chain = snap["chain"]
    replay_bodies = [entries[label] for label in LOG_L + list(chain)]

    def entry_at(seq):
        return replay_bodies[seq - 1] if 1 <= seq <= len(replay_bodies) else {}

    def verdict(label):
        found = [c for c in by_label[label].get("checks", []) if c["chain"] == chain]
        if len(found) != 1:
            case.fail(f"{label} has no verdict on L + {chain}")
            return {"verdict": "unknown"}
        return found[0]

    covered, marks = set(snap["covered"]), snap["marks"]
    case.equal(sorted(covered), snap["covered"], "covered: sorted, each once")

    def answer():
        def at(index, code, body=None, principal=None, reason=None, effect=None, revoke_seq=None):
            out = {"consistent": False, "index": index, "code": code}
            if body is not None:
                out["record_id"] = body["record_id"]
            if principal is not None:
                out["principal"] = principal
            if reason is not None:
                out["reason"] = reason
            if effect is not None:
                out["effect"] = effect
            if revoke_seq is not None:
                out["revoke_seq"] = revoke_seq
            return out

        for i, label in enumerate(snap["retained"]):
            v = verdict(label)
            if v["verdict"] != "valid" and v.get("reason") != "removed_manager":
                body = by_label[label]["record"]["body"]
                return at(i, "invalid_retained", body, body["principal"], v.get("reason"))
        seen, covers = set(), set()
        for i, label in enumerate(snap["snapshot"]):
            body = by_label[label]["record"]["body"]
            p, action = body["principal"], body["action"]
            v = verdict(label)
            if v["verdict"] != "valid":
                return at(i, "invalid_record", body, p, v.get("reason"))
            # A retained record carried as it is: the same wire record, body
            # and sig. A retained stop so carried is no record signed anew,
            # whoever signed it; a cover, hold or release must be signed anew.
            stop = action in ("revoke", "interrupt_running")
            retained = any(by_label[r]["record"] == by_label[label]["record"] for r in snap["retained"])
            anew = body["signer"] == p and not (stop and retained)
            if "origin" in body:
                if body["origin"] != snap["origin"]:
                    return at(i, "wrong_origin", body, p)
                if retained and not stop:
                    return at(i, "not_signed_anew", body, p)
                if anew and body["feed_id"] != snap["candidate_feed_id"]:
                    return at(i, "not_candidate_feed", body, p)
            first = p not in seen
            seen.add(p)
            if (first and action != "cover" and p in covered) or (action in ("hold", "release") and p not in covers):
                return at(i, "cover_not_first", body, p)
            if action == "cover" and p not in covered:
                return at(i, "uncovered_cover", body, p)
            if anew and (p not in marks or body["issued_at"] <= marks[p]):
                return at(i, "not_above_mark", body, p)
            if action == "cover":
                covers.add(p)
        end = len(snap["snapshot"])
        for p in sorted(covered - covers):
            return at(end, "cover_not_first", principal=p)
        fresh = snapshot_stops(snap["snapshot"], verdict, by_label, entry_at)
        revoked = {
            by_label[r]["record"]["body"]["principal"]
            for r in snap["retained"]
            if by_label[r]["record"]["body"]["action"] == "revoke"
        }
        for label in snap["retained"]:
            body = by_label[label]["record"]["body"]
            p, action = body["principal"], body["action"]
            if action not in ("revoke", "interrupt_running"):
                continue
            v = verdict(label)
            valid = v["verdict"] == "valid"
            code, reason = ("stop_lost", None) if valid else ("stop_not_resigned", "removed_manager")
            has = fresh.get(p, {"interrupted": []})
            if p.startswith("host:"):
                seq = body["revoke_seq"]
                entry = entry_at(seq)
                by_entry = (
                    entry.get("action") == "host_sender_revoke"
                    and entry.get("host_id") == p[len("host:"):]
                    and entry.get("interrupt_running") is True
                )
                if not by_entry and str(seq) not in has["interrupted"]:
                    return at(end, code, body, p, reason, "interrupt", seq)
                continue
            revokes = action == "revoke"
            interrupts = action == "interrupt_running" or (revokes and body["interrupt_running"])
            if revokes and "revoked" not in has:
                return at(end, code, body, p, reason, "revocation")
            # Due once its principal is revoked: then in force. Not yet due,
            # it waits pending on a host that read the old feed, so the
            # snapshot must hold an interrupt_running of that principal.
            due = revokes or p in revoked or "revoked" in has
            if due:
                kept = bool(has["interrupted"])
            else:
                kept = any(
                    by_label[s]["record"]["body"]["principal"] == p
                    and by_label[s]["record"]["body"]["action"] == "interrupt_running"
                    for s in snap["snapshot"]
                )
            if interrupts and not kept:
                return at(end, code, body, p, reason, "interrupt")
        return {"consistent": True}

    got = answer()
    case.equal(got, snap["expect"], "the answer, derived from the verdicts, the feeds, the marks and the effects")
    in_force = {
        "retained": snapshot_stops(snap["retained"], verdict, by_label, entry_at),
        "snapshot": snapshot_stops(snap["snapshot"], verdict, by_label, entry_at),
        "snapshot_over_retained": snapshot_stops(snap["retained"] + snap["snapshot"], verdict, by_label, entry_at),
    }
    case.equal(in_force, snap["in_force"], "in_force: the stops after the retained records, the snapshot alone and both")
    kept = all(in_force["snapshot_over_retained"].get(p) == s for p, s in in_force["retained"].items())
    case.check(kept, "a host that read the old feed keeps every stop it had")
    return got.get("code", "consistent")


# Applied::why's codes (host-work-v1 §11.1), by what they explain.
WHY_PENDING = {"principal_unknown", "signer_unknown", "revoke_not_in_list", "list_frozen", "not_revoked", "revoke_not_applied"}
WHY_VERIFIER_REFUSED = {
    "wrong_account", "bad_signature", "key_mismatch", "signer_not_allowed",
    "removed_manager", "host_key_signed", "not_a_service", "not_a_revoke",
}
WHY_STATE_REFUSED = {"order", "after_revoke", "not_newer", "not_after_hold"}
WHY_EVIDENCE = WHY_VERIFIER_REFUSED | {"collision", "possible_replay"}
WHY_CODES = WHY_PENDING | WHY_VERIFIER_REFUSED | WHY_STATE_REFUSED | {"collision", "possible_replay"}


def check_why(case, sequence):
    """Each step's `expect.why`: one of the codes, present exactly when the
    record is pending or refused or kept as evidence, and of the kind its
    result says (pending: a wait; refused as evidence: the verifier's
    reason, a collision or a possible replay; refused otherwise: order,
    after a revoke, not newer, or a list of another account; counted as
    evidence: a collision)."""
    bad = []
    for i, step in enumerate(sequence["steps"], 1):
        expect = step["expect"]
        result, evidence, why = expect["result"], expect["evidence"], expect.get("why")
        # Each effect not in force says the record's why; one in force says
        # nothing (O5).
        for e in expect["effects"]:
            not_in_force = e["result"] in ("pending", "refused")
            if e.get("why") != (why if not_in_force else None) or (not_in_force and why is None):
                bad.append(i)
        explains = result in ("pending", "refused") or evidence
        if (why is not None) != explains or (why is not None and why not in WHY_CODES):
            bad.append(i)
        elif result == "pending" and why not in WHY_PENDING:
            bad.append(i)
        elif result == "refused" and evidence and why not in WHY_EVIDENCE:
            bad.append(i)
        elif result == "refused" and not evidence and why not in WHY_STATE_REFUSED | {"wrong_account"}:
            bad.append(i)
        elif result in ("applied", "duplicate") and evidence and why != "collision":
            bad.append(i)
    case.check(
        not bad,
        "every step's why: a code of its kind, present exactly when pending, refused or evidence, "
        "and on each effect exactly when it isn't in force"
        + (f" (not: steps {sorted(set(bad))})" if bad else ""),
    )


def pins_of(part):
    """The record ids a part never evicts: its revocation's, its cover's."""
    return {part.get("revoked_by"), part.get("coverage", {}).get("cover", {}).get("record_id")} - {None}


def derive_bound(case, sequence):
    """The bound, derived from the file alone (no state machine): per
    principal, the counted ids start as `initial`'s and gain each step's id
    that counted (`applied` or `duplicate`, not evidence) and wasn't counted
    yet, in step order; past MAX_RECORD_IDS the oldest id that isn't pinned
    (the revocation's record, the coverage's cover, at the start or the
    end) is evicted and raises the evicted floor to its issued_at. The final
    records (in order) and `evicted_floor` must be what that gives, the
    ids gone (initial + counted) - final, and a cover or release of a
    principal not revoked, its id not counted then and issued no later than
    the floor then, must be `refused` as evidence with `why`
    `possible_replay`, and only those.

    Its limits: the pins are static (the initial and final states'
    revocation and cover records, not the ones in force at each step,
    which only matters were a pin to change during an eviction), and it
    takes each step's result as written: which records verification
    refuses or keeps pending, and that a frozen list or a failed
    verification comes before the floor, are outside it (the Rust runner
    and the suites check those)."""
    initial = sequence.get("initial", {}).get("principals", {})
    final = sequence["state"]["principals"]
    ids, issued, floor, revoked, pins, evicted = {}, {}, {}, {}, {}, {}

    def start(principal):
        part = initial.get(principal, {})
        ids[principal] = [r[0] for r in part.get("records", [])]
        for r in part.get("records", []):
            issued[(principal, r[0])] = r[2]
        floor[principal] = part.get("evicted_floor")
        revoked[principal] = "revoked_by" in part
        pins[principal] = pins_of(part) | pins_of(final.get(principal, {}))
        evicted[principal] = []

    for principal in set(initial) | set(final):
        start(principal)
    wrong, counted_before = [], []
    for i, step in enumerate(sequence["steps"], 1):
        body = by_label_of(step["record"])["record"]["body"]
        principal, rid, expect = body["principal"], body["record_id"], step["expect"]
        if principal not in ids:
            start(principal)
        counted_before.append(rid in ids[principal])
        guarded = (
            body["action"] in ("cover", "release")
            and not revoked[principal]
            and rid not in ids[principal]
            and floor[principal] is not None
            and body["issued_at"] <= floor[principal]
        )
        replay = expect.get("why") == "possible_replay"
        if guarded != replay or (guarded and (expect["result"], expect["evidence"]) != ("refused", True)):
            wrong.append(i)
        counted = expect["result"] in ("applied", "duplicate") and not expect["evidence"]
        if counted and body["action"] == "revoke":
            revoked[principal] = True
        if counted and rid not in ids[principal]:
            ids[principal].append(rid)
            issued[(principal, rid)] = body["issued_at"]
            if len(ids[principal]) > MAX_RECORD_IDS:
                victim = next(x for x in ids[principal] if x not in pins[principal])
                ids[principal].remove(victim)
                evicted[principal].append(victim)
                at = issued[(principal, victim)]
                floor[principal] = at if floor[principal] is None else max(floor[principal], at)
    case.check(
        not wrong,
        "each guarded step (an unrevoked principal's cover or release, its id not counted, issued no later than the floor) "
        "is refused as evidence with why possible_replay, and only those" + (f" (not: steps {wrong})" if wrong else ""),
    )
    for principal, want in sorted(ids.items()):
        part = final.get(principal, {})
        got = [r[0] for r in part.get("records", [])]
        # This equality is what asserts each eviction took the oldest id not
        # pinned: `want` was built by evicting exactly those.
        case.equal(got, want, f"{principal}: the final records, oldest first, as the steps count and evict (oldest unpinned first)")
        case.equal(part.get("evicted_floor"), floor[principal], f"{principal}: evicted_floor, the newest issued_at evicted")
        begin = [r[0] for r in initial.get(principal, {}).get("records", [])]
        added = [
            by_label_of(st["record"])["record"]["body"]["record_id"]
            for st in sequence["steps"]
            if by_label_of(st["record"])["record"]["body"]["principal"] == principal
            and st["expect"]["result"] in ("applied", "duplicate")
            and not st["expect"]["evidence"]
        ]
        # An id evicted and counted again is in the final records.
        gone = set(evicted[principal]) - set(got)
        case.equal(sorted(set(begin + added) - set(got)), sorted(gone), f"{principal}: the ids gone are (initial + counted) - final")
    return counted_before


def derive_hold_time(case, sequence, counted_before):
    """O1, derived from the file alone (no state machine): per principal,
    the hold's time starts as `initial`'s `hold_issued_at` and becomes the
    newest `issued_at` of every hold step that holds or finds the principal
    held (`applied` or `duplicate`, evidence or not: a hold under a counted
    id still applies) while it isn't revoked. Each release that reaches the
    rule (its principal held and not revoked, and not refused for anything
    else: pending, a verifier's reason, a possible replay, a collision or
    feed order) must lift the hold (`applied`) exactly when its `issued_at`
    is strictly greater than that time, and otherwise be `refused` with
    `why` `not_after_hold`, no evidence; no other step has that `why`. The
    final state's `hold_issued_at` must be the time derived.

    A hold whose record id is counted already (`counted_before`, from
    derive_bound) and isn't evidence is the same body replayed: a
    `duplicate` that holds nothing and records no time. One under a counted
    id with another body (evidence, a collision) applies as a stop.

    Returns what the sequence exercised, for the file's coverage: a `tie`
    refused, a `lift` after a known time, and a release refused by a time
    that came from `initial`, or from a hold read from `another_feed` than
    the release's, at `no_position`, or under a `colliding_id`.

    Its limits, as derive_bound's: each step's verification and feed order
    are taken as written (the Rust runner and the suites check those)."""
    initial = sequence.get("initial", {}).get("principals", {})
    final = sequence["state"]["principals"]
    time, held, revoked, source = {}, {}, {}, {}
    seen = set()

    def start(principal):
        part = initial.get(principal, {})
        time[principal] = part.get("hold_issued_at")
        held[principal] = part.get("held", False)
        revoked[principal] = "revoked_by" in part
        source[principal] = "initial" if time[principal] is not None else None

    for principal in set(initial) | set(final):
        start(principal)
    other_refusals = WHY_PENDING | WHY_VERIFIER_REFUSED | {"possible_replay", "collision", "order"}
    wrong, reached = [], 0
    for i, step in enumerate(sequence["steps"], 1):
        body = by_label_of(step["record"])["record"]["body"]
        principal, expect = body["principal"], step["expect"]
        if principal not in time:
            start(principal)
        why = expect.get("why")
        in_force = expect["result"] in ("applied", "duplicate")
        action = body["action"]
        replay = counted_before[i - 1] and not expect["evidence"]
        if action == "hold" and in_force and not revoked[principal] and not replay:
            at = time[principal]
            if at is None or body["issued_at"] > at:
                time[principal] = body["issued_at"]
                source[principal] = step
            held[principal] = True
            if why == "not_after_hold":
                wrong.append(i)
        elif action == "release" and held[principal] and not revoked[principal] and why not in other_refusals:
            reached += 1
            at = time[principal]
            lifts = at is None or body["issued_at"] > at
            if lifts and expect["result"] != "applied":
                wrong.append(i)
            if not lifts and (expect["result"], expect["evidence"], why) != ("refused", False, "not_after_hold"):
                wrong.append(i)
            if expect["result"] == "applied":
                held[principal] = False
            if lifts and at is not None:
                seen.add("lift")
            if not lifts:
                if body["issued_at"] == at:
                    seen.add("tie")
                by = source[principal]
                if by == "initial":
                    seen.add("initial")
                elif by is not None:
                    if by["expect"]["evidence"]:
                        seen.add("colliding_id")
                    if "pos" not in by:
                        seen.add("no_position")
                    elif "pos" in step and (by["pos"]["origin"], by["pos"]["feed_id"]) != (step["pos"]["origin"], step["pos"]["feed_id"]):
                        seen.add("another_feed")
        elif why == "not_after_hold":
            wrong.append(i)
        if action == "revoke" and any(
            e["effect"] == "revocation" and e["result"] in ("applied", "duplicate") for e in expect["effects"]
        ):
            revoked[principal] = True
    case.check(
        not wrong,
        f"{reached} releases reach the signed-time rule: each lifts the hold exactly when issued after every hold verified before it, "
        "else is refused with why not_after_hold (no other step has it)" + (f" (not: steps {wrong})" if wrong else ""),
    )
    for principal in sorted(time):
        if principal.startswith("host:"):
            continue
        case.equal(
            final.get(principal, {}).get("hold_issued_at"),
            time[principal],
            f"{principal}: hold_issued_at, the newest issued_at of every hold verified while not revoked",
        )
    return seen


# ------------------------------------------------ r9-control-ack-* fixtures


def report_id(kind, account_id, genesis_hash, principal, integration_id, host=None):
    """A Station report's id (host-work-v1 §11.4): `<kind>:` + hex SHA-256 of
    enc(["atem-station-report-id-v1", kind, account_id, genesis_hash (32 raw
    bytes), principal, integration_id, host]), without the host for
    `revoked`."""
    fields = ["atem-station-report-id-v1", kind, account_id, unhex(genesis_hash), principal, integration_id]
    if host is not None:
        fields.append(host)
    return f"{kind}:{sha256(enc(fields)).hex()}"


def ids_in(step):
    """Every report id a step names."""
    out = list(step.get("made", []))
    for intent in step.get("expect_report", []):
        out.append(intent["report_id"])
        out += intent["not_before"]
    if "confirm" in step:
        out.append(step["confirm"])
    failure = step.get("report_failure", {})
    if "report_id" in failure:
        out.append(failure["report_id"])
    for alert in failure.get("alerts", []) + step.get("alerts", []):
        out += [alert["report_id"]] if "report_id" in alert else alert.get("dropped", [])
    out += step.get("expect_refused", []) + step.get("expect_dropped", []) + step.get("expect_portal", [])
    if "replica" in step:
        out += ids_in(step["replica"])
    return out


def flat_steps(steps):
    """Every step, a branch's inside it (in order) included."""
    for step in steps:
        yield step
        yield from flat_steps(step.get("branch", []))


def check_control_ack(file, data, report, context):
    """A Station acknowledgment fixture (test 48): its device list is log
    L's, its records and integrations are the control vectors', every ack
    claims its link's association at the Station's origin and names records
    of the vectors, and every report id it names is one of its reports',
    recomputed here: each expected report's id from its own kind,
    integration and host; each `expect_counts`, the ledger's counts
    (derive_counts); and every report each step makes, what the Station
    sends at each `expect_report`, and each start (derive_reports). A
    `branch` is another history from the committed state, checked as one
    and kept apart."""
    mlog = context["membership_log"]
    control = context["host_work_control"]
    records = {v["label"]: v["record"]["body"] for v in control["records"]}
    principal_of = {}
    for body in records.values():
        integration = body.get("about", {}).get("integration_id")
        if integration is not None:
            principal_of.setdefault(integration, set()).add(body["principal"])
    setup = data["setup"]
    station = setup["station"]
    account, genesis = station["account_id"], station["genesis_hash"]

    with report.case(file, "setup") as case:
        case.equal((account, genesis), (mlog["account_id"], mlog["genesis_hash"]), "the station's device list is log L")
        case.equal(setup["records"], "r9-vectors-host-work-control", "records from the control vectors")
        for integration, principal in setup["integrations"].items():
            case.check(
                principal in principal_of.get(integration, set()),
                f"{integration} is an integration of {principal} in the vectors",
            )
        for name, link in setup["links"].items():
            case.equal((link["account_id"], link["genesis_hash"], link["host_id"]), (account, genesis, name), f"link {name}")

    # Every report this fixture's Station can make, by id.
    known = {}
    for integration, principal in setup["integrations"].items():
        known[report_id("revoked", account, genesis, principal, integration)] = ("revoked", integration, None)
        for host in setup["links"]:
            rid = report_id("revocation_applied", account, genesis, principal, integration, host)
            known[rid] = ("revocation_applied", integration, host)

    with report.case(file, "report ids") as case:
        steps = list(flat_steps(data["steps"]))
        named = [rid for step in steps for rid in ids_in(step)]
        unknown = sorted({rid for rid in named if rid not in known})
        case.check(not unknown, f"{len(set(named))} distinct report ids, each one of the station's reports", f"unknown {unknown}")
        intents = [intent for step in steps for intent in step.get("expect_report", [])]
        for intent in intents:
            r = intent["report"]
            host = r.get("host") if r["kind"] == "revocation_applied" else None
            principal = setup["integrations"].get(r["integration_id"], "")
            want = report_id(r["kind"], account, genesis, principal, r["integration_id"], host)
            case.check(intent["report_id"] == want, "", f"{r['kind']} {host or ''}: got {intent['report_id']}, want {want}")
            if r["kind"] == "revocation_applied":
                case.check(
                    any(b["record_id"] == r["record_id"] and b["principal"] == principal for b in records.values()),
                    "",
                    f"{r['record_id']} is no record of {principal}",
                )
            else:
                case.check(r["outcome"] in ("all_applied", "deadline_passed"), "", f"outcome {r['outcome']}")
                case.check((r["outcome"] == "all_applied") == (r["pending_hosts"] == []), "", "all_applied exactly when no host is pending")
        case.done = [d for d in case.done if d]
        case.check(True, f"{len(intents)} expected reports: each id recomputed from its kind, integration and host")
        if intents:
            case.check(True, "each revocation_applied names a record of the principal; all_applied exactly when no host is pending")

    with report.case(file, "acks and records") as case:
        acks, labels = [], []

        def collect(step):
            if "control_record" in step:
                labels.append(step["control_record"])
            if "control_ack" in step:
                acks.append(step)
            if "replica" in step:
                collect(step["replica"])
            for inner in step.get("either_order", []) + step.get("branch", []):
                collect(inner)

        for step in data["steps"]:
            collect(step)
        missing = sorted({label for label in labels if label not in records})
        case.check(not missing, f"{len(labels)} records, each a control vector", f"not vectors: {missing}")
        ids = {b["record_id"] for b in records.values()}
        bad = []
        for step in acks:
            a = step["control_ack"]
            link = setup["links"][step["link"]]
            claim = (a["account_id"], a["genesis_hash"], a["host_id"], a["host_trust_gen"])
            own = (link["account_id"], link["genesis_hash"], link["host_id"], link["host_trust_gen"])
            if claim != own and step.get("refused") != "not_the_link":
                bad.append(f"{step['link']}'s ack claims another association")
            if a["origin"] != station["origin"]:
                bad.append(f"{step['link']}'s ack names another origin")
            if not all(r.get("record_id", "") in ids for r in a["results"]):
                bad.append(f"{step['link']}'s ack names a record outside the vectors")
        case.check(not bad, f"{len(acks)} acks: each claims its link's association (or is refused not_the_link), at the station's origin, naming records of the vectors", "; ".join(bad))

    if any("expect_counts" in step for step in flat_steps(data["steps"])):
        with report.case(file, "counts") as case:
            derive_counts(case, data, records)

    with report.case(file, "reports") as case:
        derive_reports(case, data, records)


# A count's effect, in the ledger's order: the revocation before the interrupt.
COUNT_EFFECTS = {"revocation": 0, "interrupt": 1}


def derive_counts(case, data, records):
    """The ledger's counts (its state's `done`), derived from the steps
    alone (no ledger): the Station tracks each `revoke` and
    `interrupt_running` it records (once per record_id), and each ack it
    takes (not refused, committed) counts, for the link's host, every
    effect of a tracked record whose result is `applied` or `duplicate`,
    once per principal, effect (an interrupt at a host principal's
    revoke_seq) and host, through the first record that said so; a cover,
    hold or release, a pending or refused result, the cursor and the feed
    the ack names count nothing. A `replica` step counts once, a step with
    `commit: false` not at all, a restart keeps what was committed. Each
    `expect_counts` must be those counts, sorted by principal, effect
    (revocation first), revoke_seq and host."""
    hosts = {name: link["host_id"] for name, link in data["setup"]["links"].items()}
    tracked, counts, wrong = {}, {}, []

    def apply(step):
        if step.get("commit") is False:
            return
        if "control_record" in step:
            body = records[step["control_record"]]
            effects = {"revoke": ["revocation", "interrupt"] if body.get("interrupt_running") else ["revocation"],
                       "interrupt_running": ["interrupt"]}.get(body["action"])
            if effects is not None:
                tracked.setdefault(body["record_id"], (body["principal"], effects, body.get("revoke_seq")))
        if "control_ack" in step and "refused" not in step:
            host = hosts[step["link"]]
            for result in step["control_ack"]["results"]:
                if result.get("record_id") not in tracked:
                    continue
                principal, effects, revoke_seq = tracked[result["record_id"]]
                for e in result["effects"]:
                    if e["result"] in ("applied", "duplicate"):
                        seq = revoke_seq if e["effect"] == "interrupt" else None
                        counts.setdefault((principal, e["effect"], seq, host), result["record_id"])
        if "replica" in step:
            apply(step["replica"])
        for inner in step.get("either_order", []):
            apply(inner)

    checked = 0

    def run(steps, where):
        nonlocal tracked, counts, checked
        for i, step in enumerate(steps, 1):
            apply(step)
            if "branch" in step:
                # Another history: nothing of it reaches this one.
                saved = (dict(tracked), dict(counts))
                run(step["branch"], f"{where}{i}.")
                tracked, counts = saved
            if "expect_counts" in step:
                checked += 1
                keys = sorted(counts, key=lambda k: (k[0], COUNT_EFFECTS[k[1]], -1 if k[2] is None else k[2], k[3]))
                want = []
                for principal, effect, seq, host in keys:
                    count = {"effect": effect, "host": host, "principal": principal, "record_id": counts[(principal, effect, seq, host)]}
                    if seq is not None:
                        count["revoke_seq"] = seq
                    want.append(count)
                if step["expect_counts"] != want:
                    wrong.append(f"{where}{i}")

    run(data["steps"], "")
    case.check(
        not wrong,
        f"{checked} expect_counts: each the counts derived from the records tracked and the acks taken, per principal, effect and host, through the first record that said so"
        + (f" (not: steps {wrong})" if wrong else ""),
    )


REVOCATION_DEADLINE_MS = 24 * 60 * 60 * 1000
REVOCATION_START_SLACK_MS = 60 * 60 * 1000
MAX_SAFE_INTEGER = 2**53 - 1


def derive_reports(case, data, records):
    """Every report the Station makes, and what it sends, derived from the
    steps alone (no ledger; host-work-v1 §11.4, "Reports"). The Station's
    own first `revoke` of a principal (signed with its key, not a member's)
    starts its revocation, covering the step's hosts, at min(revoked_at_ms,
    issued_at + 1 hour), or at its issued_at with no revoked_at_ms (no
    authenticated original time: late, never early); a learned original
    time lowers the start, after the final too, where it makes nothing
    (`learn_revoked_at`; refused `unknown_revocation` without an own revoke,
    `malformed` above 2^53 - 1). Every record, ack, learn and tick first
    makes the final of each revocation whose start + 24 hours its time
    reached. A covered host is reported (`revocation_applied`, naming the
    record) at its first `applied` or `duplicate` (any record of the
    principal) once the own revoke is recorded, and at the own revoke for
    the hosts counted before it, in host order; the revocation is
    `all_applied` once every covered host is counted. A final names in
    `not_before` the reports of the covered hosts counted when it is made
    (sorted), the others as `pending_hosts`. A learn or a tick makes no
    per-host report. Each step's `made` is exactly the reports derived for
    it, in order; each `expect_report` exactly what the Station sends now
    (for each principal its earliest report not settled, once every report
    its `not_before` names is settled; nothing while reporting is
    stopped), every report it confirms or fails one of those; each
    `expect_start`, `expect_refused`, `expect_dropped` and `expect_stopped`
    the derived one. A `replica` step counts once, a step with `commit:
    false` not at all, `either_order` gives the same state and reports in
    both orders (the first kept), and a `branch` is another history, kept
    apart."""
    setup = data["setup"]
    station = setup["station"]
    account, genesis = station["account_id"], station["genesis_hash"]
    hosts = {name: link["host_id"] for name, link in setup["links"].items()}
    wrong, made_count, checked = [], 0, 0

    def fresh():
        # tracked: record_id -> principal; counted: (principal, host) -> the
        # record that first said so; revs: principal -> {integration,
        # covered, start, final}; pending: the intents not settled, in the
        # order made, each with its principal.
        return {
            "tracked": {}, "counted": {}, "revs": {}, "pending": [], "refused": set(),
            "dropped": {}, "stopped": None, "client_id": setup.get("report_client_id"),
        }

    def copy(st):
        out = dict(st)
        out.update(
            tracked=dict(st["tracked"]), counted=dict(st["counted"]), pending=list(st["pending"]),
            revs={p: dict(r) for p, r in st["revs"].items()}, refused=set(st["refused"]), dropped=dict(st["dropped"]),
        )
        return out

    def applied_id(st, principal, host):
        return report_id("revocation_applied", account, genesis, principal, st["revs"][principal]["integration"], host)

    def make(st, principal, rid, report, not_before, made):
        st["pending"].append((principal, {"not_before": not_before, "report": report, "report_id": rid}))
        made.append(rid)

    def report_applied(st, principal, host, made):
        r = st["revs"][principal]
        report = {"host": host, "integration_id": r["integration"], "kind": "revocation_applied", "record_id": st["counted"][(principal, host)]}
        make(st, principal, applied_id(st, principal, host), report, [], made)

    def finish(st, principal, made):
        r = st["revs"][principal]
        done = [h for h in sorted(r["covered"]) if (principal, h) in st["counted"]]
        pending = [h for h in sorted(r["covered"]) if (principal, h) not in st["counted"]]
        r["final"] = ("deadline_passed", pending) if pending else ("all_applied", [])
        report = {"integration_id": r["integration"], "kind": "revoked", "outcome": r["final"][0], "pending_hosts": pending}
        rid = report_id("revoked", account, genesis, principal, r["integration"])
        make(st, principal, rid, report, sorted(applied_id(st, principal, h) for h in done), made)

    def when_all_applied(st, principal, made):
        r = st["revs"][principal]
        if r["final"] is None and all((principal, h) in st["counted"] for h in r["covered"]):
            finish(st, principal, made)

    def pass_deadlines(st, now, made):
        for principal in sorted(st["revs"]):
            r = st["revs"][principal]
            if r["final"] is None and now >= r["start"] + REVOCATION_DEADLINE_MS:
                finish(st, principal, made)

    def transition(st, step, now, where):
        """The state after an input step, and the reports it made; None when
        the step is refused (nothing changes)."""
        if "refused" in step:
            if "learn_revoked_at" in step:
                at, principal = step["revoked_at_ms"], step["learn_revoked_at"]
                code = "malformed" if at > MAX_SAFE_INTEGER else None if principal in st["revs"] else "unknown_revocation"
                if code != step["refused"]:
                    wrong.append(f"{where}: refused {code}, not {step['refused']}")
            return None
        st, made = copy(st), []
        pass_deadlines(st, now, made)
        if "control_record" in step:
            body = records[step["control_record"]]
            effects = {"revoke": ["revocation"], "interrupt_running": ["interrupt"]}.get(body["action"])
            if effects is not None and body["record_id"] not in st["tracked"]:
                principal = body["principal"]
                st["tracked"][body["record_id"]] = principal
                own = not body["signer"].startswith("member:")
                if own and "revocation" in effects and principal not in st["revs"]:
                    issued = body["issued_at"]
                    start = min(step.get("revoked_at_ms", issued), issued + REVOCATION_START_SLACK_MS)
                    covered = set(step["covered_hosts"])
                    st["revs"][principal] = {"integration": body["about"]["integration_id"], "covered": covered, "start": start, "final": None}
                    for host in sorted(covered):
                        if (principal, host) in st["counted"]:
                            report_applied(st, principal, host, made)
                    when_all_applied(st, principal, made)
                    pass_deadlines(st, now, made)
        elif "control_ack" in step:
            host = hosts[step["link"]]
            for result in step["control_ack"]["results"]:
                principal = st["tracked"].get(result.get("record_id"))
                if principal is None:
                    continue
                for e in result["effects"]:
                    if e["effect"] == "revocation" and e["result"] in ("applied", "duplicate"):
                        if (principal, host) not in st["counted"]:
                            st["counted"][(principal, host)] = result["record_id"]
                            r = st["revs"].get(principal)
                            if r is not None and host in r["covered"]:
                                report_applied(st, principal, host, made)
                                when_all_applied(st, principal, made)
        elif "learn_revoked_at" in step:
            r = st["revs"].get(step["learn_revoked_at"])
            if r is None:
                wrong.append(f"{where}: a learn with no own revoke is refused unknown_revocation")
            elif step["revoked_at_ms"] > MAX_SAFE_INTEGER:
                wrong.append(f"{where}: a learn above 2^53 - 1 is refused malformed")
            else:
                # After the final too, where it makes nothing.
                r["start"] = min(r["start"], step["revoked_at_ms"])
                pass_deadlines(st, now, made)
        return st, made

    def offered(st):
        """What the Station sends now: per principal its earliest report not
        settled, once what its `not_before` names is settled."""
        if st["stopped"] is not None:
            return []
        waiting = {intent["report_id"] for _, intent in st["pending"]}
        seen, out = set(), []
        for principal, intent in st["pending"]:
            if principal in seen:
                continue
            seen.add(principal)
            if not any(rid in waiting for rid in intent["not_before"]):
                out.append(intent)
        return out

    def settle(st, rid):
        before = len(st["pending"])
        st["pending"] = [(p, i) for p, i in st["pending"] if i["report_id"] != rid]
        return len(st["pending"]) != before

    def sendable(st, rid, at):
        if not any(i["report_id"] == rid for i in offered(st)):
            wrong.append(f"{at}: {rid} is not sendable")

    def answer_of(status):
        if status == "no_answer" or status in (401, 408, 429) or 500 <= status <= 599:
            return "retry"
        return {200: "confirm", 403: "stop_reporting"}.get(status, "refuse")

    def run(st, now, steps, where):
        nonlocal made_count, checked
        for i, step in enumerate(steps, 1):
            at = f"{where}{i}"
            inputs = ("control_record", "control_ack", "learn_revoked_at", "tick")
            if any(k in step for k in inputs) or "replica" in step:
                inner = step.get("replica", step)
                t = transition(st, inner, now, at)
                if t is None:
                    continue
                if inner["made"] != t[1]:
                    wrong.append(f"{at}: made {inner['made']}, derived {t[1]}")
                made_count += len(t[1])
                if inner.get("commit") is not False:
                    st = t[0]
            elif "either_order" in step:
                def both(first, second):
                    after, made = transition(st, first, now, at)
                    after, more = transition(after, second, now, at)
                    return after, made + more

                x, y = step["either_order"]
                (s1, m1), (s2, m2) = both(x, y), both(y, x)
                if s1 != s2 or m1 != m2:
                    wrong.append(f"{at}: the two orders differ")
                if step["made"] != m1:
                    wrong.append(f"{at}: made {step['made']}, derived {m1}")
                made_count += len(m1)
                st = s1
            elif "branch" in step:
                run(copy(st), now, step["branch"], f"{at}.")
            elif "advance_ms" in step:
                now += step["advance_ms"]
            elif "expect_start" in step:
                checked += 1
                starts = {p: r["start"] for p, r in st["revs"].items()}
                if step["expect_start"] != starts:
                    wrong.append(f"{at}: starts {step['expect_start']}, derived {starts}")
            elif "expect_report" in step:
                checked += 1
                if step["expect_report"] != offered(st):
                    wrong.append(f"{at}: sends {step['expect_report']}, derived {offered(st)}")
            elif "confirm" in step:
                sendable(st, step["confirm"], at)
                st = copy(st)
                settle(st, step["confirm"])
            elif "report_failure" in step:
                f = step["report_failure"]
                sendable(st, f["report_id"], at)
                answer = answer_of(f["status"])
                if answer != f["answer"]:
                    wrong.append(f"{at}: status {f['status']} is {answer}, not {f['answer']}")
                st = copy(st)
                if answer == "refuse" and settle(st, f["report_id"]):
                    st["refused"].add(f["report_id"])
                elif answer == "stop_reporting" and st["stopped"] is None:
                    st["stopped"] = st["client_id"]
            elif "resume_reporting" in step:
                st = copy(st)
                st["client_id"] = step["resume_reporting"]
                if st["stopped"] is not None and st["stopped"] != st["client_id"]:
                    for _, intent in st["pending"]:
                        st["dropped"][intent["report_id"]] = st["stopped"]
                    st["pending"] = []
                st["stopped"] = None
            elif "expect_refused" in step:
                checked += 1
                if step["expect_refused"] != sorted(st["refused"]):
                    wrong.append(f"{at}: refused {step['expect_refused']}, derived {sorted(st['refused'])}")
            elif "expect_dropped" in step:
                checked += 1
                if step["expect_dropped"] != sorted(st["dropped"]):
                    wrong.append(f"{at}: dropped {step['expect_dropped']}, derived {sorted(st['dropped'])}")
            elif "expect_stopped" in step:
                checked += 1
                if step["expect_stopped"] != (st["stopped"] or False):
                    wrong.append(f"{at}: stopped {step['expect_stopped']}, derived {st['stopped']}")

    run(fresh(), setup["station_now_ms"], data["steps"], "")
    case.check(
        not wrong,
        f"{made_count} reports made, each exactly at the step and in the order derived (a final after the deadline from the own revoke's revoked_at_ms or issued_at, clamped and lowered by every learn, or at its last covered host; its not_before the reports of the hosts counted then; none from a learn or a tick); {checked} sends, starts, refusals, drops and stops, each the derived one",
        "; ".join(wrong),
    )


# ------------------------------------------------- r9-vectors-push-hint

# RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305
# (the suite of R9.9), written from the RFC with the `cryptography` package's
# primitives: no code of this repository.
_KEM_SUITE = b"KEM" + (0x0020).to_bytes(2, "big")
_SUITE = b"HPKE" + (0x0020).to_bytes(2, "big") + (0x0001).to_bytes(2, "big") + (0x0003).to_bytes(2, "big")


def _labeled_extract(salt, label, ikm, suite):
    return hmac.new(salt or bytes(32), b"HPKE-v1" + suite + label + ikm, hashlib.sha256).digest()


def _labeled_expand(prk, label, info, length, suite):
    labeled = length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=labeled).derive(prk)


def hpke_derive_key_pair(ikm):
    """DeriveKeyPair for X25519: (secret, public)."""
    prk = _labeled_extract(b"", b"dkp_prk", ikm, _KEM_SUITE)
    secret = _labeled_expand(prk, b"sk", b"", 32, _KEM_SUITE)
    return secret, x25519_public(secret)


def _hpke_schedule(dh, enc_key, recipient_public, info):
    kem_context = enc_key + recipient_public
    eae_prk = _labeled_extract(b"", b"eae_prk", dh, _KEM_SUITE)
    shared = _labeled_expand(eae_prk, b"shared_secret", kem_context, 32, _KEM_SUITE)
    psk_id_hash = _labeled_extract(b"", b"psk_id_hash", b"", _SUITE)
    info_hash = _labeled_extract(b"", b"info_hash", info, _SUITE)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(shared, b"secret", b"", _SUITE)
    return (
        _labeled_expand(secret, b"key", context, 32, _SUITE),
        _labeled_expand(secret, b"base_nonce", context, 12, _SUITE),
    )


def hpke_seal(recipient_public, info, plaintext, ikm_e):
    """Single-shot seal with the ephemeral DeriveKeyPair(ikm_e): (enc, ct)."""
    secret_e, enc_key = hpke_derive_key_pair(ikm_e)
    dh = x25519.X25519PrivateKey.from_private_bytes(secret_e).exchange(
        x25519.X25519PublicKey.from_public_bytes(recipient_public)
    )
    key, nonce = _hpke_schedule(dh, enc_key, recipient_public, info)
    return enc_key, ChaCha20Poly1305(key).encrypt(nonce, plaintext, b"")


def hpke_open(secret, enc_key, ct, info):
    """Single-shot open; raises InvalidTag when it doesn't open."""
    recipient_public = x25519_public(secret)
    dh = x25519.X25519PrivateKey.from_private_bytes(secret).exchange(
        x25519.X25519PublicKey.from_public_bytes(enc_key)
    )
    key, nonce = _hpke_schedule(dh, enc_key, recipient_public, info)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, b"")


PUSH_KEY_FIELDS = ("account_id", "genesis_hash", "host_id", "host_trust_gen")


def push_seal_info(body):
    """The seal `info` (R9.9) of an approval hint, or of an `outcome_unknown`
    hint (11 fields: the kind in the place of the approval's three)."""
    head = [
        "atem-push-seal-v1",
        body["account_id"],
        unhex(body["genesis_hash"]),
        body["host_id"],
        u64(body["host_trust_gen"]),
    ]
    if body.get("kind") == "outcome_unknown":
        middle = ["outcome_unknown", body["alert_id"]]
    else:
        middle = [body["approval_id"], body["session_id"], body["process_gen"]]
    tail = [u64(body["created_at"]), u64(body["expires_at"]), body["recipient"]["device_id"], body["recipient"]["enc_kid"]]
    return enc(head + middle + tail)


UUID_V4 = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"


def delegated_task(facts):
    """Only a delegated sender's task raises an alert (host-work-v1 §11.3):
    a UUID v4 task of a `member:`, `service:` or `host:` sender (an id of
    1-128 bytes of [A-Za-z0-9._:-]), or a host sender's selector task (its
    UUID v5, host-work-v1 §11.5)."""
    sender_ok = re.fullmatch(r"(member|service|host):[A-Za-z0-9._:-]{1,128}", facts["sender"]) is not None
    task = facts["task_id"]
    return sender_ok and (
        re.fullmatch(UUID_V4, task) is not None
        or facts["sender"].startswith("host:") and re.fullmatch(UUID_V5, task) is not None
    )


# Unicode's White_Space property (PropList.txt, Unicode 18.0.0), as
# inclusive code point ranges, written out from the core's generated table
# (`crates/atem-client/src/session/framing/unicode_data.rs`'s WHITE_SPACE,
# made by `scripts/gen-framing-unicode.py`) so this checker doesn't depend on
# Python's own Unicode data: `str.isspace()` is another set (it adds U+001C
# to U+001F). `cargo test -p atem-client --test vectors
# checker_white_space_is_the_framing_modules` holds them equal. An alert's
# reason (host-work-v1 §11.3), a failed resolution's detail (§11.2) and a
# Station's text (session-v1 R9.7b) must each carry something else.
WHITE_SPACE_RANGES = [
    (0x0009, 0x000D), (0x0020, 0x0020), (0x0085, 0x0085), (0x00A0, 0x00A0),
    (0x1680, 0x1680), (0x2000, 0x200A), (0x2028, 0x2029), (0x202F, 0x202F),
    (0x205F, 0x205F), (0x3000, 0x3000),
]
WHITE_SPACE = {chr(c) for a, b in WHITE_SPACE_RANGES for c in range(a, b + 1)}


# General_Category Cf (format characters) of Unicode 18.0.0, as inclusive
# code point ranges: the set the Rust core's `framing::is_format` gives
# (unicode-properties 0.1.5), written out so this checker doesn't depend
# on Python's own Unicode version. `cargo test -p atem-client --test vectors
# checker_format_ranges_are_the_framing_modules` holds them equal.
CF_RANGES = [
    (0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD),
    (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F),
    (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD),
    (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
]


def is_control(c):
    """General_Category Cc (stable since Unicode 1.1): U+0000-001F, U+007F-009F."""
    return ord(c) <= 0x1F or 0x7F <= ord(c) <= 0x9F


def is_format(c):
    """General_Category Cf of Unicode 18.0.0 (CF_RANGES)."""
    return any(a <= ord(c) <= b for a, b in CF_RANGES)


def reason_ok(reason):
    """An outcome_unknown alert's reason (host-work-v1 §11.3): 1-256 bytes,
    not blank (something besides White_Space), no control (Cc) or format
    (Cf) character."""
    return (
        1 <= len(reason.encode()) <= 256
        and any(c not in WHITE_SPACE for c in reason)
        and not any(is_control(c) or is_format(c) for c in reason)
    )


def check_push_hint(file, data, report, context):
    """Push hints (R9.9; delegated host-work I.4.6): every hint's body jcs and
    signing input, the host's signature (by the key the chain names for it),
    `sealed_hash`, `enc_kid`, the seal `info` from the body's fields, the
    sealed part opened with RFC 9180 written here and sealed again from the
    ephemeral to the same `enc` and `ct`; the resolved hint's and the seens'
    signatures; the ack entries of the `outcome_unknown` hints and their
    sealed facts. Verdicts and refusals are the Rust runner's and the binding
    suites' (R9.12)."""
    keys = context["keys"]
    mlog = context["membership_log"]
    entries = {v["label"]: v["entry"]["body"] for v in mlog["log"] + mlog["others"]}
    replay = Replay([entries[label] for label in LOG_L])
    host_alg, host_public = test_key_of(keys, "host-a")
    named = signer_key_in(replay, "host:host-a")
    with report.case(file, "host key") as case:
        case.equal((named["alg"], b64u_decode(named["pub"])), (host_alg, host_public), "host-a's host_key in log L")
        case.equal(data["verifier_now"] > 0, True, "verifier_now")

    secrets = data["recipient_secrets"]
    with report.case(file, "recipient secrets") as case:
        for device, secret in secrets.items():
            case.equal(x25519_public(unhex(secret)), keys.public(device, "enc"), f"{device}'s enc key")

    def check_hint(name, wire, details=None, sealed_expected=True):
        with report.case(file, name) as case:
            case.equal(sorted(wire), ["body", "ct", "enc", "sig"] if "enc" in wire else ["body", "sig"], "wire keys")
            body = wire["body"]
            text = jcs(body)
            case.check(len(text.encode()) <= MAX_BODY_BYTES, "body within 4096 bytes")
            case.equal(body["type"], "atem-push-hint", "type")
            signing_input = enc(["atem-push-hint-v1", text])
            if details is not None:
                case.equal(signing_input.hex(), details["signing_input_hex"], "signing input")
            case.check(verify(host_alg, host_public, b64u_decode(wire["sig"]), signing_input), "host signature")
            if "enc" not in wire:
                return
            enc_bytes, ct = b64u_decode(wire["enc"]), b64u_decode(wire["ct"])
            hash_ok = sha256(enc([enc_bytes, ct])).hex() == body["sealed_hash"]
            if sealed_expected:
                case.check(hash_ok, "sealed_hash = SHA-256(enc([enc, ct]))")
            else:
                case.check(not hash_ok, "sealed_hash names another sealed part")
            device = body["recipient"]["device_id"]
            # (A refused case spells it in upper case: the same 8 bytes.)
            case.equal(enc_kid(keys.public(device, "enc")), body["recipient"]["enc_kid"].lower(), f"{device}'s enc_kid")
            if details is None or not sealed_expected:
                return
            info = push_seal_info(body)
            case.equal(info.hex(), details["info_hex"], "seal info from the body's fields")
            case.equal(sha256(enc([enc_bytes, ct])).hex(), details["sealed_hash"], "sealed_hash")
            case.equal((enc_bytes.hex(), ct.hex()), (details["enc_hex"], details["ct_hex"]), "enc and ct")
            plain = hpke_open(unhex(secrets[device]), enc_bytes, ct, info)
            case.equal(plain.decode(), details["plain_jcs"], f"opens for {device} (RFC 9180, ChaCha20-Poly1305)")
            case.equal(jcs(json.loads(plain, object_pairs_hook=_no_duplicates)), plain.decode(), "the plaintext is canonical")
            other = "dev-mac" if device == "dev-phone" else "dev-phone"
            try:
                hpke_open(unhex(secrets[other]), enc_bytes, ct, info)
                case.fail(f"{other} opened it")
            except Exception:
                case.check(True, f"{other} can't open it")
            resealed = hpke_seal(keys.public(device, "enc"), info, plain, unhex(details["ikmE_hex"]))
            case.equal(resealed, (enc_bytes, ct), "sealed again from ikmE: the same enc and ct")
            if "ikm_label" in details:
                case.equal(sha256(enc(["atem-r9-test-ikm", details["ikm_label"]])).hex(), details["ikmE_hex"], "ikmE from its label")

    for i, (wire, details) in enumerate(zip(data["open"], data["open_details"])):
        check_hint(f"open[{i}]", wire, details)
    for name in ("open_g75", "open_g75001"):
        check_hint(name, data[name], data[f"{name}_details"])
    for i, case_ in enumerate(data["invalid"]):
        # They carry open[0]'s sealed envelope: the same sealed_hash, as the
        # Rust runner's reasons assume.
        check_hint(f"invalid[{i}]", case_["hint"])
    check_hint("resolved", data["resolved"])
    for name, input_hex in (("seen", data["seen_signing_input_hex"]), ("seen_other_process_gen", data["seen_other_process_gen_details"]["signing_input_hex"])):
        with report.case(file, name) as case:
            wire = data[name]
            signing_input = enc(["atem-seen-v1", jcs(wire["body"])])
            case.equal(signing_input.hex(), input_hex, "signing input")
            case.check(verify(host_alg, host_public, b64u_decode(wire["sig"]), signing_input), "host signature")

    # The outcome_unknown hints.
    hints = data["outcome_unknown"]
    for i, (wire, details, ack) in enumerate(zip(hints, data["outcome_unknown_details"], data["outcome_unknown_acks"])):
        check_hint(f"outcome_unknown[{i}]", wire, details)
        with report.case(file, f"outcome_unknown[{i}] facts") as case:
            body = wire["body"]
            case.equal(body["kind"], "outcome_unknown", "kind")
            case.check("state" not in body and "approval_id" not in body, "no approval state or id in the body")
            case.check(
                not any(k in body for k in ("task_id", "session_id", "sender", "reason")),
                "no sealed fact in the clear",
            )
            case.equal(jcs(details["facts"]), details["plain_jcs"], "plain_jcs = jcs of the four facts")
            case.equal(sorted(details["facts"]), ["reason", "sender", "session_id", "task_id"], "exactly the four facts")
            facts = details["facts"]
            case.check(reason_ok(facts["reason"]), "reason within 1-256 bytes, not blank, no control or format character")
            case.check(delegated_task(facts), "a delegated sender's (member:, service: or host:) UUID v4 task")
            case.check(re.fullmatch(r"ses-[a-z2-7]{12}", facts["session_id"]) is not None, "session_id")
            case.check(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", body["alert_id"]) is not None, "alert_id is a UUID v4")
            case.check(0 < body["expires_at"] - body["created_at"] <= 900000, "a window of at most 15 minutes")
            want = {"kind": "outcome_unknown", "device_id": body["recipient"]["device_id"]}
            want.update({k: body[k] for k in PUSH_KEY_FIELDS + ("alert_id",)})
            case.equal(ack, want, "ack entry")
    with report.case(file, "outcome_unknown alerts") as case:
        by_alert = {}
        for wire in hints:
            by_alert.setdefault(wire["body"]["alert_id"], []).append(wire["body"]["recipient"]["device_id"])
        case.equal(sorted(map(len, by_alert.values())), [1, 2], "one alert with two recipients, one with one")
        case.equal(len(data["outcome_unknown_invalid"]) > 0, True, "refused cases")
    for i, case_ in enumerate(data["outcome_unknown_invalid"]):
        wire = case_["hint"]
        # Well-formed and host-signed (their own refusals are the Rust runner's);
        # every one but bad_sealed carries a sealed part its sealed_hash names or
        # the first hint's envelope.
        check_hint(f"outcome_unknown_invalid[{i}]", wire, sealed_expected=(case_["code"] != "bad_sealed"))
    # Well signed and well sealed, but the sealed facts aren't a delegated
    # task's: opened here, they are exactly the stated facts, and they break
    # the rule (the recipient's refusal is the Rust runner's and the suites').
    for i, case_ in enumerate(data["outcome_unknown_invalid_facts"]):
        name = f"outcome_unknown_invalid_facts[{i}]"
        wire = case_["hint"]
        check_hint(name, wire)
        with report.case(file, f"{name} facts") as case:
            body = wire["body"]
            case.equal(case_["code"], "malformed", "refused at open as malformed")
            case.equal(body["kind"], "outcome_unknown", "kind")
            info = push_seal_info(body)
            case.equal(info.hex(), case_["info_hex"], "seal info from the body's fields")
            device = case_["device_id"]
            case.equal(body["recipient"]["device_id"], device, "the recipient")
            plain = hpke_open(unhex(secrets[device]), b64u_decode(wire["enc"]), b64u_decode(wire["ct"]), info)
            case.equal(plain.decode(), jcs(case_["facts"]), "opens to exactly the stated facts")
            case.equal(sorted(case_["facts"]), ["reason", "sender", "session_id", "task_id"], "the four facts")
            delegated, ok = delegated_task(case_["facts"]), reason_ok(case_["facts"]["reason"])
            case.check(not delegated or not ok, "not a delegated sender's UUID v4 task, or a reason that isn't one")
            if delegated:
                # Refused by the blank rule alone: no control or format
                # character a reader might refuse it for instead.
                reason = case_["facts"]["reason"]
                case.check(
                    reason != ""
                    and all(c in WHITE_SPACE for c in reason)
                    and not any(is_control(c) or is_format(c) for c in reason),
                    "a delegated task's blank reason (White_Space only, no control or format character)",
                )
    with report.case(file, "outcome_unknown_invalid_facts: coverage") as case:
        kinds = [delegated_task(c["facts"]) for c in data["outcome_unknown_invalid_facts"]]
        case.check(False in kinds, "a task that isn't a delegated sender's")
        case.check(kinds.count(True) == 1, "the deferred blank-reason case: a delegated task's blank reason (Astation's review of PR 2)")


# R9.2's table of actions, in its order: the eleven of version 1 (v0.8.2 to
# v0.8.5's rules), then delegated host work's five. A verifier of version 2
# knows exactly these (R9.2 "How a verifier reports itself"; Atem's
# proposal, for Astation's agreement).
R9_2_ACTIONS = (
    "genesis", "add", "remove", "set_roles", "add_host", "remove_host", "recovery_add",
    "set_recovery_key", "recovery_approve", "recovery_veto", "k_backup",
    "project_set", "project_remove", "host_sender_revoke", "host_sender_readmit", "host_enc_key",
)
VERIFIER_ACTION = r"[a-z][a-z0-9_]{0,31}"


def verifier_ok(v):
    """A welcome's `verifier` as R9.2 and R9.8 write it: exactly version (1 to
    2^32 - 1) and actions (1-64 names of the grammar, sorted by bytes, each
    once); a name nobody knows is no refusal."""
    if not isinstance(v, dict) or sorted(v) != ["actions", "version"]:
        return False
    version, actions = v["version"], v["actions"]
    if not (isinstance(version, int) and not isinstance(version, bool) and 1 <= version < 2**32):
        return False
    if not isinstance(actions, list) or not 1 <= len(actions) <= 64:
        return False
    if not all(isinstance(a, str) and re.fullmatch(VERIFIER_ACTION, a) is not None for a in actions):
        return False
    names = [a.encode() for a in actions]
    return all(a < b for a, b in zip(names, names[1:]))


def check_delegated_wire(file, data, report, context):
    """Delegated host work's session-v1 shapes (R9.14): host_enc_key_get, its
    host_enc_key answer, host_enc_key_new and its pending answer (the routine
    rotation, agreed with Astation 2026-11-23, #120 comment 7089435308), and
    receipts with and without provenance; and the r9 welcome's optional
    verifier (R9.2, R9.8; Atem's proposal). Each case's verdict is recomputed
    here from the rules as R9.14, R9.8 and R9.2 write them, the valid
    answers' enc_sig is verified with host-a's host_key of log L over the
    enc() input built here, every exchange of host_enc_key_new gets the one
    pending key with its own request echoed, and the release's own verifier
    is R9.2's sixteen actions at version 2."""
    ID = r"[A-Za-z0-9._:-]{1,128}"

    def whole(case):
        text = case["raw"] if "raw" in case else json.dumps(case["message"])
        try:
            return json.loads(text, object_pairs_hook=_no_duplicates)
        except Exception:
            return None

    def session_data(message, keys):
        if not isinstance(message, dict) or sorted(message) != ["data", "type"] or message["type"] != "session":
            return None
        data_ = message["data"]
        if not isinstance(data_, dict) or (keys is not None and sorted(data_) != sorted(keys)):
            return None
        return data_

    def uuid4(v):
        return isinstance(v, str) and re.fullmatch(UUID_V4, v) is not None

    def b64u_len(v, n):
        try:
            return isinstance(v, str) and len(b64u_decode(v)) == n
        except Exception:
            return False

    def get_ok(case):
        data_ = session_data(whole(case), ["v", "op", "id"])
        return data_ is not None and data_["v"] == 1 and data_["op"] == "host_enc_key_get" and uuid4(data_["id"])

    def new_ok(case):
        data_ = session_data(whole(case), ["v", "op", "id", "request_id"])
        return (
            data_ is not None and data_["v"] == 1 and data_["op"] == "host_enc_key_new"
            and uuid4(data_["id"]) and uuid4(data_["request_id"])
        )

    def pending_ok(case):
        # A host_enc_key_new's answer: the get's answer and exactly
        # request_id (a UUID v4) and state "pending".
        message = whole(case)
        data_ = session_data(message, ["v", "op", "id", "re", "request_id", "state", "host_id", "host_trust_gen", "enc_key", "enc_sig"])
        if data_ is None or data_["state"] != "pending" or not uuid4(data_["request_id"]):
            return False
        rest = {k: v for k, v in data_.items() if k not in ("request_id", "state")}
        return key_ok({"message": {"type": "session", "data": rest}})

    def key_ok(case):
        data_ = session_data(whole(case), ["v", "op", "id", "re", "host_id", "host_trust_gen", "enc_key", "enc_sig"])
        if data_ is None:
            return False
        key = data_["enc_key"]
        gen = data_["host_trust_gen"]
        return (
            data_["v"] == 1 and data_["op"] == "host_enc_key" and uuid4(data_["id"]) and uuid4(data_["re"])
            and isinstance(data_["host_id"], str) and re.fullmatch(ID, data_["host_id"]) is not None
            and isinstance(gen, int) and not isinstance(gen, bool) and 1 <= gen < 2**53
            and isinstance(key, dict) and sorted(key) == ["alg", "pub"] and key["alg"] == "x25519"
            and b64u_len(key["pub"], 32) and b64u_len(data_["enc_sig"], 64)
        )

    def receipt_ok(case):
        data_ = session_data(whole(case), None)
        if data_ is None or data_.get("op") != "receipt" or not uuid4(data_.get("id")):
            return False
        has = [k in data_ for k in ("task_id", "sender")]
        if has == [False, False]:
            return True
        if has != [True, True] or data_.get("kind") != "prompt":
            return False
        sender = data_["sender"]
        # A UUID v4 task, or a host sender's selector task (its UUID v5,
        # host-work-v1 §11.5).
        task = data_["task_id"]
        return (
            isinstance(sender, str)
            and re.fullmatch(r"(member|service|host):" + ID, sender) is not None
            and (
                uuid4(task)
                or sender.startswith("host:")
                and isinstance(task, str)
                and re.fullmatch(UUID_V5, task) is not None
            )
        )

    def nat(v):
        return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**53

    def welcome_ok(case):
        # R9.8's welcome as a client reads it: its fields (unknown ones
        # ignored), and `verifier` either absent or exactly as R9.2 says.
        data_ = session_data(whole(case), None)
        if data_ is None or data_.get("op") != "welcome" or data_.get("v") != 1:
            return False
        strings = ("id", "account_id", "atem_device_id", "runtime_gen", "controller_session", "attachment_gen", "principal", "channel_id")
        if not all(isinstance(data_.get(k), str) for k in strings) or "re" in data_ and not isinstance(data_["re"], str):
            return False
        if not all(nat(data_.get(k)) for k in ("host_trust_gen", "authorization_ms_left", "server_time", "revision")):
            return False
        head = data_.get("head")
        if (
            data_.get("client_kind") not in ("native", "service", "browser")
            or not isinstance(data_.get("permissions"), list) or not all(p in ("view", "control") for p in data_["permissions"])
            or not isinstance(data_.get("features"), list) or not all(isinstance(f, str) for f in data_["features"])
            or not isinstance(data_.get("pending_recovery"), list)
            # Head::from_json: exactly seq (from 1) and hash (64 lowercase hex).
            or not isinstance(head, dict) or sorted(head) != ["hash", "seq"]
            or not nat(head["seq"]) or head["seq"] < 1
            or not isinstance(head["hash"], str) or re.fullmatch(r"[0-9a-f]{64}", head["hash"]) is None
        ):
            return False
        return "verifier" not in data_ or verifier_ok(data_["verifier"])

    with report.case(file, "verifier") as case:
        actions = sorted(R9_2_ACTIONS, key=str.encode)
        case.equal(data["verifier"], {"version": 2, "actions": actions}, "this release's verifier: version 2, R9.2's sixteen actions")
        logged = context["membership_log"]
        seen = {v["entry"]["body"].get("action") for v in logged["log"] + logged["others"]}
        case.equal(sorted(seen, key=str.encode), actions, "every action of r9-vectors-membership-log, and only those")
        case.check(verifier_ok(data["verifier"]), "reported by the welcome's rules")
    with report.case(file, "welcome verifier") as case:
        valid = [c for c in data["welcome"] if c["valid"] and "message" in c]
        case.check(any("verifier" not in c["message"]["data"] for c in valid), "a welcome without verifier")
        case.check(any(c["message"]["data"].get("verifier") == data["verifier"] for c in valid), "a welcome with this release's")
        case.check(
            any(set(c["message"]["data"].get("verifier", {}).get("actions", [])) - set(R9_2_ACTIONS) for c in valid),
            "a welcome naming an action this release doesn't know, read",
        )

    for section, rule, rules in (
        ("host_enc_key_get", get_ok, "R9.14's"),
        ("host_enc_key", key_ok, "R9.14's"),
        ("host_enc_key_new", new_ok, "R9.14's"),
        ("host_enc_key_pending", pending_ok, "R9.14's"),
        ("receipt", receipt_ok, "R9.14's"),
        ("welcome", welcome_ok, "R9.8's and R9.2's"),
    ):
        with report.case(file, section) as case:
            cases = data[section]
            case.check(any(c["valid"] for c in cases) and any(not c["valid"] for c in cases), "valid and refused cases")
            for c in cases:
                case.equal(rule(c), c["valid"], f"{c['name']}: {'valid' if c['valid'] else 'refused'} by {rules} rules")

    keys = context["keys"]
    mlog = context["membership_log"]
    entries = {v["label"]: v["entry"]["body"] for v in mlog["log"] + mlog["others"]}
    replay = Replay([entries[label] for label in LOG_L])
    named = signer_key_in(replay, "host:host-a")
    binding = data["host_enc_key_binding"]
    with report.case(file, "host_enc_key binding") as case:
        case.equal(binding["genesis_hash"], context["genesis_hash"].hex(), "log L's genesis")
        for c in data["host_enc_key"]:
            if not c["valid"]:
                continue
            d = c["message"]["data"]
            enc_pub = b64u_decode(d["enc_key"]["pub"])
            signing_input = enc(["atem-host-enc-key-v1", binding["account_id"], unhex(binding["genesis_hash"]), d["host_id"], u64(d["host_trust_gen"]), enc_pub])
            case.equal(signing_input.hex(), binding["enc_sig_input_hex"], f"{c['name']}: enc_sig input")
            case.check(verify(named["alg"], b64u_decode(named["pub"]), b64u_decode(d["enc_sig"]), signing_input), f"{c['name']}: enc_sig by host-a's host_key")
            same = [e for e in mlog["log"] + mlog["others"] if e["entry"]["body"].get("action") == "host_enc_key" and e["entry"]["body"]["enc_key"]["pub"] == d["enc_key"]["pub"]]
            case.check(any(e["entry"]["body"]["enc_sig"] == d["enc_sig"] for e in same), f"{c['name']}: the membership log's host_enc_key pair")

    pending_binding = data["host_enc_key_pending_binding"]

    def pending_binding_ok(case, name, d):
        enc_pub = b64u_decode(d["enc_key"]["pub"])
        signing_input = enc(["atem-host-enc-key-v1", binding["account_id"], unhex(binding["genesis_hash"]), d["host_id"], u64(d["host_trust_gen"]), enc_pub])
        case.equal(signing_input.hex(), pending_binding["enc_sig_input_hex"], f"{name}: enc_sig input")
        case.check(verify(named["alg"], b64u_decode(named["pub"]), b64u_decode(d["enc_sig"]), signing_input), f"{name}: enc_sig by host-a's host_key")
        # A key the log sets later (its second host-a key): pending until then.
        same = [e for e in mlog["log"] + mlog["others"] if e["entry"]["body"].get("action") == "host_enc_key" and e["entry"]["body"]["enc_key"]["pub"] == d["enc_key"]["pub"]]
        case.check(any(e["entry"]["body"]["enc_sig"] == d["enc_sig"] for e in same), f"{name}: a key the membership log's rotation sets")
        case.check(d["enc_key"]["pub"] != data["host_enc_key"][0]["message"]["data"]["enc_key"]["pub"], f"{name}: not the current key")

    with report.case(file, "host_enc_key_pending binding") as case:
        for c in data["host_enc_key_pending"]:
            if c["valid"]:
                pending_binding_ok(case, c["name"], c["message"]["data"])

    with report.case(file, "host_enc_key_new exchanges") as case:
        exchanges = data["host_enc_key_new_exchanges"]
        case.check(len(exchanges) >= 3, "two managers and a retry")
        requests = [x["request"]["data"] for x in exchanges]
        answers = [x["answer"]["data"] for x in exchanges]
        case.check(len({(r["id"]) for r in requests}) == len(requests), "each request its own id")
        case.check(len({r["request_id"] for r in requests}) < len(requests), "a retry: the same request_id under a fresh id")
        case.check(len({r["request_id"] for r in requests}) > 1, "another manager's own request_id")
        for x, r, a in zip(exchanges, requests, answers):
            name = x["name"]
            case.check(new_ok({"message": x["request"]}), f"{name}: the request reads")
            case.check(pending_ok({"message": x["answer"]}), f"{name}: the answer reads")
            case.equal((a["re"], a["request_id"]), (r["id"], r["request_id"]), f"{name}: its own request echoed")
            case.equal((a["enc_key"], a["enc_sig"]), (answers[0]["enc_key"], answers[0]["enc_sig"]), f"{name}: the one pending key")
            others = [o for o in requests if o is not r]
            case.check(all((a["re"], a["request_id"]) != (o["id"], o["request_id"]) for o in others), f"{name}: answers no other request")
            pending_binding_ok(case, name, a)


# ------------------------------------------------- r9-vectors-host-envelope

# Envelopes and results between hosts (delegated host-work II.4.2, II.4.4;
# host-work-v1 §11.5): the body's type -> (signing label, seal label).
MAIL_LABELS = {
    "atem-envelope": ("atem-envelope-v1", "atem-envelope-seal-v1"),
    "atem-result": ("atem-result-v1", "atem-result-seal-v1"),
}
MAIL_BODY_KEYS = sorted(
    [
        "type", "v", "account_id", "genesis_hash", "sender", "recipient", "id",
        "created_at", "expires_at", "signed_at_head", "sealed_hash",
    ]
)
MAX_MESSAGE_BYTES = 240 * 1024  # host-work-v1 §5: a Message's bound, and every other plaintext's
REQUEST_WRAPPER_BYTES = len('{"kind":"request","message":}')  # 29
MAX_MAIL_OBJECT_BYTES = 512 * 1024  # one mailbox call (owner choice 13)
MAX_LIFETIME_MS = 24 * 3600 * 1000
MAX_CREATED_AHEAD_MS = 60_000
MAIL_REFUSAL_CODES = {"forbidden", "unauthorized", "stale_target", "invalid_request", "request_id_reused", "busy"}
UUID_V5 = r"[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
MAIL_HOST_ID = r"[A-Za-z0-9._:-]{1,128}"
HEX64 = r"[0-9a-f]{64}"


def uuid_v5(namespace, name):
    """RFC 9562 UUID version 5: SHA-1 of the namespace's 16 bytes and the
    name, its first 16 bytes with the version (5) and the variant (10) set,
    written lowercase with hyphens."""
    b = bytearray(hashlib.sha1(bytes.fromhex(namespace.replace("-", "")) + name).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x50
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# RFC 9562's NAMESPACE_OID: a reply's result_id and a selector's task ids
# (host-work-v1 §11.5).
NAMESPACE_OID = "6ba7b812-9dad-11d1-80b4-00c04fd430c8"


def result_id_of(task_id):
    """host-work-v1 §11.5, "result_id": UUIDv5(NAMESPACE_OID, "result:" +
    task_id)."""
    return uuid_v5(NAMESPACE_OID, ("result:" + task_id).encode())


def is_uuid(text, version):
    pattern = UUID_V5 if version == 5 else r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    return isinstance(text, str) and re.fullmatch(pattern, text) is not None


def safe_int(n, low=0):
    return type(n) is int and low <= n <= 2**53 - 1


def mail_seal_info(body):
    """The seal's info: the label of the body's type and the fields that bind
    both hosts, the ids and the times (`signed_at_head` is only signed)."""
    seal_label = MAIL_LABELS[body["type"]][1]
    s, r = body["sender"], body["recipient"]
    return enc(
        [
            seal_label,
            body["account_id"],
            unhex(body["genesis_hash"]),
            s["host_id"],
            u64(s["host_trust_gen"]),
            r["host_id"],
            u64(r["host_trust_gen"]),
            r["enc_kid"],
            body["id"],
            u64(body["created_at"]),
            u64(body["expires_at"]),
        ]
    )


def mail_signing_input(body):
    return enc([MAIL_LABELS[body["type"]][0], jcs(body)])


def mail_wire_bytes(wire):
    """The object as one mailbox call carries it (compact JSON)."""
    return json.dumps(wire, separators=(",", ":"), ensure_ascii=False).encode()


def mail_evidence(wire):
    """SHA-256(enc([jcs(body), sig, enc, ct])), enc and ct empty when absent."""
    part = lambda k: b64u_decode(wire[k]) if k in wire else b""
    return sha256(enc([jcs(wire["body"]), b64u_decode(wire["sig"]), part("enc"), part("ct")])).hex()


def mail_well_formed(wire):
    """Check 1's strict reading of a mailbox object: exact fields in their
    grammar, a sealed part of the right shape, a body within 4,096 bytes."""
    try:
        if sorted(wire) != ["body", "ct", "enc", "sig"]:
            return False
        body = wire["body"]
        if not isinstance(body, dict) or sorted(body) != MAIL_BODY_KEYS:
            return False
        if body["type"] not in MAIL_LABELS or body["v"] != 1 or type(body["v"]) is not int:
            return False
        if not (isinstance(body["account_id"], str) and 1 <= len(body["account_id"].encode()) <= 128):
            return False
        for key in ("genesis_hash", "sealed_hash"):
            if not (isinstance(body[key], str) and re.fullmatch(HEX64, body[key])):
                return False
        for host, extra in ((body["sender"], []), (body["recipient"], ["enc_kid"])):
            if not isinstance(host, dict) or sorted(host) != sorted(["host_id", "host_trust_gen"] + extra):
                return False
            if not (isinstance(host["host_id"], str) and re.fullmatch(MAIL_HOST_ID, host["host_id"])):
                return False
            if not safe_int(host["host_trust_gen"], 1):
                return False
        if not (isinstance(body["recipient"]["enc_kid"], str) and re.fullmatch(r"[0-9a-f]{16}", body["recipient"]["enc_kid"])):
            return False
        if not is_uuid(body["id"], 4) or not safe_int(body["created_at"]) or not safe_int(body["expires_at"]):
            return False
        head = body["signed_at_head"]
        if not isinstance(head, dict) or sorted(head) != ["hash", "seq"] or not safe_int(head["seq"], 1):
            return False
        if not (isinstance(head["hash"], str) and re.fullmatch(HEX64, head["hash"])):
            return False
        if len(jcs(body).encode()) > MAX_BODY_BYTES:
            return False
        return len(b64u_decode(wire["enc"])) == 32 and len(b64u_decode(wire["ct"])) >= 16
    except (ValueError, KeyError, TypeError, NotStrict):
        return False


def mail_times(body, now):
    """Check 5: the reason the body's times are refused, else None."""
    created, expires = body["created_at"], body["expires_at"]
    if expires <= created:
        return "bad_times"
    if expires - created > MAX_LIFETIME_MS:
        return "lifetime_too_long"
    if now >= expires:
        return "expired"
    if created > now + MAX_CREATED_AHEAD_MS:
        return "created_too_far_ahead"
    return None


def has_null(value):
    if value is None:
        return True
    if isinstance(value, list):
        return any(has_null(v) for v in value)
    if isinstance(value, dict):
        return any(has_null(v) for v in value.values())
    return False


def snapshot_ok(s, task_id=None):
    """A context snapshot as work_complete takes one (memory or vault); with
    `task_id`, a complete's, also a `result` snapshot naming that task's own
    reply: its id `result:<result_id(task_id)>` (host-work-v1 §11.5, Atem's
    reading for Astation)."""
    if not (
        isinstance(s, dict)
        and sorted(s) == ["digest", "id", "kind", "text", "version"]
        and safe_int(s["version"], 1)
        and isinstance(s["text"], str)
        and s["digest"] == sha256(s["text"].encode()).hex()
    ):
        return False
    if s["kind"] in ("memory", "vault"):
        return True
    return task_id is not None and s["kind"] == "result" and names_reply(s, task_id)


def names_reply(s, task_id):
    """A `result` snapshot naming task `task_id`'s own reply (host-work-v1
    §11.5): id `result:<result_id>`, version 1, its text exactly
    jcs({"digest"?, "result_id", "task_id"}), the digest a SHA-256 hex."""
    rid = result_id_of(task_id)
    try:
        named = json.loads(s["text"])
    except ValueError:
        return False
    if not isinstance(named, dict):
        return False
    keys = sorted(named)
    if keys not in (["result_id", "task_id"], ["digest", "result_id", "task_id"]):
        return False
    if "digest" in named and not (isinstance(named["digest"], str) and re.fullmatch(HEX64, named["digest"])):
        return False
    return (
        s["id"] == "result:" + rid
        and s["version"] == 1
        and named["result_id"] == rid
        and named["task_id"] == task_id
        and s["text"] == jcs(named)
    )


def reply_ok(r):
    """A reply as reply_query returns it once submitted, still kept."""
    return (
        isinstance(r, dict)
        and set(r) in ({"result_id", "state", "digest", "text", "context", "dropped"}, {"result_id", "state", "digest", "text", "context", "submitted_at", "dropped"})
        and is_uuid(r["result_id"], 5)
        and r["state"] == "submitted"
        and safe_int(r.get("submitted_at"))
        and r["dropped"] is False
        # Its format only, as the core checks it: the runtime's digest covers
        # more than the text.
        and isinstance(r["digest"], str)
        and re.fullmatch(HEX64, r["digest"]) is not None
        and isinstance(r["context"], list)
        and all(snapshot_ok(s) for s in r["context"])
    )


# host-work-v1 §4 "Status": a task's states; `detail` at most 1024 bytes.
WORK_STATES = {
    "queued", "blocked", "submitting", "submitted", "awaiting_result",
    "completed", "failed", "cancelled", "expired", "outcome_unknown",
}
MAX_SELECT_AGENTS = 32  # one message reaches at most 32 agents (collaboration §5)


def work_receipt_ok(w):
    """A §5 `work` receipt as a sealed plaintext carries it: task_id,
    receipt_id (UUID v4), state, detail, and `result` (a reference {kind, id,
    version, digest}) exactly when completed, omitted while null."""
    if not isinstance(w, dict):
        return False
    keys = sorted(w)
    if keys not in (["detail", "receipt_id", "state", "task_id"], ["detail", "receipt_id", "result", "state", "task_id"]):
        return False
    if not (is_uuid(w["receipt_id"], 4) and w["state"] in WORK_STATES):
        return False
    if not (isinstance(w["detail"], str) and len(w["detail"].encode()) <= 1024):
        return False
    if ("result" in w) != (w["state"] == "completed"):
        return False
    r = w.get("result")
    # A task its host sender completed with the reply it got back carries
    # that `result` snapshot's reference, naming its own reply (host-work-v1
    # §11.5).
    own = isinstance(r, dict) and r.get("id") == "result:" + result_id_of(w["task_id"])
    return r is None or (
        isinstance(r, dict)
        and sorted(r) == ["digest", "id", "kind", "version"]
        and r["kind"] in (("memory", "vault", "result") if own else ("memory", "vault"))
        and safe_int(r["version"], 1)
        and isinstance(r["digest"], str)
        and re.fullmatch(HEX64, r["digest"]) is not None
    )


def delivery_ok(recipient_id, d):
    """One recipient's delivery in a status object (host-work-v1 §5
    "Publish", and §11.5 "Status forms of a selector's resolution"):
    stored; refused with a code a receipt carries; work, its task the
    recipient's own; no_match, exactly {state}; resolved, 1 to 32 work
    receipts each naming a distinct selector task (a UUID v5), never the
    recipient's id."""
    if not isinstance(d, dict):
        return False
    state = d.get("state")
    if state == "stored":
        return sorted(d) == ["state"]
    if state == "refused":
        return sorted(d) == ["code", "state"] and d["code"] in ("forbidden", "stale_target")
    if state == "work":
        return sorted(d) == ["state", "work"] and work_receipt_ok(d["work"]) and d["work"]["task_id"] == recipient_id
    if state == "no_match":
        return sorted(d) == ["state"]
    if state == "resolved":
        tasks = d.get("tasks")
        if sorted(d) != ["state", "tasks"] or not isinstance(tasks, list) or not 1 <= len(tasks) <= MAX_SELECT_AGENTS:
            return False
        if not all(work_receipt_ok(t) and is_uuid(t["task_id"], 5) for t in tasks):
            return False
        ids = [t["task_id"] for t in tasks]
        return len(set(ids)) == len(ids) and recipient_id not in ids
    return False


def receipts_ok(recipients):
    ids = [r.get("recipient_id") for r in recipients if isinstance(r, dict)]
    return (
        isinstance(recipients, list)
        and 1 <= len(recipients)
        and len(ids) == len(recipients) == len(set(ids))
        and all(is_uuid(i, 4) for i in ids)
        and all(
            sorted(r) == ["delivery", "recipient_id"]
            and delivery_ok(r["recipient_id"], r["delivery"])
            for r in recipients
        )
    )


def mail_plaintext(kind, plain):
    """Step 6's strict reading of a plaintext: (reason, value). Strict I-JSON
    with no null, one of the shapes with exactly its fields, within its bound
    (a request's Message 240 KiB, so its plaintext 29 bytes more; every other
    plaintext 240 KiB) and nothing but its canonical form."""
    bound = MAX_MESSAGE_BYTES + (REQUEST_WRAPPER_BYTES if kind == "atem-envelope" else 0)
    if len(plain) > bound:
        return "plaintext_too_large", None
    try:
        text = plain.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_float=_no_float, parse_constant=_no_constant)
    except (ValueError, NotStrict):
        return "plaintext_malformed", None
    if has_null(value):
        return "plaintext_null", None
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        return "plaintext_malformed", None
    shape = sorted(value)
    k = value["kind"]
    if kind == "atem-envelope":
        task_ok = lambda t: is_uuid(t, 4) or is_uuid(t, 5)
        if k == "request" and shape == ["kind", "message"] and isinstance(value["message"], dict):
            if len(jcs(value["message"]).encode()) > MAX_MESSAGE_BYTES:
                return "plaintext_too_large", None
        elif k == "cancel" and shape == ["kind", "task_id"] and task_ok(value["task_id"]):
            pass
        elif k == "complete" and shape == ["kind", "result", "task_id"] and task_ok(value["task_id"]) and snapshot_ok(value["result"], value["task_id"]):
            pass
        else:
            return "plaintext_malformed", None
    else:
        if k == "status" and "object_id" in value:
            ok = shape == ["kind", "object_id", "refused"] and is_uuid(value["object_id"], 4) and value["refused"] in MAIL_REFUSAL_CODES
        elif k == "status":
            ok = shape == ["kind", "message_id", "recipients"] and is_uuid(value["message_id"], 4) and receipts_ok(value["recipients"])
        elif k == "result":
            ok = shape == ["kind", "reply", "task_id"] and (is_uuid(value["task_id"], 4) or is_uuid(value["task_id"], 5)) and reply_ok(value["reply"])
        else:
            ok = False
        if not ok:
            return "plaintext_malformed", None
    if not (kind == "atem-envelope" and k == "request") and len(plain) > MAX_MESSAGE_BYTES:
        return "plaintext_too_large", None
    if jcs(value) != text:
        return "plaintext_malformed", None
    return None, value


class MailList:
    """What a receiver's device list says about hosts, replayed from its
    entries (log L and a chain): current and removed hosts with the key of
    their newest add_host, the seq of each (host, generation)'s add_host, the
    sending state (authorized(g) at the first add_host or a readmit, revoked
    at a revoke; a removal keeps it), and each entry's hash."""

    def __init__(self, account_id, genesis_hash, vectors):
        self.account_id, self.genesis_hash = account_id, genesis_hash
        self.current, self.removed, self.add_hosts, self.senders, self.hashes = {}, {}, {}, {}, {}
        self.head = 0
        for vector in vectors:
            body = vector["entry"]["body"]
            seq, action = body["seq"], body["action"]
            self.head = seq
            self.hashes[seq] = vector["entry_hash"]
            if action == "add_host":
                host = body["host"]
                self.current[host["host_id"]] = (host["host_trust_gen"], b64u_decode(host["host_key"]["pub"]))
                self.removed.pop(host["host_id"], None)
                self.add_hosts[(host["host_id"], host["host_trust_gen"])] = seq
                self.senders.setdefault(host["host_id"], ("authorized", seq))
            elif action == "remove_host":
                self.removed[body["host_id"]] = self.current.pop(body["host_id"])
            elif action == "host_sender_revoke":
                self.senders[body["host_id"]] = ("revoked", seq)
            elif action == "host_sender_readmit":
                self.senders[body["host_id"]] = ("authorized", seq)


def mail_verdict(wire, call, hosts, receiver_keys, generated, receiver, now, outbox):
    """The receiver's verdict on a mailbox object (II.4.2 checks 1 to 6, and
    for a result II.4.4's), from the spec: (verdict, opened plaintext).
    `receiver_keys` maps each kid it accepts to its secret; `generated` is
    every kid it made at its generation."""
    body = wire.get("body")
    envelope = call == "open_envelope"

    def refused(reason):
        return {"verdict": "refused", "reason": reason, "evidence": mail_evidence(wire)}, None

    def authenticated(reason):
        # The claim is the sender's whose newest add_host key verified the
        # copy: (host_id, that add_host's generation).
        return {
            "verdict": "refused_authenticated",
            "object_id": body["id"],
            "reason": reason,
            "sender": {"host_id": sid, "host_trust_gen": newest},
        }, None

    # 1. Strict parse and pin.
    if not mail_well_formed(wire):
        return refused("malformed")
    if body["type"] != ("atem-envelope" if envelope else "atem-result"):
        return refused("wrong_kind")
    if (body["account_id"], body["genesis_hash"]) != (hosts.account_id, hosts.genesis_hash):
        return refused("pin_mismatch")
    # 2. The recipient: this host, its current generation, a key it accepts.
    recipient = body["recipient"]
    if recipient["host_id"] != receiver["host_id"]:
        return refused("not_for_this_host")
    if recipient["host_trust_gen"] != receiver["host_trust_gen"]:
        return refused("recipient_generation_not_current")
    # The key part waits when the head is beyond this host's and the key is
    # one it made: its own new host_enc_key may be in the entries it lacks.
    head = body["signed_at_head"]
    ahead = head["seq"] > hosts.head
    secret = receiver_keys.get(recipient["enc_kid"])
    if secret is None and not ahead:
        return refused("enc_key_not_accepted")
    # 3. The sender (a result's: only the host the outbox row went to).
    sender = body["sender"]
    sid, sgen = sender["host_id"], sender["host_trust_gen"]
    if outbox is not None and (sid, sgen) != (outbox["recipient"]["host_id"], outbox["recipient"]["host_trust_gen"]):
        return refused("not_the_recipient")
    signing_input = mail_signing_input(body)
    sig = b64u_decode(wire["sig"])

    def wait(key):
        # Beyond this head: the body's times first, then (a pair this list
        # holds has one key forever) the copy, signed and intact, then pending.
        reason = mail_times(body, now)
        if reason:
            return refused(reason)
        # Verified means signed and intact: a variant of the sender's
        # object can't take a waiting slot either.
        if key is not None and not verify("ed25519", key, sig, signing_input):
            return refused("bad_signature")
        if key is not None and sha256(enc([b64u_decode(wire["enc"]), b64u_decode(wire["ct"])])).hex() != body["sealed_hash"]:
            return refused("sealed_hash_mismatch")
        # Every host_enc_key entry for this host carries its own enc_sig, so
        # a key it never made can never become one it accepts: no wait.
        if secret is None and recipient["enc_kid"] not in generated:
            return refused("enc_key_not_accepted")
        return {"verdict": "pending", "host_id": sid, "host_trust_gen": sgen}, None

    removed = sid not in hosts.current
    known = hosts.current.get(sid) or hosts.removed.get(sid)
    if known is None:
        return wait(None) if ahead else refused("unknown_sender")
    newest, key = known
    if sgen < newest:
        return refused("stale_sender_generation")
    generation_ahead = sgen > newest
    state, at = hosts.senders[sid]
    if not ahead:
        if removed and (envelope or generation_ahead):
            return refused("removed_sender")
        if generation_ahead:
            return refused("generation_ahead")
        if state == "revoked" and envelope:
            return refused("revoked_sender")
        if state == "authorized" and head["seq"] < at:
            return refused("signed_at_head_before_generation")
        added = hosts.add_hosts.get((sid, sgen))
        if added is None or added > head["seq"]:
            return refused("generation_ahead")
        if hosts.hashes.get(head["seq"]) != head["hash"]:
            return refused("signed_at_head_wrong_hash")
    if ahead:
        # A removed host's generation never returns (add_host generations
        # strictly rise): its envelope at that generation is refused at any
        # head, after the body's times. Its result waits, to be kept as data.
        if removed and envelope and not generation_ahead:
            return refused(mail_times(body, now) or "removed_sender")
        return wait(None if generation_ahead else key)
    standing = "revoked" if state == "revoked" else "removed" if removed else "current"
    if secret is None:
        return refused("enc_key_not_accepted")
    # 4. The signature, with the key of the sender's newest add_host, and the
    # sealed part it names: a copy whose enc and ct the signed sealed_hash
    # doesn't name isn't the sender's, so it is refused unauthenticated.
    if not verify("ed25519", key, sig, signing_input):
        return refused("bad_signature")
    enc_bytes, ct = b64u_decode(wire["enc"]), b64u_decode(wire["ct"])
    if sha256(enc([enc_bytes, ct])).hex() != body["sealed_hash"]:
        return refused("sealed_hash_mismatch")
    # 5. The times (the copy is the sender's, intact, now).
    reason = mail_times(body, now)
    if reason:
        return authenticated(reason)
    # 6. The open, the plaintext.
    try:
        plain = hpke_open(secret, enc_bytes, ct, mail_seal_info(body))
    except Exception:
        return authenticated("open_failed")
    reason, value = mail_plaintext(body["type"], plain)
    if reason:
        return authenticated(reason)
    principal = "host:" + sid
    if envelope:
        if value["kind"] == "request":
            message = value["message"]
            if (message.get("message_id"), message.get("created_at"), message.get("expires_at"), message.get("sender")) != (
                body["id"], body["created_at"], body["expires_at"], principal
            ):
                return authenticated("plaintext_mismatch")
            # No attachments in this version: no mark (a task's attachments
            # are its message's mark).
            if "mark" in message:
                return authenticated("attachments_not_allowed")
            # A host sender's Message (the part of valid_from_host written here).
            if message.get("kind", "request") != "request" or "reply_to" in message or "from_session" in message:
                return authenticated("invalid_message")
        return {"verdict": "open", "sender": principal}, plain
    # A reply names its task (host-work-v1 §11.5, "result_id"): checked with
    # the plaintext, before the outbox row.
    if value["kind"] == "result" and value["reply"]["result_id"] != result_id_of(value["task_id"]):
        return authenticated("result_id_mismatch")
    answers = (
        value.get("message_id") == outbox["message_id"]
        if value["kind"] == "status" and "message_id" in value
        else value["object_id"] in [outbox["message_id"]] + outbox["cancel_complete_ids"]
        if value["kind"] == "status"
        else value["task_id"] in outbox["task_ids"]
    )
    if not answers:
        return authenticated("does_not_answer_outbox_row")
    if standing == "current":
        return {"verdict": "accepted", "sender": principal}, plain
    detail = f"result not delivered: sender {standing}"
    return {"verdict": "not_delivered", "sender": principal, "reason": detail}, plain


def check_host_envelope(file, data, report, context):
    """Envelopes and results between hosts (delegated host-work II.4.2,
    II.4.4; host-work-v1 §11.5). The entries: chained on log L, hashed and
    signed by dev-mac, each enc_sig by the host. Each object: its body's jcs
    and size, the signing input, the signature (by the test key it names, by
    nobody over a body changed after signing), `info` from the body's fields,
    `sealed_hash`, the open with the recipient key, the plaintext and its
    bounds, the seal again from ikmE to the same enc and ct, and the object's
    size on the wire. Each check: the verdict and reason (and an
    authenticated refusal's sender) recomputed from the bytes, the device
    list (L + chain) and the receiver (the keys it accepts and every key it
    made), written here from the spec, and the plaintext an open gives."""
    keys = context["keys"]
    mlog = context["membership_log"]
    log_l = mlog["log"]
    account_id, genesis = data["account_id"], data["genesis_hash"]
    entries = {v["label"]: v for v in data["entries"]}
    objects = {v["label"]: v for v in data["objects"]}
    dev_mac = b64u_decode(log_l[0]["entry"]["body"]["member"]["auth_key"]["pub"])

    with report.case(file, "account") as case:
        case.equal((account_id, genesis), (mlog["account_id"], mlog["genesis_hash"]), "log L's account and genesis")
        case.check(len(entries) == len(data["entries"]) and len(objects) == len(data["objects"]), "labels used once")

    def chain_of(labels):
        return log_l + [entries[label] for label in labels]

    for vector in data["entries"]:
        with report.case(file, vector["label"]) as case:
            body = vector["entry"]["body"]
            before = chain_of(vector["chain"])
            text = jcs(body)
            case.check(len(text.encode()) <= MAX_BODY_BYTES, "body within 4096 bytes")
            case.equal(sha256(enc(["atem-membership-hash-v1", text])).hex(), vector["entry_hash"], "entry_hash")
            case.equal((body["seq"], body["prev_hash"]), (len(before) + 1, before[-1]["entry_hash"]), "follows L + chain")
            case.equal((body["account_id"], body["genesis_hash"], body["signer"]), (account_id, genesis, "dev-mac"), "account, genesis, signer")
            signing_input = enc(["atem-membership-entry-v1", text])
            case.check(verify("p256", dev_mac, b64u_decode(vector["entry"]["sig"]), signing_input), "p256 signature by dev-mac")
            hosts = MailList(account_id, genesis, before)
            if body["action"] == "add_host":
                host = body["host"]
                name = host_key_name(host["host_id"], host["host_trust_gen"])
                case.equal(b64u_decode(host["host_key"]["pub"]), keys.public(name, "host_key"), f"the host key {name}")
            if body["action"] == "host_enc_key":
                enc_pub = b64u_decode(body["enc_key"]["pub"])
                case.check(keys.name_of(enc_pub) is not None, f"enc_key is a test key ({keys.name_of(enc_pub)})")
                enc_input = enc(["atem-host-enc-key-v1", account_id, unhex(genesis), body["host_id"], u64(body["host_trust_gen"]), enc_pub])
                gen, host_key = hosts.current[body["host_id"]]
                case.equal(gen, body["host_trust_gen"], "the host's newest generation")
                case.check(verify("ed25519", host_key, b64u_decode(body["enc_sig"]), enc_input), "enc_sig by the host's key")

    plaintexts = {}
    for vector in data["objects"]:
        label = vector["label"]
        with report.case(file, label) as case:
            wire = vector["object"]
            body = wire["body"]
            text = jcs(body)
            case.equal(text, vector["jcs"], "jcs")
            case.check(len(text.encode()) <= MAX_BODY_BYTES, "body within 4096 bytes")
            case.equal(vector["kind"], {"atem-envelope": "envelope", "atem-result": "result"}[body["type"]], "kind")
            signing_input = mail_signing_input(body)
            case.equal(signing_input.hex(), vector["signing_input_hex"], "signing input")
            size = len(mail_wire_bytes(wire))
            case.check(size <= MAX_MAIL_OBJECT_BYTES, f"{size} bytes on the wire, within a 512 KiB mailbox call")
            sig = b64u_decode(wire["sig"])
            if "signed_with" in vector:
                case.check(verify("ed25519", keys.public(vector["signed_with"], "host_key"), sig, signing_input), f"ed25519 signature by {vector['signed_with']}")
            if "edited_from" in vector:
                source = objects[vector["edited_from"]]
                case.equal(wire["sig"], source["object"]["sig"], f"{source['label']}'s signature")
                signer = keys.public(source["signed_with"], "host_key")
                if body != source["object"]["body"]:
                    case.check(not verify("ed25519", signer, sig, signing_input), "it signs another body")
                else:
                    case.check(wire.get("ct") != source["object"].get("ct"), "the sealed part changed after signing")
            if "sealed_from" in vector:
                source = objects[vector["sealed_from"]]["object"]
                case.equal((wire["enc"], wire["ct"]), (source["enc"], source["ct"]), f"{vector['sealed_from']}'s sealed part")
            sealed = vector.get("sealed")
            if sealed is None:
                continue
            to = sealed["to"]
            case.equal(enc_kid(keys.public(to, "enc")), body["recipient"]["enc_kid"], f"enc_kid of {to}")
            info = mail_seal_info(body)
            case.equal(info.hex(), sealed["info_hex"], "seal info from the body's fields")
            enc_bytes, ct = b64u_decode(wire["enc"]), b64u_decode(wire["ct"])
            sealed_hash = sha256(enc([enc_bytes, ct])).hex()
            case.equal((sealed_hash, sealed_hash), (sealed["sealed_hash"], body["sealed_hash"]), "sealed_hash = SHA-256(enc([enc, ct]))")
            ikm = sha256(enc(["atem-r9-test-ikm", sealed["ikm_label"]]))
            case.equal(ikm.hex(), sealed["ikmE_hex"], "ikmE from its label")
            plain = hpke_open(unhex(keys.keys[to]["enc"]["secret_hex"]), enc_bytes, ct, info)
            if "plaintext" in sealed:
                case.equal(plain.decode(), sealed["plaintext"], f"opens for {to} (RFC 9180, ChaCha20-Poly1305)")
            else:
                case.equal((len(plain), sha256(plain).hex()), (sealed["plaintext_bytes"], sealed["plaintext_sha256"]), f"opens for {to}: its length and SHA-256")
            case.equal(hpke_seal(keys.public(to, "enc"), info, plain, ikm), (enc_bytes, ct), "sealed again from ikmE: the same enc and ct")
            plaintexts[label] = plain
            # The objects at the bounds: a Message of exactly 240 KiB in its
            # 29-byte wrapper, and one a byte longer.
            at_bound = {"request_max": 0, "request_over": 1}
            if label in at_bound:
                message_size = len(jcs(json.loads(plain)["message"]).encode())
                want = MAX_MESSAGE_BYTES + at_bound[label]
                case.equal((message_size, len(plain)), (want, want + REQUEST_WRAPPER_BYTES), "Message and plaintext at the bound")
            if vector["built"]:
                reason, _ = mail_plaintext(body["type"], plain)
                case.equal(reason, None, "a builder's plaintext: strict, canonical, within its bound")

    for check in data["checks"]:
        with report.case(file, f"check {check['label']}") as case:
            hosts = MailList(account_id, genesis, chain_of(check["chain"]))
            receiver = check["receiver"]
            receiver_keys = {enc_kid(keys.public(name, "enc")): unhex(keys.keys[name]["enc"]["secret_hex"]) for name in receiver["keys"]}
            generated = {enc_kid(keys.public(name, "enc")) for name in receiver["generated"]}
            wire = objects[check["object"]]["object"]
            got, plain = mail_verdict(wire, check["call"], hosts, receiver_keys, generated, receiver, check["now"], check.get("outbox"))
            case.equal(got, check["expect"], f"{check['call']} on L + {len(check['chain'])}: {got['verdict']} {got.get('reason', '')}")
            if plain is not None:
                case.equal(plain, plaintexts.get(check["object"]), "the plaintext the object sealed")
    with report.case(file, "coverage") as case:
        reasons = {c["expect"].get("reason") for c in data["checks"]} - {None}
        verdicts = {c["expect"]["verdict"] for c in data["checks"]}
        case.equal(verdicts, {"open", "pending", "refused", "refused_authenticated", "accepted", "not_delivered"}, "every verdict")
        case.check(len(reasons) >= 31, f"{len(reasons)} reasons")
        case.check("result_id_mismatch" in reasons, "result_id_mismatch")
        # A result failing both the result_id check and the row's: its
        # reply names another task's result_id, and the row doesn't list
        # its task. The result_id check runs first (Atem's reading, agreed).
        both = []
        for c in data["checks"]:
            plain = plaintexts.get(c["object"])
            if c["call"] != "accept_result" or plain is None:
                continue
            value = json.loads(plain)
            if value.get("kind") != "result":
                continue
            if value["reply"]["result_id"] != result_id_of(value["task_id"]) and value["task_id"] not in c["outbox"]["task_ids"]:
                both.append((c["label"], c["expect"].get("reason")))
        case.check(both and all(reason == "result_id_mismatch" for _, reason in both), f"a result failing both checks is result_id_mismatch ({both})")
    with report.case(file, "status forms") as case:
        forms = set()
        for v in data["objects"]:
            plain = v.get("sealed", {}).get("plaintext")
            if v["kind"] == "result" and plain is not None:
                value = json.loads(plain)
                for r in value.get("recipients", []):
                    forms.add(r["delivery"]["state"])
        case.check({"no_match", "resolved"} <= forms, f"a status carries each selector form ({sorted(forms)})")
        resolved = json.loads(objects["status_resolved"]["sealed"]["plaintext"])
        task = resolved["recipients"][0]["delivery"]["tasks"][0]["task_id"]
        name = json.dumps([resolved["message_id"], resolved["recipients"][0]["recipient_id"], "ses-ab23cd45ef67"], separators=(",", ":"))
        case.equal(task, uuid_v5(NAMESPACE_OID, name.encode()), "the example's task is the selector task id of session ses-ab23cd45ef67")
    with report.case(file, "result_id") as case:
        # host-work-v1 §11.5's examples of the derivation.
        case.equal(
            [result_id_of("22222222-2222-4222-8222-222222222222"), result_id_of("80160896-4fcd-5e6e-adac-98bac5497321")],
            ["005c9723-949b-57f6-bfb1-db9b896dcfed", "996a448a-cf99-5e86-aa67-7f9a582a7eaa"],
            "UUIDv5(NAMESPACE_OID, \"result:\" + task_id), the contract's examples",
        )


# ------------------------------------------------ r9-vectors-station-calls

# The Station calls of host-work-v1 §11.4 (design I.5.8): a reader written
# from the spec's "Every message is read strictly" rules, the grammars and
# bounds of the wire rules 1 to 9, and the refusals. No code of this
# repository: the file's every text is read by it, valid and refused.
RELAY_MAX_BYTES = 262144  # R9.9: every relay message, as sent, before any parse
RELAY_MAX_ITEMS = 64  # records, results, feeds and entries (wire rule 1)
RELAY_MAX_DEPTH = 128  # the strict parser's nesting bound
SAFE_MAX = 2**53 - 1
RELAY_ID = r"[A-Za-z0-9._:-]{1,128}"
RELAY_EFFECTS = ["revocation", "interrupt", "hold", "release", "cover"]
RELAY_RESULTS = ["applied", "duplicate", "pending", "refused"]
# Wire rule 3 and 4: the effects a record's result names, in this order; a
# host sender's revoke entry's.
RECORD_EFFECT_SETS = [["cover"], ["revocation"], ["revocation", "interrupt"], ["hold"], ["release"], ["interrupt"]]
ENTRY_EFFECT_SETS = [["revocation"], ["revocation", "interrupt"]]
STATION_TO_HOST_OPS = ["control_sync_result", "heads", "membership_fetch_result", "control_sync_refused", "membership_fetch_refused", "control_ack_refused"]
HOST_TO_STATION_OPS = ["control_sync", "control_ack", "membership_fetch"]


class Refused(Exception):
    """A reader's refusal, with the code it gives."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def relay_parse(text):
    """One strict I-JSON parse: no duplicate key, integers only and at most
    2^53 - 1, no lone surrogate, nesting within the bound."""

    def safe_int(digits):
        n = int(digits)
        if abs(n) > SAFE_MAX:
            raise NotStrict(f"unsafe integer {digits}")
        return n

    value = json.loads(
        text,
        object_pairs_hook=_no_duplicates,
        parse_float=_no_float,
        parse_int=safe_int,
        parse_constant=_no_constant,
    )

    def walk(v):
        if isinstance(v, str):
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in v):
                raise NotStrict("lone surrogate")
        elif isinstance(v, list):
            for item in v:
                walk(item)
        elif isinstance(v, dict):
            for key, item in v.items():
                walk(key)
                walk(item)

    # Nesting counts containers: the message's own object is the first.
    def container_depth(v):
        if isinstance(v, list):
            return 1 + max((container_depth(i) for i in v), default=0)
        if isinstance(v, dict):
            return 1 + max((container_depth(i) for i in v.values()), default=0)
        return 0

    if container_depth(value) > RELAY_MAX_DEPTH:
        raise NotStrict("nesting too deep")
    walk(value)
    return value


def relay_origin_ok(origin):
    """An origin exact as station_route::normalize_relay writes it: https, or
    http on a loopback IP literal; a lowercase host; a port only when it
    isn't the scheme's default; no credentials, path, query or fragment."""
    if not isinstance(origin, str) or not origin.isascii() or len(origin) > 1024:
        return False
    m = re.fullmatch(r"(https|http)://(\[::1\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*)(?::([0-9]{1,5}))?", origin)
    if m is None:
        return False
    scheme, host, port = m.groups()
    if port is not None:
        if port.startswith("0") or not 1 <= int(port) <= 65535 or int(port) == {"https": 443, "http": 80}[scheme]:
            return False
    if scheme == "http":
        return host == "[::1]" or (re.fullmatch(r"127(?:\.[0-9]{1,3}){3}", host) is not None and all(int(p) <= 255 for p in host.split(".")))
    return True


def _relay_exact(obj, allowed):
    """An object with only the fields `allowed` names (its absent ones are the caller's)."""
    if not isinstance(obj, dict):
        raise Refused("malformed")
    if any(key not in allowed for key in obj):
        raise Refused("unknown_field")
    return obj


def _relay_text(obj, key):
    value = obj.get(key)
    if not isinstance(value, str):
        raise Refused("malformed")
    return value


def _relay_uint(obj, key):
    value = obj.get(key)
    if type(value) is not int or value < 0:
        raise Refused("malformed")
    return value


def _relay_array(obj, key, most):
    items = obj.get(key)
    if not isinstance(items, list):
        raise Refused("malformed")
    if len(items) > most:
        raise Refused("too_large")
    return items


def _relay_hex32(text):
    if re.fullmatch(HEX64, text) is None:
        raise Refused("malformed")
    return text


def _relay_head(value):
    head = _relay_exact(value, ["seq", "hash"])
    seq = _relay_uint(head, "seq")
    _relay_hex32(_relay_text(head, "hash"))
    if seq < 1:
        raise Refused("malformed")
    return head


def _relay_origin(text):
    if not relay_origin_ok(text):
        raise Refused("malformed")


def _relay_uuid4(text):
    if re.fullmatch(UUID_V4, text) is None:
        raise Refused("malformed")


def _read_control_sync(v):
    _relay_exact(v, ["type", "op", "request_id", "origin", "feed_id", "after"])
    # Correlation (amended in place, #164 comment 6858189009): the call's id,
    # required, a lowercase UUID v4.
    _relay_uuid4(_relay_text(v, "request_id"))
    origin = _relay_text(v, "origin")
    feed = v.get("feed_id") if "feed_id" in v else None
    if "feed_id" in v and not isinstance(feed, str):
        raise Refused("malformed")  # an optional field is omitted, never null
    after = _relay_uint(v, "after")
    _relay_origin(origin)
    if feed is not None:
        _relay_uuid4(feed)
    elif after != 0:
        raise Refused("malformed")  # wire rule 2: a cursor belongs to a feed


def _read_control_sync_result(v):
    _relay_exact(v, ["type", "op", "request_id", "origin", "feed_id", "after", "head", "station_time", "records"])
    items = _relay_array(v, "records", RELAY_MAX_ITEMS)
    seqs = []
    for item in items:
        _relay_exact(item, ["feed_seq", "record"])
        if "record" not in item:
            raise Refused("malformed")  # of any JSON type, but there
        seqs.append(_relay_uint(item, "feed_seq"))
    # Correlation: the call's id as it sent it, and its `after`, echoed.
    _relay_uuid4(_relay_text(v, "request_id"))
    after = _relay_uint(v, "after")
    origin, feed = _relay_text(v, "origin"), _relay_text(v, "feed_id")
    head = _relay_uint(v, "head")
    _relay_uint(v, "station_time")
    _relay_origin(origin)
    _relay_uuid4(feed)
    # Wire rule 7: strictly after the echoed `after`, ascending, none above
    # `head` (gaps legal); with `head` below `after`, no record at all.
    previous = after
    for seq in seqs:
        if seq <= previous or seq > head:
            raise Refused("malformed")
        previous = seq


def _read_heads(v):
    _relay_exact(v, ["type", "op", "feeds", "membership"])
    feeds = []
    for item in _relay_array(v, "feeds", RELAY_MAX_ITEMS):
        _relay_exact(item, ["origin", "feed_id", "head", "station_time"])
        origin, feed = _relay_text(item, "origin"), _relay_text(item, "feed_id")
        _relay_uint(item, "head")
        _relay_uint(item, "station_time")
        _relay_origin(origin)
        _relay_uuid4(feed)
        feeds.append((origin, feed))
    if "membership" not in v:
        raise Refused("malformed")
    _relay_head(v["membership"])
    if len(set(feeds)) != len(feeds):
        raise Refused("malformed")  # wire rule 6: an (origin, feed_id) once


# An effect's reason (O5): 1 to 64 bytes of [a-z0-9_], only beside an
# effect not in force; a code outside the vocabulary is read, unrecognized.
RELAY_WHY = r"[a-z0-9_]{1,64}"


def _relay_effects(result):
    items = result.get("effects")
    if not isinstance(items, list) or not 1 <= len(items) <= 2:
        raise Refused("malformed")
    out = []
    for item in items:
        _relay_exact(item, ["effect", "result", "why"])
        effect, outcome = _relay_text(item, "effect"), _relay_text(item, "result")
        if effect not in RELAY_EFFECTS or outcome not in RELAY_RESULTS:
            raise Refused("malformed")
        if "why" in item:
            why = item["why"]
            if not isinstance(why, str) or re.fullmatch(RELAY_WHY, why) is None:
                raise Refused("malformed")  # null, not a text, empty, over 64 bytes, another character
            if outcome not in ("pending", "refused"):
                raise Refused("malformed")  # a reason says why an effect isn't in force
        out.append((effect, outcome))
    return out


def _read_control_ack(v):
    _relay_exact(v, ["type", "op", "account_id", "genesis_hash", "host_id", "host_trust_gen", "origin", "feed_id", "cursor", "results"])
    parsed = []
    for result in _relay_array(v, "results", RELAY_MAX_ITEMS):
        if not isinstance(result, dict):
            raise Refused("malformed")
        has_record, has_entry = "record_id" in result, "entry" in result
        if has_record == has_entry:
            raise Refused("malformed")  # wire rule 4: exactly one of two forms
        if has_record:
            _relay_exact(result, ["record_id", "effects"])
            record_id, effects = _relay_text(result, "record_id"), _relay_effects(result)
            parsed.append(("record", record_id, None, None, effects))
        else:
            _relay_exact(result, ["entry", "applied_seq", "effects"])
            entry = _relay_exact(result["entry"], ["seq", "entry_hash"])
            seq = _relay_uint(entry, "seq")
            _relay_hex32(_relay_text(entry, "entry_hash"))
            parsed.append(("entry", None, seq, _relay_uint(result, "applied_seq"), _relay_effects(result)))
    account_id = _relay_text(v, "account_id")
    _relay_hex32(_relay_text(v, "genesis_hash"))
    host_id = _relay_text(v, "host_id")
    gen = _relay_uint(v, "host_trust_gen")
    origin, feed = _relay_text(v, "origin"), _relay_text(v, "feed_id")
    _relay_uint(v, "cursor")
    if not 1 <= len(account_id.encode()) <= 128 or re.fullmatch(RELAY_ID, host_id) is None or gen < 1:
        raise Refused("malformed")
    _relay_origin(origin)
    _relay_uuid4(feed)
    records, entries = set(), set()
    for kind, record_id, seq, applied_seq, effects in parsed:
        names = [e for e, _ in effects]
        if kind == "record":
            _relay_uuid4(record_id)
            if names not in RECORD_EFFECT_SETS:
                raise Refused("malformed")  # wire rule 3
            fresh = record_id not in records
            records.add(record_id)
        else:
            if seq < 1 or names not in ENTRY_EFFECT_SETS:
                raise Refused("malformed")
            # wire rule 5: applied or duplicate only once applied_seq reached seq
            if any(o in ("applied", "duplicate") for _, o in effects) and applied_seq < seq:
                raise Refused("malformed")
            fresh = seq not in entries
            entries.add(seq)
        if not fresh:
            raise Refused("malformed")  # wire rule 6: nothing twice


def _read_membership_fetch(v):
    _relay_exact(v, ["type", "op", "after"])
    _relay_uint(v, "after")


def _read_membership_fetch_result(v):
    _relay_exact(v, ["type", "op", "head", "entries"])
    for entry in _relay_array(v, "entries", RELAY_MAX_ITEMS):
        # A signed object: {body, sig}; its body is the device-list checks' (R9.3).
        if not isinstance(entry, dict) or not isinstance(entry.get("body"), dict) or not isinstance(entry.get("sig"), str):
            raise Refused("malformed")
    if "head" not in v:
        raise Refused("malformed")
    _relay_head(v["head"])


def _read_refusal(v):
    _relay_exact(v, ["type", "op", "code"])
    if _relay_text(v, "code") != "forbidden":
        raise Refused("malformed")  # exactly `forbidden` in this version


RELAY_READERS = {
    "to_station": {
        "control_sync": _read_control_sync,
        "control_ack": _read_control_ack,
        "membership_fetch": _read_membership_fetch,
    },
    "to_host": {
        "control_sync_result": _read_control_sync_result,
        "heads": _read_heads,
        "membership_fetch_result": _read_membership_fetch_result,
        "control_sync_refused": _read_refusal,
        "membership_fetch_refused": _read_refusal,
        "control_ack_refused": _read_refusal,
    },
}


def read_relay(text, reader):
    """(message, None) if the reader (`to_station`: a host's calls, `to_host`:
    a Station's messages) reads `text` as sent, else (None, the code it
    refuses it with): the size bound before any parse, one strict parse, a
    relay message of an op this reader reads, then that message's rules."""
    try:
        if len(text.encode("utf-8")) > RELAY_MAX_BYTES:
            raise Refused("too_large")
        try:
            value = relay_parse(text)
        except (NotStrict, ValueError, RecursionError):
            raise Refused("not_strict")
        op = value.get("op") if isinstance(value, dict) and value.get("type") == "relay" else None
        reader_for = RELAY_READERS[reader].get(op) if isinstance(op, str) else None
        if reader_for is None:
            raise Refused("wrong_message")
        reader_for(value)
        return value, None
    except Refused as refused:
        return None, refused.code


def relay_sync_verdict(call, result):
    """Whether the page `result` answers the call `call` (both read): the
    same request_id, origin, feed when the call named one (a call that named
    none, from 0, is answered on whichever feed the page names) and after;
    else the first of those that differs. The link generation, account and
    genesis are the caller's to compare."""
    if result["request_id"] != call["request_id"]:
        return "request_id"
    if result["origin"] != call["origin"]:
        return "origin"
    if "feed_id" in call and result["feed_id"] != call["feed_id"]:
        return "feed_id"
    if result["after"] != call["after"]:
        return "after"
    return "answers"


# The refused forms of correlation the file must hold (a result on another
# feed than its call's is a matching case: no reader sees the call).
CORRELATION_REFUSALS = {
    "control_sync_request_id_missing", "control_sync_request_id_upper_case", "control_sync_request_id_not_uuid_v4",
    "control_sync_result_request_id_missing", "control_sync_result_request_id_upper_case",
    "control_sync_result_request_id_not_uuid_v4", "control_sync_result_after_missing",
    "control_sync_result_record_at_after", "control_sync_result_record_below_after",
    "control_sync_result_head_below_after_with_records",
}
SYNC_VERDICTS = {"answers", "request_id", "origin", "feed_id", "after"}


def compact_ijson(value):
    """RFC 8785's compact text of a message: keys in UTF-16 order, no
    whitespace, integers and strings as the check's `jcs`, and `null` where a
    record is any JSON value."""
    if value is None:
        return "null"
    if isinstance(value, list):
        return "[" + ",".join(compact_ijson(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + compact_ijson(value[k]) for k in keys) + "}"
    return jcs(value)


def check_station_calls(file, data, report, context):
    """The Station calls' goldens (host-work-v1 §11.4). Every valid text is
    strict I-JSON whose compact form in RFC 8785 key order is the text; this
    file's own reader (written here from the spec) reads it as its direction
    says, its fields are the text's and the other direction refuses it; what
    the text names is the other vectors': a feed of the control vectors'
    stations, records, device-list entries and heads of log L, effects as each
    record's action carries them (wire rule 3), each page record's parse
    verdict as the control vectors list it. Every invalid text is refused by
    that reader with the code the file says, a bounded text (`wire_fill`) is
    built here to its size: exactly the bound (`at_the_bound`) is read, one
    byte over and 300,000 bytes are `too_large`, for each call that can carry
    a large page (a page's record, a fetch result's entry), so a reader that
    allowed more for either (the 512 KiB of stage 3's mailbox calls is no
    exemption for `membership_fetch_result`) fails. A record that is not a
    JSON object is `malformed` to the signed-object parse (R9.1: a signed
    object is an object), derived here. An effect's typed reason (O5) is
    read by the same rules as the Rust reader: absent, or 1 to 64 bytes of
    [a-z0-9_] beside `pending` or `refused`, a code outside the vocabulary
    read as unrecognized. Correlation (#164 comment 6858189009): a call's
    `request_id` and a result's echoed `request_id` and `after` are read by
    the same rules (required, a lowercase UUID v4; a safe whole number), a
    page's records strictly after its `after`; each `matching` case's
    verdict is this file's own matcher's (the same id, origin, feed when the
    call named one, and after; else the first that differs). The builders'
    exact bytes are the Rust runner's (`station_calls_build_byte_for_byte`)
    and the binding suites'."""
    mlog = context["membership_log"]
    control = context["host_work_control"]
    with report.case(file, "bound") as case:
        case.equal(data["max_message_bytes"], RELAY_MAX_BYTES, "R9.9's 262,144 bytes for every relay message")
        case.equal(sorted(data), ["at_the_bound", "calls", "invalid", "kind", "matching", "max_message_bytes", "name", "note", "requires", "why_codes"], "fields")
        codes = data["why_codes"]
        case.check(len(set(codes)) == len(codes) and set(codes) == WHY_CODES, "why_codes: the vocabulary of reasons, each code once (O5)", f"got {codes}")
        case.check(all(re.fullmatch(RELAY_WHY, c) for c in codes), "each code a reason's form")

    stations = {(s["origin"], s["feed_id"]) for s in control["stations"].values()}
    records = {compact_ijson(v["record"]): v for v in control["records"]}
    entries = {e["label"]: e for e in mlog["log"] + mlog["others"]}
    log_entries = mlog["log"]
    head = mlog["head"]

    def record_effects(body):
        action = body["action"]
        if action == "revoke":
            return ["revocation", "interrupt"] if body.get("interrupt_running") else ["revocation"]
        return {"cover": ["cover"], "hold": ["hold"], "release": ["release"], "interrupt_running": ["interrupt"]}[action]

    names = set()
    ops = {}
    fetch_after = None
    sync_ids = []
    for call in data["calls"]:
        name, op, direction = call["name"], call["op"], call["direction"]
        with report.case(file, f"call {name}") as case:
            case.check(name not in names and re.fullmatch(r"[a-z0-9_]+", name) is not None, "a name of its own")
            names.add(name)
            wire = call["wire"]
            case.equal(sorted(k for k in call if k not in ("judged", "hand_assembled")), ["direction", "fields", "name", "note", "op", "wire"], "case fields")
            # A page with a record the parser refuses is a builder's page with
            # the records put in their slots, and says so (exactly then).
            case.equal(
                call.get("hand_assembled", False),
                op == "control_sync_result" and any(not j["parses"] for j in call["judged"]),
                "hand_assembled exactly when a page record doesn't parse",
            )
            case.equal(direction, "to_host" if op in STATION_TO_HOST_OPS else "to_station", "its direction")
            case.check(len(wire.encode()) <= RELAY_MAX_BYTES, "within 262,144 bytes")
            message, code = read_relay(wire, direction)
            case.equal(code, None, "read by its side's reader")
            if message is None:
                continue
            ops.setdefault(op, []).append(name)
            case.equal(message["op"], op, "its op")
            case.equal(compact_ijson(message), wire, "compact RFC 8785 text of its own parse")
            case.equal({k: v for k, v in message.items() if k not in ("type", "op")}, call["fields"], "fields are the text's")
            other = "to_host" if direction == "to_station" else "to_station"
            case.equal(read_relay(wire, other)[1], "wrong_message", "the other side refuses it")
            f = call["fields"]
            if op in ("control_sync", "control_sync_result", "control_ack"):
                case.check(
                    (f["origin"], f.get("feed_id")) in stations or (op == "control_sync" and "feed_id" not in f and any(f["origin"] == o for o, _ in stations)),
                    "a feed of the control vectors' stations",
                )
            if op == "control_sync":
                sync_ids.append(f["request_id"])
            if op == "control_sync_result":
                # Correlation: none of its records at or below its after.
                case.check(all(r["feed_seq"] > f["after"] for r in f["records"]), "records strictly after the echoed after")
                if f["head"] < f["after"]:
                    case.equal(f["records"], [], "head below after: no record (the host rescans)")
                judged = call["judged"]
                case.equal([j["feed_seq"] for j in judged], [r["feed_seq"] for r in f["records"]], "judged parallel to the records")
                for r, j in zip(f["records"], judged):
                    vector = records.get(compact_ijson(r["record"]))
                    if vector is not None:
                        parses = "parse_error" not in vector
                        case.equal(j["parses"], parses, f"record {r['feed_seq']} ({vector['label']}) parses as the control vectors say")
                        if parses:
                            case.equal(j["record_id"], vector["record"]["body"]["record_id"], f"record {r['feed_seq']}: its record_id")
                        else:
                            case.equal(j["error"], vector["parse_error"], f"record {r['feed_seq']}: its parse error")
                    elif not isinstance(r["record"], dict):
                        # Not a JSON object: the signed-object parse refuses it as malformed.
                        case.equal({k: v for k, v in j.items() if k != "feed_seq"}, {"parses": False, "error": "malformed"}, f"record {r['feed_seq']}: not an object, malformed")
                    else:
                        case.check(j["parses"] is False and isinstance(j.get("error"), str) and j["error"] != "", f"record {r['feed_seq']}: not a vectors' record, no record")
            if op == "heads":
                case.equal(f["membership"], head, "the device list's head: log L's")
                case.check(all(isinstance(x["head"], int) for x in f["feeds"]), "feeds with heads")
            if op == "control_ack":
                case.equal((f["account_id"], f["genesis_hash"]), (mlog["account_id"], mlog["genesis_hash"]), "log L's account and genesis")
                # A record_id names one record, but the vectors reuse some on
                # purpose (the conflicting-id records): the effects are those
                # of a record that carries the id.
                by_id = {}
                for v in control["records"]:
                    if "parse_error" not in v:
                        by_id.setdefault(v["record"]["body"]["record_id"], []).append(v["record"]["body"])
                # Typed reasons (O5): the vocabulary's codes, but in the
                # golden of a later version's, which carries codes outside it.
                whys = [e["why"] for r in f["results"] for e in r["effects"] if "why" in e]
                if "unrecognized" in name:
                    case.check(any(w not in WHY_CODES for w in whys), "reasons outside the vocabulary: read, unrecognized")
                else:
                    case.check(all(w in WHY_CODES for w in whys), "each reason a code of the vocabulary", f"got {whys}")
                for result in f["results"]:
                    effects = [e["effect"] for e in result["effects"]]
                    if "record_id" in result:
                        bodies = by_id.get(result["record_id"])
                        if bodies is not None:
                            case.check(effects in [record_effects(b) for b in bodies], f"{result['record_id'][-4:]}: the effects its {bodies[0]['action']} carries", f"got {effects}")
                    else:
                        entry = next((e for e in entries.values() if e["entry_hash"] == result["entry"]["entry_hash"]), None)
                        case.check(entry is not None, "an entry of the device-list vectors")
                        if entry is not None:
                            body = entry["entry"]["body"]
                            case.equal((body["seq"], body["action"]), (result["entry"]["seq"], "host_sender_revoke"), "its seq and a host sender's revoke")
                            case.equal(effects, ["revocation", "interrupt"] if body["interrupt_running"] else ["revocation"], "the effects its revoke carries")
            if op == "membership_fetch":
                fetch_after = f["after"]
            if op == "membership_fetch_result":
                top = f["head"]["seq"]
                case.equal(f["head"], head, "the Station's head: log L's")
                case.equal(f["head"]["hash"], log_entries[top - 1]["entry_hash"], "its hash is the head entry's")
                want = [e["entry"] for e in log_entries[(fetch_after if name == "membership_fetch_result" else top):top]]
                case.equal(f["entries"], want, "the entries after the host's seq: log L's")
            if op.endswith("_refused"):
                case.equal(wire, '{"code":"forbidden","op":"%s","type":"relay"}' % op, "exactly the agreed refusal")
    with report.case(file, "calls: coverage") as case:
        case.equal(sorted(ops), sorted(HOST_TO_STATION_OPS + STATION_TO_HOST_OPS), "all six calls and all three refusals")
        case.check(len(ops["control_ack"]) >= 5 and len(ops["control_sync_result"]) >= 3, "ack and page forms")
        case.check(len(set(sync_ids)) == len(sync_ids), "each call's request_id its own (a fresh one for every call)")
        case.check(
            any(c["op"] == "control_sync_result" and c["fields"]["head"] < c["fields"]["after"] for c in data["calls"]),
            "a page whose head is below its after (a feed gone back)",
        )
        case.check(
            any(c["op"] == "control_sync" and "feed_id" in c["fields"] and c["fields"]["after"] == 0 for c in data["calls"]),
            "a call that names its feed and asks from 0 (a first read or a rescan; asked by Astation, #156 comment 6885246159)",
        )

    # Correlation (amended in place on Astation's request, #164 comment
    # 6858189009): each case's calls and result read by this file's readers,
    # each a builder's compact text, and this file's own matcher's verdict on
    # the result for each call, as the file says.
    matched = set()
    seen_verdicts = set()
    for m in data["matching"]:
        name = m["name"]
        with report.case(file, f"matching {name}") as case:
            case.equal(sorted(m), ["calls", "name", "note", "result", "verdicts"], "case fields")
            case.check(name not in matched and name not in names and re.fullmatch(r"[a-z0-9_]+", name) is not None, "a name of its own")
            matched.add(name)
            result, code = read_relay(m["result"], "to_host")
            case.equal((code, result and result["op"]), (None, "control_sync_result"), "the result: a control_sync_result")
            case.equal(len(m["calls"]), len(m["verdicts"]), "a verdict for each call")
            case.check(len(m["calls"]) >= 1, "at least one call")
            if result is not None:
                case.equal(compact_ijson(result), m["result"], "the result: its compact text")
            for i, (text, verdict) in enumerate(zip(m["calls"], m["verdicts"])):
                call, code = read_relay(text, "to_station")
                case.equal((code, call and call["op"]), (None, "control_sync"), f"call {i}: a control_sync")
                case.check(verdict in SYNC_VERDICTS, f"call {i}: a verdict", f"got {verdict}")
                if call is None or result is None:
                    continue
                case.equal(compact_ijson(call), text, f"call {i}: its compact text")
                case.equal(relay_sync_verdict(call, result), verdict, f"call {i}: the verdict")
                seen_verdicts.add(verdict)
    with report.case(file, "matching: coverage") as case:
        case.equal(seen_verdicts, SYNC_VERDICTS, "every verdict: answers and each field that can differ")
        case.check(
            {"two_calls_at_the_same_cursor", "a_late_reply_to_a_retired_call", "discovery_answered_on_the_current_feed", "another_feed",
             "a_named_feed_read_from_0_answers_on_its_feed", "a_named_feed_read_from_0_is_answered_on_that_feed_only"} <= matched,
            "two calls at one cursor, a retired call's late reply, discovery, a result on another feed, a named feed read from 0 (answered on that feed only)",
            f"got {sorted(matched)}",
        )
        # A named feed's read from 0 is no discovery: the page that answers
        # a discovery call, on another feed, answers it nothing.
        named_0 = [m for m in data["matching"] if m["name"] == "a_named_feed_read_from_0_is_answered_on_that_feed_only"]
        if named_0:
            calls = [read_relay(t, "to_station")[0] for t in named_0[0]["calls"]]
            case.check(
                len(calls) == 1 and calls[0] is not None and "feed_id" in calls[0] and calls[0]["after"] == 0
                and named_0[0]["verdicts"] == ["feed_id"],
                "a call naming its feed from 0, refused on another feed",
            )
        same_cursor = [m for m in data["matching"] if m["name"] == "two_calls_at_the_same_cursor"]
        if same_cursor:
            calls = [read_relay(t, "to_station")[0] for t in same_cursor[0]["calls"]]
            case.check(
                len(calls) == 2 and all(calls) and calls[0]["request_id"] != calls[1]["request_id"]
                and {k: v for k, v in calls[0].items() if k != "request_id"} == {k: v for k, v in calls[1].items() if k != "request_id"},
                "two calls that differ only by their request_id",
            )

    # Exactly the bound is read: the reader that refuses it is a byte too
    # strict, and the one that allows more than the bound for a fetch result
    # is refused by the invalid texts below.
    seen_bound = set()
    with report.case(file, "at the bound") as case:
        log_bodies = [e["entry"]["body"] for e in log_entries]
        for bound in data["at_the_bound"]:
            name = bound["name"]
            case.equal(sorted(bound), ["accepts", "direction", "name", "note", "op", "wire_fill"], f"{name}: case fields")
            fill = bound["wire_fill"]
            wire = fill["prefix"] + fill["fill"] * fill["count"] + fill["suffix"]
            case.equal((len(wire.encode()), fill["bytes"]), (RELAY_MAX_BYTES, RELAY_MAX_BYTES), f"{name}: built to exactly 262,144 bytes")
            case.check(name not in names, f"{name}: a name of its own")
            message, code = read_relay(wire, bound["direction"])
            case.equal(code, None, f"{name}: read")
            if message is not None:
                accepts = bound["accepts"]
                if bound["op"] == "control_sync_result":
                    case.equal((message["head"], len(message["records"])), (accepts["head"], accepts["records"]), f"{name}: head and records")
                    # Not a JSON object: not a record (the page stands).
                    case.equal([isinstance(r["record"], dict) for r in message["records"]], accepts["records_parse"], f"{name}: which records can parse")
                else:
                    case.equal((message["head"], len(message["entries"])), (accepts["head"], accepts["entries"]), f"{name}: head and entries")
                    case.equal(message["head"], head, f"{name}: log L's head")
                    entry = message["entries"][0]
                    case.check(entry["body"] in log_bodies, f"{name}: the entry's body is log L's")
                    case.check(any(entry["sig"].startswith(e["entry"]["sig"]) for e in log_entries), f"{name}: its signature is log L's, padded")
                case.equal(read_relay(wire, "to_station")[1], "wrong_message", f"{name}: the other side refuses it")
            seen_bound.add(bound["op"])
        case.equal(seen_bound, {"control_sync_result", "membership_fetch_result"}, "a text at the bound for each call that can carry a large page")

    by_op = {}
    for bad in data["invalid"]:
        by_op.setdefault(bad["op"], []).append(bad)
    codes = set()
    seen = set()
    for op in HOST_TO_STATION_OPS + STATION_TO_HOST_OPS:
        with report.case(file, f"invalid {op}") as case:
            for bad in by_op.get(op, []):
                name = bad["name"]
                case.check(name not in seen and name not in names, f"{name}: a name of its own")
                seen.add(name)
                if "wire_fill" in bad:
                    fill = bad["wire_fill"]
                    wire = fill["prefix"] + fill["fill"] * fill["count"] + fill["suffix"]
                    case.equal(len(wire.encode()), fill["bytes"], f"{name}: built to its size")
                    case.check(fill["bytes"] in (RELAY_MAX_BYTES + 1, 300000), f"{name}: one byte over the bound, or 300,000 bytes")
                else:
                    wire = bad["wire"]
                case.equal(sorted(k for k in bad if k not in ("wire", "wire_fill")), ["code", "name", "op", "reader"], f"{name}: case fields")
                case.equal(read_relay(wire, bad["reader"])[1], bad["code"], f"{name}: refused {bad['code']}")
                codes.add(bad["code"])
            case.check(by_op.get(op), "refused variants")
    with report.case(file, "invalid: coverage") as case:
        case.equal(sorted(by_op), sorted(HOST_TO_STATION_OPS + STATION_TO_HOST_OPS), "every call and refusal has refused variants")
        case.equal(codes, {"too_large", "not_strict", "wrong_message", "unknown_field", "malformed"}, "every refusal code")
        sized = {(b["op"], b["wire_fill"]["bytes"]) for b in data["invalid"] if "wire_fill" in b}
        case.equal(
            sized,
            {(op, n) for op in ("control_sync_result", "membership_fetch_result") for n in (RELAY_MAX_BYTES + 1, 300000)},
            "the byte bound refused one byte over and at 300,000, for a page and a fetch result",
        )
        case.equal(sum("wire_fill" in b for b in data["invalid"]), 4, "four texts over the byte bound")
        reasons = {
            "control_ack_why_null", "control_ack_why_not_a_string", "control_ack_why_empty",
            "control_ack_why_over_64_bytes", "control_ack_why_upper_case", "control_ack_why_outside_the_characters",
            "control_ack_why_beside_applied", "control_ack_why_beside_duplicate", "control_ack_why_duplicate_key",
        }
        case.check(reasons <= seen, "every refused form of a reason (O5)", f"missing {sorted(reasons - seen)}")
        case.check(CORRELATION_REFUSALS <= seen, "every refused form of correlation", f"missing {sorted(CORRELATION_REFUSALS - seen)}")
        case.check(
            {"control_ack_with_reasons", "control_ack_with_unrecognized_reasons"} <= names,
            "goldens with reasons and with a later version's reasons",
        )
        counts = {b["name"] for b in data["invalid"] if b["code"] == "too_large"}
        case.check({"control_sync_result_65_records", "heads_65_feeds", "control_ack_65_results", "membership_fetch_result_65_entries"} <= counts, "65 records, feeds, results and entries")


# ------------------------------------------------ r9-vectors-mailbox-calls

# host-work-v1 §11.5, "The mailbox calls" (rules 1 to 11), written here from
# the contract: the readers, and a model of the Station's mailbox of its own.
MAILBOX_MAX_BYTES = 512 * 1024  # rule 9: every mailbox_* message, as sent
MAILBOX_TO_STATION = ["mailbox_put", "mailbox_sync", "mailbox_done"]
MAILBOX_TO_HOST = [
    "mailbox_stored", "mailbox_put_refused", "mailbox_sync_result",
    "mailbox_done_result", "mailbox_sync_refused", "mailbox_done_refused",
]
MAILBOX_PUT_CODES = ["quota", "id_reused", "expired", "forbidden"]
MAILBOX_ID_LABEL = "atem-reference-mailbox-id-v1"
# A put's object, as received, is at most 512 KiB less a page's own fields
# with every number at its largest (rules 4 and 9; Atem's reading): checked
# against the file's max_served_object_bytes, computed here.
UUID_V4_EXAMPLE = "9d2f6c1e-3b4a-4c5d-8e6f-7a8b9c0d1e2f"  # any lowercase UUID v4: they are all 36 characters


def mailbox_object_ok(obj):
    """A put's object: check 1's reading of an envelope or a result (exact
    fields, a sealed part of the right shape) and a base64url signature."""
    if not mail_well_formed(obj):
        return False
    try:
        b64u_decode(obj["sig"])
        return True
    except ValueError:
        return False


def _mb_position(v, key):
    n = _relay_uint(v, key)
    if n < 1:
        raise Refused("malformed")
    return n


def member_text(text, key):
    """The exact text of the top-level member `key`'s value in the JSON
    object `text` (strict already): walked token by token."""
    decoder = json.JSONDecoder()
    i, n = 0, len(text)

    def skip(i):
        while i < n and text[i] in " \t\n\r":
            i += 1
        return i

    i = skip(i) + 1  # past the opening brace
    while True:
        i = skip(i)
        if text[i] == "}":
            return None
        name, i = decoder.raw_decode(text, i)
        i = skip(skip(i) + 1)  # past the colon
        start = i
        _, i = decoder.raw_decode(text, i)
        if name == key:
            return text[start:i]
        i = skip(i)
        if text[i] == ",":
            i += 1


def put_object_bytes(text):
    """A put's object as received: its exact text's UTF-8 bytes."""
    return len(member_text(text, "object").encode("utf-8"))


def _read_mailbox_put(v, text, served):
    _relay_exact(v, ["type", "op", "request_id", "object"])
    rid = _relay_text(v, "request_id")
    if "object" not in v:
        raise Refused("malformed")
    if put_object_bytes(text) > served:
        raise Refused("too_large")  # a page can't carry it at every position
    _relay_uuid4(rid)
    if not mailbox_object_ok(v["object"]):
        raise Refused("malformed")


def _read_mailbox_stored(v):
    _relay_exact(v, ["type", "op", "request_id", "id"])
    _relay_uuid4(_relay_text(v, "request_id"))
    _relay_uuid4(_relay_text(v, "id"))


def _read_mailbox_put_refused(v):
    _relay_exact(v, ["type", "op", "request_id", "id", "code"])
    _relay_uuid4(_relay_text(v, "request_id"))
    _relay_uuid4(_relay_text(v, "id"))
    if _relay_text(v, "code") not in MAILBOX_PUT_CODES:
        raise Refused("malformed")


def _read_mailbox_sync(v):
    _relay_exact(v, ["type", "op", "request_id", "mailbox_id", "after"])
    _relay_uuid4(_relay_text(v, "request_id"))
    _relay_uuid4(_relay_text(v, "mailbox_id"))
    _relay_uint(v, "after")


def _read_mailbox_sync_result(v):
    _relay_exact(v, ["type", "op", "request_id", "mailbox_id", "after", "head", "through", "objects"])
    items = _relay_array(v, "objects", 1)  # at most one object (rule 11)
    positions = []
    for item in items:
        _relay_exact(item, ["position", "object"])
        positions.append(_mb_position(item, "position"))
        if "object" not in item:
            raise Refused("malformed")  # of any JSON type, but there
    _relay_uuid4(_relay_text(v, "request_id"))
    _relay_uuid4(_relay_text(v, "mailbox_id"))
    after, head, through = (_relay_uint(v, k) for k in ("after", "head", "through"))
    if head < after:
        # The mailbox went back under its id (rule 4): nothing listed,
        # through at the head.
        if through != head or positions:
            raise Refused("malformed")
        return
    if not after <= through <= head:
        raise Refused("malformed")
    previous = after
    for position in positions:
        if position <= previous or position > through:
            raise Refused("malformed")
        previous = position


def _read_mailbox_done(v):
    _relay_exact(v, ["type", "op", "request_id", "mailbox_id", "position"])
    _relay_uuid4(_relay_text(v, "request_id"))
    _relay_uuid4(_relay_text(v, "mailbox_id"))
    _mb_position(v, "position")


def _read_mailbox_refusal(v):
    _relay_exact(v, ["type", "op", "code"])
    if _relay_text(v, "code") != "forbidden":
        raise Refused("malformed")


MAILBOX_READERS = {
    "to_station": {
        "mailbox_put": _read_mailbox_put,
        "mailbox_sync": _read_mailbox_sync,
        "mailbox_done": _read_mailbox_done,
    },
    "to_host": {
        "mailbox_stored": _read_mailbox_stored,
        "mailbox_put_refused": _read_mailbox_put_refused,
        "mailbox_sync_result": _read_mailbox_sync_result,
        "mailbox_done_result": _read_mailbox_done,
        "mailbox_sync_refused": _read_mailbox_refusal,
        "mailbox_done_refused": _read_mailbox_refusal,
    },
}


def read_mailbox(text, reader, served):
    """(message, None) if the reader reads `text`, else (None, its code): the
    512 KiB bound before any parse, one strict parse, a mailbox message of
    the reader's direction, then its rules (a put's object, as received, at
    most `served` bytes)."""
    try:
        if len(text.encode("utf-8")) > MAILBOX_MAX_BYTES:
            raise Refused("too_large")
        try:
            value = relay_parse(text)
        except (NotStrict, ValueError, RecursionError):
            raise Refused("not_strict")
        op = value.get("op") if isinstance(value, dict) and value.get("type") == "relay" else None
        reader_for = MAILBOX_READERS[reader].get(op) if isinstance(op, str) else None
        if reader_for is None:
            raise Refused("wrong_message")
        if op == "mailbox_put":
            reader_for(value, text, served)
        else:
            reader_for(value)
        return value, None
    except Refused as refused:
        return None, refused.code


def read_heads_with(text, mailbox):
    """§11.4's heads (256 KiB), with the calling host's mailbox head read
    only when `mailbox` (rule 6): ({mailbox} or {}, None), or (None, code)."""
    try:
        if len(text.encode("utf-8")) > RELAY_MAX_BYTES:
            raise Refused("too_large")
        try:
            value = relay_parse(text)
        except (NotStrict, ValueError, RecursionError):
            raise Refused("not_strict")
        if not (isinstance(value, dict) and value.get("type") == "relay" and value.get("op") == "heads"):
            raise Refused("wrong_message")
        _relay_exact(value, ["type", "op", "feeds", "membership"] + (["mailbox"] if mailbox else []))
        _read_heads({k: v for k, v in value.items() if k != "mailbox"})
        if "mailbox" not in value:
            return {}, None
        m = _relay_exact(value["mailbox"], ["mailbox_id", "head"])
        _relay_uuid4(_relay_text(m, "mailbox_id"))
        _relay_uint(m, "head")
        return {"mailbox": m}, None
    except Refused as refused:
        return None, refused.code


def mailbox_fill(recipe):
    return recipe["prefix"] + recipe["fill"] * recipe["count"] + recipe["suffix"]


def mailbox_id_of(seed, account_id, genesis, host_id, host_trust_gen, n):
    """The reference mailbox's minted id: the first 16 bytes of SHA-256 over
    its fields, as a lowercase UUID v4."""
    b = bytearray(sha256(enc([MAILBOX_ID_LABEL, seed, account_id, genesis, host_id, u64(host_trust_gen), u64(n)]))[:16])
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


class MailStation:
    """A Station's mailboxes for one device list, written here from §11.5's
    rules: one mailbox per receiving (host, generation), minted by a store,
    positions in store order; puts from a current host with its own objects
    to a current host, times, the key (calling host, id) by object hash,
    quotas per sending host, receiving host and account in objects and in
    bytes as received; pages of one object with a scan boundary over removed
    positions; done and sync from a current host on its own mailbox only;
    expiry by the clock; resets."""

    def __init__(self, data, scenario):
        link = data["link"]
        self.account, self.genesis = link["account_id"], link["genesis_hash"]
        self.seed = unhex(data["seed_hex"])
        self.quotas = scenario["quotas"]
        self.hosts = {h["host_id"]: h["host_trust_gen"] for h in scenario["hosts"]}
        self.max_served = data["max_served_object_bytes"]
        self.lifetime = data["max_lifetime_ms"]
        self.heads_base = relay_parse(data["heads_base"])
        self.boxes = {}  # (host_id, gen) -> {"id", "head", "stored": {position: entry}}
        self.minted = {}
        self.dropped = 0

    def mint(self, key):
        n = self.minted.get(key, 0)
        self.minted[key] = n + 1
        return mailbox_id_of(self.seed, self.account, unhex(self.genesis), key[0], key[1], n)

    def box(self, key):
        if key not in self.boxes:
            self.boxes[key] = {"id": self.mint(key), "head": 0, "stored": {}}
        return self.boxes[key]

    def expire(self, now):
        for b in self.boxes.values():
            b["stored"] = {p: e for p, e in b["stored"].items() if e["expires_at"] > now}

    def usage(self, keep):
        entries = [e for k, b in self.boxes.items() for e in b["stored"].values() if keep(k, e)]
        return len(entries), sum(e["bytes"] for e in entries)

    def over(self, used, quota, size):
        return used[0] + 1 > quota["objects"] or used[1] + size > quota["bytes"]

    def call(self, caller, text, now):
        self.expire(now)
        value, code = read_mailbox(text, "to_station", self.max_served)
        if code:
            self.dropped += 1
            return {"outcome": "dropped", "why": code}, None
        op = value["op"]
        if op == "mailbox_put":
            return self.put(caller, value, put_object_bytes(text), now)
        key = (caller["host_id"], caller["host_trust_gen"])
        own = self.boxes.get(key)
        # Only a current host, and only its own mailbox (rule 1).
        if own is None or own["id"] != value["mailbox_id"] or self.hosts.get(key[0]) != key[1]:
            refusal = op + "_refused"
            return {"outcome": "refused", "op": refusal}, compact_ijson({"type": "relay", "op": refusal, "code": "forbidden"})
        if op == "mailbox_done":
            removed = own["stored"].pop(value["position"], None) is not None
            answer = {k: value[k] for k in ("request_id", "mailbox_id", "position")}
            return {"outcome": "done", "removed": removed}, compact_ijson(dict(answer, type="relay", op="mailbox_done_result"))
        after, head = value["after"], own["head"]
        page = {"type": "relay", "op": "mailbox_sync_result", "request_id": value["request_id"], "mailbox_id": value["mailbox_id"], "after": after, "head": head}
        later = sorted(p for p in own["stored"] if p > after)
        if after > head:
            outcome, through, objects = {"outcome": "page", "through": head, "reset": True}, head, []
        elif later:
            through = later[1] - 1 if len(later) > 1 else head
            objects = [{"position": later[0], "object": own["stored"][later[0]]["object"]}]
            outcome = {"outcome": "page", "through": through, "reset": False, "position": later[0]}
        else:
            outcome, through, objects = {"outcome": "page", "through": head, "reset": False}, head, []
        return outcome, compact_ijson(dict(page, through=through, objects=objects))

    def put(self, caller, value, size, now):
        """`size`: the object's bytes as received, what it is charged."""
        obj, rid = value["object"], value["request_id"]
        body = obj["body"]

        def answer(op, **more):
            return compact_ijson(dict({"type": "relay", "op": op, "request_id": rid, "id": body["id"]}, **more))

        def refuse(code):
            return {"outcome": "put_refused", "code": code}, answer("mailbox_put_refused", code=code)

        sender, recipient = body["sender"], body["recipient"]
        if (
            self.hosts.get(caller["host_id"]) != caller["host_trust_gen"]
            or sender["host_id"] != caller["host_id"]
            or (body["account_id"], body["genesis_hash"]) != (self.account, self.genesis)
            or self.hosts.get(recipient["host_id"]) != recipient["host_trust_gen"]
        ):
            return refuse("forbidden")
        created, expires = body["created_at"], body["expires_at"]
        if now >= expires or expires <= created or expires - created > self.lifetime:
            return refuse("expired")
        object_hash = mail_evidence(obj)
        rkey = (recipient["host_id"], recipient["host_trust_gen"])
        held = self.boxes.get(rkey, {"stored": {}})["stored"]  # only a store mints a mailbox
        for position, e in held.items():
            if (e["sender"], e["id"]) == (caller["host_id"], body["id"]):
                if e["object_hash"] == object_hash:
                    return {"outcome": "already_stored", "position": position}, answer("mailbox_stored")
                return refuse("id_reused")
        if (
            self.over(self.usage(lambda k, e: e["sender"] == caller["host_id"]), self.quotas["sender"], size)
            or self.over(self.usage(lambda k, e: k == rkey), self.quotas["receiver"], size)
            or self.over(self.usage(lambda k, e: True), self.quotas["account"], size)
        ):
            return refuse("quota")
        box = self.box(rkey)
        box["head"] += 1
        box["stored"][box["head"]] = {
            "position": box["head"], "sender": caller["host_id"], "id": body["id"],
            "object_hash": object_hash, "bytes": size, "expires_at": expires, "object": obj,
        }
        return {"outcome": "stored", "position": box["head"]}, answer("mailbox_stored")

    def heads(self, caller, host_senders, now):
        self.expire(now)
        message = dict(self.heads_base)
        outcome = {"outcome": "heads"}
        if host_senders:
            box = self.box((caller["host_id"], caller["host_trust_gen"]))
            message["mailbox"] = outcome["mailbox"] = {"mailbox_id": box["id"], "head": box["head"]}
        return outcome, compact_ijson(message)

    def reset(self, host_id, gen, how):
        box = self.boxes[(host_id, gen)]
        if how == "new_mailbox":
            self.boxes[(host_id, gen)] = {"id": self.mint((host_id, gen)), "head": 0, "stored": {}}
        else:
            back = how["head_back"]
            assert back < box["head"], "a head below the mailbox's"
            box["stored"] = {p: e for p, e in box["stored"].items() if p <= back}
            box["head"] = back

    def state(self):
        return {
            "dropped": self.dropped,
            "mailboxes": [
                {
                    "host_id": k[0], "host_trust_gen": k[1], "mailbox_id": b["id"], "head": b["head"],
                    "stored": [{f: e[f] for f in ("position", "sender", "id", "object_hash", "bytes", "expires_at")} for _, e in sorted(b["stored"].items())],
                }
                for k, b in sorted(self.boxes.items())
            ],
        }


def check_mailbox_calls(file, data, report, context):
    """The mailbox calls (host-work-v1 §11.5): the bounds and the reference
    model's constants; each object's shape, signature, object_hash and
    encoded size; the object_hash known answers; every valid text strict,
    compact in RFC 8785 order, read as its direction says to its fields and
    refused by the other; every invalid text refused with its code; heads'
    mailbox head with and without host.senders; and every scenario run
    against a model of the Station's mailbox written here, each outcome,
    answer and state."""
    keys = context["keys"]
    with report.case(file, "constants") as case:
        case.equal((data["max_message_bytes"], data["max_heads_bytes"], data["max_lifetime_ms"]), (MAILBOX_MAX_BYTES, RELAY_MAX_BYTES, MAX_LIFETIME_MS), "512 KiB, heads 256 KiB, 24 hours")
        largest = 2**53 - 1
        page = {"type": "relay", "op": "mailbox_sync_result", "request_id": UUID_V4_EXAMPLE, "mailbox_id": UUID_V4_EXAMPLE, "after": largest - 1, "head": largest, "through": largest, "objects": [{"position": largest, "object": {}}]}
        wrapper = len(compact_ijson(page)) - 2
        served = MAILBOX_MAX_BYTES - wrapper
        case.equal(data["max_served_object_bytes"], served, "the largest object a page carries at every position")
        low = dict(page, after=0, head=1, through=1, objects=[{"position": 1, "object": {}}])
        case.equal(MAILBOX_MAX_BYTES - (len(compact_ijson(low)) - 2), 524_073, "a page at position 1 would carry more: the bound is position-independent")
        case.equal(data["link"]["genesis_hash"], context["genesis_hash"].hex(), "log L's account root")

    hashes = {}
    for v in data["objects"]:
        with report.case(file, f"object {v['label']}") as case:
            obj = v["object"]
            case.check(mailbox_object_ok(obj), "a mailbox object (check 1)")
            body = obj["body"]
            signer = body["sender"]["host_id"]
            case.check(verify("ed25519", keys.public(signer, "host_key"), b64u_decode(obj["sig"]), mail_signing_input(body)), f"signed by {signer}'s host key")
            case.equal(v["object_hash"], mail_evidence(obj), "object_hash")
            case.equal(v["bytes"], len(compact_ijson(obj).encode()), "its compact JSON's length")
            hashes[v["label"]] = v["object_hash"]

    for v in data["object_hash"]:
        with report.case(file, f"object_hash {v['name']}") as case:
            obj = relay_parse(v["object_text"])
            case.check(mailbox_object_ok(obj), "a mailbox object")
            case.equal(v["object_hash"], mail_evidence(obj), "SHA-256(enc([jcs(body), sig, enc, ct]))")
    with report.case(file, "object_hash: the same object serialized again") as case:
        by_name = {v["name"]: v for v in data["object_hash"]}
        again = by_name["o1_serialized_again"]
        case.check(again["object_text"] != compact_ijson(relay_parse(again["object_text"])), "not its compact form")
        case.equal(again["object_hash"], hashes["o1"], "o1's object_hash")
        case.check(len({hashes["o1"], hashes["o1_other"], hashes["o1_resigned"]}) == 3, "another sealed part, another body: other objects")

    ops = set()
    for v in data["calls"]:
        with report.case(file, f"call {v['name']}") as case:
            value, code = read_mailbox(v["wire"], v["direction"], served)
            case.equal(code, None, f"read {v['direction']}")
            if value is None:
                continue
            case.equal(compact_ijson(value), v["wire"], "compact, keys in RFC 8785 order")
            case.equal({k: x for k, x in value.items() if k not in ("type", "op")}, v["fields"], "its fields")
            case.equal(value["op"], v["op"], "op")
            other = "to_host" if v["direction"] == "to_station" else "to_station"
            case.equal(read_mailbox(v["wire"], other, served)[1], "wrong_message", "the other direction refuses it")
            ops.add(v["op"])
    with report.case(file, "calls coverage") as case:
        case.equal(sorted(ops), sorted(MAILBOX_TO_STATION + MAILBOX_TO_HOST), "every call and answer")
        codes = sorted(v["fields"]["code"] for v in data["calls"] if v["op"] == "mailbox_put_refused")
        case.equal(codes, sorted(MAILBOX_PUT_CODES), "every put refusal's code")

    for v in data["invalid"]:
        with report.case(file, f"invalid {v['name']}") as case:
            case.equal(read_mailbox(v["wire"], v["reader"], served)[1], v["code"], f"refused by {v['reader']}")
    for v in data["bounds"]:
        with report.case(file, f"bound {v['name']}") as case:
            text = mailbox_fill(v["wire_fill"])
            case.equal(len(text.encode()), v["wire_fill"]["bytes"], "its length")
            case.equal(read_mailbox(text, v["reader"], served)[1], v.get("code"), "read" if "accepts" in v else "refused")
            if v["op"] == "mailbox_put" and len(text.encode()) <= MAILBOX_MAX_BYTES:
                object_bytes = put_object_bytes(text)
                case.check((object_bytes <= served) == ("accepts" in v), f"its object, {object_bytes} bytes as received, against the served bound")
    with report.case(file, "bounds coverage") as case:
        sizes = {v["name"]: v["wire_fill"]["bytes"] for v in data["bounds"]}
        case.equal((sizes["put_at_the_bound"], sizes["put_over_the_bound"]), (MAILBOX_MAX_BYTES, MAILBOX_MAX_BYTES + 1), "at and a byte over 512 KiB")
        objects = {v["name"]: put_object_bytes(mailbox_fill(v["wire_fill"])) for v in data["bounds"] if v["op"] == "mailbox_put" and v["wire_fill"]["bytes"] <= MAILBOX_MAX_BYTES}
        case.equal(
            (objects["put_at_the_bound"], objects["put_object_over_what_a_page_carries"], objects["put_object_spaced_over_what_a_page_carries"]),
            (served, served + 1, served + 1),
            "objects at and a byte over the served bound, as received",
        )
        spaced = relay_parse(mailbox_fill(next(v for v in data["bounds"] if v["name"] == "put_object_spaced_over_what_a_page_carries")["wire_fill"]))
        case.check(len(compact_ijson(spaced["object"]).encode()) <= served, "the spaced object is under the bound compact")

    for v in data["heads"]:
        with report.case(file, f"heads {v['name']}") as case:
            text = mailbox_fill(v["wire_fill"]) if "wire_fill" in v else v["wire"]
            got, code = read_heads_with(text, v["reader"] == "mailbox")
            if "code" in v:
                case.equal(code, v["code"], f"refused by the {v['reader']} reader")
            else:
                case.equal((got, code), (v["accepts"], None), f"read by the {v['reader']} reader")
    with report.case(file, "heads coverage") as case:
        sizes = [len(mailbox_fill(v["wire_fill"]).encode()) for v in data["heads"] if "wire_fill" in v]
        case.equal(sorted(sizes), [RELAY_MAX_BYTES, RELAY_MAX_BYTES + 1], "heads at and over its 256 KiB bound")

    outcomes = set()
    for scenario in data["scenarios"]:
        with report.case(file, f"scenario {scenario['name']}") as case:
            station = MailStation(data, scenario)
            for n, event in enumerate(scenario["events"]):
                kind = event["event"]
                got = answer = None
                if kind == "call":
                    text = event["call"] if "call" in event else mailbox_fill(event["call_fill"])
                    got, answer = station.call(event["caller"], text, event["at"])
                elif kind == "heads":
                    got, answer = station.heads(event["caller"], event["host_senders"], event["at"])
                elif kind == "reset":
                    station.reset(event["host_id"], event["host_trust_gen"], event["reset"])
                elif kind == "hosts":
                    station.hosts = {h["host_id"]: h["host_trust_gen"] for h in event["hosts"]}
                elif kind == "tick":
                    station.expire(event["at"])
                else:
                    case.fail(f"event {n}: no event {kind}")
                if got is not None:
                    case.equal(got, event["expect"], f"event {n} outcome")
                    case.equal(answer, event.get("answer"), f"event {n} answer")
                    outcomes.add(" ".join(str(got.get(k)) for k in ("outcome", "code", "why", "op") if k in got) + (" reset" if got.get("reset") else ""))
                case.equal(station.state(), event["state"], f"event {n} state")
            case.done.append(f"{len(scenario['events'])} events")
    with report.case(file, "scenarios coverage") as case:
        want = {
            "stored", "already_stored", "put_refused quota", "put_refused id_reused", "put_refused expired",
            "put_refused forbidden", "dropped not_strict", "dropped malformed", "dropped wrong_message",
            "dropped too_large", "page", "page reset", "done",
            "refused mailbox_sync_refused", "refused mailbox_done_refused", "heads",
        }
        case.check(want <= outcomes, "every outcome", f"missing {sorted(want - outcomes)}")


# ------------------------------------------------- r9-vectors-host-route

# The two kinds of host route proof (session-v1 R9.7b): their body `type` and
# signing label. The proxy kind (a Station's challenge through Astation's
# `:8080`) is agreed with Astation (2026-11-16, #174 comment 6919776085).
ROUTE_KINDS = {
    "relay": ("atem-host-route", "atem-host-route-v1"),
    "proxy": ("atem-host-route-proxy", "atem-host-route-proxy-v1"),
}
ROUTE_BODY_FIELDS = {"type", "v", "account_id", "genesis_hash", "host_id", "atem_id", "room", "nonce", "head"}


def check_host_route(file, data, report, context):
    """Recomputes every valid proof's jcs and signing input and verifies its
    signature with the host's key at the verifier's head (log L's add_host,
    then the case's `chain`), for both kinds; checks that a proof never
    verifies under the other kind's label and type, and that each `cross`
    case's code follows from its type and signature."""
    mlog = context["membership_log"]
    extra = {e["label"]: e["entry"]["body"] for e in data["entries"]}
    challenge = data["challenge"]

    def host_key(host_id, chain):
        key = None
        bodies = [v["entry"]["body"] for v in mlog["log"]] + [extra[label] for label in chain]
        for body in bodies:
            if body["action"] == "add_host" and body["host"]["host_id"] == host_id:
                key = b64u_decode(body["host"]["host_key"]["pub"])
            elif body["action"] == "remove_host" and body["host_id"] == host_id:
                key = None
        return key

    def kind_of(body):
        return next((k for k, (t, _) in ROUTE_KINDS.items() if body.get("type") == t), None)

    def signed(body, label, sig, key):
        return key is not None and verify("ed25519", key, sig, enc([label, jcs(body)]))

    def check_valid(case, vector, kind):
        proof = vector["message"]["proof"]
        body, sig = proof["body"], b64u_decode(proof["sig"])
        body_type, label = ROUTE_KINDS[kind]
        case.equal(sorted(vector["message"]), ["op", "proof", "type", "v"], "message fields")
        case.equal((vector["message"]["type"], vector["message"]["op"], vector["message"]["v"]), ("relay", "host_route", 1), "a host_route relay message")
        case.equal(set(body), ROUTE_BODY_FIELDS, "the body's fields")
        case.equal((body["type"], body["v"]), (body_type, 1), "type and v")
        case.equal((body["nonce"], body["room"], body["atem_id"]), (challenge["message"]["nonce"], challenge["room"], challenge["atem_id"]), "the challenge's nonce and room, the relay's atem_id")
        case.equal(body["genesis_hash"], context["genesis_hash"].hex(), "log L's genesis")
        text = jcs(body)
        case.equal(text, vector["jcs"], "jcs")
        case.equal(enc([label, text]).hex(), vector["signing_input_hex"], "signing input")
        key = host_key(body["host_id"], vector["chain"])
        case.check(signed(body, label, sig, key), f"signature by {context['keys'].name_of(key)} over {label}")
        for other, (other_type, other_label) in ROUTE_KINDS.items():
            if other != kind:
                relabelled = dict(body, type=other_type)
                case.check(not signed(relabelled, other_label, sig, key), f"never valid as the {other} kind")
                case.check(not signed(body, other_label, sig, key), f"not over {other_label}")
        return body

    relay_bodies = {}
    for vector in data["valid"]:
        with report.case(file, f"valid {vector['label']}") as case:
            relay_bodies[vector["label"]] = check_valid(case, vector, "relay")
    proxy = data["proxy"]
    for vector in proxy["valid"]:
        with report.case(file, f"proxy valid {vector['label']}") as case:
            body = check_valid(case, vector, "proxy")
            case.equal(dict(body, type="atem-host-route"), relay_bodies.get(vector["label"]), "the relay case's body but its type")
            case.equal(vector["chain"], next(v["chain"] for v in data["valid"] if v["label"] == vector["label"]), "the relay case's chain")
    codes = set()
    for vector in proxy["cross"]:
        with report.case(file, f"proxy cross {vector['label']}") as case:
            verifier = vector["verifier"]
            body = vector["message"]["proof"]["body"]
            sig = b64u_decode(vector["message"]["proof"]["sig"])
            kind = kind_of(body)
            case.check(kind is not None, "a host route type")
            if kind != verifier:
                case.equal(vector["code"], "malformed", f"a {kind} proof to the {verifier} verifier: its type")
            else:
                label = ROUTE_KINDS[verifier][1]
                key = host_key(body["host_id"], vector["chain"])
                case.check(not signed(body, label, sig, key), f"its signature isn't over {label}")
                # A genuine relabel: restored to the other kind's type, the
                # signature verifies over that kind's label.
                original = next(k for k in ROUTE_KINDS if k != verifier)
                original_type, original_label = ROUTE_KINDS[original]
                case.check(
                    signed(dict(body, type=original_type), original_label, sig, key),
                    f"a genuine {original} proof relabelled (its signature verifies as {original_type} over {original_label})",
                )
                case.equal(vector["code"], "bad_signature", "relabelled: bad_signature")
            codes.add((verifier, vector["code"]))
    with report.case(file, "proxy coverage") as case:
        case.equal(sorted(v["label"] for v in proxy["valid"]), sorted(relay_bodies), "every valid relay case has its proxy case")
        case.equal(codes, {(v, c) for v in ROUTE_KINDS for c in ("malformed", "bad_signature")}, "each verifier refuses the other kind and a relabelled proof")
    check_route_replies(file, data, report)


# The relay's verdicts on a proof (R9.7b) and the Station's notice on an open
# host link (the delegated host-work design III.5), read here from the
# contract: a verifier code alone, or the Station's `service_suspended` with
# a required `text` (1 to 256 bytes of UTF-8, nonblank, no character of
# General Category Cc, Cf, Zl or Zp; Atem's proposal, #120 7207832274,
# agreed with Astation, #120 7212501350 and 7213560895).
ROUTE_REFUSAL_CODES = [
    "malformed", "frozen", "wrong_account", "unknown_host", "bad_signature",
    "stale_log", "fork", "nonce_mismatch", "room_mismatch", "atem_id_mismatch",
]
STATION_ROUTE_REFUSALS = ["service_suspended"]
ROUTE_MESSAGE_MAX = 16 * 1024
SERVICE_TEXT_MAX = 256
SERVICE_NOTICE_MAX = 1024


def service_text_ok(text):
    """A Station's text a host shows: 1-256 bytes of UTF-8, nonblank
    (something besides White_Space, WHITE_SPACE above: Astation's item 3,
    #120 7213560895), no Cc, Cf, Zl (U+2028) or Zp (U+2029) character."""
    return (
        isinstance(text, str)
        and 1 <= len(text.encode("utf-8")) <= SERVICE_TEXT_MAX
        and any(c not in WHITE_SPACE for c in text)
        and not any(is_control(c) or is_format(c) or c in "\u2028\u2029" for c in text)
    )


def relay_object(text, op, bound):
    """A strict relay message of `op` (type relay, v 1) within `bound`
    bytes; raises Refused with the shared core's codes (too_large,
    not_strict_json, malformed)."""
    if len(text.encode("utf-8")) > bound:
        raise Refused("too_large")
    try:
        o = relay_parse(text)
    except ValueError:
        raise Refused("not_strict_json")
    if not isinstance(o, dict) or o.get("type") != "relay" or o.get("op") != op:
        raise Refused("malformed")
    if type(o.get("v")) is not int or o["v"] != 1:
        raise Refused("malformed")
    return o


def route_reply(text):
    """host_route_ok or host_route_refused, exactly: ("ok", host_id, head),
    ("refused", code) or ("suspended", text); raises Refused("malformed")
    (R9.7b: every bad reply is malformed)."""
    try:
        value = json.loads(text)
    except ValueError:
        raise Refused("malformed")
    if not isinstance(value, dict):
        raise Refused("malformed")
    op = value.get("op")
    try:
        o = relay_object(text, op, ROUTE_MESSAGE_MAX)
    except Refused:
        raise Refused("malformed")
    if op == "host_route_ok":
        head = o.get("head")
        ok = (
            set(o) == {"type", "op", "v", "host_id", "head"}
            and isinstance(o["host_id"], str) and 1 <= len(o["host_id"].encode()) <= 256
            and isinstance(head, dict) and set(head) == {"seq", "hash"}
            and type(head["seq"]) is int and head["seq"] >= 1
            and isinstance(head["hash"], str) and re.fullmatch(r"[0-9a-f]{64}", head["hash"]) is not None
        )
        if not ok:
            raise Refused("malformed")
        return ("ok", o["host_id"], head)
    if op != "host_route_refused":
        raise Refused("malformed")
    code = o.get("code")
    if code in ROUTE_REFUSAL_CODES:
        if set(o) != {"type", "op", "v", "code"}:
            raise Refused("malformed")
        return ("refused", code)
    if code in STATION_ROUTE_REFUSALS:
        if set(o) != {"type", "op", "v", "code", "text"} or not service_text_ok(o["text"]):
            raise Refused("malformed")
        return ("suspended", o["text"])
    raise Refused("malformed")


def service_notice(text):
    """The open link's service_suspended notice, exactly: its text; raises
    Refused (too_large over 1024 bytes as received, not_strict_json,
    malformed)."""
    o = relay_object(text, "service_suspended", SERVICE_NOTICE_MAX)
    if set(o) != {"type", "op", "v", "text"} or not service_text_ok(o["text"]):
        raise Refused("malformed")
    return o["text"]


def check_route_replies(file, data, report):
    """Every relay reply's verdict and every service_suspended notice's,
    from the readers above: a valid case reads to its `expect`, an invalid
    one is refused with its code; a verifier code never carries a text, and
    service_suspended is no verifier code."""
    replies = data["relay_replies"]
    for vector in replies["valid"]:
        with report.case(file, f"relay reply {vector['label']}") as case:
            got = route_reply(json.dumps(vector["message"], ensure_ascii=False))
            expect = vector["expect"]
            if got[0] == "ok":
                case.equal((got[1], got[2]), (expect["host_id"], expect["head"]), "host_id and head")
            elif got[0] == "refused":
                case.equal((got[1], "text" in expect), (expect["code"], False), "a verifier code, no text")
            else:
                case.equal(("service_suspended", got[1]), (expect["code"], expect["text"]), "service_suspended and its text")
    for vector in replies["invalid"]:
        with report.case(file, f"relay reply {vector['label']}") as case:
            try:
                route_reply(vector["text"])
                case.check(False, "refused")
            except Refused as refused:
                case.equal(refused.code, "malformed", "refused malformed")
    with report.case(file, "relay reply coverage") as case:
        case.check(not set(STATION_ROUTE_REFUSALS) & set(ROUTE_REFUSAL_CODES), "service_suspended is no verifier code")
        kinds = {route_reply(json.dumps(v["message"]))[0] for v in replies["valid"]}
        case.equal(kinds, {"ok", "refused", "suspended"}, "an ok, a verifier code and a suspension")
    notices = data["service_suspended"]
    for vector in notices["valid"]:
        with report.case(file, f"service_suspended {vector['label']}") as case:
            text = vector["text"] if "text" in vector else json.dumps(vector["message"], ensure_ascii=False)
            case.equal(service_notice(text), vector["expect"]["text"], "its text")
    for vector in notices["invalid"]:
        with report.case(file, f"service_suspended {vector['label']}") as case:
            try:
                service_notice(vector["text"])
                case.check(False, "refused")
            except Refused as refused:
                case.equal(refused.code, vector["code"], "the refusal's code")


# ------------------------------------------------ r9-vectors-verifier-report

# A member's signed verifier report (session-v1 R9.2 "How a verifier reports
# itself"; agreed for implementation on Astation #101): its body's fields,
# the body's challenge echo, and the challenge a minter stores.
VR_BODY_FIELDS = ["account_id", "challenge", "genesis_hash", "head", "process", "signer", "slot", "type", "v", "verifier"]
VR_ECHO_FIELDS = ["connection", "expires_at", "issued_at", "nonce", "origin"]
VR_CHALLENGE_FIELDS = ["connection", "expires_at", "issued_at", "nonce", "origin", "signer", "slot"]
VR_LABEL = "atem-verifier-report-v1"
VR_MAX_LEASE_MS = 30_000
VR_MAX_CHALLENGE_BYTES = 4096
VR_MAX_OBJECT_BYTES = 16 * 1024
# The report's signer: an r9 principal name with an opaque id; only a
# member and a service can sign (the others are unknown_signer).
VR_SIGNER = r"(member|service|host|browser):([A-Za-z0-9._:-]{1,128})"


def b64u_encode(raw):
    import base64

    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def vr_int(v, low=0):
    return type(v) is int and low <= v <= SAFE_MAX


def vr_b64u(v, n):
    try:
        return isinstance(v, str) and len(b64u_decode(v)) == n
    except ValueError:
        return False


def vr_echo(o):
    """The fields a challenge and a body's echo share, by R9.2's report
    rules; raises Refused("malformed")."""
    if not isinstance(o["origin"], str) or not relay_origin_ok(o["origin"]):
        raise Refused("malformed")
    if not vr_int(o["connection"], 1) or not vr_b64u(o["nonce"], 32):
        raise Refused("malformed")
    issued, expires = o["issued_at"], o["expires_at"]
    if not vr_int(issued) or not vr_int(expires) or not 0 < expires - issued <= VR_MAX_LEASE_MS:
        raise Refused("malformed")


def vr_strict(text, bound):
    if len(text.encode("utf-8")) > bound:
        raise Refused("malformed")
    try:
        return relay_parse(text)
    except ValueError:  # NotStrict, and json's own errors
        raise Refused("malformed")


def read_vr_challenge(text):
    """ReportChallenge::parse as written from the file's note: exactly the
    seven fields, the signer a member or a service."""
    value = vr_strict(text, VR_MAX_CHALLENGE_BYTES)
    if not isinstance(value, dict) or sorted(value) != VR_CHALLENGE_FIELDS:
        raise Refused("malformed")
    signer = value["signer"]
    m = re.fullmatch(VR_SIGNER, signer) if isinstance(signer, str) else None
    if m is None or m.group(1) not in ("member", "service"):
        raise Refused("malformed")
    if not isinstance(value["slot"], str) or re.fullmatch(OPAQUE_ID, value["slot"]) is None:
        raise Refused("malformed")
    vr_echo(value)
    return value


def vr_arrays_ok(value, path=()):
    """No null anywhere; an array only at verifier.actions (a set: strictly
    ascending by bytes)."""
    if value is None:
        return False
    if isinstance(value, dict):
        return all(vr_arrays_ok(v, path + (k,)) for k, v in value.items())
    if isinstance(value, list):
        if path != ("verifier", "actions") or not all(isinstance(v, str) for v in value):
            return False
        raw = [v.encode() for v in value]
        return all(a < b for a, b in zip(raw, raw[1:]))
    return True


def read_vr_report(text):
    """The report as the shared core reads it: strict I-JSON within 16 KiB,
    exactly body and sig, the body's jcs within 4,096 bytes, exactly its
    fields at every level and each field's grammar. Returns (body, sig)."""
    value = vr_strict(text, VR_MAX_OBJECT_BYTES)
    if not isinstance(value, dict) or sorted(value) != ["body", "sig"]:
        raise Refused("malformed")
    body = value["body"]
    try:
        sig = b64u_decode(value["sig"])
    except ValueError:
        raise Refused("malformed")
    if not isinstance(body, dict) or not vr_arrays_ok(body):
        raise Refused("malformed")
    if body.get("type") != "atem-verifier-report" or type(body.get("v")) is not int or body["v"] != 1:
        raise Refused("malformed")
    if len(jcs(body).encode("utf-8")) > MAX_BODY_BYTES or sorted(body) != VR_BODY_FIELDS:
        raise Refused("malformed")
    account = body["account_id"]
    if not isinstance(account, str) or not 1 <= len(account.encode()) <= 128:
        raise Refused("malformed")
    for text_field in ("genesis_hash",):
        if not isinstance(body[text_field], str) or re.fullmatch(HEX64, body[text_field]) is None:
            raise Refused("malformed")
    head = body["head"]
    if (
        not isinstance(head, dict) or sorted(head) != ["hash", "seq"] or not vr_int(head["seq"], 1)
        or not isinstance(head["hash"], str) or re.fullmatch(HEX64, head["hash"]) is None
    ):
        raise Refused("malformed")
    if not isinstance(body["signer"], str) or re.fullmatch(VR_SIGNER, body["signer"]) is None:
        raise Refused("malformed")
    if not isinstance(body["slot"], str) or re.fullmatch(OPAQUE_ID, body["slot"]) is None:
        raise Refused("malformed")
    if not vr_b64u(body["process"], 16):
        raise Refused("malformed")
    echo = body["challenge"]
    if not isinstance(echo, dict) or sorted(echo) != VR_ECHO_FIELDS:
        raise Refused("malformed")
    vr_echo(echo)
    if not verifier_ok(body["verifier"]):
        raise Refused("malformed")
    return body, sig


class VrList:
    """A device list as the report's checks read it, replayed from L and a
    case's chain: who is a member of which kind and with which key, the
    chain's entry hashes, and a freeze. A recovery_add is pending until a
    recovery_approve naming its entry_hash makes it take effect (its member
    then current: `recovered`) or a recovery_veto cancels it (R9.5), as the
    shared verifier reads them. Its 24 h wait never ends here: each of the
    vectors' lists is read at one host clock reading, the one its entries
    were carried at."""

    def __init__(self, bodies, frozen):
        self.members, self.hashes, self.frozen = {}, [], frozen
        self.recovered = set()
        pending = {}
        for body in bodies:
            self.hashes.append(sha256(enc(["atem-membership-hash-v1", jcs(body)])).hex())
            action = body["action"]
            if action in ("genesis", "add"):
                member = body["member"]
                self.members[member["device_id"]] = dict(member, standing="active")
            elif action == "recovery_add":
                self.members[body["member"]["device_id"]] = dict(body["member"], standing="pending")
                pending[self.hashes[-1]] = body["member"]["device_id"]
            elif action in ("recovery_approve", "recovery_veto") and body["target"] in pending:
                device_id = pending.pop(body["target"])
                if action == "recovery_approve":
                    self.members[device_id]["standing"] = "active"
                    self.recovered.add(device_id)
                else:
                    self.members[device_id]["standing"] = "cancelled"
            elif action == "set_roles" and "roles" in body:
                # Roles change, the standing and the key don't.
                self.members[body["device_id"]]["roles"] = body["roles"]
            elif action == "remove":
                self.members[body["device_id"]]["standing"] = "removed"
        self.account_id = bodies[0]["account_id"]
        self.genesis_hash = self.hashes[0]

    def head(self):
        return {"seq": len(self.hashes), "hash": self.hashes[-1]}

    def signer(self, signer, now):
        """(kind, alg, public key) of a current signer, or Refused."""
        m = re.fullmatch(VR_SIGNER, signer)
        kind = {"member": "native", "service": "service"}.get(m.group(1))
        member = self.members.get(m.group(2))
        if kind is None or member is None or member["standing"] != "active" or member["kind"] != kind:
            raise Refused("unknown_signer")
        if kind == "service" and now >= member["expires_at"]:
            raise Refused("signer_expired")
        return kind, member["auth_key"]["alg"], b64u_decode(member["auth_key"]["pub"])


def vr_verify(text, lst, expected, now):
    """verify_verifier_report, from the file's note: the first failure in
    the agreed order, or the verified report."""
    body, sig = read_vr_report(text)
    if lst.frozen:
        raise Refused("frozen")
    if body["account_id"] != lst.account_id or body["genesis_hash"] != lst.genesis_hash:
        raise Refused("wrong_account")
    kind, alg, public = lst.signer(body["signer"], now)
    if not verify(alg, public, sig, enc([VR_LABEL, jcs(body)])):
        raise Refused("bad_signature")
    head = body["head"]
    if head["seq"] > len(lst.hashes):
        raise Refused("stale_log")
    if lst.hashes[head["seq"] - 1] != head["hash"]:
        raise Refused("fork")
    if body["signer"] != expected["signer"]:
        raise Refused("signer_mismatch")
    if body["slot"] != expected["slot"]:
        raise Refused("slot_mismatch")
    if any(body["challenge"][k] != expected[k] for k in VR_ECHO_FIELDS):
        raise Refused("challenge_mismatch")
    if now >= expected["expires_at"]:
        raise Refused("expired")
    return {
        "signer": body["signer"], "kind": kind, "slot": body["slot"], "process": body["process"],
        "connection": body["challenge"]["connection"], "head": head, "at_head": head == lst.head(),
        "inventory": body["verifier"], "expires_at": body["challenge"]["expires_at"],
    }


def vr_normalize(origin):
    """station_route::normalize_relay for a configured Station: the scheme
    and host lowercased, a default port and a lone trailing "/" dropped;
    None for anything it refuses."""
    if not isinstance(origin, str) or not origin.isascii() or len(origin) > 1024 or "@" in origin:
        return None
    m = re.fullmatch(r"([A-Za-z][A-Za-z0-9+.-]*)://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::([0-9]{1,5}))?/?", origin)
    if m is None:
        return None
    scheme, host, port = m.group(1).lower(), m.group(2).lower(), m.group(3)
    if port is not None and int(port) == {"https": 443, "http": 80}.get(scheme):
        port = None
    out = f"{scheme}://{host}" + (f":{int(port)}" if port is not None else "")
    return out if relay_origin_ok(out) else None


def vr_build(case, lst, inventory):
    """verifier_report_body, from the file's note: the body but its process,
    or Refused."""
    signer, slot, now, challenge = case["signer"], case["slot"], case["now_ms"], case["challenge"]
    m = re.fullmatch(VR_SIGNER, signer)
    if m is None or m.group(1) not in ("member", "service") or re.fullmatch(OPAQUE_ID, slot) is None:
        raise Refused("malformed")
    station = vr_normalize(case["station"])
    if station is None:
        raise Refused("malformed")
    if lst.frozen:
        raise Refused("frozen")
    if challenge["origin"] != station:
        raise Refused("origin_mismatch")
    if challenge["signer"] != signer:
        raise Refused("signer_mismatch")
    if challenge["slot"] != slot:
        raise Refused("slot_mismatch")
    lst.signer(signer, now)
    if now >= challenge["expires_at"]:
        raise Refused("expired")
    return {
        "type": "atem-verifier-report", "v": 1, "account_id": lst.account_id, "genesis_hash": lst.genesis_hash,
        "head": lst.head(), "signer": signer, "slot": slot,
        "challenge": {k: challenge[k] for k in VR_ECHO_FIELDS}, "verifier": inventory,
    }


def vr_sign(keys, name, message):
    """A signature by an r9-vectors-keys key (`<name>/<part>`), P-256 low S."""
    key_name, part = name.split("/")
    entry = keys.keys[key_name]
    key = entry if part == "" else entry[part]
    secret = unhex(key["secret_hex"])
    if key["alg"] == "ed25519":
        return ed25519.Ed25519PrivateKey.from_private_bytes(secret).sign(message)
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    der = ec.derive_private_key(int.from_bytes(secret, "big"), ec.SECP256R1()).sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    s = min(s, P256_N - s)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def report_bodies(data, mlog, labels):
    """Log L's entry bodies, then the file's `entries` named by `labels`."""
    entries = {e["label"]: e for e in data["entries"]}
    return [v["entry"]["body"] for v in mlog["log"]] + [entries[label]["entry"]["body"] for label in labels]


def check_report_entries(case, data, mlog):
    """Each of a report file's `entries`: it chains on L and the entries it
    extends (`on`), its seq and entry_hash, and its signature by its
    signer's key on that list (a current member's auth_key, or the recovery
    key of L's genesis)."""
    for e in data["entries"]:
        body = e["entry"]["body"]
        base = report_bodies(data, mlog, e["on"])
        case.equal(body["prev_hash"], sha256(enc(["atem-membership-hash-v1", jcs(base[-1])])).hex(), f"{e['label']} chains on L + {e['on']}")
        case.equal(body["seq"], len(base) + 1, f"{e['label']} seq")
        case.equal(sha256(enc(["atem-membership-hash-v1", jcs(body)])).hex(), e["entry_hash"], f"{e['label']} entry_hash")
        if body["signer"] == "recovery":
            key = base[0]["recovery_key"]
        else:
            member = VrList(base, False).members.get(body["signer"], {})
            key = member.get("auth_key") if member.get("standing") == "active" else None
        case.check(
            key is not None and verify(key["alg"], b64u_decode(key["pub"]), b64u_decode(e["entry"]["sig"]), enc(["atem-membership-entry-v1", jcs(body)])),
            f"{e['label']} signed by {body['signer']}",
        )


def report_list(c, data, mlog, cls):
    """A case's list: L, its chain (each entry extending the ones before
    it), then its `freeze` carriage when it names one."""
    entries = {e["label"]: e for e in data["entries"]}
    for i, label in enumerate(c["chain"]):
        if entries[label]["on"] != c["chain"][:i]:
            raise ValueError(f"{label} doesn't extend {c['chain'][:i]}")
    bodies = report_bodies(data, mlog, c["chain"])
    frozen = False
    if "freeze" in c:
        # A carriage at a position the list holds, by a current manager,
        # another body: the conflict rule freezes (R9.4).
        others = {v["label"]: v["entry"]["body"] for v in mlog["log"] + mlog["others"]}
        other = others[c["freeze"]]
        signer = VrList(bodies, False).members.get(other["signer"], {})
        frozen = (
            other["seq"] <= len(bodies)
            and jcs(other) != jcs(bodies[other["seq"] - 1])
            and signer.get("standing") == "active"
            and "manage" in signer.get("roles", [])
        )
    return cls(bodies, frozen)


def check_verifier_report(file, data, report, context):
    """Every case's verdict derived here from the file's note (R9.2's report
    as agreed on Astation #101): each challenge text read or refused; each
    report's code in the agreed order, or its verified fields, against log
    L and the case's chain (the entries' signatures verified with dev-mac's
    key, the hashes recomputed), the valid reports' jcs, signing input and
    signature by their signer's key; the builder's bodies (but their
    process) and refusals; and the immutable request's finishes, signed
    here (P-256 with a fresh nonce) over the held body with the vectors'
    process."""
    keys = context["keys"]
    mlog = context["membership_log"]
    inventory = {"version": 2, "actions": sorted(R9_2_ACTIONS, key=str.encode)}
    entries = {e["label"]: e for e in data["entries"]}
    with report.case(file, "entries") as case:
        check_report_entries(case, data, mlog)
        desk = entries["VR7_add_desk"]["entry"]["body"]["member"]
        case.equal((desk["auth_key"]["alg"], b64u_decode(desk["auth_key"]["pub"])), ("ed25519", keys.public("dev-desk", "auth")), "dev-desk's Ed25519 key")
        case.equal(jcs(entries["VR7_recovery_add_newmac"]["entry"]), jcs(next(v["entry"] for v in mlog["others"] if v["label"] == "R7")), "VR7_recovery_add_newmac is R7, byte for byte")

    def lst(c):
        return report_list(c, data, mlog, VrList)

    for c in data["challenges"]:
        with report.case(file, f"challenge {c['label']}") as case:
            try:
                fields = read_vr_challenge(c["text"])
                case.equal(fields, c.get("fields"), "read, its fields")
            except Refused as e:
                case.equal(e.code, c.get("code"), "refused")
    codes = set()
    for c in data["valid"] + data["invalid"]:
        with report.case(file, f"report {c['label']}") as case:
            expected = read_vr_challenge(json.dumps(c["challenge"]))
            try:
                verified = vr_verify(c["report"], lst(c), expected, c["now_ms"])
                case.equal(verified, c.get("expect"), "verified")
                body = json.loads(c["report"])["body"]
                case.equal(jcs(body), c["jcs"], "jcs")
                case.equal(enc([VR_LABEL, jcs(body)]).hex(), c["signing_input_hex"], "signing input")
                name, part = c["signed_with"].split("/")
                case.check(
                    verify(keys.keys[name][part]["alg"], keys.public(name, part), b64u_decode(json.loads(c["report"])["sig"]), enc([VR_LABEL, jcs(body)])),
                    f"signed by {c['signed_with']}",
                )
            except Refused as e:
                case.equal(e.code, c.get("code"), "refused")
                codes.add(e.code)
                if c["label"] == "high_s_signature":
                    # A genuine malleation: S above n / 2, and its low-S twin
                    # is the signer's valid signature.
                    report_ = json.loads(c["report"])
                    sig = b64u_decode(report_["sig"])
                    s_ = int.from_bytes(sig[32:], "big")
                    case.check(s_ > P256_N // 2, "S is high")
                    twin = sig[:32] + (P256_N - s_).to_bytes(32, "big")
                    case.check(verify("p256", keys.public("dev-phone", "auth"), twin, enc([VR_LABEL, jcs(report_["body"])])), "its low-S twin verifies")
    with report.case(file, "coverage") as case:
        case.equal(sorted(codes), sorted(["malformed", "frozen", "wrong_account", "unknown_signer", "signer_expired", "bad_signature", "stale_log", "fork", "signer_mismatch", "slot_mismatch", "challenge_mismatch", "expired"]), "every verifier code")
        labels = {c["label"] for c in data["valid"] + data["invalid"]}
        for label in ("native_after_set_roles", "native_after_set_roles_at_head", "pending_recovery_subject", "high_s_signature"):
            case.check(label in labels, f"{label} present")
    for c in data["builder"] + data["request"]:
        with report.case(file, f"builder {c['label']}") as case:
            try:
                body = vr_build(c, lst(c), inventory)
                case.equal(body, c.get("body_but_process"), "the body but its process")
            except Refused as e:
                case.equal(e.code, c.get("code"), "refused")
    for c in data["request"]:
        with report.case(file, f"request {c['label']}") as case:
            case.equal(c["sign_request"], {"purpose": "verifier_report", "fresh_confirmation": False, "label": VR_LABEL}, "sign request")
            held = dict(c["body_but_process"], process=b64u_encode(b"vectors-process!"))
            signer_alg = keys.keys[c["key"].split("/")[0]]["auth"]["alg"]
            signer_pub = keys.public(c["key"].split("/")[0], "auth")
            for f in c["finishes"]:
                if f["over"] == "held":
                    over = held
                else:
                    over = dict(held, slot=f["over"]["slot"])
                sig = vr_sign(keys, f["signed_with"], enc([VR_LABEL, jcs(over)]))
                ok = verify(signer_alg, signer_pub, sig, enc([VR_LABEL, jcs(held)]))
                case.equal(ok, "code" not in f, f"{f['label']}: {'taken' if ok else 'refused'}")
                if not ok:
                    case.equal(f["code"], "bad_signature", f"{f['label']}: bad_signature")


# ------------------------------------------------ r9-vectors-signer-report

# A native manager's signed report of its control-record signing journal
# (host-work-v1 §11.1 "The signer report"; Astation #114 item 4, agreed on
# #114 comment 7089435073): the verifier report's core with a recovery and a
# journal in place of the inventory.
SR_BODY_FIELDS = sorted(["account_id", "challenge", "genesis_hash", "head", "journal", "process", "recovery", "signer", "slot", "type", "v"])
SR_CHALLENGE_FIELDS = sorted(VR_CHALLENGE_FIELDS + ["recovery"])
SR_RECOVERY_FIELDS = ["candidate_feed_id", "evidence_hash", "generation", "plan_id", "source_hash"]
SR_JOURNAL_FIELDS = ["drafts", "drafts_hash", "id", "records", "records_hash", "revision", "since"]
SR_LABEL = "atem-signer-report-v1"
SR_RECORDS = "atem-signer-report-records-v1"
SR_DRAFTS = "atem-signer-report-drafts-v1"
SR_MAX_GENERATION = 2**63 - 1
SR_VERIFY_ORDER = [
    "malformed", "frozen", "wrong_account", "unknown_signer", "not_a_manager", "bad_signature", "stale_log", "fork",
    "signer_mismatch", "slot_mismatch", "challenge_mismatch", "recovery_mismatch", "records_mismatch", "expired",
]
CONTROL_LABEL = "atem-host-work-control-v1"
# A control record's body fields (record.rs, delegated host-work I.5.3).
CONTROL_FIELDS = {
    "type", "v", "account_id", "genesis_hash", "origin", "feed_id", "principal", "principal_key", "signer",
    "action", "interrupt_running", "revoke_seq", "record_id", "issued_at", "about",
}


def sr_device_id(text, prefix):
    """`<prefix><id>`, the id opaque and not the reserved `recovery`."""
    return (
        isinstance(text, str) and text.startswith(prefix)
        and re.fullmatch(OPAQUE_ID, text[len(prefix):]) is not None and text[len(prefix):] != "recovery"
    )


def sr_flat(value):
    """No null and no array anywhere (a control record's body and a signer
    report's have no array)."""
    if value is None or isinstance(value, list):
        return False
    if isinstance(value, dict):
        return all(sr_flat(v) for v in value.values())
    return True


def sr_control_body(value):
    """A control record's body exactly as ControlBody::from_json reads it
    (R9.1's object rules, then I.5.3's two forms), or Refused("malformed")."""
    if not isinstance(value, dict) or not sr_flat(value):
        raise Refused("malformed")
    if value.get("type") != "atem-host-work-control" or type(value.get("v")) is not int or value["v"] != 1:
        raise Refused("malformed")
    if len(jcs(value).encode()) > MAX_BODY_BYTES or not set(value) <= CONTROL_FIELDS:
        raise Refused("malformed")
    about = value.get("about")
    if not isinstance(about, dict) or not set(about) <= {"integration_id", "by"}:
        raise Refused("malformed")
    account = value.get("account_id")
    ok = isinstance(account, str) and 1 <= len(account.encode()) <= 128
    ok = ok and isinstance(value.get("genesis_hash"), str) and re.fullmatch(HEX64, value["genesis_hash"]) is not None
    principal, signer, action = value.get("principal"), value.get("signer"), value.get("action")
    service = sr_device_id(principal, "service:")
    host = isinstance(principal, str) and principal.startswith("host:") and re.fullmatch(OPAQUE_ID, principal[5:]) is not None
    ok = ok and (service or host)
    ok = ok and (signer == principal or sr_device_id(signer, "member:"))
    ok = ok and action in ("cover", "revoke", "hold", "release", "interrupt_running")
    if ok and service:
        ok = (
            relay_origin_ok(value.get("origin"))
            and isinstance(value.get("feed_id"), str) and re.fullmatch(UUID_V4, value["feed_id"]) is not None
            and isinstance(value.get("principal_key"), str) and re.fullmatch(HEX64, value["principal_key"]) is not None
            and "revoke_seq" not in value
            and (isinstance(value.get("interrupt_running"), bool) if action == "revoke" else "interrupt_running" not in value)
            and isinstance(about.get("integration_id"), str) and re.fullmatch(OPAQUE_ID, about["integration_id"]) is not None
        )
    elif ok:
        ok = (
            action == "interrupt_running"
            and not {"origin", "feed_id", "principal_key", "interrupt_running"} & set(value)
            and "integration_id" not in about
            and vr_int(value.get("revoke_seq"), 1)
        )
    ok = ok and isinstance(value.get("record_id"), str) and re.fullmatch(UUID_V4, value["record_id"]) is not None
    ok = ok and vr_int(value.get("issued_at"))
    by = about.get("by")
    ok = ok and isinstance(by, str) and re.fullmatch(r"[a-z_]{1,32}", by) is not None
    if not ok:
        raise Refused("malformed")
    return value


# Why a body isn't one of the plan's records, in the order the predicate
# checks (signer_report_plan_record).
SR_OUT_OF_PLAN = ["another_account", "another_genesis", "another_signer", "another_origin"]


def sr_plan_record(body, lst, member, origin):
    """The plan predicate (B2) on a control-record body as sr_control_body
    reads it, from the file's note: None when it is one of the plan's
    records by `member:<member>` at `origin` (a service's revoke or
    interrupt_running naming `origin`, or a host principal's
    interrupt_running, which names none), else why not, in the order
    checked: another_account, another_genesis, another_signer, then
    another_origin. This member's cover, hold or release is
    Refused("malformed") (judged after the signer, before the origin: a
    native manager signs none)."""
    if body["account_id"] != lst.account_id:
        return "another_account"
    if body["genesis_hash"] != lst.genesis_hash:
        return "another_genesis"
    if body["signer"] != f"member:{member}":
        return "another_signer"
    if body["action"] in ("cover", "hold", "release"):
        raise Refused("malformed")
    if body["principal"].startswith("service:"):
        return None if body["origin"] == origin else "another_origin"
    return None


def sr_of_plan(body, lst, member, origin):
    """One of the plan's records by `member:<member>` (B2): the predicate
    answers it in the plan."""
    try:
        return sr_plan_record(body, lst, member, origin) is None
    except Refused:
        return False


def sr_plan_predicate(c, lst):
    """signer_report_plan_record, from the file's note: the member
    member:<id> and the origin in its exact form (else malformed), the body
    read as the builder reads a journal's (strict within 16 KiB, exactly a
    control record's body, else malformed), then the predicate."""
    m = re.fullmatch(VR_SIGNER, c["member"])
    if m is None or m.group(1) != "member" or not relay_origin_ok(c["origin"]):
        raise Refused("malformed")
    body = sr_control_body(vr_strict(c["body"], VR_MAX_OBJECT_BYTES))
    return sr_plan_record(body, lst, m.group(2), c["origin"])


def sr_set_hash(label, digests):
    return sha256(enc([label] + sorted(digests))).hex()


def sr_recovery_ok(o):
    """The recovery's five fields: generation a canonical decimal 1 to 2^63 - 1,
    plan_id and candidate_feed_id UUID v4, the hashes lowercase hex."""
    if not isinstance(o, dict) or sorted(o) != SR_RECOVERY_FIELDS:
        return False
    g = o["generation"]
    if not isinstance(g, str) or re.fullmatch(r"[1-9][0-9]{0,18}", g) is None or int(g) > SR_MAX_GENERATION:
        return False
    if not all(isinstance(o[k], str) and re.fullmatch(UUID_V4, o[k]) is not None for k in ("plan_id", "candidate_feed_id")):
        return False
    return all(isinstance(o[k], str) and re.fullmatch(HEX64, o[k]) is not None for k in ("source_hash", "evidence_hash"))


def sr_journal_ok(o):
    if not isinstance(o, dict) or sorted(o) != SR_JOURNAL_FIELDS:
        return False
    return (
        vr_b64u(o["id"], 16) and vr_int(o["since"], 1) and vr_int(o["revision"]) and vr_int(o["records"]) and vr_int(o["drafts"])
        and all(isinstance(o[k], str) and re.fullmatch(HEX64, o[k]) is not None for k in ("records_hash", "drafts_hash"))
    )


def read_sr_challenge(text):
    """SignerReportChallenge::parse as the file's note writes it: the
    verifier report's challenge, its signer a member, and the recovery."""
    value = vr_strict(text, VR_MAX_CHALLENGE_BYTES)
    if not isinstance(value, dict) or sorted(value) != SR_CHALLENGE_FIELDS:
        raise Refused("malformed")
    signer = value["signer"]
    m = re.fullmatch(VR_SIGNER, signer) if isinstance(signer, str) else None
    if m is None or m.group(1) != "member":
        raise Refused("malformed")
    if not isinstance(value["slot"], str) or re.fullmatch(OPAQUE_ID, value["slot"]) is None:
        raise Refused("malformed")
    vr_echo(value)
    if not sr_recovery_ok(value["recovery"]):
        raise Refused("malformed")
    return value


def read_sr_report(text):
    """The report as the shared core reads it: strict I-JSON within 16 KiB,
    exactly body and sig, no null and no array, the body's jcs within 4,096
    bytes, exactly its fields at every level and each field's grammar."""
    value = vr_strict(text, VR_MAX_OBJECT_BYTES)
    if not isinstance(value, dict) or sorted(value) != ["body", "sig"]:
        raise Refused("malformed")
    body = value["body"]
    try:
        sig = b64u_decode(value["sig"])
    except ValueError:
        raise Refused("malformed")
    if not isinstance(body, dict) or not sr_flat(body):
        raise Refused("malformed")
    if body.get("type") != "atem-signer-report" or type(body.get("v")) is not int or body["v"] != 1:
        raise Refused("malformed")
    if len(jcs(body).encode("utf-8")) > MAX_BODY_BYTES or sorted(body) != SR_BODY_FIELDS:
        raise Refused("malformed")
    account = body["account_id"]
    if not isinstance(account, str) or not 1 <= len(account.encode()) <= 128:
        raise Refused("malformed")
    if not isinstance(body["genesis_hash"], str) or re.fullmatch(HEX64, body["genesis_hash"]) is None:
        raise Refused("malformed")
    head = body["head"]
    if (
        not isinstance(head, dict) or sorted(head) != ["hash", "seq"] or not vr_int(head["seq"], 1)
        or not isinstance(head["hash"], str) or re.fullmatch(HEX64, head["hash"]) is None
    ):
        raise Refused("malformed")
    if not isinstance(body["signer"], str) or re.fullmatch(VR_SIGNER, body["signer"]) is None:
        raise Refused("malformed")
    if not isinstance(body["slot"], str) or re.fullmatch(OPAQUE_ID, body["slot"]) is None:
        raise Refused("malformed")
    if not vr_b64u(body["process"], 16):
        raise Refused("malformed")
    echo = body["challenge"]
    if not isinstance(echo, dict) or sorted(echo) != VR_ECHO_FIELDS:
        raise Refused("malformed")
    vr_echo(echo)
    if not sr_recovery_ok(body["recovery"]) or not sr_journal_ok(body["journal"]):
        raise Refused("malformed")
    return body, sig


class SrList(VrList):
    """VrList, with who held manage at some seq of it: a native entering
    with manage (genesis, add, or a recovery_add once it took effect), or
    given it by set_roles. A recovery_add still waiting gives nothing."""

    def __init__(self, bodies, frozen):
        super().__init__(bodies, frozen)
        self.managed = set()
        for body in bodies:
            if body["action"] in ("genesis", "add"):
                member = body["member"]
                if member["kind"] == "native" and "manage" in member["roles"]:
                    self.managed.add(member["device_id"])
            elif body["action"] == "set_roles" and "manage" in body.get("roles", []):
                self.managed.add(body["device_id"])
        # A recovery_add's member (always [control, manage, view]) once its
        # recovery took effect.
        for device_id in self.recovered:
            if "manage" in self.members[device_id]["roles"]:
                self.managed.add(device_id)

    def manager(self, signer):
        """(alg, public key) of a current native member that held manage, or
        Refused (unknown_signer, not_a_manager)."""
        m = re.fullmatch(VR_SIGNER, signer)
        member = self.members.get(m.group(2)) if m.group(1) == "member" else None
        if member is None or member["standing"] != "active" or member["kind"] != "native":
            raise Refused("unknown_signer")
        if m.group(2) not in self.managed:
            raise Refused("not_a_manager")
        return member["auth_key"]["alg"], b64u_decode(member["auth_key"]["pub"])


def sr_exported(exported, journal, lst, member, origin, alg, public):
    """The exported records against the report's records: each a signed
    control record of the plan by this member, its signature verified
    (low S), none twice, their count and records_hash the journal's."""
    digests = []
    for text in exported:
        try:
            value = vr_strict(text, VR_MAX_OBJECT_BYTES)
            if not isinstance(value, dict) or sorted(value) != ["body", "sig"]:
                raise Refused("records_mismatch")
            body = sr_control_body(value["body"])
            sig = b64u_decode(value["sig"])
        except (Refused, ValueError):
            raise Refused("records_mismatch")
        if not sr_of_plan(body, lst, member, origin):
            raise Refused("records_mismatch")
        if not verify(alg, public, sig, enc([CONTROL_LABEL, jcs(body)])):
            raise Refused("records_mismatch")
        digests.append(sha256(jcs(body).encode()))
    if len(set(digests)) != len(digests) or len(digests) != journal["records"]:
        raise Refused("records_mismatch")
    if sr_set_hash(SR_RECORDS, digests) != journal["records_hash"]:
        raise Refused("records_mismatch")
    return [jcs(vr_strict(t, VR_MAX_OBJECT_BYTES)) for t in exported]


def sr_verify(text, lst, expected, exported, now):
    """verify_signer_report, from the file's note: the first failure in the
    agreed order, or the verified report."""
    body, sig = read_sr_report(text)
    if lst.frozen:
        raise Refused("frozen")
    if body["account_id"] != lst.account_id or body["genesis_hash"] != lst.genesis_hash:
        raise Refused("wrong_account")
    alg, public = lst.manager(body["signer"])
    if not verify(alg, public, sig, enc([SR_LABEL, jcs(body)])):
        raise Refused("bad_signature")
    head = body["head"]
    if head["seq"] > len(lst.hashes):
        raise Refused("stale_log")
    if lst.hashes[head["seq"] - 1] != head["hash"]:
        raise Refused("fork")
    if body["signer"] != expected["signer"]:
        raise Refused("signer_mismatch")
    if body["slot"] != expected["slot"]:
        raise Refused("slot_mismatch")
    if any(body["challenge"][k] != expected[k] for k in VR_ECHO_FIELDS):
        raise Refused("challenge_mismatch")
    if body["recovery"] != expected["recovery"]:
        raise Refused("recovery_mismatch")
    member = body["signer"][len("member:"):]
    records = sr_exported(exported, body["journal"], lst, member, body["challenge"]["origin"], alg, public)
    if now >= expected["expires_at"]:
        raise Refused("expired")
    return {
        "signer": body["signer"], "slot": body["slot"], "process": body["process"],
        "connection": body["challenge"]["connection"], "head": head, "at_head": head == lst.head(),
        "recovery": body["recovery"], "journal": body["journal"], "records": records,
    }


def sr_digests(texts, lst, member, origin):
    """A journal set's bodies, each read strictly as one of the plan's
    records by this member: their digests, or Refused("malformed") (a body
    twice included)."""
    digests = []
    for text in texts:
        try:
            body = sr_control_body(vr_strict(text, VR_MAX_OBJECT_BYTES))
        except Refused:
            raise Refused("malformed")
        if not sr_of_plan(body, lst, member, origin):
            raise Refused("malformed")
        digests.append(sha256(jcs(body).encode()))
    if len(set(digests)) != len(digests):
        raise Refused("malformed")
    return digests


def sr_build(case, lst):
    """signer_report_body, from the file's note: the body but its process,
    or Refused."""
    signer, slot, now, challenge, journal = case["signer"], case["slot"], case["now_ms"], case["challenge"], case["journal"]
    m = re.fullmatch(VR_SIGNER, signer)
    if m is None or m.group(1) != "member" or re.fullmatch(OPAQUE_ID, slot) is None:
        raise Refused("malformed")
    station = vr_normalize(case["station"])
    if station is None:
        raise Refused("malformed")
    if lst.frozen:
        raise Refused("frozen")
    if challenge["origin"] != station:
        raise Refused("origin_mismatch")
    if challenge["signer"] != signer:
        raise Refused("signer_mismatch")
    if challenge["slot"] != slot:
        raise Refused("slot_mismatch")
    lst.manager(signer)
    if now >= challenge["expires_at"]:
        raise Refused("expired")
    if not vr_int(journal["since"], 1) or not vr_int(journal["revision"]):
        raise Refused("malformed")
    records = sr_digests(journal["records"], lst, m.group(2), challenge["origin"])
    drafts = sr_digests(journal["drafts"], lst, m.group(2), challenge["origin"])
    return {
        "type": "atem-signer-report", "v": 1, "account_id": lst.account_id, "genesis_hash": lst.genesis_hash,
        "head": lst.head(), "signer": signer, "slot": slot,
        "challenge": {k: challenge[k] for k in VR_ECHO_FIELDS}, "recovery": challenge["recovery"],
        "journal": {
            "id": journal["id"], "since": journal["since"], "revision": journal["revision"],
            "records": len(records), "records_hash": sr_set_hash(SR_RECORDS, records),
            "drafts": len(drafts), "drafts_hash": sr_set_hash(SR_DRAFTS, drafts),
        },
    }


def check_signer_report(file, data, report, context):
    """Every case's verdict derived here from the file's note (host-work-v1
    §11.1's signer report as agreed on Astation #114): the chain's entries;
    each record's body, jcs, digest and signature by its signer's key; each
    challenge text read or refused; each report's code in the agreed order,
    or its verified fields, with its exported records against the report's
    journal (each read as a control record of the plan by the signer,
    verified, the count and the sorted-digest hash), against log L and the
    case's chain; the valid reports' jcs, signing input and signature; the
    builder's bodies (but their process) and refusals, the set hashes
    recomputed from the journal's bodies; and the immutable request's
    finishes, signed here (P-256 with a fresh nonce) over the held body with
    the vectors' process."""
    keys = context["keys"]
    mlog = context["membership_log"]
    entries = {e["label"]: e for e in data["entries"]}
    with report.case(file, "entries") as case:
        check_report_entries(case, data, mlog)
        desk = entries["SR7_add_desk"]["entry"]["body"]["member"]
        case.equal((desk["auth_key"]["alg"], b64u_decode(desk["auth_key"]["pub"])), ("ed25519", keys.public("dev-desk", "auth")), "dev-desk's Ed25519 key")
        case.check("manage" not in desk["roles"], "dev-desk added without manage")
        case.equal(jcs(entries["SR7_recovery_add_newmac"]["entry"]), jcs(next(v["entry"] for v in mlog["others"] if v["label"] == "R7")), "SR7_recovery_add_newmac is R7, byte for byte")
        case.equal(jcs(entries["SR8_recovery_approve_newmac"]["entry"]), jcs(next(v["entry"] for v in mlog["others"] if v["label"] == "A8")), "SR8_recovery_approve_newmac is A8, byte for byte")

    def lst(c):
        return report_list(c, data, mlog, SrList)

    for rec in data["records"]:
        with report.case(file, f"record {rec['label']}") as case:
            body = sr_control_body(rec["body"])
            case.equal(jcs(body), rec["jcs"], "jcs")
            case.equal(sha256(rec["jcs"].encode()).hex(), rec["digest_hex"], "digest = SHA-256(jcs(body))")
            case.equal(rec["record"]["body"], rec["body"], "the record's body")
            name, part = rec["signed_with"].split("/")
            case.check(
                verify(keys.keys[name][part]["alg"], keys.public(name, part), b64u_decode(rec["record"]["sig"]), enc([CONTROL_LABEL, rec["jcs"]])),
                f"signed by {rec['signed_with']}",
            )
            case.equal(body["signer"], f"member:{name}", "signed by the member it names")
    for c in data["challenges"]:
        with report.case(file, f"challenge {c['label']}") as case:
            try:
                fields = read_sr_challenge(c["text"])
                case.equal(fields, c.get("fields"), "read, its fields")
            except Refused as e:
                case.equal(e.code, c.get("code"), "refused")
    codes = set()
    for c in data["valid"] + data["invalid"]:
        with report.case(file, f"report {c['label']}") as case:
            expected = read_sr_challenge(json.dumps(c["challenge"]))
            try:
                verified = sr_verify(c["report"], lst(c), expected, c["exported"], c["now_ms"])
                case.equal(verified, c.get("expect"), "verified")
                body = json.loads(c["report"])["body"]
                case.equal(jcs(body), c["jcs"], "jcs")
                case.equal(enc([SR_LABEL, jcs(body)]).hex(), c["signing_input_hex"], "signing input")
                name, part = c["signed_with"].split("/")
                case.check(
                    verify(keys.keys[name][part]["alg"], keys.public(name, part), b64u_decode(json.loads(c["report"])["sig"]), enc([SR_LABEL, jcs(body)])),
                    f"signed by {c['signed_with']}",
                )
            except Refused as e:
                case.equal(e.code, c.get("code"), "refused")
                codes.add(e.code)
                if c["label"] == "high_s_signature":
                    report_ = json.loads(c["report"])
                    sig = b64u_decode(report_["sig"])
                    s_ = int.from_bytes(sig[32:], "big")
                    case.check(s_ > P256_N // 2, "S is high")
                    twin = sig[:32] + (P256_N - s_).to_bytes(32, "big")
                    case.check(verify("p256", keys.public("dev-phone", "auth"), twin, enc([SR_LABEL, jcs(report_["body"])])), "its low-S twin verifies")
    with report.case(file, "coverage") as case:
        case.equal(sorted(codes), sorted(SR_VERIFY_ORDER), "every verifier code")
        labels = {c["label"] for c in data["valid"] + data["invalid"]}
        for label in (
            "at_head", "at_ancestor", "zero_records", "drafts_only", "reinstalled_journal", "demoted_manager",
            "not_a_manager", "recovered_manager", "pending_recovery_subject", "high_s_signature", "signer_mismatch", "slot_mismatch", "records_one_missing",
            "records_one_extra", "records_signed_after_report", "records_possibly_signed", "records_body_without_signature",
            "records_wrong_signer", "records_another_origin", "records_duplicate", "expired_at_expires_at",
        ):
            case.check(label in labels, f"{label} present")
        mismatched = {c["label"] for c in data["invalid"] if c["code"] == "recovery_mismatch"}
        case.equal(len(mismatched), 5, "each recovery field mismatched")
    reasons = set()
    for c in data["plan_predicate"]:
        with report.case(file, f"plan predicate {c['label']}") as case:
            try:
                why = sr_plan_predicate(c, lst(c))
                got = {"in_plan": why is None} if why is None else {"in_plan": False, "reason": why}
                case.equal(got, {k: c[k] for k in ("in_plan", "reason", "code") if k in c}, "the answer")
                if why is not None:
                    reasons.add(why)
            except Refused as e:
                case.equal(e.code, c.get("code"), "refused")
    with report.case(file, "plan predicate coverage") as case:
        case.equal(sorted(reasons), sorted(SR_OUT_OF_PLAN), "every reason")
        labels = {c["label"] for c in data["plan_predicate"]}
        for label in (
            "service_revoke", "service_interrupt", "host_interrupt", "host_interrupt_at_another_origin",
            "another_origin", "another_member", "another_account", "another_genesis", "cover", "hold", "release",
            "hold_at_another_origin", "frozen_list", "demoted_manager", "origin_not_exact", "member_a_service",
        ):
            case.check(label in labels, f"{label} present")
    for c in data["builder"] + data["request"]:
        with report.case(file, f"builder {c['label']}") as case:
            try:
                body = sr_build(c, lst(c))
                case.equal(body, c.get("body_but_process"), "the body but its process")
            except Refused as e:
                case.equal(e.code, c.get("code"), "refused")
    for c in data["request"]:
        with report.case(file, f"request {c['label']}") as case:
            case.equal(c["sign_request"], {"purpose": "signer_report", "fresh_confirmation": True, "label": SR_LABEL}, "sign request")
            held = dict(c["body_but_process"], process=b64u_encode(b"vectors-process!"))
            signer_alg = keys.keys[c["key"].split("/")[0]]["auth"]["alg"]
            signer_pub = keys.public(c["key"].split("/")[0], "auth")
            for f in c["finishes"]:
                over = held if f["over"] == "held" else dict(held, slot=f["over"]["slot"])
                sig = vr_sign(keys, f["signed_with"], enc([SR_LABEL, jcs(over)]))
                ok = verify(signer_alg, signer_pub, sig, enc([SR_LABEL, jcs(held)]))
                case.equal(ok, "code" not in f, f"{f['label']}: {'taken' if ok else 'refused'}")
                if not ok:
                    case.equal(f["code"], "bad_signature", f"{f['label']}: bad_signature")


# ----------------------------------------------- r9-vectors-station-binding

# A native manager's Station binding proof (delegated host-work III.5 (b);
# Atem's answer on #120 comment 7207827118, owner decision 2026-11-27: an
# unbind needs the same proof): the body is the Station's challenge, exactly.
SB_FIELDS = sorted([
    "type", "v", "action", "origin", "issuer", "subject", "auth_time", "account_id", "genesis_hash", "head",
    "signer", "expected_binding", "nonce", "issued_at", "expires_at",
])
SB_RECORD_FIELDS = ["binding_id", "owner", "state", "version"]
SB_LABEL = "atem-station-binding-v1"
SB_VERIFY_ORDER = [
    "malformed", "frozen", "wrong_account", "unknown_signer", "not_a_manager", "bad_signature", "stale_log", "fork",
    "challenge_mismatch", "expired",
]
SB_BUILD_ORDER = [
    "malformed", "frozen", "wrong_account", "origin_mismatch", "signer_mismatch", "unknown_signer", "not_a_manager",
    "stale_log", "fork", "binding_mismatch", "expired",
]
SB_LABELS = {
    "signed_under_verifier_report_label": VR_LABEL,
    "signed_under_signer_report_label": "atem-signer-report-v1",
    "signed_under_route_label": "atem-host-route-v1",
    "signed_under_proxy_route_label": "atem-host-route-proxy-v1",
    "signed_under_sig_c_label": "atem-ch1-client-sig-v1",
    "signed_under_control_label": "atem-host-work-control-v1",
    "signed_under_entry_label": "atem-membership-entry-v1",
}


def sb_claim_ok(v):
    """An issuer, a subject or an owner: 1 to 256 bytes of printable ASCII."""
    return isinstance(v, str) and 1 <= len(v.encode()) <= 256 and all(0x21 <= ord(c) <= 0x7E for c in v)


def sb_expected_ok(o):
    """{state: never_bound} exactly, or a record in its state with its id,
    version and owner (owner in every recorded state: Atem's proposal,
    agreed with Astation)."""
    if not isinstance(o, dict):
        return False
    if o.get("state") == "never_bound":
        return sorted(o) == ["state"]
    return (
        sorted(o) == SB_RECORD_FIELDS and o["state"] in ("bound", "unbound", "released")
        and isinstance(o["binding_id"], str) and re.fullmatch(OPAQUE_ID, o["binding_id"]) is not None
        and vr_int(o["version"], 1) and sb_claim_ok(o["owner"])
    )


def sb_body(value):
    """A challenge, which is also a proof's body, as the file's note writes
    it: exactly the fifteen fields, each field's grammar, the per-action
    rules, its jcs within 4,096 bytes; raises Refused("malformed")."""
    if not isinstance(value, dict) or sorted(value) != SB_FIELDS or not sr_flat(value):
        raise Refused("malformed")
    if value["type"] != "atem-station-binding" or type(value["v"]) is not int or value["v"] != 1:
        raise Refused("malformed")
    head, signer, expected = value["head"], value["signer"], value["expected_binding"]
    ok = (
        value["action"] in ("bind", "transfer", "unbind")
        and relay_origin_ok(value["origin"])
        and sb_claim_ok(value["issuer"]) and sb_claim_ok(value["subject"])
        and vr_int(value["auth_time"])
        and isinstance(value["account_id"], str) and re.fullmatch(OPAQUE_ID, value["account_id"]) is not None
        and isinstance(value["genesis_hash"], str) and re.fullmatch(HEX64, value["genesis_hash"]) is not None
        and isinstance(head, dict) and sorted(head) == ["hash", "seq"] and vr_int(head["seq"], 1)
        and isinstance(head["hash"], str) and re.fullmatch(HEX64, head["hash"]) is not None
        and isinstance(signer, str) and signer.startswith("member:") and re.fullmatch(OPAQUE_ID, signer[7:]) is not None
        and sb_expected_ok(expected)
        and vr_b64u(value["nonce"], 32)
        and vr_int(value["issued_at"]) and vr_int(value["expires_at"])
    )
    if not ok or not 0 < value["expires_at"] - value["issued_at"] <= VR_MAX_LEASE_MS:
        raise Refused("malformed")
    if value["auth_time"] * 1000 > value["issued_at"]:
        raise Refused("malformed")
    state, subject = expected["state"], value["subject"]
    per_action = {
        "bind": state in ("never_bound", "unbound", "released"),
        "transfer": state == "bound" and subject != expected.get("owner"),
        "unbind": state == "bound" and subject == expected.get("owner"),
    }[value["action"]]
    if not per_action or len(jcs(value).encode()) > MAX_BODY_BYTES:
        raise Refused("malformed")
    return value


def read_sb_challenge(text):
    """StationBindingChallenge::parse: one strict parse of at most 4,096
    bytes, then the body's grammar."""
    return sb_body(vr_strict(text, VR_MAX_CHALLENGE_BYTES))


def read_sb_proof(text):
    """A proof as the shared core reads it: strict I-JSON within 16 KiB,
    exactly body and sig, the body a challenge. Returns (body, sig)."""
    value = vr_strict(text, VR_MAX_OBJECT_BYTES)
    if not isinstance(value, dict) or sorted(value) != ["body", "sig"]:
        raise Refused("malformed")
    try:
        sig = b64u_decode(value["sig"])
    except ValueError:
        raise Refused("malformed")
    return sb_body(value["body"]), sig


class SbList(VrList):
    """VrList, with a binding's signer: a current native member holding
    manage at this list's head (its roles as set_roles last left them)."""

    def manager_at_head(self, signer):
        """(alg, public key), or Refused (unknown_signer, not_a_manager)."""
        member = self.members.get(signer[len("member:"):])
        if member is None or member["standing"] != "active" or member["kind"] != "native":
            raise Refused("unknown_signer")
        if "manage" not in member["roles"]:
            raise Refused("not_a_manager")
        return member["auth_key"]["alg"], b64u_decode(member["auth_key"]["pub"])

    def on_chain(self, head):
        """at_head, or Refused (stale_log beyond the list, fork off it)."""
        if head["seq"] > len(self.hashes):
            raise Refused("stale_log")
        if self.hashes[head["seq"] - 1] != head["hash"]:
            raise Refused("fork")
        return head == self.head()


def sb_verify(text, lst, expected, now):
    """verify_station_binding, from the file's note: the first failure in
    the order of Atem's answer (#120 comment 7207827118, Atem's proposal,
    agreed with Astation, Atem #210 comment 7209922243), or the verified
    binding."""
    body, sig = read_sb_proof(text)
    if lst.frozen:
        raise Refused("frozen")
    if body["account_id"] != lst.account_id or body["genesis_hash"] != lst.genesis_hash:
        raise Refused("wrong_account")
    alg, public = lst.manager_at_head(body["signer"])
    if not verify(alg, public, sig, enc([SB_LABEL, jcs(body)])):
        raise Refused("bad_signature")
    at_head = lst.on_chain(body["head"])
    if jcs(body) != jcs(expected):
        raise Refused("challenge_mismatch")
    if now >= expected["expires_at"]:
        raise Refused("expired")
    return {
        "action": body["action"], "signer": body["signer"], "head": body["head"], "at_head": at_head,
        "account_id": body["account_id"], "genesis_hash": body["genesis_hash"], "issuer": body["issuer"],
        "subject": body["subject"], "auth_time": body["auth_time"], "expected_binding": body["expected_binding"],
        "nonce": body["nonce"], "expires_at": body["expires_at"],
    }


def sb_build(case, lst):
    """station_binding_request, from the file's note: the held body's jcs,
    or Refused. The challenge is read first, as the bindings' request reads
    the text it is handed."""
    signer, now, claims = case["signer"], case["now_ms"], case["expected"]
    challenge = read_sb_challenge(json.dumps(case["challenge"]))
    if not signer.startswith("member:") or re.fullmatch(OPAQUE_ID, signer[7:]) is None:
        raise Refused("malformed")
    station = vr_normalize(case["station"])
    if station is None:
        raise Refused("malformed")
    if sorted(claims) != ["auth_time", "issuer", "subject"] or not sb_claim_ok(claims["issuer"]) or not sb_claim_ok(claims["subject"]) or not vr_int(claims["auth_time"]):
        raise Refused("malformed")
    if lst.frozen:
        raise Refused("frozen")
    if challenge["account_id"] != lst.account_id or challenge["genesis_hash"] != lst.genesis_hash:
        raise Refused("wrong_account")
    if challenge["origin"] != station:
        raise Refused("origin_mismatch")
    if challenge["signer"] != signer:
        raise Refused("signer_mismatch")
    lst.manager_at_head(signer)
    lst.on_chain(challenge["head"])
    if any(challenge[k] != claims[k] for k in ("issuer", "subject", "auth_time")):
        raise Refused("binding_mismatch")
    if now >= challenge["expires_at"]:
        raise Refused("expired")
    return jcs(challenge)


def check_station_binding(file, data, report, context):
    """Every case's verdict derived here from the file's note: Astation's
    examples (each challenge read, its signing input's digest, both
    signatures under the posted keys, over that input only); the chain's
    entries; each challenge text read or refused; each proof's code in the
    order of Atem's answer (#120 comment 7207827118, Atem's proposal, agreed
    with Astation, Atem #210 comment 7209922243), or its verified fields,
    against log L and the case's
    chain, the valid proofs' jcs, signing input and signature by their
    signer's key; the builder's held bodies and refusals; and the immutable
    request's finishes, signed here (P-256 with a fresh nonce)."""
    keys = context["keys"]
    mlog = context["membership_log"]
    entries = {e["label"]: e for e in data["entries"]}
    with report.case(file, "external") as case:
        ext = data["external"]
        posted = {k["alg"]: b64u_decode(k["pub"]) for k in ext["public_keys"]}
        case.equal(sorted(posted), ["ed25519", "p256"], "an Ed25519 and a P-256 key")
        inputs = []
        for c in ext["cases"]:
            try:
                body = read_sb_challenge(json.dumps(c["challenge"]))
                case.check(True, f"{body['action']}: its challenge reads")
            except Refused as e:
                case.fail(f"a posted challenge refused: {e.code}")
                continue
            inputs.append(enc([SB_LABEL, jcs(body)]))
            case.equal(sha256(inputs[-1]).hex(), c["signing_input_sha256"], f"{body['action']}: the signing input's digest")
        case.equal(sorted(c["challenge"]["action"] for c in ext["cases"]), ["bind", "transfer", "unbind"], "one example of each action")
        for i, c in enumerate(ext["cases"]):
            for alg in ("ed25519", "p256"):
                sig = b64u_decode(c[f"{alg}_sig"])
                for j, message in enumerate(inputs):
                    case.equal(verify(alg, posted[alg], sig, message), i == j, f"case {i}'s {alg} signature over case {j}'s input")
                case.check(not verify(alg, posted[alg], sig, enc([VR_LABEL, jcs(c["challenge"])])), f"case {i}'s {alg} signature isn't a verifier report's")
    with report.case(file, "entries") as case:
        check_report_entries(case, data, mlog)
        desk = entries["SB7_add_desk"]["entry"]["body"]["member"]
        case.equal((desk["auth_key"]["alg"], b64u_decode(desk["auth_key"]["pub"])), ("ed25519", keys.public("dev-desk", "auth")), "dev-desk's Ed25519 key")
        case.check("manage" in desk["roles"], "dev-desk added with manage")
        case.equal(entries["SB7_set_roles_phone"]["entry"]["body"]["roles"], ["control", "view"], "dev-phone demoted")
        case.equal(jcs(entries["SB7_recovery_add_newmac"]["entry"]), jcs(next(v["entry"] for v in mlog["others"] if v["label"] == "R7")), "SB7_recovery_add_newmac is R7, byte for byte")

    def lst(c):
        return report_list(c, data, mlog, SbList)

    for c in data["challenges"]:
        with report.case(file, f"challenge {c['label']}") as case:
            try:
                case.equal(read_sb_challenge(c["text"]), c.get("fields"), "read, its fields")
            except Refused as e:
                case.equal(e.code, c.get("code"), "refused")
    codes, actions = set(), set()
    for c in data["valid"] + data["invalid"]:
        with report.case(file, f"proof {c['label']}") as case:
            expected = read_sb_challenge(json.dumps(c["challenge"]))
            try:
                verified = sb_verify(c["proof"], lst(c), expected, c["now_ms"])
                case.equal(verified, c.get("expect"), "verified")
                actions.add(verified["action"])
                body = json.loads(c["proof"])["body"]
                case.equal(jcs(body), c["jcs"], "jcs")
                case.equal(enc([SB_LABEL, jcs(body)]).hex(), c["signing_input_hex"], "signing input")
                name, part = c["signed_with"].split("/")
                case.check(
                    verify(keys.keys[name][part]["alg"], keys.public(name, part), b64u_decode(json.loads(c["proof"])["sig"]), enc([SB_LABEL, jcs(body)])),
                    f"signed by {c['signed_with']}",
                )
            except Refused as e:
                case.equal(e.code, c.get("code"), "refused")
                codes.add(e.code)
                proof = json.loads(c["proof"]) if e.code != "malformed" else None
                if c["label"] == "high_s_signature":
                    # A genuine malleation: S above n / 2, its low-S twin the
                    # signer's valid signature.
                    sig = b64u_decode(proof["sig"])
                    s_ = int.from_bytes(sig[32:], "big")
                    case.check(s_ > P256_N // 2, "S is high")
                    twin = sig[:32] + (P256_N - s_).to_bytes(32, "big")
                    case.check(verify("p256", keys.public("dev-phone", "auth"), twin, enc([SB_LABEL, jcs(proof["body"])])), "its low-S twin verifies")
                if c["label"] in SB_LABELS:
                    # A genuine relabel: the signature verifies over the other label.
                    other = SB_LABELS[c["label"]]
                    case.check(
                        verify("p256", keys.public("dev-phone", "auth"), b64u_decode(proof["sig"]), enc([other, jcs(proof["body"])])),
                        f"signed over {other}",
                    )
    with report.case(file, "coverage") as case:
        case.equal(sorted(codes), sorted(SB_VERIFY_ORDER), "every verifier code")
        case.equal(sorted(actions), ["bind", "transfer", "unbind"], "every action verifies")
        labels = {c["label"] for c in data["valid"] + data["invalid"]}
        for label in (
            "bind_p256_at_head", "bind_p256_at_ancestor", "bind_ed25519_at_head", "bind_ed25519_at_ancestor",
            "rebind_after_unbound", "rebind_after_released", "transfer_p256", "transfer_ed25519", "unbind_p256",
            "unbind_ed25519", "demoted_manager", "pending_recovery_subject", "high_s_signature",
            "unbound_without_owner", "released_without_owner", "transfer_to_the_current_owner", "unbind_by_another_account",
            "auth_time_after_issued_at", "lease_zero", "lease_over_30_seconds", "account_id_space",
        ) + tuple(SB_LABELS):
            case.check(label in labels, f"{label} present")
        mismatched = {c["label"] for c in data["invalid"] if c["code"] == "challenge_mismatch"}
        case.equal(len(mismatched), 16, "each challenge field against the stored challenge")
    build_codes = set()
    for c in data["builder"] + data["request"]:
        with report.case(file, f"builder {c['label']}") as case:
            try:
                case.equal(sb_build(c, lst(c)), c.get("body_json"), "the held body")
            except Refused as e:
                case.equal(e.code, c.get("code"), "refused")
                build_codes.add(e.code)
    with report.case(file, "builder coverage") as case:
        case.equal(sorted(build_codes), sorted(SB_BUILD_ORDER), "every builder code")
    for c in data["request"]:
        with report.case(file, f"request {c['label']}") as case:
            case.equal(c["sign_request"], {"purpose": "station_binding", "fresh_confirmation": True, "label": SB_LABEL}, "sign request")
            held = c["challenge"]
            name = c["key"].split("/")[0]
            signer_alg, signer_pub = keys.keys[name]["auth"]["alg"], keys.public(name, "auth")
            for f in c["finishes"]:
                over = held if f["over"] == "held" else dict(held, nonce=f["over"]["nonce"])
                sig = vr_sign(keys, f["signed_with"], enc([SB_LABEL, jcs(over)]))
                ok = verify(signer_alg, signer_pub, sig, enc([SB_LABEL, jcs(held)]))
                case.equal(ok, "code" not in f, f"{f['label']}: {'taken' if ok else 'refused'}")
                if not ok:
                    case.equal(f["code"], "bad_signature", f"{f['label']}: bad_signature")


# ------------------------------------------- host-work/requests-v1 (task ops)

# The requests naming a task (host-work-v1 §4 "Query, cancel, complete",
# §11.2): their exact fields beyond v, id, host, op and task_id.
TASK_OPS = {
    "work_query": [],
    "reply_query": [],
    "work_cancel": [],
    "work_complete": ["result"],
    "work_interrupt": [],
    "work_resolve": ["resolution"],
}
# The owner's ops (§11.2): they name a host sender's selector task (its
# UUID v5, §11.5) as well as a UUID v4; the others a UUID v4 only.
# `reply_query` among them: Astation's ask, #120 comment 7082465179.
OWNER_TASK_OPS = {"work_query", "reply_query", "work_interrupt", "work_resolve"}
WORK_STATES = {
    "queued", "blocked", "submitting", "submitted", "awaiting_result",
    "completed", "failed", "cancelled", "expired", "outcome_unknown",
}
OPAQUE_ID = r"[A-Za-z0-9._:-]{1,128}"
MAX_REQUEST_BYTES = 256 * 1024


def task_snapshot_ok(s):
    """A context snapshot a channel's work_complete or work_resolve{done}
    carries (§4): memory or vault (a `result` kind is local only), exactly
    its fields, an opaque id, a version from 1, a text of at most 128 KiB
    without NUL whose SHA-256 is the digest."""
    return (
        isinstance(s, dict)
        and sorted(s) == ["digest", "id", "kind", "text", "version"]
        and s["kind"] in ("memory", "vault")
        and isinstance(s["id"], str) and re.fullmatch(OPAQUE_ID, s["id"]) is not None
        and safe_int(s["version"], 1)
        and isinstance(s["text"], str) and len(s["text"].encode()) <= 128 * 1024 and "\0" not in s["text"]
        and s["digest"] == sha256(s["text"].encode()).hex()
    )


def failed_detail_ok(d):
    """`failed.detail` (§11.2): 1-1024 bytes, something besides White_Space,
    no control character and no Cf character."""
    import unicodedata

    return (
        isinstance(d, str)
        and 1 <= len(d.encode()) <= 1024
        and any(c not in WHITE_SPACE for c in d)
        and not any(unicodedata.category(c) in ("Cc", "Cf") for c in d)
    )


def host_target_ok(h):
    return (
        isinstance(h, dict)
        and sorted(h) == ["account_id", "atem_device_id", "host_trust_gen"]
        and all(isinstance(h[k], str) and re.fullmatch(OPAQUE_ID, h[k]) for k in ("account_id", "atem_device_id"))
        and safe_int(h["host_trust_gen"])
    )


def task_request_ok(text):
    """A whole request naming a task, as host-work-v1 §1, §4 and §11.2 write
    it: strict JSON, `{"type":"session","data":{...}}`, the op's exact
    fields, v 1, a UUID v4 id, the host, the task id (a lowercase UUID v4,
    or for the owner's ops a UUID v5 too), and the op's own field."""
    try:
        message = json.loads(text, object_pairs_hook=_no_duplicates, parse_float=_no_float, parse_constant=_no_constant)
    except (ValueError, NotStrict):
        return False
    if not isinstance(message, dict) or sorted(message) != ["data", "type"] or message["type"] != "session":
        return False
    d = message["data"]
    if not isinstance(d, dict) or d.get("op") not in TASK_OPS:
        return False
    op = d["op"]
    if sorted(d) != sorted(["v", "id", "host", "op", "task_id"] + TASK_OPS[op]):
        return False
    if len(json.dumps(d, separators=(",", ":"), ensure_ascii=False).encode()) > MAX_REQUEST_BYTES:
        return False
    task = d["task_id"]
    task_ok = is_uuid(task, 4) or op in OWNER_TASK_OPS and is_uuid(task, 5)
    if not (d["v"] == 1 and type(d["v"]) is int and is_uuid(d["id"], 4) and host_target_ok(d["host"]) and task_ok):
        return False
    if op == "work_complete":
        return task_snapshot_ok(d["result"])
    if op == "work_resolve":
        r = d["resolution"]
        if not isinstance(r, dict):
            return False
        if r.get("kind") == "failed":
            return sorted(r) == ["detail", "kind"] and failed_detail_ok(r["detail"])
        if r.get("kind") == "done":
            return sorted(r) == ["kind", "result"] and task_snapshot_ok(r["result"])
        return False
    return True


def resolver_ok(resolved):
    """`resolved{by, at}` (§11.2): `local`, or `member:`/`service:` and an
    opaque id; the host's wall clock, a safe integer."""
    return (
        isinstance(resolved, dict)
        and sorted(resolved) == ["at", "by"]
        and isinstance(resolved["by"], str)
        and (resolved["by"] == "local" or re.fullmatch(r"(member|service):" + OPAQUE_ID, resolved["by"]) is not None)
        and safe_int(resolved["at"])
    )


def work_status_ok(w):
    """A `work` status (§4 "Status", §11.2): its task a UUID v4 or a host
    sender's selector task (its UUID v5: a status answers only the request
    that named its task), the attempt's UUID v4 `receipt_id`, a state, a
    detail of at most 1024 bytes, a result exactly when completed (a
    snapshot), and `resolved` only on a settled status, never null."""
    if not isinstance(w, dict):
        return False
    keys = set(w)
    if not {"task_id", "receipt_id", "state", "detail"} <= keys <= {"task_id", "receipt_id", "state", "detail", "result", "resolved"}:
        return False
    result = w.get("result")
    return (
        (is_uuid(w["task_id"], 4) or is_uuid(w["task_id"], 5))
        and is_uuid(w["receipt_id"], 4)
        and w["state"] in WORK_STATES
        and isinstance(w["detail"], str) and len(w["detail"].encode()) <= 1024
        and (result is None or task_snapshot_ok(result))
        and (w["state"] == "completed") == (result is not None)
        and ("resolved" not in w or resolver_ok(w["resolved"]) and w["state"] in ("completed", "failed"))
    )


def work_result_ok(r):
    """A `host_work_result` of kind `work` (§7), as its data."""
    return (
        isinstance(r, dict)
        and sorted(r) == ["attachment_gen", "channel_id", "host", "id", "op", "re", "result", "v"]
        and r["v"] == 1 and type(r["v"]) is int and r["op"] == "host_work_result"
        and all(is_uuid(r[k], 4) for k in ("id", "re", "attachment_gen"))
        and host_target_ok(r["host"])
        and isinstance(r["channel_id"], str) and r["channel_id"] != ""
        and isinstance(r["result"], dict) and sorted(r["result"]) == ["kind", "work"] and r["result"]["kind"] == "work"
        and work_status_ok(r["result"]["work"])
    )


def channel_reply_ok(r):
    """A reply as `reply_query` returns it (§4 "Reply"), in any state (the
    host envelope's `reply_ok` takes a submitted one only): exactly its fields
    (`submitted_at` null, or omitted, before it is submitted), a lowercase
    UUID v5 `result_id`, a state, a SHA-256 hex digest, a text of at most
    16 KiB with no control character but newline and tab, 0-8 context
    snapshots (§4's) only once submitted, `submitted_at` exactly when
    submitted (a safe integer), and once `dropped` no text and no
    context."""
    if not isinstance(r, dict):
        return False
    keys = {"result_id", "state", "digest", "text", "context", "dropped"}
    if set(r) not in (keys, keys | {"submitted_at"}):
        return False
    import unicodedata

    text, context, at = r["text"], r["context"], r.get("submitted_at")
    return (
        is_uuid(r["result_id"], 5)
        and r["state"] in ("publishing", "submitted", "refused")
        and isinstance(r["digest"], str) and re.fullmatch(HEX64, r["digest"]) is not None
        and isinstance(text, str) and len(text.encode()) <= 16 * 1024
        and not any(unicodedata.category(c) == "Cc" and c not in "\n\t" for c in text)
        and isinstance(context, list) and len(context) <= 8
        and all(task_snapshot_ok(c) for c in context)
        and (r["state"] == "submitted" or context == [])
        and (r["state"] == "submitted") == (at is not None)
        and (at is None or safe_int(at))
        and type(r["dropped"]) is bool
        and (not r["dropped"] or text == "" and context == [])
    )


def reply_result_ok(r):
    """A `host_work_result` of kind `reply` (§7), as its data: no reply yet
    (`null`) or a reply."""
    return (
        isinstance(r, dict)
        and sorted(r) == ["attachment_gen", "channel_id", "host", "id", "op", "re", "result", "v"]
        and r["v"] == 1 and type(r["v"]) is int and r["op"] == "host_work_result"
        and all(is_uuid(r[k], 4) for k in ("id", "re", "attachment_gen"))
        and host_target_ok(r["host"])
        and isinstance(r["channel_id"], str) and r["channel_id"] != ""
        and isinstance(r["result"], dict) and sorted(r["result"]) == ["kind", "reply"] and r["result"]["kind"] == "reply"
        and (r["result"]["reply"] is None or channel_reply_ok(r["result"]["reply"]))
    )


def task_answer(request, result):
    """Whether a result (its data) answers a request naming a task: its `re`
    and host, then a reply naming the task's `result_id` (or none yet), or
    the task's own status (with `work_complete`'s result, or settled the way
    `work_resolve` asked)."""
    d = request["data"]
    if result["re"] != d["id"] or result["host"] != d["host"]:
        return False
    body, op = result["result"], d["op"]
    if body["kind"] == "reply":
        return op == "reply_query" and (body["reply"] is None or body["reply"]["result_id"] == result_id_of(d["task_id"]))
    if body["kind"] != "work" or op == "reply_query" or body["work"]["task_id"] != d["task_id"]:
        return False
    w = body["work"]
    if op == "work_complete":
        return w.get("result") == d["result"]
    if op == "work_resolve":
        r = d["resolution"]
        settled = w["state"] == "failed" if r["kind"] == "failed" else w["state"] == "completed" and w.get("result") == r["result"]
        return "resolved" in w and settled
    return True


def check_host_work_task_requests(file, data, report):
    """host-work/requests-v1's requests that name a task (§4, §11.2): each
    case's verdict recomputed from the rules as written there (the owner's
    `work_query`, `reply_query`, `work_interrupt` and `work_resolve` take a
    host sender's selector task, its UUID v5, as well as a UUID v4,
    Astation's asks on #120 comments 7028723996 and 7082465179; the other
    ops a UUID v4 only); its `work` results' (a selector task's status among
    them) and `reply` results' (a selector task's reply in each state among
    them); and the `answers` cases' correlation, each result read first.
    The file's other cases are the Rust runner's and the binding suites'."""

    def op_of(c):
        m = c.get("message")
        return m["data"].get("op") if isinstance(m, dict) and isinstance(m.get("data"), dict) else None

    with report.case(file, "task requests") as case:
        cases = [c for c in data["cases"] if op_of(c) in TASK_OPS]
        for op in OWNER_TASK_OPS:
            case.check(
                any(op_of(c) == op and c["valid"] and is_uuid(c["message"]["data"]["task_id"], 5) for c in cases),
                f"{op}: a selector task's id read",
            )
            case.check(
                any(op_of(c) == op and not c["valid"] and isinstance(c["message"]["data"].get("task_id"), str) and c["message"]["data"]["task_id"].lower() != c["message"]["data"]["task_id"] for c in cases),
                f"{op}: an uppercase id refused",
            )
        for op in set(TASK_OPS) - OWNER_TASK_OPS:
            case.check(
                any(op_of(c) == op and not c["valid"] and is_uuid(c["message"]["data"]["task_id"], 5) for c in cases),
                f"{op}: a UUID v5 refused",
            )
        for c in cases:
            text = c["raw"] if "raw" in c else json.dumps(c["message"], ensure_ascii=False)
            case.equal(task_request_ok(text), c["valid"], f"{c['name']}: {'read' if c['valid'] else 'refused'} by §4 and §11.2's rules")
    with report.case(file, "work results") as case:
        works = [c for c in data["results"] if isinstance(c["result"].get("result"), dict) and c["result"]["result"].get("kind") == "work"]
        case.check(any(c["valid"] and is_uuid(c["result"]["result"]["work"]["task_id"], 5) for c in works), "a selector task's status read")
        for c in works:
            case.equal(work_result_ok(c["result"]), c["valid"], f"{c['name']}: {'read' if c['valid'] else 'refused'}")
    with report.case(file, "reply results") as case:
        replies = [c for c in data["results"] if isinstance(c["result"].get("result"), dict) and c["result"]["result"].get("kind") == "reply"]
        selector_result = result_id_of("80160896-4fcd-5e6e-adac-98bac5497321")
        for state in ("publishing", "submitted", "refused"):
            case.check(
                any(c["valid"] and c["result"]["result"]["reply"]["state"] == state and c["result"]["result"]["reply"]["result_id"] == selector_result for c in replies),
                f"a selector task's {state} reply read",
            )
        case.check(any(c["valid"] and c["result"]["result"]["reply"]["dropped"] is True for c in replies), "a dropped reply read")
        for c in replies:
            case.equal(reply_result_ok(c["result"]), c["valid"], f"{c['name']}: {'read' if c['valid'] else 'refused'}")
    with report.case(file, "answers") as case:
        for c in data["answers"]:
            text = json.dumps(c["request"], ensure_ascii=False)
            case.check(task_request_ok(text), f"{c['name']}: its request reads")
            case.check(work_result_ok(c["result"]) or reply_result_ok(c["result"]), f"{c['name']}: its result reads")
            case.equal(task_answer(c["request"], c["result"]), c["answers"], f"{c['name']}: answers")
        case.check(
            any(c["answers"] and c["request"]["data"]["op"] == "reply_query" and is_uuid(c["request"]["data"]["task_id"], 5) and c["result"]["result"]["kind"] == "reply" and c["result"]["result"]["reply"] is not None for c in data["answers"]),
            "a selector task's reply answers its reply_query",
        )


# ---------------------------------------------------------------------- main

# In order: a checker may use what an earlier one recorded in `context`.
CHECKERS = [
    ("r9-vectors-keys", check_keys),
    ("r9-vectors-membership-log", check_membership_log),
    ("r9-vectors-host-route", check_host_route),
    ("r9-vectors-host-work-control", check_host_work_control),
    ("r9-vectors-push-hint", check_push_hint),
    ("r9-vectors-delegated-wire", check_delegated_wire),
    ("r9-vectors-host-envelope", check_host_envelope),
    ("r9-vectors-station-calls", check_station_calls),
    ("r9-vectors-mailbox-calls", check_mailbox_calls),
    ("r9-vectors-verifier-report", check_verifier_report),
    ("r9-vectors-signer-report", check_signer_report),
    ("r9-vectors-station-binding", check_station_binding),
]


def main(argv):
    if len(argv) != 2:
        print(f"usage: {argv[0]} <designs/protocol/fixtures>", file=sys.stderr)
        return 2
    fixtures = Path(argv[1])
    report = Report()
    context = {}
    # The kit tags need the log's genesis: read it first.
    log = load_strict(fixtures / "r9-vectors-membership-log.json")
    context["genesis_hash"] = unhex(log["genesis_hash"])
    for name, checker in CHECKERS:
        path = fixtures / f"{name}.json"
        with report.case(name, "file") as case:
            data = load_strict(path)
            case.equal((data.get("name"), data.get("kind"), data.get("requires")), (name, "vectors", "r9"), "name, kind, requires")
        checker(name, data, report, context)
    for path in sorted(fixtures.glob("r9-control-ack-*.json")):
        name = path.stem
        with report.case(name, "file") as case:
            data = load_strict(path)
            case.equal(
                (data.get("name"), data.get("kind"), data.get("requires"), data.get("side")),
                (name, "scenario", "r9", "relay"),
                "name, kind, requires, side",
            )
        check_control_ack(name, data, report, context)
    requests = "host-work/requests-v1"
    check_host_work_task_requests(requests, load_strict(fixtures / f"{requests}.json"), report)
    print(f"{report.cases} cases, {report.failures} failed")
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
