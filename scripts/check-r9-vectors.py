#!/usr/bin/env python3
"""Independent check of the r9 vectors (session-v1 R9.12).

Recomputes and verifies, with Python's standard library and the
`cryptography` package only (no code of this repository), the cryptographic
values `crates/atem-client` computed for the r9 vector files: canonical
JSON (RFC 8785 for the subset the vectors use: objects, arrays, strings,
integers, booleans), `enc` (a 4-byte big-endian length before every field),
hashes, key derivations, and every Ed25519 and P-256 signature (P-256 as
64-byte r||s, low S required), a host's `enc_sig` included. It doesn't
derive a verifier's verdicts: `expect` and each `reason` are checked by the
Rust runner (`crates/atem-client/tests/vectors.rs`) and the binding suites.
It also recomputes every Station report id of the acknowledgment fixtures
(`r9-control-ack-*`, host-work-v1 §11.4): the known answers of the
reference ledger's `report_id`.

Usage: python3 -I scripts/check-r9-vectors.py designs/protocol/fixtures

Prints one line per case and exits non-zero on any mismatch. Each vectors
file has its own checker in CHECKERS; a file without one isn't checked here
yet (`crates/atem-client/tests/vectors.rs` runs every file).
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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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
    record_id: the SHA-256 of a body of that principal with that id).
    Verdicts and per-effect results are the Rust runner's and the binding
    suites' (R9.12)."""
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
            if "parse_error" in vector:
                case.check(True, f"refused at parse ({vector['parse_error']}; not derived here)")

    for sequence in data["sequences"]:
        with report.case(file, sequence["label"]) as case:
            for step in sequence["steps"]:
                case.check(step["record"] in by_label, f"{step['record']} is a record of the file")
                if "pos" in step:
                    pos = step["pos"]
                    case.equal(sorted(pos), ["feed_id", "feed_seq", "origin"], "a position {origin, feed_id, feed_seq}")
                    case.check((pos["origin"], pos["feed_id"]) in stations, "a position in a station's feed")
            state = sequence["state"]
            case.equal((state["account_id"], state["genesis_hash"]), (data["account_id"], data["genesis_hash"]), "the state's account")
            for principal, digests in state["records"].items():
                for record_id, digest in digests.items():
                    texts = jcs_by_record_id.get((principal, record_id), set())
                    case.check(
                        digest in {sha256(t.encode()).hex() for t in texts},
                        f"{principal} {record_id[-4:]}: the SHA-256 of a record body of that principal with that id",
                    )


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


def check_control_ack(file, data, report, context):
    """A Station acknowledgment fixture (test 48): its device list is log
    L's, its records and integrations are the control vectors', every ack
    claims its link's association at the Station's origin and names records
    of the vectors, and every report id it names is one of its reports',
    recomputed here: each expected report's id from its own kind,
    integration and host. Which reports are made, and when, is the ledger's
    (the Rust runner and the binding suites, R9.12)."""
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
        steps = data["steps"]
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


# ---------------------------------------------------------------------- main

# In order: a checker may use what an earlier one recorded in `context`.
CHECKERS = [
    ("r9-vectors-keys", check_keys),
    ("r9-vectors-membership-log", check_membership_log),
    ("r9-vectors-host-work-control", check_host_work_control),
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
    print(f"{report.cases} cases, {report.failures} failed")
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
