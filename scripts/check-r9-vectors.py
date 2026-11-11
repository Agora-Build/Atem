#!/usr/bin/env python3
"""Independent check of the r9 vectors (session-v1 R9.12).

Recomputes and verifies, with Python's standard library and the
`cryptography` package only (no code of this repository), the cryptographic
values `crates/atem-client` computed for the r9 vector files: canonical
JSON (RFC 8785 for the subset the vectors use: objects, arrays, strings,
integers, booleans), `enc` (a 4-byte big-endian length before every field),
hashes, key derivations, and every Ed25519 and P-256 signature (P-256 as
64-byte r||s, low S required), a host's `enc_sig` included, and the sealed
parts of the envelopes and results between hosts (RFC 9180 base mode,
written here: opened, and sealed again from the ephemeral to the same
bytes). It derives no verifier's verdict, but for `r9-vectors-host-envelope`,
whose every check's verdict and reason it derives from the bytes, the device
list and the receiver (II.4.2's checks 1 to 6 and II.4.4's, written here from
host-work-v1 §11.5). The other files' `expect` and each `reason` are checked
by the Rust runner (`crates/atem-client/tests/vectors.rs`) and the binding
suites.

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


# ------------------------------------------------- r9-vectors-host-envelope

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


def snapshot_ok(s):
    return (
        isinstance(s, dict)
        and sorted(s) == ["digest", "id", "kind", "text", "version"]
        and s["kind"] in ("memory", "vault")
        and safe_int(s["version"], 1)
        and isinstance(s["text"], str)
        and s["digest"] == sha256(s["text"].encode()).hex()
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


def receipts_ok(recipients):
    ids = [r.get("recipient_id") for r in recipients if isinstance(r, dict)]
    return (
        isinstance(recipients, list)
        and 1 <= len(recipients)
        and len(ids) == len(recipients) == len(set(ids))
        and all(is_uuid(i, 4) for i in ids)
        and all(
            sorted(r) == ["delivery", "recipient_id"]
            and isinstance(r["delivery"], dict)
            and r["delivery"].get("state") in ("stored", "refused", "work")
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
        elif k == "complete" and shape == ["kind", "result", "task_id"] and task_ok(value["task_id"]) and snapshot_ok(value["result"]):
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


def mail_verdict(wire, call, hosts, receiver_keys, receiver, now, outbox):
    """The receiver's verdict on a mailbox object (II.4.2 checks 1 to 6, and
    for a result II.4.4's), from the spec: (verdict, opened plaintext)."""
    body = wire.get("body")
    envelope = call == "open_envelope"

    def refused(reason):
        return {"verdict": "refused", "reason": reason, "evidence": mail_evidence(wire)}, None

    def authenticated(reason):
        return {"verdict": "refused_authenticated", "object_id": body["id"], "reason": reason}, None

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
    # The key part waits when the head is beyond this host's: its own new
    # host_enc_key may be in the entries it lacks.
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
        # holds has one key forever) the signature, then pending.
        reason = mail_times(body, now)
        if reason:
            return refused(reason)
        if key is not None and not verify("ed25519", key, sig, signing_input):
            return refused("bad_signature")
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
    size on the wire. Each check: the verdict and reason recomputed from the
    bytes, the device list (L + chain) and the receiver, written here from
    the spec, and the plaintext an open gives."""
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
            wire = objects[check["object"]]["object"]
            got, plain = mail_verdict(wire, check["call"], hosts, receiver_keys, receiver, check["now"], check.get("outbox"))
            case.equal(got, check["expect"], f"{check['call']} on L + {len(check['chain'])}: {got['verdict']} {got.get('reason', '')}")
            if plain is not None:
                case.equal(plain, plaintexts.get(check["object"]), "the plaintext the object sealed")
    with report.case(file, "coverage") as case:
        reasons = {c["expect"].get("reason") for c in data["checks"]} - {None}
        verdicts = {c["expect"]["verdict"] for c in data["checks"]}
        case.equal(verdicts, {"open", "pending", "refused", "refused_authenticated", "accepted", "not_delivered"}, "every verdict")
        case.check(len(reasons) >= 30, f"{len(reasons)} reasons")


# ---------------------------------------------------------------------- main

# In order: a checker may use what an earlier one recorded in `context`.
CHECKERS = [
    ("r9-vectors-keys", check_keys),
    ("r9-vectors-membership-log", check_membership_log),
    ("r9-vectors-host-envelope", check_host_envelope),
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
    print(f"{report.cases} cases, {report.failures} failed")
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
