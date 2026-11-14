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
derives from the bytes, the device list and the receiver (II.4.2's checks 1
to 6 and II.4.4's, written here from host-work-v1 §11.5). The other files'
`expect` and each `reason` are checked by the Rust runner
(`crates/atem-client/tests/vectors.rs`) and the binding suites.
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
    1-128 bytes of [A-Za-z0-9._:-])."""
    return (
        re.fullmatch(UUID_V4, facts["task_id"]) is not None
        and re.fullmatch(r"(member|service|host):[A-Za-z0-9._:-]{1,128}", facts["sender"]) is not None
    )


# Unicode's White_Space property (PropList.txt), written out: an alert's
# reason must carry something else (host-work-v1 §11.3).
WHITE_SPACE = set(
    "\t\n\x0b\x0c\r \x85\xa0\u1680" + "".join(chr(c) for c in range(0x2000, 0x200B))
    + "\u2028\u2029\u202f\u205f\u3000"
)


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
    host_enc_key answer, and receipts with and without provenance; and the r9
    welcome's optional verifier (R9.2, R9.8; Atem's proposal). Each case's
    verdict is recomputed here from the rules as R9.14, R9.8 and R9.2 write
    them, the valid answer's enc_sig is verified with host-a's host_key of log
    L over the enc() input built here, and the release's own verifier is
    R9.2's sixteen actions at version 2."""
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
        return (
            uuid4(data_["task_id"])
            and isinstance(sender, str)
            and re.fullmatch(r"(member|service|host):" + ID, sender) is not None
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
        case.check(len(reasons) >= 30, f"{len(reasons)} reasons")


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
            {"two_calls_at_the_same_cursor", "a_late_reply_to_a_retired_call", "discovery_answered_on_the_current_feed", "another_feed"} <= matched,
            "two calls at one cursor, a retired call's late reply, discovery, a result on another feed",
            f"got {sorted(matched)}",
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


# ---------------------------------------------------------------------- main

# In order: a checker may use what an earlier one recorded in `context`.
CHECKERS = [
    ("r9-vectors-keys", check_keys),
    ("r9-vectors-membership-log", check_membership_log),
    ("r9-vectors-host-work-control", check_host_work_control),
    ("r9-vectors-push-hint", check_push_hint),
    ("r9-vectors-delegated-wire", check_delegated_wire),
    ("r9-vectors-host-envelope", check_host_envelope),
    ("r9-vectors-station-calls", check_station_calls),
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
