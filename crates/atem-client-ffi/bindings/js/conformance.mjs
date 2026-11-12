// The shared r9 vectors (designs/protocol/fixtures/r9-vectors-*.json) and the
// host-work prompt-framing vectors (fixtures/host-work/prompt-framing-v1.json,
// framing-size-v1.json) run through the WASM binding under Node. Usage:
//   node conformance.mjs <wasm-bindgen nodejs pkg dir> <fixtures dir>
// The same checks run through Kotlin (bindings/kotlin/Conformance.kt) and
// Swift (bindings/swift/Tests/…/ConformanceTests.swift).
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { createHash, createHmac } from "node:crypto";
import { join, resolve } from "node:path";

const [pkgDir, fixturesDir] = process.argv.slice(2).map((p) => resolve(p));
const require = createRequire(import.meta.url);
const m = require(join(pkgDir, "atem_client_ffi.js"));

const load = (name) => JSON.parse(readFileSync(join(fixturesDir, `${name}.json`), "utf8"));
const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (h) => new Uint8Array(Buffer.from(h, "hex"));
const b64u = (s) => new Uint8Array(Buffer.from(s, "base64url"));
const utf8 = (s) => new Uint8Array(Buffer.from(s, "utf8"));
const str = (v) => JSON.stringify(v);
const head = (h) => ({ seq: h.seq, hash: h.hash });

let passed = 0;
const failures = [];
function check(name, f) {
  try {
    f();
    passed++;
  } catch (e) {
    failures.push(`${name}: ${e && e.stack ? e.stack.split("\n").slice(0, 3).join(" | ") : e}`);
  }
}
function eq(a, b, what = "") {
  const sa = typeof a === "string" ? a : str(a);
  const sb = typeof b === "string" ? b : str(b);
  if (sa !== sb) throw new Error(`${what} expected ${sb} got ${sa}`);
}
function throwsCode(f, code) {
  try {
    f();
  } catch (e) {
    if (e.code === code || e.detail === code) return e;
    throw new Error(`expected ${code}, got ${e.kind}/${e.code}/${e.detail}`);
  }
  throw new Error(`expected ${code}, nothing thrown`);
}

const enc = load("r9-vectors-encoding");
const keys = load("r9-vectors-keys").keys;
const mlog = load("r9-vectors-membership-log");
const rec = load("r9-vectors-recovery");
const hs = load("r9-vectors-channel-handshake");
const grant = load("r9-vectors-browser-grant");
const push = load("r9-vectors-push-hint");

const ACCOUNT = mlog.account_id;
const GENESIS = mlog.genesis_hash;
const byLabel = Object.fromEntries([...mlog.log, ...mlog.others].map((v) => [v.label, v]));
const entry = (label) => str(byLabel[label].entry);
const L = mlog.log.map((v) => str(v.entry));
const NOW = { wallMs: 1793264001000, monoMs: 1000, bootId: "boot-1" };
const logL = () => m.MembershipLog.verify(ACCOUNT, GENESIS, L, NOW);

// ---------------------------------------------------------------- encoding
check("enc fields", () => eq(hex(m.encodeFields(enc.enc[0].fields_utf8.map(utf8))), enc.enc[0].hex));
check("enc u64", () => eq(hex(m.encodeFields([unhex("0000000000000006")])), enc.enc[1].hex));
check("jcs", () => eq(m.canonicalJson(enc.jcs[0].input), enc.jcs[0].jcs));
check("jcs refuses duplicates and floats", () => {
  throwsCode(() => m.canonicalJson('{"a":1,"a":2}'), "not_strict_json");
  throwsCode(() => m.canonicalJson('{"a":1.5}'), "not_strict_json");
});
check("p256 low S only", () => {
  const p = enc.p256_low_s;
  const pub = unhex(keys[p.key].auth.pub_hex);
  m.verifyRawSignature("p256", pub, unhex(p.message_hex), unhex(p.sig_low_s_hex));
  throwsCode(() => m.verifyRawSignature("p256", pub, unhex(p.message_hex), unhex(p.sig_high_s_hex)), "high_s");
});
check("ed25519 strict", () => {
  const e = enc.ed25519_strict;
  const pub = unhex(keys[e.key].host_key.pub_hex);
  m.verifyRawSignature("ed25519", pub, unhex(e.message_hex), unhex(e.sig_hex));
  const bad = unhex(e.sig_hex);
  bad[63] ^= 1;
  throwsCode(() => m.verifyRawSignature("ed25519", pub, unhex(e.message_hex), bad), "bad_signature");
});

// -------------------------------------------------------------------- keys
check("test keys: label derivation and public halves", () => {
  for (const device of ["dev-mac", "dev-phone", "dev-ipad", "dev-newmac"]) {
    for (const part of ["auth", "enc"]) {
      const k = keys[device][part];
      eq(m.hashFields([utf8("atem-r9-test-key"), utf8(`${device} ${part}`)]), k.secret_hex, `${device} ${part} label`);
      const store = new m.SoftwareKeyStore();
      if (part === "auth") store.insertP256("k", unhex(k.secret_hex));
      else store.insertX25519("k", unhex(k.secret_hex));
      eq(hex(store.publicKey("k").raw), k.pub_hex, `${device} ${part} public`);
      m.checkPublicKey(part === "auth" ? "p256" : "x25519", unhex(k.pub_hex));
    }
  }
  const store = new m.SoftwareKeyStore();
  store.insertEd25519("h", unhex(keys["host-a"].host_key.secret_hex));
  eq(hex(store.publicKey("h").raw), keys["host-a"].host_key.pub_hex, "host-a");
  store.insertEd25519("s", unhex(keys["svc-discord"].auth.secret_hex));
  eq(hex(store.publicKey("s").raw), keys["svc-discord"].auth.pub_hex, "svc-discord");
});
check("enc_kid", () => eq(m.encKid(unhex(keys["dev-phone"].enc.pub_hex)), push.open_details[0].enc_kid));

// -------------------------------------------------------------- membership
check("log L verifies to its head", () => eq(logL().head(), { seq: mlog.head.seq, hash: mlog.head.hash }));
check("every entry: jcs, signing input, entry_hash", () => {
  for (const v of [...mlog.log, ...mlog.others]) {
    if (v.label === "K7_current_no_kit_sig") continue;
    // A set out of order: the signed-object parse itself refuses it.
    if (v.reason === "array_not_canonical") {
      throwsCode(() => m.signedObjectInfo(str(v.entry)), "array_not_canonical");
      continue;
    }
    const info = m.signedObjectInfo(str(v.entry));
    if (v.jcs !== undefined) eq(info.bodyJcs, v.jcs, `${v.label} jcs`);
    if (v.signing_input_hex !== undefined) eq(hex(info.signingInput), v.signing_input_hex, `${v.label} input`);
    eq(info.entryHash, v.entry_hash, `${v.label} hash`);
  }
});
check("kit current without kit_sig is refused", () =>
  throwsCode(() => m.signedObjectInfo(entry("K7_current_no_kit_sig")), "kit_sig_missing"));
check("members and hosts of L", () => {
  const log = logL();
  const phone = log.member("dev-phone");
  eq(phone.kind, "native");
  eq(phone.status, "active");
  eq(hex(phone.authKey.raw), keys["dev-phone"].auth.pub_hex);
  eq(hex(phone.encKey.raw), keys["dev-phone"].enc.pub_hex);
  eq(log.member("dev-ipad").status, "removed");
  eq(log.member("svc-discord").kind, "service");
  eq(hex(log.host("host-a").hostKey.raw), keys["host-a"].host_key.pub_hex);
  eq(log.host("host-a").hostTrustGen, 1);
});
check("E7 extends L; its hedged retry is the same entry", () => {
  const log = logL();
  const r = log.extend([entry("E7")], NOW);
  eq(r.appended, 1);
  eq(r.stop, null);
  eq(r.head.hash, byLabel.E7.entry_hash);
  eq(m.signedObjectInfo(entry("E7_retry")).entryHash, byLabel.E7.entry_hash);
});
check("refusals in context", () => {
  const stop = (labels, base = L) => {
    const log = m.MembershipLog.verify(ACCOUNT, GENESIS, base, NOW);
    return log.evaluate(labels.map(entry), NOW).stop;
  };
  eq(stop(["E7", "X8_badsig"]), { type: "invalid", index: 1, code: "bad_signature" });
  eq(stop(["C6_mac"]).outcome, "freeze");
  eq(stop(["C6_ipad"]).outcome, "ignored:signer_removed");
  eq(stop(["X7_ipad"]).type, "invalid");
  eq(stop(["KB7", "KB8_stale"]), { type: "invalid", index: 1, code: "blob_version_not_increasing" });
  eq(stop(["R7_wrong_key"]), { type: "invalid", index: 0, code: "bad_signature" });
});
check("a recovery_add waits 24 h on the verifier's clock", () => {
  const log = logL();
  const r = log.extend([entry("R7")], NOW);
  eq(r.appended, 1);
  const pending = log.pendingRecovery(NOW);
  eq(pending.length, 1);
  eq(pending[0].entryHash, byLabel.R7.entry_hash);
  eq(pending[0].subject, "dev-newmac");
  eq(pending[0].effectiveAt, NOW.wallMs + 86400000);
  eq(log.member("dev-newmac").status, "pending");
});
check("the log's durable snapshot restores against the app's anchors", () => {
  const log = logL();
  log.extend([entry("R7")], NOW);
  const saved = log.storedJson();
  const later = { wallMs: NOW.wallMs + 3600000, monoMs: NOW.monoMs + 3600000, bootId: "boot-1" };
  const restored = m.MembershipLog.fromStored(ACCOUNT, GENESIS, saved, later);
  eq(restored.head(), log.head());
  eq(restored.pendingRecovery(later)[0].effectiveAt, NOW.wallMs + 86400000, "same boot: from first sight");
  const reboot = { wallMs: NOW.wallMs + 7200000, monoMs: 500, bootId: "boot-2" };
  eq(m.MembershipLog.fromStored(ACCOUNT, GENESIS, saved, reboot).pendingRecovery(reboot)[0].effectiveAt, reboot.wallMs + 86400000, "another boot: nothing waited was persisted");
  const e = throwsCode(() => m.MembershipLog.fromStored("acct-other", GENESIS, saved, NOW), "account_mismatch");
  eq(e.kind, "stored");
  throwsCode(() => m.MembershipLog.fromStored(ACCOUNT, byLabel.SUB1.entry_hash, saved, NOW), "genesis_mismatch");
  throwsCode(() => m.MembershipLog.fromStored(ACCOUNT, GENESIS, saved.slice(0, saved.length / 2), NOW), "malformed");
  throwsCode(() => m.MembershipLog.fromStored(ACCOUNT, GENESIS, saved.replace("{", '{"extra":1,'), NOW), "stored_invalid");
});
check("a wait-ended decision survives the snapshot", () => {
  const log = logL();
  log.extend([entry("R7")], NOW);
  const day = { wallMs: NOW.wallMs + 86400000, monoMs: NOW.monoMs + 86400000, bootId: "boot-1" };
  eq(log.advance(day).length > 0, true);
  const saved = log.storedJson();
  eq(saved.includes('"reason":"wait_ended"'), true);
  const restored = m.MembershipLog.fromStored(ACCOUNT, GENESIS, saved, day);
  eq(restored.member("dev-newmac").status, "active");
  eq(restored.extend([entry("N8")], day).appended, 1, "N8 relies on the decision");
  throwsCode(() => m.MembershipLog.fromStored(ACCOUNT, GENESIS, saved.replaceAll('"v":1', '"v":2'), day), "unsupported_version");
});
check("draft + publish reproduces E7 byte for byte (RFC 6979)", () => {
  const log = logL();
  const e7 = byLabel.E7.entry.body;
  const body = log.draftEntry("dev-phone", e7.signed_at, str({ action: "remove", device_id: e7.device_id }));
  eq(body, byLabel.E7.jcs);
  const store = new m.SoftwareKeyStore();
  store.insertP256("dev-phone/auth", unhex(keys["dev-phone"].auth.secret_hex));
  const p = new m.EntryPublisher();
  p.prepare(log, body);
  if (!p.preparedJson()) throw new Error("prepared state not persisted");
  const req = p.sign(store, "dev-phone/auth", undefined);
  eq(req.entryHash, byLabel.E7.entry_hash);
  eq(req.expected, head(mlog.head));
  eq(m.canonicalJson(req.entryJson), m.canonicalJson(entry("E7")));
  // A restart: the saved state resumes (one append per device, so the old
  // object goes first).
  const saved = p.preparedJson();
  p.free();
  const resumed = m.EntryPublisher.resume(saved);
  eq(resumed.outstanding().entryHash, byLabel.E7.entry_hash);
  eq(resumed.replyStored(log, NOW), { type: "committed", head: { seq: 7, hash: byLabel.E7.entry_hash } });
  eq(log.head().seq, 7);
  eq(resumed.preparedJson(), undefined);
});
check("a draft the verifier would refuse is refused before signing", () => {
  throwsCode(() => logL().draftEntry("dev-phone", 1, str({ action: "remove" })), "membership_invalid");
});

check("capacity and the service change guard (D23)", () => {
  const log = logL();
  eq(log.capacity(), { entries: 6, maxEntries: 1024, members: 3, maxMembers: 256, hosts: 1, maxHosts: 64, level: "ok", entriesLevel: "ok", membersLevel: "ok", hostsLevel: "ok" });
  const e5 = byLabel.E5.entry.body;
  const svc = e5.member;
  const at = e5.signed_at;
  const day = 86400000;
  const change = (ops, expiresAt) => str({ action: "set_roles", device_id: "svc-discord", roles: ["service"], scope: { ...svc.scope, ops }, expires_at: expiresAt });
  const renew = change(svc.scope.ops, svc.expires_at + day);
  eq(log.checkChange(renew, at + 3600000), { type: "service_change_too_soon", lastSignedAt: at, retryAt: at + day }, "a renewal within 24 h");
  eq(log.checkChange(renew, at + day), null, "after 24 h");
  eq(log.checkChange(change(["view"], svc.expires_at), at + 3600000), null, "narrowing");
  eq(log.checkChange(str({ action: "remove", device_id: "svc-discord" }), at + 3600000), null, "removal");
  const hostKey = byLabel.E2.entry.body.host.host_key;
  eq(log.checkChange(str({ action: "add_host", host: { host_id: "host-b", host_trust_gen: 1, host_key: hostKey } }), at), null, "a host with room");
  throwsCode(() => log.checkChange(str({ action: "remove" }), at), "membership_invalid");
});

check("service builders: add, set_roles, renewal, narrowing (§R9.6)", () => {
  const log = logL();
  const e5 = byLabel.E5.entry.body;
  const svc = e5.member;
  const at = e5.signed_at;
  const day = 86400000;
  const svcKey = unhex(keys["svc-discord"].auth.pub_hex);
  // E5's member, rebuilt from its parts in another order: the vector's bytes.
  const shuffled = { hosts: svc.scope.hosts, projects: [...svc.scope.projects].reverse(), ops: ["prompt", "interrupt"] };
  eq(m.serviceAddAction("svc-discord", "ed25519", svcKey, shuffled, svc.expires_at, at), m.canonicalJson(str({ action: "add", member: svc })));
  eq(log.serviceGrant("svc-discord"), { scope: { hosts: svc.scope.hosts, projects: svc.scope.projects, sessions: null, ops: svc.scope.ops }, expiresAt: svc.expires_at });
  eq(log.serviceGrant("dev-phone") ?? null, null);
  const newSvc = m.serviceAddAction("svc-new", "ed25519", svcKey, { hosts: ["host-a"], ops: ["prompt"], sessions: ["ses-bbbbbbbbbbbb", "ses-aaaaaaaaaaaa"] }, at + 3600000, at);
  eq(JSON.parse(newSvc).member.scope, { hosts: ["host-a"], ops: ["prompt", "view"], sessions: ["ses-aaaaaaaaaaaa", "ses-bbbbbbbbbbbb"] });
  log.draftEntry("dev-phone", at, newSvc);
  eq(log.checkChange(newSvc, at), null, "an add with room");
  const change = (ops, expiresAt) => m.canonicalJson(str({ action: "set_roles", device_id: "svc-discord", roles: ["service"], scope: { ...svc.scope, ops }, expires_at: expiresAt }));
  const renew = log.serviceRenewalAction("svc-discord", svc.expires_at + day, at + day);
  eq(renew, change(svc.scope.ops, svc.expires_at + day), "renewal");
  eq(log.checkChange(renew, at + 3600000), { type: "service_change_too_soon", lastSignedAt: at, retryAt: at + day }, "a renewal is paced");
  const narrow = log.serviceNarrowingAction("svc-discord", { ...svc.scope, ops: ["view"] }, null, at + 3600000);
  eq(narrow, change(["view"], svc.expires_at), "narrowing");
  eq(log.checkChange(narrow, at + 3600000), null, "a narrowing isn't paced");
  eq(m.serviceSetRolesAction("svc-discord", { ...svc.scope, ops: ["view"] }, svc.expires_at, at), narrow);
  throwsCode(() => log.serviceNarrowingAction("svc-discord", { ...svc.scope, ops: ["stop", "view"] }, null, at), "not_a_narrowing");
  throwsCode(() => log.serviceNarrowingAction("svc-discord", svc.scope, null, at), "not_a_narrowing");
  throwsCode(() => log.serviceRenewalAction("svc-discord", svc.expires_at, at), "not_a_renewal");
  throwsCode(() => log.serviceRenewalAction("dev-phone", svc.expires_at + day, at), "not_a_service");
  throwsCode(() => m.serviceSetRolesAction("svc-discord", { hosts: [], ops: ["view"] }, svc.expires_at, at), "bad_scope");
  throwsCode(() => m.serviceSetRolesAction("svc-discord", { hosts: ["host-a"], ops: ["fly"] }, svc.expires_at, at), "bad_scope");
  throwsCode(() => m.serviceSetRolesAction("svc-discord", { hosts: ["host-a"], ops: [] }, at + 90 * day + 1, at), "service_expiry");
  throwsCode(() => m.serviceAddAction("svc-x", "x25519", unhex(keys["dev-phone"].enc.pub_hex), { hosts: ["host-a"], ops: [] }, at, at), "wrong_alg");
});
// r9_svc vectors: atem-client's own file (crates/atem-client/vectors),
// next to the shared fixtures' repository.
const svcFp = JSON.parse(readFileSync(join(fixturesDir, "../../../crates/atem-client/vectors/r9-svc-fingerprint.json"), "utf8"));
check("service key fingerprint r9_svc (atem-client vectors)", () => {
  for (const c of svcFp.valid) {
    eq(hex(b64u(c.auth_key.pub)), c.pub_hex, c.case);
    eq(m.serviceKeyFingerprint(c.auth_key.alg, b64u(c.auth_key.pub)), c.fingerprint, c.case);
  }
  for (const c of svcFp.invalid) throwsCode(() => m.serviceKeyFingerprint(c.auth_key.alg, b64u(c.auth_key.pub)), c.code);
  const discord = svcFp.valid.find((c) => c.case.includes("svc-discord"));
  eq(logL().serviceKeyFingerprint("svc-discord"), discord.fingerprint);
  eq(logL().serviceKeyFingerprint("dev-phone") ?? null, null);
});
// The host's own vector (src/memory/account_keys.rs H1_VECTOR): h1. of
// "github.com/agora/atem" under K = [7; 32], kid 0123abcd.
const H1_VECTOR = "h1.0123abcd.777eda018c9c9736a84728e10308571167773f209924bf052477a1283cfd7cb6";
check("project keys and hashes (§R9.6)", () => {
  eq(m.projectKeyOfRemote("git@github.com:Agora-Build/Atem.git"), "github.com/agora-build/atem");
  eq(m.projectKeyOfRemote("https://user:tok@github.com/Agora-Build/Atem.git/"), "github.com/agora-build/atem");
  eq(m.projectKeyOfRemote("file:///srv/repo.git") ?? null, null);
  eq(m.localProjectKey("Scratch"), "local:Scratch");
  eq(hex(m.projectHashInput("github.com/agora/atem")), hex(utf8("github.com/agora/atem")));
  eq(m.projectHash({ kid: "0123abcd", k: new Uint8Array(32).fill(7) }, "github.com/agora/atem"), H1_VECTOR);
  const mac = createHmac("sha256", Buffer.alloc(32, 7)).update(m.projectHashInput("github.com/agora/atem")).digest();
  eq(m.projectHashFromMac("0123abcd", new Uint8Array(mac)), H1_VECTOR);
  throwsCode(() => m.projectHashFromMac("01.23", new Uint8Array(mac)), "malformed");
  throwsCode(() => m.projectHashFromMac("0123abcd", new Uint8Array(31)), "malformed");
  eq(m.isProjectHash(byLabel.E5.entry.body.member.scope.projects[0]), true);
  eq(m.isProjectHash("h1.0123abcd.zz"), false);
});

// ----------------------------------- delegated host work: device-list actions
// The vectors of `others` that follow a `chain` on log L (P*, EK*, HS*): a
// valid one carries `expect`, the state a verifier derives after it (read
// here through the log's queries); a refused one `valid: false` and `reason`
// (`evaluate` stops with it at index 0; a body the signed-object parse
// refuses, `array_not_canonical`, never reaches the log: `evaluate` throws).
// `project_set`, `project_remove`, `host_sender_revoke`,
// `host_sender_readmit` and `host_enc_key` are also rebuilt by their
// builders, byte for byte, where a builder can write the body.
const FIVE = ["project_set", "project_remove", "host_sender_revoke", "host_sender_readmit", "host_enc_key"];
const delegated = mlog.others.filter((v) => v.chain !== undefined);
const sorted = (v) =>
  Array.isArray(v) ? v.map(sorted) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sorted(v[k])])) : v;
const same = (a, b, what) => eq(str(sorted(a)), str(sorted(b)), what);
const logAfter = (chain) => {
  const log = logL();
  eq(log.extend(chain.map(entry), NOW).stop, null, `chain ${chain}`);
  return log;
};
const hostKeyName = (hostId, gen) => (gen === 1 ? hostId : `${hostId}-gen-${gen}`);
const encKeyOf = (k) => ({ alg: k.alg, raw: b64u(k.pub) });
const stateOf = (log) => {
  const state = { hosts: {}, projects: {}, host_senders: {}, host_enc_keys: {} };
  const keyOut = (k) => ({ enc_kid: k.encKid, pub: Buffer.from(k.key.raw).toString("base64url"), seq: k.seq, host_trust_gen: k.hostTrustGen });
  for (const id of ["host-a", "host-b"]) {
    const host = log.host(id);
    if (host) state.hosts[id] = host.hostTrustGen;
    const sender = log.hostSenderState(id);
    const epoch = log.hostMembershipEpoch(id) ?? null;
    if (sender) {
      state.host_senders[id] = { state: sender.type, seq: sender.type === "authorized" ? sender.generation : sender.seq };
      if (epoch !== null) state.host_senders[id].membership_epoch = epoch;
    } else eq(epoch, null, `${id} epoch without an add_host`);
    const keysOf = log.hostEncKey(id);
    if (keysOf) {
      state.host_enc_keys[id] = { current: keyOut(keysOf.current) };
      if (keysOf.previous) state.host_enc_keys[id].previous = { ...keyOut(keysOf.previous.key), retired: keysOf.previous.retired, replaced_at_seq: keysOf.previous.replacedAtSeq };
    }
  }
  for (const p of log.projects()) state.projects[p.name] = { hosts: p.hosts, members: p.members, ops: p.ops };
  return state;
};
const opsBetween = (expect, a, b) => {
  if (a === b) return [];
  const ops = new Set();
  for (const p of Object.values(expect.projects)) if (p.members.includes(a) && p.members.includes(b)) for (const op of p.ops) ops.add(op);
  return [...ops].sort();
};
check("device-list actions: the queries read every vector's expect, refusals carry their reason", () => {
  let valid = 0;
  let refused = 0;
  for (const v of delegated) {
    const log = logAfter(v.chain);
    if (v.valid === false) {
      refused++;
      if (v.reason === "array_not_canonical") throwsCode(() => log.evaluate([entry(v.label)], NOW), v.reason);
      else eq(log.evaluate([entry(v.label)], NOW).stop, { type: "invalid", index: 0, code: v.reason }, v.label);
      continue;
    }
    valid++;
    const r = log.extend([entry(v.label)], NOW);
    eq(r.stop, null, v.label);
    eq(r.appended, 1, v.label);
    eq(r.head.hash, v.entry_hash, v.label);
    same(stateOf(log), v.expect, v.label);
    for (const [a, b] of [["host-a", "host-b"], ["host-b", "host-a"], ["host-a", "host-a"]]) eq(log.projectOpsBetween(a, b), opsBetween(v.expect, a, b), `${v.label} ${a} ${b}`);
    for (const id of ["host-a", "host-b"]) eq(log.hostProjects(id), Object.entries(v.expect.projects).filter(([, p]) => p.members.includes(id)).map(([name]) => name).sort(), `${v.label} ${id}`);
  }
  if (valid < 34 || refused < 35) throw new Error(`${valid} valid, ${refused} refused`);
});
const buildAction = (body) => {
  const at = body.signed_at;
  switch (body.action) {
    case "project_set": return m.projectSetAction(body.project.name, body.project.hosts, body.project.ops, at);
    case "project_remove": return m.projectRemoveAction(body.name, at);
    case "host_sender_revoke": return m.hostSenderRevokeAction(body.host_id, body.interrupt_running, at);
    case "host_sender_readmit": return m.hostSenderReadmitAction(body.host_id, at);
    case "host_enc_key": return m.hostEncKeyAction(body.host_id, body.host_trust_gen, body.enc_key.alg, b64u(body.enc_key.pub), body.enc_sig, body.retire_previous === true, at);
    default: throw new Error(body.action);
  }
};
// A body no builder writes: another signer's entry (a builder's action is
// drafted for the signer that asks), or a shape outside the builders' inputs
// (`retire_previous: false`, a revoke without `interrupt_running`, a field
// the action doesn't have, a set out of order).
const unbuildable = (v) =>
  v.entry.body.signer !== "dev-mac" ||
  v.entry.body.retire_previous === false ||
  (v.entry.body.action === "host_sender_revoke" && typeof v.entry.body.interrupt_running !== "boolean") ||
  v.reason === "unknown_field" ||
  v.reason === "array_not_canonical";
const ADVICE = ["already_revoked", "not_revoked", "enc_key_reused"];
check("device-list actions: the builders reproduce the vectors; check_change advises on a redundant revoke or readmit and a reused key", () => {
  let built = 0;
  for (const v of delegated.filter((x) => FIVE.includes(x.entry.body.action))) {
    const body = v.entry.body;
    if (unbuildable(v)) continue;
    // A shape the verifier refuses by itself is the builder's refusal too.
    if (["bad_project", "malformed", "wrong_alg"].includes(v.reason)) {
      throwsCode(() => buildAction(body), v.reason);
      continue;
    }
    const log = logAfter(v.chain);
    const action = buildAction(body);
    built++;
    eq(log.draftEntry("dev-mac", body.signed_at, action), v.jcs, v.label);
    const advice = log.checkChange(action, body.signed_at);
    eq(advice, ADVICE.includes(v.reason) ? { type: v.reason } : null, `${v.label} check_change`);
  }
  if (built < 38) throw new Error(`${built} built`);
});
check("device-list actions: shapes the verifier refuses by itself", () => {
  const two = ["host-a", "host-b"];
  throwsCode(() => m.projectSetAction("astation", two, ["deploy"], 1), "bad_project");
  throwsCode(() => m.projectSetAction("astation", two, [], 1), "bad_project");
  throwsCode(() => m.projectSetAction("astation", ["host-a"], ["message"], 1), "bad_project");
  throwsCode(() => m.projectSetAction("Astation", two, ["message"], 1), "bad_project");
  throwsCode(() => m.projectSetAction("astation", two, ["notify", "prompt"], 1), "bad_project");
  throwsCode(() => m.projectRemoveAction("Bad Name", 1), "bad_project");
  throwsCode(() => m.hostSenderRevokeAction("Not an id", false, 1), "malformed");
  throwsCode(() => m.hostSenderReadmitAction("", 1), "malformed");
  const ek = byLabel.EK7_set.entry.body;
  throwsCode(() => m.hostEncKeyAction("host-a", 1, "ed25519", unhex(keys["host-a"].host_key.pub_hex), ek.enc_sig, false, 1), "wrong_alg");
  throwsCode(() => m.hostEncKeyAction("host-a", 1, "x25519", b64u(ek.enc_key.pub), "AAAA", false, 1), "malformed");
  throwsCode(() => m.hostEncKeyAction("host-a", 1, "x25519", b64u(ek.enc_key.pub), `${ek.enc_sig}=`, false, 1), "malformed");
});
check("device-list actions: verifyHostEncSig binds every field of a host's enc_sig", () => {
  const ek = byLabel.EK7_set.entry.body;
  const hostA = ["ed25519", unhex(keys["host-a"].host_key.pub_hex)];
  const verify = (host, account, genesis, hostId, gen, key, sig) => m.verifyHostEncSig(...host, account, genesis, hostId, gen, key.alg, key.raw, sig);
  const key = encKeyOf(ek.enc_key);
  eq(verify(hostA, ACCOUNT, GENESIS, "host-a", 1, key, ek.enc_sig), true);
  eq(verify(["ed25519", unhex(keys["host-b"].host_key.pub_hex)], ACCOUNT, GENESIS, "host-a", 1, key, ek.enc_sig), false, "another host's key");
  eq(verify(hostA, "acct-other", GENESIS, "host-a", 1, key, ek.enc_sig), false, "account");
  eq(verify(hostA, ACCOUNT, "00".repeat(32), "host-a", 1, key, ek.enc_sig), false, "genesis");
  eq(verify(hostA, ACCOUNT, GENESIS, "host-b", 1, key, ek.enc_sig), false, "host id");
  eq(verify(hostA, ACCOUNT, GENESIS, "host-a", 2, key, ek.enc_sig), false, "generation");
  eq(verify(hostA, ACCOUNT, GENESIS, "host-a", 1, encKeyOf(byLabel.EK8_rotate.entry.body.enc_key), ek.enc_sig), false, "key");
  eq(verify(["p256", unhex(keys["dev-mac"].auth.pub_hex)], ACCOUNT, GENESIS, "host-a", 1, key, ek.enc_sig), false, "a P-256 host key");
  eq(verify(hostA, ACCOUNT, GENESIS, "host-a", 1, { alg: "ed25519", raw: key.raw }, ek.enc_sig), false, "an Ed25519 enc_key");
  eq(verify(hostA, ACCOUNT, "not hex", "host-a", 1, key, ek.enc_sig), false, "a malformed genesis");
  eq(verify(hostA, ACCOUNT, GENESIS, "host-a", 1, key, "AAAA"), false, "a short signature");
  // Inputs no key, generation or algorithm can be: false, never a throw.
  eq(verify(["rsa", hostA[1]], ACCOUNT, GENESIS, "host-a", 1, key, ek.enc_sig), false, "an unknown host alg");
  eq(verify(hostA, ACCOUNT, GENESIS, "host-a", 1, { alg: "rsa", raw: key.raw }, ek.enc_sig), false, "an unknown enc alg");
  for (const gen of [-1, 1.5, 2 ** 53]) eq(verify(hostA, ACCOUNT, GENESIS, "host-a", gen, key, ek.enc_sig), false, `generation ${gen}`);
  // Every enc_sig of the vectors whose binding fields parse (they carry
  // enc_sig_input_hex) verifies under the host key of its generation, but the bad one.
  for (const v of delegated.filter((x) => x.enc_sig_input_hex !== undefined)) {
    const b = v.entry.body;
    const host = ["ed25519", unhex(keys[hostKeyName(b.host_id, b.host_trust_gen)].host_key.pub_hex)];
    eq(verify(host, ACCOUNT, GENESIS, b.host_id, b.host_trust_gen, encKeyOf(b.enc_key), b.enc_sig), v.reason !== "bad_enc_sig", v.label);
  }
});

// ---------------------------------------------------------------- recovery
const kit1 = () => m.RecoveryKit.read(unhex(rec.R_hex), rec.kit.account_id, rec.kit.genesis_hash, unhex(rec.kit.kit_tag_hex));
check("kit 1: tag, recovery key, X25519 key", () => {
  const kit = kit1();
  eq(hex(kit.kitTag()), rec.kit.kit_tag_hex);
  eq(hex(kit.recoveryKey().raw), hex(b64u(rec.recovery_key.pub)));
  eq(hex(kit.x25519Public()), rec.recovery_key_x25519_pub_hex);
  eq(hex(m.ed25519PublicToX25519(b64u(rec.recovery_key.pub))), rec.recovery_key_x25519_pub_hex);
  eq(m.hashFields([utf8("atem-r9-test-key"), utf8("recovery kit R")]), rec.R_hex);
});
check("a mistyped kit is refused", () => {
  const tag = unhex(rec.kit.kit_tag_hex);
  tag[0] ^= 1;
  throwsCode(() => m.RecoveryKit.read(unhex(rec.R_hex), rec.kit.account_id, rec.kit.genesis_hash, tag), "kit_tag_mismatch");
});
check("K backups: hash, open with kit 1, refused by kit 2", () => {
  const kb = rec.k_backup;
  eq(m.parseKBackup(str(kb.wire)).backupHash, kb.backup_hash);
  const keysOut = m.openKBackup(str(kb.wire), kit1());
  const plain = JSON.parse(kb.plain_jcs).keys;
  eq(keysOut.map((k) => k.kid), plain.map((k) => k.kid));
  eq(keysOut.map((k) => hex(k.k)), plain.map((k) => hex(b64u(k.k))));
  const kit2 = m.RecoveryKit.read(unhex(rec.kit_2.R_hex), rec.kit_2.kit.account_id, rec.kit_2.kit.genesis_hash, unhex(rec.kit_2.kit.kit_tag_hex));
  throwsCode(() => m.openKBackup(str(kb.wire), kit2), "backup_invalid");
  m.openKBackup(str(rec.kit_2.k_backup_resealed.wire), kit2);
  eq(m.parseKBackup(str(rec.k_backup_bad_ct.wire)).backupHash, rec.k_backup_bad_ct.backup_hash);
  throwsCode(() => m.openKBackup(str(rec.k_backup_bad_ct.wire), kit1()), "backup_invalid");
});
check("recovery entry hash", () => eq(m.signedObjectInfo(str(rec.recovery_entry.entry)).entryHash, rec.recovery_entry_hash));
check("restore: a substitute chain is refused by the kit's anchor", () => {
  const s = m.RestoreSession.read(unhex(rec.R_hex), rec.kit.account_id, rec.kit.genesis_hash, unhex(rec.kit.kit_tag_hex));
  throwsCode(() => s.attempt(rec.substitute_chain.entries.map(entry), str(rec.substitute_chain.backup.wire), [], NOW), "genesis_mismatch");
  eq(s.kStored(), false);
});
check("restore: no host reachable withholds; a host head confirms", () => {
  const s = m.RestoreSession.read(unhex(rec.R_hex), rec.kit.account_id, rec.kit.genesis_hash, unhex(rec.kit.kit_tag_hex));
  const entries = [...L, entry("KB7")];
  throwsCode(() => s.attempt(entries, str(rec.k_backup.wire), [], NOW), "no_host_reachable");
  eq(s.waitingForHosts(), ["host-a"]);
  // The handshake vector's host head is (6, E6): behind KB7's log, so the
  // log reaches it and the restore goes on to the backup KB7 names.
  const r = s.attempt(entries, str(rec.k_backup.wire), [{ initJson: str(hs.init), acceptJson: str(hs.accept) }], NOW);
  eq(r.head.seq, 7);
  eq(r.keys.map((k) => k.kid), ["b982533d", "1f2e3d4c"]);
  eq(s.kStored(), true);
  eq(s.mayRotateK("dev-newmac"), false);
});

// ----------------------------------------------------------------- channel
check("accept: th2 and sig_h", () => {
  eq(m.hostAcceptTh2(str(hs.init), str(hs.accept)), hs.th2_hex);
  eq(hex(m.signingInput("channel_host", unhex(hs.th2_hex))), hs.sig_h_input_hex);
  m.verifySignature("ed25519", unhex(hs.inputs.host_key_pub_hex), "channel_host", unhex(hs.th2_hex), unhex(hs.sig_h_hex));
  eq(m.verifyHostAccept(str(hs.init), str(hs.accept), logL()), head(hs.inputs.head));
});
check("a rewritten head fails sig_h", () => {
  const neg = hs.negative.find((n) => n.case === "tampered_head");
  const accept = { ...hs.accept, head: neg.head };
  eq(m.hostAcceptTh2(str(hs.init), str(accept)), neg.th2_hex);
  throwsCode(() => m.verifyHostAccept(str(hs.init), str(accept), logL()), "handshake_failed");
});
check("sig_c over th3", () => {
  eq(hex(m.signingInput("channel_client", unhex(hs.th3_hex))), hs.sig_c_input_hex);
  m.verifySignature("p256", unhex(hs.inputs.client_auth_pub_hex), "channel_client", unhex(hs.th3_hex), unhex(hs.sig_c_hex));
  const bad = unhex(hs.th3_hex);
  bad[0] ^= 1;
  throwsCode(() => m.verifySignature("p256", unhex(hs.inputs.client_auth_pub_hex), "channel_client", bad, unhex(hs.sig_c_hex)), "bad_signature");
});

// ----------------------------------------------------------- browser grant
check("browser grant: hash, issuer signature, sig_c", () => {
  const info = m.parseBrowserGrant(str(grant.grant));
  eq(info.grantHash, grant.grant_hash_hex);
  eq(info.issuer, "dev-phone");
  eq(info.ops, ["view"]);
  eq(info.sessionId, "ses-aaaaaaaaaaaa");
  eq(hex(m.signedObjectInfo(str(grant.grant)).signingInput), grant.signing_input_hex);
  m.verifySignedObject(str(grant.grant), "p256", unhex(keys["dev-phone"].auth.pub_hex));
  throwsCode(() => m.verifySignedObject(str(grant.grant), "p256", unhex(keys["dev-mac"].auth.pub_hex)), "bad_signature");
  m.verifySignature("p256", unhex(keys.browser.pub_hex), "channel_client", unhex(grant.th3_hex), unhex(grant.sig_c_hex));
});

// -------------------------------------------------------------------- push
const NOWP = push.verifier_now;
check("open hints verify and open for their device only", () => {
  push.open.forEach((h, i) => {
    const d = push.open_details[i];
    const hint = m.verifyPushHint(str(h), logL(), NOWP, "client");
    eq(hint.state(), { type: "open", deviceId: d.device_id, encKid: d.enc_kid, sealedHash: d.sealed_hash });
    eq(hex(m.signedObjectInfo(str(h)).signingInput), d.signing_input_hex);
    const store = new m.SoftwareKeyStore();
    store.insertX25519("enc", unhex(push.recipient_secrets[d.device_id]));
    const plain = JSON.parse(d.plain_jcs);
    eq(hint.open(store, "enc", d.device_id), { tool: plain.tool, summary: plain.summary });
    const other = d.device_id === "dev-phone" ? "dev-mac" : "dev-phone";
    throwsCode(() => hint.open(store, "enc", other), "malformed");
  });
});
check("resolved and seen", () => {
  const r = m.verifyPushHint(str(push.resolved), logL(), NOWP, "client");
  eq(r.state(), { type: "resolved", reason: "answered_remote", resolvedAt: push.resolved.body.resolved_at });
  const seen = m.verifySeen(str(push.seen), logL());
  eq(seen.deviceId, "dev-phone");
  eq(seen.seenAt, push.seen.body.seen_at);
  eq(hex(m.signedObjectInfo(str(push.seen)).signingInput), push.seen_signing_input_hex);
  eq(m.seenInWindow(str(push.seen), logL(), push.open[0].body.created_at), true);
});
check("invalid hints are refused for their reason", () => {
  for (const verifier of ["client", "relay"]) {
    throwsCode(() => m.verifyPushHint(str(push.invalid[0].hint), logL(), NOWP, verifier), "skew");
    throwsCode(() => m.verifyPushHint(str(push.invalid[1].hint), logL(), NOWP, verifier), "invalid_times");
    throwsCode(() => m.verifyPushHint(str(push.invalid[2].hint), logL(), NOWP, verifier), "invalid_times");
  }
  const book = new m.PushHintBook();
  eq(book.offer(m.verifyPushHint(str(push.open[0]), logL(), NOWP, "client")), "accepted");
  eq(book.offer(m.verifyPushHint(str(push.open[0]), logL(), NOWP, "client")), "idempotent");
  throwsCode(() => book.offer(m.verifyPushHint(str(push.invalid[3].hint), logL(), NOWP, "client")), "duplicate");
});
check("a resolved dominates its opens in either order", () => {
  const book = new m.PushHintBook();
  eq(book.offer(m.verifyPushHint(str(push.resolved), logL(), NOWP, "client")), "accepted");
  eq(book.offer(m.verifyPushHint(str(push.open[0]), logL(), NOWP, "client")), "ignored_after_resolved");
  eq(book.isResolved(m.verifyPushHint(str(push.open[1]), logL(), NOWP, "client").approval()), true);
});
check("tampered created_at fails the signature", () => {
  const h = JSON.parse(str(push.open[0]));
  h.body.created_at += 1;
  throwsCode(() => m.verifyPushHint(str(h), logL(), NOWP, "client"), "bad_signature");
});
check("acks round trip", () => {
  const hint = m.verifyPushHint(str(push.open[0]), logL(), NOWP, "client");
  const message = m.pushAckMessage([hint.ackJson()]);
  eq(m.parsePushAck(message), [hint.ackJson()]);
});
check("schedule from the signed created_at, and the 15 s guard", () => {
  for (const [vec, sent] of [[push.open_g75, false], [push.open_g75001, true]]) {
    const hint = m.verifyPushHint(str(vec), logL(), vec.body.created_at, "client");
    const mobile = { deviceClass: "mobile", connected: false, immediateMobile: false };
    const stages = m.pushStages(hint.createdAt(), mobile);
    eq(stages, [{ stage: "mobile", due: hint.createdAt() + 60000, providerPush: true }]);
    eq(m.pushSendNow("mobile", stages[0].due, stages[0].due, hint.expiresAt(), false, false), sent);
    eq(m.pushGuard(hint.expiresAt()), hint.expiresAt() - 15000);
  }
  const created = push.open[0].body.created_at;
  const desktop = { deviceClass: "desktop", connected: false, immediateMobile: false };
  eq(m.pushStages(created, desktop), [{ stage: "desktop_os", due: created, providerPush: true }]);
  eq(m.pushSendNow("mobile", created + 60000, created + 60000, push.open[0].body.expires_at, false, true), false);
  eq(m.pushNextDue(created, push.open[0].body.expires_at, desktop, ["desktop_os"], created), undefined);
});

const pairing = load("r9-vectors-pairing");
check("verifyCommit host_trust_gen (r9-vectors-pairing)", () => {
  for (const c of pairing.verify_commit.valid) eq(m.verifyCommitHostTrustGen(c.raw), c.host_trust_gen, c.case);
  for (const c of pairing.verify_commit.invalid) {
    let refused = false;
    try {
      m.verifyCommitHostTrustGen(c.raw);
    } catch (e) {
      refused = e.kind !== undefined || e.code !== undefined;
    }
    if (!refused) throw new Error(`${c.case} was accepted`);
  }
});

// ----------------------------------------------------------------- framing
// The prompt framing (delegated host-work design III.2) over
// designs/protocol/fixtures/host-work/: the escaping and the marker check,
// the Unicode version they are pinned to, the preflight size check and (a
// test-vectors build only) the rendering, byte for byte.
const loadWork = (name) => JSON.parse(readFileSync(join(fixturesDir, "host-work", `${name}.json`), "utf8"));
const framing = loadWork("prompt-framing-v1");
const framingSize = loadWork("framing-size-v1");
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
// A tag's 60 bits as written (XXXX-XXXX-XXXX, Crockford base32): a BigInt,
// which is what the binding takes (60 bits don't fit a JS number).
const tagBitsOf = (tag) =>
  [...tag.replaceAll("-", "")].reduce((bits, c) => {
    const i = CROCKFORD.indexOf(c);
    if (i < 0) throw new Error(`not a tag character: ${c}`);
    return (bits << 5n) | BigInt(i);
  }, 0n);
const sha256Hex = (text) => createHash("sha256").update(text, "utf8").digest("hex");
const snapshot = (kind, id, version, text) => ({ kind, id, version, digest: sha256Hex(text), text });
// framingCheckedLen of a text, an optional mark (a host-work MarkTask object)
// and snapshots (host-work ContextSnapshot objects): the complete inputs.
const checkedLen = (text, mark, context) => m.framingCheckedLen(text, mark === undefined ? undefined : str(mark), str(context));
const LINE_BREAK = /[\n\r\v\f\u0085\u2028\u2029]/;
check("framing: Unicode version, escape cases, marker check (III.2)", () => {
  eq(m.framingUnicodeVersion(), framing.unicode_version, "Unicode version");
  eq(framing.unicode_version, "18.0.0");
  eq(framing.escape.length, 57);
  for (const c of framing.escape) {
    const r = m.framingEscape(c.text);
    eq(r.escaped, c.escaped, c.name);
    eq(r.barsAdded, c.bars_added, c.name);
    // The marker check on each line (after the bars it already starts with)
    // agrees with where the escaping put its bars.
    const folding = c.text.split(LINE_BREAK).filter((line) => m.framingFoldsToMarker(line.replace(/^\|+/, ""))).length;
    eq(folding, c.bars_added, `${c.name}: lines that fold`);
  }
  for (const line of ["[atem]", "  [ATEM x", "[\u0410\u0422\u0415\u041c]", "[a\ufe0ftem]"]) eq(m.framingFoldsToMarker(line), true, line);
  for (const line of ["", "x[atem]", "[ atem]", "|[atem]", "[atom]"]) eq(m.framingFoldsToMarker(line), false, line);
});
check("framing: rendered prompts byte for byte, tags from their bits (vectors only)", () => {
  const bits = tagBitsOf(framing.tag);
  eq(framing.prompts.length, 9);
  for (const p of framing.prompts) {
    const rendered = m.framingRenderForVectors(str(p.input), bits);
    eq(rendered, p.rendered, p.name);
    eq(Buffer.byteLength(rendered, "utf8"), p.bytes, `${p.name}: bytes`);
  }
  // Every tag of the vectors renders the prompt with that tag, on Atem's own
  // lines only (the sender's text is not touched, even where it holds the
  // vectors' tag).
  const first = framing.prompts[0];
  const old = `[atem ${framing.tag}] `;
  for (const t of framing.tags) {
    const fresh = `[atem ${t.tag}] `;
    const expected = first.rendered
      .split("\n")
      .map((line) => (line.startsWith(old) ? fresh + line.slice(old.length) : line))
      .join("\n");
    eq(m.framingRenderForVectors(str(first.input), BigInt(`0x${t.bits}`)), expected, t.bits);
  }
  // What the core refuses, and what is no input, is refused: a snapshot whose
  // text doesn't match its digest is never rendered.
  const input = JSON.parse(str(framing.prompts[2].input));
  m.framingRenderForVectors(str(input), 1n);
  const tampered = JSON.parse(str(input));
  tampered.context[0].text = "not what the digest says";
  throwsCode(() => m.framingRenderForVectors(str(tampered), 1n), "malformed");
  const headless = JSON.parse(str(input));
  delete headless.header;
  throwsCode(() => m.framingRenderForVectors(str(headless), 1n), "malformed");
});
check("framing: the size section (typical, worst, worst with a mark, at the bound)", () => {
  const size = framing.size;
  const vault = (id, version, n) => snapshot("vault", id, version, "c".repeat(n));
  // A typical task: 5,120 bytes of context, a 1,024-byte prompt.
  eq(checkedLen("t".repeat(1024), undefined, [vault("api-contract", 3, 5120)]) - 1024 - 5120, size.typical.checked_atem_bytes, "typical");
  // The worst: eight 1,000-byte contexts with 128-byte ids and 16-digit
  // versions, a 1,000-byte prompt.
  const worst = Array.from({ length: 8 }, (_, i) => snapshot("memory", `${i}${"m".repeat(127)}`, 9007199254740991, "c".repeat(1000)));
  const text = "t".repeat(1000);
  eq(checkedLen(text, undefined, worst) - 1000 - 8 * 1000, size.worst.checked_atem_bytes, "worst");
  // The same with a mark (the vectors' own, with a 128-byte mark id).
  const mark = { ...framing.prompts.find((p) => p.input.mark !== undefined).input.mark, mark_id: "k".repeat(128) };
  eq(checkedLen(text, mark, worst), size.worst_mark.checked_bytes, "worst with a mark");
  // At the bound: one byte more is over it.
  const n = size.at_bound.context_bytes;
  const at = (k) => checkedLen("x", undefined, [snapshot("vault", "c", 1, "y".repeat(k))]);
  eq(at(n), size.at_bound.checked_len, "at the bound");
  eq(at(n), framingSize.max_prompt_bytes, "exactly the bound");
  eq(at(n + 1), framingSize.max_prompt_bytes + 1, "one byte over");
});
check("framing: every framing-size-v1 case with its complete inputs", () => {
  eq(framingSize.max_prompt_bytes, 32768);
  eq(framingSize.attachment_reserve, 4096);
  if (framingSize.cases.length < 10) throw new Error(`only ${framingSize.cases.length} cases`);
  for (const c of framingSize.cases) eq(checkedLen(c.text, c.mark, c.context), c.checked_len, c.name);
  // What the preflight takes is exactly the host-work shapes: anything else
  // is refused, never read loosely.
  const okContext = str([snapshot("vault", "a", 1, "x")]);
  eq(m.framingCheckedLen("t", undefined, "[]") > 0, true);
  eq(m.framingCheckedLen("t", undefined, okContext) > 0, true);
  const dup = okContext.replace('"id":"a"', '"id":"a","id":"b"');
  const float = okContext.replace('"version":1', '"version":1.5');
  if (dup === okContext || float === okContext) throw new Error("the refusal inputs changed nothing");
  throwsCode(() => m.framingCheckedLen("t", undefined, "["), "not_strict_json");
  throwsCode(() => m.framingCheckedLen("t", undefined, dup), "not_strict_json");
  throwsCode(() => m.framingCheckedLen("t", undefined, float), "not_strict_json");
  for (const context of ["{}", "null", '[{"kind":"vault","id":"a","version":1,"digest":"d"}]', '[{"kind":"notes","id":"a","version":1,"digest":"d","text":"x"}]']) {
    throwsCode(() => m.framingCheckedLen("t", undefined, context), "malformed");
  }
  for (const mark of ["null", "{}", "[]", '{"mark_id":"m"}']) throwsCode(() => m.framingCheckedLen("t", mark, "[]"), "malformed");
});

console.log(`wasm conformance: ${passed} passed, ${failures.length} failed`);
for (const f of failures) console.log(`FAIL ${f}`);
process.exit(failures.length === 0 ? 0 : 1);
