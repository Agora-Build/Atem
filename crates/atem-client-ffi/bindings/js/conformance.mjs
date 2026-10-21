// The shared r9 vectors (designs/protocol/fixtures/r9-vectors-*.json) run
// through the WASM binding under Node. Usage:
//   node conformance.mjs <wasm-bindgen nodejs pkg dir> <fixtures dir>
// The same checks run through Kotlin (bindings/kotlin/Conformance.kt) and
// Swift (bindings/swift/Tests/…/ConformanceTests.swift).
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
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

console.log(`wasm conformance: ${passed} passed, ${failures.length} failed`);
for (const f of failures) console.log(`FAIL ${f}`);
process.exit(failures.length === 0 ? 0 : 1);
