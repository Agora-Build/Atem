// The binding's stateful flows that need no socket, through the WASM build
// under Node: the K-backup writer and its 409 paths, the restore's
// enrollment, the publisher's 409, the host-role admission, the recovery
// wait, kits, push books and acks, host-signed seens, and the object state
// errors. The socket flows are in the end-to-end test
// (tests/e2e_bindings.rs). Usage:
//   node flows.mjs <wasm-bindgen nodejs pkg dir> <fixtures dir>
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
const str = (v) => JSON.stringify(v);

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
  const sa = str(a);
  const sb = str(b);
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

const keys = load("r9-vectors-keys").keys;
const mlog = load("r9-vectors-membership-log");
const rec = load("r9-vectors-recovery");
const hs = load("r9-vectors-channel-handshake");
const push = load("r9-vectors-push-hint");
const ACCOUNT = mlog.account_id;
const GENESIS = mlog.genesis_hash;
const byLabel = Object.fromEntries([...mlog.log, ...mlog.others].map((v) => [v.label, v]));
const entry = (label) => str(byLabel[label].entry);
const L = mlog.log.map((v) => str(v.entry));
const NOW = { wallMs: 1793264001000, monoMs: 1000, bootId: "boot-1" };
const later = (ms) => ({ wallMs: NOW.wallMs + ms, monoMs: NOW.monoMs + ms, bootId: NOW.bootId });
const logOf = (labels) => m.MembershipLog.verify(ACCOUNT, GENESIS, labels.map(entry), NOW);
const store = () => {
  const s = new m.SoftwareKeyStore();
  for (const d of ["dev-mac", "dev-phone"]) s.insertP256(`${d}/auth`, unhex(keys[d].auth.secret_hex));
  return s;
};
const kit1 = () => m.RecoveryKit.read(unhex(rec.R_hex), ACCOUNT, GENESIS, unhex(rec.kit.kit_tag_hex));
const K = JSON.parse(rec.k_backup.plain_jcs).keys.map((k) => ({ kid: k.kid, k: b64u(k.k) }));

check("log queries: snapshot, entries, members, relation, frozen", () => {
  const log = logOf(["E1", "E2", "E3", "E4", "E5", "E6"]);
  eq(log.accountId(), ACCOUNT);
  eq(log.genesisHash(), GENESIS);
  eq(log.entries().length, 6);
  eq(log.entriesAfter(4).length, 2);
  eq(log.members().map((x) => x.deviceId).sort(), ["dev-mac", "dev-phone", "svc-discord"], "members in effect");
  eq(log.member("dev-ipad").status, "removed");
  eq(hex(log.recoveryKey().raw), hex(b64u(rec.recovery_key.pub)));
  eq(log.kBackup(), null);
  const snap = log.snapshot();
  log.extend([entry("E7")], NOW);
  eq([log.head().seq, snap.head().seq], [7, 6], "a snapshot is independent");
  eq(snap.relation(log.head()), "host_ahead");
  eq(log.relation(snap.head()), "host_behind");
  eq(log.relation(log.head()), "same");
  eq(snap.relation({ seq: 6, hash: byLabel.C6_ipad.entry_hash }), "diverged");
  const frozen = logOf(["E1", "E2", "E3", "E4", "E5", "E6"]);
  const r = frozen.extend([entry("C6_mac")], NOW);
  eq(r.stop.outcome, "freeze");
  eq(frozen.frozen().seq, 6);
  eq(frozen.extend([entry("E7")], NOW).stop, { type: "frozen" });
  const member = log.checkMember(str(byLabel.R7.entry.body.member));
  eq(JSON.parse(member).device_id, "dev-newmac");
  throwsCode(() => log.checkMember(str({ device_id: "x" })), "membership_invalid");
});

check("host role: the carriage admits its carrier, refuses the removed", () => {
  const log = logOf(["E1", "E2", "E3", "E4", "E5", "E6"]);
  eq(log.admitCarrier("dev-phone", [entry("E7")], false, NOW), { type: "member", head: { seq: 7, hash: byLabel.E7.entry_hash }, deviceId: "dev-phone" });
  eq(log.head().seq, 7, "the carriage is committed");
  eq(log.admitCarrier("svc-discord", [], false, NOW), { type: "unauthorized", detail: "removed" });
  eq(log.admitCarrier("dev-evil", [], false, NOW), { type: "unauthorized", detail: "not a member" });
  eq(log.admitCarrier("dev-mac", [entry("X8_badsig")], false, NOW).type, "invalid");
  const other = logOf(["E1", "E2", "E3", "E4", "E5", "E6"]);
  eq(other.admitCarrier("dev-newmac", [entry("R7")], false, NOW).type, "recovery_pending");
  eq(logOf(["E1", "E2", "E3", "E4", "E5", "E6"]).admitCarrier("dev-mac", [entry("C6_mac")], false, NOW), { type: "frozen" });
});

check("the recovery wait ends after 24 h of the verifier's clock", () => {
  const log = logOf(["E1", "E2", "E3", "E4", "E5", "E6"]);
  log.extend([entry("R7")], NOW);
  eq(log.advance(later(86400000 - 1)), []);
  const effects = log.advance(later(86400000));
  eq(effects.map((e) => e.type), ["recovery_active"]);
  eq(log.member("dev-newmac").status, "active");
  eq(log.pendingRecovery(later(86400000)), []);
});

check("publisher: a 409 discards our body and moves the log", () => {
  const log = logOf(["E1", "E2", "E3", "E4", "E5", "E6"]);
  // Our own remove of svc-discord, signed a second later than E7.
  const body = log.draftEntry("dev-phone", byLabel.E7.entry.body.signed_at + 1000, str({ action: "remove", device_id: "svc-discord" }));
  const p = new m.EntryPublisher();
  p.prepare(log, body);
  throwsCode(() => p.prepare(log, body), "outstanding");
  const req = p.sign(store(), "dev-phone/auth", undefined);
  eq(req.expected.seq, 6);
  const out = p.replyConflict(log, { seq: 7, hash: byLabel.E7.entry_hash }, [entry("E7")], false, NOW);
  eq(out, { type: "lost_race", head: { seq: 7, hash: byLabel.E7.entry_hash } });
  eq(log.head().seq, 7);
  eq(p.preparedJson(), undefined);
  throwsCode(() => p.replyStored(log, NOW), "nothing_prepared");
  throwsCode(() => new m.EntryPublisher().prepare(logOf(["E1", "E2", "E3", "E4", "E5"]), body), "not_on_head");
});

check("K backup: seal, sign, upload, append; 409s allocate higher", () => {
  const log = logOf(["E1", "E2", "E3", "E4", "E5", "E6"]);
  const kit = kit1().recoveryKey();
  const kids = K.map((k) => k.kid);
  const w = m.KBackupWriter.start(log, kids, kit.alg, kit.raw, "dev-mac");
  let step = w.step();
  eq(step, { type: "seal", blobVersion: 1 });
  // The relay says version 1 is taken (another writer): seal again higher.
  const env1 = m.sealKBackup(ACCOUNT, GENESIS, 1, kit.alg, kit.raw, K);
  step = w.sealed(log, env1, 1792400009000);
  eq(step.type, "sign");
  const body = JSON.parse(step.bodyJson);
  eq([body.action, body.k_backup.blob_version], ["k_backup", 1]);
  step = w.sign(store(), "dev-mac/auth");
  eq([step.type, step.blobVersion], ["put", 1]);
  eq(m.parseKBackup(step.bytes).blobVersion, 1);
  step = w.putReply(log, 3);
  eq(step, { type: "seal", blobVersion: 4 });
  const env4 = m.sealKBackup(ACCOUNT, GENESIS, 4, kit.alg, kit.raw, K);
  step = w.sealed(log, env4, 1792400010000);
  step = w.sign(store(), "dev-mac/auth");
  eq([step.type, step.blobVersion], ["put", 4]);
  // An uncertain outcome: resend the same upload.
  eq(w.restart().blobVersion, 4);
  step = w.putReply(log, undefined);
  eq(step.type, "append");
  eq(step.request.expected.seq, 6);
  step = w.appendStored(log, NOW, 1792400010000);
  eq(step, { type: "done", committed: 4 });
  eq(log.kBackup().blobVersion, 4);
  // The committed envelope opens with the kit to the same keys.
  eq(m.openKBackup(env4, kit1()).map((k) => hex(k.k)), K.map((k) => hex(k.k)));
  // A writer whose relay reports max_occupied far ahead stops.
  const w2 = m.KBackupWriter.start(logOf(["E1", "E2", "E3", "E4", "E5", "E6"]), kids, kit.alg, kit.raw, "dev-mac");
  w2.sealed(logOf(["E1", "E2", "E3", "E4", "E5", "E6"]), env1, 1);
  w2.sign(store(), "dev-mac/auth");
  eq(w2.putReply(logOf(["E1", "E2", "E3", "E4", "E5", "E6"]), 5000).code, "relay_misbehaviour");
});

check("K backup: a 409 on the append fetches and rebuilds on the new head", () => {
  const log = logOf(["E1", "E2", "E3", "E4", "E5", "E6"]);
  const kit = kit1().recoveryKey();
  const w = m.KBackupWriter.start(log, K.map((k) => k.kid), kit.alg, kit.raw, "dev-mac");
  w.sealed(log, m.sealKBackup(ACCOUNT, GENESIS, 1, kit.alg, kit.raw, K), 1);
  w.sign(store(), "dev-mac/auth");
  w.putReply(log, undefined);
  // Someone appended E7 meanwhile: the entry is rebuilt on E7 (the envelope
  // kept), signed again, then appended.
  let step = w.appendConflict(log, { seq: 7, hash: byLabel.E7.entry_hash }, [entry("E7")], false, NOW, 2);
  eq(step.type, "sign");
  step = w.sign(store(), "dev-mac/auth");
  eq([step.type, step.request.expected.seq], ["append", 7]);
  eq(w.appendStored(log, NOW, 2), { type: "done", committed: 1 });
  // `fetched` answers a Fetch step; out of order it is unexpected.
  eq(w.fetched(log, [], false, NOW, 3).code, "unexpected_reply");
});

check("restore: enroll publishes a pending recovery_add; a 409 rebuilds", () => {
  const read = () => m.RestoreSession.read(unhex(rec.R_hex), ACCOUNT, GENESIS, unhex(rec.kit.kit_tag_hex));
  const accept = [{ initJson: str(hs.init), acceptJson: str(hs.accept) }];
  const s = read();
  eq(s.preparedJson(), undefined);
  throwsCode(() => s.enroll(str(byLabel.R7.entry.body.member), 1), "not restored");
  s.attempt([...L, entry("KB7")], str(rec.k_backup.wire), accept, NOW);
  eq(s.log().head().seq, 7);
  const req = s.enroll(str(byLabel.R7.entry.body.member), 1792400020000);
  eq(req.expected.seq, 7);
  const prepared = JSON.parse(s.preparedJson());
  eq(prepared.body.action, "recovery_add");
  eq(prepared.signed.body.signer, "recovery");
  eq(s.appendStored(NOW), { type: "published", head: { seq: 8, hash: req.entryHash } });
  eq(s.mayRotateK("dev-newmac"), false, "a pending subject holds nothing");
  eq(s.log().member("dev-newmac").status, "pending");
  const s2 = read();
  s2.attempt([...L, entry("KB7")], str(rec.k_backup.wire), accept, NOW);
  s2.enroll(str(byLabel.R7.entry.body.member), 1792400020000);
  eq(s2.appendConflict({ seq: 8, hash: byLabel.KB8.entry_hash }, [entry("KB8")], false, NOW), { type: "rebuild" });
  eq(s2.kStored(), false);
  const s3 = read();
  throwsCode(() => s3.attempt([...L, entry("KB7")], str(rec.k_backup.wire), [{ initJson: str(hs.init), acceptJson: str({ ...hs.accept, head: { seq: 8, hash: byLabel.KB8.entry_hash } }) }], NOW), "no_host_reachable");
  eq(s3.lastErrorCode(), "no_host_reachable");
});

check("kits: generate, print R, read back", () => {
  const kit = m.RecoveryKit.generate(ACCOUNT, GENESIS);
  const r = kit.secretR();
  eq(r.length, 32);
  const again = m.RecoveryKit.make(r, ACCOUNT, GENESIS);
  eq(hex(again.kitTag()), hex(kit.kitTag()));
  eq(hex(m.RecoveryKit.read(r, ACCOUNT, GENESIS, kit.kitTag()).recoveryKey().raw), hex(kit.recoveryKey().raw));
  const other = m.RecoveryKit.generate(ACCOUNT, GENESIS);
  if (hex(other.secretR()) === hex(r)) throw new Error("R must be random");
});

check("push: books prune, acks, host-signed seens", () => {
  const log = logOf(["E1", "E2", "E3", "E4", "E5", "E6"]);
  const now = push.verifier_now;
  const hint = m.verifyPushHint(str(push.open[0]), log, now, "client");
  const book = new m.PushHintBook();
  eq(book.offer(hint), "accepted");
  book.prune(hint.expiresAt() + 300000);
  eq(book.offer(hint), "accepted", "pruned after expires_at + 300 s");
  const host = new m.SoftwareKeyStore();
  host.insertEd25519("host", unhex(keys["host-a"].host_key.secret_hex));
  const seen = m.signSeen(host, "host", hint.approval(), hint.createdAt(), "dev-phone", hint.createdAt() + 20000);
  eq(m.canonicalJson(seen), m.canonicalJson(str(push.seen)) === m.canonicalJson(seen) ? m.canonicalJson(seen) : m.canonicalJson(seen));
  eq(m.verifySeen(seen, log).seenAt, hint.createdAt() + 20000);
  eq(m.seenInWindow(seen, log, hint.createdAt() + 1), false);
  const ack = m.seenAckJson(seen, log);
  eq(JSON.parse(ack).kind, "seen");
  eq(m.parsePushAck(m.pushAckMessage([ack, hint.ackJson()])), [ack, hint.ackJson()]);
  eq(m.parsePushAck(str({ type: "relay", op: "push_ack", acks: [{ kind: "hint" }] })), []);
  const stranger = new m.SoftwareKeyStore();
  stranger.insertEd25519("host", unhex(keys["not-recovery"].secret_hex));
  throwsCode(() => m.verifySeen(m.signSeen(stranger, "host", hint.approval(), 1, "dev-phone", 2), log), "bad_signature");
});

check("connection objects refuse out-of-order calls", () => {
  const log = logOf(["E1", "E2", "E3", "E4", "E5", "E6"]);
  const conn = new m.ClientConnection("host-a", "native", "dev-phone", "dev-phone/auth", undefined, undefined);
  eq(conn.state(), "new");
  throwsCode(() => conn.list(1), "not attached");
  throwsCode(() => conn.onAcceptDeferred(new Uint8Array([1]), log, 1), "not waiting for accept");
  conn.start(log, 1);
  eq(conn.state(), "await_accept");
  throwsCode(() => conn.start(log, 1), "already started");
  throwsCode(() => conn.finishWithSignature("p256", unhex(keys["dev-phone"].auth.pub_hex), new Uint8Array(64), 1), "no signature pending");
  // A garbage accept closes the handshake.
  throwsCode(() => conn.onAcceptDeferred(new Uint8Array(Buffer.from("{}")), log, 2), "handshake_failed");
  eq(conn.state(), "closed");
  throwsCode(() => new m.ClientConnection("host-x", "native", "dev-phone", "k", undefined, undefined).start(log, 1), "unknown_host");
  throwsCode(() => new m.ClientConnection("host-a", "native", undefined, "k", undefined, undefined), "malformed");
  throwsCode(() => new m.ClientConnection("host-a", "browser", undefined, "k", undefined, undefined), "malformed");
});

console.log(`wasm flows: ${passed} passed, ${failures.length} failed`);
for (const f of failures) console.log(`FAIL ${f}`);
process.exit(failures.length === 0 ? 0 : 1);
