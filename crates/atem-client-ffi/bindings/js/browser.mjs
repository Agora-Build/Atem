// The end-to-end "browser": a browser principal (a grant from the phone)
// whose key is a non-extractable WebCrypto P-256 key. WebCrypto signs
// asynchronously, so it uses the deferred handshake: the binding returns
// the SignRequest, WebCrypto signs it, the binding takes the signature.
// Socket I/O is its own (Node net, 4-byte big-endian length + frame).
// Driven by crates/atem-client-ffi/tests/e2e_bindings.rs.
// Args: <wasm pkg dir> <fixtures dir> <host port> <relay port> <wall ms>
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import net from "node:net";
import readline from "node:readline";

const [pkgDir, fixturesDir, hostPort, relayPort, wallBase] = process.argv.slice(2);
const require = createRequire(import.meta.url);
const m = require(join(resolve(pkgDir), "atem_client_ffi.js"));
const started = performance.now();
const mono = () => Math.floor(performance.now() - started);
const wall = () => Number(wallBase) + mono();
const fail = (what) => {
  console.log(`FAIL ${what}`);
  process.exit(1);
};
const expect = (ok, what) => {
  if (!ok) fail(what);
};

class Wire {
  constructor(port) {
    this.socket = net.connect(Number(port), "127.0.0.1");
    this.buf = Buffer.alloc(0);
    this.waiting = [];
    this.frames = [];
    this.socket.on("data", (d) => {
      this.buf = Buffer.concat([this.buf, d]);
      while (this.buf.length >= 4) {
        const n = this.buf.readUInt32BE(0);
        if (this.buf.length < 4 + n) break;
        const frame = new Uint8Array(this.buf.subarray(4, 4 + n));
        this.buf = this.buf.subarray(4 + n);
        const w = this.waiting.shift();
        if (w) w(frame);
        else this.frames.push(frame);
      }
    });
    this.socket.on("error", (e) => fail(`socket: ${e}`));
  }
  send(frame) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(frame.length, 0);
    this.socket.write(Buffer.concat([len, Buffer.from(frame)]));
  }
  recv() {
    const f = this.frames.shift();
    return f ? Promise.resolve(f) : new Promise((r) => this.waiting.push(r));
  }
}

async function main() {
  const mlog = JSON.parse(readFileSync(join(fixturesDir, "r9-vectors-membership-log.json"), "utf8"));
  const entries = mlog.log.map((v) => JSON.stringify(v.entry));
  const log = m.MembershipLog.verify(mlog.account_id, mlog.genesis_hash, entries, { wallMs: wall(), monoMs: mono(), bootId: "browser" });

  // The browser key: generated here, never extractable.
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  console.log(`BROWSER_KEY ${Buffer.from(publicRaw).toString("hex")}`);

  const rl = readline.createInterface({ input: process.stdin });
  const grant = await new Promise((r) => rl.on("line", (line) => line.startsWith("GRANT ") && r(line.slice(6))));
  const info = m.parseBrowserGrant(grant);
  expect(Buffer.from(info.browserKey.raw).equals(Buffer.from(publicRaw)), "the grant names this key");

  const wire = new Wire(hostPort);
  const conn = new m.ClientConnection("host-a", "browser", undefined, "browser-webcrypto", grant, undefined);
  wire.send(conn.start(log, mono()));
  const request = conn.onAcceptDeferred(await wire.recv(), log, mono());
  expect(request.purpose === "channel" && request.freshConfirmation === false, "channel purpose");
  expect(request.label === "atem-ch1-client-sig-v1" && request.keyId === "browser-webcrypto", "request label and key");
  expect(JSON.stringify(conn.state()) === '"await_signature"', "waiting for the signature");
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, request.input));
  wire.send(conn.finishWithSignature(signature, mono()));
  const welcome = conn.onWelcome(await wire.recv(), log, mono());
  console.log(`WELCOME ${welcome.principal} ${welcome.clientKind} ${[...welcome.permissions].sort().join(",")} ${welcome.revision} ${welcome.head.seq}`);
  expect(welcome.authorizationMsLeft <= 3_000_000, "authorization bounded by the grant");

  async function exchange(out, done) {
    wire.send(out.frame);
    const events = [];
    while (!done(events)) {
      const got = conn.onFrame(await wire.recv(), mono());
      if (process.env.ATEM_E2E_DEBUG) console.error(JSON.stringify(got));
      for (const e of got) {
        if (e.type === "outgoing") wire.send(e.frame);
        events.push(e);
      }
    }
    return events;
  }
  const receipts = (ev) => ev.filter((e) => e.type === "session" && e.op === "receipt").map((e) => JSON.parse(e.json).data.state);

  await exchange(conn.list(mono()), (ev) => ev.some((e) => e.type === "registry"));
  console.log(`SESSIONS ${conn.sessions().map((s) => s.sessionId).join(",")}`);
  const ses = "ses-aaaaaaaaaaaa";
  const lease = await exchange(conn.acquire(ses, false, mono()), (ev) => ev.some((e) => e.type === "lease"));
  console.log(`LEASE ${lease.find((e) => e.type === "lease").outcome}`);
  const prompt = await exchange(conn.submitPrompt(ses, crypto.randomUUID(), "ls", mono()), (ev) => receipts(ev).includes("completed"));
  console.log(`PROMPT ${receipts(prompt).join(" ")}`);
  const renewed = await exchange(conn.renew(ses, mono()), (ev) => ev.some((e) => e.type === "lease" || e.type === "error"));
  expect(renewed.some((e) => e.type === "lease" && e.outcome === "applied"), `renew applied: ${JSON.stringify(renewed)}`);
  expect(conn.lease(ses, mono()).controls === true, "controls");
  expect(JSON.parse(conn.bindingJson(ses, true, mono())).lease_epoch !== undefined, "a mutation binding");
  // The grant's ops are prompt + view: an interrupt is outside them.
  const interrupt = await exchange(conn.submitInterrupt(ses, crypto.randomUUID(), mono()), (ev) => ev.some((e) => e.type === "error" || e.type === "session"));
  expect(interrupt.some((e) => e.type === "error" && e.code === "forbidden"), "interrupt outside the grant's ops is forbidden");
  const released = await exchange(conn.release(ses, mono()), (ev) => ev.some((e) => e.type === "lease"));
  expect(released.some((e) => e.type === "session" && e.op === "lease_released"), "released");
  expect(conn.lease(ses, mono()).controls === false, "a viewer again");
  // Outside the grant's session there is no binding to build.
  try {
    conn.acquire("ses-bbbbbbbbbbbb", false, mono());
    fail("acquire outside the grant must be refused locally");
  } catch (e) {
    expect(e.kind === "request" && e.detail === "unknown session", `local refusal (${e.kind} ${e.detail})`);
  }
  console.log("REQUESTS renew interrupt:forbidden release");

  const relay = new Wire(relayPort);
  relay.send(Buffer.from(JSON.stringify({ device_id: "browser" })));
  console.log("READY_FOR_PUSH");
  const message = JSON.parse(Buffer.from(await relay.recv()).toString("utf8"));
  expect(message.op === "push_hint", "a push_hint message");
  const devices = [];
  for (const h of message.hints) {
    const asClient = m.verifyPushHint(JSON.stringify(h), log, wall(), "client");
    const asRelay = m.verifyPushHint(JSON.stringify(h), log, wall(), "relay");
    asClient.checkSealed();
    expect(asRelay.json() === asClient.json(), "same hint");
    const state = asClient.state();
    expect(state.type === "open", "open hint");
    devices.push(state.deviceId);
    const stages = m.pushStages(asClient.createdAt(), { deviceClass: "mobile", connected: false, immediateMobile: false });
    expect(stages[0].due === asClient.createdAt() + 60000, "mobile stage at +60 s");
  }
  console.log(`HINTS_VERIFIED ${devices.sort().join(",")} sealed`);
  const seenMessage = JSON.parse(Buffer.from(await relay.recv()).toString("utf8"));
  expect(seenMessage.op === "push_seen", "a push_seen message");
  const seen = m.verifySeen(JSON.stringify(seenMessage.seen), log);
  console.log(`SEEN_VERIFIED ${seen.deviceId}`);

  // The phone revokes the grant: the host fences this attachment, and a new
  // connection with the same grant is refused.
  let fenced;
  while (!fenced) {
    const events = conn.onFrame(await wire.recv(), mono());
    fenced = events.find((e) => e.type === "fenced");
  }
  expect(conn.isClosed(), "the channel is closed after the fence");
  console.log(`FENCED ${fenced.code} ${fenced.detail}`);
  const again = new Wire(hostPort);
  const conn2 = new m.ClientConnection("host-a", "browser", undefined, "browser-webcrypto", grant, undefined);
  again.send(conn2.start(log, mono()));
  const request2 = conn2.onAcceptDeferred(await again.recv(), log, mono());
  const signature2 = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, request2.input));
  again.send(conn2.finishWithSignature(signature2, mono()));
  try {
    conn2.onWelcome(await again.recv(), log, mono());
    fail("a revoked grant must be refused");
  } catch (e) {
    expect(e.kind === "refused" && e.next.type === "stop", `refused with stop (${e.kind})`);
    console.log(`REFUSED ${e.code} ${e.detail}`);
  }
  console.log("DONE");
  process.exit(0);
}

main().catch((e) => fail(`${e.kind || ""} ${e.code || ""} ${e.detail || ""} ${e.stack || e}`));
