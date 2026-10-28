// The end-to-end "bot": a service member (svc-discord, §R9.6) through the
// WASM build under Node, its Ed25519 key in a SoftwareKeyStore (a bot's own
// secret store), the way an integration outside Station reaches a host.
// Socket I/O is its own (Node net, 4-byte big-endian length + frame).
// Driven by crates/atem-client-ffi/tests/e2e_bindings.rs.
// Args: <wasm pkg dir> <fixtures dir> <host port> <wall ms>
// Stdin: "EXPIRED" once the test moved the host's clock past the
// service's expiry.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import net from "node:net";
import readline from "node:readline";

const [pkgDir, fixturesDir, hostPort, wallBase] = process.argv.slice(2);
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
  const keys = JSON.parse(readFileSync(join(fixturesDir, "r9-vectors-keys.json"), "utf8")).keys;
  const mlog = JSON.parse(readFileSync(join(fixturesDir, "r9-vectors-membership-log.json"), "utf8"));
  const entries = mlog.log.map((v) => JSON.stringify(v.entry));
  const log = m.MembershipLog.verify(mlog.account_id, mlog.genesis_hash, entries, { wallMs: wall(), monoMs: mono(), bootId: "bot" });
  const grant = log.serviceGrant("svc-discord");
  expect(grant && grant.scope.ops.join(",") === "interrupt,prompt,view", "the log names the bot's grant");

  const store = new m.SoftwareKeyStore();
  store.insertEd25519("svc-discord/auth", new Uint8Array(Buffer.from(keys["svc-discord"].auth.secret_hex, "hex")));
  const connect = async () => {
    const wire = new Wire(hostPort);
    const conn = new m.ClientConnection("host-a", "service", "svc-discord", "svc-discord/auth", undefined, undefined);
    wire.send(conn.start(log, mono()));
    wire.send(conn.onAccept(await wire.recv(), log, store, mono()));
    return { wire, conn, first: await wire.recv() };
  };

  // Admission: a service principal with the scope the log grants.
  const { wire, conn, first } = await connect();
  const welcome = conn.onWelcome(first, log, mono());
  const scope = JSON.parse(welcome.scopeJson);
  console.log(`WELCOME ${welcome.principal} ${welcome.clientKind} ${[...welcome.permissions].sort().join(",")} ${welcome.revision} ${welcome.head.seq} ${scope.ops.join(",")}`);
  expect(welcome.authorizationMsLeft <= grant.expiresAt - Number(wallBase), "authorization bounded by the expiry");

  async function exchange(frame, done) {
    wire.send(frame);
    const events = [];
    while (!done(events)) {
      for (const e of conn.onFrame(await wire.recv(), mono())) {
        if (e.type === "outgoing") wire.send(e.frame);
        events.push(e);
      }
    }
    return events;
  }
  const replyTo = (id) => (ev) => ev.some((e) => (e.type === "error" || e.type === "session") && e.re === id);
  const receipts = (ev) => ev.filter((e) => e.type === "session" && e.op === "receipt").map((e) => JSON.parse(e.json).data.state);

  // The registry shows only the sessions in scope: ses-a's launch project
  // hash is in the scope's projects, ses-b's isn't.
  await exchange(conn.list(mono()).frame, (ev) => ev.some((e) => e.type === "registry"));
  console.log(`SESSIONS ${conn.sessions().map((s) => s.sessionId).join(",")}`);

  // Inside the scope's ops: a lease, a prompt, an interrupt.
  const ses = "ses-aaaaaaaaaaaa";
  const lease = await exchange(conn.acquire(ses, false, mono()).frame, (ev) => ev.some((e) => e.type === "lease"));
  expect(lease.some((e) => e.type === "lease" && e.outcome === "applied"), "lease applied");
  const prompt = await exchange(conn.submitPrompt(ses, crypto.randomUUID(), "status", mono()).frame, (ev) => receipts(ev).includes("completed"));
  const interrupt = await exchange(conn.submitInterrupt(ses, crypto.randomUUID(), mono()).frame, (ev) => receipts(ev).includes("completed"));
  console.log(`IN_SCOPE prompt:${receipts(prompt).at(-1)} interrupt:${receipts(interrupt).at(-1)}`);

  // Outside the ops (approval, stop, terminal input): forbidden at the host.
  const refusals = [];
  const approval = conn.submitApproval(ses, crypto.randomUUID(), "8c3e9d6b-1f40-4b52-8dae-4f5a6b7c8d9e", "allow_once", undefined, undefined, mono());
  const a = await exchange(approval.frame, replyTo(approval.id));
  refusals.push(`approval:${a.find((e) => e.type === "error")?.code}`);
  const stop = conn.submitStop(ses, crypto.randomUUID(), mono());
  const s = await exchange(stop.frame, replyTo(stop.id));
  refusals.push(`stop:${s.find((e) => e.type === "error")?.code}`);
  const binding = JSON.parse(conn.bindingJson(ses, true, mono()));
  const input = conn.sendJson(JSON.stringify({ type: "terminal", data: { v: 1, op: "input", terminal_id: ses, binding, generation: "22222222-2222-4222-8222-222222222222", stream_id: crypto.randomUUID(), seq: 1, data_b64: "bHMK" } }), mono());
  const t = await exchange(input, (ev) => ev.some((e) => e.type === "family"));
  refusals.push(`terminal:${JSON.parse(t.find((e) => e.type === "family").json).data.code}`);

  // A session out of scope, named with a hand-made binding (the registry
  // never showed it): unknown_session, as for one that doesn't exist.
  const read = JSON.parse(conn.bindingJson(ses, false, mono()));
  read.target.session_id = "ses-bbbbbbbbbbbb";
  read.target.process_gen = "33333333-3333-4333-8333-333333333333";
  const qid = crypto.randomUUID();
  const q = await exchange(conn.sendJson(JSON.stringify({ type: "session", data: { v: 1, op: "receipt_query", id: qid, binding: read, request_ids: [crypto.randomUUID()] } }), mono()), replyTo(qid));
  refusals.push(`out_of_scope:${q.find((e) => e.type === "error")?.code}`);
  console.log(`REFUSED ${refusals.join(" ")}`);
  const released = await exchange(conn.release(ses, mono()).frame, (ev) => ev.some((e) => e.type === "lease"));
  expect(released.some((e) => e.type === "session" && e.op === "lease_released"), "released");
  console.log("READY_FOR_EXPIRY");

  // Expiry: the host's clock passes `expires_at`; its timer fences the
  // attachment, and a new connection is refused.
  const rl = readline.createInterface({ input: process.stdin });
  await new Promise((r) => rl.on("line", (line) => line === "EXPIRED" && r()));
  let fenced;
  while (!fenced) {
    fenced = conn.onFrame(await wire.recv(), mono()).find((e) => e.type === "fenced");
  }
  expect(conn.isClosed(), "the channel is closed after the fence");
  console.log(`FENCED ${fenced.code} ${fenced.detail}`);
  const again = await connect();
  try {
    again.conn.onWelcome(again.first, log, mono());
    fail("an expired service must be refused");
  } catch (e) {
    expect(e.kind === "refused" && e.next.type === "stop", `refused with stop (${e.kind} ${JSON.stringify(e.next)})`);
    console.log(`REFUSED_AGAIN ${e.code} ${e.detail}`);
  }
  console.log("DONE");
  process.exit(0);
}

main().catch((e) => fail(`${e.kind || ""} ${e.code || ""} ${e.detail || ""} ${e.stack || e}`));
