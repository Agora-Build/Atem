// The end-to-end "phone": a native member (dev-phone) whose keys are in a
// Kotlin AppKeyProvider (JdkKeys), doing its own socket I/O over loopback
// TCP (4-byte big-endian length, then the frame) and passing every frame
// through the binding. Driven by crates/atem-client-ffi/tests/e2e_bindings.rs.
// Args: <fixtures dir> <host port> <relay port> <browser key hex> <wall ms>
package atem.bindings.test

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.Socket
import java.util.UUID
import uniffi.atem_client_ffi.*

private class Wire(port: Int) {
    private val socket = Socket("127.0.0.1", port)
    private val input = DataInputStream(socket.getInputStream())
    private val output = DataOutputStream(socket.getOutputStream())

    fun send(frame: ByteArray) {
        output.writeInt(frame.size)
        output.write(frame)
        output.flush()
    }

    fun recv(): ByteArray {
        val n = input.readInt()
        return ByteArray(n).also { input.readFully(it) }
    }
}

private fun fail(what: String): Nothing {
    println("FAIL $what")
    System.out.flush()
    kotlin.system.exitProcess(1)
}

private fun expect(ok: Boolean, what: String) {
    if (!ok) fail(what)
}

fun main(args: Array<String>) {
    try {
        run(args)
    } catch (e: AtemException) {
        fail("${e.codeOf()} ${e.detailOf()}")
    } catch (e: Throwable) {
        fail("$e")
    }
}

private fun run(args: Array<String>) {
    val dir = File(args[0])
    val hostPort = args[1].toInt()
    val relayPort = args[2].toInt()
    val browserKey = unhex(args[3])
    val wallBase = args[4].toULong()
    val started = System.nanoTime()
    fun mono(): ULong = ((System.nanoTime() - started) / 1_000_000).toULong()
    fun wall(): ULong = wallBase + mono()

    val keys = Json.parse(File(dir, "r9-vectors-keys.json").readText())["keys"]
    val mlog = Json.parse(File(dir, "r9-vectors-membership-log.json").readText())
    val entries = mlog["log"].arr().map { Json.write(it["entry"]) }
    val log = MembershipLog.verify(mlog["account_id"].s(), mlog["genesis_hash"].s(), entries, HostClock(wall(), mono(), "phone-boot"))

    val provider = JdkKeys()
    val auth = keys["dev-phone"]["auth"]
    val enc = keys["dev-phone"]["enc"]
    provider.addP256("dev-phone/auth", unhex(auth["secret_hex"].s()), unhex(auth["pub_hex"].s()))
    provider.addX25519("dev-phone/enc", unhex(enc["secret_hex"].s()), unhex(enc["pub_hex"].s()))

    // The handshake: init → accept → finish (sig_c through the provider) → welcome.
    val wire = Wire(hostPort)
    val conn = ClientConnection("host-a", ClientIdentity(PrincipalKind.NATIVE, "dev-phone", "dev-phone/auth", null), null)
    wire.send(conn.start(log, mono()))
    wire.send(conn.onAccept(wire.recv(), log, provider, mono()))
    val channelSig = provider.requests.single()
    expect(channelSig.purpose == SigningPurpose.CHANNEL && !channelSig.freshConfirmation && channelSig.bodyJson == null, "channel signing purpose")
    val welcome = conn.onWelcome(wire.recv(), log, mono())
    println("WELCOME ${welcome.principal} ${welcome.clientKind} ${welcome.permissions.sorted().joinToString(",")} ${welcome.revision} ${welcome.head.seq}")
    expect(welcome.head == log.head() && conn.fetchTo(log) == null, "welcome head")

    fun exchange(out: Outgoing, done: (List<ClientEvent>) -> Boolean): List<ClientEvent> {
        wire.send(out.frame)
        val events = ArrayList<ClientEvent>()
        while (!done(events)) {
            for (e in conn.onFrame(wire.recv(), mono())) {
                if (e is ClientEvent.Outgoing) wire.send(e.frame)
                events.add(e)
            }
        }
        return events
    }
    fun receipts(events: List<ClientEvent>) = events.filterIsInstance<ClientEvent.Session>()
        .filter { it.op == "receipt" }
        .map { Json.parse(it.json)["data"]["state"].s() }

    exchange(conn.list(mono())) { ev -> ev.any { it is ClientEvent.Registry } }
    println("SESSIONS ${conn.sessions().map { it.sessionId }.joinToString(",")}")

    val ses = "ses-aaaaaaaaaaaa"
    val lease = exchange(conn.acquire(ses, false, mono())) { ev -> ev.any { it is ClientEvent.Lease } }
    println("LEASE ${(lease.first { it is ClientEvent.Lease } as ClientEvent.Lease).outcome}")
    expect(conn.lease(ses, mono())!!.controls, "controls after acquire")

    val requestId = UUID.randomUUID().toString()
    val prompt = exchange(conn.submitPrompt(ses, requestId, "npm test", mono())) { ev -> receipts(ev).contains("completed") }
    println("PROMPT ${receipts(prompt).joinToString(" ")}")
    val query = exchange(conn.receiptQuery(ses, listOf(requestId), mono())) { ev -> ev.any { it is ClientEvent.Session && it.op == "receipts" } }
    expect(query.any { it is ClientEvent.Session && it.json.contains(requestId) }, "receipt_query names the request")

    // The rest of the session requests under the lease.
    val renewed = exchange(conn.renew(ses, mono())) { ev -> ev.any { it is ClientEvent.Lease } }
    expect(renewed.any { it is ClientEvent.Lease && it.outcome == "applied" }, "renew applied")
    val binding = Json.parse(conn.bindingJson(ses, true, mono())!!)
    expect(binding["lease_epoch"] != null && binding["target"]["session_id"] == ses, "a mutation binding while controlling")
    expect(Json.parse(conn.bindingJson(ses, false, mono())!!).obj()["lease_epoch"] == null, "a read binding carries no lease epoch")
    fun completes(out: Outgoing) = exchange(out) { ev -> receipts(ev).contains("completed") }
    completes(conn.submitInterrupt(ses, UUID.randomUUID().toString(), mono()))
    completes(conn.submitApproval(ses, UUID.randomUUID().toString(), "6f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b", ApprovalChoice.ALLOW_ONCE, null, null, mono()))
    completes(conn.submitRuleRevoke(ses, UUID.randomUUID().toString(), "s-0123456789abcdef", mono()))
    completes(conn.submitStop(ses, UUID.randomUUID().toString(), mono()))
    try {
        conn.submitApproval(ses, UUID.randomUUID().toString(), "6f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b", ApprovalChoice.ALLOW_ALWAYS, null, null, mono())
        fail("allow_always without a rule_id must be refused before sending")
    } catch (e: AtemException.Invalid) {}
    // terminal-v1 and chat-v1 requests decode and are authorized at the host
    // (the test host has no terminal or chat behind them, so no reply): the
    // next request's reply is the first thing back, with no error before it.
    wire.send(conn.terminalSubscribe(ses, mono()).frame)
    wire.send(conn.chatOpen(ses, "c-" + UUID.randomUUID().toString(), mono()).frame)
    val after = exchange(conn.list(mono())) { ev -> ev.any { it is ClientEvent.Registry } }
    expect(after.none { it is ClientEvent.Error || it is ClientEvent.Family }, "terminal subscribe and chat open accepted")
    println("REQUESTS renew interrupt approval rule_revoke stop terminal chat")
    val released = exchange(conn.release(ses, mono())) { ev -> ev.any { it is ClientEvent.Lease } }
    val releasedOp = released.filterIsInstance<ClientEvent.Session>().firstOrNull()?.op
    println("RELEASED $releasedOp")
    expect(!conn.lease(ses, mono())!!.controls, "released")

    // A browser grant (the QR) for the browser's WebCrypto key: prompt + view
    // on ses-a…, one hour at most; a fresh owner confirmation.
    val issued = wall()
    val grant = issueBrowserGrant(log, provider, "dev-phone/auth", "dev-phone", PublicKeyData(KeyAlg.P256, browserKey),
        "host-a", 1uL, ses, listOf("prompt", "view"), issued, issued + 3_000_000uL)
    val grantSig = provider.requests.last()
    expect(grantSig.purpose == SigningPurpose.BROWSER_GRANT && grantSig.freshConfirmation && grantSig.bodyJson != null, "grant signing purpose")
    expect(parseBrowserGrant(grant).ops == listOf("prompt", "view"), "grant ops")
    println("GRANT $grant")

    // Push: the relay socket delivers the host's signed hints.
    val relay = Wire(relayPort)
    relay.send(Json.write(mapOf("device_id" to "dev-phone")).toByteArray())
    println("READY_FOR_PUSH")
    System.out.flush()
    val message = Json.parse(String(relay.recv()))
    expect(message["op"] == "push_hint", "a push_hint message")
    val book = PushHintBook()
    var opened: PushHint? = null
    for (h in message["hints"].arr()) {
        val hint = verifyPushHint(Json.write(h), log, wall(), PushVerifier.CLIENT)
        expect(book.offer(hint) == HintOffer.ACCEPTED, "new hint accepted")
        expect(book.offer(hint) == HintOffer.IDEMPOTENT, "same hint idempotent")
        val state = hint.state()
        if (state is HintStateInfo.Open && state.deviceId == "dev-phone") opened = hint
    }
    val mine = opened ?: fail("no hint for dev-phone")
    val content = mine.open(provider, "dev-phone/enc", "dev-phone")
    println("HINT dev-phone ${content.tool} ${content.summary}")

    // The card was shown in a focused window to an active user: seen.
    val approval = mine.approval()
    val seen = conn.approvalSeen(approval.sessionId, approval.approvalId, mono())
    val reply = exchange(seen) { ev -> ev.any { it is ClientEvent.Seen || it is ClientEvent.Error } }
    expect(reply.any { it is ClientEvent.Seen && it.re == seen.id }, "seen answered")
    println("SEEN ok")

    // A manager's entry carried on the open channel: draft E7 (remove
    // svc-discord), publish it (relay 200), then send it to the host, which
    // answers with its new head.
    val e7Body = log.draftEntry("dev-phone", wall(), Json.write(mapOf("action" to "remove", "device_id" to "svc-discord")))
    val publisher = EntryPublisher()
    publisher.prepare(log, e7Body)
    expect(publisher.preparedJson() != null, "the prepared body is persisted before signing")
    val append = publisher.sign(provider, "dev-phone/auth", null)
    expect(provider.requests.last().purpose == SigningPurpose.REMOVE && provider.requests.last().freshConfirmation, "entry signing purpose")
    expect(publisher.replyStored(log, HostClock(wall(), mono(), "phone-boot")) is PublishOutcome.Committed, "committed")
    val carried = conn.sendMembership(listOf(append.entryJson), mono())
    val heads = exchange(carried) { ev -> ev.any { it is ClientEvent.MembershipHead } }
    val head = (heads.first { it is ClientEvent.MembershipHead } as ClientEvent.MembershipHead).head
    expect(head == log.head() && head.seq == 7uL, "the host's head is the published entry")
    println("MEMBERSHIP ${head.seq}")

    // The phone revokes the browser's grant: the host fences it.
    val grantId = parseBrowserGrant(grant).grantId
    val revoked = exchange(conn.revokeGrant(grantId, mono())) { ev -> ev.any { it is ClientEvent.GrantRevoked || it is ClientEvent.Error } }
    expect(revoked.any { it is ClientEvent.GrantRevoked }, "grant revoked")
    println("REVOKED $grantId")
    conn.disconnect()
    expect(conn.isClosed() && conn.state() == ConnectionState.CLOSED, "closed")
    println("DONE")
}
