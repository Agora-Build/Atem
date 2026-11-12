// The shared r9 vectors (designs/protocol/fixtures/r9-vectors-*.json) and the
// host-work prompt-framing vectors (fixtures/host-work/prompt-framing-v1.json,
// framing-size-v1.json) run through the Kotlin binding (UniFFI + JNA), the
// same checks as the WASM (bindings/js/conformance.mjs) and Swift runs. Usage:
//   java -Djna.library.path=<dir of libatem_client_ffi.so> -cp … \
//     atem.bindings.test.ConformanceKt <fixtures dir>
package atem.bindings.test

import java.io.File
import java.security.MessageDigest
import java.util.Base64
import uniffi.atem_client_ffi.*

private var passed = 0
private val failures = ArrayList<String>()

private fun check(name: String, f: () -> Unit) {
    try {
        f()
        passed++
    } catch (e: Throwable) {
        failures.add("$name: $e ${e.stackTrace.take(2).joinToString(" | ")}")
    }
}

private fun eq(a: Any?, b: Any?, what: String = "") {
    if (a != b) throw AssertionError("$what expected <$b> got <$a>")
}

fun AtemException.codeOf(): String = when (this) {
    is AtemException.Invalid -> code
    is AtemException.Membership -> code
    is AtemException.Channel -> code
    is AtemException.Refused -> code
    is AtemException.Restore -> code
    is AtemException.Publish -> code
    is AtemException.Push -> code
    is AtemException.Stored -> code
    is AtemException.BadWelcome -> "bad_welcome"
    is AtemException.Request -> "request"
    is AtemException.State -> "state"
}

fun AtemException.detailOf(): String? = when (this) {
    is AtemException.Invalid -> detail
    is AtemException.Membership -> detail
    is AtemException.Channel -> detail
    is AtemException.Refused -> detail
    is AtemException.Restore -> detail
    is AtemException.Publish -> detail
    is AtemException.Push -> detail
    is AtemException.Stored -> detail
    is AtemException.BadWelcome -> check
    is AtemException.Request -> detail
    is AtemException.State -> detail
}

private fun throwsCode(code: String, f: () -> Unit) {
    try {
        f()
    } catch (e: AtemException) {
        if (e.codeOf() == code || e.detailOf() == code) return
        throw AssertionError("expected $code, got ${e.codeOf()}/${e.detailOf()}")
    }
    throw AssertionError("expected $code, nothing thrown")
}

private fun b64u(s: String): ByteArray = Base64.getUrlDecoder().decode(s)

private fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)

private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// A tag's 60 bits as written (XXXX-XXXX-XXXX, Crockford base32).
private fun tagBitsOf(tag: String): ULong =
    tag.filter { it != '-' }.fold(0uL) { bits, c ->
        val i = CROCKFORD.indexOf(c)
        require(i >= 0) { "not a tag character: $c" }
        (bits shl 5) or i.toULong()
    }

private fun sha256Hex(text: String): String = hex(MessageDigest.getInstance("SHA-256").digest(utf8(text)))

fun main(args: Array<String>) {
    val dir = File(args[0])
    fun load(name: String) = Json.parse(File(dir, "$name.json").readText())
    val enc = load("r9-vectors-encoding")
    val keys = load("r9-vectors-keys")["keys"]
    val mlog = load("r9-vectors-membership-log")
    val rec = load("r9-vectors-recovery")
    val hs = load("r9-vectors-channel-handshake")
    val grant = load("r9-vectors-browser-grant")
    val push = load("r9-vectors-push-hint")

    val account = mlog["account_id"].s()
    val genesis = mlog["genesis_hash"].s()
    val vectors = mlog["log"].arr() + mlog["others"].arr()
    val byLabel = vectors.associateBy { it["label"].s() }
    fun entry(label: String) = Json.write(byLabel.getValue(label)["entry"])
    val l = mlog["log"].arr().map { Json.write(it["entry"]) }
    val now = HostClock(1793264001000uL, 1000uL, "boot-1")
    fun logL() = MembershipLog.verify(account, genesis, l, now)
    val mlogHead = LogHead(mlog["head"]["seq"].l().toULong(), mlog["head"]["hash"].s())

    // ------------------------------------------------------------ encoding
    check("enc fields") {
        val fields = enc["enc"][0]["fields_utf8"].arr().map { utf8(it.s()) }
        eq(hex(encodeFields(fields)), enc["enc"][0]["hex"])
    }
    check("enc u64") { eq(hex(encodeFields(listOf(unhex("0000000000000006")))), enc["enc"][1]["hex"]) }
    check("jcs") { eq(canonicalJson(enc["jcs"][0]["input"].s()), enc["jcs"][0]["jcs"]) }
    check("jcs refuses duplicates and floats") {
        throwsCode("not_strict_json") { canonicalJson("{\"a\":1,\"a\":2}") }
        throwsCode("not_strict_json") { canonicalJson("{\"a\":1.5}") }
    }
    check("p256 low S only") {
        val p = enc["p256_low_s"]
        val pub = PublicKeyData(KeyAlg.P256, unhex(keys[p["key"].s()]["auth"]["pub_hex"].s()))
        verifyRawSignature(pub, unhex(p["message_hex"].s()), unhex(p["sig_low_s_hex"].s()))
        throwsCode("high_s") { verifyRawSignature(pub, unhex(p["message_hex"].s()), unhex(p["sig_high_s_hex"].s())) }
    }
    check("ed25519 strict") {
        val e = enc["ed25519_strict"]
        val pub = PublicKeyData(KeyAlg.ED25519, unhex(keys[e["key"].s()]["host_key"]["pub_hex"].s()))
        verifyRawSignature(pub, unhex(e["message_hex"].s()), unhex(e["sig_hex"].s()))
        val bad = unhex(e["sig_hex"].s())
        bad[63] = (bad[63].toInt() xor 1).toByte()
        throwsCode("bad_signature") { verifyRawSignature(pub, unhex(e["message_hex"].s()), bad) }
    }

    // ---------------------------------------------------------------- keys
    check("test keys: label derivation and public halves") {
        for (device in listOf("dev-mac", "dev-phone", "dev-ipad", "dev-newmac")) {
            for (part in listOf("auth", "enc")) {
                val k = keys[device][part]
                eq(hashFields(listOf(utf8("atem-r9-test-key"), utf8("$device $part"))), k["secret_hex"], "$device $part label")
                val store = SoftwareKeyStore()
                if (part == "auth") store.insertP256("k", unhex(k["secret_hex"].s())) else store.insertX25519("k", unhex(k["secret_hex"].s()))
                eq(hex(store.publicKeyOf("k").raw), k["pub_hex"], "$device $part public")
                checkPublicKey(PublicKeyData(if (part == "auth") KeyAlg.P256 else KeyAlg.X25519, unhex(k["pub_hex"].s())))
            }
        }
        val store = SoftwareKeyStore()
        store.insertEd25519("h", unhex(keys["host-a"]["host_key"]["secret_hex"].s()))
        eq(hex(store.publicKeyOf("h").raw), keys["host-a"]["host_key"]["pub_hex"])
        store.insertEd25519("s", unhex(keys["svc-discord"]["auth"]["secret_hex"].s()))
        eq(hex(store.publicKeyOf("s").raw), keys["svc-discord"]["auth"]["pub_hex"])
    }
    check("enc_kid") {
        eq(encKid(PublicKeyData(KeyAlg.X25519, unhex(keys["dev-phone"]["enc"]["pub_hex"].s()))), push["open_details"][0]["enc_kid"])
    }

    // ---------------------------------------------------------- membership
    check("log L verifies to its head") { eq(logL().head(), mlogHead) }
    check("every entry: jcs, signing input, entry_hash") {
        for (v in vectors) {
            val label = v["label"].s()
            if (label == "K7_current_no_kit_sig") continue
            // A set out of order: the signed-object parse itself refuses it.
            if (v.obj()["reason"] == "array_not_canonical") {
                throwsCode("array_not_canonical") { signedObjectInfo(Json.write(v["entry"])) }
                continue
            }
            val info = signedObjectInfo(Json.write(v["entry"]))
            v.obj()["jcs"]?.let { eq(info.bodyJcs, it, "$label jcs") }
            v.obj()["signing_input_hex"]?.let { eq(hex(info.signingInput), it, "$label input") }
            eq(info.entryHash, v["entry_hash"], "$label hash")
        }
    }
    check("kit current without kit_sig is refused") {
        throwsCode("kit_sig_missing") { signedObjectInfo(entry("K7_current_no_kit_sig")) }
    }
    check("members and hosts of L") {
        val log = logL()
        val phone = log.member("dev-phone")!!
        eq(phone.kind, "native")
        eq(phone.status, MemberStatusKind.ACTIVE)
        eq(hex(phone.authKey.raw), keys["dev-phone"]["auth"]["pub_hex"])
        eq(hex(phone.encKey!!.raw), keys["dev-phone"]["enc"]["pub_hex"])
        eq(log.member("dev-ipad")!!.status, MemberStatusKind.REMOVED)
        eq(log.member("svc-discord")!!.kind, "service")
        eq(hex(log.host("host-a")!!.hostKey.raw), keys["host-a"]["host_key"]["pub_hex"])
        eq(log.host("host-a")!!.hostTrustGen, 1uL)
    }
    check("E7 extends L; its hedged retry is the same entry") {
        val log = logL()
        val r = log.extend(listOf(entry("E7")), now)
        eq(r.appended, 1uL)
        eq(r.stop, null)
        eq(r.head.hash, byLabel.getValue("E7")["entry_hash"])
        eq(signedObjectInfo(entry("E7_retry")).entryHash, byLabel.getValue("E7")["entry_hash"])
    }
    check("refusals in context") {
        fun stop(labels: List<String>) = logL().evaluate(labels.map(::entry), now).stop
        eq(stop(listOf("E7", "X8_badsig")), CarriageStop.Invalid(1uL, "bad_signature"))
        eq((stop(listOf("C6_mac")) as CarriageStop.Conflict).outcome, "freeze")
        eq((stop(listOf("C6_ipad")) as CarriageStop.Conflict).outcome, "ignored:signer_removed")
        eq(stop(listOf("X7_ipad")) is CarriageStop.Invalid, true)
        eq(stop(listOf("KB7", "KB8_stale")), CarriageStop.Invalid(1uL, "blob_version_not_increasing"))
        eq(stop(listOf("R7_wrong_key")), CarriageStop.Invalid(0uL, "bad_signature"))
    }
    check("a recovery_add waits 24 h on the verifier's clock") {
        val log = logL()
        eq(log.extend(listOf(entry("R7")), now).appended, 1uL)
        val pending = log.pendingRecovery(now)
        eq(pending.size, 1)
        eq(pending[0].entryHash, byLabel.getValue("R7")["entry_hash"])
        eq(pending[0].subject, "dev-newmac")
        eq(pending[0].effectiveAt, now.wallMs + 86400000uL)
        eq(log.member("dev-newmac")!!.status, MemberStatusKind.PENDING)
    }
    check("the log's durable snapshot restores against the app's anchors") {
        val log = logL()
        log.extend(listOf(entry("R7")), now)
        val saved = log.storedJson()
        val later = HostClock(now.wallMs + 3600000uL, now.monoMs + 3600000uL, "boot-1")
        val restored = MembershipLog.fromStored(account, genesis, saved, later)
        eq(restored.head(), log.head())
        eq(restored.pendingRecovery(later)[0].effectiveAt, now.wallMs + 86400000uL, "same boot: from first sight")
        val reboot = HostClock(now.wallMs + 7200000uL, 500uL, "boot-2")
        eq(MembershipLog.fromStored(account, genesis, saved, reboot).pendingRecovery(reboot)[0].effectiveAt, reboot.wallMs + 86400000uL, "another boot: nothing waited was persisted")
        throwsCode("account_mismatch") { MembershipLog.fromStored("acct-other", genesis, saved, now) }
        throwsCode("genesis_mismatch") { MembershipLog.fromStored(account, byLabel.getValue("SUB1")["entry_hash"].s(), saved, now) }
        throwsCode("malformed") { MembershipLog.fromStored(account, genesis, saved.substring(0, saved.length / 2), now) }
        throwsCode("stored_invalid") { MembershipLog.fromStored(account, genesis, saved.replaceFirst("{", "{\"extra\":1,"), now) }
    }
    check("a wait-ended decision survives the snapshot") {
        val log = logL()
        log.extend(listOf(entry("R7")), now)
        val day = HostClock(now.wallMs + 86400000uL, now.monoMs + 86400000uL, "boot-1")
        eq(log.advance(day).isNotEmpty(), true)
        val saved = log.storedJson()
        eq(saved.contains("\"reason\":\"wait_ended\""), true)
        val restored = MembershipLog.fromStored(account, genesis, saved, day)
        eq(restored.member("dev-newmac")!!.status, MemberStatusKind.ACTIVE)
        eq(restored.extend(listOf(entry("N8")), day).appended, 1uL, "N8 relies on the decision")
        throwsCode("unsupported_version") { MembershipLog.fromStored(account, genesis, saved.replace("\"v\":1", "\"v\":2"), day) }
    }
    check("draft + publish reproduces E7 (Kotlin signer through the foreign trait)") {
        val log = logL()
        val e7 = byLabel.getValue("E7")["entry"]["body"]
        val body = log.draftEntry("dev-phone", e7["signed_at"].l().toULong(),
            Json.write(mapOf("action" to "remove", "device_id" to e7["device_id"])))
        eq(body, byLabel.getValue("E7")["jcs"])
        val phone = JdkKeys()
        phone.addP256("dev-phone/auth", unhex(keys["dev-phone"]["auth"]["secret_hex"].s()), unhex(keys["dev-phone"]["auth"]["pub_hex"].s()))
        val p = EntryPublisher()
        p.prepare(log, body)
        check(p.preparedJson() != null)
        val req = p.sign(phone, "dev-phone/auth", null)
        // The JDK's ECDSA nonce is random: same entry_hash, another signature.
        eq(req.entryHash, byLabel.getValue("E7")["entry_hash"])
        eq(req.expected, mlogHead)
        eq(phone.requests.single().purpose, SigningPurpose.REMOVE)
        eq(phone.requests.single().freshConfirmation, true)
        eq(phone.requests.single().bodyJson, body)
        verifySignedObject(req.entryJson, PublicKeyData(KeyAlg.P256, unhex(keys["dev-phone"]["auth"]["pub_hex"].s())))
        // A restart: the saved state resumes (one append per device, so the
        // old object goes first).
        val saved = p.preparedJson()!!
        p.destroy()
        val resumed = EntryPublisher.resume(saved)
        eq(resumed.outstanding()!!.entryHash, req.entryHash)
        eq(resumed.replyStored(log, now), PublishOutcome.Committed(LogHead(7uL, byLabel.getValue("E7")["entry_hash"].s())))
        eq(log.head().seq, 7uL)
        eq(resumed.preparedJson(), null)
        // The software store (bots) reproduces E7's RFC 6979 signature exactly.
        val store = SoftwareKeyStore()
        store.insertP256("dev-phone/auth", unhex(keys["dev-phone"]["auth"]["secret_hex"].s()))
        val p2 = EntryPublisher()
        p2.prepare(logL(), body)
        eq(canonicalJson(p2.sign(store.provider(), "dev-phone/auth", null).entryJson), canonicalJson(entry("E7")))
        p2.destroy()
    }
    check("a draft the verifier would refuse is refused before signing") {
        throwsCode("membership_invalid") { logL().draftEntry("dev-phone", 1uL, "{\"action\":\"remove\"}") }
    }

    check("capacity and the service change guard (D23)") {
        val log = logL()
        eq(log.capacity(), CapacityInfo(6uL, 1024uL, 3uL, 256uL, 1uL, 64uL, CapacityLevelKind.OK, CapacityLevelKind.OK, CapacityLevelKind.OK, CapacityLevelKind.OK))
        val e5 = byLabel.getValue("E5")["entry"]["body"]
        val svc = e5["member"]
        val at = e5["signed_at"].l().toULong()
        val day = 86_400_000L
        fun change(ops: Any?, expiresAt: Long) = Json.write(mapOf(
            "action" to "set_roles", "device_id" to "svc-discord", "roles" to listOf("service"),
            "scope" to svc["scope"].obj() + ("ops" to ops), "expires_at" to expiresAt))
        val renew = change(svc["scope"]["ops"], svc["expires_at"].l() + day)
        eq(log.checkChange(renew, at + 3_600_000uL), ChangeRefusalInfo.ServiceChangeTooSoon(at, at + day.toULong()), "a renewal within 24 h")
        eq(log.checkChange(renew, at + day.toULong()), null, "after 24 h")
        eq(log.checkChange(change(listOf("view"), svc["expires_at"].l()), at + 3_600_000uL), null, "narrowing")
        eq(log.checkChange("{\"action\":\"remove\",\"device_id\":\"svc-discord\"}", at + 3_600_000uL), null, "removal")
        val hostKey = byLabel.getValue("E2")["entry"]["body"]["host"]["host_key"]
        val addHost = Json.write(mapOf("action" to "add_host", "host" to mapOf("host_id" to "host-b", "host_trust_gen" to 1L, "host_key" to hostKey)))
        eq(log.checkChange(addHost, at), null, "a host with room")
        throwsCode("membership_invalid") { log.checkChange("{\"action\":\"remove\"}", at) }
    }

    check("service builders: add, set_roles, renewal, narrowing (§R9.6)") {
        val log = logL()
        val e5 = byLabel.getValue("E5")["entry"]["body"]
        val svc = e5["member"]
        val at = e5["signed_at"].l().toULong()
        val exp = svc["expires_at"].l().toULong()
        val day = 86_400_000uL
        val svcKey = PublicKeyData(KeyAlg.ED25519, unhex(keys["svc-discord"]["auth"]["pub_hex"].s()))
        fun strs(v: Any?) = v.arr().map { it.s() }
        val hosts = strs(svc["scope"]["hosts"])
        val projects = strs(svc["scope"]["projects"])
        val ops = strs(svc["scope"]["ops"])
        // E5's member, rebuilt from its parts in another order: the vector's bytes.
        val shuffled = ServiceScopeInfo(hosts, projects.reversed(), null, listOf("prompt", "interrupt"))
        eq(serviceAddAction("svc-discord", svcKey, shuffled, exp, at), canonicalJson(Json.write(mapOf("action" to "add", "member" to svc))))
        eq(log.serviceGrant("svc-discord"), ServiceGrantInfo(ServiceScopeInfo(hosts, projects, null, ops), exp))
        eq(log.serviceGrant("dev-phone"), null)
        val newSvc = serviceAddAction("svc-new", svcKey, ServiceScopeInfo(listOf("host-a"), null, listOf("ses-bbbbbbbbbbbb", "ses-aaaaaaaaaaaa"), listOf("prompt")), at + 3_600_000uL, at)
        eq(Json.write(Json.parse(newSvc)["member"]["scope"]), "{\"hosts\":[\"host-a\"],\"ops\":[\"prompt\",\"view\"],\"sessions\":[\"ses-aaaaaaaaaaaa\",\"ses-bbbbbbbbbbbb\"]}")
        log.draftEntry("dev-phone", at, newSvc)
        eq(log.checkChange(newSvc, at), null, "an add with room")
        fun change(o: List<String>, e: ULong) = canonicalJson(Json.write(mapOf(
            "action" to "set_roles", "device_id" to "svc-discord", "roles" to listOf("service"),
            "scope" to svc["scope"].obj() + ("ops" to o), "expires_at" to e.toLong())))
        val renew = log.serviceRenewalAction("svc-discord", exp + day, at + day)
        eq(renew, change(ops, exp + day), "renewal")
        eq(log.checkChange(renew, at + 3_600_000uL), ChangeRefusalInfo.ServiceChangeTooSoon(at, at + day), "a renewal is paced")
        val viewOnly = ServiceScopeInfo(hosts, projects, null, listOf("view"))
        val narrow = log.serviceNarrowingAction("svc-discord", viewOnly, null, at + 3_600_000uL)
        eq(narrow, change(listOf("view"), exp), "narrowing")
        eq(log.checkChange(narrow, at + 3_600_000uL), null, "a narrowing isn't paced")
        eq(serviceSetRolesAction("svc-discord", viewOnly, exp, at), narrow)
        throwsCode("not_a_narrowing") { log.serviceNarrowingAction("svc-discord", ServiceScopeInfo(hosts, projects, null, listOf("stop", "view")), null, at) }
        throwsCode("not_a_narrowing") { log.serviceNarrowingAction("svc-discord", ServiceScopeInfo(hosts, projects, null, ops), null, at) }
        throwsCode("not_a_renewal") { log.serviceRenewalAction("svc-discord", exp, at) }
        throwsCode("not_a_service") { log.serviceRenewalAction("dev-phone", exp + day, at) }
        throwsCode("bad_scope") { serviceSetRolesAction("svc-discord", ServiceScopeInfo(listOf(), null, null, listOf("view")), exp, at) }
        throwsCode("bad_scope") { serviceSetRolesAction("svc-discord", ServiceScopeInfo(listOf("host-a"), null, null, listOf("fly")), exp, at) }
        throwsCode("service_expiry") { serviceSetRolesAction("svc-discord", ServiceScopeInfo(listOf("host-a"), null, null, listOf()), at + 90uL * day + 1uL, at) }
        throwsCode("wrong_alg") { serviceAddAction("svc-x", PublicKeyData(KeyAlg.X25519, unhex(keys["dev-phone"]["enc"]["pub_hex"].s())), ServiceScopeInfo(listOf("host-a"), null, null, listOf()), at, at) }
    }
    // r9_svc vectors: atem-client's own file (crates/atem-client/vectors).
    val svcFp = Json.parse(File(dir, "../../../crates/atem-client/vectors/r9-svc-fingerprint.json").readText())
    check("service key fingerprint r9_svc (atem-client vectors)") {
        fun alg(name: String) = when (name) { "p256" -> KeyAlg.P256; "ed25519" -> KeyAlg.ED25519; else -> KeyAlg.X25519 }
        for (c in svcFp["valid"].arr()) {
            eq(hex(b64u(c["auth_key"]["pub"].s())), c["pub_hex"].s(), c["case"].s())
            eq(serviceKeyFingerprint(PublicKeyData(alg(c["auth_key"]["alg"].s()), b64u(c["auth_key"]["pub"].s()))), c["fingerprint"].s(), c["case"].s())
        }
        for (c in svcFp["invalid"].arr()) {
            throwsCode(c["code"].s()) { serviceKeyFingerprint(PublicKeyData(alg(c["auth_key"]["alg"].s()), b64u(c["auth_key"]["pub"].s()))) }
        }
        val discord = svcFp["valid"].arr().first { it["case"].s().contains("svc-discord") }
        eq(logL().serviceKeyFingerprint("svc-discord"), discord["fingerprint"].s())
        eq(logL().serviceKeyFingerprint("dev-phone"), null)
    }
    // The host's own vector (src/memory/account_keys.rs H1_VECTOR): h1. of
    // "github.com/agora/atem" under K = [7; 32], kid 0123abcd.
    val h1Vector = "h1.0123abcd.777eda018c9c9736a84728e10308571167773f209924bf052477a1283cfd7cb6"
    check("project keys and hashes (§R9.6)") {
        eq(projectKeyOfRemote("git@github.com:Agora-Build/Atem.git"), "github.com/agora-build/atem")
        eq(projectKeyOfRemote("https://user:tok@github.com/Agora-Build/Atem.git/"), "github.com/agora-build/atem")
        eq(projectKeyOfRemote("file:///srv/repo.git"), null)
        eq(localProjectKey("Scratch"), "local:Scratch")
        eq(hex(projectHashInput("github.com/agora/atem")), hex(utf8("github.com/agora/atem")))
        eq(projectHash(AccountKey("0123abcd", ByteArray(32) { 7 }), "github.com/agora/atem"), h1Vector)
        val hmac = javax.crypto.Mac.getInstance("HmacSHA256")
        hmac.init(javax.crypto.spec.SecretKeySpec(ByteArray(32) { 7 }, "HmacSHA256"))
        val mac = hmac.doFinal(projectHashInput("github.com/agora/atem"))
        eq(projectHashFromMac("0123abcd", mac), h1Vector)
        throwsCode("malformed") { projectHashFromMac("01.23", mac) }
        throwsCode("malformed") { projectHashFromMac("0123abcd", ByteArray(31)) }
        eq(isProjectHash(byLabel.getValue("E5")["entry"]["body"]["member"]["scope"]["projects"][0].s()), true)
        eq(isProjectHash("h1.0123abcd.zz"), false)
    }

    // ------------------------------- delegated host work: device-list actions
    // The vectors of `others` that follow a `chain` on log L (P*, EK*, HS*): a
    // valid one carries `expect`, the state a verifier derives after it (read
    // here through the log's queries); a refused one `valid: false` and
    // `reason` (`evaluate` stops with it at index 0; a body the signed-object
    // parse refuses, `array_not_canonical`, never reaches the log: `evaluate`
    // throws). The five actions are also rebuilt by their builders, byte for
    // byte, where a builder can write the body, and a manager signs them
    // through the foreign provider under purposes that name them.
    val fiveActions = setOf("project_set", "project_remove", "host_sender_revoke", "host_sender_readmit", "host_enc_key")
    val delegated = mlog["others"].arr().filter { it.obj().containsKey("chain") }
    fun strs(v: Any?) = v.arr().map { it.s() }
    fun logAfter(chain: List<String>): MembershipLog {
        val log = logL()
        eq(log.extend(chain.map(::entry), now).stop, null, "chain $chain")
        return log
    }
    fun hostKeyName(hostId: String, gen: Long) = if (gen == 1L) hostId else "$hostId-gen-$gen"
    fun encKeyOf(k: Any?) = PublicKeyData(KeyAlg.X25519, b64u(k["pub"].s()))
    // A body's key object with the alg it names (a vector may carry another).
    fun keyOf(k: Any?) = PublicKeyData(
        when (val alg = k["alg"].s()) {
            "x25519" -> KeyAlg.X25519
            "ed25519" -> KeyAlg.ED25519
            "p256" -> KeyAlg.P256
            else -> error(alg)
        },
        b64u(k["pub"].s()))
    fun stateOf(log: MembershipLog): Map<String, Any?> {
        val hosts = LinkedHashMap<String, Any?>()
        val senders = LinkedHashMap<String, Any?>()
        val encKeys = LinkedHashMap<String, Any?>()
        fun keyOut(k: HostEncKeyInfo) = linkedMapOf<String, Any?>(
            "enc_kid" to k.encKid,
            "pub" to Base64.getUrlEncoder().withoutPadding().encodeToString(k.key.raw),
            "seq" to k.seq.toLong(),
            "host_trust_gen" to k.hostTrustGen.toLong())
        for (id in listOf("host-a", "host-b")) {
            log.host(id)?.let { hosts[id] = it.hostTrustGen.toLong() }
            val sender = log.hostSenderState(id)
            val epoch = log.hostMembershipEpoch(id)
            if (sender != null) {
                val entry = linkedMapOf<String, Any?>()
                when (sender) {
                    is HostSenderStateInfo.Authorized -> { entry["state"] = "authorized"; entry["seq"] = sender.generation.toLong() }
                    is HostSenderStateInfo.Revoked -> { entry["state"] = "revoked"; entry["seq"] = sender.seq.toLong() }
                }
                if (epoch != null) entry["membership_epoch"] = epoch.toLong()
                senders[id] = entry
            } else {
                eq(epoch, null, "$id epoch without an add_host")
            }
            log.hostEncKey(id)?.let { keys ->
                val entry = linkedMapOf<String, Any?>("current" to keyOut(keys.current))
                keys.previous?.let { p ->
                    entry["previous"] = keyOut(p.key).also { it["retired"] = p.retired; it["replaced_at_seq"] = p.replacedAtSeq.toLong() }
                }
                encKeys[id] = entry
            }
        }
        val projects = LinkedHashMap<String, Any?>()
        for (p in log.projects()) projects[p.name] = mapOf("hosts" to p.hosts, "members" to p.members, "ops" to p.ops)
        return mapOf("hosts" to hosts, "projects" to projects, "host_senders" to senders, "host_enc_keys" to encKeys)
    }
    fun opsBetween(expect: Any?, a: String, b: String): List<String> {
        if (a == b) return listOf()
        val ops = java.util.TreeSet<String>()
        for (p in expect["projects"].obj().values) if (strs(p["members"]).containsAll(listOf(a, b))) ops.addAll(strs(p["ops"]))
        return ops.toList()
    }
    check("device-list actions: the queries read every vector's expect, refusals carry their reason") {
        var valid = 0
        var refused = 0
        for (v in delegated) {
            val label = v["label"].s()
            val log = logAfter(strs(v["chain"]))
            if (v.obj()["valid"] == false) {
                refused++
                if (v["reason"].s() == "array_not_canonical") throwsCode("array_not_canonical") { log.evaluate(listOf(entry(label)), now) }
                else eq(log.evaluate(listOf(entry(label)), now).stop, CarriageStop.Invalid(0uL, v["reason"].s()), label)
                continue
            }
            valid++
            val r = log.extend(listOf(entry(label)), now)
            eq(r.stop, null, label)
            eq(r.appended, 1uL, label)
            eq(r.head.hash, v["entry_hash"], label)
            eq(stateOf(log), v["expect"].obj(), label)
            for ((a, b) in listOf("host-a" to "host-b", "host-b" to "host-a", "host-a" to "host-a")) {
                eq(log.projectOpsBetween(a, b), opsBetween(v["expect"], a, b), "$label $a $b")
            }
            for (id in listOf("host-a", "host-b")) {
                val inEffect = v["expect"]["projects"].obj().filter { strs(it.value["members"]).contains(id) }.keys.sorted()
                eq(log.hostProjects(id), inEffect, "$label $id")
            }
        }
        check(valid >= 34 && refused >= 35) { "$valid valid, $refused refused" }
    }
    fun buildAction(body: Any?): String {
        val at = body["signed_at"].l().toULong()
        return when (val action = body["action"].s()) {
            "project_set" -> projectSetAction(body["project"]["name"].s(), strs(body["project"]["hosts"]), strs(body["project"]["ops"]), at)
            "project_remove" -> projectRemoveAction(body["name"].s(), at)
            "host_sender_revoke" -> hostSenderRevokeAction(body["host_id"].s(), body["interrupt_running"] as Boolean, at)
            "host_sender_readmit" -> hostSenderReadmitAction(body["host_id"].s(), at)
            "host_enc_key" -> hostEncKeyAction(body["host_id"].s(), body["host_trust_gen"].l().toULong(), keyOf(body["enc_key"]), body["enc_sig"].s(), body["retire_previous"] == true, at)
            else -> error(action)
        }
    }
    // A body no builder writes: another signer's entry (a builder's action is
    // drafted for the signer that asks), or a shape outside the builders'
    // inputs (`retire_previous: false`, a revoke without `interrupt_running`,
    // a field the action doesn't have, a set out of order).
    fun unbuildable(v: Any?): Boolean {
        val body = v["entry"]["body"]
        return body["signer"] != "dev-mac" ||
            body["retire_previous"] == false ||
            (body["action"] == "host_sender_revoke" && body["interrupt_running"] !is Boolean) ||
            v.obj()["reason"] in setOf<Any?>("unknown_field", "array_not_canonical")
    }
    check("device-list actions: the builders reproduce the vectors; check_change advises on a redundant revoke or readmit and a reused key") {
        var built = 0
        for (v in delegated.filter { fiveActions.contains(it["entry"]["body"]["action"].s()) }) {
            val label = v["label"].s()
            val body = v["entry"]["body"]
            if (unbuildable(v)) continue
            // A shape the verifier refuses by itself is the builder's refusal too.
            val reason = v.obj()["reason"]
            if (reason in setOf<Any?>("bad_project", "malformed", "wrong_alg")) {
                throwsCode(reason as String) { buildAction(body) }
                continue
            }
            val log = logAfter(strs(v["chain"]))
            val action = buildAction(body)
            built++
            val signedAt = body["signed_at"].l().toULong()
            eq(log.draftEntry("dev-mac", signedAt, action), v["jcs"], label)
            val want = when (reason) {
                "already_revoked" -> ChangeRefusalInfo.AlreadyRevoked
                "not_revoked" -> ChangeRefusalInfo.NotRevoked
                "enc_key_reused" -> ChangeRefusalInfo.EncKeyReused
                else -> null
            }
            eq(log.checkChange(action, signedAt), want, "$label check_change")
        }
        check(built >= 38) { "$built built" }
    }
    check("device-list actions: shapes the verifier refuses by itself") {
        val two = listOf("host-a", "host-b")
        throwsCode("bad_project") { projectSetAction("astation", two, listOf("deploy"), 1uL) }
        throwsCode("bad_project") { projectSetAction("astation", two, listOf(), 1uL) }
        throwsCode("bad_project") { projectSetAction("astation", listOf("host-a"), listOf("message"), 1uL) }
        throwsCode("bad_project") { projectSetAction("Astation", two, listOf("message"), 1uL) }
        throwsCode("bad_project") { projectSetAction("astation", two, listOf("notify", "prompt"), 1uL) }
        throwsCode("bad_project") { projectRemoveAction("Bad Name", 1uL) }
        throwsCode("malformed") { hostSenderRevokeAction("Not an id", false, 1uL) }
        throwsCode("malformed") { hostSenderReadmitAction("", 1uL) }
        val ek = byLabel.getValue("EK7_set")["entry"]["body"]
        val hostA = PublicKeyData(KeyAlg.ED25519, unhex(keys["host-a"]["host_key"]["pub_hex"].s()))
        throwsCode("wrong_alg") { hostEncKeyAction("host-a", 1uL, hostA, ek["enc_sig"].s(), false, 1uL) }
        throwsCode("malformed") { hostEncKeyAction("host-a", 1uL, encKeyOf(ek["enc_key"]), "AAAA", false, 1uL) }
        throwsCode("malformed") { hostEncKeyAction("host-a", 1uL, encKeyOf(ek["enc_key"]), ek["enc_sig"].s() + "=", false, 1uL) }
    }
    check("device-list actions: verifyHostEncSig binds every field of a host's enc_sig") {
        val ek = byLabel.getValue("EK7_set")["entry"]["body"]
        val sig = ek["enc_sig"].s()
        fun hostKey(name: String) = PublicKeyData(KeyAlg.ED25519, unhex(keys[name]["host_key"]["pub_hex"].s()))
        val key = encKeyOf(ek["enc_key"])
        fun verify(host: PublicKeyData, account: String, genesisHash: String, hostId: String, gen: ULong, enc: PublicKeyData, signature: String) =
            verifyHostEncSig(host, account, genesisHash, hostId, gen, enc, signature)
        eq(verify(hostKey("host-a"), account, genesis, "host-a", 1uL, key, sig), true)
        eq(verify(hostKey("host-b"), account, genesis, "host-a", 1uL, key, sig), false, "another host's key")
        eq(verify(hostKey("host-a"), "acct-other", genesis, "host-a", 1uL, key, sig), false, "account")
        eq(verify(hostKey("host-a"), account, "00".repeat(32), "host-a", 1uL, key, sig), false, "genesis")
        eq(verify(hostKey("host-a"), account, genesis, "host-b", 1uL, key, sig), false, "host id")
        eq(verify(hostKey("host-a"), account, genesis, "host-a", 2uL, key, sig), false, "generation")
        eq(verify(hostKey("host-a"), account, genesis, "host-a", 1uL, encKeyOf(byLabel.getValue("EK8_rotate")["entry"]["body"]["enc_key"]), sig), false, "key")
        val p256 = PublicKeyData(KeyAlg.P256, unhex(keys["dev-mac"]["auth"]["pub_hex"].s()))
        eq(verify(p256, account, genesis, "host-a", 1uL, key, sig), false, "a P-256 host key")
        eq(verify(hostKey("host-a"), account, genesis, "host-a", 1uL, PublicKeyData(KeyAlg.ED25519, key.raw), sig), false, "an Ed25519 enc_key")
        eq(verify(hostKey("host-a"), account, "not hex", "host-a", 1uL, key, sig), false, "a malformed genesis")
        eq(verify(hostKey("host-a"), account, genesis, "host-a", 1uL, key, "AAAA"), false, "a short signature")
        // Every enc_sig of the vectors whose binding fields parse (they carry
        // enc_sig_input_hex) verifies under the host key of its generation, but the bad one.
        for (v in delegated.filter { it.obj().containsKey("enc_sig_input_hex") }) {
            val b = v["entry"]["body"]
            val gen = b["host_trust_gen"].l()
            eq(verify(hostKey(hostKeyName(b["host_id"].s(), gen)), account, genesis, b["host_id"].s(), gen.toULong(), encKeyOf(b["enc_key"]), b["enc_sig"].s()),
                v.obj()["reason"] != "bad_enc_sig", v["label"].s())
        }
    }
    check("device-list actions: a manager signs each under a purpose that names it (R9.6 rule 4)") {
        val mac = JdkKeys()
        mac.addP256("dev-mac/auth", unhex(keys["dev-mac"]["auth"]["secret_hex"].s()), unhex(keys["dev-mac"]["auth"]["pub_hex"].s()))
        // L plus host-b (P7_add_host_b), so a project can list two hosts.
        val log = logAfter(listOf("P7_add_host_b"))
        val ek = byLabel.getValue("EK7_set")["entry"]["body"]
        val at = 1_793_620_800_000uL
        val steps = listOf(
            Triple(projectSetAction("astation", listOf("host-b", "host-a"), listOf("prompt", "message"), at + 8000uL), SigningPurpose.PROJECT, "project_set"),
            Triple(hostSenderRevokeAction("host-b", true, at + 9000uL), SigningPurpose.HOST_SENDER, "host_sender_revoke"),
            Triple(hostSenderReadmitAction("host-b", at + 10000uL), SigningPurpose.HOST_SENDER, "host_sender_readmit"),
            Triple(hostEncKeyAction("host-a", 1uL, encKeyOf(ek["enc_key"]), ek["enc_sig"].s(), false, at + 11000uL), SigningPurpose.HOST_ENC_KEY, "host_enc_key"),
            Triple(projectRemoveAction("astation", at + 12000uL), SigningPurpose.PROJECT, "project_remove"))
        for ((action, purpose, name) in steps) {
            eq(log.checkChange(action, at), null, name)
            val body = log.draftEntry("dev-mac", at, action)
            val p = EntryPublisher()
            p.prepare(log, body)
            p.sign(mac, "dev-mac/auth", null)
            val sent = mac.requests.last()
            eq(sent.purpose, purpose, name)
            eq(sent.freshConfirmation, true, "$name: a fresh confirmation")
            eq(sent.bodyJson, body, "$name: the confirmed body")
            eq(sent.label, "atem-membership-entry-v1", name)
            eq(p.replyStored(log, now) is PublishOutcome.Committed, true, name)
            p.destroy()
        }
        eq(log.head().seq, 12uL)
        eq(log.projects().isEmpty(), true)
        eq(log.hostSenderState("host-b"), HostSenderStateInfo.Authorized(10uL))
        val keysOf = log.hostEncKey("host-a")!!
        eq(keysOf.current.encKid, encKid(encKeyOf(ek["enc_key"])))
        eq(keysOf.previous, null)
    }

    // ---------------------------- delegated host work: control records
    // r9-vectors-host-work-control: every record parses and verifies on each
    // of its chains as `checks` says (or its parse refuses it,
    // `parse_error`); the builders reproduce it byte for byte (a software
    // store, or the signing input and a signature); every sequence runs
    // through a ControlStateHandle with each step's per-effect results and
    // the state it leaves (a handle never changes, so a failed commit loses
    // no effect); and a provider is asked under the purpose the record's
    // signer gives.
    val ctl = load("r9-vectors-host-work-control")
    val ctlRecords = ctl["records"].arr()
    val ctlByLabel = ctlRecords.associateBy { it["label"].s() }
    val controlFields = setOf("type", "v", "account_id", "genesis_hash", "origin", "feed_id", "principal", "principal_key",
        "signer", "action", "interrupt_running", "revoke_seq", "record_id", "issued_at", "about")
    // The typed body of a record's body JSON (null: a field the body doesn't have).
    fun controlBodyOf(b: Any?): ControlRecordBody? {
        val o = b.obj()
        if (!controlFields.containsAll(o.keys)) return null
        return ControlRecordBody(
            accountId = o["account_id"].s(),
            genesisHash = o["genesis_hash"].s(),
            origin = o["origin"] as String?,
            feedId = o["feed_id"] as String?,
            principal = o["principal"].s(),
            principalKey = o["principal_key"] as String?,
            signer = o["signer"].s(),
            action = o["action"].s(),
            interruptRunning = o["interrupt_running"] as Boolean?,
            revokeSeq = (o["revoke_seq"] as Long?)?.toULong(),
            recordId = o["record_id"].s(),
            issuedAt = o["issued_at"].l().toULong(),
            integrationId = o["about"].obj()["integration_id"] as String?,
            by = o["about"]["by"].s())
    }
    // A test key by name: a member's auth key, or a host's host_key.
    fun testKeyOf(name: String): Triple<KeyAlg, ByteArray, ByteArray> {
        val k = keys[name].obj()["auth"] ?: keys[name]["host_key"]
        val alg = if (k["alg"].s() == "p256") KeyAlg.P256 else KeyAlg.ED25519
        return Triple(alg, unhex(k["pub_hex"].s()), unhex(k["secret_hex"].s()))
    }
    fun verdictOf(chain: Any?, got: ControlCheckInfo): Map<String, Any?> = when (got) {
        is ControlCheckInfo.Valid -> linkedMapOf<String, Any?>("chain" to chain, "verdict" to "valid", "signer" to got.signer)
            .also { v -> got.keySeq?.let { v["key_seq"] = it.toLong() } }
        is ControlCheckInfo.Pending -> mapOf("chain" to chain, "verdict" to "pending", "reason" to got.reason)
        is ControlCheckInfo.Refused -> mapOf("chain" to chain, "verdict" to "refused", "reason" to got.reason)
    }
    check("control records: every record parses and verifies on its chains as the vectors say") {
        var verdicts = 0
        val svc = ctl["services"]["svc-discord"]["auth_key"]
        for (r in ctlRecords) {
            val label = r["label"].s()
            val json = Json.write(r["record"])
            val parseError = r.obj()["parse_error"]
            if (parseError != null) {
                throwsCode(parseError.s()) { parseControlRecord(json) }
                throwsCode(parseError.s()) { verifyControlRecord(logL(), json) }
                continue
            }
            eq(parseControlRecord(json), controlBodyOf(r["record"]["body"]), "$label body")
            val info = signedObjectInfo(json)
            eq(info.bodyJcs, r["jcs"], label)
            eq(hex(info.signingInput), r["signing_input_hex"], label)
            eq(hex(signingInput(SignLabelKind.HOST_WORK_CONTROL, utf8(r["jcs"].s()))), r["signing_input_hex"], label)
            if (r.obj().containsKey("r9_svc")) {
                eq(serviceKeyFingerprint(PublicKeyData(KeyAlg.ED25519, b64u(svc["pub"].s()))), r["r9_svc"], label)
                eq(r["record"]["body"]["principal_key"] == r["r9_svc"], r["checks"][0]["reason"] != "key_mismatch", "$label principal_key")
            }
            for (c in r["checks"].arr()) {
                val log = logAfter(strs(c["chain"]))
                val got = verifyControlRecord(log, json)
                eq(verdictOf(c["chain"], got), c.obj(), "$label on ${c["chain"]}")
                if (got is ControlCheckInfo.Valid) eq(got.head, log.head(), label)
                verdicts++
            }
        }
        check(verdicts >= 52) { "$verdicts verdicts" }
    }
    check("control records: the builders reproduce every record; a body the parse refuses is refused") {
        var built = 0
        for (r in ctlRecords) {
            val label = r["label"].s()
            val body = controlBodyOf(r["record"]["body"])
            if (body == null) {
                eq(r["parse_error"], "unknown_field", label)
                continue
            }
            val (alg, pub, secret) = testKeyOf(r["signed_with"].s())
            val store = SoftwareKeyStore()
            if (alg == KeyAlg.P256) store.insertP256("k", secret) else store.insertEd25519("k", secret)
            val parseError = r.obj()["parse_error"]
            if (parseError != null) {
                throwsCode(parseError.s()) { buildControlRecord(store.provider(), "k", body) }
                throwsCode(parseError.s()) { controlRecordSigningInput(body) }
                continue
            }
            eq(hex(controlRecordSigningInput(body)), r["signing_input_hex"], label)
            val sig = b64u(r["record"]["sig"].s())
            if (r["checks"][0]["reason"] == "bad_signature") {
                throwsCode("bad_signature") { controlRecordWithSignature(body, PublicKeyData(alg, pub), sig) }
                continue
            }
            val canonical = canonicalJson(Json.write(r["record"]))
            eq(controlRecordWithSignature(body, PublicKeyData(alg, pub), sig), canonical, label)
            eq(buildControlRecord(store.provider(), "k", body), canonical, label)
            built++
        }
        check(built >= 44) { "$built built" }
    }
    fun controlActionOf(a: ControlHostAction): Map<String, Any?> = when (a) {
        is ControlHostAction.Revoke -> mapOf("type" to "revoke", "principal" to a.principal)
        is ControlHostAction.Hold -> mapOf("type" to "hold", "principal" to a.principal)
        is ControlHostAction.Release -> mapOf("type" to "release", "principal" to a.principal)
        is ControlHostAction.Interrupt -> mapOf("type" to "interrupt", "principal" to a.principal, "revocation" to a.revocation)
        is ControlHostAction.Cover -> mapOf("type" to "cover", "principal" to a.principal, "origin" to a.origin, "feed_id" to a.feedId)
    }
    fun controlAppliedOf(a: ControlApplied): Map<String, Any?> = mapOf(
        "result" to a.result.name.lowercase(),
        "effects" to a.effects.map { mapOf("effect" to it.effect.name.lowercase(), "result" to it.result.name.lowercase()) },
        "actions" to a.actions.map(::controlActionOf),
        "evidence" to a.evidence)
    fun ctlPos(p: Any?): ControlFeedPos? =
        p?.let { ControlFeedPos(it["origin"].s(), it["feed_id"].s(), it["feed_seq"].l().toULong()) }
    check("control records: every sequence's per-effect results and its state through ControlStateHandle") {
        for (q in ctl["sequences"].arr()) {
            val label = q["label"].s()
            var state = ControlStateHandle(logL())
            q["steps"].arr().forEachIndexed { i, step ->
                val record = Json.write(ctlByLabel.getValue(step["record"].s())["record"])
                val t = state.apply(record, logAfter(strs(step["chain"])), ctlPos(step.obj()["pos"]), step["host_applied_seq"].l().toULong())
                eq(controlAppliedOf(t.applied), step["expect"].obj(), "$label step ${i + 1}")
                state = t.next
            }
            val text = canonicalJson(Json.write(q["state"]))
            eq(state.toJson(), text, label)
            eq(ControlStateHandle.fromJson(logL(), text).toJson(), text, label)
        }
        // Only its own device list's state, exactly as written.
        val text = canonicalJson(Json.write(ctl["sequences"][0]["state"]))
        throwsCode("account_mismatch") { ControlStateHandle.fromJson(logL(), text.replace("\"acct-test-1\"", "\"acct-other\"")) }
        throwsCode("unsupported_version") { ControlStateHandle.fromJson(logL(), text.replace("\"v\":1", "\"v\":2")) }
        throwsCode("malformed") { ControlStateHandle.fromJson(logL(), "[") }
    }
    check("control records: a failed commit loses no effect (apply leaves its handle as it was)") {
        val state = ControlStateHandle(logL())
        val before = state.toJson()
        val record = Json.write(ctlByLabel.getValue("S5_revoke_interrupt")["record"])
        val a = ctl["stations"]["A"]
        val pos = ControlFeedPos(a["origin"].s(), a["feed_id"].s(), 1uL)
        val first = state.apply(record, logL(), pos, 6uL)
        eq(first.applied.actions.size, 2)
        // The caller's transaction failed: apply again to the handle it kept.
        eq(state.toJson(), before)
        val again = state.apply(record, logL(), pos, 6uL)
        eq(again.applied, first.applied, "the same results and actions")
        eq(again.next.toJson(), first.next.toJson())
        // Committed: the next state goes on, and the record is a duplicate.
        eq(again.next.apply(record, logL(), pos, 6uL).applied.result, ControlResultKind.DUPLICATE)
    }
    check("control records: a Station's service key signs with no confirmation, a native manager's asks a fresh one") {
        val station = JdkKeys()
        val svc = keys["svc-discord"]["auth"]
        station.addEd25519("svc-discord/auth", unhex(svc["secret_hex"].s()), unhex(svc["pub_hex"].s()))
        val mac = keys["dev-mac"]["auth"]
        station.addP256("dev-mac/auth", unhex(mac["secret_hex"].s()), unhex(mac["pub_hex"].s()))
        for ((label, keyId, purpose) in listOf(
            Triple("S1_cover", "svc-discord/auth", SigningPurpose.SERVICE_CONTROL),
            Triple("S4_revoke", "svc-discord/auth", SigningPurpose.SERVICE_CONTROL),
            Triple("M1_revoke", "dev-mac/auth", SigningPurpose.CONTROL_RECORD),
            Triple("H1_interrupt_7", "dev-mac/auth", SigningPurpose.CONTROL_RECORD))) {
            val r = ctlByLabel.getValue(label)
            val made = buildControlRecord(station, keyId, controlBodyOf(r["record"]["body"])!!)
            val sent = station.requests.last()
            eq(sent.purpose, purpose, label)
            eq(sent.freshConfirmation, purpose == SigningPurpose.CONTROL_RECORD, label)
            eq(sent.bodyJson, r["jcs"], label)
            eq(sent.label, "atem-host-work-control-v1", label)
            // The JDK's P-256 signatures are randomized: the record verifies as the vector's.
            val last = r["checks"].arr().last()
            eq(verdictOf(last["chain"], verifyControlRecord(logAfter(strs(last["chain"])), made)), last.obj(), label)
        }
    }

    // ------------------------------- delegated host work: the Station's side
    // r9-control-ack-*: every acknowledgment fixture through AckLedgerHandle
    // as a Station persists it (each call's next state committed before the
    // reports go, adopted after; restarts reload the committed state;
    // replicas serialized); a call never changes its handle; the relay
    // builders and readers agree; the Portal's statuses in their classes.
    fun canon(v: Any?) = canonicalJson(Json.write(v))
    fun intentOf(i: ReportIntentInfo): Map<String, Any?> = mapOf(
        "not_before" to i.notBefore,
        "report" to when (val r = i.report) {
            is StationReport.RevocationApplied -> mapOf("kind" to "revocation_applied", "integration_id" to r.integrationId,
                "host" to r.host, "record_id" to r.recordId)
            is StationReport.Revoked -> mapOf("kind" to "revoked", "integration_id" to r.integrationId,
                "outcome" to r.outcome, "pending_hosts" to r.pendingHosts)
        },
        "report_id" to i.reportId)
    fun alertOf(a: LedgerAlertInfo): Map<String, Any?> = when (a) {
        is LedgerAlertInfo.ReportRefused -> mapOf("kind" to "report_refused", "report_id" to a.reportId)
        is LedgerAlertInfo.ReportingStopped -> mapOf("kind" to "reporting_stopped", "client_id" to a.clientId)
        is LedgerAlertInfo.ReportsDropped -> mapOf("kind" to "reports_dropped", "client_id" to a.clientId, "dropped" to a.dropped)
    }
    fun answerOf(a: ReportAnswerKind) = when (a) {
        ReportAnswerKind.CONFIRM -> "confirm"
        ReportAnswerKind.RETRY -> "retry"
        ReportAnswerKind.REFUSE -> "refuse"
        ReportAnswerKind.STOP_REPORTING -> "stop_reporting"
    }
    fun linkOf(l: Any?) = LinkAssociationInfo(l["account_id"].s(), l["genesis_hash"].s(), l["host_id"].s(),
        l["host_trust_gen"].l().toULong(), l["connection_id"].s())
    fun ctlRecord(label: String) = Json.write(ctlByLabel.getValue(label)["record"])
    val ackNames = dir.list()!!.filter { it.startsWith("r9-control-ack-") && it.endsWith(".json") }
        .map { it.removeSuffix(".json") }.sorted()
    for (name in ackNames) check("Station acks: $name through AckLedgerHandle") {
        eq(ackNames.size, 5, "the acknowledgment fixtures")
        val f = load(name)
        val setup = f["setup"]
        val st = setup["station"]
        var ledger = AckLedgerHandle(st["origin"].s(), st["account_id"].s(), st["genesis_hash"].s())
        var committed = ledger.toJson()
        var now = setup["station_now_ms"].l().toULong()
        var clientId = setup.obj()["report_client_id"] as String?
        fun input(on: AckLedgerHandle, step: Any?): AckTransition? {
            val o = step.obj()
            return when {
                "control_record" in o -> on.record(ctlRecord(o["control_record"].s()),
                    o["revoked_at_ms"]?.l()?.toULong() ?: now, strs(o["covered_hosts"]), now)
                "control_ack" in o -> {
                    val link = linkOf(setup["links"][o["link"].s()])
                    val ack = Json.write(o["control_ack"])
                    if ("refused" in o) {
                        throwsCode(o["refused"].s()) { on.ack(link, ack, now) }
                        null
                    } else on.ack(link, ack, now)
                }
                "tick" in o -> on.tick(now)
                else -> throw AssertionError("not an input: ${Json.write(step)}")
            }
        }
        fun made(t: AckTransition, step: Any?) {
            eq(t.made.map { it.reportId }, strs(step["made"]), "$name made")
            eq(t.alerts, emptyList<LedgerAlertInfo>(), "$name alerts")
        }
        fun commit(t: AckTransition) {
            committed = t.next.toJson()
            ledger = t.next
        }
        fun sendable(id: String) {
            if (ledger.pendingReports().none { it.reportId == id }) throw AssertionError("$id is not sendable")
        }
        for (step in f["steps"].arr()) {
            val o = step.obj()
            when {
                "control_record" in o || "control_ack" in o || "tick" in o -> {
                    val t = input(ledger, step)
                    if (t != null) {
                        made(t, step)
                        if (o["commit"] != false) commit(t)
                    }
                }
                "replica" in o -> {
                    val inner = o["replica"]
                    val t1 = input(AckLedgerHandle.fromJson(committed), inner)!!
                    val t2 = input(AckLedgerHandle.fromJson(committed), inner)!!
                    eq(t1.next.toJson(), t2.next.toJson(), "$name replicas' states")
                    eq(t1.made, t2.made, "$name replicas' intents")
                    made(t1, inner)
                    commit(t1)
                    eq(input(AckLedgerHandle.fromJson(committed), inner)!!.made, emptyList<ReportIntentInfo>(), "$name the replica that lost")
                }
                "advance_ms" in o -> now += o["advance_ms"].l().toULong()
                "restart" in o -> {
                    ledger = AckLedgerHandle.fromJson(committed)
                    eq(ledger.toJson(), committed, "$name restart")
                }
                "expect_report" in o -> eq(canon(ledger.pendingReports().map(::intentOf)), canon(o["expect_report"]), "$name reports")
                "confirm" in o -> {
                    sendable(o["confirm"].s())
                    commit(ledger.confirm(o["confirm"].s()))
                }
                "report_failure" in o -> {
                    val fl = o["report_failure"]
                    val id = fl["report_id"].s()
                    sendable(id)
                    val status = fl["status"]
                    val answer = if (status is Long) answerOf(reportAnswer(status.toInt().toUShort())) else "retry"
                    eq(answer, fl["answer"], "$name answer")
                    val t = when (answer) {
                        "refuse" -> ledger.refuse(id)
                        "stop_reporting" -> ledger.stopReporting(clientId!!)
                        else -> null
                    }
                    eq(canon(t?.alerts?.map(::alertOf) ?: emptyList<Any?>()), canon(fl.obj()["alerts"] ?: emptyList<Any?>()), "$name alerts")
                    if (t != null) commit(t)
                }
                "expect_resign_alerts" in o -> eq(ledger.resignAlerts(),
                    strs(o["expect_resign_alerts"]).map { ctlByLabel.getValue(it)["record"]["body"]["record_id"].s() }.sorted(), "$name resign alerts")
                "expect_refused" in o -> eq(ledger.refusedReports(), strs(o["expect_refused"]), "$name refused")
                "expect_dropped" in o -> eq(ledger.droppedReports(), strs(o["expect_dropped"]), "$name dropped")
                "resume_reporting" in o -> {
                    clientId = o["resume_reporting"].s()
                    val t = ledger.resumeReporting(clientId!!)
                    eq(canon(t.alerts.map(::alertOf)), canon(o["alerts"]), "$name resume alerts")
                    eq(t.made, emptyList<ReportIntentInfo>(), "$name resume")
                    commit(t)
                }
                "expect_stopped" in o -> {
                    eq(ledger.stoppedClientId() ?: false, o["expect_stopped"], "$name stopped")
                    eq(ledger.reportingStopped(), o["expect_stopped"] != false, "$name stopped")
                }
                "expect_portal" in o -> {} // the Portal's side: no Portal model here
                else -> throw AssertionError("unknown step ${Json.write(step)}")
            }
        }
    }
    check("Station acks: a call never changes its handle; the state loads only as written") {
        val f = load("r9-control-ack-per-effect")
        val st = f["setup"]["station"]
        val linkB = linkOf(f["setup"]["links"]["host-b"])
        val nowMs = 1793620940000uL
        val l = AckLedgerHandle(st["origin"].s(), st["account_id"].s(), st["genesis_hash"].s())
            .record(ctlRecord("S4_revoke"), 1793620903000uL, listOf("host-b", "host-c"), nowMs).next
        val before = l.toJson()
        val ack = Json.write(f["steps"][6]["control_ack"])
        val t1 = l.ack(linkB, ack, nowMs)
        val t2 = l.ack(linkB, ack, nowMs)
        // The commit failed: the handle is as it was, and the same call again gives the same.
        eq(l.toJson(), before)
        eq(t1.next.toJson(), t2.next.toJson())
        eq(t1.made, t2.made)
        eq(t1.made.size, 1)
        val id = t1.made[0].reportId
        eq(t1.next.refuse(id).alerts, listOf(LedgerAlertInfo.ReportRefused(id)))
        eq(t1.next.pendingReports().size, 1)
        val stopped = t1.next.stopReporting("station-1").next
        eq(stopped.reportingStopped(), true)
        eq(stopped.stoppedClientId(), "station-1")
        eq(stopped.pendingReports(), emptyList<ReportIntentInfo>())
        eq(t1.next.reportingStopped(), false)
        // The same report client ID keeps every report; another drops them.
        eq(stopped.resumeReporting("station-1").next.pendingReports(), t1.next.pendingReports())
        val other = stopped.resumeReporting("station-2")
        eq(other.alerts, listOf(LedgerAlertInfo.ReportsDropped("station-1", listOf(id))))
        eq(other.next.droppedReports(), listOf(id))
        eq(other.next.droppedClientIds(), listOf("station-1"))
        throwsCode("malformed") { l.stopReporting("a b") }
        val text = t1.next.toJson()
        eq(AckLedgerHandle.fromJson(text).toJson(), text)
        throwsCode("malformed") { AckLedgerHandle.fromJson("[") }
        throwsCode("unsupported_version") { AckLedgerHandle.fromJson(text.replace("\"v\":1", "\"v\":2")) }
        throwsCode("stored_invalid") { AckLedgerHandle.fromJson(text.replaceFirst("{", "{\"extra\":1,")) }
        throwsCode("malformed") { AckLedgerHandle("https://Station-dev.agora.build/", st["account_id"].s(), st["genesis_hash"].s()) }
        throwsCode("incomplete_link") { l.ack(linkB.copy(connectionId = ""), ack, nowMs) }
        throwsCode("not_the_link") { l.ack(linkB, ack.replace("host-b", "host-c"), nowMs) }
        throwsCode("unknown_field") { l.record(ctlRecord("P4_unknown_field"), 0uL, emptyList(), nowMs) }
    }
    check("Station calls: fixture acks read and write back; pages, heads and fetches round-trip; builders refuse what readers refuse") {
        for (name in ackNames) for (step in load(name)["steps"].arr()) {
            val inner = step.obj()["replica"] ?: step
            val msg = inner.obj()["control_ack"] ?: continue
            val read = relayDecodeToStation(Json.write(msg)) as RelayToStation.ControlAck
            eq(canonicalJson(relayControlAck(read.ack)), canon(msg), name)
        }
        val a = ctl["stations"]["A"]
        val origin = a["origin"].s()
        val feed = a["feed_id"].s()
        eq(relayDecodeToStation(relayControlSync(origin, feed, 7uL)), RelayToStation.ControlSync(origin, feed, 7uL))
        eq(relayDecodeToStation(relayControlSync(origin, null, 0uL)), RelayToStation.ControlSync(origin, null, 0uL))
        throwsCode("malformed") { relayControlSync(origin, null, 5uL) }
        val page = listOf("S1_cover", "S4_revoke", "M1_revoke").mapIndexed { i, label -> RelayFeedRecord((i + 1).toULong(), ctlRecord(label)) }
        val read = relayDecodeToHost(relayControlSyncResult(origin, feed, 3uL, 1793620940000uL, page)) as RelayToHost.ControlSyncResult
        eq(read.records.map { canonicalJson(it.recordJson) }, page.map { canonicalJson(it.recordJson) })
        val refusedPage = page.mapIndexed { i, r -> if (i == 1) RelayFeedRecord(r.feedSeq, ctlRecord("P4_unknown_field")) else r }
        throwsCode("unknown_field") { relayControlSyncResult(origin, feed, 3uL, 0uL, refusedPage) }
        throwsCode("malformed") { relayControlSyncResult(origin, feed, 2uL, 0uL, page) }
        throwsCode("malformed") { relayControlSyncResult(origin, feed, 3uL, 0uL, listOf(page[1], page[0])) }
        val heads = listOf(RelayFeedHead(origin, feed, 3uL, 1793620940000uL))
        val hm = relayHeads(heads, mlogHead)
        eq(relayDecodeToHost(hm), RelayToHost.Heads(heads, mlogHead))
        val withMailbox = Json.parse(hm).obj() + ("mailbox" to mapOf("mailbox_id" to feed, "head" to 1L))
        throwsCode("unknown_field") { relayDecodeToHost(Json.write(withMailbox)) }
        eq(relayDecodeToStation(relayMembershipFetch(2uL)), RelayToStation.MembershipFetch(2uL))
        val entries = listOf("E3", "E4", "E5", "E6").map(::entry)
        val fetched = relayDecodeToHost(relayMembershipFetchResult(mlogHead, entries)) as RelayToHost.MembershipFetchResult
        eq(fetched.head, mlogHead)
        eq(fetched.entries.map(::canonicalJson), entries.map(::canonicalJson))
        throwsCode("wrong_message") { relayDecodeToHost(relayControlSync(origin, null, 0uL)) }
        throwsCode("wrong_message") { relayDecodeToStation("{\"type\":\"relay\",\"op\":\"push_hint\",\"hints\":[]}") }
        throwsCode("not_strict") { relayDecodeToStation("{") }
    }
    check("Station calls: the three refusals exactly and read strictly; a stale-association ack refused without disclosure or ledger advance") {
        val refusals: List<Triple<(RelayRefusalCode) -> String, String, RelayToHost>> = listOf(
            Triple({ c -> relayControlSyncRefused(c) }, "control_sync_refused", RelayToHost.ControlSyncRefused(RelayRefusalCode.FORBIDDEN)),
            Triple({ c -> relayMembershipFetchRefused(c) }, "membership_fetch_refused", RelayToHost.MembershipFetchRefused(RelayRefusalCode.FORBIDDEN)),
            Triple({ c -> relayControlAckRefused(c) }, "control_ack_refused", RelayToHost.ControlAckRefused(RelayRefusalCode.FORBIDDEN)))
        for ((build, op, want) in refusals) {
            val msg = build(RelayRefusalCode.FORBIDDEN)
            eq(canonicalJson(msg), canon(mapOf("type" to "relay", "op" to op, "code" to "forbidden")), op)
            eq(relayDecodeToHost(msg), want, op)
            throwsCode("wrong_message") { relayDecodeToStation(msg) }
            for ((fields, code) in listOf("\"code\":\"not_found\"" to "malformed", "\"code\":null" to "malformed",
                "\"code\":\"forbidden\",\"feed_id\":\"x\"" to "unknown_field",
                "\"code\":\"forbidden\",\"code\":\"forbidden\"" to "not_strict")) {
                throwsCode(code) { relayDecodeToHost("{\"type\":\"relay\",\"op\":\"$op\",$fields}") }
            }
        }
        // A stale association: the link was verified at trust generation 2, the ack claims 1.
        val f = load("r9-control-ack-deadline")
        val st = f["setup"]["station"]
        val nowMs = 1793620940000uL
        val l = AckLedgerHandle(st["origin"].s(), st["account_id"].s(), st["genesis_hash"].s())
            .record(ctlRecord("S4_revoke"), 1793620903000uL, listOf("host-b"), nowMs).next
        val before = l.toJson()
        val ack = Json.write(f["steps"][1]["control_ack"])
        val link = linkOf(f["setup"]["links"]["host-b"]).copy(hostTrustGen = 2uL)
        throwsCode("not_the_link") { l.ack(link, ack, nowMs) }
        eq(l.toJson(), before)
        eq(l.pendingReports(), emptyList<ReportIntentInfo>())
        val reply = relayControlAckRefused(RelayRefusalCode.FORBIDDEN)
        for (secret in listOf(st["account_id"].s(), st["genesis_hash"].s(), st["origin"].s(), "host-b",
            ctlByLabel.getValue("S4_revoke")["record"]["body"]["record_id"].s())) {
            if (reply.contains(secret)) throw AssertionError("the refusal names $secret")
        }
        eq(l.ack(link.copy(hostTrustGen = 1uL), ack, nowMs).made.size, 2)
    }
    check("Station: the Portal's statuses in their classes") {
        for ((status, want) in listOf(200 to "confirm", 401 to "retry", 408 to "retry", 429 to "retry", 500 to "retry", 503 to "retry",
            400 to "refuse", 404 to "refuse", 409 to "refuse", 413 to "refuse", 415 to "refuse", 204 to "refuse",
            302 to "refuse", 403 to "stop_reporting")) {
            eq(answerOf(reportAnswer(status.toUShort())), want, "$status")
        }
    }

    // ------------------------------------------------------------ recovery
    fun kit1() = RecoveryKitHandle.read(unhex(rec["R_hex"].s()), rec["kit"]["account_id"].s(), rec["kit"]["genesis_hash"].s(), unhex(rec["kit"]["kit_tag_hex"].s()))
    check("kit 1: tag, recovery key, X25519 key") {
        val kit = kit1()
        eq(hex(kit.kitTag()), rec["kit"]["kit_tag_hex"])
        eq(hex(kit.recoveryKey().raw), hex(b64u(rec["recovery_key"]["pub"].s())))
        eq(hex(kit.x25519Public()), rec["recovery_key_x25519_pub_hex"])
        eq(hex(ed25519PublicToX25519(PublicKeyData(KeyAlg.ED25519, b64u(rec["recovery_key"]["pub"].s())))), rec["recovery_key_x25519_pub_hex"])
        eq(hashFields(listOf(utf8("atem-r9-test-key"), utf8("recovery kit R"))), rec["R_hex"])
    }
    check("a mistyped kit is refused") {
        val tag = unhex(rec["kit"]["kit_tag_hex"].s())
        tag[0] = (tag[0].toInt() xor 1).toByte()
        throwsCode("kit_tag_mismatch") { RecoveryKitHandle.read(unhex(rec["R_hex"].s()), rec["kit"]["account_id"].s(), rec["kit"]["genesis_hash"].s(), tag) }
    }
    check("K backups: hash, open with kit 1, refused by kit 2") {
        val kb = rec["k_backup"]
        eq(parseKBackup(Json.write(kb["wire"])).backupHash, kb["backup_hash"])
        val out = openKBackup(Json.write(kb["wire"]), kit1())
        val plain = Json.parse(kb["plain_jcs"].s())["keys"].arr()
        eq(out.map { it.kid }, plain.map { it["kid"] })
        eq(out.map { hex(it.k) }, plain.map { hex(b64u(it["k"].s())) })
        val k2 = rec["kit_2"]
        val kit2 = RecoveryKitHandle.read(unhex(k2["R_hex"].s()), k2["kit"]["account_id"].s(), k2["kit"]["genesis_hash"].s(), unhex(k2["kit"]["kit_tag_hex"].s()))
        throwsCode("backup_invalid") { openKBackup(Json.write(kb["wire"]), kit2) }
        openKBackup(Json.write(k2["k_backup_resealed"]["wire"]), kit2)
        eq(parseKBackup(Json.write(rec["k_backup_bad_ct"]["wire"])).backupHash, rec["k_backup_bad_ct"]["backup_hash"])
        throwsCode("backup_invalid") { openKBackup(Json.write(rec["k_backup_bad_ct"]["wire"]), kit1()) }
    }
    check("recovery entry hash") { eq(signedObjectInfo(Json.write(rec["recovery_entry"]["entry"])).entryHash, rec["recovery_entry_hash"]) }
    fun restore() = RestoreSession.read(unhex(rec["R_hex"].s()), rec["kit"]["account_id"].s(), rec["kit"]["genesis_hash"].s(), unhex(rec["kit"]["kit_tag_hex"].s()))
    check("restore: a substitute chain is refused by the kit's anchor") {
        val s = restore()
        throwsCode("genesis_mismatch") {
            s.attempt(rec["substitute_chain"]["entries"].arr().map { entry(it.s()) }, Json.write(rec["substitute_chain"]["backup"]["wire"]), emptyList(), now)
        }
        eq(s.kStored(), false)
    }
    check("restore: no host reachable withholds; a host head confirms") {
        val s = restore()
        val entries = l + entry("KB7")
        throwsCode("no_host_reachable") { s.attempt(entries, Json.write(rec["k_backup"]["wire"]), emptyList(), now) }
        eq(s.waitingForHosts(), listOf("host-a"))
        val r = s.attempt(entries, Json.write(rec["k_backup"]["wire"]), listOf(HostAcceptPair(Json.write(hs["init"]), Json.write(hs["accept"]))), now)
        eq(r.head.seq, 7uL)
        eq(r.keys.map { it.kid }, listOf("b982533d", "1f2e3d4c"))
        eq(s.kStored(), true)
        eq(s.mayRotateK("dev-newmac"), false)
    }

    // ------------------------------------------------------------- channel
    check("accept: th2 and sig_h") {
        eq(hostAcceptTh2(Json.write(hs["init"]), Json.write(hs["accept"])), hs["th2_hex"])
        eq(hex(signingInput(SignLabelKind.CHANNEL_HOST, unhex(hs["th2_hex"].s()))), hs["sig_h_input_hex"])
        verifySignature(PublicKeyData(KeyAlg.ED25519, unhex(hs["inputs"]["host_key_pub_hex"].s())), SignLabelKind.CHANNEL_HOST, unhex(hs["th2_hex"].s()), unhex(hs["sig_h_hex"].s()))
        eq(verifyHostAccept(Json.write(hs["init"]), Json.write(hs["accept"]), logL()), LogHead(hs["inputs"]["head"]["seq"].l().toULong(), hs["inputs"]["head"]["hash"].s()))
    }
    check("a rewritten head fails sig_h") {
        val neg = hs["negative"].arr().first { it["case"] == "tampered_head" }
        val accept = LinkedHashMap(hs["accept"].obj())
        accept["head"] = neg["head"]
        eq(hostAcceptTh2(Json.write(hs["init"]), Json.write(accept)), neg["th2_hex"])
        throwsCode("handshake_failed") { verifyHostAccept(Json.write(hs["init"]), Json.write(accept), logL()) }
    }
    check("sig_c over th3") {
        eq(hex(signingInput(SignLabelKind.CHANNEL_CLIENT, unhex(hs["th3_hex"].s()))), hs["sig_c_input_hex"])
        val pub = PublicKeyData(KeyAlg.P256, unhex(hs["inputs"]["client_auth_pub_hex"].s()))
        verifySignature(pub, SignLabelKind.CHANNEL_CLIENT, unhex(hs["th3_hex"].s()), unhex(hs["sig_c_hex"].s()))
        val bad = unhex(hs["th3_hex"].s())
        bad[0] = (bad[0].toInt() xor 1).toByte()
        throwsCode("bad_signature") { verifySignature(pub, SignLabelKind.CHANNEL_CLIENT, bad, unhex(hs["sig_c_hex"].s())) }
    }

    // ------------------------------------------------------- browser grant
    check("browser grant: hash, issuer signature, sig_c") {
        val g = Json.write(grant["grant"])
        val info = parseBrowserGrant(g)
        eq(info.grantHash, grant["grant_hash_hex"])
        eq(info.issuer, "dev-phone")
        eq(info.ops, listOf("view"))
        eq(info.sessionId, "ses-aaaaaaaaaaaa")
        eq(hex(signedObjectInfo(g).signingInput), grant["signing_input_hex"])
        verifySignedObject(g, PublicKeyData(KeyAlg.P256, unhex(keys["dev-phone"]["auth"]["pub_hex"].s())))
        throwsCode("bad_signature") { verifySignedObject(g, PublicKeyData(KeyAlg.P256, unhex(keys["dev-mac"]["auth"]["pub_hex"].s()))) }
        verifySignature(PublicKeyData(KeyAlg.P256, unhex(keys["browser"]["pub_hex"].s())), SignLabelKind.CHANNEL_CLIENT, unhex(grant["th3_hex"].s()), unhex(grant["sig_c_hex"].s()))
    }

    // ---------------------------------------------------------------- push
    val nowP = push["verifier_now"].l().toULong()
    check("open hints verify and open for their device only (Kotlin HPKE through the foreign trait)") {
        push["open"].arr().forEachIndexed { i, h ->
            val d = push["open_details"][i]
            val hint = verifyPushHint(Json.write(h), logL(), nowP, PushVerifier.CLIENT)
            eq(hint.state(), HintStateInfo.Open(d["device_id"].s(), d["enc_kid"].s(), d["sealed_hash"].s()))
            eq(hex(signedObjectInfo(Json.write(h)).signingInput), d["signing_input_hex"])
            val device = d["device_id"].s()
            val keysJdk = JdkKeys()
            keysJdk.addX25519("enc", unhex(push["recipient_secrets"][device].s()), unhex(keys[device]["enc"]["pub_hex"].s()))
            val plain = Json.parse(d["plain_jcs"].s())
            eq(hint.open(keysJdk, "enc", device), HintContent(plain["tool"].s(), plain["summary"].s()))
            val other = if (device == "dev-phone") "dev-mac" else "dev-phone"
            throwsCode("malformed") { hint.open(keysJdk, "enc", other) }
        }
    }
    check("resolved and seen") {
        val r = verifyPushHint(Json.write(push["resolved"]), logL(), nowP, PushVerifier.CLIENT)
        eq(r.state(), HintStateInfo.Resolved("answered_remote", push["resolved"]["body"]["resolved_at"].l().toULong()))
        val seen = verifySeen(Json.write(push["seen"]), logL())
        eq(seen.deviceId, "dev-phone")
        eq(seen.seenAt, push["seen"]["body"]["seen_at"].l().toULong())
        eq(hex(signedObjectInfo(Json.write(push["seen"])).signingInput), push["seen_signing_input_hex"])
        eq(seenInWindow(Json.write(push["seen"]), logL(), push["open"][0]["body"]["created_at"].l().toULong()), true)
    }
    check("invalid hints are refused for their reason") {
        for (verifier in listOf(PushVerifier.CLIENT, PushVerifier.RELAY)) {
            throwsCode("skew") { verifyPushHint(Json.write(push["invalid"][0]["hint"]), logL(), nowP, verifier) }
            throwsCode("invalid_times") { verifyPushHint(Json.write(push["invalid"][1]["hint"]), logL(), nowP, verifier) }
            throwsCode("invalid_times") { verifyPushHint(Json.write(push["invalid"][2]["hint"]), logL(), nowP, verifier) }
        }
        val book = PushHintBook()
        eq(book.offer(verifyPushHint(Json.write(push["open"][0]), logL(), nowP, PushVerifier.CLIENT)), HintOffer.ACCEPTED)
        eq(book.offer(verifyPushHint(Json.write(push["open"][0]), logL(), nowP, PushVerifier.CLIENT)), HintOffer.IDEMPOTENT)
        throwsCode("duplicate") { book.offer(verifyPushHint(Json.write(push["invalid"][3]["hint"]), logL(), nowP, PushVerifier.CLIENT)) }
    }
    check("a resolved dominates its opens in either order") {
        val book = PushHintBook()
        eq(book.offer(verifyPushHint(Json.write(push["resolved"]), logL(), nowP, PushVerifier.CLIENT)), HintOffer.ACCEPTED)
        eq(book.offer(verifyPushHint(Json.write(push["open"][0]), logL(), nowP, PushVerifier.CLIENT)), HintOffer.IGNORED_AFTER_RESOLVED)
        eq(book.isResolved(verifyPushHint(Json.write(push["open"][1]), logL(), nowP, PushVerifier.CLIENT).approval()), true)
    }
    check("tampered created_at fails the signature") {
        val h = Json.parse(Json.write(push["open"][0])).obj().toMutableMap()
        val body = LinkedHashMap(h["body"].obj())
        body["created_at"] = body["created_at"].l() + 1
        h["body"] = body
        throwsCode("bad_signature") { verifyPushHint(Json.write(h), logL(), nowP, PushVerifier.CLIENT) }
    }
    check("acks round trip") {
        val hint = verifyPushHint(Json.write(push["open"][0]), logL(), nowP, PushVerifier.CLIENT)
        eq(parsePushAck(pushAckMessage(listOf(hint.ackJson()))), listOf(hint.ackJson()))
    }
    check("schedule from the signed created_at, and the 15 s guard") {
        for ((vec, sent) in listOf(push["open_g75"] to false, push["open_g75001"] to true)) {
            val hint = verifyPushHint(Json.write(vec), logL(), vec["body"]["created_at"].l().toULong(), PushVerifier.CLIENT)
            val mobile = PushRecipient(DeviceKind.MOBILE, false, false)
            val stages = pushStages(hint.createdAt(), mobile)
            eq(stages, listOf(PushStageDue(PushStage.MOBILE, hint.createdAt() + 60000uL, true)))
            eq(pushSendNow(PushStage.MOBILE, stages[0].due, stages[0].due, hint.expiresAt(), false, false), sent)
            eq(pushGuard(hint.expiresAt()), hint.expiresAt() - 15000uL)
        }
        val created = push["open"][0]["body"]["created_at"].l().toULong()
        val expires = push["open"][0]["body"]["expires_at"].l().toULong()
        val desktop = PushRecipient(DeviceKind.DESKTOP, false, false)
        eq(pushStages(created, desktop), listOf(PushStageDue(PushStage.DESKTOP_OS, created, true)))
        eq(pushSendNow(PushStage.MOBILE, created + 60000uL, created + 60000uL, expires, false, true), false)
        eq(pushNextDue(created, expires, desktop, listOf(PushStage.DESKTOP_OS), created), null)
    }

    val pairing = load("r9-vectors-pairing")
    check("verifyCommit host_trust_gen (r9-vectors-pairing)") {
        for (c in pairing["verify_commit"]["valid"].arr()) {
            eq(verifyCommitHostTrustGen(c["raw"].s()), c["host_trust_gen"].l().toULong(), c["case"].s())
        }
        for (c in pairing["verify_commit"]["invalid"].arr()) {
            try {
                verifyCommitHostTrustGen(c["raw"].s())
                throw AssertionError("${c["case"].s()} was accepted")
            } catch (e: AtemException.Invalid) {
            }
        }
    }

    // ------------------------------------------------------------- framing
    // The prompt framing (delegated host-work design III.2) over
    // designs/protocol/fixtures/host-work/: the escaping and the marker
    // check, the Unicode version they are pinned to, the preflight size check
    // and (a test-vectors build only) the rendering, byte for byte.
    fun loadWork(name: String) = Json.parse(File(File(dir, "host-work"), "$name.json").readText())
    val framing = loadWork("prompt-framing-v1")
    val framingSize = loadWork("framing-size-v1")
    fun snapshot(kind: String, id: String, version: Long, text: String): Map<String, Any?> =
        linkedMapOf("kind" to kind, "id" to id, "version" to version, "digest" to sha256Hex(text), "text" to text)
    // framingCheckedLen of a text, an optional mark (a host-work MarkTask
    // object) and snapshots (host-work ContextSnapshot objects): the complete
    // inputs.
    fun checkedLen(text: String, mark: Any?, context: List<Any?>): Long =
        framingCheckedLen(text, mark?.let { Json.write(it) }, Json.write(context)).toLong()

    check("framing: Unicode version, escape cases, marker check (III.2)") {
        eq(framingUnicodeVersion(), framing["unicode_version"].s(), "Unicode version")
        eq(framing["unicode_version"].s(), "18.0.0")
        val cases = framing["escape"].arr()
        eq(cases.size, 57)
        for (c in cases) {
            val name = c["name"].s()
            val r = framingEscape(c["text"].s())
            eq(r.escaped, c["escaped"].s(), name)
            eq(r.barsAdded.toLong(), c["bars_added"].l(), name)
            // The marker check on each line (after the bars it already starts
            // with) agrees with where the escaping put its bars.
            val folding = c["text"].s()
                .split('\n', '\r', '\u000B', '\u000C', '\u0085', '\u2028', '\u2029')
                .count { framingFoldsToMarker(it.trimStart('|')) }
            eq(folding.toLong(), c["bars_added"].l(), "$name: lines that fold")
        }
        for (line in listOf("[atem]", "  [ATEM x", "[\u0410\u0422\u0415\u041c]", "[a\ufe0ftem]")) eq(framingFoldsToMarker(line), true, line)
        for (line in listOf("", "x[atem]", "[ atem]", "|[atem]", "[atom]")) eq(framingFoldsToMarker(line), false, line)
    }
    check("framing: rendered prompts byte for byte, tags from their bits (vectors only)") {
        val tag = framing["tag"].s()
        val bits = tagBitsOf(tag)
        val prompts = framing["prompts"].arr()
        eq(prompts.size, 9)
        for (p in prompts) {
            val name = p["name"].s()
            val rendered = framingRenderForVectors(Json.write(p["input"]), bits)
            eq(rendered, p["rendered"].s(), name)
            eq(utf8(rendered).size.toLong(), p["bytes"].l(), "$name: bytes")
        }
        // Every tag of the vectors renders the prompt with that tag, on Atem's
        // own lines only (the sender's text is not touched, even where it
        // holds the vectors' tag).
        val first = prompts[0]
        val old = "[atem $tag] "
        for (t in framing["tags"].arr()) {
            val fresh = "[atem ${t["tag"].s()}] "
            val expected = first["rendered"].s().split('\n').joinToString("\n") { line ->
                if (line.startsWith(old)) fresh + line.removePrefix(old) else line
            }
            eq(framingRenderForVectors(Json.write(first["input"]), t["bits"].s().toULong(16)), expected, t["bits"].s())
        }
        // What the core refuses, and what is no input, is refused: a snapshot
        // whose text doesn't match its digest is never rendered.
        val input = prompts[2]["input"].obj()
        framingRenderForVectors(Json.write(input), 1uL)
        val firstContext = LinkedHashMap(input["context"].arr()[0].obj())
        firstContext["text"] = "not what the digest says"
        val tampered = LinkedHashMap(input)
        tampered["context"] = listOf(firstContext)
        throwsCode("malformed") { framingRenderForVectors(Json.write(tampered), 1uL) }
        val headless = LinkedHashMap(input)
        headless.remove("header")
        throwsCode("malformed") { framingRenderForVectors(Json.write(headless), 1uL) }
    }
    check("framing: the size section (typical, worst, worst with a mark, at the bound)") {
        val size = framing["size"]
        fun vault(id: String, version: Long, n: Int) = snapshot("vault", id, version, "c".repeat(n))
        // A typical task: 5,120 bytes of context, a 1,024-byte prompt.
        eq(checkedLen("t".repeat(1024), null, listOf(vault("api-contract", 3L, 5120))) - 1024 - 5120, size["typical"]["checked_atem_bytes"].l(), "typical")
        // The worst: eight 1,000-byte contexts with 128-byte ids and 16-digit
        // versions, a 1,000-byte prompt.
        val worst = (0 until 8).map { i -> snapshot("memory", "$i" + "m".repeat(127), 9007199254740991L, "c".repeat(1000)) }
        val text = "t".repeat(1000)
        eq(checkedLen(text, null, worst) - 1000 - 8 * 1000, size["worst"]["checked_atem_bytes"].l(), "worst")
        // The same with a mark (the vectors' own, with a 128-byte mark id).
        val withMark = framing["prompts"].arr().first { it["input"].obj().containsKey("mark") }
        val mark = LinkedHashMap(withMark["input"]["mark"].obj())
        mark["mark_id"] = "k".repeat(128)
        eq(checkedLen(text, mark, worst), size["worst_mark"]["checked_bytes"].l(), "worst with a mark")
        // At the bound: one byte more is over it.
        val n = size["at_bound"]["context_bytes"].l().toInt()
        fun at(k: Int) = checkedLen("x", null, listOf(snapshot("vault", "c", 1L, "y".repeat(k))))
        val bound = framingSize["max_prompt_bytes"].l()
        eq(at(n), size["at_bound"]["checked_len"].l(), "at the bound")
        eq(at(n), bound, "exactly the bound")
        eq(at(n + 1), bound + 1, "one byte over")
    }
    check("framing: every framing-size-v1 case with its complete inputs") {
        eq(framingSize["max_prompt_bytes"].l(), 32768L)
        eq(framingSize["attachment_reserve"].l(), 4096L)
        val cases = framingSize["cases"].arr()
        if (cases.size < 10) throw AssertionError("only ${cases.size} cases")
        for (c in cases) eq(checkedLen(c["text"].s(), c["mark"], c["context"].arr()), c["checked_len"].l(), c["name"].s())
        // What the preflight takes is exactly the host-work shapes: anything
        // else is refused, never read loosely.
        val okContext = Json.write(listOf(snapshot("vault", "a", 1L, "x")))
        framingCheckedLen("t", null, "[]")
        framingCheckedLen("t", null, okContext)
        val dup = okContext.replace("\"id\":\"a\"", "\"id\":\"a\",\"id\":\"b\"")
        val float = okContext.replace("\"version\":1", "\"version\":1.5")
        if (dup == okContext || float == okContext) throw AssertionError("the refusal inputs changed nothing")
        throwsCode("not_strict_json") { framingCheckedLen("t", null, "[") }
        throwsCode("not_strict_json") { framingCheckedLen("t", null, dup) }
        throwsCode("not_strict_json") { framingCheckedLen("t", null, float) }
        for (context in listOf(
            "{}",
            "null",
            """[{"kind":"vault","id":"a","version":1,"digest":"d"}]""",
            """[{"kind":"notes","id":"a","version":1,"digest":"d","text":"x"}]""",
        )) {
            throwsCode("malformed") { framingCheckedLen("t", null, context) }
        }
        for (mark in listOf("null", "{}", "[]", """{"mark_id":"m"}""")) {
            throwsCode("malformed") { framingCheckedLen("t", mark, "[]") }
        }
    }

    println("kotlin conformance: $passed passed, ${failures.size} failed")
    failures.forEach { println("FAIL $it") }
    kotlin.system.exitProcess(if (failures.isEmpty()) 0 else 1)
}
