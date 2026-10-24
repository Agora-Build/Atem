// The shared r9 vectors (designs/protocol/fixtures/r9-vectors-*.json) run
// through the Kotlin binding (UniFFI + JNA), the same checks as the WASM
// (bindings/js/conformance.mjs) and Swift runs. Usage:
//   java -Djna.library.path=<dir of libatem_client_ffi.so> -cp … \
//     atem.bindings.test.ConformanceKt <fixtures dir>
package atem.bindings.test

import java.io.File
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

    println("kotlin conformance: $passed passed, ${failures.size} failed")
    failures.forEach { println("FAIL $it") }
    kotlin.system.exitProcess(if (failures.isEmpty()) 0 else 1)
}
