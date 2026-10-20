// The shared r9 vectors (designs/protocol/fixtures/r9-vectors-*.json) run
// through the Swift binding, the same checks as the Kotlin
// (bindings/kotlin/Conformance.kt) and WASM (bindings/js/conformance.mjs)
// runs. ATEM_FIXTURES names the fixtures directory.
import Foundation
import XCTest
@testable import AtemClient

private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

private func unhex(_ s: String) -> Data {
    var out = Data(capacity: s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}

private func b64u(_ s: String) -> Data {
    var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    return Data(base64Encoded: t)!
}

private func utf8(_ s: String) -> Data { Data(s.utf8) }

private func o(_ v: Any?) -> [String: Any] { v as! [String: Any] }
private func a(_ v: Any?) -> [Any] { v as! [Any] }
private func s(_ v: Any?) -> String { v as! String }
private func u(_ v: Any?) -> UInt64 { (v as! NSNumber).uint64Value }
private func js(_ v: Any) -> String {
    String(data: try! JSONSerialization.data(withJSONObject: v, options: [.fragmentsAllowed]), encoding: .utf8)!
}

private struct Failure: Error, CustomStringConvertible {
    let description: String
}

private func eq<T: Equatable>(_ a: T, _ b: T, _ what: String = "") throws {
    if a != b { throw Failure(description: "\(what) expected <\(b)> got <\(a)>") }
}

func codeOf(_ e: AtemError) -> (String, String?) {
    switch e {
    case let .Invalid(code, detail): return (code, detail)
    case let .Membership(code, detail, _): return (code, detail)
    case let .Channel(code, detail): return (code, detail)
    case let .Refused(code, detail, _, _): return (code, detail)
    case let .BadWelcome(check): return ("bad_welcome", check)
    case let .Request(detail): return ("request", detail)
    case let .Restore(code, detail): return (code, detail)
    case let .Publish(code, detail): return (code, detail)
    case let .Push(code, detail): return (code, detail)
    case let .State(detail): return ("state", detail)
    }
}

private func throwsCode(_ code: String, _ f: () throws -> Void) throws {
    do {
        try f()
    } catch let e as AtemError {
        let (c, d) = codeOf(e)
        if c == code || d == code { return }
        throw Failure(description: "expected \(code), got \(c)/\(d ?? "")")
    }
    throw Failure(description: "expected \(code), nothing thrown")
}

final class ConformanceTests: XCTestCase {
    private var passed = 0
    private var failures: [String] = []

    private func check(_ name: String, _ f: () throws -> Void) {
        do {
            try f()
            passed += 1
        } catch {
            failures.append("\(name): \(error)")
        }
    }

    func testSharedVectors() throws {
        let dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["ATEM_FIXTURES"]
            ?? "../../../designs/protocol/fixtures")
        func load(_ name: String) throws -> [String: Any] {
            o(try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent("\(name).json"))))
        }
        let enc = try load("r9-vectors-encoding")
        let keys = o(try load("r9-vectors-keys")["keys"])
        let mlog = try load("r9-vectors-membership-log")
        let rec = try load("r9-vectors-recovery")
        let hs = try load("r9-vectors-channel-handshake")
        let grant = try load("r9-vectors-browser-grant")
        let push = try load("r9-vectors-push-hint")
        func key(_ name: String, _ part: String) -> [String: Any] { o(o(keys[name])[part]) }

        let account = s(mlog["account_id"])
        let genesis = s(mlog["genesis_hash"])
        let vectors = a(mlog["log"]).map(o) + a(mlog["others"]).map(o)
        var byLabel: [String: [String: Any]] = [:]
        for v in vectors { byLabel[s(v["label"])] = v }
        func entry(_ label: String) -> String { js(byLabel[label]!["entry"]!) }
        let l = a(mlog["log"]).map { js(o($0)["entry"]!) }
        let now = HostClock(wallMs: 1_793_264_001_000, monoMs: 1000, bootId: "boot-1")
        func logL() throws -> MembershipLog { try MembershipLog.verify(accountId: account, genesisHash: genesis, entries: l, now: now) }
        let mhead = o(mlog["head"])
        let mlogHead = LogHead(seq: u(mhead["seq"]), hash: s(mhead["hash"]))
        func hash(_ label: String) -> String { s(byLabel[label]!["entry_hash"]) }

        // ------------------------------------------------------------ encoding
        let enc0 = o(a(enc["enc"])[0])
        check("enc fields") { try eq(hex(encodeFields(fields: a(enc0["fields_utf8"]).map { utf8(s($0)) })), s(enc0["hex"])) }
        check("enc u64") { try eq(hex(encodeFields(fields: [unhex("0000000000000006")])), s(o(a(enc["enc"])[1])["hex"])) }
        let jcs0 = o(a(enc["jcs"])[0])
        check("jcs") { try eq(try canonicalJson(json: s(jcs0["input"])), s(jcs0["jcs"])) }
        check("jcs refuses duplicates and floats") {
            try throwsCode("not_strict_json") { _ = try canonicalJson(json: "{\"a\":1,\"a\":2}") }
            try throwsCode("not_strict_json") { _ = try canonicalJson(json: "{\"a\":1.5}") }
        }
        check("p256 low S only") {
            let p = o(enc["p256_low_s"])
            let pub = PublicKeyData(alg: .p256, raw: unhex(s(key(s(p["key"]), "auth")["pub_hex"])))
            try verifyRawSignature(key: pub, message: unhex(s(p["message_hex"])), signature: unhex(s(p["sig_low_s_hex"])))
            try throwsCode("high_s") { try verifyRawSignature(key: pub, message: unhex(s(p["message_hex"])), signature: unhex(s(p["sig_high_s_hex"]))) }
        }
        check("ed25519 strict") {
            let e = o(enc["ed25519_strict"])
            let pub = PublicKeyData(alg: .ed25519, raw: unhex(s(key(s(e["key"]), "host_key")["pub_hex"])))
            try verifyRawSignature(key: pub, message: unhex(s(e["message_hex"])), signature: unhex(s(e["sig_hex"])))
            var bad = unhex(s(e["sig_hex"]))
            bad[63] ^= 1
            try throwsCode("bad_signature") { try verifyRawSignature(key: pub, message: unhex(s(e["message_hex"])), signature: bad) }
        }

        // ---------------------------------------------------------------- keys
        check("test keys: label derivation and public halves") {
            for device in ["dev-mac", "dev-phone", "dev-ipad", "dev-newmac"] {
                for part in ["auth", "enc"] {
                    let k = key(device, part)
                    try eq(hashFields(fields: [utf8("atem-r9-test-key"), utf8("\(device) \(part)")]), s(k["secret_hex"]), "\(device) \(part) label")
                    let store = SoftwareKeyStore()
                    if part == "auth" { try store.insertP256(keyId: "k", secret: unhex(s(k["secret_hex"]))) } else { try store.insertX25519(keyId: "k", secret: unhex(s(k["secret_hex"]))) }
                    try eq(hex(try store.publicKeyOf(keyId: "k").raw), s(k["pub_hex"]), "\(device) \(part) public")
                    try checkPublicKey(key: PublicKeyData(alg: part == "auth" ? .p256 : .x25519, raw: unhex(s(k["pub_hex"]))))
                }
            }
            let store = SoftwareKeyStore()
            try store.insertEd25519(keyId: "h", seed: unhex(s(key("host-a", "host_key")["secret_hex"])))
            try eq(hex(try store.publicKeyOf(keyId: "h").raw), s(key("host-a", "host_key")["pub_hex"]))
            try store.insertEd25519(keyId: "s", seed: unhex(s(key("svc-discord", "auth")["secret_hex"])))
            try eq(hex(try store.publicKeyOf(keyId: "s").raw), s(key("svc-discord", "auth")["pub_hex"]))
        }
        let openDetails = a(push["open_details"]).map(o)
        check("enc_kid") { try eq(try encKid(encKey: PublicKeyData(alg: .x25519, raw: unhex(s(key("dev-phone", "enc")["pub_hex"])))), s(openDetails[0]["enc_kid"])) }

        // ---------------------------------------------------------- membership
        check("log L verifies to its head") { try eq(try logL().head(), mlogHead) }
        check("every entry: jcs, signing input, entry_hash") {
            for v in vectors {
                let label = s(v["label"])
                if label == "K7_current_no_kit_sig" { continue }
                let info = try signedObjectInfo(json: js(v["entry"]!))
                if let j = v["jcs"] { try eq(info.bodyJcs, s(j), "\(label) jcs") }
                if let i = v["signing_input_hex"] { try eq(hex(info.signingInput), s(i), "\(label) input") }
                try eq(info.entryHash, s(v["entry_hash"]), "\(label) hash")
            }
        }
        check("kit current without kit_sig is refused") { try throwsCode("kit_sig_missing") { _ = try signedObjectInfo(json: entry("K7_current_no_kit_sig")) } }
        check("members and hosts of L") {
            let log = try logL()
            let phone = log.member(deviceId: "dev-phone")!
            try eq(phone.kind, "native")
            try eq(phone.status, .active)
            try eq(hex(phone.authKey.raw), s(key("dev-phone", "auth")["pub_hex"]))
            try eq(hex(phone.encKey!.raw), s(key("dev-phone", "enc")["pub_hex"]))
            try eq(log.member(deviceId: "dev-ipad")!.status, .removed)
            try eq(log.member(deviceId: "svc-discord")!.kind, "service")
            try eq(hex(log.host(hostId: "host-a")!.hostKey.raw), s(key("host-a", "host_key")["pub_hex"]))
            try eq(log.host(hostId: "host-a")!.hostTrustGen, 1)
        }
        check("E7 extends L; its hedged retry is the same entry") {
            let log = try logL()
            let r = try log.extend(entries: [entry("E7")], now: now)
            try eq(r.appended, 1)
            try eq(r.stop, nil)
            try eq(r.head.hash, hash("E7"))
            try eq(try signedObjectInfo(json: entry("E7_retry")).entryHash, hash("E7"))
        }
        check("refusals in context") {
            func stop(_ labels: [String]) throws -> CarriageStop? { try logL().evaluate(entries: labels.map(entry), now: now).stop }
            try eq(try stop(["E7", "X8_badsig"]), .invalid(index: 1, code: "bad_signature"))
            guard case .conflict(_, let freeze) = try stop(["C6_mac"]) else { throw Failure(description: "C6_mac") }
            try eq(freeze, "freeze")
            guard case .conflict(_, let ignored) = try stop(["C6_ipad"]) else { throw Failure(description: "C6_ipad") }
            try eq(ignored, "ignored:signer_removed")
            guard case .invalid = try stop(["X7_ipad"]) else { throw Failure(description: "X7_ipad") }
            try eq(try stop(["KB7", "KB8_stale"]), .invalid(index: 1, code: "blob_version_not_increasing"))
            try eq(try stop(["R7_wrong_key"]), .invalid(index: 0, code: "bad_signature"))
        }
        check("a recovery_add waits 24 h on the verifier's clock") {
            let log = try logL()
            try eq(try log.extend(entries: [entry("R7")], now: now).appended, 1)
            let pending = log.pendingRecovery(now: now)
            try eq(pending.count, 1)
            try eq(pending[0].entryHash, hash("R7"))
            try eq(pending[0].subject, "dev-newmac")
            try eq(pending[0].effectiveAt, now.wallMs + 86_400_000)
            try eq(log.member(deviceId: "dev-newmac")!.status, .pending)
        }
        let phoneAuth = key("dev-phone", "auth")
        check("draft + publish reproduces E7 (a Swift signer through the foreign trait)") {
            let log = try logL()
            let e7 = o(o(byLabel["E7"]!["entry"])["body"])
            let body = try log.draftEntry(signer: "dev-phone", signedAt: u(e7["signed_at"]), actionJson: js(["action": "remove", "device_id": s(e7["device_id"])]))
            try eq(body, s(byLabel["E7"]!["jcs"]))
            #if canImport(CryptoKit)
            let phone = CryptoKitKeys()
            try phone.addP256("dev-phone/auth", secret: unhex(s(phoneAuth["secret_hex"])))
            let provider: AppKeyProvider = phone
            #else
            let store = SoftwareKeyStore()
            try store.insertP256(keyId: "dev-phone/auth", secret: unhex(s(phoneAuth["secret_hex"])))
            let provider = store.provider()
            #endif
            let p = EntryPublisher()
            try p.prepare(log: log, bodyJson: body)
            try eq(p.preparedJson() != nil, true)
            let req = try p.sign(provider: provider, keyId: "dev-phone/auth", cosignKit: nil)
            try eq(req.entryHash, hash("E7"))
            try eq(req.expected, mlogHead)
            #if canImport(CryptoKit)
            try eq(phone.requests.count, 1)
            try eq(phone.requests[0].purpose, .remove)
            try eq(phone.requests[0].freshConfirmation, true)
            try eq(phone.requests[0].bodyJson, body)
            #endif
            try verifySignedObject(json: req.entryJson, key: PublicKeyData(alg: .p256, raw: unhex(s(phoneAuth["pub_hex"]))))
            try eq(try EntryPublisher.resume(preparedJson: p.preparedJson()!).outstanding()!.entryHash, req.entryHash)
            try eq(try p.replyStored(log: log, now: now), .committed(head: LogHead(seq: 7, hash: hash("E7"))))
            try eq(log.head().seq, 7)
            try eq(p.preparedJson(), nil)
        }
        check("a draft the verifier would refuse is refused before signing") {
            try throwsCode("membership_invalid") { _ = try logL().draftEntry(signer: "dev-phone", signedAt: 1, actionJson: "{\"action\":\"remove\"}") }
        }

        // ------------------------------------------------------------ recovery
        let kit = o(rec["kit"])
        func kit1() throws -> RecoveryKitHandle {
            try RecoveryKitHandle.read(r: unhex(s(rec["R_hex"])), accountId: s(kit["account_id"]), genesisHash: s(kit["genesis_hash"]), kitTag: unhex(s(kit["kit_tag_hex"])))
        }
        let recoveryPub = b64u(s(o(rec["recovery_key"])["pub"]))
        check("kit 1: tag, recovery key, X25519 key") {
            let k = try kit1()
            try eq(hex(k.kitTag()), s(kit["kit_tag_hex"]))
            try eq(hex(k.recoveryKey().raw), hex(recoveryPub))
            try eq(hex(try k.x25519Public()), s(rec["recovery_key_x25519_pub_hex"]))
            try eq(hex(try ed25519PublicToX25519(key: PublicKeyData(alg: .ed25519, raw: recoveryPub))), s(rec["recovery_key_x25519_pub_hex"]))
            try eq(hashFields(fields: [utf8("atem-r9-test-key"), utf8("recovery kit R")]), s(rec["R_hex"]))
        }
        check("a mistyped kit is refused") {
            var tag = unhex(s(kit["kit_tag_hex"]))
            tag[0] ^= 1
            try throwsCode("kit_tag_mismatch") { _ = try RecoveryKitHandle.read(r: unhex(s(rec["R_hex"])), accountId: s(kit["account_id"]), genesisHash: s(kit["genesis_hash"]), kitTag: tag) }
        }
        check("K backups: hash, open with kit 1, refused by kit 2") {
            let kb = o(rec["k_backup"])
            try eq(try parseKBackup(envelopeJson: js(kb["wire"]!)).backupHash, s(kb["backup_hash"]))
            let out = try openKBackup(envelopeJson: js(kb["wire"]!), kit: kit1())
            let plain = a(o(try JSONSerialization.jsonObject(with: utf8(s(kb["plain_jcs"]))))["keys"]).map(o)
            try eq(out.map { $0.kid }, plain.map { s($0["kid"]) })
            try eq(out.map { hex($0.k) }, plain.map { hex(b64u(s($0["k"]))) })
            let k2 = o(rec["kit_2"])
            let k2kit = o(k2["kit"])
            let kit2 = try RecoveryKitHandle.read(r: unhex(s(k2["R_hex"])), accountId: s(k2kit["account_id"]), genesisHash: s(k2kit["genesis_hash"]), kitTag: unhex(s(k2kit["kit_tag_hex"])))
            try throwsCode("backup_invalid") { _ = try openKBackup(envelopeJson: js(kb["wire"]!), kit: kit2) }
            _ = try openKBackup(envelopeJson: js(o(k2["k_backup_resealed"])["wire"]!), kit: kit2)
            let bad = o(rec["k_backup_bad_ct"])
            try eq(try parseKBackup(envelopeJson: js(bad["wire"]!)).backupHash, s(bad["backup_hash"]))
            try throwsCode("backup_invalid") { _ = try openKBackup(envelopeJson: js(bad["wire"]!), kit: kit1()) }
        }
        check("recovery entry hash") { try eq(try signedObjectInfo(json: js(o(rec["recovery_entry"])["entry"]!)).entryHash, s(rec["recovery_entry_hash"])) }
        func restore() throws -> RestoreSession {
            try RestoreSession.read(r: unhex(s(rec["R_hex"])), accountId: s(kit["account_id"]), genesisHash: s(kit["genesis_hash"]), kitTag: unhex(s(kit["kit_tag_hex"])))
        }
        check("restore: a substitute chain is refused by the kit's anchor") {
            let session = try restore()
            let sub = o(rec["substitute_chain"])
            try throwsCode("genesis_mismatch") {
                _ = try session.attempt(relayEntries: a(sub["entries"]).map { entry(s($0)) }, envelopeJson: js(o(sub["backup"])["wire"]!), hostAccepts: [], now: now)
            }
            try eq(session.kStored(), false)
        }
        check("restore: no host reachable withholds; a host head confirms") {
            let session = try restore()
            let entries = l + [entry("KB7")]
            let wire = js(o(rec["k_backup"])["wire"]!)
            try throwsCode("no_host_reachable") { _ = try session.attempt(relayEntries: entries, envelopeJson: wire, hostAccepts: [], now: now) }
            try eq(session.waitingForHosts(), ["host-a"])
            let r = try session.attempt(relayEntries: entries, envelopeJson: wire, hostAccepts: [HostAcceptPair(initJson: js(hs["init"]!), acceptJson: js(hs["accept"]!))], now: now)
            try eq(r.head.seq, 7)
            try eq(r.keys.map { $0.kid }, ["b982533d", "1f2e3d4c"])
            try eq(session.kStored(), true)
            try eq(session.mayRotateK(deviceId: "dev-newmac"), false)
        }

        // ------------------------------------------------------------- channel
        let inputs = o(hs["inputs"])
        check("accept: th2 and sig_h") {
            try eq(try hostAcceptTh2(initJson: js(hs["init"]!), acceptJson: js(hs["accept"]!)), s(hs["th2_hex"]))
            try eq(hex(signingInput(label: .channelHost, payload: unhex(s(hs["th2_hex"])))), s(hs["sig_h_input_hex"]))
            try verifySignature(key: PublicKeyData(alg: .ed25519, raw: unhex(s(inputs["host_key_pub_hex"]))), label: .channelHost, payload: unhex(s(hs["th2_hex"])), signature: unhex(s(hs["sig_h_hex"])))
            let head = o(inputs["head"])
            try eq(try verifyHostAccept(initJson: js(hs["init"]!), acceptJson: js(hs["accept"]!), log: logL()), LogHead(seq: u(head["seq"]), hash: s(head["hash"])))
        }
        check("a rewritten head fails sig_h") {
            let neg = a(hs["negative"]).map(o).first { s($0["case"]) == "tampered_head" }!
            var accept = o(hs["accept"])
            accept["head"] = neg["head"]
            try eq(try hostAcceptTh2(initJson: js(hs["init"]!), acceptJson: js(accept)), s(neg["th2_hex"]))
            try throwsCode("handshake_failed") { _ = try verifyHostAccept(initJson: js(hs["init"]!), acceptJson: js(accept), log: logL()) }
        }
        check("sig_c over th3") {
            try eq(hex(signingInput(label: .channelClient, payload: unhex(s(hs["th3_hex"])))), s(hs["sig_c_input_hex"]))
            let pub = PublicKeyData(alg: .p256, raw: unhex(s(inputs["client_auth_pub_hex"])))
            try verifySignature(key: pub, label: .channelClient, payload: unhex(s(hs["th3_hex"])), signature: unhex(s(hs["sig_c_hex"])))
            var bad = unhex(s(hs["th3_hex"]))
            bad[0] ^= 1
            try throwsCode("bad_signature") { try verifySignature(key: pub, label: .channelClient, payload: bad, signature: unhex(s(hs["sig_c_hex"]))) }
        }

        // ------------------------------------------------------- browser grant
        check("browser grant: hash, issuer signature, sig_c") {
            let g = js(grant["grant"]!)
            let info = try parseBrowserGrant(grantJson: g)
            try eq(info.grantHash, s(grant["grant_hash_hex"]))
            try eq(info.issuer, "dev-phone")
            try eq(info.ops, ["view"])
            try eq(info.sessionId, "ses-aaaaaaaaaaaa")
            try eq(hex(try signedObjectInfo(json: g).signingInput), s(grant["signing_input_hex"]))
            try verifySignedObject(json: g, key: PublicKeyData(alg: .p256, raw: unhex(s(phoneAuth["pub_hex"]))))
            try throwsCode("bad_signature") { try verifySignedObject(json: g, key: PublicKeyData(alg: .p256, raw: unhex(s(key("dev-mac", "auth")["pub_hex"])))) }
            try verifySignature(key: PublicKeyData(alg: .p256, raw: unhex(s(o(keys["browser"])["pub_hex"]))), label: .channelClient, payload: unhex(s(grant["th3_hex"])), signature: unhex(s(grant["sig_c_hex"])))
        }

        // ---------------------------------------------------------------- push
        let nowP = u(push["verifier_now"])
        let opens = a(push["open"]).map(o)
        let secrets = o(push["recipient_secrets"])
        check("open hints verify and open for their device only") {
            for (i, h) in opens.enumerated() {
                let d = openDetails[i]
                let device = s(d["device_id"])
                let hint = try verifyPushHint(hintJson: js(h), log: logL(), nowMs: nowP, verifier: .client)
                try eq(hint.state(), .open(deviceId: device, encKid: s(d["enc_kid"]), sealedHash: s(d["sealed_hash"])))
                try eq(hex(try signedObjectInfo(json: js(h)).signingInput), s(d["signing_input_hex"]))
                #if canImport(CryptoKit)
                let keysCK = CryptoKitKeys()
                try keysCK.addX25519("enc", secret: unhex(s(secrets[device])))
                let provider: AppKeyProvider = keysCK
                #else
                let store = SoftwareKeyStore()
                try store.insertX25519(keyId: "enc", secret: unhex(s(secrets[device])))
                let provider = store.provider()
                #endif
                let plain = o(try JSONSerialization.jsonObject(with: utf8(s(d["plain_jcs"]))))
                try eq(try hint.open(provider: provider, encKeyId: "enc", deviceId: device), HintContent(tool: s(plain["tool"]), summary: s(plain["summary"])))
                let other = device == "dev-phone" ? "dev-mac" : "dev-phone"
                try throwsCode("malformed") { _ = try hint.open(provider: provider, encKeyId: "enc", deviceId: other) }
            }
        }
        let resolved = o(push["resolved"])
        let seenVec = o(push["seen"])
        check("resolved and seen") {
            let r = try verifyPushHint(hintJson: js(resolved), log: logL(), nowMs: nowP, verifier: .client)
            try eq(r.state(), .resolved(reason: "answered_remote", resolvedAt: u(o(resolved["body"])["resolved_at"])))
            let seen = try verifySeen(seenJson: js(seenVec), log: logL())
            try eq(seen.deviceId, "dev-phone")
            try eq(seen.seenAt, u(o(seenVec["body"])["seen_at"]))
            try eq(hex(try signedObjectInfo(json: js(seenVec)).signingInput), s(push["seen_signing_input_hex"]))
            try eq(try seenInWindow(seenJson: js(seenVec), log: logL(), openCreatedAt: u(o(opens[0]["body"])["created_at"])), true)
        }
        let invalid = a(push["invalid"]).map { js(o($0)["hint"]!) }
        check("invalid hints are refused for their reason") {
            for verifier in [PushVerifier.client, PushVerifier.relay] {
                try throwsCode("skew") { _ = try verifyPushHint(hintJson: invalid[0], log: logL(), nowMs: nowP, verifier: verifier) }
                try throwsCode("invalid_times") { _ = try verifyPushHint(hintJson: invalid[1], log: logL(), nowMs: nowP, verifier: verifier) }
                try throwsCode("invalid_times") { _ = try verifyPushHint(hintJson: invalid[2], log: logL(), nowMs: nowP, verifier: verifier) }
            }
            let book = PushHintBook()
            try eq(try book.offer(hint: verifyPushHint(hintJson: js(opens[0]), log: logL(), nowMs: nowP, verifier: .client)), .accepted)
            try eq(try book.offer(hint: verifyPushHint(hintJson: js(opens[0]), log: logL(), nowMs: nowP, verifier: .client)), .idempotent)
            try throwsCode("duplicate") { _ = try book.offer(hint: verifyPushHint(hintJson: invalid[3], log: logL(), nowMs: nowP, verifier: .client)) }
        }
        check("a resolved dominates its opens in either order") {
            let book = PushHintBook()
            try eq(try book.offer(hint: verifyPushHint(hintJson: js(resolved), log: logL(), nowMs: nowP, verifier: .client)), .accepted)
            try eq(try book.offer(hint: verifyPushHint(hintJson: js(opens[0]), log: logL(), nowMs: nowP, verifier: .client)), .ignoredAfterResolved)
            try eq(try book.isResolved(approval: verifyPushHint(hintJson: js(opens[1]), log: logL(), nowMs: nowP, verifier: .client).approval()), true)
        }
        check("tampered created_at fails the signature") {
            var h = opens[0]
            var body = o(h["body"])
            body["created_at"] = NSNumber(value: u(body["created_at"]) + 1)
            h["body"] = body
            try throwsCode("bad_signature") { _ = try verifyPushHint(hintJson: js(h), log: logL(), nowMs: nowP, verifier: .client) }
        }
        check("acks round trip") {
            let hint = try verifyPushHint(hintJson: js(opens[0]), log: logL(), nowMs: nowP, verifier: .client)
            try eq(try parsePushAck(messageJson: pushAckMessage(acks: [hint.ackJson()])), [hint.ackJson()])
        }
        check("schedule from the signed created_at, and the 15 s guard") {
            for (name, sent) in [("open_g75", false), ("open_g75001", true)] {
                let vec = o(push[name])
                let hint = try verifyPushHint(hintJson: js(vec), log: logL(), nowMs: u(o(vec["body"])["created_at"]), verifier: .client)
                let mobile = PushRecipient(deviceClass: .mobile, connected: false, immediateMobile: false)
                let stages = pushStages(createdAt: hint.createdAt(), recipient: mobile)
                try eq(stages, [PushStageDue(stage: .mobile, due: hint.createdAt() + 60000, providerPush: true)])
                try eq(pushSendNow(stage: .mobile, due: stages[0].due, now: stages[0].due, expiresAt: hint.expiresAt(), resolved: false, seen: false), sent)
                try eq(pushGuard(expiresAt: hint.expiresAt()), hint.expiresAt() - 15000)
            }
            let body = o(opens[0]["body"])
            let created = u(body["created_at"])
            let expires = u(body["expires_at"])
            let desktop = PushRecipient(deviceClass: .desktop, connected: false, immediateMobile: false)
            try eq(pushStages(createdAt: created, recipient: desktop), [PushStageDue(stage: .desktopOs, due: created, providerPush: true)])
            try eq(pushSendNow(stage: .mobile, due: created + 60000, now: created + 60000, expiresAt: expires, resolved: false, seen: true), false)
            try eq(pushNextDue(createdAt: created, expiresAt: expires, recipient: desktop, sent: [.desktopOs], now: created), nil)
        }

        print("swift conformance: \(passed) passed, \(failures.count) failed")
        for f in failures { print("FAIL \(f)") }
        XCTAssertEqual(failures, [], "conformance failures")
        XCTAssertEqual(passed, 34)
    }
}
