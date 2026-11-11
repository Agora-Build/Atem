// The shared r9 vectors (designs/protocol/fixtures/r9-vectors-*.json) run
// through the Swift binding, the same checks as the Kotlin
// (bindings/kotlin/Conformance.kt) and WASM (bindings/js/conformance.mjs)
// runs. ATEM_FIXTURES names the fixtures directory.
import CryptoKit
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

private func b64uString(_ d: Data) -> String {
    d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

private func utf8(_ s: String) -> Data { Data(s.utf8) }

private func o(_ v: Any?) -> [String: Any] { v as! [String: Any] }
private func a(_ v: Any?) -> [Any] { v as! [Any] }
private func s(_ v: Any?) -> String { v as! String }
private func u(_ v: Any?) -> UInt64 { (v as! NSNumber).uint64Value }
private func js(_ v: Any) -> String {
    String(data: try! JSONSerialization.data(withJSONObject: v, options: [.fragmentsAllowed]), encoding: .utf8)!
}

// JSON with sorted keys, to compare two values whatever their key order.
private func canon(_ v: Any) -> String {
    String(data: try! JSONSerialization.data(withJSONObject: v, options: [.fragmentsAllowed, .sortedKeys]), encoding: .utf8)!
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
    case let .Stored(code, detail): return (code, detail)
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
        func scopeOfE5() -> [String: Any] { o(o(o(o(byLabel["E5"]!["entry"])["body"])["member"])["scope"]) }

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
                // A set out of order: the signed-object parse itself refuses it.
                if (v["reason"] as? String) == "array_not_canonical" {
                    try throwsCode("array_not_canonical") { _ = try signedObjectInfo(json: js(v["entry"]!)) }
                    continue
                }
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
            let pending = try log.pendingRecovery(now: now)
            try eq(pending.count, 1)
            try eq(pending[0].entryHash, hash("R7"))
            try eq(pending[0].subject, "dev-newmac")
            try eq(pending[0].effectiveAt, now.wallMs + 86_400_000)
            try eq(log.member(deviceId: "dev-newmac")!.status, .pending)
        }
        check("the log's durable snapshot restores against the app's anchors") {
            let log = try logL()
            _ = try log.extend(entries: [entry("R7")], now: now)
            let saved = try log.storedJson()
            let later = HostClock(wallMs: now.wallMs + 3_600_000, monoMs: now.monoMs + 3_600_000, bootId: "boot-1")
            let restored = try MembershipLog.fromStored(accountId: account, genesisHash: genesis, storedJson: saved, now: later)
            try eq(restored.head(), log.head())
            try eq(restored.pendingRecovery(now: later)[0].effectiveAt, now.wallMs + 86_400_000, "same boot: from first sight")
            let reboot = HostClock(wallMs: now.wallMs + 7_200_000, monoMs: 500, bootId: "boot-2")
            try eq(try MembershipLog.fromStored(accountId: account, genesisHash: genesis, storedJson: saved, now: reboot).pendingRecovery(now: reboot)[0].effectiveAt, reboot.wallMs + 86_400_000, "another boot: nothing waited was persisted")
            try throwsCode("account_mismatch") { _ = try MembershipLog.fromStored(accountId: "acct-other", genesisHash: genesis, storedJson: saved, now: now) }
            try throwsCode("genesis_mismatch") { _ = try MembershipLog.fromStored(accountId: account, genesisHash: hash("SUB1"), storedJson: saved, now: now) }
            try throwsCode("malformed") { _ = try MembershipLog.fromStored(accountId: account, genesisHash: genesis, storedJson: String(saved.prefix(saved.count / 2)), now: now) }
            let extra = saved.replacingOccurrences(of: "{", with: "{\"extra\":1,", options: [], range: saved.range(of: "{"))
            try throwsCode("stored_invalid") { _ = try MembershipLog.fromStored(accountId: account, genesisHash: genesis, storedJson: extra, now: now) }
        }
        check("a wait-ended decision survives the snapshot") {
            let log = try logL()
            _ = try log.extend(entries: [entry("R7")], now: now)
            let day = HostClock(wallMs: now.wallMs + 86_400_000, monoMs: now.monoMs + 86_400_000, bootId: "boot-1")
            try eq(try log.advance(now: day).isEmpty, false)
            let saved = try log.storedJson()
            try eq(saved.contains("\"reason\":\"wait_ended\""), true)
            let restored = try MembershipLog.fromStored(accountId: account, genesisHash: genesis, storedJson: saved, now: day)
            try eq(restored.member(deviceId: "dev-newmac")!.status, .active)
            try eq(try restored.extend(entries: [entry("N8")], now: day).appended, 1, "N8 relies on the decision")
            let newer = saved.replacingOccurrences(of: "\"v\":1", with: "\"v\":2")
            try throwsCode("unsupported_version") { _ = try MembershipLog.fromStored(accountId: account, genesisHash: genesis, storedJson: newer, now: day) }
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
            var p: EntryPublisher? = EntryPublisher()
            try p!.prepare(log: log, bodyJson: body)
            try eq(p!.preparedJson() != nil, true)
            let req = try p!.sign(provider: provider, keyId: "dev-phone/auth", cosignKit: nil)
            try eq(req.entryHash, hash("E7"))
            try eq(req.expected, mlogHead)
            #if canImport(CryptoKit)
            try eq(phone.requests.count, 1)
            try eq(phone.requests[0].purpose, .remove)
            try eq(phone.requests[0].freshConfirmation, true)
            try eq(phone.requests[0].bodyJson, body)
            #endif
            try verifySignedObject(json: req.entryJson, key: PublicKeyData(alg: .p256, raw: unhex(s(phoneAuth["pub_hex"]))))
            // A restart: the saved state resumes (one append per device, so
            // the old object goes first).
            let saved = p!.preparedJson()!
            p = nil
            let resumed = try EntryPublisher.resume(preparedJson: saved)
            try eq(resumed.outstanding()!.entryHash, req.entryHash)
            try eq(try resumed.replyStored(log: log, now: now), .committed(head: LogHead(seq: 7, hash: hash("E7"))))
            try eq(log.head().seq, 7)
            try eq(resumed.preparedJson(), nil)
        }
        check("a draft the verifier would refuse is refused before signing") {
            try throwsCode("membership_invalid") { _ = try logL().draftEntry(signer: "dev-phone", signedAt: 1, actionJson: "{\"action\":\"remove\"}") }
        }

        check("capacity and the service change guard (D23)") {
            let log = try logL()
            try eq(log.capacity(), CapacityInfo(entries: 6, maxEntries: 1024, members: 3, maxMembers: 256, hosts: 1, maxHosts: 64, level: .ok, entriesLevel: .ok, membersLevel: .ok, hostsLevel: .ok))
            let e5 = o(o(byLabel["E5"]!["entry"])["body"])
            let svc = o(e5["member"])
            let at = u(e5["signed_at"])
            let day: UInt64 = 86_400_000
            func change(_ ops: Any, _ expiresAt: UInt64) -> String {
                var scope = o(svc["scope"])
                scope["ops"] = ops
                return js(["action": "set_roles", "device_id": "svc-discord", "roles": ["service"], "scope": scope, "expires_at": expiresAt] as [String: Any])
            }
            let renew = change(o(svc["scope"])["ops"]!, u(svc["expires_at"]) + day)
            try eq(try log.checkChange(actionJson: renew, nowMs: at + 3_600_000), .serviceChangeTooSoon(lastSignedAt: at, retryAt: at + day), "a renewal within 24 h")
            try eq(try log.checkChange(actionJson: renew, nowMs: at + day), nil, "after 24 h")
            try eq(try log.checkChange(actionJson: change(["view"], u(svc["expires_at"])), nowMs: at + 3_600_000), nil, "narrowing")
            try eq(try log.checkChange(actionJson: "{\"action\":\"remove\",\"device_id\":\"svc-discord\"}", nowMs: at + 3_600_000), nil, "removal")
            let hostKey = o(o(o(o(byLabel["E2"]!["entry"])["body"])["host"])["host_key"])
            let addHost = js(["action": "add_host", "host": ["host_id": "host-b", "host_trust_gen": 1, "host_key": hostKey] as [String: Any]] as [String: Any])
            try eq(try log.checkChange(actionJson: addHost, nowMs: at), nil, "a host with room")
            try throwsCode("membership_invalid") { _ = try log.checkChange(actionJson: "{\"action\":\"remove\"}", nowMs: at) }
        }

        check("service builders: add, set_roles, renewal, narrowing (§R9.6)") {
            let log = try logL()
            let e5 = o(o(byLabel["E5"]!["entry"])["body"])
            let svc = o(e5["member"])
            let scope = o(svc["scope"])
            let at = u(e5["signed_at"])
            let exp = u(svc["expires_at"])
            let day: UInt64 = 86_400_000
            let svcKey = PublicKeyData(alg: .ed25519, raw: unhex(s(key("svc-discord", "auth")["pub_hex"])))
            let hosts = a(scope["hosts"]).map(s)
            let projects = a(scope["projects"]).map(s)
            let ops = a(scope["ops"]).map(s)
            // E5's member, rebuilt from its parts in another order: the vector's bytes.
            let shuffled = ServiceScopeInfo(hosts: hosts, projects: Array(projects.reversed()), sessions: nil, ops: ["prompt", "interrupt"])
            try eq(try serviceAddAction(deviceId: "svc-discord", authKey: svcKey, scope: shuffled, expiresAt: exp, signedAt: at),
                   try canonicalJson(json: js(["action": "add", "member": svc] as [String: Any])))
            try eq(log.serviceGrant(deviceId: "svc-discord"), ServiceGrantInfo(scope: ServiceScopeInfo(hosts: hosts, projects: projects, sessions: nil, ops: ops), expiresAt: exp))
            try eq(log.serviceGrant(deviceId: "dev-phone"), nil)
            let newSvc = try serviceAddAction(deviceId: "svc-new", authKey: svcKey,
                scope: ServiceScopeInfo(hosts: ["host-a"], projects: nil, sessions: ["ses-bbbbbbbbbbbb", "ses-aaaaaaaaaaaa"], ops: ["prompt"]),
                expiresAt: at + 3_600_000, signedAt: at)
            let newScope = o(o(o(try JSONSerialization.jsonObject(with: Data(newSvc.utf8)))["member"])["scope"])
            try eq(a(newScope["ops"]).map(s), ["prompt", "view"])
            try eq(a(newScope["sessions"]).map(s), ["ses-aaaaaaaaaaaa", "ses-bbbbbbbbbbbb"])
            _ = try log.draftEntry(signer: "dev-phone", signedAt: at, actionJson: newSvc)
            try eq(try log.checkChange(actionJson: newSvc, nowMs: at), nil, "an add with room")
            func change(_ o2: [String], _ e: UInt64) throws -> String {
                var sc = scope
                sc["ops"] = o2
                return try canonicalJson(json: js(["action": "set_roles", "device_id": "svc-discord", "roles": ["service"], "scope": sc, "expires_at": e] as [String: Any]))
            }
            let renew = try log.serviceRenewalAction(deviceId: "svc-discord", expiresAt: exp + day, signedAt: at + day)
            try eq(renew, try change(ops, exp + day), "renewal")
            try eq(try log.checkChange(actionJson: renew, nowMs: at + 3_600_000), .serviceChangeTooSoon(lastSignedAt: at, retryAt: at + day), "a renewal is paced")
            let viewOnly = ServiceScopeInfo(hosts: hosts, projects: projects, sessions: nil, ops: ["view"])
            let narrow = try log.serviceNarrowingAction(deviceId: "svc-discord", scope: viewOnly, expiresAt: nil, signedAt: at + 3_600_000)
            try eq(narrow, try change(["view"], exp), "narrowing")
            try eq(try log.checkChange(actionJson: narrow, nowMs: at + 3_600_000), nil, "a narrowing isn't paced")
            try eq(try serviceSetRolesAction(deviceId: "svc-discord", scope: viewOnly, expiresAt: exp, signedAt: at), narrow)
            try throwsCode("not_a_narrowing") { _ = try log.serviceNarrowingAction(deviceId: "svc-discord", scope: ServiceScopeInfo(hosts: hosts, projects: projects, sessions: nil, ops: ["stop", "view"]), expiresAt: nil, signedAt: at) }
            try throwsCode("not_a_narrowing") { _ = try log.serviceNarrowingAction(deviceId: "svc-discord", scope: ServiceScopeInfo(hosts: hosts, projects: projects, sessions: nil, ops: ops), expiresAt: nil, signedAt: at) }
            try throwsCode("not_a_renewal") { _ = try log.serviceRenewalAction(deviceId: "svc-discord", expiresAt: exp, signedAt: at) }
            try throwsCode("not_a_service") { _ = try log.serviceRenewalAction(deviceId: "dev-phone", expiresAt: exp + day, signedAt: at) }
            try throwsCode("bad_scope") { _ = try serviceSetRolesAction(deviceId: "svc-discord", scope: ServiceScopeInfo(hosts: [], projects: nil, sessions: nil, ops: ["view"]), expiresAt: exp, signedAt: at) }
            try throwsCode("bad_scope") { _ = try serviceSetRolesAction(deviceId: "svc-discord", scope: ServiceScopeInfo(hosts: ["host-a"], projects: nil, sessions: nil, ops: ["fly"]), expiresAt: exp, signedAt: at) }
            try throwsCode("service_expiry") { _ = try serviceSetRolesAction(deviceId: "svc-discord", scope: ServiceScopeInfo(hosts: ["host-a"], projects: nil, sessions: nil, ops: []), expiresAt: at + 90 * day + 1, signedAt: at) }
            try throwsCode("wrong_alg") { _ = try serviceAddAction(deviceId: "svc-x", authKey: PublicKeyData(alg: .x25519, raw: unhex(s(key("dev-phone", "enc")["pub_hex"]))), scope: ServiceScopeInfo(hosts: ["host-a"], projects: nil, sessions: nil, ops: []), expiresAt: at, signedAt: at) }
        }
        // r9_svc vectors: atem-client's own file (crates/atem-client/vectors).
        let svcFp = o(try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent("../../../crates/atem-client/vectors/r9-svc-fingerprint.json"))))
        check("service key fingerprint r9_svc (atem-client vectors)") {
            func alg(_ name: String) -> KeyAlg { name == "p256" ? .p256 : (name == "ed25519" ? .ed25519 : .x25519) }
            for c in a(svcFp["valid"]).map(o) {
                let k = o(c["auth_key"])
                try eq(hex(b64u(s(k["pub"]))), s(c["pub_hex"]), s(c["case"]))
                try eq(try serviceKeyFingerprint(authKey: PublicKeyData(alg: alg(s(k["alg"])), raw: b64u(s(k["pub"])))), s(c["fingerprint"]), s(c["case"]))
            }
            for c in a(svcFp["invalid"]).map(o) {
                let k = o(c["auth_key"])
                try throwsCode(s(c["code"])) { _ = try serviceKeyFingerprint(authKey: PublicKeyData(alg: alg(s(k["alg"])), raw: b64u(s(k["pub"])))) }
            }
            let discord = a(svcFp["valid"]).map(o).first { s($0["case"]).contains("svc-discord") }!
            try eq(try logL().serviceKeyFingerprint(deviceId: "svc-discord"), s(discord["fingerprint"]))
            try eq(try logL().serviceKeyFingerprint(deviceId: "dev-phone"), nil)
        }
        // The host's own vector (src/memory/account_keys.rs H1_VECTOR): h1. of
        // "github.com/agora/atem" under K = [7; 32], kid 0123abcd.
        let h1Vector = "h1.0123abcd.777eda018c9c9736a84728e10308571167773f209924bf052477a1283cfd7cb6"
        check("project keys and hashes (§R9.6)") {
            try eq(projectKeyOfRemote(url: "git@github.com:Agora-Build/Atem.git"), "github.com/agora-build/atem")
            try eq(projectKeyOfRemote(url: "https://user:tok@github.com/Agora-Build/Atem.git/"), "github.com/agora-build/atem")
            try eq(projectKeyOfRemote(url: "file:///srv/repo.git"), nil)
            try eq(localProjectKey(folderName: "Scratch"), "local:Scratch")
            try eq(hex(projectHashInput(projectKey: "github.com/agora/atem")), hex(utf8("github.com/agora/atem")))
            try eq(try projectHash(key: AccountKey(kid: "0123abcd", k: Data(repeating: 7, count: 32)), projectKey: "github.com/agora/atem"), h1Vector)
            let mac = Data(HMAC<SHA256>.authenticationCode(for: projectHashInput(projectKey: "github.com/agora/atem"),
                                                           using: SymmetricKey(data: Data(repeating: 7, count: 32))))
            try eq(try projectHashFromMac(kid: "0123abcd", mac: mac), h1Vector)
            try throwsCode("malformed") { _ = try projectHashFromMac(kid: "01.23", mac: mac) }
            try throwsCode("malformed") { _ = try projectHashFromMac(kid: "0123abcd", mac: Data(count: 31)) }
            try eq(isProjectHash(text: s(a(scopeOfE5()["projects"])[0])), true)
            try eq(isProjectHash(text: "h1.0123abcd.zz"), false)
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
        let fiveActions: Set<String> = ["project_set", "project_remove", "host_sender_revoke", "host_sender_readmit", "host_enc_key"]
        let delegated = a(mlog["others"]).map(o).filter { $0["chain"] != nil }
        func logAfter(_ chain: [String]) throws -> MembershipLog {
            let log = try logL()
            try eq(try log.extend(entries: chain.map(entry), now: now).stop, nil, "chain \(chain)")
            return log
        }
        func hostKeyName(_ hostId: String, _ gen: UInt64) -> String { gen == 1 ? hostId : "\(hostId)-gen-\(gen)" }
        func encKeyOf(_ k: Any?) -> PublicKeyData { PublicKeyData(alg: .x25519, raw: b64u(s(o(k)["pub"]))) }
        // A body's key object with the alg it names (a vector may carry another).
        func keyOf(_ k: Any?) throws -> PublicKeyData {
            let alg: KeyAlg
            switch s(o(k)["alg"]) {
            case "x25519": alg = .x25519
            case "ed25519": alg = .ed25519
            case "p256": alg = .p256
            default: throw Failure(description: "unknown alg \(s(o(k)["alg"]))")
            }
            return PublicKeyData(alg: alg, raw: b64u(s(o(k)["pub"])))
        }
        func stateOf(_ log: MembershipLog) throws -> [String: Any] {
            var hosts: [String: Any] = [:]
            var senders: [String: Any] = [:]
            var encKeys: [String: Any] = [:]
            func keyOut(_ k: HostEncKeyInfo) -> [String: Any] {
                ["enc_kid": k.encKid, "pub": b64uString(k.key.raw), "seq": k.seq, "host_trust_gen": k.hostTrustGen]
            }
            for id in ["host-a", "host-b"] {
                if let h = log.host(hostId: id) { hosts[id] = h.hostTrustGen }
                let epoch = log.hostMembershipEpoch(hostId: id)
                if let sender = log.hostSenderState(hostId: id) {
                    var item: [String: Any] = [:]
                    switch sender {
                    case let .authorized(generation): item["state"] = "authorized"; item["seq"] = generation
                    case let .revoked(seq): item["state"] = "revoked"; item["seq"] = seq
                    }
                    if let e = epoch { item["membership_epoch"] = e }
                    senders[id] = item
                } else {
                    try eq(epoch, nil, "\(id) epoch without an add_host")
                }
                if let keysOf = log.hostEncKey(hostId: id) {
                    var item: [String: Any] = ["current": keyOut(keysOf.current)]
                    if let p = keysOf.previous {
                        var previous = keyOut(p.key)
                        previous["retired"] = p.retired
                        previous["replaced_at_seq"] = p.replacedAtSeq
                        item["previous"] = previous
                    }
                    encKeys[id] = item
                }
            }
            var projects: [String: Any] = [:]
            for p in log.projects() { projects[p.name] = ["hosts": p.hosts, "members": p.members, "ops": p.ops] as [String: Any] }
            return ["hosts": hosts, "projects": projects, "host_senders": senders, "host_enc_keys": encKeys]
        }
        func opsBetween(_ expect: [String: Any], _ x: String, _ y: String) -> [String] {
            if x == y { return [] }
            var ops = Set<String>()
            for (_, project) in o(expect["projects"]) {
                let members = a(o(project)["members"]).map(s)
                if members.contains(x) && members.contains(y) { for op in a(o(project)["ops"]) { ops.insert(s(op)) } }
            }
            return ops.sorted()
        }
        check("device-list actions: the queries read every vector's expect, refusals carry their reason") {
            var valid = 0
            var refused = 0
            for v in delegated {
                let label = s(v["label"])
                let log = try logAfter(a(v["chain"]).map(s))
                if (v["valid"] as? Bool) == false {
                    refused += 1
                    if s(v["reason"]) == "array_not_canonical" {
                        try throwsCode("array_not_canonical") { _ = try log.evaluate(entries: [entry(label)], now: now) }
                    } else {
                        try eq(try log.evaluate(entries: [entry(label)], now: now).stop, .invalid(index: 0, code: s(v["reason"])), label)
                    }
                    continue
                }
                valid += 1
                let r = try log.extend(entries: [entry(label)], now: now)
                try eq(r.stop, nil, label)
                try eq(r.appended, 1, label)
                try eq(r.head.hash, s(v["entry_hash"]), label)
                let expect = o(v["expect"])
                try eq(canon(try stateOf(log)), canon(expect), label)
                for (x, y) in [("host-a", "host-b"), ("host-b", "host-a"), ("host-a", "host-a")] {
                    try eq(log.projectOpsBetween(a: x, b: y), opsBetween(expect, x, y), "\(label) \(x) \(y)")
                }
                for id in ["host-a", "host-b"] {
                    let inEffect = o(expect["projects"]).filter { a(o($0.value)["members"]).map(s).contains(id) }.keys.sorted()
                    try eq(log.hostProjects(hostId: id), inEffect, "\(label) \(id)")
                }
            }
            if !(valid >= 34 && refused >= 35) { throw Failure(description: "\(valid) valid, \(refused) refused") }
        }
        func buildAction(_ body: [String: Any]) throws -> String {
            let at = u(body["signed_at"])
            switch s(body["action"]) {
            case "project_set":
                let project = o(body["project"])
                return try projectSetAction(name: s(project["name"]), hosts: a(project["hosts"]).map(s), ops: a(project["ops"]).map(s), signedAt: at)
            case "project_remove":
                return try projectRemoveAction(name: s(body["name"]), signedAt: at)
            case "host_sender_revoke":
                return try hostSenderRevokeAction(hostId: s(body["host_id"]), interruptRunning: body["interrupt_running"] as! Bool, signedAt: at)
            case "host_sender_readmit":
                return try hostSenderReadmitAction(hostId: s(body["host_id"]), signedAt: at)
            case "host_enc_key":
                return try hostEncKeyAction(hostId: s(body["host_id"]), hostTrustGen: u(body["host_trust_gen"]), encKey: keyOf(body["enc_key"]),
                                            encSigB64u: s(body["enc_sig"]), retirePrevious: (body["retire_previous"] as? Bool) == true, signedAt: at)
            default:
                throw Failure(description: "unknown action \(s(body["action"]))")
            }
        }
        // A body no builder writes: another signer's entry (a builder's action is
        // drafted for the signer that asks), or a shape outside the builders'
        // inputs (`retire_previous: false`, a revoke without `interrupt_running`,
        // a field the action doesn't have, a set out of order).
        func unbuildable(_ v: [String: Any]) -> Bool {
            let body = o(o(v["entry"])["body"])
            let reason = v["reason"] as? String
            return s(body["signer"]) != "dev-mac"
                || (body["retire_previous"] as? Bool) == false
                || (s(body["action"]) == "host_sender_revoke" && !(body["interrupt_running"] is Bool))
                || reason == "unknown_field" || reason == "array_not_canonical"
        }
        check("device-list actions: the builders reproduce the vectors; check_change advises on a redundant revoke or readmit and a reused key") {
            var built = 0
            for v in delegated.filter({ fiveActions.contains(s(o(o($0["entry"])["body"])["action"])) }) {
                let label = s(v["label"])
                let body = o(o(v["entry"])["body"])
                if unbuildable(v) { continue }
                // A shape the verifier refuses by itself is the builder's refusal too.
                if let reason = v["reason"] as? String, ["bad_project", "malformed", "wrong_alg"].contains(reason) {
                    try throwsCode(reason) { _ = try buildAction(body) }
                    continue
                }
                let log = try logAfter(a(v["chain"]).map(s))
                let action = try buildAction(body)
                built += 1
                let signedAt = u(body["signed_at"])
                try eq(try log.draftEntry(signer: "dev-mac", signedAt: signedAt, actionJson: action), s(v["jcs"]), label)
                var want: ChangeRefusalInfo? = nil
                if (v["reason"] as? String) == "already_revoked" { want = .alreadyRevoked }
                if (v["reason"] as? String) == "not_revoked" { want = .notRevoked }
                if (v["reason"] as? String) == "enc_key_reused" { want = .encKeyReused }
                try eq(try log.checkChange(actionJson: action, nowMs: signedAt), want, "\(label) check_change")
            }
            if built < 38 { throw Failure(description: "\(built) built") }
        }
        check("device-list actions: shapes the verifier refuses by itself") {
            let two = ["host-a", "host-b"]
            try throwsCode("bad_project") { _ = try projectSetAction(name: "astation", hosts: two, ops: ["deploy"], signedAt: 1) }
            try throwsCode("bad_project") { _ = try projectSetAction(name: "astation", hosts: two, ops: [], signedAt: 1) }
            try throwsCode("bad_project") { _ = try projectSetAction(name: "astation", hosts: ["host-a"], ops: ["message"], signedAt: 1) }
            try throwsCode("bad_project") { _ = try projectSetAction(name: "Astation", hosts: two, ops: ["message"], signedAt: 1) }
            try throwsCode("bad_project") { _ = try projectSetAction(name: "astation", hosts: two, ops: ["notify", "prompt"], signedAt: 1) }
            try throwsCode("bad_project") { _ = try projectRemoveAction(name: "Bad Name", signedAt: 1) }
            try throwsCode("malformed") { _ = try hostSenderRevokeAction(hostId: "Not an id", interruptRunning: false, signedAt: 1) }
            try throwsCode("malformed") { _ = try hostSenderReadmitAction(hostId: "", signedAt: 1) }
            let ek = o(o(byLabel["EK7_set"]!["entry"])["body"])
            let hostA = PublicKeyData(alg: .ed25519, raw: unhex(s(key("host-a", "host_key")["pub_hex"])))
            try throwsCode("wrong_alg") { _ = try hostEncKeyAction(hostId: "host-a", hostTrustGen: 1, encKey: hostA, encSigB64u: s(ek["enc_sig"]), retirePrevious: false, signedAt: 1) }
            try throwsCode("malformed") { _ = try hostEncKeyAction(hostId: "host-a", hostTrustGen: 1, encKey: encKeyOf(ek["enc_key"]), encSigB64u: "AAAA", retirePrevious: false, signedAt: 1) }
            try throwsCode("malformed") { _ = try hostEncKeyAction(hostId: "host-a", hostTrustGen: 1, encKey: encKeyOf(ek["enc_key"]), encSigB64u: s(ek["enc_sig"]) + "=", retirePrevious: false, signedAt: 1) }
        }
        check("device-list actions: verifyHostEncSig binds every field of a host's enc_sig") {
            let ek = o(o(byLabel["EK7_set"]!["entry"])["body"])
            let sig = s(ek["enc_sig"])
            func hostKey(_ name: String) -> PublicKeyData { PublicKeyData(alg: .ed25519, raw: unhex(s(key(name, "host_key")["pub_hex"]))) }
            let enc = encKeyOf(ek["enc_key"])
            func verify(_ host: PublicKeyData, _ acct: String, _ genesisHex: String, _ hostId: String, _ gen: UInt64, _ encKey: PublicKeyData, _ signature: String) -> Bool {
                verifyHostEncSig(hostKey: host, accountId: acct, genesisHash: genesisHex, hostId: hostId, hostTrustGen: gen, encKey: encKey, encSigB64u: signature)
            }
            try eq(verify(hostKey("host-a"), account, genesis, "host-a", 1, enc, sig), true)
            try eq(verify(hostKey("host-b"), account, genesis, "host-a", 1, enc, sig), false, "another host's key")
            try eq(verify(hostKey("host-a"), "acct-other", genesis, "host-a", 1, enc, sig), false, "account")
            try eq(verify(hostKey("host-a"), account, String(repeating: "00", count: 32), "host-a", 1, enc, sig), false, "genesis")
            try eq(verify(hostKey("host-a"), account, genesis, "host-b", 1, enc, sig), false, "host id")
            try eq(verify(hostKey("host-a"), account, genesis, "host-a", 2, enc, sig), false, "generation")
            try eq(verify(hostKey("host-a"), account, genesis, "host-a", 1, encKeyOf(o(o(byLabel["EK8_rotate"]!["entry"])["body"])["enc_key"]), sig), false, "key")
            let p256 = PublicKeyData(alg: .p256, raw: unhex(s(key("dev-mac", "auth")["pub_hex"])))
            try eq(verify(p256, account, genesis, "host-a", 1, enc, sig), false, "a P-256 host key")
            try eq(verify(hostKey("host-a"), account, genesis, "host-a", 1, PublicKeyData(alg: .ed25519, raw: enc.raw), sig), false, "an Ed25519 enc_key")
            try eq(verify(hostKey("host-a"), account, "not hex", "host-a", 1, enc, sig), false, "a malformed genesis")
            try eq(verify(hostKey("host-a"), account, genesis, "host-a", 1, enc, "AAAA"), false, "a short signature")
            // Every enc_sig of the vectors whose binding fields parse (they carry
            // enc_sig_input_hex) verifies under the host key of its generation, but the bad one.
            for v in delegated.filter({ $0["enc_sig_input_hex"] != nil }) {
                let b = o(o(v["entry"])["body"])
                let gen = u(b["host_trust_gen"])
                try eq(verify(hostKey(hostKeyName(s(b["host_id"]), gen)), account, genesis, s(b["host_id"]), gen, encKeyOf(b["enc_key"]), s(b["enc_sig"])),
                       (v["reason"] as? String) != "bad_enc_sig", s(v["label"]))
            }
        }
        check("device-list actions: a manager signs each under a purpose that names it (R9.6 rule 4)") {
            #if canImport(CryptoKit)
            let mac = CryptoKitKeys()
            try mac.addP256("dev-mac/auth", secret: unhex(s(key("dev-mac", "auth")["secret_hex"])))
            // L plus host-b (P7_add_host_b), so a project can list two hosts.
            let log = try logAfter(["P7_add_host_b"])
            let ek = o(o(byLabel["EK7_set"]!["entry"])["body"])
            let at: UInt64 = 1_793_620_800_000
            let setAction = try projectSetAction(name: "astation", hosts: ["host-b", "host-a"], ops: ["prompt", "message"], signedAt: at + 8000)
            let revokeAction = try hostSenderRevokeAction(hostId: "host-b", interruptRunning: true, signedAt: at + 9000)
            let readmitAction = try hostSenderReadmitAction(hostId: "host-b", signedAt: at + 10000)
            let encAction = try hostEncKeyAction(hostId: "host-a", hostTrustGen: 1, encKey: encKeyOf(ek["enc_key"]), encSigB64u: s(ek["enc_sig"]), retirePrevious: false, signedAt: at + 11000)
            let removeAction = try projectRemoveAction(name: "astation", signedAt: at + 12000)
            let steps: [(String, SigningPurpose, String)] = [
                (setAction, .project, "project_set"),
                (revokeAction, .hostSender, "host_sender_revoke"),
                (readmitAction, .hostSender, "host_sender_readmit"),
                (encAction, .hostEncKey, "host_enc_key"),
                (removeAction, .project, "project_remove"),
            ]
            for (action, purpose, name) in steps {
                try eq(try log.checkChange(actionJson: action, nowMs: at), nil, name)
                let body = try log.draftEntry(signer: "dev-mac", signedAt: at, actionJson: action)
                let p = EntryPublisher()
                try p.prepare(log: log, bodyJson: body)
                _ = try p.sign(provider: mac, keyId: "dev-mac/auth", cosignKit: nil)
                guard let sent = mac.requests.last else { throw Failure(description: "\(name): no signing request") }
                try eq(sent.purpose, purpose, name)
                try eq(sent.freshConfirmation, true, "\(name): a fresh confirmation")
                try eq(sent.bodyJson, body, "\(name): the confirmed body")
                try eq(sent.label, "atem-membership-entry-v1", name)
                guard case .committed = try p.replyStored(log: log, now: now) else { throw Failure(description: "\(name): not committed") }
            }
            try eq(log.head().seq, 12)
            try eq(log.projects().isEmpty, true)
            try eq(log.hostSenderState(hostId: "host-b"), .authorized(generation: 10))
            let keysOf = log.hostEncKey(hostId: "host-a")!
            try eq(keysOf.current.encKid, try encKid(encKey: encKeyOf(ek["enc_key"])))
            try eq(keysOf.previous, nil)
            #endif
        }

        // ---------------------------- delegated host work: control records
        // r9-vectors-host-work-control: every record parses and verifies on
        // each of its chains as `checks` says (or its parse refuses it,
        // `parse_error`); the builders reproduce it byte for byte (a software
        // store, or the signing input and a signature); every sequence runs
        // through a ControlStateHandle with each step's per-effect results and
        // the state it leaves (a handle never changes, so a failed commit
        // loses no effect); and a provider is asked under the purpose the
        // record's signer gives.
        let ctl = try load("r9-vectors-host-work-control")
        let ctlRecords = a(ctl["records"]).map(o)
        var ctlByLabel: [String: [String: Any]] = [:]
        for r in ctlRecords { ctlByLabel[s(r["label"])] = r }
        let controlFields: Set<String> = ["type", "v", "account_id", "genesis_hash", "origin", "feed_id", "principal", "principal_key",
                                          "signer", "action", "interrupt_running", "revoke_seq", "record_id", "issued_at", "about"]
        // The typed body of a record's body JSON (nil: a field the body doesn't have).
        func controlBodyOf(_ b: [String: Any]) -> ControlRecordBody? {
            if !Set(b.keys).isSubset(of: controlFields) { return nil }
            let about = o(b["about"])
            return ControlRecordBody(
                accountId: s(b["account_id"]), genesisHash: s(b["genesis_hash"]),
                origin: b["origin"] as? String, feedId: b["feed_id"] as? String,
                principal: s(b["principal"]), principalKey: b["principal_key"] as? String,
                signer: s(b["signer"]), action: s(b["action"]),
                interruptRunning: b["interrupt_running"] as? Bool,
                revokeSeq: (b["revoke_seq"] as? NSNumber)?.uint64Value,
                recordId: s(b["record_id"]), issuedAt: u(b["issued_at"]),
                integrationId: about["integration_id"] as? String, by: s(about["by"]))
        }
        // A test key by name: a member's auth key, or a host's host_key.
        func testKeyOf(_ name: String) -> (KeyAlg, Data, Data) {
            let entry = o(keys[name])
            let k = o(entry["auth"] ?? entry["host_key"])
            let alg: KeyAlg = s(k["alg"]) == "p256" ? .p256 : .ed25519
            return (alg, unhex(s(k["pub_hex"])), unhex(s(k["secret_hex"])))
        }
        func verdictOf(_ chain: Any, _ got: ControlCheckInfo) -> [String: Any] {
            switch got {
            case let .valid(signer, keySeq, _):
                var v: [String: Any] = ["chain": chain, "verdict": "valid", "signer": signer]
                if let seq = keySeq { v["key_seq"] = seq }
                return v
            case let .pending(reason):
                return ["chain": chain, "verdict": "pending", "reason": reason]
            case let .refused(reason):
                return ["chain": chain, "verdict": "refused", "reason": reason]
            }
        }
        check("control records: every record parses and verifies on its chains as the vectors say") {
            var verdicts = 0
            let svc = o(o(o(ctl["services"])["svc-discord"])["auth_key"])
            for r in ctlRecords {
                let label = s(r["label"])
                let json = js(r["record"]!)
                if let parseError = r["parse_error"] as? String {
                    try throwsCode(parseError) { _ = try parseControlRecord(recordJson: json) }
                    try throwsCode(parseError) { _ = try verifyControlRecord(log: try logL(), recordJson: json) }
                    continue
                }
                try eq(try parseControlRecord(recordJson: json), controlBodyOf(o(o(r["record"])["body"])), "\(label) body")
                let info = try signedObjectInfo(json: json)
                try eq(info.bodyJcs, s(r["jcs"]), label)
                try eq(hex(info.signingInput), s(r["signing_input_hex"]), label)
                try eq(hex(signingInput(label: .hostWorkControl, payload: utf8(s(r["jcs"])))), s(r["signing_input_hex"]), label)
                let checks = a(r["checks"]).map(o)
                if let r9 = r["r9_svc"] as? String {
                    try eq(try serviceKeyFingerprint(authKey: PublicKeyData(alg: .ed25519, raw: b64u(s(svc["pub"])))), r9, label)
                    let principalKey = s(o(o(r["record"])["body"])["principal_key"])
                    try eq(principalKey == r9, (checks[0]["reason"] as? String) != "key_mismatch", "\(label) principal_key")
                }
                for c in checks {
                    let chain = a(c["chain"]).map(s)
                    let log = try logAfter(chain)
                    let got = try verifyControlRecord(log: log, recordJson: json)
                    try eq(canon(verdictOf(a(c["chain"]), got)), canon(c), "\(label) on \(chain)")
                    if case let .valid(_, _, head) = got { try eq(head, log.head(), label) }
                    verdicts += 1
                }
            }
            if verdicts < 52 { throw Failure(description: "\(verdicts) verdicts") }
        }
        check("control records: the builders reproduce every record; a body the parse refuses is refused") {
            var built = 0
            for r in ctlRecords {
                let label = s(r["label"])
                guard let body = controlBodyOf(o(o(r["record"])["body"])) else {
                    try eq(r["parse_error"] as? String, "unknown_field", label)
                    continue
                }
                let (alg, pub, secret) = testKeyOf(s(r["signed_with"]))
                let store = SoftwareKeyStore()
                if alg == .p256 { try store.insertP256(keyId: "k", secret: secret) } else { try store.insertEd25519(keyId: "k", seed: secret) }
                if let parseError = r["parse_error"] as? String {
                    try throwsCode(parseError) { _ = try buildControlRecord(provider: store.provider(), keyId: "k", body: body) }
                    try throwsCode(parseError) { _ = try controlRecordSigningInput(body: body) }
                    continue
                }
                try eq(hex(try controlRecordSigningInput(body: body)), s(r["signing_input_hex"]), label)
                let sig = b64u(s(o(r["record"])["sig"]))
                let signer = PublicKeyData(alg: alg, raw: pub)
                if (a(r["checks"]).map(o)[0]["reason"] as? String) == "bad_signature" {
                    try throwsCode("bad_signature") { _ = try controlRecordWithSignature(body: body, signerKey: signer, signature: sig) }
                    continue
                }
                let canonical = try canonicalJson(json: js(r["record"]!))
                try eq(try controlRecordWithSignature(body: body, signerKey: signer, signature: sig), canonical, label)
                try eq(try buildControlRecord(provider: store.provider(), keyId: "k", body: body), canonical, label)
                built += 1
            }
            if built < 44 { throw Failure(description: "\(built) built") }
        }
        func controlActionOf(_ action: ControlHostAction) -> [String: Any] {
            switch action {
            case let .revoke(principal): return ["type": "revoke", "principal": principal]
            case let .hold(principal): return ["type": "hold", "principal": principal]
            case let .release(principal): return ["type": "release", "principal": principal]
            case let .interrupt(principal, revocation): return ["type": "interrupt", "principal": principal, "revocation": revocation]
            case let .cover(principal, origin, feedId): return ["type": "cover", "principal": principal, "origin": origin, "feed_id": feedId]
            }
        }
        func resultCode(_ r: ControlResultKind) -> String {
            switch r {
            case .applied: return "applied"
            case .duplicate: return "duplicate"
            case .pending: return "pending"
            case .refused: return "refused"
            }
        }
        func effectCode(_ e: ControlEffectKind) -> String {
            switch e {
            case .revocation: return "revocation"
            case .interrupt: return "interrupt"
            case .hold: return "hold"
            case .release: return "release"
            case .cover: return "cover"
            }
        }
        func controlAppliedOf(_ applied: ControlApplied) -> [String: Any] {
            let effects: [[String: Any]] = applied.effects.map { ["effect": effectCode($0.effect), "result": resultCode($0.result)] }
            return ["result": resultCode(applied.result), "effects": effects, "actions": applied.actions.map(controlActionOf), "evidence": applied.evidence]
        }
        func ctlPos(_ v: Any?) -> ControlFeedPos? {
            guard let p = v as? [String: Any] else { return nil }
            return ControlFeedPos(origin: s(p["origin"]), feedId: s(p["feed_id"]), feedSeq: u(p["feed_seq"]))
        }
        check("control records: every sequence's per-effect results and its state through ControlStateHandle") {
            for q in a(ctl["sequences"]).map(o) {
                let label = s(q["label"])
                var state = ControlStateHandle(log: try logL())
                for (i, step) in a(q["steps"]).map(o).enumerated() {
                    let record = js(ctlByLabel[s(step["record"])]!["record"]!)
                    let t = try state.apply(recordJson: record, log: try logAfter(a(step["chain"]).map(s)), pos: ctlPos(step["pos"]), hostAppliedSeq: u(step["host_applied_seq"]))
                    try eq(canon(controlAppliedOf(t.applied)), canon(o(step["expect"])), "\(label) step \(i + 1)")
                    state = t.next
                }
                let text = try canonicalJson(json: js(q["state"]!))
                try eq(state.toJson(), text, label)
                try eq(try ControlStateHandle.fromJson(log: try logL(), stateJson: text).toJson(), text, label)
            }
            // Only its own device list's state, exactly as written.
            let text = try canonicalJson(json: js(o(a(ctl["sequences"])[0])["state"]!))
            try throwsCode("account_mismatch") { _ = try ControlStateHandle.fromJson(log: try logL(), stateJson: text.replacingOccurrences(of: "\"acct-test-1\"", with: "\"acct-other\"")) }
            try throwsCode("unsupported_version") { _ = try ControlStateHandle.fromJson(log: try logL(), stateJson: text.replacingOccurrences(of: "\"v\":1", with: "\"v\":2")) }
            try throwsCode("malformed") { _ = try ControlStateHandle.fromJson(log: try logL(), stateJson: "[") }
        }
        check("control records: a failed commit loses no effect (apply leaves its handle as it was)") {
            let state = ControlStateHandle(log: try logL())
            let before = state.toJson()
            let record = js(ctlByLabel["S5_revoke_interrupt"]!["record"]!)
            let station = o(o(ctl["stations"])["A"])
            let pos = ControlFeedPos(origin: s(station["origin"]), feedId: s(station["feed_id"]), feedSeq: 1)
            let first = try state.apply(recordJson: record, log: try logL(), pos: pos, hostAppliedSeq: 6)
            try eq(first.applied.actions.count, 2)
            // The caller's transaction failed: apply again to the handle it kept.
            try eq(state.toJson(), before)
            let again = try state.apply(recordJson: record, log: try logL(), pos: pos, hostAppliedSeq: 6)
            try eq(canon(controlAppliedOf(again.applied)), canon(controlAppliedOf(first.applied)), "the same results and actions")
            try eq(again.next.toJson(), first.next.toJson())
            // Committed: the next state goes on, and the record is a duplicate.
            let after = try again.next.apply(recordJson: record, log: try logL(), pos: pos, hostAppliedSeq: 6)
            try eq(resultCode(after.applied.result), "duplicate")
        }
        check("control records: a Station's service key signs with no confirmation, a native manager's asks a fresh one") {
            #if canImport(CryptoKit)
            let station = CryptoKitKeys()
            try station.addEd25519("svc-discord/auth", seed: unhex(s(key("svc-discord", "auth")["secret_hex"])))
            try station.addP256("dev-mac/auth", secret: unhex(s(key("dev-mac", "auth")["secret_hex"])))
            let cases: [(String, String, SigningPurpose)] = [
                ("S1_cover", "svc-discord/auth", .serviceControl),
                ("S4_revoke", "svc-discord/auth", .serviceControl),
                ("M1_revoke", "dev-mac/auth", .controlRecord),
                ("H1_interrupt_7", "dev-mac/auth", .controlRecord),
            ]
            for (label, keyId, purpose) in cases {
                let r = ctlByLabel[label]!
                let made = try buildControlRecord(provider: station, keyId: keyId, body: controlBodyOf(o(o(r["record"])["body"]))!)
                guard let sent = station.requests.last else { throw Failure(description: "\(label): no signing request") }
                try eq(sent.purpose, purpose, label)
                try eq(sent.freshConfirmation, purpose == .controlRecord, label)
                try eq(sent.bodyJson, s(r["jcs"]), label)
                try eq(sent.label, "atem-host-work-control-v1", label)
                // CryptoKit's signatures are randomized: the record verifies as the vector's.
                let last = a(r["checks"]).map(o).last!
                let got = try verifyControlRecord(log: try logAfter(a(last["chain"]).map(s)), recordJson: made)
                try eq(canon(verdictOf(a(last["chain"]), got)), canon(last), label)
            }
            #endif
        }

        // ------------------------------- delegated host work: the Station's side
        // r9-control-ack-*: every acknowledgment fixture through AckLedgerHandle
        // as a Station persists it (each call's next state committed before the
        // reports go, adopted after; restarts reload the committed state;
        // replicas serialized); a call never changes its handle; the relay
        // builders and readers agree; the Portal's statuses in their classes.
        func intentOf(_ i: ReportIntentInfo) -> [String: Any] {
            let report: [String: Any]
            switch i.report {
            case let .revocationApplied(integrationId, host, recordId):
                report = ["kind": "revocation_applied", "integration_id": integrationId, "host": host, "record_id": recordId]
            case let .revoked(integrationId, outcome, pendingHosts):
                report = ["kind": "revoked", "integration_id": integrationId, "outcome": outcome, "pending_hosts": pendingHosts]
            }
            return ["not_before": i.notBefore, "report": report, "report_id": i.reportId]
        }
        func alertOf(_ alert: LedgerAlertInfo) -> [String: Any] {
            switch alert {
            case let .reportRefused(reportId): return ["kind": "report_refused", "report_id": reportId]
            case let .reportingStopped(clientId): return ["kind": "reporting_stopped", "client_id": clientId]
            case let .reportsDropped(clientId, dropped): return ["kind": "reports_dropped", "client_id": clientId, "dropped": dropped]
            }
        }
        func answerOf(_ answer: ReportAnswerKind) -> String {
            switch answer {
            case .confirm: return "confirm"
            case .retry: return "retry"
            case .refuse: return "refuse"
            case .stopReporting: return "stop_reporting"
            }
        }
        func linkOf(_ v: Any?) -> LinkAssociationInfo {
            let l = o(v)
            return LinkAssociationInfo(accountId: s(l["account_id"]), genesisHash: s(l["genesis_hash"]), hostId: s(l["host_id"]),
                                       hostTrustGen: u(l["host_trust_gen"]), connectionId: s(l["connection_id"]))
        }
        func ctlRecord(_ label: String) -> String { js(ctlByLabel[label]!["record"]!) }
        let ackNames = try FileManager.default.contentsOfDirectory(atPath: dir.path)
            .filter { $0.hasPrefix("r9-control-ack-") && $0.hasSuffix(".json") }
            .map { String($0.dropLast(5)) }
            .sorted()
        for name in ackNames {
            check("Station acks: \(name) through AckLedgerHandle") {
                try eq(ackNames.count, 5, "the acknowledgment fixtures")
                let f = try load(name)
                let setup = o(f["setup"])
                let st = o(setup["station"])
                let links = o(setup["links"])
                var ledger = try AckLedgerHandle(origin: s(st["origin"]), accountId: s(st["account_id"]), genesisHash: s(st["genesis_hash"]))
                var committed = ledger.toJson()
                var now = u(setup["station_now_ms"])
                var clientId = setup["report_client_id"] as? String
                func input(_ on: AckLedgerHandle, _ step: [String: Any]) throws -> AckTransition? {
                    if let label = step["control_record"] {
                        let at = step["revoked_at_ms"].map { u($0) } ?? now
                        return try on.record(recordJson: ctlRecord(s(label)), revokedAtMs: at, coveredHosts: a(step["covered_hosts"]).map(s), nowMs: now)
                    }
                    if let message = step["control_ack"] {
                        let link = linkOf(links[s(step["link"])])
                        if let refused = step["refused"] {
                            try throwsCode(s(refused)) { _ = try on.ack(link: link, ackJson: js(message), nowMs: now) }
                            return nil
                        }
                        return try on.ack(link: link, ackJson: js(message), nowMs: now)
                    }
                    if step["tick"] != nil { return on.tick(nowMs: now) }
                    throw Failure(description: "not an input: \(canon(step))")
                }
                func made(_ t: AckTransition, _ step: [String: Any]) throws {
                    try eq(t.made.map { $0.reportId }, a(step["made"]).map(s), "\(name) made")
                    try eq(t.alerts, [LedgerAlertInfo](), "\(name) alerts")
                }
                func commit(_ t: AckTransition) {
                    committed = t.next.toJson()
                    ledger = t.next
                }
                func sendable(_ id: String) throws {
                    if !ledger.pendingReports().contains(where: { $0.reportId == id }) {
                        throw Failure(description: "\(id) is not sendable")
                    }
                }
                for step in a(f["steps"]).map(o) {
                    if step["control_record"] != nil || step["control_ack"] != nil || step["tick"] != nil {
                        if let t = try input(ledger, step) {
                            try made(t, step)
                            if (step["commit"] as? Bool) != false { commit(t) }
                        }
                    } else if let inner = step["replica"].map(o) {
                        let t1 = try input(try AckLedgerHandle.fromJson(stateJson: committed), inner)!
                        let t2 = try input(try AckLedgerHandle.fromJson(stateJson: committed), inner)!
                        try eq(t1.next.toJson(), t2.next.toJson(), "\(name) replicas' states")
                        try eq(t1.made, t2.made, "\(name) replicas' intents")
                        try made(t1, inner)
                        commit(t1)
                        let lost = try input(try AckLedgerHandle.fromJson(stateJson: committed), inner)!
                        try eq(lost.made, [ReportIntentInfo](), "\(name) the replica that lost")
                    } else if let ms = step["advance_ms"] {
                        now += u(ms)
                    } else if step["restart"] != nil {
                        ledger = try AckLedgerHandle.fromJson(stateJson: committed)
                        try eq(ledger.toJson(), committed, "\(name) restart")
                    } else if let want = step["expect_report"] {
                        try eq(canon(ledger.pendingReports().map(intentOf)), canon(want), "\(name) reports")
                    } else if let id = step["confirm"] {
                        try sendable(s(id))
                        commit(ledger.confirm(reportId: s(id)))
                    } else if let fl = step["report_failure"].map(o) {
                        let id = s(fl["report_id"])
                        try sendable(id)
                        let answer = fl["status"] is String ? "retry" : answerOf(reportAnswer(status: UInt16(u(fl["status"]))))
                        try eq(answer, s(fl["answer"]), "\(name) answer")
                        let t: AckTransition?
                        switch answer {
                        case "refuse": t = ledger.refuse(reportId: id)
                        case "stop_reporting": t = try ledger.stopReporting(clientId: clientId!)
                        default: t = nil
                        }
                        let alerts: [[String: Any]] = t?.alerts.map(alertOf) ?? []
                        try eq(canon(alerts), canon(fl["alerts"] ?? [Any]()), "\(name) alerts")
                        if let t = t { commit(t) }
                    } else if let labels = step["expect_resign_alerts"] {
                        let want = a(labels).map { s(o(o(ctlByLabel[s($0)]!["record"])["body"])["record_id"]) }.sorted()
                        try eq(ledger.resignAlerts(), want, "\(name) resign alerts")
                    } else if let want = step["expect_dropped"] {
                        try eq(ledger.droppedReports(), a(want).map(s), "\(name) dropped")
                    } else if let want = step["expect_refused"] {
                        try eq(ledger.refusedReports(), a(want).map(s), "\(name) refused")
                    } else if let id = step["resume_reporting"] {
                        clientId = s(id)
                        let t = try ledger.resumeReporting(clientId: s(id))
                        try eq(canon(t.alerts.map(alertOf)), canon(step["alerts"]!), "\(name) resume alerts")
                        try eq(t.made, [ReportIntentInfo](), "\(name) resume")
                        commit(t)
                    } else if let want = step["expect_stopped"] {
                        // The stopped report client ID, or false.
                        let id = want as? String
                        if id == nil { try eq(want as! Bool, false, "\(name) stopped") }
                        try eq(ledger.stoppedClientId(), id, "\(name) stopped")
                        try eq(ledger.reportingStopped(), id != nil, "\(name) stopped")
                    } else if step["expect_portal"] == nil {
                        // expect_portal is the Portal's side: no Portal model here.
                        throw Failure(description: "unknown step \(canon(step))")
                    }
                }
            }
        }
        check("Station acks: a call never changes its handle; the state loads only as written") {
            let f = try load("r9-control-ack-per-effect")
            let setup = o(f["setup"])
            let st = o(setup["station"])
            let linkB = linkOf(o(setup["links"])["host-b"])
            let nowMs: UInt64 = 1_793_620_940_000
            let l = try AckLedgerHandle(origin: s(st["origin"]), accountId: s(st["account_id"]), genesisHash: s(st["genesis_hash"]))
                .record(recordJson: ctlRecord("S4_revoke"), revokedAtMs: 1_793_620_903_000, coveredHosts: ["host-b", "host-c"], nowMs: nowMs).next
            let before = l.toJson()
            let ack = js(o(a(f["steps"])[6])["control_ack"]!)
            let t1 = try l.ack(link: linkB, ackJson: ack, nowMs: nowMs)
            let t2 = try l.ack(link: linkB, ackJson: ack, nowMs: nowMs)
            // The commit failed: the handle is as it was, and the same call again gives the same.
            try eq(l.toJson(), before)
            try eq(t1.next.toJson(), t2.next.toJson())
            try eq(t1.made, t2.made)
            try eq(t1.made.count, 1)
            let id = t1.made[0].reportId
            try eq(t1.next.refuse(reportId: id).alerts, [LedgerAlertInfo.reportRefused(reportId: id)])
            try eq(t1.next.pendingReports().count, 1)
            let stopped = try t1.next.stopReporting(clientId: "station-1").next
            try eq(stopped.reportingStopped(), true)
            try eq(stopped.stoppedClientId(), "station-1")
            try eq(stopped.pendingReports(), [ReportIntentInfo]())
            try eq(t1.next.reportingStopped(), false)
            // The same report client ID keeps every report; another drops them.
            try eq(try stopped.resumeReporting(clientId: "station-1").next.pendingReports(), t1.next.pendingReports())
            let other = try stopped.resumeReporting(clientId: "station-2")
            try eq(other.alerts, [LedgerAlertInfo.reportsDropped(clientId: "station-1", dropped: [id])])
            try eq(other.next.droppedReports(), [id])
            try eq(other.next.droppedClientIds(), ["station-1"])
            try throwsCode("malformed") { _ = try l.stopReporting(clientId: "a b") }
            let text = t1.next.toJson()
            try eq(try AckLedgerHandle.fromJson(stateJson: text).toJson(), text)
            try throwsCode("malformed") { _ = try AckLedgerHandle.fromJson(stateJson: "[") }
            try throwsCode("unsupported_version") { _ = try AckLedgerHandle.fromJson(stateJson: text.replacingOccurrences(of: "\"v\":1", with: "\"v\":2")) }
            try throwsCode("stored_invalid") { _ = try AckLedgerHandle.fromJson(stateJson: "{\"extra\":1," + text.dropFirst()) }
            try throwsCode("malformed") { _ = try AckLedgerHandle(origin: "https://Station-dev.agora.build/", accountId: s(st["account_id"]), genesisHash: s(st["genesis_hash"])) }
            var noConnection = linkB
            noConnection.connectionId = ""
            try throwsCode("incomplete_link") { _ = try l.ack(link: noConnection, ackJson: ack, nowMs: nowMs) }
            try throwsCode("not_the_link") { _ = try l.ack(link: linkB, ackJson: ack.replacingOccurrences(of: "host-b", with: "host-c"), nowMs: nowMs) }
            try throwsCode("unknown_field") { _ = try l.record(recordJson: ctlRecord("P4_unknown_field"), revokedAtMs: 0, coveredHosts: [], nowMs: nowMs) }
        }
        check("Station calls: fixture acks read and write back; pages, heads and fetches round-trip; builders refuse what readers refuse") {
            for name in ackNames {
                for step in a(try load(name)["steps"]).map(o) {
                    let inner = step["replica"].map(o) ?? step
                    guard let msg = inner["control_ack"] else { continue }
                    guard case let .controlAck(ack) = try relayDecodeToStation(message: js(msg)) else {
                        throw Failure(description: "\(name): not an ack")
                    }
                    try eq(try canonicalJson(json: relayControlAck(ack: ack)), try canonicalJson(json: js(msg)), name)
                }
            }
            let station = o(o(ctl["stations"])["A"])
            let origin = s(station["origin"])
            let feed = s(station["feed_id"])
            try eq(try relayDecodeToStation(message: relayControlSync(origin: origin, feedId: feed, after: 7)), .controlSync(origin: origin, feedId: feed, after: 7))
            try eq(try relayDecodeToStation(message: relayControlSync(origin: origin, feedId: nil, after: 0)), .controlSync(origin: origin, feedId: nil, after: 0))
            try throwsCode("malformed") { _ = try relayControlSync(origin: origin, feedId: nil, after: 5) }
            let page = ["S1_cover", "S4_revoke", "M1_revoke"].enumerated().map {
                RelayFeedRecord(feedSeq: UInt64($0.offset + 1), recordJson: ctlRecord($0.element))
            }
            guard case let .controlSyncResult(_, _, _, _, records) = try relayDecodeToHost(message: relayControlSyncResult(origin: origin, feedId: feed, head: 3, stationTime: 1_793_620_940_000, records: page)) else {
                throw Failure(description: "not a page")
            }
            try eq(try records.map { try canonicalJson(json: $0.recordJson) }, try page.map { try canonicalJson(json: $0.recordJson) })
            var refusedPage = page
            refusedPage[1] = RelayFeedRecord(feedSeq: 2, recordJson: ctlRecord("P4_unknown_field"))
            try throwsCode("unknown_field") { _ = try relayControlSyncResult(origin: origin, feedId: feed, head: 3, stationTime: 0, records: refusedPage) }
            try throwsCode("malformed") { _ = try relayControlSyncResult(origin: origin, feedId: feed, head: 2, stationTime: 0, records: page) }
            let heads = [RelayFeedHead(origin: origin, feedId: feed, head: 3, stationTime: 1_793_620_940_000)]
            let hm = try relayHeads(feeds: heads, membership: mlogHead)
            try eq(try relayDecodeToHost(message: hm), .heads(feeds: heads, membership: mlogHead))
            var withMailbox = o(try JSONSerialization.jsonObject(with: Data(hm.utf8)))
            withMailbox["mailbox"] = ["mailbox_id": feed, "head": 1] as [String: Any]
            try throwsCode("unknown_field") { _ = try relayDecodeToHost(message: js(withMailbox)) }
            try eq(try relayDecodeToStation(message: relayMembershipFetch(after: 2)), .membershipFetch(after: 2))
            let entries = ["E3", "E4", "E5", "E6"].map(entry)
            guard case let .membershipFetchResult(fetchedHead, fetched) = try relayDecodeToHost(message: relayMembershipFetchResult(head: mlogHead, entries: entries)) else {
                throw Failure(description: "not a fetch result")
            }
            try eq(fetchedHead, mlogHead)
            try eq(try fetched.map { try canonicalJson(json: $0) }, try entries.map { try canonicalJson(json: $0) })
            try throwsCode("wrong_message") { _ = try relayDecodeToHost(message: relayControlSync(origin: origin, feedId: nil, after: 0)) }
            try throwsCode("wrong_message") { _ = try relayDecodeToStation(message: "{\"type\":\"relay\",\"op\":\"push_hint\",\"hints\":[]}") }
            try throwsCode("not_strict") { _ = try relayDecodeToStation(message: "{") }
        }
        check("Station: the Portal's statuses in their classes") {
            let want: [(UInt16, String)] = [(200, "confirm"), (401, "retry"), (408, "retry"), (429, "retry"), (500, "retry"), (503, "retry"),
                                            (400, "refuse"), (404, "refuse"), (409, "refuse"), (413, "refuse"), (415, "refuse"),
                                            (204, "refuse"), (302, "refuse"), (403, "stop_reporting")]
            for (status, answer) in want { try eq(answerOf(reportAnswer(status: status)), answer, "\(status)") }
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

        let pairing = o(try load("r9-vectors-pairing"))
        check("verifyCommit host_trust_gen (r9-vectors-pairing)") {
            // The binding's reader, never JSONDecoder (it takes 3.0 as Int).
            let commits = o(pairing["verify_commit"])
            for c in a(commits["valid"]).map(o) {
                try eq(try verifyCommitHostTrustGen(messageJson: s(c["raw"])), u(c["host_trust_gen"]), s(c["case"]))
            }
            for c in a(commits["invalid"]).map(o) {
                do {
                    _ = try verifyCommitHostTrustGen(messageJson: s(c["raw"]))
                    throw Failure(description: "\(s(c["case"])) was accepted")
                } catch AtemError.Invalid {
                }
            }
        }

        print("swift conformance: \(passed) passed, \(failures.count) failed")
        for f in failures { print("FAIL \(f)") }
        XCTAssertEqual(failures, [], "conformance failures")
        XCTAssertEqual(passed, 59)
    }
}
