// The shared r9 vectors (designs/protocol/fixtures/r9-vectors-*.json) and the
// host-work prompt-framing vectors (fixtures/host-work/prompt-framing-v1.json,
// framing-size-v1.json) run through the Swift binding, the same checks as the
// Kotlin (bindings/kotlin/Conformance.kt) and WASM
// (bindings/js/conformance.mjs) runs. ATEM_FIXTURES names the fixtures
// directory.
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

private func sha256Hex(_ text: String) -> String { hex(Data(SHA256.hash(data: Data(text.utf8)))) }

// A tag's 60 bits as written (XXXX-XXXX-XXXX, Crockford base32).
private func tagBitsOf(_ tag: String) -> UInt64 {
    let crockford = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    return tag.filter { $0 != "-" }.reduce(UInt64(0)) { bits, c in (bits << 5) | UInt64(crockford.firstIndex(of: c)!) }
}

// The lines of a text (a line ends at LF, CR, VT, FF, NEL, U+2028 or U+2029,
// taken per scalar: Swift's own Character view joins CR LF) without the `|`s
// each starts with: what the marker check is given, as the escaping does.
private func linesWithoutLeadingBars(_ text: String) -> [String] {
    var lines: [String] = []
    var current = String.UnicodeScalarView()
    var leading = true
    for c in text.unicodeScalars {
        switch c.value {
        case 0x0A, 0x0D, 0x0B, 0x0C, 0x85, 0x2028, 0x2029:
            lines.append(String(current))
            current = String.UnicodeScalarView()
            leading = true
        case 0x7C where leading:
            break
        default:
            leading = false
            current.append(c)
        }
    }
    lines.append(String(current))
    return lines
}

// `rendered` with `old` swapped for `fresh` at the start of every line (a
// line ends at "\n" only), byte for byte: Swift's String equality is
// canonical equivalence, so what is compared is UTF-8.
private func retagged(_ rendered: String, from old: String, to fresh: String) -> [UInt8] {
    let bytes = Array(rendered.utf8)
    let oldBytes = Array(old.utf8)
    let freshBytes = Array(fresh.utf8)
    var out: [UInt8] = []
    var atLineStart = true
    var i = 0
    while i < bytes.count {
        if atLineStart && bytes[i...].starts(with: oldBytes) {
            out.append(contentsOf: freshBytes)
            i += oldBytes.count
            atLineStart = false
        } else {
            out.append(bytes[i])
            atLineStart = bytes[i] == 0x0A
            i += 1
        }
    }
    return out
}

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

// How the vector files are decoded. Apple's JSONSerialization builds each
// string value through NSString, which takes a U+FEFF that starts the value
// for a byte order mark and drops it: a vector text such as
// "\u{FEFF}[atem] byte order mark" would reach the binding without its first
// scalar (the binding itself keeps it: UniFFI lowers and lifts strings as
// plain UTF-8). So every U+FEFF in a file (the bytes EF BB BF, or a \uFEFF
// escape) is swapped for U+E000 before parsing, a private-use scalar the
// vector files never contain (a file that does is refused), and swapped back
// in the decoded strings and keys by Swift's own String, which keeps it. A
// file without a U+FEFF is parsed as it is.
private func decodeVectors(_ data: Data) throws -> Any {
    let bytes = [UInt8](data)
    var swapped: [UInt8] = []
    swapped.reserveCapacity(bytes.count)
    var found = false
    var i = 0
    while i < bytes.count {
        let b = bytes[i]
        if b == 0xEF, i + 2 < bytes.count, bytes[i + 1] == 0xBB, bytes[i + 2] == 0xBF {
            swapped += [0xEE, 0x80, 0x80]
            found = true
            i += 3
        } else if b == 0xEE, i + 2 < bytes.count, bytes[i + 1] == 0x80, bytes[i + 2] == 0x80 {
            throw Failure(description: "a vector file holds U+E000, the stand-in for U+FEFF")
        } else if b == 0x5C, i + 1 < bytes.count {
            // A backslash and the byte it escapes (an escaped backslash is no
            // start of an escape); \uFEFF in either case.
            if bytes[i + 1] == 0x75, i + 5 < bytes.count,
               (bytes[i + 2] | 0x20) == 0x66, (bytes[i + 3] | 0x20) == 0x65,
               (bytes[i + 4] | 0x20) == 0x66, (bytes[i + 5] | 0x20) == 0x66 {
                swapped += [0xEE, 0x80, 0x80]
                found = true
                i += 6
            } else {
                swapped += [b, bytes[i + 1]]
                i += 2
            }
        } else {
            swapped.append(b)
            i += 1
        }
    }
    let parsed = try JSONSerialization.jsonObject(with: Data(swapped))
    return found ? restoringBOM(parsed) : parsed
}

private func restoringBOM(_ v: Any) -> Any {
    switch v {
    case let text as String:
        return restoringBOM(inString: text)
    case let object as [String: Any]:
        var out: [String: Any] = [:]
        for (key, value) in object { out[restoringBOM(inString: key)] = restoringBOM(value) }
        return out
    case let array as [Any]:
        return array.map { restoringBOM($0) }
    default:
        return v
    }
}

private func restoringBOM(inString text: String) -> String {
    let standIn: Unicode.Scalar = "\u{E000}"
    let bom: Unicode.Scalar = "\u{FEFF}"
    guard text.unicodeScalars.contains(standIn) else { return text }
    var scalars = String.UnicodeScalarView()
    for c in text.unicodeScalars { scalars.append(c == standIn ? bom : c) }
    return String(scalars)
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
            o(try decodeVectors(Data(contentsOf: dir.appendingPathComponent("\(name).json"))))
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
        let svcFp = o(try decodeVectors(Data(contentsOf: dir.appendingPathComponent("../../../crates/atem-client/vectors/r9-svc-fingerprint.json"))))
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
            try throwsCode("malformed") { _ = try relayControlSyncResult(origin: origin, feedId: feed, head: 3, stationTime: 0, records: [page[1], page[0]]) }
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
        check("Station calls: the three refusals exactly and read strictly; a stale-association ack refused without disclosure or ledger advance") {
            let refusals: [((RelayRefusalCode) throws -> String, String, RelayToHost)] = [
                ({ try relayControlSyncRefused(code: $0) }, "control_sync_refused", .controlSyncRefused(code: .forbidden)),
                ({ try relayMembershipFetchRefused(code: $0) }, "membership_fetch_refused", .membershipFetchRefused(code: .forbidden)),
                ({ try relayControlAckRefused(code: $0) }, "control_ack_refused", .controlAckRefused(code: .forbidden)),
            ]
            for (build, op, want) in refusals {
                let msg = try build(.forbidden)
                try eq(try canonicalJson(json: msg), try canonicalJson(json: js(["type": "relay", "op": op, "code": "forbidden"])), op)
                try eq(try relayDecodeToHost(message: msg), want, op)
                try throwsCode("wrong_message") { _ = try relayDecodeToStation(message: msg) }
                let bad: [(String, String)] = [
                    ("\"code\":\"not_found\"", "malformed"),
                    ("\"code\":null", "malformed"),
                    ("\"code\":\"forbidden\",\"feed_id\":\"x\"", "unknown_field"),
                    ("\"code\":\"forbidden\",\"code\":\"forbidden\"", "not_strict"),
                ]
                for (fields, code) in bad {
                    try throwsCode(code) { _ = try relayDecodeToHost(message: "{\"type\":\"relay\",\"op\":\"\(op)\",\(fields)}") }
                }
            }
            // A stale association: the link was verified at trust generation 2, the ack claims 1.
            let f = try load("r9-control-ack-deadline")
            let setup = o(f["setup"])
            let st = o(setup["station"])
            let nowMs: UInt64 = 1_793_620_940_000
            let l = try AckLedgerHandle(origin: s(st["origin"]), accountId: s(st["account_id"]), genesisHash: s(st["genesis_hash"]))
                .record(recordJson: ctlRecord("S4_revoke"), revokedAtMs: 1_793_620_903_000, coveredHosts: ["host-b"], nowMs: nowMs).next
            let before = l.toJson()
            let ack = js(o(a(f["steps"])[1])["control_ack"]!)
            var link = linkOf(o(setup["links"])["host-b"])
            link.hostTrustGen = 2
            try throwsCode("not_the_link") { _ = try l.ack(link: link, ackJson: ack, nowMs: nowMs) }
            try eq(l.toJson(), before)
            try eq(l.pendingReports(), [ReportIntentInfo]())
            let reply = try relayControlAckRefused(code: .forbidden)
            let secrets = [s(st["account_id"]), s(st["genesis_hash"]), s(st["origin"]), "host-b",
                           s(o(o(ctlByLabel["S4_revoke"]!["record"])["body"])["record_id"])]
            for secret in secrets where reply.contains(secret) {
                throw Failure(description: "the refusal names \(secret)")
            }
            link.hostTrustGen = 1
            try eq(try l.ack(link: link, ackJson: ack, nowMs: nowMs).made.count, 2)
        }
        // r9-vectors-station-calls (host-work-v1 §11.4): every message of the six
        // Station calls and the three refusals as the builders write it, byte for
        // byte from its fields (an ack is written again from what it decoded to),
        // read back to those fields (each page record judged by
        // parseControlRecord as the file says), refused by the other side's
        // reader, and every invalid text refused with its code. A page record the
        // control parser refuses can't be built: a Station serves only what it
        // validated at intake.
        let stationCalls = try load("r9-vectors-station-calls")
        check("Station calls: the byte goldens build exactly, read back to their fields and are refused by the other side; every invalid variant is refused with its code") {
            func logHead(_ h: Any?) -> LogHead { LogHead(seq: u(o(h)["seq"]), hash: s(o(h)["hash"])) }
            func judge(_ recordJson: String) throws -> [String: Any] {
                do {
                    return ["parses": true, "record_id": try parseControlRecord(recordJson: recordJson).recordId]
                } catch let e as AtemError {
                    return ["parses": false, "error": codeOf(e).0]
                }
            }
            try eq(u(stationCalls["max_message_bytes"]), 262144)
            try eq(a(stationCalls["calls"]).count >= 20, true, "goldens")
            for c in a(stationCalls["calls"]).map(o) {
                let f = o(c["fields"])
                let wire = s(c["wire"])
                let name = s(c["name"])
                let op = s(c["op"])
                switch op {
                case "control_sync":
                    let feed = f["feed_id"] as? String
                    try eq(try relayControlSync(origin: s(f["origin"]), feedId: feed, after: u(f["after"])), wire, name)
                    try throwsCode("wrong_message") { _ = try relayDecodeToHost(message: wire) }
                    try eq(try relayDecodeToStation(message: wire), .controlSync(origin: s(f["origin"]), feedId: feed, after: u(f["after"])), name)
                case "control_sync_result":
                    let items = a(f["records"]).map(o)
                    let records = items.map { RelayFeedRecord(feedSeq: u($0["feed_seq"]), recordJson: js($0["record"]!)) }
                    let judged = a(c["judged"]).map(o)
                    let build = { try relayControlSyncResult(origin: s(f["origin"]), feedId: s(f["feed_id"]), head: u(f["head"]), stationTime: u(f["station_time"]), records: records) }
                    let handAssembled = (c["hand_assembled"] as? Bool) ?? false
                    try eq(judged.contains(where: { ($0["parses"] as! Bool) == false }), handAssembled, "\(name) hand_assembled")
                    if let refused = judged.first(where: { ($0["parses"] as! Bool) == false }) {
                        try throwsCode(s(refused["error"])) { _ = try build() }
                    } else {
                        try eq(try build(), wire, name)
                    }
                    try throwsCode("wrong_message") { _ = try relayDecodeToStation(message: wire) }
                    guard case let .controlSyncResult(origin, feedId, pageHead, stationTime, read) = try relayDecodeToHost(message: wire) else {
                        throw Failure(description: "\(name): not a page")
                    }
                    try eq(origin, s(f["origin"]), name)
                    try eq(feedId, s(f["feed_id"]), name)
                    try eq(pageHead, u(f["head"]), name)
                    try eq(stationTime, u(f["station_time"]), name)
                    try eq(read.count, items.count, "\(name) records")
                    for (i, r) in read.enumerated() {
                        try eq(r.feedSeq, u(items[i]["feed_seq"]), "\(name) feed_seq")
                        let sent = try JSONSerialization.jsonObject(with: Data(r.recordJson.utf8), options: [.fragmentsAllowed])
                        try eq(canon(sent), canon(items[i]["record"]!), "\(name) record \(i)")
                        var want = judged[i]
                        want["feed_seq"] = nil
                        try eq(canon(try judge(r.recordJson)), canon(want), "\(name) record \(i) judged")
                    }
                case "heads":
                    let feeds = a(f["feeds"]).map(o).map {
                        RelayFeedHead(origin: s($0["origin"]), feedId: s($0["feed_id"]), head: u($0["head"]), stationTime: u($0["station_time"]))
                    }
                    try eq(try relayHeads(feeds: feeds, membership: logHead(f["membership"])), wire, name)
                    try throwsCode("wrong_message") { _ = try relayDecodeToStation(message: wire) }
                    try eq(try relayDecodeToHost(message: wire), .heads(feeds: feeds, membership: logHead(f["membership"])), name)
                case "control_ack":
                    try throwsCode("wrong_message") { _ = try relayDecodeToHost(message: wire) }
                    guard case let .controlAck(ack) = try relayDecodeToStation(message: wire) else {
                        throw Failure(description: "\(name): not an ack")
                    }
                    try eq(try relayControlAck(ack: ack), wire, "\(name) written again")
                    try eq(ack.hostId, s(f["host_id"]), name)
                    try eq(ack.hostTrustGen, u(f["host_trust_gen"]), name)
                    try eq(ack.cursor, u(f["cursor"]), name)
                    try eq(ack.results.count, a(f["results"]).count, name)
                case "membership_fetch":
                    try eq(try relayMembershipFetch(after: u(f["after"])), wire, name)
                    try throwsCode("wrong_message") { _ = try relayDecodeToHost(message: wire) }
                    try eq(try relayDecodeToStation(message: wire), .membershipFetch(after: u(f["after"])), name)
                case "membership_fetch_result":
                    let entries = a(f["entries"]).map { js($0) }
                    try eq(try relayMembershipFetchResult(head: logHead(f["head"]), entries: entries), wire, name)
                    try throwsCode("wrong_message") { _ = try relayDecodeToStation(message: wire) }
                    guard case let .membershipFetchResult(fetchedHead, fetched) = try relayDecodeToHost(message: wire) else {
                        throw Failure(description: "\(name): not a fetch result")
                    }
                    try eq(fetchedHead, logHead(f["head"]), name)
                    try eq(try fetched.map { try canonicalJson(json: $0) }, try entries.map { try canonicalJson(json: $0) }, "\(name) entries")
                default:
                    let built: String
                    let want: RelayToHost
                    switch op {
                    case "control_sync_refused":
                        built = try relayControlSyncRefused(code: .forbidden)
                        want = .controlSyncRefused(code: .forbidden)
                    case "membership_fetch_refused":
                        built = try relayMembershipFetchRefused(code: .forbidden)
                        want = .membershipFetchRefused(code: .forbidden)
                    default:
                        built = try relayControlAckRefused(code: .forbidden)
                        want = .controlAckRefused(code: .forbidden)
                    }
                    try eq(built, wire, name)
                    try throwsCode("wrong_message") { _ = try relayDecodeToStation(message: wire) }
                    try eq(try relayDecodeToHost(message: wire), want, name)
                }
            }
            func textOf(_ c: [String: Any]) -> String {
                if let fill = c["wire_fill"] {
                    let w = o(fill)
                    return s(w["prefix"]) + String(repeating: s(w["fill"]), count: Int(u(w["count"]))) + s(w["suffix"])
                }
                return s(c["wire"])
            }
            // Exactly the bound is read, the same bound for every call that can carry
            // a large page; `accepts` is what it gives back.
            for c in a(stationCalls["at_the_bound"]).map(o) {
                let wire = textOf(c)
                let accepts = o(c["accepts"])
                let name = s(c["name"])
                try eq(wire.utf8.count, 262144, "\(name) bytes")
                switch try relayDecodeToHost(message: wire) {
                case let .controlSyncResult(_, _, pageHead, _, records):
                    try eq(pageHead, u(accepts["head"]), "\(name) head")
                    try eq(records.count, Int(u(accepts["records"])), "\(name) records")
                    for (r, want) in zip(records, a(accepts["records_parse"])) {
                        try eq(try judge(r.recordJson)["parses"] as! Bool, want as! Bool, "\(name) parse")
                    }
                case let .membershipFetchResult(fetchedHead, fetched):
                    try eq(fetchedHead, logHead(accepts["head"]), "\(name) head")
                    try eq(fetched.count, Int(u(accepts["entries"])), "\(name) entries")
                default:
                    throw Failure(description: "\(name): not a page or a fetch result")
                }
                try throwsCode("wrong_message") { _ = try relayDecodeToStation(message: wire) }
            }
            for bad in a(stationCalls["invalid"]).map(o) {
                let wire = textOf(bad)
                let code = s(bad["code"])
                if s(bad["reader"]) == "to_host" {
                    try throwsCode(code) { _ = try relayDecodeToHost(message: wire) }
                } else {
                    try throwsCode(code) { _ = try relayDecodeToStation(message: wire) }
                }
            }
        }
        check("Station: the Portal's statuses in their classes") {
            let want: [(UInt16, String)] = [(200, "confirm"), (401, "retry"), (408, "retry"), (429, "retry"), (500, "retry"), (503, "retry"),
                                            (400, "refuse"), (404, "refuse"), (409, "refuse"), (413, "refuse"), (415, "refuse"),
                                            (204, "refuse"), (302, "refuse"), (403, "stop_reporting")]
            for (status, answer) in want { try eq(answerOf(reportAnswer(status: status)), answer, "\(status)") }
        }

        // ------------------------------- delegated host work: envelopes and results
        // r9-vectors-host-envelope (host-work-v1 §11.5; planned, host role, feature
        // `host`): the device lists (log L and the file's `entries`), the builders
        // reproducing every `built` object byte for byte, and every check's
        // verdict through openEnvelope or acceptResult, with the plaintext an
        // open gives.
        let mail = try load("r9-vectors-host-envelope")
        var mailEntry: [String: [String: Any]] = [:]
        for e in a(mail["entries"]).map(o) { mailEntry[s(e["label"])] = e }
        var mailObject: [String: [String: Any]] = [:]
        for x in a(mail["objects"]).map(o) { mailObject[s(x["label"])] = x }
        let mailChecks = a(mail["checks"]).map(o)
        let mailNow = u(mail["now"])
        func mailList(_ chain: [String]) throws -> MembershipLog {
            let log = try logL()
            try eq(try log.extend(entries: chain.map { js(mailEntry[$0]!["entry"]!) }, now: now).stop, nil, "chain \(chain)")
            return log
        }
        // Every host key under its r9-vectors-keys name, and every host encryption key.
        func mailStore() throws -> AppKeyProvider {
            let store = SoftwareKeyStore()
            for (name, value) in keys {
                guard let parts = value as? [String: Any] else { continue }
                if let k = parts["host_key"] { try store.insertEd25519(keyId: name, seed: unhex(s(o(k)["secret_hex"]))) }
                if name.hasPrefix("host-"), let k = parts["enc"] { try store.insertX25519(keyId: name, secret: unhex(s(o(k)["secret_hex"]))) }
            }
            return store.provider()
        }
        func encKey(_ name: String) -> PublicKeyData { PublicKeyData(alg: .x25519, raw: unhex(s(key(name, "enc")["pub_hex"]))) }
        func mailHost(_ h: Any?) -> MailHostData { MailHostData(hostId: s(o(h)["host_id"]), hostTrustGen: u(o(h)["host_trust_gen"])) }
        func mailFields(_ body: Any?) -> MailFieldsData {
            let b = o(body)
            let head = o(b["signed_at_head"])
            return MailFieldsData(
                accountId: s(b["account_id"]), genesisHash: s(b["genesis_hash"]), sender: mailHost(b["sender"]), recipient: mailHost(b["recipient"]),
                encKid: s(o(b["recipient"])["enc_kid"]), id: s(b["id"]), createdAt: u(b["created_at"]), expiresAt: u(b["expires_at"]),
                signedAtHead: LogHead(seq: u(head["seq"]), hash: s(head["hash"])))
        }
        func mailRecipient(_ r: Any?) throws -> MailRecipientData {
            let x = o(r)
            let keyRefs = try a(x["keys"]).map { MailKeyData(keyId: s($0), encKid: try encKid(encKey: encKey(s($0)))) }
            return MailRecipientData(hostId: s(x["host_id"]), hostTrustGen: u(x["host_trust_gen"]), keys: keyRefs)
        }
        func mailOutbox(_ v: Any?) -> MailOutboxData {
            let x = o(v)
            return MailOutboxData(recipient: mailHost(x["recipient"]), messageId: s(x["message_id"]), cancelCompleteIds: a(x["cancel_complete_ids"]).map(s), taskIds: a(x["task_ids"]).map(s))
        }
        func sha256Hex(_ text: String) -> String { SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined() }
        // A verdict as `expect` writes it; an open's plaintext against the object's.
        func mailExpect(_ c: [String: Any], _ verdict: [String: Any], _ plain: String?) throws {
            let label = s(c["label"])
            try eq(canon(verdict), canon(o(c["expect"])), label)
            guard let plain = plain else { return }
            let sealed = o(mailObject[s(c["object"])]!["sealed"])
            if let text = sealed["plaintext"] {
                try eq(plain, s(text), label)
            } else {
                try eq(UInt64(Data(plain.utf8).count), u(sealed["plaintext_bytes"]), label)
                try eq(sha256Hex(plain), s(sealed["plaintext_sha256"]), label)
            }
        }
        func envelopeVerdict(_ got: EnvelopeVerdictInfo) -> ([String: Any], String?) {
            switch got {
            case let .open(plainJson, sender): return (["verdict": "open", "sender": sender], plainJson)
            case let .pending(hostId, hostTrustGen): return (["verdict": "pending", "host_id": hostId, "host_trust_gen": hostTrustGen], nil)
            case let .refused(reason, evidence): return (["verdict": "refused", "reason": reason, "evidence": evidence], nil)
            case let .refusedAuthenticated(objectId, reason): return (["verdict": "refused_authenticated", "object_id": objectId, "reason": reason], nil)
            case let .unavailable(code, detail): return (["verdict": "unavailable", "code": code, "detail": detail], nil)
            }
        }
        func resultVerdict(_ got: ResultVerdictInfo) -> ([String: Any], String?) {
            switch got {
            case let .accepted(plainJson, sender): return (["verdict": "accepted", "sender": sender], plainJson)
            case let .notDelivered(plainJson, sender, reason): return (["verdict": "not_delivered", "sender": sender, "reason": reason], plainJson)
            case let .pending(hostId, hostTrustGen): return (["verdict": "pending", "host_id": hostId, "host_trust_gen": hostTrustGen], nil)
            case let .refused(reason, evidence): return (["verdict": "refused", "reason": reason, "evidence": evidence], nil)
            case let .refusedAuthenticated(objectId, reason): return (["verdict": "refused_authenticated", "object_id": objectId, "reason": reason], nil)
            case let .unavailable(code, detail): return (["verdict": "unavailable", "code": code, "detail": detail], nil)
            }
        }
        check("host mail: the entries extend log L to their hashes") {
            for e in a(mail["entries"]).map(o) {
                let r = try mailList(a(e["chain"]).map(s)).extend(entries: [js(e["entry"]!)], now: now)
                try eq(r.stop, nil, s(e["label"]))
                try eq(r.head.hash, s(e["entry_hash"]), s(e["label"]))
            }
        }
        check("host mail: the builders reproduce every built object; a fresh seal opens; what no builder seals is refused") {
            let store = try mailStore()
            var built = 0
            for x in a(mail["objects"]).map(o) where (x["built"] as? Bool) == true {
                let sealed = o(x["sealed"])
                guard let plain = sealed["plaintext"] as? String else { continue }
                let fields = mailFields(o(x["object"])["body"])
                let signer = s(x["signed_with"])
                let to = encKey(s(sealed["to"]))
                let ikmE = unhex(s(sealed["ikmE_hex"]))
                let made: String
                if s(x["kind"]) == "envelope" {
                    made = try sealEnvelopeWithIkm(provider: store, hostKeyId: signer, fields: fields, plainJson: plain, recipientEnc: to, ikmE: ikmE)
                } else {
                    made = try sealResultWithIkm(provider: store, hostKeyId: signer, fields: fields, plainJson: plain, recipientEnc: to, ikmE: ikmE)
                }
                try eq(made, try canonicalJson(json: js(x["object"]!)), s(x["label"]))
                built += 1
            }
            if built < 20 { throw Failure(description: "\(built) built") }
            let b = ["M7_add_host_b", "M8_enc_a", "M9_enc_b", "M10_add_host_evil"]
            let toB = MailRecipientData(hostId: "host-b", hostTrustGen: 1, keys: [MailKeyData(keyId: "host-b-enc-1", encKid: try encKid(encKey: encKey("host-b-enc-1")))])
            let req = mailObject["request"]!
            let reqPlain = s(o(req["sealed"])["plaintext"])
            let fresh = try sealEnvelope(provider: store, hostKeyId: "host-a", fields: mailFields(o(req["object"])["body"]), plainJson: reqPlain, recipientEnc: encKey("host-b-enc-1"))
            try eq(try openEnvelope(objectJson: fresh, log: try mailList(b), me: toB, provider: store, nowMs: mailNow), .open(plainJson: reqPlain, sender: "host:host-a"))
            // The builder seals a plaintext's canonical form only.
            let loose = mailObject["plaintext_not_canonical"]!
            let loosePlain = s(o(loose["sealed"])["plaintext"])
            let canonicalSeal = try sealEnvelope(provider: store, hostKeyId: "host-a", fields: mailFields(o(loose["object"])["body"]), plainJson: loosePlain, recipientEnc: encKey("host-b-enc-1"))
            guard case let .open(openedJson, _) = try openEnvelope(objectJson: canonicalSeal, log: try mailList(b), me: toB, provider: store, nowMs: mailNow) else {
                throw Failure(description: "the canonical seal doesn't open")
            }
            try eq(openedJson, try canonicalJson(json: loosePlain))
            let status = mailObject["status"]!
            let freshResult = try sealResult(provider: store, hostKeyId: "host-b", fields: mailFields(o(status["object"])["body"]), plainJson: s(o(status["sealed"])["plaintext"]), recipientEnc: encKey("host-a-enc-1"))
            let toA = MailRecipientData(hostId: "host-a", hostTrustGen: 1, keys: [MailKeyData(keyId: "host-a-enc-1", encKid: try encKid(encKey: encKey("host-a-enc-1")))])
            let row = mailOutbox(mailChecks.first { s($0["label"]) == "status_accepted" }!["outbox"])
            guard case .accepted(_, _) = try acceptResult(objectJson: freshResult, log: try mailList(b), me: toA, outbox: row, provider: store, nowMs: mailNow) else {
                throw Failure(description: "a fresh result isn't accepted")
            }
            let nul = mailObject["plaintext_null"]!
            try throwsCode("null_value") { _ = try sealEnvelope(provider: store, hostKeyId: "host-a", fields: mailFields(o(nul["object"])["body"]), plainJson: s(o(nul["sealed"])["plaintext"]), recipientEnc: encKey("host-b-enc-1")) }
            let dropped = mailObject["dropped_reply"]!
            try throwsCode("malformed") { _ = try sealResult(provider: store, hostKeyId: "host-b", fields: mailFields(o(dropped["object"])["body"]), plainJson: s(o(dropped["sealed"])["plaintext"]), recipientEnc: encKey("host-a-enc-1")) }
            // The enc_kid names the key sealed to.
            try throwsCode("malformed") { _ = try sealEnvelope(provider: store, hostKeyId: "host-a", fields: mailFields(o(req["object"])["body"]), plainJson: reqPlain, recipientEnc: encKey("host-a-enc-1")) }
        }
        check("host mail: every envelope check's verdict (openEnvelope)") {
            let store = try mailStore()
            var n = 0
            for c in mailChecks where s(c["call"]) == "open_envelope" {
                let object = js(mailObject[s(c["object"])]!["object"]!)
                let got = try openEnvelope(objectJson: object, log: try mailList(a(c["chain"]).map(s)), me: try mailRecipient(c["receiver"]), provider: store, nowMs: u(c["now"]))
                let (verdict, plain) = envelopeVerdict(got)
                try mailExpect(c, verdict, plain)
                n += 1
            }
            if n < 44 { throw Failure(description: "\(n) checks") }
            #if canImport(CryptoKit)
            // Through a platform provider (CryptoKit, as Astation's): the
            // request opens, and the re-signed copy's seal doesn't
            // (ProviderError.OpenFailed), so it is refused authenticated,
            // open_failed, as through the software store.
            let platform = CryptoKitKeys()
            try platform.addX25519("host-b-enc-1", secret: unhex(s(key("host-b-enc-1", "enc")["secret_hex"])))
            for label in ["request_opens", "resigned"] {
                let c = mailChecks.first { s($0["label"]) == label }!
                let object = js(mailObject[s(c["object"])]!["object"]!)
                let got = try openEnvelope(objectJson: object, log: try mailList(a(c["chain"]).map(s)), me: try mailRecipient(c["receiver"]), provider: platform, nowMs: u(c["now"]))
                let (verdict, plain) = envelopeVerdict(got)
                try mailExpect(c, verdict, plain)
            }
            // A low-order `enc` (the zero point) doesn't open either: the
            // encapsulated key's refusal is OpenFailed too.
            do {
                _ = try platform.hpkeOpen(keyId: "host-b-enc-1", enc: Data(count: 32), ct: Data(count: 16), info: Data(), aad: Data())
                throw Failure(description: "a low-order enc opened")
            } catch ProviderError.OpenFailed {
            }
            #endif
        }
        check("host mail: every result check's verdict (acceptResult)") {
            let store = try mailStore()
            var n = 0
            for c in mailChecks where s(c["call"]) == "accept_result" {
                let object = js(mailObject[s(c["object"])]!["object"]!)
                let got = try acceptResult(objectJson: object, log: try mailList(a(c["chain"]).map(s)), me: try mailRecipient(c["receiver"]), outbox: mailOutbox(c["outbox"]), provider: store, nowMs: u(c["now"]))
                let (verdict, plain) = resultVerdict(got)
                try mailExpect(c, verdict, plain)
                n += 1
            }
            if n < 9 { throw Failure(description: "\(n) checks") }
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
                try eq(try hint.open(provider: provider, encKeyId: "enc", deviceId: device), .approval(tool: s(plain["tool"]), summary: s(plain["summary"])))
                let other = device == "dev-phone" ? "dev-mac" : "dev-phone"
                try throwsCode("malformed") { _ = try hint.open(provider: provider, encKeyId: "enc", deviceId: other) }
                try throwsCode("malformed") { _ = try hint.alert() }
            }
        }
        // The outcome_unknown hints (delegated host work, I.4.6).
        let alertHints = a(push["outcome_unknown"]).map(o)
        let alertDetails = a(push["outcome_unknown_details"]).map(o)
        let alertAcks = a(push["outcome_unknown_acks"]).map(o)
        func providerFor(_ device: String) throws -> AppKeyProvider {
            #if canImport(CryptoKit)
            let keysCK = CryptoKitKeys()
            try keysCK.addX25519("enc", secret: unhex(s(secrets[device])))
            return keysCK
            #else
            let store = SoftwareKeyStore()
            try store.insertX25519(keyId: "enc", secret: unhex(s(secrets[device])))
            return store.provider()
            #endif
        }
        func verified(_ h: [String: Any]) throws -> PushHint {
            try verifyPushHint(hintJson: js(h), log: logL(), nowMs: nowP, verifier: .client)
        }
        check("outcome_unknown hints verify and open for their device only") {
            for (i, h) in alertHints.enumerated() {
                let d = alertDetails[i]
                let device = s(d["device_id"])
                let body = o(h["body"])
                let hint = try verified(h)
                try eq(hint.state(), .outcomeUnknown(deviceId: device, encKid: s(d["enc_kid"]), sealedHash: s(d["sealed_hash"])))
                try eq(hex(try signedObjectInfo(json: js(h)).signingInput), s(d["signing_input_hex"]))
                try hint.checkSealed()
                try eq(hint.createdAt(), u(body["created_at"]))
                try eq(hint.expiresAt(), u(body["expires_at"]))
                try eq(try hint.alert(), AlertRef(accountId: s(body["account_id"]), genesisHash: s(body["genesis_hash"]), hostId: s(body["host_id"]), hostTrustGen: u(body["host_trust_gen"]), alertId: s(body["alert_id"])))
                try throwsCode("malformed") { _ = try hint.approval() }
                try eq(canon(try JSONSerialization.jsonObject(with: utf8(hint.ackJson()))), canon(alertAcks[i]))
                let facts = o(d["facts"])
                try eq(try hint.open(provider: providerFor(device), encKeyId: "enc", deviceId: device), .outcomeUnknown(taskId: s(facts["task_id"]), sessionId: s(facts["session_id"]), sender: s(facts["sender"]), reason: s(facts["reason"])))
                let other = device == "dev-phone" ? "dev-mac" : "dev-phone"
                try throwsCode("malformed") { _ = try hint.open(provider: providerFor(device), encKeyId: "enc", deviceId: other) }
            }
        }
        check("outcome_unknown hints: refusals, dedup and acks") {
            let cases = a(push["outcome_unknown_invalid"]).map(o)
            for c in cases {
                let code = s(c["code"])
                if ["malformed", "binding", "invalid_times", "skew"].contains(code) {
                    for verifier in [PushVerifier.client, PushVerifier.relay] {
                        try throwsCode(code) { _ = try verifyPushHint(hintJson: js(c["hint"]!), log: logL(), nowMs: nowP, verifier: verifier) }
                    }
                }
            }
            let book = PushHintBook()
            try eq(try book.offer(hint: verified(alertHints[0])), .accepted)
            try eq(try book.offer(hint: verified(alertHints[0])), .idempotent)
            try eq(try book.offer(hint: verified(alertHints[1])), .accepted)
            let duplicate = cases.first { s($0["code"]) == "duplicate" }!
            try throwsCode("duplicate") { _ = try book.offer(hint: verified(o(duplicate["hint"]))) }
            // A swapped sealed part verifies (its body and signature are the
            // host's) and is refused where the sealed part counts.
            let swapped = try verified(o(cases.first { s($0["code"]) == "bad_sealed" }!["hint"]))
            try throwsCode("bad_sealed") { try swapped.checkSealed() }
            try throwsCode("bad_sealed") { _ = try PushHintBook().offer(hint: swapped) }
            try throwsCode("open_failed") { _ = try swapped.open(provider: providerFor("dev-phone"), encKeyId: "enc", deviceId: "dev-phone") }
            // Well signed and well sealed, but the sealed facts aren't a
            // delegated sender's UUID v4 task: verified and kept, refused at open.
            for c in a(push["outcome_unknown_invalid_facts"]).map(o) {
                for verifier in [PushVerifier.client, PushVerifier.relay] {
                    _ = try verifyPushHint(hintJson: js(c["hint"]!), log: logL(), nowMs: nowP, verifier: verifier)
                }
                let hint = try verified(o(c["hint"]))
                try hint.checkSealed()
                let device = s(c["device_id"])
                try throwsCode(s(c["code"])) { _ = try hint.open(provider: providerFor(device), encKeyId: "enc", deviceId: device) }
            }
            // The ack entries, and an approval hint is no alert.
            let acks = try alertHints.map { try verified($0).ackJson() }
            try eq(try parsePushAck(messageJson: pushAckMessage(acks: acks)), acks)
            try eq(try acks.map { canon(try JSONSerialization.jsonObject(with: utf8($0))) }, alertAcks.map { canon($0) })
            try throwsCode("malformed") { _ = try verified(opens[0]).alert() }
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

        // ------------------------------------------------------------ framing
        // The prompt framing (delegated host-work design III.2) over
        // designs/protocol/fixtures/host-work/: the escaping and the marker
        // check, the Unicode version they are pinned to, the preflight size
        // check and (a test-vectors build only) the rendering, byte for byte.
        // Strings are compared as UTF-8: Swift's == is canonical equivalence.
        func loadWork(_ name: String) throws -> [String: Any] {
            o(try decodeVectors(Data(contentsOf: dir.appendingPathComponent("host-work").appendingPathComponent("\(name).json"))))
        }
        let framing = try loadWork("prompt-framing-v1")
        let framingSize = try loadWork("framing-size-v1")
        let framingPrompts = a(framing["prompts"]).map(o)
        func snapshot(_ kind: String, _ id: String, _ version: UInt64, _ text: String) -> [String: Any] {
            ["kind": kind, "id": id, "version": NSNumber(value: version), "digest": sha256Hex(text), "text": text]
        }
        // framingCheckedLen of a text, an optional mark (a host-work MarkTask
        // object) and snapshots (host-work ContextSnapshot objects): the
        // complete inputs.
        func checkedLen(_ text: String, _ mark: [String: Any]?, _ context: [[String: Any]]) throws -> UInt64 {
            try framingCheckedLen(text: text, markJson: mark.map { js($0) }, contextJson: js(context))
        }

        check("framing: Unicode version, escape cases, marker check (III.2)") {
            try eq(framingUnicodeVersion(), s(framing["unicode_version"]), "Unicode version")
            try eq(s(framing["unicode_version"]), "18.0.0")
            let cases = a(framing["escape"]).map(o)
            try eq(cases.count, 57)
            // The decoding kept the vectors' U+FEFF (see decodeVectors).
            try eq(cases.contains { s($0["text"]).unicodeScalars.first?.value == 0xFEFF }, true, "a text starting with U+FEFF reached the check")
            for c in cases {
                let name = s(c["name"])
                let r = framingEscape(text: s(c["text"]))
                try eq(Array(r.escaped.utf8), Array(s(c["escaped"]).utf8), name)
                try eq(UInt64(r.barsAdded), u(c["bars_added"]), name)
                // The marker check on each line (after the bars it already
                // starts with) agrees with where the escaping put its bars.
                let folding = linesWithoutLeadingBars(s(c["text"])).filter { framingFoldsToMarker(line: $0) }.count
                try eq(UInt64(folding), u(c["bars_added"]), "\(name): lines that fold")
            }
            for line in ["[atem]", "  [ATEM x", "[\u{410}\u{422}\u{415}\u{41c}]", "[a\u{fe0f}tem]"] {
                try eq(framingFoldsToMarker(line: line), true, line)
            }
            for line in ["", "x[atem]", "[ atem]", "|[atem]", "[atom]"] {
                try eq(framingFoldsToMarker(line: line), false, line)
            }
        }
        check("framing: rendered prompts byte for byte, tags from their bits (vectors only)") {
            let tag = s(framing["tag"])
            let bits = tagBitsOf(tag)
            try eq(framingPrompts.count, 9)
            for p in framingPrompts {
                let name = s(p["name"])
                let rendered = try framingRenderForVectors(inputJson: js(p["input"]!), tagBits: bits)
                try eq(Array(rendered.utf8), Array(s(p["rendered"]).utf8), name)
                try eq(UInt64(rendered.utf8.count), u(p["bytes"]), "\(name): bytes")
            }
            // Every tag of the vectors renders the prompt with that tag, on
            // Atem's own lines only (the sender's text is not touched, even
            // where it holds the vectors' tag).
            let first = framingPrompts[0]
            let old = "[atem \(tag)] "
            for t in a(framing["tags"]).map(o) {
                let fresh = "[atem \(s(t["tag"]))] "
                let expected = retagged(s(first["rendered"]), from: old, to: fresh)
                let tagBits = UInt64(s(t["bits"]), radix: 16)!
                let got = try framingRenderForVectors(inputJson: js(first["input"]!), tagBits: tagBits)
                try eq(Array(got.utf8), expected, s(t["bits"]))
            }
            // What the core refuses, and what is no input, is refused: a
            // snapshot whose text doesn't match its digest is never rendered.
            let input = o(framingPrompts[2]["input"])
            _ = try framingRenderForVectors(inputJson: js(input), tagBits: 1)
            var firstContext = o(a(input["context"])[0])
            firstContext["text"] = "not what the digest says"
            var tampered = input
            tampered["context"] = [firstContext]
            try throwsCode("malformed") { _ = try framingRenderForVectors(inputJson: js(tampered), tagBits: 1) }
            var headless = input
            headless["header"] = nil
            try throwsCode("malformed") { _ = try framingRenderForVectors(inputJson: js(headless), tagBits: 1) }
        }
        check("framing: the size section (typical, worst, worst with a mark, at the bound)") {
            let size = o(framing["size"])
            func vault(_ id: String, _ version: UInt64, _ n: Int) -> [String: Any] {
                snapshot("vault", id, version, String(repeating: "c", count: n))
            }
            // A typical task: 5,120 bytes of context, a 1,024-byte prompt.
            let typical = try checkedLen(String(repeating: "t", count: 1024), nil, [vault("api-contract", 3, 5120)])
            try eq(typical - 1024 - 5120, u(o(size["typical"])["checked_atem_bytes"]), "typical")
            // The worst: eight 1,000-byte contexts with 128-byte ids and
            // 16-digit versions, a 1,000-byte prompt.
            var worst: [[String: Any]] = []
            for i in 0..<8 {
                worst.append(snapshot("memory", "\(i)" + String(repeating: "m", count: 127), 9_007_199_254_740_991, String(repeating: "c", count: 1000)))
            }
            let text = String(repeating: "t", count: 1000)
            let worstLen = try checkedLen(text, nil, worst)
            try eq(worstLen - 1000 - 8 * 1000, u(o(size["worst"])["checked_atem_bytes"]), "worst")
            // The same with a mark (the vectors' own, with a 128-byte mark id).
            let withMark = framingPrompts.first(where: { o($0["input"])["mark"] != nil })!
            var mark = o(o(withMark["input"])["mark"])
            mark["mark_id"] = String(repeating: "k", count: 128)
            try eq(try checkedLen(text, mark, worst), u(o(size["worst_mark"])["checked_bytes"]), "worst with a mark")
            // At the bound: one byte more is over it.
            let n = Int(u(o(size["at_bound"])["context_bytes"]))
            func at(_ k: Int) throws -> UInt64 {
                try checkedLen("x", nil, [snapshot("vault", "c", 1, String(repeating: "y", count: k))])
            }
            let bound = u(framingSize["max_prompt_bytes"])
            try eq(try at(n), u(o(size["at_bound"])["checked_len"]), "at the bound")
            try eq(try at(n), bound, "exactly the bound")
            try eq(try at(n + 1), bound + 1, "one byte over")
        }
        check("framing: every framing-size-v1 case with its complete inputs") {
            try eq(u(framingSize["max_prompt_bytes"]), 32768)
            try eq(u(framingSize["attachment_reserve"]), 4096)
            let cases = a(framingSize["cases"]).map(o)
            if cases.count < 10 { throw Failure(description: "only \(cases.count) cases") }
            for c in cases {
                let got = try framingCheckedLen(text: s(c["text"]), markJson: c["mark"].map { js($0) }, contextJson: js(c["context"]!))
                try eq(got, u(c["checked_len"]), s(c["name"]))
            }
            // What the preflight takes is exactly the host-work shapes:
            // anything else is refused, never read loosely.
            let okContext = js([snapshot("vault", "a", 1, "x")])
            _ = try framingCheckedLen(text: "t", markJson: nil, contextJson: "[]")
            _ = try framingCheckedLen(text: "t", markJson: nil, contextJson: okContext)
            let dup = okContext.replacingOccurrences(of: "\"id\":\"a\"", with: "\"id\":\"a\",\"id\":\"b\"")
            let float = okContext.replacingOccurrences(of: "\"version\":1", with: "\"version\":1.5")
            if dup == okContext || float == okContext { throw Failure(description: "the refusal inputs changed nothing") }
            try throwsCode("not_strict_json") { _ = try framingCheckedLen(text: "t", markJson: nil, contextJson: "[") }
            try throwsCode("not_strict_json") { _ = try framingCheckedLen(text: "t", markJson: nil, contextJson: dup) }
            try throwsCode("not_strict_json") { _ = try framingCheckedLen(text: "t", markJson: nil, contextJson: float) }
            for context in [
                "{}",
                "null",
                #"[{"kind":"vault","id":"a","version":1,"digest":"d"}]"#,
                #"[{"kind":"notes","id":"a","version":1,"digest":"d","text":"x"}]"#,
            ] {
                try throwsCode("malformed") { _ = try framingCheckedLen(text: "t", markJson: nil, contextJson: context) }
            }
            for mark in ["null", "{}", "[]", #"{"mark_id":"m"}"#] {
                try throwsCode("malformed") { _ = try framingCheckedLen(text: "t", markJson: mark, contextJson: "[]") }
            }
        }

        print("swift conformance: \(passed) passed, \(failures.count) failed")
        for f in failures { print("FAIL \(f)") }
        XCTAssertEqual(failures, [], "conformance failures")
        XCTAssertEqual(passed, 71)
    }
}
