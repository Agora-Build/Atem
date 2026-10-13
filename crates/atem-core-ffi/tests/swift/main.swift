import Foundation

let appID = "970CA35de60c44645bbae8a215061b33"
let cert = "5CFd2fd1755d40ecb72977518be15d3b"
let vector = "007eJwBigB1/yAAFqC4TFpegsv3T7gT0J9ZxUvaycBhIFgFOayXV46VixogADk3MENBMzVkZTYwYzQ0NjQ1YmJhZThhMjE1MDYxYjMzR/QQAFgCAAABAAAAAQABAAEAAQBYAgAAIAA3ZDcyMzY1ZWI5ODM0ODUzOTdlM2UzZjlkNDYwYmRkYQoAMjg4MjM0MTI3M8JqJOM="

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(("FAIL: " + message + "\n").data(using: .utf8)!)
    exit(1)
}

/// Takes ownership of a string returned by atem-core.
func take(_ p: UnsafeMutablePointer<CChar>?) -> String? {
    guard let p else { return nil }
    defer { atem_core_string_free(p) }
    return String(cString: p)
}

guard atem_core_abi_version() == ATEM_CORE_ABI_VERSION else { fail("abi version") }

let token: String = appID.withCString { app in
    cert.withCString { certificate in
        "7d72365eb983485397e3e3f9d460bdda".withCString { channel in
            var p = AtemCoreRtcTokenParams()
            p.struct_size = UInt32(MemoryLayout<AtemCoreRtcTokenParams>.size)
            p.app_id = app
            p.app_certificate = certificate
            p.channel = channel
            p.uid = 2882341273
            p.role = ATEM_CORE_ROLE_SUBSCRIBER
            p.token_expire = 600
            p.privilege_expire = 600
            p.issued_at = 1111111
            p.salt = 1
            var out: UnsafeMutablePointer<CChar>? = nil
            var error: UnsafeMutablePointer<CChar>? = nil
            let status = atem_core_build_rtc_token(&p, &out, &error)
            if status != ATEM_CORE_OK { fail("build status \(status): \(take(error) ?? "")") }
            guard let token = take(out) else { fail("no token") }
            return token
        }
    }
}
guard token == vector else { fail("token differs from the published vector") }

var json: UnsafeMutablePointer<CChar>? = nil
var error: UnsafeMutablePointer<CChar>? = nil
guard atem_core_decode_token(token, &json, &error) == ATEM_CORE_OK, let text = take(json),
      let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
      object["app_id"] as? String == appID
else { fail("decode") }

var valid: Int32 = -1
guard atem_core_verify_token_signature(token, cert, &valid, &error) == ATEM_CORE_OK, valid == 1 else { fail("verify") }

print("atem_core Swift caller: ok")
