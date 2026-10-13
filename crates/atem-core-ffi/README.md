# atem-core-ffi

C ABI for [`atem-core`](../atem-core/README.md): build, decode and verify Agora
AccessToken2 (RTC/RTM) tokens from C, C++ or Swift. The header is
[`include/atem_core.h`](include/atem_core.h). Design:
[`designs/atem-core.md`](../../designs/atem-core.md).

## ABI rules

ABI version 1 (`ATEM_CORE_ABI_VERSION`; `atem_core_abi_version()` returns the
linked library's).

- Strings are NUL-terminated UTF-8.
- Every function returns `ATEM_CORE_OK` (0) or an error code. On success the
  output string is set and `*out_error` is NULL. On failure the outputs are NULL
  and, if `out_error` is not NULL, `*out_error` holds a message. For
  `atem_core_verify_token_signature`, `*out_valid` is also 0 on error.
- Every string returned through an out-parameter belongs to the caller and must
  be freed exactly once with `atem_core_string_free` (NULL is ok). The string
  from `atem_core_version()` is static: never free it.
- Functions are thread-safe and keep no state.
- Nothing is logged. Error messages never contain the App Certificate or a
  token.
- Panics are caught at the C boundary and become `ATEM_CORE_ERR_INTERNAL`, but
  only when the host builds and links Rust with unwinding. Under
  `panic = "abort"` a panic aborts the process.

### `struct_size`

Both parameter structs start with `uint32_t struct_size`. Set it to
`sizeof(...)` of the struct you compiled against. The library rejects any other
size with `ATEM_CORE_ERR_STRUCT_SIZE` before it reads another field, so a header
and library that disagree fail loudly. Zero the struct first
(`AtemCoreRtcTokenParams p = {0};`) so unused fields are 0 / NULL.

### Status codes

| Code | Name | Meaning |
|---|---|---|
| 0 | `ATEM_CORE_OK` | Success |
| 1 | `ATEM_CORE_ERR_NULL_ARGUMENT` | A required pointer is NULL |
| 2 | `ATEM_CORE_ERR_INVALID_UTF8` | A string is not UTF-8 |
| 3 | `ATEM_CORE_ERR_STRUCT_SIZE` | `struct_size` does not match |
| 4 | `ATEM_CORE_ERR_INVALID_ARGUMENT` | Bad `role` or `with_rtm` value |
| 10 | `ATEM_CORE_ERR_INVALID_APP_ID` | App ID is not 32 hex characters |
| 11 | `ATEM_CORE_ERR_INVALID_APP_CERTIFICATE` | Certificate is not 32 hex characters |
| 12 | `ATEM_CORE_ERR_INVALID_CHANNEL` | Channel is not 1-64 bytes |
| 13 | `ATEM_CORE_ERR_INVALID_USER_ACCOUNT` | User account is not 1-255 bytes |
| 14 | `ATEM_CORE_ERR_INVALID_RTM_USER_ID` | RTM user id is not 1-64 bytes |
| 15 | `ATEM_CORE_ERR_INVALID_EXPIRY` | An expiry is less than 1 second |
| 20 | `ATEM_CORE_ERR_UNSUPPORTED_VERSION` | Token does not start with `007` |
| 21 | `ATEM_CORE_ERR_MALFORMED_TOKEN` | Token cannot be decoded |
| 99 | `ATEM_CORE_ERR_INTERNAL` | Internal error (caught panic) |

### Functions

- `atem_core_build_rtc_token(params, &out_token, &out_error)`
- `atem_core_build_rtm_token(params, &out_token, &out_error)`
- `atem_core_decode_token(token, &out_json, &out_error)`: fields as JSON. It
  does not verify; use `atem_core_verify_token_signature`.
- `atem_core_verify_token_signature(token, certificate, &out_valid, &out_error)`:
  `*out_valid` is 1 if the token was signed with that certificate, else 0.
- `atem_core_string_free(s)`, `atem_core_abi_version()`, `atem_core_version()`

The JSON shape and the RTC `role` values (`ATEM_CORE_ROLE_EXPLICIT`,
`_PUBLISHER`, `_SUBSCRIBER`) are documented in the header.

## Using the release artifacts (macOS)

Each Atem release carries `atem-core-<version>-macos-xcframework.zip`,
`atem-core-<version>-atem_core.h` and `atem-core-<version>-SHA256SUMS.txt`
(`<version>` is the tag without the `v`).

1. Download the zip and the sums file from the Atem release page.
2. Check them: `shasum -a 256 -c atem-core-<version>-SHA256SUMS.txt`
3. Unzip, then add `AtemCore.xcframework` to the Xcode target under
   Frameworks, Libraries. Set it to "Do Not Embed": it is a static library.
4. In Swift, `import AtemCore`.

The xcframework is a universal (arm64 + x86_64) static library with the header
and a module map.

```swift
import AtemCore

/// Takes ownership of a string returned by atem-core.
func take(_ p: UnsafeMutablePointer<CChar>?) -> String? {
    guard let p else { return nil }
    defer { atem_core_string_free(p) }
    return String(cString: p)
}

// Build an RTC token. The ID and certificate are Agora's public test values.
let token: String = "970CA35de60c44645bbae8a215061b33".withCString { app in
    "5CFd2fd1755d40ecb72977518be15d3b".withCString { certificate in
        "demo".withCString { channel in
            var p = AtemCoreRtcTokenParams()
            p.struct_size = UInt32(MemoryLayout<AtemCoreRtcTokenParams>.size)
            p.app_id = app
            p.app_certificate = certificate
            p.channel = channel
            p.uid = 1234
            p.role = ATEM_CORE_ROLE_PUBLISHER
            p.token_expire = 3600
            p.privilege_expire = 3600
            var out: UnsafeMutablePointer<CChar>? = nil
            var error: UnsafeMutablePointer<CChar>? = nil
            let status = atem_core_build_rtc_token(&p, &out, &error)
            if status != ATEM_CORE_OK { fatalError("status \(status): \(take(error) ?? "")") }
            return take(out)!
        }
    }
}

// Decode it. This does not verify the signature.
var json: UnsafeMutablePointer<CChar>? = nil
var error: UnsafeMutablePointer<CChar>? = nil
if atem_core_decode_token(token, &json, &error) == ATEM_CORE_OK, let text = take(json) {
    print(text)
}

// Verify it.
var valid: Int32 = 0
if atem_core_verify_token_signature(token, "5CFd2fd1755d40ecb72977518be15d3b", &valid, &error) == ATEM_CORE_OK {
    print(valid == 1 ? "signed with this certificate" : "different certificate")
}
```

`issued_at = 0` and `salt = 0` mean "now" and "random". Set them only in tests.
`tests/swift/main.swift` is the full version that checks the published vector.

## Building from source

```bash
cargo build -p atem-core-ffi --release
```

This produces `target/release/libatem_core_ffi.a` on Linux and macOS, and
`target/release/atem_core_ffi.lib` on Windows (MSVC). A shared library is built
too. A static link also needs the system libraries Rust uses on that platform:

```bash
cargo rustc -p atem-core-ffi --release --lib --crate-type staticlib -- --print native-static-libs
```

Add the libraries it prints to your link line. For example, compiling the C
test consumer:

```bash
cc -std=c11 -Wall -Wextra -Werror -I crates/atem-core-ffi/include \
   crates/atem-core-ffi/tests/c/consumer.c target/release/libatem_core_ffi.a $LIBS -o consumer
```

`scripts/check-atem-core-ffi.sh` does all of this (and the Swift check on
macOS). `scripts/package-atem-core-macos.sh <version> <output-dir>` builds the
xcframework, header and checksums; the release workflow runs it.

```bash
cargo test -p atem-core -p atem-core-ffi
./scripts/check-atem-core-ffi.sh
```
