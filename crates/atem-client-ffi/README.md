# atem-client-ffi

Bindings over [`atem-client`](../atem-client/README.md), the atem-session r9
client core, for Astation's apps, bots and browsers: Swift and Kotlin through
UniFFI 0.32.2, JavaScript through wasm-bindgen 0.2.101. The binding and
effect contract (objects, call order, what the app must sign, persist, send
and render, the `KeyProvider` contract, errors, threading, packaging) is
[`designs/protocol/atem-client-bindings.md`](../../designs/protocol/atem-client-bindings.md);
the protocol is the r9 appendix of
[`atem-session-v1.md`](../../designs/protocol/atem-session-v1.md).

Sans-I/O like the core: the app owns sockets, storage, clocks, UI and key
storage; native members' private keys never enter Rust (`AppKeyProvider`).

## Features

| feature | |
|---|---|
| `uniffi` (default) | Swift/Kotlin scaffolding |
| `bindgen` | the `uniffi-bindgen` binary (library mode) |
| `wasm` | the wasm-bindgen surface (`--no-default-features --features wasm`) |
| `software-keys`, `test-vectors`, `host` | conformance and host-side tests only; never in a shipped package |

## Packages

Built by `.github/workflows/atem-client-bindings.yml` from the commit under
review, each with `SHA256SUMS` and a `SOURCE.json` source pin, uploaded as
workflow artifacts (nothing goes to a registry):

| package | script |
|---|---|
| SwiftPM `AtemClient` + `atem_client_ffiFFI.xcframework` (macOS, iOS, iOS simulator) | `scripts/package-atem-client-apple.sh` (macOS) |
| WASM (`web/`, `nodejs/`, `bundler/`) | `scripts/package-atem-client-bindings.sh … wasm` |
| Kotlin/JVM (generated Kotlin, JNA library, jar) | `scripts/package-atem-client-bindings.sh … kotlin` |
| Android: `libatem_client_ffi.so` for arm64-v8a, armeabi-v7a, x86_64 (minSdk 24, 16 KB LOAD alignment) + Kotlin | `scripts/package-atem-client-bindings.sh … android` (NDK r28c in CI) |

`scripts/check-atem-client-packages.sh` checks a downloaded package the way
Astation should (sums, pin, no test-only or host-role export, a call each;
Android: ELF class, machine and alignment per ABI).

## Tests

```bash
cargo test -p atem-client-ffi                     # Rust: durability, no lock while signing, binding e2e
./scripts/check-atem-client-bindings.sh           # Kotlin (JNA), WASM (Node), e2e; Swift on macOS
```

The conformance suites (`bindings/kotlin`, `bindings/js`, `bindings/swift`)
run every `r9-vectors-*` file, the host-work prompt-framing vectors
(`prompt-framing-v1.json`, `framing-size-v1.json`) and the `result_id`,
request, `answers` and `reply` result vectors of `requests-v1.json`
(`host_work_result_id`, `host_work_request_valid`,
`host_work_result_answers`: the owner's ops naming
a host sender's selector task among them, its `reply_query` with a reply in
each state) through the generated
bindings; the end-to-end
test drives a Kotlin phone and a Node/WASM browser against a test host over
loopback TCP. Toolchains are passed in by environment (`KOTLINC`, `JNA_JAR`,
`WASM_BINDGEN`, …; see the script).

The suites also render the host-result header's vectors
(`framing-host-result-v1.json`: another host's reply, naming that host and
no session) byte for byte through the vectors-only
`framing_render_for_vectors`, and check what it never renders.
