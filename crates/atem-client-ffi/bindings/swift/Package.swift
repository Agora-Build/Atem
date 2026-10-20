// swift-tools-version:5.9
// AtemClient: the UniFFI-generated Swift over atem-client
// (crates/atem-client-ffi), linked against atem_client_ffiFFI.xcframework.
// scripts/package-atem-client-apple.sh copies this file next to the
// generated Sources/ and the xcframework. The test target exists only in a
// conformance build (features software-keys, test-vectors); the release
// package drops the line marked `conformance`.
import PackageDescription

let package = Package(
    name: "AtemClient",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [.library(name: "AtemClient", targets: ["AtemClient"])],
    targets: [
        // Named (target and xcframework) like the module its module.modulemap declares (UniFFI's
        // `atem_client_ffiFFI`), which the generated Swift imports.
        .binaryTarget(name: "atem_client_ffiFFI", path: "atem_client_ffiFFI.xcframework"),
        .target(name: "AtemClient", dependencies: ["atem_client_ffiFFI"], path: "Sources/AtemClient"),
        .testTarget(name: "AtemClientTests", dependencies: ["AtemClient"], path: "Tests/AtemClientTests"), // conformance
    ]
)
