// swift-tools-version:5.9
import PackageDescription

// macOS 13 is the floor Swift Testing needs for its macro expansion.
// Test runs go through scripts/test.sh, the one place that knows how to find
// the test frameworks on a machine with Command Line Tools only.
//
// Two executables, one core (CF-04). `handsal-sign` is the shipped signer and depends on the core
// alone. `handsal-sign-conformance` runs the `render` and `emit` vectors, holds no key and is
// never installed: it is its own product with its own entry point, so which one a process is
// decided by the file that was started, never by a flag or an environment variable.
let package = Package(
    name: "handsal-sign",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "HandsalCore", targets: ["HandsalCore"]),
        .executable(name: "handsal-sign", targets: ["handsal-sign"]),
        .executable(name: "handsal-sign-conformance", targets: ["handsal-sign-conformance"]),
    ],
    targets: [
        .target(name: "HandsalCore"),
        .target(name: "HandsalConformance", dependencies: ["HandsalCore"]),
        .target(name: "HandsalSecureEnclave", dependencies: ["HandsalCore"]),
        .executableTarget(name: "handsal-sign", dependencies: ["HandsalCore", "HandsalSecureEnclave"]),
        .executableTarget(name: "handsal-sign-conformance", dependencies: ["HandsalCore", "HandsalConformance"]),
        .testTarget(name: "HandsalCoreTests", dependencies: ["HandsalCore", "HandsalConformance", "HandsalSecureEnclave"]),
    ]
)
