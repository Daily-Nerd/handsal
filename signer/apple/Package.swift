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
        .executable(name: "handsal-pin", targets: ["handsal-pin"]),
        .executable(name: "handsal-link", targets: ["handsal-link"]),
        .executable(name: "handsal-ceremony", targets: ["handsal-ceremony"]),
    ],
    targets: [
        .target(name: "HandsalCore"),
        .target(name: "HandsalIJSON", dependencies: ["HandsalCore"]),
        .target(name: "HandsalConformance", dependencies: ["HandsalCore", "HandsalIJSON"]),
        .target(name: "HandsalSecureEnclave", dependencies: ["HandsalCore"]),
        .target(name: "HandsalPinCore", dependencies: ["HandsalCore"]),
        .target(name: "HandsalLinkCore", dependencies: ["HandsalCore"]),
        .target(name: "HandsalCeremonyCore", dependencies: ["HandsalCore", "HandsalIJSON", "HandsalPinCore"]),
        .executableTarget(name: "handsal-ceremony", dependencies: ["HandsalCore", "HandsalCeremonyCore"]),
        .testTarget(name: "HandsalCeremonyTests", dependencies: ["HandsalCore", "HandsalCeremonyCore"]),
        .executableTarget(name: "handsal-link", dependencies: ["HandsalCore", "HandsalLinkCore"]),
        .testTarget(name: "HandsalLinkTests", dependencies: ["HandsalCore", "HandsalLinkCore"]),
        .executableTarget(name: "handsal-pin", dependencies: ["HandsalCore", "HandsalPinCore"]),
        .testTarget(name: "HandsalPinTests", dependencies: ["HandsalCore", "HandsalPinCore"]),
        .executableTarget(name: "handsal-sign", dependencies: ["HandsalCore", "HandsalSecureEnclave"]),
        .executableTarget(name: "handsal-sign-conformance", dependencies: ["HandsalCore", "HandsalConformance"]),
        .testTarget(name: "HandsalCoreTests", dependencies: ["HandsalCore", "HandsalConformance", "HandsalIJSON", "HandsalSecureEnclave"]),
    ]
)
