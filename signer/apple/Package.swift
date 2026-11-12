// swift-tools-version:5.9
import PackageDescription

// macOS 13 is the floor Swift Testing needs for its macro expansion.
// Test runs go through scripts/test.sh, the one place that knows how to find
// the test frameworks on a machine with Command Line Tools only.
let package = Package(
    name: "handsal-sign",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "HandsalCore", targets: ["HandsalCore"]),
        .executable(name: "handsal-sign", targets: ["handsal-sign"]),
    ],
    targets: [
        .target(name: "HandsalCore"),
        .executableTarget(name: "handsal-sign", dependencies: ["HandsalCore"]),
        .testTarget(name: "HandsalCoreTests", dependencies: ["HandsalCore"]),
    ]
)
