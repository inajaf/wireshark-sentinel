// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "WiresharkSentinel",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SentinelCore", targets: ["SentinelCore"]),
        .executable(name: "WiresharkSentinel", targets: ["WiresharkSentinel"]),
    ],
    targets: [
        .target(name: "SentinelCore", path: "Sources/SentinelCore"),
        .executableTarget(
            name: "WiresharkSentinel",
            dependencies: ["SentinelCore"],
            path: "Sources/WiresharkSentinel"
        ),
        .testTarget(
            name: "SentinelCoreTests",
            dependencies: ["SentinelCore"],
            path: "Tests/SentinelCoreTests"
        ),
    ],
    swiftLanguageModes: [.v5]
)
