// swift-tools-version:6.0
import PackageDescription

// One module per unit. A unit's tests compile its module and its dependencies only,
// so a half-written sibling cannot break another owner's verify command.
let package = Package(
    name: "WiresharkSentinel",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "WiresharkSentinel", targets: ["WiresharkSentinel"]),
    ],
    targets: [
        .target(name: "SentinelDomain", path: "Sources/SentinelDomain"),
        .target(name: "SentinelEngine", dependencies: ["SentinelDomain"], path: "Sources/SentinelEngine"),
        .target(name: "SentinelIdentity", dependencies: ["SentinelDomain"], path: "Sources/SentinelIdentity"),
        .target(name: "SentinelAttribution", dependencies: ["SentinelDomain"], path: "Sources/SentinelAttribution"),
        .target(name: "SentinelSuspicion", dependencies: ["SentinelDomain"], path: "Sources/SentinelSuspicion"),
        .target(
            name: "SentinelReport",
            dependencies: ["SentinelDomain", "SentinelSuspicion"],
            path: "Sources/SentinelReport"
        ),
        .target(name: "SentinelTestSupport", path: "Sources/SentinelTestSupport"),
        .executableTarget(
            name: "WiresharkSentinel",
            dependencies: [
                "SentinelDomain", "SentinelEngine", "SentinelIdentity",
                "SentinelAttribution", "SentinelSuspicion", "SentinelReport",
            ],
            path: "Sources/WiresharkSentinel"
        ),
        .testTarget(
            name: "SentinelEngineTests",
            dependencies: ["SentinelEngine", "SentinelTestSupport"],
            path: "Tests/SentinelEngineTests"
        ),
        .testTarget(
            name: "SentinelIdentityTests",
            dependencies: ["SentinelIdentity", "SentinelTestSupport"],
            path: "Tests/SentinelIdentityTests"
        ),
        .testTarget(
            name: "SentinelAttributionTests",
            dependencies: ["SentinelAttribution", "SentinelTestSupport"],
            path: "Tests/SentinelAttributionTests"
        ),
        .testTarget(
            name: "SentinelSuspicionTests",
            dependencies: ["SentinelSuspicion", "SentinelTestSupport"],
            path: "Tests/SentinelSuspicionTests"
        ),
        .testTarget(
            name: "SentinelReportTests",
            dependencies: ["SentinelReport", "SentinelTestSupport"],
            path: "Tests/SentinelReportTests"
        ),
    ],
    swiftLanguageModes: [.v5]
)
