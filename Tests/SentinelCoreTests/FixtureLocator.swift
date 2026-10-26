import Foundation
import XCTest

/// Shared test helper. Lead-owned. Do not edit from a unit branch.
///
/// Fixtures live at the repository root in `Fixtures/`. The path is derived from
/// `#filePath`, so tests read the same bytes from any working directory.
enum Fixture {
    static var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // Tests/SentinelCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // repository root
    }

    static var directory: URL { repositoryRoot.appendingPathComponent("Fixtures") }

    static func url(_ name: String) throws -> URL {
        let candidate = directory.appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: candidate.path) else {
            throw XCTSkip("fixture \(name) is absent at \(candidate.path)")
        }
        return candidate
    }

    static func text(_ name: String) throws -> String {
        try String(contentsOf: try url(name), encoding: .utf8)
    }

    static func data(_ name: String) throws -> Data {
        try Data(contentsOf: try url(name))
    }
}
