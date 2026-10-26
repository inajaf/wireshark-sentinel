import Foundation

/// Shared test helper. Lead-owned. Do not edit from a unit branch.
///
/// Fixtures live at the repository root in `Fixtures/`. The path is derived from
/// `#filePath`, so tests read the same bytes from any working directory.
public enum Fixture {
    public static var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // Sources/SentinelTestSupport
            .deletingLastPathComponent()   // Sources
            .deletingLastPathComponent()   // repository root
    }

    public static var directory: URL { repositoryRoot.appendingPathComponent("Fixtures") }

    public struct MissingFixture: Error, CustomStringConvertible {
        public let path: String
        public var description: String { "fixture missing at \(path)" }
    }

    public static func url(_ name: String) throws -> URL {
        let candidate = directory.appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: candidate.path) else {
            throw MissingFixture(path: candidate.path)
        }
        return candidate
    }

    public static func text(_ name: String) throws -> String {
        try String(contentsOf: try url(name), encoding: .utf8)
    }

    public static func data(_ name: String) throws -> Data {
        try Data(contentsOf: try url(name))
    }

    /// Absolute path to the installed Wireshark engine, or nil when absent.
    public static var wiresharkApp: URL? {
        let candidates = [
            "/Applications/Wireshark.app",
            NSHomeDirectory() + "/Applications/Wireshark.app",
        ]
        return candidates.first { FileManager.default.fileExists(atPath: $0) }
            .map { URL(fileURLWithPath: $0) }
    }
}
