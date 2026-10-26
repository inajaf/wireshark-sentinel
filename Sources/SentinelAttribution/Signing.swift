import Foundation
import SentinelDomain

public protocol SigningChecking: Sendable {
    func status(forPath path: String) -> SigningStatus
}

public struct CodesignSigningChecker: SigningChecking {
    private let codesignPath: String

    public init(codesignPath: String = "/usr/bin/codesign") {
        self.codesignPath = codesignPath
    }

    public func status(forPath path: String) -> SigningStatus {
        guard let output = Subprocess.output(codesignPath, ["-dv", "--verbose=4", path]) else { return .unknown }
        return Self.status(fromCodesignOutput: output)
    }

    static func status(fromCodesignOutput output: String) -> SigningStatus {
        if output.contains("is not signed at all") { return .unsigned }
        if output.contains("Signature=adhoc") || output.contains("(adhoc)") { return .adHoc }
        if let team = developerIDTeam(in: output) { return .developerID(team: team) }
        if output.contains("Software Signing") || output.contains("Platform identifier") { return .apple }
        return .unknown
    }

    private static func developerIDTeam(in output: String) -> String? {
        let prefix = "Authority=Developer ID Application: "
        guard let line = output.split(separator: "\n").first(where: { $0.hasPrefix(prefix) }) else { return nil }
        if let open = line.lastIndex(of: "("), let close = line.lastIndex(of: ")"), open < close {
            return String(line[line.index(after: open)..<close])
        }
        return teamIdentifier(in: output) ?? "unknown"
    }

    private static func teamIdentifier(in output: String) -> String? {
        let prefix = "TeamIdentifier="
        guard let line = output.split(separator: "\n").first(where: { $0.hasPrefix(prefix) }) else { return nil }
        let value = line.dropFirst(prefix.count)
        return value.isEmpty || value == "not set" ? nil : String(value)
    }
}
