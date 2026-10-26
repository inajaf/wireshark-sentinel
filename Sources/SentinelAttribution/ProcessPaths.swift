import Foundation

public protocol ProcessPathResolving: Sendable {
    func path(forPID pid: Int32) -> String?
}

public struct LsofProcessPaths: ProcessPathResolving {
    private let lsofPath: String
    private let psPath: String

    public init(lsofPath: String = "/usr/sbin/lsof", psPath: String = "/bin/ps") {
        self.lsofPath = lsofPath
        self.psPath = psPath
    }

    public func path(forPID pid: Int32) -> String? {
        if let text = Subprocess.output(lsofPath, ["-p", "\(pid)", "-a", "-d", "txt", "-Fn"]) {
            for line in text.split(separator: "\n") where line.hasPrefix("n") {
                let path = String(line.dropFirst())
                if !path.isEmpty { return path }
            }
        }
        guard let text = Subprocess.output(psPath, ["-p", "\(pid)", "-o", "comm="]) else { return nil }
        let path = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return path.isEmpty ? nil : path
    }
}
