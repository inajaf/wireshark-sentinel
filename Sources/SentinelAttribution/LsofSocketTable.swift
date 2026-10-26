import Foundation
import SentinelDomain

public struct LsofSocketTable: SocketTableProviding {
    private let lsofPath: String

    public init(lsofPath: String = "/usr/sbin/lsof") {
        self.lsofPath = lsofPath
    }

    public func snapshot() -> [SocketOwner] {
        guard let text = Subprocess.output(lsofPath, ["-nP", "-i"]) else { return [] }
        return LsofRowParser.owners(from: text)
    }
}

enum LsofRowParser {
    static func owners(from text: String) -> [SocketOwner] {
        text.split(separator: "\n").compactMap(owner(from:))
    }

    private static func owner(from line: Substring) -> SocketOwner? {
        let tokens = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        let lowered = tokens.map { $0.lowercased() }
        guard lowered.count > 4, let pid = Int32(tokens[1]) else { return nil }
        guard let nodeIndex = lowered.indices.dropFirst(4).first(where: { lowered[$0] == "tcp" || lowered[$0] == "udp" }),
              nodeIndex + 1 < tokens.count
        else { return nil }
        guard let sockets = sockets(from: tokens[(nodeIndex + 1)...].joined(separator: " ")) else { return nil }
        return SocketOwner(
            pid: pid,
            command: tokens[0],
            transport: lowered[nodeIndex] == "tcp" ? .tcp : .udp,
            localAddress: sockets.local.host,
            localPort: sockets.local.port,
            remoteAddress: sockets.remote.host,
            remotePort: sockets.remote.port
        )
    }

    private static func sockets(from name: String) -> (local: (host: String, port: UInt16), remote: (host: String, port: UInt16))? {
        let cleaned = stripState(name)
        guard let arrow = cleaned.range(of: "->") else {
            guard let local = endpoint(cleaned) else { return nil }
            return (local, ("*", 0))
        }
        guard let local = endpoint(String(cleaned[..<arrow.lowerBound])),
              let remote = endpoint(String(cleaned[arrow.upperBound...]))
        else { return nil }
        return (local, remote)
    }

    private static func stripState(_ name: String) -> String {
        guard name.hasSuffix(")"), let open = name.lastIndex(of: "(") else { return name }
        return name[..<open].trimmingCharacters(in: .whitespaces)
    }

    private static func endpoint(_ text: String) -> (host: String, port: UInt16)? {
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]") else { return nil }
            let host = String(text[text.index(after: text.startIndex)..<close])
            let tail = text[text.index(after: close)...]
            guard tail.hasPrefix(":") else { return nil }
            return (host, port(String(tail.dropFirst())))
        }
        guard let colon = text.lastIndex(of: ":") else { return nil }
        let host = text[..<colon]
        return (host.isEmpty ? "*" : String(host), port(String(text[text.index(after: colon)...])))
    }

    private static func port(_ text: String) -> UInt16 {
        text == "*" ? 0 : (UInt16(text) ?? 0)
    }
}
