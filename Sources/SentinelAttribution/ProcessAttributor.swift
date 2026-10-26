import Foundation
import SentinelDomain

/// A socket table row, as `lsof -nP -i` reports it.
public struct SocketOwner: Sendable, Hashable {
    public let pid: Int32
    public let command: String
    public let transport: TransportProtocol
    public let localAddress: String
    public let localPort: UInt16
    public let remoteAddress: String
    public let remotePort: UInt16

    public init(
        pid: Int32, command: String, transport: TransportProtocol,
        localAddress: String, localPort: UInt16,
        remoteAddress: String, remotePort: UInt16
    ) {
        self.pid = pid
        self.command = command
        self.transport = transport
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
    }
}

public protocol SocketTableProviding: Sendable {
    func snapshot() -> [SocketOwner]
}

/// Answers "which program on this Mac opened that connection".
public final class ProcessAttributor: @unchecked Sendable {
    private struct CacheKey: Hashable {
        let pid: Int32
        let command: String
    }

    private let table: SocketTableProviding
    private let signing: SigningChecking
    private let paths: ProcessPathResolving
    private let lock = NSLock()
    private var rows: [SocketOwner] = []
    private var identities: [CacheKey: ProcessIdentity] = [:]

    public init(
        table: SocketTableProviding = LsofSocketTable(),
        signing: SigningChecking = CodesignSigningChecker(),
        paths: ProcessPathResolving = LsofProcessPaths()
    ) {
        self.table = table
        self.signing = signing
        self.paths = paths
    }

    public func refresh() {
        let snapshot = table.snapshot()
        lock.lock()
        rows = snapshot
        lock.unlock()
    }

    public func process(remote: Endpoint, localPort: UInt16, transport: TransportProtocol) -> ProcessIdentity? {
        guard localPort != 0 else { return nil }
        lock.lock()
        let candidates = rows.filter { $0.transport == transport && $0.localPort == localPort }
        lock.unlock()
        let exact = candidates.first { matches($0, remote: remote) }
        // An unconnected UDP socket reports its remote as `*:*`, so the local port is the only key.
        let row = exact ?? (transport == .udp ? candidates.first : nil)
        guard let row else { return nil }
        return identity(for: row)
    }

    private func matches(_ row: SocketOwner, remote: Endpoint) -> Bool {
        guard remote.port != 0, row.remotePort == remote.port else { return false }
        return trimmed(row.remoteAddress) == trimmed(remote.host)
    }

    private func trimmed(_ address: String) -> String {
        var value = address.lowercased()
        if value.hasPrefix("["), value.hasSuffix("]") {
            value = String(value.dropFirst().dropLast())
        }
        return value
    }

    private func identity(for row: SocketOwner) -> ProcessIdentity {
        let key = CacheKey(pid: row.pid, command: row.command)
        lock.lock()
        let cached = identities[key]
        lock.unlock()
        if let cached { return cached }

        let path = paths.path(forPID: row.pid)
        let identity = ProcessIdentity(
            pid: row.pid,
            name: path.map { URL(fileURLWithPath: $0).lastPathComponent } ?? row.command,
            path: path,
            bundleID: nil,
            signing: path.map { signing.status(forPath: $0) } ?? .unknown
        )
        lock.lock()
        identities[key] = identity
        lock.unlock()
        return identity
    }
}
