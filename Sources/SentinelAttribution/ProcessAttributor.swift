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

public struct LsofSocketTable: SocketTableProviding {
    public init(lsofPath: String = "/usr/sbin/lsof") {}
    public func snapshot() -> [SocketOwner] { [] }
}

public protocol SigningChecking: Sendable {
    func status(forPath path: String) -> SigningStatus
}

public struct CodesignSigningChecker: SigningChecking {
    public init() {}
    public func status(forPath path: String) -> SigningStatus { .unknown }
}

/// Answers "which program on this Mac opened that connection".
public final class ProcessAttributor: @unchecked Sendable {
    public init(table: SocketTableProviding = LsofSocketTable(), signing: SigningChecking = CodesignSigningChecker()) {}

    public func refresh() {}

    public func process(remote: Endpoint, localPort: UInt16, transport: TransportProtocol) -> ProcessIdentity? { nil }
}
