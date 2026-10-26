import SentinelDomain

/// Port to service name, from the system table plus a built-in catalogue.
public struct ServiceCatalog: Sendable {
    private let entries: [UInt16: String]

    public init(entries: [UInt16: String] = [:]) {
        self.entries = entries
    }

    public static let builtIn = ServiceCatalog()

    /// Caller entries win, so a capture-specific name can replace a generic one.
    public func service(forPort port: UInt16, transport: TransportProtocol) -> String? {
        if let named = entries[port] { return named }
        switch transport {
        case .tcp: return Self.tcpServices[port] ?? Self.sharedServices[port]
        case .udp: return Self.udpServices[port] ?? Self.sharedServices[port]
        case .other: return Self.sharedServices[port] ?? Self.tcpServices[port] ?? Self.udpServices[port]
        }
    }

    private static let sharedServices: [UInt16: String] = [
        443: "https",
        80: "http",
        53: "domain",
        22: "ssh",
    ]

    private static let tcpServices: [UInt16: String] = [
        25: "smtp",
        587: "submission",
        993: "imaps",
        5223: "apns",
        5228: "google-play",
        6679: "google-quic",
    ]

    private static let udpServices: [UInt16: String] = [
        123: "ntp",
        5353: "mdns",
        67: "dhcp",
        68: "dhcp",
    ]
}
