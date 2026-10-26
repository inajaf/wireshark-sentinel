import Foundation

// The frozen contract for every other file in this package.
// Types here change only through the Lead. Implementations must not edit this file.

// MARK: - Addresses and flows

public enum TransportProtocol: String, Sendable, Codable, CaseIterable {
    case tcp, udp, other

    public init(ipProtocolNumber: Int) {
        switch ipProtocolNumber {
        case 6: self = .tcp
        case 17: self = .udp
        default: self = .other
        }
    }
}

public struct Endpoint: Hashable, Sendable, Codable, CustomStringConvertible {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    public var description: String { port == 0 ? host : "\(host):\(port)" }
}

public enum FlowDirection: String, Sendable, Codable {
    case inbound, outbound, loopback, broadcast, multicast
}

public struct FlowKey: Hashable, Sendable, Codable {
    public let transport: TransportProtocol
    public let local: Endpoint
    public let remote: Endpoint

    public init(transport: TransportProtocol, local: Endpoint, remote: Endpoint) {
        self.transport = transport
        self.local = local
        self.remote = remote
    }

    /// The remote endpoint is the resource under investigation.
    public var remoteEndpoint: Endpoint { remote }
    public var localEndpoint: Endpoint { local }
}

// MARK: - Captured data

public struct CapturedPacket: Identifiable, Sendable {
    public let id: Int
    public let time: Date
    public let source: String
    public let destination: String
    public let proto: String
    public let length: Int
    public let info: String
    public let transport: TransportProtocol
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let fields: [String: [String]]

    public init(
        id: Int,
        time: Date,
        source: String,
        destination: String,
        proto: String,
        length: Int,
        info: String,
        transport: TransportProtocol = .other,
        sourcePort: UInt16 = 0,
        destinationPort: UInt16 = 0,
        fields: [String: [String]] = [:]
    ) {
        self.id = id
        self.time = time
        self.source = source
        self.destination = destination
        self.proto = proto
        self.length = length
        self.info = info
        self.transport = transport
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.fields = fields
    }

    /// First value of a field, using the underscored EK field name.
    public func field(_ name: String) -> String? { fields[name]?.first }
}

public enum PacketEvent: Sendable {
    case packet(CapturedPacket)
    case error(String)
    case finished
}

public struct DetailNode: Identifiable, Sendable {
    public let id: String
    public let label: String
    public let value: String?
    public let children: [DetailNode]

    public init(id: String, label: String, value: String? = nil, children: [DetailNode] = []) {
        self.id = id
        self.label = label
        self.value = value
        self.children = children
    }
}

public struct PacketDetail: Sendable {
    public let frameNumber: Int
    public let tree: [DetailNode]
    public let bytes: [String]

    public init(frameNumber: Int, tree: [DetailNode] = [], bytes: [String] = []) {
        self.frameNumber = frameNumber
        self.tree = tree
        self.bytes = bytes
    }
}

public struct CaptureInterface: Identifiable, Hashable, Sendable {
    public let id: String
    public let name: String
    public let detail: String?

    public init(id: String, name: String, detail: String? = nil) {
        self.id = id
        self.name = name
        self.detail = detail
    }
}

public struct CaptureFilter: Sendable {
    public let interfaceID: String
    public let displayFilter: String?

    public init(interfaceID: String, displayFilter: String? = nil) {
        self.interfaceID = interfaceID
        self.displayFilter = displayFilter
    }
}

// MARK: - The engine seam

public protocol CaptureEngine: AnyObject, Sendable {
    func interfaces() async -> [CaptureInterface]
    func start(_ filter: CaptureFilter) async throws -> AsyncStream<PacketEvent>
    func stop() async
    func detail(frameNumber: Int) async throws -> PacketDetail
}

// MARK: - Identity

public enum Confidence: String, Sendable, Codable {
    case observed, inferred, unknown
}

public enum IdentitySource: String, Sendable, Codable, CaseIterable {
    case ptr
    case sni
    case httpHost
    case dnsQuery
    case tlsSubject
    case tlsIssuer
    case serviceCatalog
    case portTable
    case userAgent
    case localAddress
    case manual
}

public struct IdentityFact: Sendable, Codable, Equatable {
    public let value: String
    public let source: IdentitySource
    public let confidence: Confidence

    public init(value: String, source: IdentitySource, confidence: Confidence) {
        self.value = value
        self.source = source
        self.confidence = confidence
    }
}

/// What the scanner learned about one remote resource.
public struct EndpointIdentity: Sendable {
    public var facts: [IdentityFact]
    public var organization: String?
    public var service: String?
    public var firstSeen: Date?
    public var lastSeen: Date?
    public var packetCount: Int
    public var byteCount: Int
    public var ports: Set<UInt16>
    public var isLocal: Bool
    public var isPrivate: Bool

    public init(
        facts: [IdentityFact] = [],
        organization: String? = nil,
        service: String? = nil,
        firstSeen: Date? = nil,
        lastSeen: Date? = nil,
        packetCount: Int = 0,
        byteCount: Int = 0,
        ports: Set<UInt16> = [],
        isLocal: Bool = false,
        isPrivate: Bool = false
    ) {
        self.facts = facts
        self.organization = organization
        self.service = service
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.packetCount = packetCount
        self.byteCount = byteCount
        self.ports = ports
        self.isLocal = isLocal
        self.isPrivate = isPrivate
    }

    /// The best human-readable name, observed facts before inferred ones.
    public var displayName: String? {
        let ranked = facts.sorted { lhs, rhs in
            rank(lhs.confidence) < rank(rhs.confidence)
        }
        return ranked.first?.value
    }

    public var isIdentified: Bool {
        facts.contains { $0.confidence != .unknown } || organization != nil || service != nil
    }

    private func rank(_ c: Confidence) -> Int {
        switch c {
        case .observed: return 0
        case .inferred: return 1
        case .unknown: return 2
        }
    }
}

// MARK: - Attribution

public enum SigningStatus: Sendable, Codable, Equatable {
    case apple
    case developerID(team: String)
    case adHoc
    case unsigned
    case unknown
}

public struct ProcessIdentity: Sendable, Codable, Equatable {
    public let pid: Int32
    public let name: String
    public let path: String?
    public let bundleID: String?
    public let signing: SigningStatus

    public init(pid: Int32, name: String, path: String? = nil, bundleID: String? = nil, signing: SigningStatus = .unknown) {
        self.pid = pid
        self.name = name
        self.path = path
        self.bundleID = bundleID
        self.signing = signing
    }
}

// MARK: - Assessment

public enum SignalKind: String, Sendable, Codable, CaseIterable {
    case unknownDestination
    case inboundUnsolicited
    case beaconing
    case unsignedProcess
    case unusualPort
    case plaintextProtocol
    case dnsHighVolume
    case longLivedIdle
    case newDestinationBurst
    case rawIPTraffic
    case unrecognisedService

    public var title: String {
        switch self {
        case .unknownDestination: return "Unidentified destination"
        case .inboundUnsolicited: return "Inbound connection to this Mac"
        case .beaconing: return "Regular beaconing"
        case .unsignedProcess: return "Unsigned or unnotarised process"
        case .unusualPort: return "Unusual service port"
        case .plaintextProtocol: return "Plaintext protocol"
        case .dnsHighVolume: return "High-volume DNS"
        case .longLivedIdle: return "Long-lived idle connection"
        case .newDestinationBurst: return "Burst of new destinations"
        case .rawIPTraffic: return "Traffic with no payload protocol"
        case .unrecognisedService: return "Service not in the catalogue"
        }
    }
}

public struct Signal: Sendable, Codable, Equatable {
    public let kind: SignalKind
    public let weight: Int
    public let detail: String
    public let evidence: [String]

    public init(kind: SignalKind, weight: Int, detail: String, evidence: [String] = []) {
        self.kind = kind
        self.weight = weight
        self.detail = detail
        self.evidence = evidence
    }
}

public enum Verdict: String, Sendable, Codable {
    case known, unknown, suspicious
}

public struct FlowAssessment: Sendable, Identifiable {
    public var id: FlowKey { key }
    public let key: FlowKey
    public let direction: FlowDirection
    public let identity: EndpointIdentity
    public let process: ProcessIdentity?
    public let signals: [Signal]
    public let score: Int
    public let verdict: Verdict
    public let rationale: String
    public let firstSeen: Date
    public let lastSeen: Date
    public let packetCount: Int
    public let byteCount: Int

    public init(
        key: FlowKey,
        direction: FlowDirection,
        identity: EndpointIdentity,
        process: ProcessIdentity?,
        signals: [Signal],
        score: Int,
        verdict: Verdict,
        rationale: String,
        firstSeen: Date,
        lastSeen: Date,
        packetCount: Int,
        byteCount: Int
    ) {
        self.key = key
        self.direction = direction
        self.identity = identity
        self.process = process
        self.signals = signals
        self.score = score
        self.verdict = verdict
        self.rationale = rationale
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.packetCount = packetCount
        self.byteCount = byteCount
    }
}

// MARK: - Shared helpers

public enum AddressScope {
    public static func isPrivate(_ host: String) -> Bool {
        if host.hasPrefix("10.") || host.hasPrefix("192.168.") || host.hasPrefix("127.") { return true }
        if host.hasPrefix("172.") {
            let parts = host.split(separator: ".")
            if parts.count > 1, let second = Int(parts[1]), (16...31).contains(second) { return true }
        }
        if host.hasPrefix("169.254.") { return true }
        if host.lowercased().hasPrefix("fe80:") || host == "::1" || host.lowercased().hasPrefix("fc") || host.lowercased().hasPrefix("fd") { return true }
        return false
    }

    public static func isMulticastOrBroadcast(_ host: String) -> Bool {
        host == "255.255.255.255" || host.hasPrefix("224.") || host.lowercased().hasPrefix("ff02:")
    }
}
