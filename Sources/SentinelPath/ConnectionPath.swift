import Foundation
import SentinelDomain

// MARK: - Route

/// What the system routing table says about reaching one address. This is local
/// data, not a network probe.
public struct RouteInfo: Sendable, Codable, Equatable {
    public var destination: String
    public var gateway: String?
    public var interfaceName: String?

    public init(destination: String, gateway: String? = nil, interfaceName: String? = nil) {
        self.destination = destination
        self.gateway = gateway
        self.interfaceName = interfaceName
    }

    public var isDirect: Bool { gateway == nil }
}

// MARK: - Nodes

public struct PathLocal: Sendable, Codable, Equatable {
    public var address: String
    public var port: UInt16
    public var interfaceName: String?
    public var processName: String?
    public var pid: Int32?
    public var signing: SigningStatus?
    public var socketState: String?
    public var direction: FlowDirection

    public init(
        address: String,
        port: UInt16,
        interfaceName: String? = nil,
        processName: String? = nil,
        pid: Int32? = nil,
        signing: SigningStatus? = nil,
        socketState: String? = nil,
        direction: FlowDirection
    ) {
        self.address = address
        self.port = port
        self.interfaceName = interfaceName
        self.processName = processName
        self.pid = pid
        self.signing = signing
        self.socketState = socketState
        self.direction = direction
    }
}

public struct PathRemote: Sendable, Codable, Equatable {
    public var address: String
    public var port: UInt16
    public var transport: TransportProtocol
    public var scope: IPScope
    public var evidencedName: String?
    public var reverseDNS: String?
    public var serviceGuess: String?
    public var asn: String?
    public var asnDescription: String?
    public var organization: String?
    public var networkName: String?
    public var country: String?
    public var registry: String?
    public var ttl: Int?
    public var estimatedHops: Int?
    public var observedProtocols: [String]

    public init(
        address: String,
        port: UInt16,
        transport: TransportProtocol,
        scope: IPScope,
        evidencedName: String? = nil,
        reverseDNS: String? = nil,
        serviceGuess: String? = nil,
        asn: String? = nil,
        asnDescription: String? = nil,
        organization: String? = nil,
        networkName: String? = nil,
        country: String? = nil,
        registry: String? = nil,
        ttl: Int? = nil,
        estimatedHops: Int? = nil,
        observedProtocols: [String] = []
    ) {
        self.address = address
        self.port = port
        self.transport = transport
        self.scope = scope
        self.evidencedName = evidencedName
        self.reverseDNS = reverseDNS
        self.serviceGuess = serviceGuess
        self.asn = asn
        self.asnDescription = asnDescription
        self.organization = organization
        self.networkName = networkName
        self.country = country
        self.registry = registry
        self.ttl = ttl
        self.estimatedHops = estimatedHops
        self.observedProtocols = observedProtocols
    }
}

public struct PathHop: Sendable, Codable, Identifiable, Hashable {
    public var index: Int
    public var address: String?
    public var rttMilliseconds: Double?
    public var scope: IPScope
    public var note: String?
    public var isDestination: Bool

    public var id: String { "\(index)|\(address ?? "no-reply")" }
    public var displayAddress: String { address ?? "no reply" }

    public init(
        index: Int,
        address: String? = nil,
        rttMilliseconds: Double? = nil,
        scope: IPScope = .unknown,
        note: String? = nil,
        isDestination: Bool = false
    ) {
        self.index = index
        self.address = address
        self.rttMilliseconds = rttMilliseconds
        self.scope = scope
        self.note = note
        self.isDestination = isDestination
    }
}

/// One name and every place the evidence for it came from. The same hostname
/// commonly appears in SNI, the certificate and reverse DNS; showing it once with
/// three source labels is more honest than presenting three separate "names".
public struct PathName: Sendable, Codable, Identifiable, Hashable {
    public var value: String
    public var sources: [ObservationSource]
    public var evidence: [String]

    public var id: String { value.lowercased() }

    public init(value: String, source: ObservationSource, evidence: String? = nil) {
        self.value = value
        self.sources = [source]
        self.evidence = evidence.map { [$0] } ?? []
    }

    public mutating func add(source: ObservationSource, evidence: String?) {
        if !sources.contains(source) { sources.append(source) }
        if let evidence, !evidence.isEmpty, !self.evidence.contains(evidence) {
            self.evidence.append(evidence)
        }
    }
}

// MARK: - Active checks

public struct PingResult: Sendable, Codable, Equatable {
    public var host: String
    public var hostname: String?
    public var responded: Bool
    public var rttMilliseconds: Double?
    public var packetLossPercent: Double?
    public var error: String?
    public var method: String
    public var command: String
    public var ranAt: Date

    public init(
        host: String,
        hostname: String? = nil,
        responded: Bool = false,
        rttMilliseconds: Double? = nil,
        packetLossPercent: Double? = nil,
        error: String? = nil,
        method: String = "ICMP echo",
        command: String = "",
        ranAt: Date = Date()
    ) {
        self.host = host
        self.hostname = hostname
        self.responded = responded
        self.rttMilliseconds = rttMilliseconds
        self.packetLossPercent = packetLossPercent
        self.error = error
        self.method = method
        self.command = command
        self.ranAt = ranAt
    }
}

public struct PathTrace: Sendable, Codable, Equatable {
    public var ranAt: Date
    public var hops: [PathHop]
    public var reachedDestination: Bool
    public var error: String?
    public var warnings: [String]
    public var command: String

    public init(
        ranAt: Date = Date(),
        hops: [PathHop] = [],
        reachedDestination: Bool = false,
        error: String? = nil,
        warnings: [String] = [],
        command: String = ""
    ) {
        self.ranAt = ranAt
        self.hops = hops
        self.reachedDestination = reachedDestination
        self.error = error
        self.warnings = warnings
        self.command = command
    }

    public var isPartial: Bool {
        error == nil && !reachedDestination && !hops.isEmpty
    }
}

// MARK: - The whole path

public struct ConnectionPath: Sendable, Codable {
    public var flow: FlowKey
    public var builtAt: Date
    public var local: PathLocal
    public var route: RouteInfo?
    public var remote: PathRemote
    public var names: [PathName]
    public var trace: PathTrace?
    public var ping: PingResult?
    public var observations: [ConnectionObservation]
    public var warnings: [String]

    public init(
        flow: FlowKey,
        builtAt: Date = Date(),
        local: PathLocal,
        route: RouteInfo?,
        remote: PathRemote,
        names: [PathName] = [],
        trace: PathTrace? = nil,
        ping: PingResult? = nil,
        observations: [ConnectionObservation] = [],
        warnings: [String] = []
    ) {
        self.flow = flow
        self.builtAt = builtAt
        self.local = local
        self.route = route
        self.remote = remote
        self.names = names
        self.trace = trace
        self.ping = ping
        self.observations = observations
        self.warnings = warnings
    }

    /// Hops between this Mac and the service. The destination gets its own node,
    /// so the last traceroute hop would otherwise be shown twice.
    public var transitHops: [PathHop] {
        (trace?.hops ?? []).filter { !$0.isDestination }
    }

    public var bestName: String? {
        if let name = remote.evidencedName { return name }
        if let name = names.first(where: { !$0.sources.contains(.dns) })?.value { return name }
        return remote.reverseDNS ?? names.first?.value
    }

    public mutating func addName(_ value: String, source: ObservationSource, evidence: String? = nil) {
        let clean = PathAddress.cleanName(value)
        guard !clean.isEmpty, !EndpointIdentity.isAddressLiteral(clean) else { return }
        if let index = names.firstIndex(where: {
            $0.value.caseInsensitiveCompare(clean) == .orderedSame
        }) {
            names[index].add(source: source, evidence: evidence)
        } else {
            names.append(PathName(value: clean, source: source, evidence: evidence))
        }
    }
}

// MARK: - Probe safety

public enum PathProbeSafety {
    /// Trace and ping run from this Mac. They refuse targets that cannot be a
    /// remote service or would need privileges this app should not ask for.
    public static func problem(
        for host: String,
        localAddresses: Set<String> = [],
        broadcastAddresses: Set<String> = []
    ) -> String? {
        let address = PathAddress.bare(host)
        guard !address.isEmpty else { return "The target address is empty." }

        switch IPClassifier.classify(address).scope {
        case .loopback:
            return "Loopback traffic stays on this Mac and cannot be traced to a service."
        case .multicast:
            return "A multicast group is not one host, so there is no path to trace."
        case .broadcast:
            return "A broadcast address is not one host, so there is no path to trace."
        case .unspecified:
            return "The unspecified address has no service to reach."
        case .linkLocal:
            return "Link-local addresses need a zone and are not traced from this window."
        case .unknown:
            return "\(address) is not an IPv4 or IPv6 address."
        default:
            break
        }

        for broadcast in broadcastAddresses where PathAddress.same(broadcast, address) {
            return "\(address) is a broadcast address for this Mac's network."
        }
        for local in localAddresses where PathAddress.same(local, address) {
            return "\(address) is this Mac's own address."
        }
        return nil
    }

    public static func isAllowed(
        _ host: String,
        localAddresses: Set<String> = [],
        broadcastAddresses: Set<String> = []
    ) -> Bool {
        problem(for: host, localAddresses: localAddresses, broadcastAddresses: broadcastAddresses) == nil
    }
}
