import Foundation

// MARK: - IP classification

public enum IPScope: String, Sendable, Codable, CaseIterable {
    case publicInternet
    case privateNetwork
    case carrierGradeNAT
    case loopback
    case linkLocal
    case multicast
    case broadcast
    case documentation
    case benchmark
    case reserved
    case unspecified
    case unknown

    public var label: String {
        switch self {
        case .publicInternet: return "public internet"
        case .privateNetwork: return "private network"
        case .carrierGradeNAT: return "carrier-grade NAT"
        case .loopback: return "this Mac (loopback)"
        case .linkLocal: return "link-local"
        case .multicast: return "multicast group"
        case .broadcast: return "broadcast"
        case .documentation: return "documentation range"
        case .benchmark: return "benchmark range"
        case .reserved: return "reserved or special-use"
        case .unspecified: return "unspecified address"
        case .unknown: return "unknown"
        }
    }

    /// A public address is the only kind that should be sent to an external
    /// registry or probed without an explicit local-network confirmation.
    public var isPublic: Bool { self == .publicInternet }
}

public struct IPClassification: Sendable, Codable, Equatable {
    public var address: String
    public var family: String
    public var scope: IPScope
    public var isPublic: Bool
    public var explanation: String

    public init(address: String, family: String, scope: IPScope, explanation: String) {
        self.address = address
        self.family = family
        self.scope = scope
        self.isPublic = scope.isPublic
        self.explanation = explanation
    }
}

// MARK: - Scan options

public enum ScanDepth: String, Sendable, Codable, CaseIterable, Identifiable {
    case passive
    case standard
    case deep
    case active

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .passive: return "Passive"
        case .standard: return "Standard"
        case .deep: return "Deep"
        case .active: return "Active probe"
        }
    }

    public var summary: String {
        switch self {
        case .passive:
            return "Read only the packets already captured. No new traffic."
        case .standard:
            return "Passive plus reverse DNS for public names."
        case .deep:
            return "Passive plus TLS certificates, JA3/JA4, TCP timing and certificate chain."
        case .active:
            return "Deep plus a consented TCP probe of the selected ports. Sends new traffic."
        }
    }
}

public struct ScanOptions: Sendable, Codable, Equatable {
    public var depth: ScanDepth
    public var includePrivate: Bool
    public var resolvePTR: Bool
    public var lookupRDAP: Bool
    public var lookupASN: Bool
    public var analyzeTLS: Bool
    public var analyzeTCP: Bool
    public var activeProbe: Bool
    public var activePorts: [UInt16]
    public var activeTimeout: TimeInterval
    public var maxConcurrentProbes: Int

    public init(
        depth: ScanDepth = .standard,
        includePrivate: Bool = false,
        resolvePTR: Bool = true,
        lookupRDAP: Bool = false,
        lookupASN: Bool = false,
        analyzeTLS: Bool = true,
        analyzeTCP: Bool = true,
        activeProbe: Bool = false,
        activePorts: [UInt16] = ScanOptions.commonPorts,
        activeTimeout: TimeInterval = 1.5,
        maxConcurrentProbes: Int = 8
    ) {
        self.depth = depth
        self.includePrivate = includePrivate
        self.resolvePTR = resolvePTR
        self.lookupRDAP = lookupRDAP
        self.lookupASN = lookupASN
        self.analyzeTLS = analyzeTLS
        self.analyzeTCP = analyzeTCP
        self.activeProbe = activeProbe
        self.activePorts = activePorts
        self.activeTimeout = activeTimeout
        self.maxConcurrentProbes = maxConcurrentProbes
    }

    public static let commonPorts: [UInt16] = [
        21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 631,
        993, 995, 1433, 1521, 1883, 3306, 3389, 5432, 5900, 6379, 8080,
        8443, 8888, 9200, 27017,
    ]

    /// A preset is a starting point; every toggle below can be changed afterwards.
    public static func preset(_ depth: ScanDepth) -> ScanOptions {
        switch depth {
        case .passive:
            return ScanOptions(
                depth: .passive,
                resolvePTR: false,
                lookupRDAP: false,
                analyzeTLS: true,
                analyzeTCP: true,
                activeProbe: false
            )
        case .standard:
            return ScanOptions(depth: .standard)
        case .deep:
            return ScanOptions(
                depth: .deep,
                resolvePTR: true,
                lookupRDAP: false,
                analyzeTLS: true,
                analyzeTCP: true,
                activeProbe: false
            )
        case .active:
            return ScanOptions(
                depth: .active,
                resolvePTR: true,
                lookupRDAP: false,
                analyzeTLS: true,
                analyzeTCP: true,
                activeProbe: true
            )
        }
    }

    public var sendsNewTraffic: Bool { activeProbe }
    public var sendsAddressToRegistry: Bool { lookupRDAP || lookupASN }
}

// MARK: - RDAP

public struct RDAPRecord: Sendable, Codable, Equatable {
    public var address: String
    public var asn: String?
    public var asnDescription: String?
    public var networkName: String?
    public var organization: String?
    public var country: String?
    public var abuseContact: String?
    public var registry: String?
    public var handle: String?
    public var fetchedAt: Date

    public init(
        address: String,
        asn: String? = nil,
        asnDescription: String? = nil,
        networkName: String? = nil,
        organization: String? = nil,
        country: String? = nil,
        abuseContact: String? = nil,
        registry: String? = nil,
        handle: String? = nil,
        fetchedAt: Date = Date()
    ) {
        self.address = address
        self.asn = asn
        self.asnDescription = asnDescription
        self.networkName = networkName
        self.organization = organization
        self.country = country
        self.abuseContact = abuseContact
        self.registry = registry
        self.handle = handle
        self.fetchedAt = fetchedAt
    }
}

// MARK: - Active probe

public enum ActiveProbeKind: String, Sendable, Codable, CaseIterable {
    case tcpConnect
    case tlsCertificate
    case httpHead
    case banner
}

public struct ActiveProbeResult: Sendable, Codable, Equatable, Identifiable {
    public var id: String { "\(host)|\(port)|\(transport.rawValue)" }
    public var host: String
    public var port: UInt16
    public var transport: TransportProtocol
    public var kind: ActiveProbeKind
    public var opened: Bool
    public var elapsed: TimeInterval?
    public var banner: String?
    public var tls: TLSDetails?
    public var httpStatus: Int?
    public var httpServer: String?
    public var error: String?

    public init(
        host: String,
        port: UInt16,
        transport: TransportProtocol = .tcp,
        kind: ActiveProbeKind = .tcpConnect,
        opened: Bool = false,
        elapsed: TimeInterval? = nil,
        banner: String? = nil,
        tls: TLSDetails? = nil,
        httpStatus: Int? = nil,
        httpServer: String? = nil,
        error: String? = nil
    ) {
        self.host = host
        self.port = port
        self.transport = transport
        self.kind = kind
        self.opened = opened
        self.elapsed = elapsed
        self.banner = banner
        self.tls = tls
        self.httpStatus = httpStatus
        self.httpServer = httpServer
        self.error = error
    }
}
