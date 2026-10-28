import Foundation

// Additive contracts for the connection inspector and the deeper IP scan.
// Nothing here changes the existing capture, identity or assessment types.

// MARK: - Provenance

/// Where one value came from. The inspector shows this next to the value so a
/// certificate name and a port guess cannot be mistaken for each other.
public enum ObservationSource: String, Sendable, Codable, CaseIterable {
    case packets
    case tshark
    case certificate
    case dns
    case lsof
    case process
    case rdap
    case asn
    case userInput
    case inferred

    public var label: String {
        switch self {
        case .packets: return "captured packets"
        case .tshark: return "Wireshark dissector"
        case .certificate: return "TLS certificate"
        case .dns: return "reverse DNS"
        case .lsof: return "open socket table"
        case .process: return "process table"
        case .rdap: return "RDAP registry"
        case .asn: return "ASN lookup"
        case .userInput: return "your input"
        case .inferred: return "inferred"
        }
    }
}

public struct ConnectionObservation: Sendable, Codable, Identifiable, Hashable {
    public let section: String
    public let label: String
    public let value: String
    public let source: ObservationSource
    public let confidence: Confidence

    public var id: String { "\(section)|\(label)|\(value)|\(source.rawValue)" }

    public init(
        section: String,
        label: String,
        value: String,
        source: ObservationSource,
        confidence: Confidence = .observed
    ) {
        self.section = section
        self.label = label
        self.value = value
        self.source = source
        self.confidence = confidence
    }
}

// MARK: - Network

public struct NetworkDetails: Sendable, Codable, Equatable {
    public var address: String
    public var family: String
    public var scope: String
    public var reverseDNS: String?
    public var organization: String?
    public var networkName: String?
    public var asn: String?
    public var asnDescription: String?
    public var registry: String?
    public var country: String?
    public var abuseContact: String?
    public var ttl: Int?
    public var estimatedHops: Int?
    public var dontFragment: Bool?
    public var fragmentation: String?
    public var dscp: Int?
    public var ecn: Int?
    public var ipv6FlowLabel: String?
    public var firstSeen: Date?
    public var lastSeen: Date?
    public var bytesSent: Int
    public var bytesReceived: Int
    public var packetsSent: Int
    public var packetsReceived: Int

    public init(
        address: String,
        family: String = "",
        scope: String = "",
        reverseDNS: String? = nil,
        organization: String? = nil,
        networkName: String? = nil,
        asn: String? = nil,
        asnDescription: String? = nil,
        registry: String? = nil,
        country: String? = nil,
        abuseContact: String? = nil,
        ttl: Int? = nil,
        estimatedHops: Int? = nil,
        dontFragment: Bool? = nil,
        fragmentation: String? = nil,
        dscp: Int? = nil,
        ecn: Int? = nil,
        ipv6FlowLabel: String? = nil,
        firstSeen: Date? = nil,
        lastSeen: Date? = nil,
        bytesSent: Int = 0,
        bytesReceived: Int = 0,
        packetsSent: Int = 0,
        packetsReceived: Int = 0
    ) {
        self.address = address
        self.family = family
        self.scope = scope
        self.reverseDNS = reverseDNS
        self.organization = organization
        self.networkName = networkName
        self.asn = asn
        self.asnDescription = asnDescription
        self.registry = registry
        self.country = country
        self.abuseContact = abuseContact
        self.ttl = ttl
        self.estimatedHops = estimatedHops
        self.dontFragment = dontFragment
        self.fragmentation = fragmentation
        self.dscp = dscp
        self.ecn = ecn
        self.ipv6FlowLabel = ipv6FlowLabel
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.packetsSent = packetsSent
        self.packetsReceived = packetsReceived
    }
}

// MARK: - Transport

public struct TCPDetails: Sendable, Codable, Equatable {
    public var state: String?
    public var streams: [Int]
    public var synCount: Int
    public var synAckCount: Int
    public var finCount: Int
    public var rstCount: Int
    public var retransmissions: Int
    public var fastRetransmissions: Int
    public var duplicateACKs: Int
    public var outOfOrder: Int
    public var zeroWindow: Int
    public var keepAlives: Int
    public var initialRTT: Double?
    public var lastRTT: Double?
    public var mss: Int?
    public var windowScale: Int?
    public var sackPermitted: Bool?
    public var timestamps: Bool?
    public var completeness: String?
    public var bytesSent: Int
    public var bytesReceived: Int
    public var packetsSent: Int
    public var packetsReceived: Int

    public init(
        state: String? = nil,
        streams: [Int] = [],
        synCount: Int = 0,
        synAckCount: Int = 0,
        finCount: Int = 0,
        rstCount: Int = 0,
        retransmissions: Int = 0,
        fastRetransmissions: Int = 0,
        duplicateACKs: Int = 0,
        outOfOrder: Int = 0,
        zeroWindow: Int = 0,
        keepAlives: Int = 0,
        initialRTT: Double? = nil,
        lastRTT: Double? = nil,
        mss: Int? = nil,
        windowScale: Int? = nil,
        sackPermitted: Bool? = nil,
        timestamps: Bool? = nil,
        completeness: String? = nil,
        bytesSent: Int = 0,
        bytesReceived: Int = 0,
        packetsSent: Int = 0,
        packetsReceived: Int = 0
    ) {
        self.state = state
        self.streams = streams
        self.synCount = synCount
        self.synAckCount = synAckCount
        self.finCount = finCount
        self.rstCount = rstCount
        self.retransmissions = retransmissions
        self.fastRetransmissions = fastRetransmissions
        self.duplicateACKs = duplicateACKs
        self.outOfOrder = outOfOrder
        self.zeroWindow = zeroWindow
        self.keepAlives = keepAlives
        self.initialRTT = initialRTT
        self.lastRTT = lastRTT
        self.mss = mss
        self.windowScale = windowScale
        self.sackPermitted = sackPermitted
        self.timestamps = timestamps
        self.completeness = completeness
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.packetsSent = packetsSent
        self.packetsReceived = packetsReceived
    }
}

public struct UDPDetails: Sendable, Codable, Equatable {
    public var streams: [Int]
    public var bytesSent: Int
    public var bytesReceived: Int
    public var packetsSent: Int
    public var packetsReceived: Int

    public init(
        streams: [Int] = [],
        bytesSent: Int = 0,
        bytesReceived: Int = 0,
        packetsSent: Int = 0,
        packetsReceived: Int = 0
    ) {
        self.streams = streams
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.packetsSent = packetsSent
        self.packetsReceived = packetsReceived
    }
}

public struct TransportDetails: Sendable, Codable, Equatable {
    public var tcp: TCPDetails?
    public var udp: UDPDetails?
    public var duration: TimeInterval?

    public init(tcp: TCPDetails? = nil, udp: UDPDetails? = nil, duration: TimeInterval? = nil) {
        self.tcp = tcp
        self.udp = udp
        self.duration = duration
    }
}

// MARK: - TLS

public struct CertificateSummary: Sendable, Codable, Identifiable, Hashable {
    public var index: Int
    public var subject: String?
    public var issuer: String?
    public var commonName: String?
    public var organization: String?
    public var subjectAlternativeNames: [String]
    public var notBefore: Date?
    public var notAfter: Date?
    public var serialNumber: String?
    public var signatureAlgorithm: String?
    public var publicKeyAlgorithm: String?
    public var curve: String?
    public var sha256: String?
    public var isCA: Bool?
    public var isExpired: Bool?
    public var daysRemaining: Int?

    public var id: String {
        "\(index)|\(serialNumber ?? "")|\(subject ?? "")"
    }

    public init(
        index: Int,
        subject: String? = nil,
        issuer: String? = nil,
        commonName: String? = nil,
        organization: String? = nil,
        subjectAlternativeNames: [String] = [],
        notBefore: Date? = nil,
        notAfter: Date? = nil,
        serialNumber: String? = nil,
        signatureAlgorithm: String? = nil,
        publicKeyAlgorithm: String? = nil,
        curve: String? = nil,
        sha256: String? = nil,
        isCA: Bool? = nil,
        isExpired: Bool? = nil,
        daysRemaining: Int? = nil
    ) {
        self.index = index
        self.subject = subject
        self.issuer = issuer
        self.commonName = commonName
        self.organization = organization
        self.subjectAlternativeNames = subjectAlternativeNames
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.serialNumber = serialNumber
        self.signatureAlgorithm = signatureAlgorithm
        self.publicKeyAlgorithm = publicKeyAlgorithm
        self.curve = curve
        self.sha256 = sha256
        self.isCA = isCA
        self.isExpired = isExpired
        self.daysRemaining = daysRemaining
    }
}

public struct TLSDetails: Sendable, Codable, Equatable {
    public var version: String?
    public var cipherSuite: String?
    public var cipherSuiteName: String?
    public var alpn: [String]
    public var serverName: String?
    public var ja3: String?
    public var ja3Full: String?
    public var ja4: String?
    public var ja4R: String?
    public var handshakeFrames: [Int]
    public var supportedGroups: [String]
    public var signatureAlgorithms: [String]
    public var certificates: [CertificateSummary]

    public init(
        version: String? = nil,
        cipherSuite: String? = nil,
        cipherSuiteName: String? = nil,
        alpn: [String] = [],
        serverName: String? = nil,
        ja3: String? = nil,
        ja3Full: String? = nil,
        ja4: String? = nil,
        ja4R: String? = nil,
        handshakeFrames: [Int] = [],
        supportedGroups: [String] = [],
        signatureAlgorithms: [String] = [],
        certificates: [CertificateSummary] = []
    ) {
        self.version = version
        self.cipherSuite = cipherSuite
        self.cipherSuiteName = cipherSuiteName
        self.alpn = alpn
        self.serverName = serverName
        self.ja3 = ja3
        self.ja3Full = ja3Full
        self.ja4 = ja4
        self.ja4R = ja4R
        self.handshakeFrames = handshakeFrames
        self.supportedGroups = supportedGroups
        self.signatureAlgorithms = signatureAlgorithms
        self.certificates = certificates
    }
}

// MARK: - Application

public struct ApplicationDetails: Sendable, Codable, Equatable {
    public var protocols: [String]
    public var httpMethods: [String]
    public var httpHosts: [String]
    public var httpURIs: [String]
    public var httpUserAgents: [String]
    public var httpServers: [String]
    public var httpStatusCodes: [String]
    public var httpContentTypes: [String]
    public var dnsQueries: [String]
    public var dnsAnswers: [String]
    public var dnsRecordTypes: [String]
    public var quicVersions: [String]
    public var sshProtocols: [String]
    public var sshKeyExchange: [String]
    public var dhcpHostnames: [String]
    public var mdnsNames: [String]

    public init(
        protocols: [String] = [],
        httpMethods: [String] = [],
        httpHosts: [String] = [],
        httpURIs: [String] = [],
        httpUserAgents: [String] = [],
        httpServers: [String] = [],
        httpStatusCodes: [String] = [],
        httpContentTypes: [String] = [],
        dnsQueries: [String] = [],
        dnsAnswers: [String] = [],
        dnsRecordTypes: [String] = [],
        quicVersions: [String] = [],
        sshProtocols: [String] = [],
        sshKeyExchange: [String] = [],
        dhcpHostnames: [String] = [],
        mdnsNames: [String] = []
    ) {
        self.protocols = protocols
        self.httpMethods = httpMethods
        self.httpHosts = httpHosts
        self.httpURIs = httpURIs
        self.httpUserAgents = httpUserAgents
        self.httpServers = httpServers
        self.httpStatusCodes = httpStatusCodes
        self.httpContentTypes = httpContentTypes
        self.dnsQueries = dnsQueries
        self.dnsAnswers = dnsAnswers
        self.dnsRecordTypes = dnsRecordTypes
        self.quicVersions = quicVersions
        self.sshProtocols = sshProtocols
        self.sshKeyExchange = sshKeyExchange
        self.dhcpHostnames = dhcpHostnames
        self.mdnsNames = mdnsNames
    }
}

// MARK: - Socket and the whole report

public struct SocketDetails: Sendable, Codable, Equatable {
    public var pid: Int32
    public var command: String
    public var uid: Int?
    public var state: String?
    public var localAddress: String
    public var localPort: UInt16
    public var remoteAddress: String
    public var remotePort: UInt16
    public var transport: TransportProtocol
    public var fileDescriptor: Int?

    public init(
        pid: Int32,
        command: String,
        uid: Int? = nil,
        state: String? = nil,
        localAddress: String,
        localPort: UInt16,
        remoteAddress: String,
        remotePort: UInt16,
        transport: TransportProtocol,
        fileDescriptor: Int? = nil
    ) {
        self.pid = pid
        self.command = command
        self.uid = uid
        self.state = state
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.transport = transport
        self.fileDescriptor = fileDescriptor
    }
}

public struct ConnectionDetails: Sendable, Codable {
    public var flow: FlowKey
    public var scannedAt: Date
    public var captureFile: String?
    public var packetCount: Int
    public var firstSeen: Date?
    public var lastSeen: Date?
    public var network: NetworkDetails
    public var transport: TransportDetails
    public var tls: TLSDetails?
    public var application: ApplicationDetails
    public var socket: SocketDetails?
    public var process: ProcessIdentity?
    public var observations: [ConnectionObservation]
    public var warnings: [String]

    public init(
        flow: FlowKey,
        scannedAt: Date = Date(),
        captureFile: String? = nil,
        packetCount: Int = 0,
        firstSeen: Date? = nil,
        lastSeen: Date? = nil,
        network: NetworkDetails,
        transport: TransportDetails = TransportDetails(),
        tls: TLSDetails? = nil,
        application: ApplicationDetails = ApplicationDetails(),
        socket: SocketDetails? = nil,
        process: ProcessIdentity? = nil,
        observations: [ConnectionObservation] = [],
        warnings: [String] = []
    ) {
        self.flow = flow
        self.scannedAt = scannedAt
        self.captureFile = captureFile
        self.packetCount = packetCount
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.network = network
        self.transport = transport
        self.tls = tls
        self.application = application
        self.socket = socket
        self.process = process
        self.observations = observations
        self.warnings = warnings
    }

    public var duration: TimeInterval? {
        guard let firstSeen, let lastSeen else { return nil }
        return lastSeen.timeIntervalSince(firstSeen)
    }
}
