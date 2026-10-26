import Foundation
import SentinelDomain

/// What the network itself told us about a host, gathered from the packets.
public struct EndpointEvidence: Sendable, Equatable {
    public var sni: String?
    public var httpHost: String?
    public var dnsQueries: [String]
    public var ptrName: String?
    public var tlsSubject: String?
    public var tlsIssuer: String?
    public var serviceNames: [String]
    public var organization: String?

    public init(
        sni: String? = nil, httpHost: String? = nil, dnsQueries: [String] = [],
        ptrName: String? = nil, tlsSubject: String? = nil, tlsIssuer: String? = nil,
        serviceNames: [String] = [], organization: String? = nil
    ) {
        self.sni = sni
        self.httpHost = httpHost
        self.dnsQueries = dnsQueries
        self.ptrName = ptrName
        self.tlsSubject = tlsSubject
        self.tlsIssuer = tlsIssuer
        self.serviceNames = serviceNames
        self.organization = organization
    }
}

public protocol PTRResolving: Sendable {
    func name(for address: String) -> String?
}

/// Turns evidence into an identity a person can read.
public struct IdentityResolver: Sendable {
    private let ptr: PTRResolving
    private let catalog: ServiceCatalog

    public init(ptr: PTRResolving = SystemPTRResolver(), catalog: ServiceCatalog = .builtIn) {
        self.ptr = ptr
        self.catalog = catalog
    }

    /// Facts learned from one packet, keyed by the host they describe.
    ///
    /// A DNS question describes the host that was asked for. SNI, HTTP Host and the
    /// certificate describe the peer, so they land on the address that is not this
    /// Mac's half of the conversation.
    public func observe(_ packet: CapturedPacket) -> [String: [IdentityFact]] {
        var evidence = Self.evidence(from: packet)
        let peer = Self.peer(of: packet)
        evidence.ptrName = ptr.name(for: peer.host)
        evidence.serviceNames = catalog.service(forPort: peer.port, transport: packet.transport).map { [$0] } ?? []
        return Self.facts(from: evidence, peer: peer.host)
    }

    private static func facts(from evidence: EndpointEvidence, peer: String) -> [String: [IdentityFact]] {
        var peerFacts: [IdentityFact] = []
        if let sni = evidence.sni {
            peerFacts.append(IdentityFact(value: sni, source: .sni, confidence: .observed))
        }
        if let httpHost = evidence.httpHost {
            peerFacts.append(IdentityFact(value: httpHost, source: .httpHost, confidence: .observed))
        }
        if let subject = evidence.tlsSubject {
            peerFacts.append(IdentityFact(value: subject, source: .tlsSubject, confidence: .inferred))
        }
        if let issuer = evidence.tlsIssuer {
            peerFacts.append(IdentityFact(value: issuer, source: .tlsIssuer, confidence: .inferred))
        }
        if let ptrName = evidence.ptrName {
            peerFacts.append(IdentityFact(value: ptrName, source: .ptr, confidence: .inferred))
        }
        for service in evidence.serviceNames {
            peerFacts.append(IdentityFact(value: service, source: .serviceCatalog, confidence: .inferred))
        }

        var facts: [String: [IdentityFact]] = [:]
        if !peerFacts.isEmpty { facts[peer] = peerFacts }
        for query in evidence.dnsQueries where !query.isEmpty {
            facts[query, default: []].append(
                IdentityFact(value: query, source: .dnsQuery, confidence: .observed)
            )
        }
        return facts
    }

    public func identity(host: String, facts: [IdentityFact]) -> EndpointIdentity {
        EndpointIdentity(
            facts: facts,
            organization: facts.first { $0.source == .tlsIssuer }?.value,
            service: facts.first { $0.source == .serviceCatalog || $0.source == .portTable }?.value,
            isLocal: Self.isLoopback(host),
            isPrivate: AddressScope.isPrivate(host)
        )
    }

    /// One sentence for the report: what this host is, or why nobody named it.
    public func explanation(for identity: EndpointIdentity, host: String) -> String {
        guard let name = identity.evidencedName,
              let best = identity.facts.first(where: { $0.value == name }) else {
            return "\(host) is unidentified: no SNI, HTTP Host, DNS name, certificate, PTR record or known service was seen for it."
        }
        return "\(host) is \(name), from \(Self.label(best.source)) (\(best.confidence.rawValue))."
    }

    /// Pull the identity-relevant strings out of one packet. Pure and offline.
    public static func evidence(from packet: CapturedPacket) -> EndpointEvidence {
        EndpointEvidence(
            sni: packet.field("tls_handshake_extensions_server_name"),
            httpHost: packet.field("http_host"),
            dnsQueries: packet.fields["dns_qry_name"] ?? [],
            tlsSubject: certificateName(in: packet)
        )
    }

    /// tshark emits certificate RDNs as one flat list with no attribute names, mixing
    /// common names, organisations and localities from every certificate in the chain.
    /// Only a string shaped like a DNS name can name the peer. TLS 1.3 encrypts the
    /// certificate, so this is usually nil and is never the only name a host has.
    private static func certificateName(in packet: CapturedPacket) -> String? {
        let strings = (packet.fields["x509sat_uTF8String"] ?? [])
            + (packet.fields["x509sat_printableString"] ?? [])
        return strings.first { looksLikeHostname($0) }
    }

    private static func looksLikeHostname(_ value: String) -> Bool {
        let name = value.hasPrefix("*.") ? String(value.dropFirst(2)) : value
        guard name.contains("."), !name.hasPrefix("."), !name.hasSuffix(".") else { return false }
        return name.allSatisfy { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }
    }

    /// The side of the packet that offers a service, which is the resource under
    /// investigation. The client half of a flow uses an ephemeral port, so when both
    /// addresses look local the ephemeral port decides which half is the client.
    private static func peer(of packet: CapturedPacket) -> Endpoint {
        let source = Endpoint(host: packet.source, port: packet.sourcePort)
        let destination = Endpoint(host: packet.destination, port: packet.destinationPort)
        let sourceIsLocal = AddressScope.isPrivate(source.host)
        let destinationIsLocal = AddressScope.isPrivate(destination.host)

        if sourceIsLocal != destinationIsLocal { return sourceIsLocal ? destination : source }
        if isEphemeral(destination.port) && !isEphemeral(source.port) { return source }
        if isEphemeral(source.port) && !isEphemeral(destination.port) { return destination }
        return destination
    }

    private static func isEphemeral(_ port: UInt16) -> Bool { port >= 49152 }

    private static func isLoopback(_ host: String) -> Bool {
        host == "::1" || host.hasPrefix("127.")
    }

    private static func label(_ source: IdentitySource) -> String {
        switch source {
        case .ptr: return "a reverse DNS lookup"
        case .sni: return "the TLS server name"
        case .httpHost: return "the HTTP Host header"
        case .dnsQuery: return "a DNS question from this Mac"
        case .tlsSubject: return "the certificate subject"
        case .tlsIssuer: return "the certificate issuer"
        case .serviceCatalog, .portTable: return "the port table"
        case .userAgent: return "the user agent"
        case .localAddress: return "a local address"
        case .manual: return "a manual entry"
        }
    }
}
