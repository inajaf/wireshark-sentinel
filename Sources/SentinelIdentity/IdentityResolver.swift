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

public struct SystemPTRResolver: PTRResolving {
    public init() {}
    public func name(for address: String) -> String? { nil }
}

/// Port to service name, from the system table plus a built-in catalogue.
public struct ServiceCatalog: Sendable {
    public init(entries: [UInt16: String] = [:]) {}
    public static let builtIn = ServiceCatalog()
    public func service(forPort port: UInt16, transport: TransportProtocol) -> String? { nil }
}

/// Turns evidence into an identity a person can read.
public struct IdentityResolver: Sendable {
    public init(ptr: PTRResolving = SystemPTRResolver(), catalog: ServiceCatalog = .builtIn) {}

    /// Facts learned from one packet, keyed by the host they describe.
    public func observe(_ packet: CapturedPacket) -> [String: [IdentityFact]] { [:] }

    public func identity(host: String, facts: [IdentityFact]) -> EndpointIdentity {
        EndpointIdentity(facts: facts, isPrivate: AddressScope.isPrivate(host))
    }

    /// Pull the identity-relevant strings out of one packet. Pure and offline.
    public static func evidence(from packet: CapturedPacket) -> EndpointEvidence {
        EndpointEvidence()
    }
}
