import Foundation
import SentinelDomain

/// Builds the passive half of a path map. Route lookup is local, and every other
/// value comes from the capture, the socket table or the deep scan. Trace and ping
/// are separate, explicit actions in the model.
public struct ConnectionPathBuilder: Sendable {
    private let routes: RouteResolving

    public init(routes: RouteResolving = SystemRouteResolver()) {
        self.routes = routes
    }

    public func build(
        assessment: FlowAssessment,
        details: ConnectionDetails?,
        route: RouteInfo? = nil
    ) async -> ConnectionPath {
        let resolved: RouteInfo?
        if let route {
            resolved = route
        } else {
            resolved = await routes.route(to: assessment.key.remoteEndpoint.host)
        }
        return Self.snapshot(assessment: assessment, details: details, route: resolved)
    }

    public static func snapshot(
        assessment: FlowAssessment,
        details: ConnectionDetails?,
        route: RouteInfo?
    ) -> ConnectionPath {
        let flow = assessment.key
        let remoteHost = flow.remoteEndpoint.host
        let classification = IPClassifier.classify(remoteHost)
        let process = details?.process ?? assessment.process
        let socket = details?.socket

        let local = PathLocal(
            address: nonEmpty(socket?.localAddress) ?? flow.localEndpoint.host,
            port: socket?.localPort ?? flow.localEndpoint.port,
            interfaceName: route?.interfaceName,
            processName: process?.name,
            pid: process?.pid,
            signing: process?.signing,
            socketState: details?.transport.tcp?.state ?? socket?.state,
            direction: assessment.direction
        )

        let remote = PathRemote(
            address: remoteHost,
            port: flow.remoteEndpoint.port,
            transport: flow.transport,
            scope: classification.scope,
            evidencedName: assessment.identity.evidencedName,
            reverseDNS: details?.network.reverseDNS,
            serviceGuess: assessment.identity.serviceGuess,
            asn: details?.network.asn,
            asnDescription: details?.network.asnDescription,
            organization: details?.network.organization,
            networkName: details?.network.networkName,
            country: details?.network.country,
            registry: details?.network.registry,
            ttl: details?.network.ttl,
            estimatedHops: details?.network.estimatedHops,
            observedProtocols: details?.application.protocols ?? []
        )

        var path = ConnectionPath(
            flow: flow,
            local: local,
            route: route,
            remote: remote,
            observations: details?.observations ?? []
        )

        addIdentityNames(assessment, to: &path)

        if let details {
            addName(details.network.reverseDNS, source: .dns, evidence: "reverse DNS (PTR)", to: &path)
            if let tls = details.tls {
                addName(tls.serverName, source: .packets, evidence: "TLS server name (SNI)", to: &path)
                for certificate in tls.certificates {
                    let leaf = certificate.index == 0
                    addName(
                        certificate.commonName,
                        source: .certificate,
                        evidence: leaf ? "leaf certificate common name" : "certificate \(certificate.index + 1) common name",
                        to: &path
                    )
                    for san in certificate.subjectAlternativeNames {
                        addName(
                            san,
                            source: .certificate,
                            evidence: leaf ? "leaf certificate SAN" : "certificate \(certificate.index + 1) SAN",
                            to: &path
                        )
                    }
                }
            }
            for host in details.application.httpHosts {
                addName(host, source: .packets, evidence: "HTTP Host header", to: &path)
            }
            for name in details.application.dnsQueries {
                addName(name, source: .packets, evidence: "DNS question in the capture", to: &path)
            }
            for name in details.application.dnsAnswers {
                addName(name, source: .packets, evidence: "DNS answer in the capture", to: &path)
            }
            for name in details.application.mdnsNames {
                addName(name, source: .packets, evidence: "mDNS name in the capture", to: &path)
            }
            for name in details.application.dhcpHostnames {
                addName(name, source: .packets, evidence: "DHCP hostname in the capture", to: &path)
            }
            path.warnings.append(contentsOf: details.warnings)
        } else {
            path.warnings.append("This path was built without a deep scan. Certificate, HTTP and DNS evidence may be missing.")
        }

        if route == nil {
            path.warnings.append("The system routing table returned no route for \(remoteHost). Local socket and capture evidence are still shown.")
        }
        if path.names.isEmpty {
            path.warnings.append("No domain name appeared in the captured evidence. Ping & resolve can ask the network, but it sends new traffic.")
        }
        path.warnings = dedupe(path.warnings)
        return path
    }

    private static func addIdentityNames(_ assessment: FlowAssessment, to path: inout ConnectionPath) {
        for fact in assessment.identity.facts where fact.confidence != .unknown {
            guard let mapped = mapping(for: fact.source) else { continue }
            addName(fact.value, source: mapped.source, evidence: mapped.evidence, to: &path)
        }
    }

    private static func mapping(for source: IdentitySource) -> (source: ObservationSource, evidence: String)? {
        switch source {
        case .ptr:
            return (.dns, "reverse DNS from the identity resolver")
        case .sni:
            return (.packets, "TLS server name (SNI)")
        case .httpHost:
            return (.packets, "HTTP Host header")
        case .dnsQuery:
            return (.packets, "DNS question in the capture")
        case .tlsSubject:
            return (.certificate, "certificate subject")
        case .manual:
            return (.userInput, "manual note")
        case .tlsIssuer, .serviceCatalog, .portTable, .userAgent, .localAddress:
            return nil
        }
    }

    private static func addName(
        _ value: String?,
        source: ObservationSource,
        evidence: String,
        to path: inout ConnectionPath
    ) {
        guard let value, !value.isEmpty else { return }
        path.addName(value, source: source, evidence: evidence)
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let value, !value.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return value
    }

    private static func dedupe(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}
