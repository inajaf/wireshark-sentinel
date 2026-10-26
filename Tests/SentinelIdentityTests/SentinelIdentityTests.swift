import XCTest
import SentinelDomain
import SentinelIdentity

private struct StubPTR: PTRResolving {
    let names: [String: String]
    func name(for address: String) -> String? { names[address] }
}

final class SentinelIdentityTests: XCTestCase {
    private let offline = IdentityResolver(ptr: StubPTR(names: [:]))

    func testEvidenceReadsTheRecordedDissection() throws {
        let query = IdentityResolver.evidence(from: try FixturePackets.packet(1))
        XCTAssertEqual(query.dnsQueries, ["example.com"])
        XCTAssertNil(query.sni)
        XCTAssertNil(query.httpHost)
        XCTAssertNil(query.tlsSubject)

        XCTAssertEqual(IdentityResolver.evidence(from: try FixturePackets.packet(5)).sni, "example.com")
        XCTAssertEqual(IdentityResolver.evidence(from: try FixturePackets.packet(42)).sni, "quic.cftunnel.com")
    }

    func testFactsAreKeyedByTheHostTheyDescribe() throws {
        let hello = offline.observe(try FixturePackets.packet(5))
        XCTAssertEqual(hello["104.20.23.154"], [
            IdentityFact(value: "example.com", source: .sni, confidence: .observed),
            IdentityFact(value: "https", source: .serviceCatalog, confidence: .inferred),
        ])
        XCTAssertNil(hello["192.168.1.80"])

        let query = offline.observe(try FixturePackets.packet(1))
        XCTAssertEqual(query["example.com"]?.first, IdentityFact(value: "example.com", source: .dnsQuery, confidence: .observed))
        XCTAssertEqual(query["192.168.1.254"]?.first, IdentityFact(value: "domain", source: .serviceCatalog, confidence: .inferred))
    }

    func testObservedNameOutranksInferredPTR() throws {
        let resolver = IdentityResolver(ptr: StubPTR(names: ["104.20.23.154": "ptr.example.net"]))
        let facts = resolver.observe(try FixturePackets.packet(5))["104.20.23.154"] ?? []
        XCTAssertTrue(facts.contains(IdentityFact(value: "ptr.example.net", source: .ptr, confidence: .inferred)))

        let identity = resolver.identity(host: "104.20.23.154", facts: facts)
        XCTAssertEqual(identity.displayName, "example.com")
        XCTAssertEqual(identity.service, "https")
        XCTAssertTrue(identity.isIdentified)
        XCTAssertTrue(resolver.explanation(for: identity, host: "104.20.23.154").contains("the TLS server name"))
    }

    func testInjectedPTRNamesAnUnnamedPeerAndStaysInferred() throws {
        let resolver = IdentityResolver(ptr: StubPTR(names: ["198.41.192.37": "relay.example.net"]))
        let outbound = resolver.observe(try FixturePackets.packet(41))["198.41.192.37"]
        XCTAssertEqual(outbound, [IdentityFact(value: "relay.example.net", source: .ptr, confidence: .inferred)])
        XCTAssertEqual(resolver.observe(try FixturePackets.packet(43))["198.41.192.37"], outbound)
    }

    func testAddressWithNoEvidenceIsUnidentifiedWithAReason() throws {
        let facts = offline.observe(try FixturePackets.packet(41))["198.41.192.37"] ?? []
        XCTAssertTrue(facts.isEmpty)

        let identity = offline.identity(host: "198.41.192.37", facts: facts)
        XCTAssertFalse(identity.isIdentified)
        let reason = offline.explanation(for: identity, host: "198.41.192.37")
        XCTAssertTrue(reason.contains("198.41.192.37"))
        XCTAssertTrue(reason.contains("unidentified"))
    }

    func testHTTPHostNamesThePeerOffTheWire() {
        let packet = FixturePackets.crafted(from: "192.168.1.80", to: "203.0.113.7", destinationPort: 80, proto: "HTTP", fields: ["http_host": ["example.com"]])
        let facts = offline.observe(packet)["203.0.113.7"] ?? []
        XCTAssertTrue(facts.contains(IdentityFact(value: "example.com", source: .httpHost, confidence: .observed)))
        XCTAssertEqual(offline.identity(host: "203.0.113.7", facts: facts).displayName, "example.com")
    }

    func testCertificateLinePicksOneNameAndNeverTheWholeRDNList() throws {
        let certificate = FixturePackets.crafted(
            from: "104.20.23.154", to: "192.168.1.80", sourcePort: 443, destinationPort: 53791,
            info: "Certificate, Server Key Exchange", fields: try FixturePackets.ekFields(frame: 8)
        )
        XCTAssertEqual(IdentityResolver.evidence(from: certificate).tlsSubject, "example.com")
        let facts = offline.observe(certificate)["104.20.23.154"] ?? []
        XCTAssertTrue(facts.contains(IdentityFact(value: "example.com", source: .tlsSubject, confidence: .inferred)))
        for fact in facts {
            XCTAssertFalse(fact.value.contains(" "), fact.value)
            XCTAssertFalse(fact.value.contains(","), fact.value)
        }

        var claimed = try FixturePackets.ekFields(frame: 8)
        claimed["x509sat_uTF8String"] = ["Other Corporation", "cdn.other.example"]
        let hello = FixturePackets.crafted(from: "192.168.1.80", to: "104.20.23.154", sourcePort: 53791, destinationPort: 443, fields: try FixturePackets.ekFields(frame: 4))
        let competing = FixturePackets.crafted(from: "104.20.23.154", to: "192.168.1.80", sourcePort: 443, destinationPort: 53791, fields: claimed)
        let merged = (offline.observe(hello)["104.20.23.154"] ?? []) + (offline.observe(competing)["104.20.23.154"] ?? [])
        XCTAssertTrue(merged.contains(IdentityFact(value: "cdn.other.example", source: .tlsSubject, confidence: .inferred)))
        XCTAssertEqual(offline.identity(host: "104.20.23.154", facts: merged).displayName, "example.com")
    }

    func testTheCaptureNamesItsKnownHostsFromSNIAndDNS() throws {
        let hosts = [(5, "104.20.23.154", "example.com"), (21, "173.222.200.245", "www.apple.com"), (25, "140.82.121.3", "github.com")]
        for (frame, host, name) in hosts {
            let facts = offline.observe(try FixturePackets.packet(frame))[host] ?? []
            let identity = offline.identity(host: host, facts: facts)
            XCTAssertEqual(identity.displayName, name, "frame \(frame)")
            XCTAssertEqual(identity.service, "https", "frame \(frame)")
        }

        let asked = offline.observe(try FixturePackets.packet(17))["www.apple.com"] ?? []
        XCTAssertEqual(asked.first?.source, .dnsQuery)
        XCTAssertEqual(offline.identity(host: "www.apple.com", facts: asked).displayName, "www.apple.com")
    }

    func testServiceCatalogNamesThePortsThisMacUses() {
        let catalog = ServiceCatalog.builtIn
        let ports: [(UInt16, TransportProtocol, String)] = [
            (443, .tcp, "https"), (80, .tcp, "http"), (53, .udp, "domain"), (123, .udp, "ntp"),
            (5223, .tcp, "apns"), (5353, .udp, "mdns"), (67, .udp, "dhcp"), (68, .udp, "dhcp"),
            (22, .tcp, "ssh"), (25, .tcp, "smtp"), (587, .tcp, "submission"), (993, .tcp, "imaps"),
            (6679, .tcp, "google-quic"), (5228, .tcp, "google-play"),
        ]
        for (port, transport, name) in ports {
            XCTAssertEqual(catalog.service(forPort: port, transport: transport), name, "port \(port)")
        }
        XCTAssertNil(catalog.service(forPort: 5353, transport: .tcp))
        XCTAssertNil(catalog.service(forPort: 7844, transport: .udp))

        let mine = ServiceCatalog(entries: [443: "https-alt", 9999: "mine"])
        XCTAssertEqual(mine.service(forPort: 443, transport: .tcp), "https-alt")
        XCTAssertEqual(mine.service(forPort: 9999, transport: .tcp), "mine")
        XCTAssertEqual(mine.service(forPort: 80, transport: .tcp), "http")
    }
}
