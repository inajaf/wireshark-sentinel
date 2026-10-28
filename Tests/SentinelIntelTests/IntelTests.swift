import XCTest
import SentinelDomain
@testable import SentinelIntel

final class IntelTests: XCTestCase {
    func testRDAPParsingPrefersRegistrantAndKeepsAbuseContact() throws {
        let json = """
        {
          "handle": "NET-104-16-0-0-1",
          "name": "CLOUDFLARENET",
          "country": "US",
          "entities": [
            {
              "handle": "CLOUDFLARENET",
              "roles": ["registrant"],
              "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Cloudflare, Inc."]
              ]]
            },
            {
              "handle": "ABUSE",
              "roles": ["abuse"],
              "vcardArray": ["vcard", [
                ["fn", {}, "text", "Abuse"],
                ["email", {}, "text", "abuse@cloudflare.com"]
              ]]
            }
          ]
        }
        """
        let record = try RDAPClient.record(
            from: Data(json.utf8),
            address: "104.16.0.1",
            registry: "ARIN"
        )
        XCTAssertEqual(record.handle, "NET-104-16-0-0-1")
        XCTAssertEqual(record.networkName, "CLOUDFLARENET")
        XCTAssertEqual(record.organization, "Cloudflare, Inc.")
        XCTAssertEqual(record.abuseContact, "abuse@cloudflare.com")
        XCTAssertEqual(record.country, "US")
        XCTAssertEqual(record.registry, "ARIN")
    }

    func testRegistryNameComesFromTheRedirectTarget() {
        XCTAssertEqual(RDAPClient.registryName(from: URL(string: "https://rdap.arin.net/registry/ip/1.1.1.1")), "ARIN")
        XCTAssertEqual(RDAPClient.registryName(from: URL(string: "https://rdap.db.ripe.net/ip/1.1.1.1")), "RIPE NCC")
        XCTAssertEqual(RDAPClient.registryName(from: URL(string: "https://rdap.apnic.net/ip/1.1.1.1")), "APNIC")
        XCTAssertEqual(RDAPClient.registryName(from: nil), "RDAP")
    }

    func testRDAPRefusesAPrivateAddressBeforeAnyRequest() async {
        do {
            _ = try await RDAPClient().lookup(address: "192.168.1.1")
            XCTFail("a private address must not be sent to a registry")
        } catch {
            XCTAssertTrue(String(describing: error).contains("not a public address"))
        }
    }

    func testASNQueryNamesUseTheReversedAddress() {
        XCTAssertEqual(
            TeamCymruASNClient.queryName(for: "104.16.0.1"),
            "1.0.16.104.origin.asn.cymru.com"
        )
        XCTAssertEqual(
            TeamCymruASNClient.queryName(for: "2606:4700:4700::1111"),
            "1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.origin6.asn.cymru.com"
        )
    }

    func testASNOriginAndDescriptionParsing() {
        let origin = TeamCymruASNClient.record(
            fromOriginTXT: "\"13335 | 104.16.0.0/13 | US | arin | 2014-03-28\"\n",
            address: "104.16.0.1"
        )
        XCTAssertEqual(origin?.n, 13335)
        XCTAssertEqual(origin?.prefix, "104.16.0.0/13")
        XCTAssertEqual(origin?.country, "US")
        XCTAssertEqual(origin?.registry, "arin")

        XCTAssertEqual(
            TeamCymruASNClient.description(fromASNTXT: "\"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US\""),
            "CLOUDFLARENET, US"
        )
    }

    func testHTTPProbeParserReadsStatusAndServer() {
        let response = Data("HTTP/1.1 204 No Content\r\nServer: cloudflare\r\nConnection: close\r\n\r\n".utf8)
        let parsed = ProbeSession.parseHTTP(response)
        XCTAssertEqual(parsed?.status, 204)
        XCTAssertEqual(parsed?.server, "cloudflare")
        XCTAssertNil(ProbeSession.parseHTTP(Data("not http".utf8)))
    }

    func testProbeRefusesLoopbackAndPrivateTargetsWithoutConsent() async {
        let loopback = await ActiveProber().probe(host: "127.0.0.1", port: 80)
        XCTAssertFalse(loopback.opened)
        XCTAssertTrue(loopback.error?.contains("will not be probed") == true)

        let privateTarget = await ActiveProber().probe(host: "192.168.1.10", port: 80)
        XCTAssertFalse(privateTarget.opened)
        XCTAssertTrue(privateTarget.error?.contains("private network") == true)
    }

    func testProbeRefusesPortZero() async {
        let result = await ActiveProber().probe(host: "1.1.1.1", port: 0)
        XCTAssertFalse(result.opened)
        XCTAssertTrue(result.error?.contains("not a usable TCP port") == true)
    }

    func testIntelClientDoesNotSendNonPublicAddresses() async {
        let report = await IntelClient().enrich(address: "10.0.0.1")
        XCTAssertNil(report.rdap)
        XCTAssertNil(report.asn)
        XCTAssertEqual(report.warnings.count, 1)
    }
}
