import XCTest
import SentinelDomain
@testable import SentinelEngine

final class DeepScanTests: XCTestCase {
    private var fixtures: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
    }

    func testTLS12FixtureYieldsNamesCipherAndCertificate() async throws {
        guard let install = WiresharkInstall.locate() else {
            throw XCTSkip("Wireshark is not installed")
        }
        let capture = fixtures.appendingPathComponent("sample-tls12.pcapng")
        XCTAssertTrue(FileManager.default.fileExists(atPath: capture.path))

        let flow = FlowKey(
            transport: .tcp,
            local: Endpoint(host: "192.168.1.80", port: 49711),
            remote: Endpoint(host: "104.20.23.154", port: 443)
        )
        let request = DeepScanRequest(
            flow: flow,
            captureFile: capture,
            options: .preset(.deep)
        )
        let details = try await TSharkDeepScanner(install: install).scan(request)

        XCTAssertGreaterThan(details.packetCount, 0)
        XCTAssertEqual(details.network.family, "IPv4")
        XCTAssertEqual(details.network.scope, "public internet")
        XCTAssertEqual(details.tls?.serverName, "example.com")
        XCTAssertEqual(details.tls?.version, "TLS 1.2")
        XCTAssertNotNil(details.tls?.ja3)
        XCTAssertNotNil(details.tls?.ja4)
        XCTAssertFalse(details.tls?.certificates.isEmpty ?? true)
        XCTAssertTrue(details.tls?.certificates.first?.subjectAlternativeNames.contains("example.com") == true)
        XCTAssertTrue(details.application.protocols.contains("tls"))
        XCTAssertNotNil(details.transport.tcp)
    }

    func testDisplayFilterUsesTheRemoteAddressAndServicePort() {
        let flow = FlowKey(
            transport: .tcp,
            local: Endpoint(host: "10.0.0.5", port: 50000),
            remote: Endpoint(host: "203.0.113.9", port: 8443)
        )
        XCTAssertEqual(
            TSharkDeepScanner.displayFilter(for: flow),
            "ip.addr==203.0.113.9 && tcp.port==8443"
        )
    }

    func testIPv6DisplayFilterUsesTheIPv6Field() {
        let flow = FlowKey(
            transport: .udp,
            local: Endpoint(host: "fe80::1", port: 50000),
            remote: Endpoint(host: "2606:4700:4700::1111", port: 53)
        )
        XCTAssertEqual(
            TSharkDeepScanner.displayFilter(for: flow),
            "ipv6.addr==2606:4700:4700::1111 && udp.port==53"
        )
    }

    func testClassifierSeparatesPublicAndSpecialRanges() {
        XCTAssertEqual(IPClassifier.classify("203.0.113.9").scope, .documentation)
        XCTAssertEqual(IPClassifier.classify("192.168.1.10").scope, .privateNetwork)
        XCTAssertEqual(IPClassifier.classify("100.64.0.1").scope, .carrierGradeNAT)
        XCTAssertEqual(IPClassifier.classify("127.0.0.1").scope, .loopback)
        XCTAssertEqual(IPClassifier.classify("169.254.1.1").scope, .linkLocal)
        XCTAssertEqual(IPClassifier.classify("224.0.0.251").scope, .multicast)
        XCTAssertEqual(IPClassifier.classify("2606:4700:4700::1111").scope, .publicInternet)
        XCTAssertEqual(IPClassifier.classify("fe80::1%en0").scope, .linkLocal)
        XCTAssertEqual(IPClassifier.classify("not-an-address").scope, .unknown)
    }
}
