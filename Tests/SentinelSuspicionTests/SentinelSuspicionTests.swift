import XCTest
import SentinelDomain
import SentinelSuspicion

final class SentinelSuspicionTests: XCTestCase {
    private let epoch = Date(timeIntervalSince1970: 1_700_000_000)
    private let engine = SuspicionEngine()

    private func times(_ intervals: [Double]) -> [Date] {
        intervals.reduce([epoch]) { $0 + [$0[$0.count - 1].addingTimeInterval($1)] }
    }

    private func every(_ seconds: Double, count: Int) -> [Date] {
        times(Array(repeating: seconds, count: count))
    }

    private func identified(_ name: String = "example.com") -> EndpointIdentity {
        EndpointIdentity(facts: [IdentityFact(value: name, source: .sni, confidence: .observed)], organization: "Example Inc")
    }

    private func signedProcess(_ signing: SigningStatus, name: String = "Safari") -> ProcessIdentity {
        ProcessIdentity(pid: 501, name: name, bundleID: "com.apple.\(name)", signing: signing)
    }

    private func flow(
        remote: String = "203.0.113.9", port: UInt16 = 443, direction: FlowDirection = .outbound,
        packetTimes: [Date] = [], byteCount: Int = 0, identity: EndpointIdentity = EndpointIdentity(),
        process: ProcessIdentity? = nil, protocols: Set<String> = ["TCP"], plaintext: Bool = false,
        inboundInitiated: Bool = false, localListener: Bool = false
    ) -> FlowObservation {
        FlowObservation(
            key: FlowKey(
                transport: .tcp,
                local: Endpoint(host: "192.168.1.20", port: 49152),
                remote: Endpoint(host: remote, port: port)
            ),
            direction: direction, packetTimes: packetTimes, byteCount: byteCount, identity: identity,
            process: process, protocols: protocols, sawPlaintext: plaintext,
            isInboundInitiated: inboundInitiated, hasLocalListener: localListener
        )
    }

    private func kinds(_ assessment: FlowAssessment) -> Set<SignalKind> { Set(assessment.signals.map(\.kind)) }

    func testUnidentifiedDestinationIsFlagged() {
        let assessment = engine.assess(flow())
        XCTAssertEqual(kinds(assessment), [.unknownDestination])
        XCTAssertEqual(assessment.score, 30)
        XCTAssertEqual(assessment.verdict, .unknown)
    }

    func testOrdinaryBrowsingStaysKnown() {
        let assessment = engine.assess(flow(
            remote: "93.184.216.34", identity: identified(), process: signedProcess(.apple), protocols: ["TCP", "TLS"]
        ))
        XCTAssertTrue(assessment.signals.isEmpty)
        XCTAssertEqual(assessment.score, 0)
        XCTAssertEqual(assessment.verdict, .known)
        XCTAssertEqual(assessment.rationale, "")
    }

    func testPrivateAndMulticastDestinationsAreNeverSuspiciousOnIdentityAlone() {
        let heavy = SuspicionEngine(policy: SuspicionPolicy(weights: [.unknownDestination: 100]))
        XCTAssertEqual(heavy.assess(flow(remote: "203.0.113.9")).verdict, .suspicious)

        let privateAddress = heavy.assess(flow(remote: "192.168.1.50"))
        XCTAssertEqual(privateAddress.score, 100)
        XCTAssertEqual(privateAddress.verdict, .unknown)

        let multicast = heavy.assess(flow(remote: "239.255.255.250", port: 5353, direction: .multicast))
        XCTAssertEqual(multicast.verdict, .unknown)
    }

    func testBeaconingFlowIsSuspicious() {
        let assessment = engine.assess(flow(packetTimes: times([58, 61, 59, 62, 60, 59, 61, 60])))
        XCTAssertTrue(kinds(assessment).contains(.beaconing))
        XCTAssertEqual(assessment.score, 65)
        XCTAssertEqual(assessment.verdict, .suspicious)
    }

    func testIrregularIntervalsDoNotFireBeaconing() {
        let erratic = engine.assess(flow(packetTimes: times([5, 55, 8, 62, 3, 70, 12, 48])))
        XCTAssertFalse(kinds(erratic).contains(.beaconing))

        var seed: UInt64 = 0x9E37_79B9_7F4A_7C15
        let uniform = (0..<40).map { _ -> Double in
            seed = seed &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return Double((seed >> 33) % 120 + 1)
        }
        XCTAssertFalse(kinds(engine.assess(flow(packetTimes: times(uniform)))).contains(.beaconing))
    }

    func testInboundIsUnsolicitedOnlyWhenNothingListens() {
        let unsolicited = engine.assess(flow(
            remote: "203.0.113.7", port: 41337, direction: .inbound,
            identity: identified("telemetry.example"), protocols: ["TLS"], inboundInitiated: true
        ))
        XCTAssertEqual(kinds(unsolicited), [.inboundUnsolicited, .unusualPort])
        XCTAssertEqual(unsolicited.score, 65)
        XCTAssertEqual(unsolicited.verdict, .suspicious)

        let listening = engine.assess(flow(
            remote: "203.0.113.7", port: 22, direction: .inbound,
            identity: identified("ssh.example"), protocols: ["TLS"], inboundInitiated: true, localListener: true
        ))
        XCTAssertTrue(listening.signals.isEmpty)
        XCTAssertEqual(listening.verdict, .known)

        XCTAssertFalse(kinds(engine.assess(flow(identity: identified(), protocols: ["TLS"]))).contains(.inboundUnsolicited))
    }

    func testUnsignedProcessIsFlagged() {
        let assessment = engine.assess(flow(
            identity: identified(), process: signedProcess(.unsigned, name: "helper"), protocols: ["TLS"]
        ))
        XCTAssertEqual(kinds(assessment), [.unsignedProcess])
        XCTAssertEqual(assessment.score, 30)
        XCTAssertEqual(assessment.verdict, .unknown)
    }

    func testKnownDevelopersAreNotFlagged() {
        for signing in [SigningStatus.apple, .developerID(team: "ABCDE12345"), .unknown] {
            let assessment = engine.assess(flow(identity: identified(), process: signedProcess(signing), protocols: ["TLS"]))
            XCTAssertFalse(kinds(assessment).contains(.unsignedProcess), "\(signing)")
        }
    }

    func testUnusualPortIsFlaggedButWellKnownPortsAreNot() {
        let unusual = engine.assess(flow(
            remote: "198.51.100.7", port: 8443, identity: identified(), process: signedProcess(.apple), protocols: ["TLS"]
        ))
        XCTAssertTrue(kinds(unusual).contains(.unusualPort))

        for port: UInt16 in [443, 80, 53, 123, 22, 993, 587, 5223, 5228, 5353] {
            let known = engine.assess(flow(
                remote: "198.51.100.7", port: port, identity: identified(), process: signedProcess(.apple), protocols: ["TLS"]
            ))
            XCTAssertFalse(kinds(known).contains(.unusualPort), "port \(port)")
        }
    }

    func testPlaintextProtocolIsFlagged() {
        let assessment = engine.assess(flow(
            remote: "198.51.100.7", port: 8080, identity: identified(),
            process: signedProcess(.apple), protocols: ["TCP", "HTTP"], plaintext: true
        ))
        XCTAssertTrue(kinds(assessment).contains(.plaintextProtocol))
        XCTAssertFalse(kinds(assessment).contains(.rawIPTraffic))
    }

    func testRawIpTrafficNeedsNoApplicationProtocol() {
        let raw = engine.assess(flow(
            remote: "198.51.100.7", port: 4444, identity: identified(), process: signedProcess(.apple), protocols: ["UDP"]
        ))
        XCTAssertTrue(kinds(raw).contains(.rawIPTraffic))

        let application = engine.assess(flow(
            remote: "198.51.100.7", port: 4444, identity: identified(), process: signedProcess(.apple), protocols: ["UDP", "QUIC"]
        ))
        XCTAssertFalse(kinds(application).contains(.rawIPTraffic))
    }

    func testDnsBurstFiresOnlyInsideAMinute() {
        let burst = engine.assess(flow(
            remote: "8.8.8.8", port: 53, packetTimes: every(0.2, count: 150),
            byteCount: 9000, identity: identified("dns.google"), protocols: ["DNS"]
        ))
        XCTAssertTrue(kinds(burst).contains(.dnsHighVolume))

        let spread = engine.assess(flow(
            remote: "8.8.8.8", port: 53, packetTimes: every(2, count: 150),
            byteCount: 9000, identity: identified("dns.google"), protocols: ["DNS"]
        ))
        XCTAssertFalse(kinds(spread).contains(.dnsHighVolume))
    }

    func testLongLivedIdleNeedsALongQuietConnection() {
        let idle = engine.assess(flow(
            remote: "198.51.100.7", packetTimes: every(60, count: 20), byteCount: 400,
            identity: identified(), protocols: ["TLS"]
        ))
        XCTAssertTrue(kinds(idle).contains(.longLivedIdle))

        let busy = engine.assess(flow(
            remote: "198.51.100.7", packetTimes: every(60, count: 20), byteCount: 2_000_000,
            identity: identified(), protocols: ["TLS"]
        ))
        XCTAssertFalse(kinds(busy).contains(.longLivedIdle))
    }

    func testScoresAtTheThresholdsDecideTheVerdict() {
        let unusual = flow(
            remote: "198.51.100.7", port: 8443, identity: identified(), process: signedProcess(.apple), protocols: ["TLS"]
        )
        XCTAssertEqual(SuspicionEngine(policy: SuspicionPolicy(weights: [.unusualPort: 60])).assess(unusual).verdict, .suspicious)
        XCTAssertEqual(SuspicionEngine(policy: SuspicionPolicy(weights: [.unusualPort: 25])).assess(unusual).verdict, .unknown)
        XCTAssertEqual(SuspicionEngine(policy: SuspicionPolicy(weights: [.unusualPort: 24])).assess(unusual).verdict, .known)
    }

    func testRationaleNamesTheStrongestSignalsInPlainWords() {
        let assessment = engine.assess(flow(
            remote: "198.51.100.7", port: 8443, packetTimes: times([58, 61, 59, 62, 60, 59, 61, 60]),
            identity: identified(), process: signedProcess(.apple), protocols: ["TLS"]
        ))
        XCTAssertEqual(kinds(assessment), [.beaconing, .unusualPort])
        XCTAssertEqual(
            assessment.rationale,
            "Suspicious because it repeats on a regular timer instead of when a person acts, "
                + "and it uses remote port 8443, which is not a usual service port."
        )
    }

    func testKnownVerdictWithAFiredSignalStillExplainsItself() {
        let quiet = SuspicionEngine(policy: SuspicionPolicy(weights: [.unusualPort: 0]))
        let assessment = quiet.assess(flow(
            remote: "198.51.100.7", port: 8443, identity: identified(), process: signedProcess(.apple), protocols: ["TLS"]
        ))
        XCTAssertEqual(assessment.signals.map(\.kind), [.unusualPort])
        XCTAssertEqual(assessment.verdict, .known)
        XCTAssertEqual(
            assessment.rationale,
            "Nothing serious, but it uses remote port 8443, which is not a usual service port."
        )
    }

    func testAssessmentWithoutPacketsUsesTheIdentityWindowNotTheClock() {
        let identity = EndpointIdentity(firstSeen: epoch, lastSeen: epoch.addingTimeInterval(30))
        let assessment = engine.assess(flow(identity: identity))
        XCTAssertEqual(assessment.firstSeen, epoch)
        XCTAssertEqual(assessment.lastSeen, epoch.addingTimeInterval(30))
        XCTAssertEqual(assessment.packetCount, 0)
    }
}
