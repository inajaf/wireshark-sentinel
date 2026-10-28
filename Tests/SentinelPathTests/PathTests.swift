import XCTest
import SentinelDomain
import SentinelIdentity
import SentinelPath

private struct StubPTR: PTRResolving {
    let names: [String: String]
    func name(for address: String) -> String? { names[address] }
}

private actor CallLog {
    private(set) var calls: [(executable: String, arguments: [String])] = []

    func record(executable: String, arguments: [String]) {
        calls.append((executable, arguments))
    }
}

private struct ScriptedRunner: PathCommandRunning {
    var stdout: String = ""
    var stderr: String = ""
    var exitCode: Int32 = 0
    var timedOut: Bool = false
    var log: CallLog?

    func run(executable: String, arguments: [String], timeout: TimeInterval) async -> PathCommandResult {
        await log?.record(executable: executable, arguments: arguments)
        return PathCommandResult(
            executable: executable,
            arguments: arguments,
            exitCode: exitCode,
            stdout: stdout,
            stderr: stderr,
            timedOut: timedOut
        )
    }
}

final class SentinelPathTests: XCTestCase {
    // MARK: - Address handling

    func testBareAddressHandlesBracketsPortsZonesAndCompression() {
        XCTAssertEqual(PathAddress.bare("[2606:4700:4700::1111]:443"), "2606:4700:4700::1111")
        XCTAssertEqual(PathAddress.bare("1.1.1.1:443"), "1.1.1.1")
        XCTAssertEqual(PathAddress.bare("fe80::1%en0"), "fe80::1")
        XCTAssertEqual(PathAddress.bare("2001:db8::1"), "2001:db8::1")
        XCTAssertTrue(PathAddress.same("::1", "0:0:0:0:0:0:0:1"))
        XCTAssertTrue(PathAddress.same("1.1.1.1", "1.1.1.1"))
        XCTAssertFalse(PathAddress.same("1.1.1.1", "1.1.1.2"))
    }

    func testCleanNameRejectsAddressLiteralsAndRemovesRootDotAndPort() {
        XCTAssertEqual(PathAddress.cleanName("Example.COM."), "Example.COM")
        XCTAssertEqual(PathAddress.cleanName("example.com:443"), "example.com")
        XCTAssertEqual(PathAddress.cleanName("93.184.216.34"), "")
        XCTAssertEqual(PathAddress.cleanName("[2606:4700:4700::1111]:443"), "")
        XCTAssertEqual(PathAddress.cleanName("..."), "")
    }

    // MARK: - Safety

    func testProbeSafetyRefusesTargetsThatAreNotOneRemoteService() {
        XCTAssertNotNil(PathProbeSafety.problem(for: "127.0.0.1"))
        XCTAssertNotNil(PathProbeSafety.problem(for: "::1"))
        XCTAssertNotNil(PathProbeSafety.problem(for: "224.0.0.1"))
        XCTAssertNotNil(PathProbeSafety.problem(for: "255.255.255.255"))
        XCTAssertNotNil(PathProbeSafety.problem(for: "192.168.1.255", broadcastAddresses: ["192.168.1.255"]))
        XCTAssertNotNil(PathProbeSafety.problem(for: "0.0.0.0"))
        XCTAssertNotNil(PathProbeSafety.problem(for: "169.254.10.1"))
        XCTAssertNotNil(PathProbeSafety.problem(for: "not-an-address.example"))
        XCTAssertNotNil(PathProbeSafety.problem(for: "1.1.1.1", localAddresses: ["1.1.1.1"]))

        XCTAssertNil(PathProbeSafety.problem(for: "1.1.1.1"))
        XCTAssertNil(PathProbeSafety.problem(for: "192.168.1.10"))
        XCTAssertNil(PathProbeSafety.problem(for: "2606:4700:4700::1111"))
    }

    func testRefusedPingNeverRunsACommand() async {
        let log = CallLog()
        let client = PingClient(
            runner: ScriptedRunner(stdout: "should not run", log: log),
            ptr: StubPTR(names: ["127.0.0.1": "localhost"])
        )
        let result = await client.ping("127.0.0.1")

        XCTAssertFalse(result.responded)
        XCTAssertNil(result.hostname)
        XCTAssertTrue(result.error?.contains("Loopback") == true)
        let calls = await log.calls
        XCTAssertTrue(calls.isEmpty)
    }

    // MARK: - Command runner

    func testSystemRunnerReturnsOutputWithoutANetworkProbe() async {
        let result = await SystemPathCommandRunner().run(
            executable: "/bin/echo",
            arguments: ["sentinel"],
            timeout: 2
        )
        XCTAssertTrue(result.succeeded)
        XCTAssertEqual(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines), "sentinel")
        XCTAssertEqual(result.exitCode, 0)
    }

    // MARK: - Route

    func testRouteParserReadsGatewayAndDirectRoute() throws {
        let gatewayOutput = """
           route to: 1.1.1.1
        destination: default
               mask: default
            gateway: 192.168.1.254
          interface: en0
              flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
         recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
               0         0         0         0         0         0      1500         0
        """
        let gateway = try XCTUnwrap(RouteOutputParser.parse(gatewayOutput))
        XCTAssertEqual(gateway.destination, "default")
        XCTAssertEqual(gateway.gateway, "192.168.1.254")
        XCTAssertEqual(gateway.interfaceName, "en0")
        XCTAssertFalse(gateway.isDirect)

        let directOutput = """
           route to: 192.168.1.1
        destination: 192.168.1.0
               mask: 255.255.255.0
          interface: en0
              flags: <UP,DONE,CLONING,STATIC>
        """
        let direct = try XCTUnwrap(RouteOutputParser.parse(directOutput))
        XCTAssertEqual(direct.destination, "192.168.1.0")
        XCTAssertNil(direct.gateway)
        XCTAssertEqual(direct.interfaceName, "en0")
        XCTAssertTrue(direct.isDirect)
        XCTAssertNil(RouteOutputParser.parse("interface: en0\n"))
    }

    func testRouteResolverRunsTheSystemRouteLookup() async {
        let log = CallLog()
        let output = """
        destination: default
            gateway: 192.168.1.254
          interface: en0
        """
        let resolver = SystemRouteResolver(
            runner: ScriptedRunner(stdout: output, log: log)
        )
        let route = await resolver.route(to: "1.1.1.1")

        XCTAssertEqual(route?.gateway, "192.168.1.254")
        let calls = await log.calls
        XCTAssertEqual(calls.first?.executable, "/sbin/route")
        XCTAssertEqual(calls.first?.arguments, ["-n", "get", "1.1.1.1"])
    }

    // MARK: - Traceroute

    func testTracerouteParserKeepsTimeoutsAndFindsTheDestination() {
        let output = """
        traceroute to 1.1.1.1 (1.1.1.1), 16 hops max, 52 byte packets
         1  192.168.1.254  2.199 ms
         2  *
         3  10.0.0.1  5.500 ms
         4  1.1.1.1  12.400 ms
        """
        let trace = TracerouteOutputParser.parse(output, target: "1.1.1.1")

        XCTAssertEqual(trace.hops.count, 4)
        XCTAssertEqual(trace.hops[0].index, 1)
        XCTAssertEqual(trace.hops[0].address, "192.168.1.254")
        XCTAssertEqual(trace.hops[0].rttMilliseconds ?? 0, 2.199, accuracy: 0.0001)
        XCTAssertEqual(trace.hops[0].scope, .privateNetwork)
        XCTAssertNil(trace.hops[1].address)
        XCTAssertTrue(trace.hops[3].isDestination)
        XCTAssertTrue(trace.reachedDestination)
        XCTAssertTrue(trace.warnings.isEmpty)
    }

    func testTracerouteParserReportsAPartialPathAndUnreachableHop() {
        let output = """
        traceroute to 203.0.113.9 (203.0.113.9), 16 hops max, 52 byte packets
         1  192.168.1.254  1.000 ms
         2  *
         3  10.1.1.1  3.000 ms !H
        """
        let trace = TracerouteOutputParser.parse(output, target: "203.0.113.9")

        XCTAssertFalse(trace.reachedDestination)
        XCTAssertTrue(trace.isPartial)
        XCTAssertEqual(trace.hops.count, 3)
        XCTAssertEqual(trace.hops[2].note, "host unreachable")
        XCTAssertTrue(trace.warnings.contains { $0.contains("partial") })
    }

    func testTracerouteClientUsesTheIPv6BinaryForAnIPv6Target() async {
        let log = CallLog()
        let output = """
        traceroute6 to 2606:4700:4700::1111 (2606:4700:4700::1111), 16 hops max, 28 byte packets
         1  2606:4700:4700::1111  0.100 ms
        """
        let client = TracerouteClient(
            runner: ScriptedRunner(stdout: output, log: log)
        )
        let trace = await client.trace(to: "2606:4700:4700::1111")

        XCTAssertTrue(trace.reachedDestination)
        let calls = await log.calls
        XCTAssertEqual(calls.first?.executable, "/usr/sbin/traceroute6")
        XCTAssertTrue(calls.first?.arguments.contains("2606:4700:4700::1111") == true)
    }

    // MARK: - Ping

    func testPingParserReadsNameStatsAndAverageRoundTrip() {
        let output = """
        PING example.com (93.184.216.34): 56 data bytes
        64 bytes from 93.184.216.34: icmp_seq=0 ttl=54 time=12.300 ms

        --- example.com ping statistics ---
        1 packets transmitted, 1 packets received, 0.0% packet loss
        round-trip min/avg/max/stddev = 12.300/12.300/12.300/0.000 ms
        """
        let ping = PingOutputParser.parse(output, target: "93.184.216.34")

        XCTAssertEqual(ping.hostname, "example.com")
        XCTAssertTrue(ping.responded)
        XCTAssertEqual(ping.rttMilliseconds ?? 0, 12.3, accuracy: 0.0001)
        XCTAssertEqual(ping.packetLossPercent ?? -1, 0, accuracy: 0.0001)
    }

    func testPingParserDoesNotTurnAnAddressIntoAName() {
        let output = """
        PING 1.1.1.1 (1.1.1.1): 56 data bytes

        --- 1.1.1.1 ping statistics ---
        1 packets transmitted, 0 packets received, 100.0% packet loss
        """
        let ping = PingOutputParser.parse(output, target: "1.1.1.1")

        XCTAssertNil(ping.hostname)
        XCTAssertFalse(ping.responded)
        XCTAssertEqual(ping.packetLossPercent, 100)
        XCTAssertNotNil(ping.error)
    }

    func testPingClientFallsBackToReverseDNSWhenICMPFails() async {
        let client = PingClient(
            runner: ScriptedRunner(stdout: "", stderr: "ping: sendto: No route to host", exitCode: 2),
            ptr: StubPTR(names: ["203.0.113.9": "edge.example.net"])
        )
        let ping = await client.ping("203.0.113.9")

        XCTAssertFalse(ping.responded)
        XCTAssertEqual(ping.hostname, "edge.example.net")
        XCTAssertEqual(ping.method, "reverse DNS only")
        XCTAssertTrue(ping.error?.contains("reverse DNS") == true)
    }

    // MARK: - Path builder

    func testBuilderMergesTheSameNameFromSNIAndCertificate() throws {
        let assessment = makeAssessment()
        let route = RouteInfo(destination: "default", gateway: "192.168.1.254", interfaceName: "en0")
        let details = makeDetails(for: assessment, route: route)

        let path = ConnectionPathBuilder.snapshot(
            assessment: assessment,
            details: details,
            route: route
        )

        XCTAssertEqual(path.local.processName, "Safari")
        XCTAssertEqual(path.local.interfaceName, "en0")
        XCTAssertEqual(path.remote.scope, .publicInternet)
        XCTAssertEqual(path.remote.asn, "AS13335")
        XCTAssertEqual(path.remote.evidencedName, "example.com")
        XCTAssertEqual(path.bestName, "example.com")
        XCTAssertEqual(path.route?.gateway, "192.168.1.254")

        let example = try XCTUnwrap(path.names.first { $0.value == "example.com" })
        XCTAssertTrue(example.sources.contains(.packets))
        XCTAssertTrue(example.sources.contains(.certificate))
        XCTAssertTrue(example.evidence.contains { $0.contains("SNI") })
        XCTAssertTrue(example.evidence.contains { $0.contains("SAN") })
        XCTAssertTrue(path.names.contains { $0.value == "www.example.com" })
        XCTAssertTrue(path.names.contains { $0.value == "ptr.example.net" })
    }

    func testBuilderWarnsWhenThereIsNoRouteAndNoName() {
        let assessment = makeAssessment(facts: [], includeProcess: false)
        let path = ConnectionPathBuilder.snapshot(
            assessment: assessment,
            details: nil,
            route: nil
        )

        XCTAssertTrue(path.names.isEmpty)
        XCTAssertNil(path.route)
        XCTAssertTrue(path.warnings.contains { $0.contains("routing table") })
        XCTAssertTrue(path.warnings.contains { $0.contains("No domain name") })
        XCTAssertTrue(path.warnings.contains { $0.contains("without a deep scan") })
        XCTAssertEqual(path.local.address, "192.168.1.10")
        XCTAssertEqual(path.local.port, 51000)
    }

    func testTransitHopsLeaveTheDestinationForTheServiceNode() {
        let assessment = makeAssessment()
        var path = ConnectionPathBuilder.snapshot(
            assessment: assessment,
            details: nil,
            route: RouteInfo(destination: "default", gateway: "192.168.1.254", interfaceName: "en0")
        )
        path.trace = PathTrace(
            hops: [
                PathHop(index: 1, address: "192.168.1.254", scope: .privateNetwork),
                PathHop(index: 2, address: "1.1.1.1", scope: .publicInternet, isDestination: true),
            ],
            reachedDestination: true
        )

        XCTAssertEqual(path.transitHops.map(\.index), [1])
        XCTAssertEqual(path.trace?.hops.last?.isDestination, true)
    }

    // MARK: - Fixtures

    private func makeAssessment(
        facts: [IdentityFact]? = nil,
        includeProcess: Bool = true
    ) -> FlowAssessment {
        let identity = EndpointIdentity(
            facts: facts ?? [
                IdentityFact(value: "example.com", source: .sni, confidence: .observed),
                IdentityFact(value: "ptr.example.net", source: .ptr, confidence: .inferred),
            ],
            service: "https",
            ports: [443]
        )
        let process = includeProcess
            ? ProcessIdentity(
                pid: 42,
                name: "Safari",
                path: "/Applications/Safari.app",
                bundleID: "com.apple.Safari",
                signing: .apple
            )
            : nil
        return FlowAssessment(
            key: FlowKey(
                transport: .tcp,
                local: Endpoint(host: "192.168.1.10", port: 51000),
                remote: Endpoint(host: "93.184.216.34", port: 443)
            ),
            direction: .outbound,
            identity: identity,
            process: process,
            signals: [],
            score: 0,
            verdict: .known,
            rationale: "",
            firstSeen: Date(timeIntervalSince1970: 1_700_000_000),
            lastSeen: Date(timeIntervalSince1970: 1_700_000_012),
            packetCount: 24,
            byteCount: 8_192
        )
    }

    private func makeDetails(for assessment: FlowAssessment, route: RouteInfo) -> ConnectionDetails {
        let certificate = CertificateSummary(
            index: 0,
            subject: "CN=example.com",
            issuer: "Example CA",
            commonName: "example.com",
            organization: "Example Org",
            subjectAlternativeNames: ["example.com", "www.example.com"]
        )
        return ConnectionDetails(
            flow: assessment.key,
            packetCount: 24,
            firstSeen: assessment.firstSeen,
            lastSeen: assessment.lastSeen,
            network: NetworkDetails(
                address: assessment.key.remoteEndpoint.host,
                family: "IPv4",
                scope: "public internet",
                reverseDNS: "ptr.example.net",
                organization: "Example Org",
                networkName: "EXAMPLE-NET",
                asn: "AS13335",
                asnDescription: "Cloudflare",
                registry: "ARIN",
                country: "US",
                ttl: 54,
                estimatedHops: 10
            ),
            transport: TransportDetails(tcp: TCPDetails(state: "ESTABLISHED")),
            tls: TLSDetails(
                version: "TLS 1.3",
                serverName: "example.com",
                certificates: [certificate]
            ),
            application: ApplicationDetails(
                protocols: ["TLS", "HTTP"],
                httpHosts: ["example.com:443"],
                dnsQueries: ["example.com"]
            ),
            socket: SocketDetails(
                pid: 42,
                command: "Safari",
                localAddress: "192.168.1.10",
                localPort: 51000,
                remoteAddress: assessment.key.remoteEndpoint.host,
                remotePort: 443,
                transport: .tcp
            ),
            process: assessment.process
        )
    }
}
