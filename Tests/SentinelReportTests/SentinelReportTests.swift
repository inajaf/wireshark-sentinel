import Foundation
import SentinelDomain
import SentinelReport
import XCTest

final class SentinelReportTests: XCTestCase {
    func testAttentionSectionHoldsOnlyTheNonKnownConversationsInScoreOrder() throws {
        let markdown = report([knownAssessment, unknownAssessment, suspiciousAssessment]).render(.markdown)
        let attention = try XCTUnwrap(section("Worth your attention", in: markdown))
        let suspicious = try XCTUnwrap(attention.range(of: "93.184.216.34"))
        let unknown = try XCTUnwrap(attention.range(of: "203.0.113.9"))
        XCTAssertLessThan(suspicious.lowerBound, unknown.lowerBound)
        XCTAssertFalse(attention.contains("142.250.185.78"))
        XCTAssertTrue(attention.contains("Possibly spying"))
        XCTAssertTrue(attention.contains("Not sure yet"))
    }

    func testEveryLineNamingAHostCarriesAVerdictWord() {
        let noisy = makeAssessment(
            host: "93.184.216.35", port: 9000, verdict: .unknown, score: 30,
            signals: [Signal(kind: .unknownDestination, weight: 30, detail: "Nothing names 93.184.216.35 in any source.")],
            rationale: "Not sure about this connection because nothing names 93.184.216.35."
        )
        let markdown = report([knownAssessment, unknownAssessment, suspiciousAssessment, noisy]).render(.markdown)
        let words = ["Expected", "Not sure yet", "Possibly spying"]
        var checked = 0
        for line in markdown.split(separator: "\n")
        where line.range(of: #"\d{1,3}(\.\d{1,3}){3}"#, options: .regularExpression) != nil {
            checked += 1
            XCTAssertTrue(words.contains { line.contains($0) }, "a line names a host with no verdict word: \(line)")
        }
        XCTAssertGreaterThan(checked, 3)
    }

    func testJSONMatchesTheContractExactly() throws {
        let object = try jsonObject(report([knownAssessment, unknownAssessment, suspiciousAssessment]).render(.json))
        XCTAssertEqual(Set(object.keys), ["generatedAt", "interface", "durationSeconds", "summary", "conversations"])
        XCTAssertEqual(object["interface"] as? String, "en0")
        XCTAssertEqual(object["durationSeconds"] as? Double, 20)
        XCTAssertNotNil(ISO8601DateFormatter().date(from: try XCTUnwrap(object["generatedAt"] as? String)))

        let summary = try XCTUnwrap(object["summary"] as? [String: Any])
        XCTAssertEqual(Set(summary.keys), ["total", "known", "unknown", "suspicious"])
        XCTAssertEqual(summary["total"] as? Int, 3)
        XCTAssertEqual(summary["known"] as? Int, 1)
        XCTAssertEqual(summary["unknown"] as? Int, 1)
        XCTAssertEqual(summary["suspicious"] as? Int, 1)

        let conversations = try XCTUnwrap(object["conversations"] as? [[String: Any]])
        XCTAssertEqual(conversations.count, 3)
        let required: Set<String> = [
            "endpoint", "host", "transport", "direction", "verdict", "name", "identified",
            "process", "signals", "score", "packetCount", "byteCount", "rationale",
        ]
        let provenance: Set<String> = ["nameSource", "service", "serviceSource"]
        let keys = Set(conversations[0].keys)
        XCTAssertTrue(required.isSubset(of: keys), "contract keys missing: \(required.subtracting(keys))")
        XCTAssertTrue(keys.isSubset(of: required.union(provenance)), "undeclared keys: \(keys.subtracting(required.union(provenance)))")
        XCTAssertEqual(conversations[0]["endpoint"] as? String, "93.184.216.34:443")
        XCTAssertEqual(conversations[0]["host"] as? String, "93.184.216.34")
        XCTAssertEqual(conversations[0]["transport"] as? String, "tcp")
        XCTAssertEqual(conversations[0]["direction"] as? String, "outbound")
        XCTAssertEqual(conversations[0]["verdict"] as? String, "suspicious")
        XCTAssertEqual(conversations[0]["name"] as? String, "example.com")
        XCTAssertEqual(conversations[0]["identified"] as? Bool, true)
        XCTAssertEqual(conversations[0]["score"] as? Int, 95)

        let signals = try XCTUnwrap(conversations[0]["signals"] as? [[String: Any]])
        XCTAssertEqual(Set(signals[0].keys), ["kind", "title", "detail"])
        XCTAssertEqual(signals[0]["kind"] as? String, "beaconing")
        XCTAssertEqual(signals[0]["title"] as? String, "Regular beaconing")

        let process = try XCTUnwrap(conversations[0]["process"] as? [String: Any])
        XCTAssertEqual(Set(process.keys), ["pid", "name", "path", "signing"])
        XCTAssertEqual(process["pid"] as? Int, 77)
        XCTAssertEqual(process["path"] as? String, "/usr/bin/curl")
        XCTAssertEqual(process["signing"] as? String, "unsigned")

        XCTAssertTrue(conversations[1]["process"] is NSNull)
    }

    func testUnidentifiedNameIsNullAndNeverInvented() throws {
        let addressAsName = makeAssessment(
            host: "203.0.113.9", port: 8443, verdict: .unknown, score: 30,
            name: "203.0.113.9", confidence: .unknown
        )
        let object = try jsonObject(report([unknownAssessment, addressAsName]).render(.json))
        let conversations = try XCTUnwrap(object["conversations"] as? [[String: Any]])
        XCTAssertEqual(conversations.count, 2)
        for entry in conversations {
            XCTAssertEqual(entry["identified"] as? Bool, false)
            XCTAssertTrue(entry["name"] is NSNull, "an unnamed conversation must emit null, got \(String(describing: entry["name"]))")
        }

        let markdown = report([unknownAssessment]).render(.markdown)
        XCTAssertTrue(markdown.contains("- Name: unidentified"))
        XCTAssertTrue(markdown.contains("We could not identify who this destination belongs to."))
    }

    func testUnknownVerdictHeaderDoesNotContradictANamedResource() throws {
        let named = makeAssessment(
            host: "17.248.211.70", port: 443, verdict: .unknown, score: 25,
            name: "cdn.example.net", source: .ptr,
            signals: [Signal(kind: .plaintextProtocol, weight: 25, detail: "It sends data without encryption.")]
        )
        let markdown = report([named]).render(.markdown)
        XCTAssertTrue(markdown.contains("### Not sure yet: 17.248.211.70:443"))
        XCTAssertTrue(markdown.contains("- Name: cdn.example.net"))
        for line in markdown.split(separator: "\n") where line.hasPrefix("### ") {
            XCTAssertFalse(line.contains("Unidentified"), "a header must not deny a name the report then prints: \(line)")
        }
    }

    func testEachVerdictPrintsItsOwnHeaderWord() throws {
        let markdown = report([knownAssessment, unknownAssessment, suspiciousAssessment]).render(.markdown)
        XCTAssertTrue(markdown.contains("### Possibly spying: 93.184.216.34:443"))
        XCTAssertTrue(markdown.contains("### Not sure yet: 203.0.113.9:8443"))
        XCTAssertTrue(markdown.contains("- Expected: 142.250.185.78:443 (google.com)"))
    }

    func testJSONSortsByScoreThenFirstSeen() throws {
        let later = makeAssessment(host: "198.51.100.7", port: 8080, verdict: .unknown, score: 30, firstSeen: reportDate.addingTimeInterval(60))
        let earlier = makeAssessment(host: "198.51.100.8", port: 8080, verdict: .unknown, score: 30, firstSeen: reportDate)
        let object = try jsonObject(report([later, earlier, suspiciousAssessment]).render(.json))
        let endpoints = try XCTUnwrap(object["conversations"] as? [[String: Any]]).compactMap { $0["endpoint"] as? String }
        XCTAssertEqual(endpoints, ["93.184.216.34:443", "198.51.100.8:8080", "198.51.100.7:8080"])
    }

    func testAPortNumberNeverBecomesAName() throws {
        var identity = EndpointIdentity()
        identity.facts = [IdentityFact(value: "https", source: .serviceCatalog, confidence: .inferred)]
        identity.service = "https"
        let assessment = FlowAssessment(
            key: FlowKey(transport: .tcp, local: Endpoint(host: "127.0.0.1", port: 50000),
                         remote: Endpoint(host: "203.0.113.9", port: 443)),
            direction: .outbound, identity: identity, process: nil, signals: [
                Signal(kind: .unknownDestination, weight: 30,
                       detail: "We could not identify who this destination belongs to."),
            ],
            score: 30, verdict: .unknown, rationale: "Not sure about this connection.",
            firstSeen: reportDate, lastSeen: reportDate, packetCount: 2, byteCount: 100
        )
        let markdown = report([assessment]).render(.markdown)
        XCTAssertFalse(markdown.contains("Name: https"),
                       "a port label must never be printed as the resource name")
        XCTAssertTrue(markdown.contains("- Name: unidentified"))
        XCTAssertTrue(markdown.contains("- Service: https (guessed from the port number, not a name)"))

        let object = try jsonObject(report([assessment]).render(.json))
        let conversation = try XCTUnwrap((object["conversations"] as? [[String: Any]])?.first)
        XCTAssertEqual(conversation["identified"] as? Bool, false)
        XCTAssertNil(conversation["name"] as? String)
        XCTAssertEqual(conversation["service"] as? String, "https")
    }

    func testAnAddressLiteralIsNeverUsedAsAName() throws {
        var identity = EndpointIdentity()
        identity.facts = [IdentityFact(value: "203.0.113.9", source: .sni, confidence: .observed)]
        let assessment = FlowAssessment(
            key: FlowKey(transport: .tcp, local: Endpoint(host: "127.0.0.1", port: 50001),
                         remote: Endpoint(host: "203.0.113.9", port: 443)),
            direction: .outbound, identity: identity, process: nil, signals: [
                Signal(kind: .unknownDestination, weight: 30,
                       detail: "We could not identify who this destination belongs to."),
            ],
            score: 30, verdict: .unknown, rationale: "Not sure about this connection.",
            firstSeen: reportDate, lastSeen: reportDate, packetCount: 2, byteCount: 100
        )
        let markdown = report([assessment]).render(.markdown)
        XCTAssertTrue(markdown.contains("- Name: unidentified"),
                      "an address must never be dressed up as a name")
    }

    func testNameCarriesItsSource() throws {
        let object = try jsonObject(report([suspiciousAssessment]).render(.json))
        let conversation = try XCTUnwrap((object["conversations"] as? [[String: Any]])?.first)
        XCTAssertEqual(conversation["name"] as? String, "example.com")
        XCTAssertEqual(conversation["nameSource"] as? String, "ptr")
    }

    func testMarkdownNeverPrintsDomainTypeNames() {
        let markdown = report([knownAssessment, unknownAssessment, suspiciousAssessment]).render(.markdown)
        XCTAssertFalse(markdown.contains("FlowAssessment"))
        XCTAssertFalse(markdown.contains("SignalKind"))
        XCTAssertFalse(markdown.contains("nil"))
    }

    func testEmptyReportIsHonest() throws {
        let object = try jsonObject(SentinelReport(assessments: []).render(.json))
        XCTAssertEqual(object["interface"] as? String, "")
        XCTAssertEqual((object["conversations"] as? [Any])?.isEmpty, true)
        let summary = try XCTUnwrap(object["summary"] as? [String: Any])
        XCTAssertEqual(summary["total"] as? Int, 0)
        XCTAssertEqual(summary["known"] as? Int, 0)
        XCTAssertTrue(report([]).render(.markdown).contains("Nothing needed your attention."))
    }

    func testEndpointIsNeverEmpty() throws {
        let nowhere = makeAssessment(host: "", port: 0, verdict: .unknown, score: 30)
        let object = try jsonObject(report([nowhere]).render(.json))
        let entry = try XCTUnwrap((object["conversations"] as? [[String: Any]])?.first)
        XCTAssertFalse(try XCTUnwrap(entry["endpoint"] as? String).isEmpty)
        XCTAssertFalse(try XCTUnwrap(entry["host"] as? String).isEmpty)
        XCTAssertEqual(entry["identified"] as? Bool, false)
    }

    func testWriteProducesBothFormatsOnDisk() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("sentinel-report-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let subject = report([knownAssessment, unknownAssessment, suspiciousAssessment])
        let markdownFile = directory.appendingPathComponent("sentinel-report.md")
        let jsonFile = directory.appendingPathComponent("sentinel-report.json")
        try subject.write(to: markdownFile, format: .markdown)
        try subject.write(to: jsonFile, format: .json)

        XCTAssertTrue(try String(contentsOf: markdownFile, encoding: .utf8).contains("## Worth your attention"))
        let object = try jsonObject(try String(contentsOf: jsonFile, encoding: .utf8))
        XCTAssertEqual(Set(object.keys).count, 5)
        XCTAssertEqual((object["conversations"] as? [Any])?.count, 3)
    }
}

private let reportDate = Date(timeIntervalSince1970: 1_700_000_000)

private func report(_ assessments: [FlowAssessment]) -> SentinelReport {
    SentinelReport(assessments: assessments, interfaceName: "en0", duration: 20, generatedAt: reportDate)
}

private func section(_ title: String, in markdown: String) -> String? {
    markdown.components(separatedBy: "\n## ").first { $0.hasPrefix(title) }
}

private func jsonObject(_ text: String) throws -> [String: Any] {
    try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
}

private func makeAssessment(
    host: String,
    port: UInt16 = 443,
    verdict: Verdict,
    score: Int,
    name: String? = nil,
    source: IdentitySource = .ptr,
    confidence: Confidence = .observed,
    process: ProcessIdentity? = nil,
    signals: [Signal] = [],
    rationale: String = "",
    firstSeen: Date = reportDate,
    packetCount: Int = 4,
    byteCount: Int = 400
) -> FlowAssessment {
    let facts = name.map { [IdentityFact(value: $0, source: source, confidence: confidence)] } ?? []
    let identity = EndpointIdentity(
        facts: facts, firstSeen: firstSeen, lastSeen: firstSeen,
        packetCount: packetCount, byteCount: byteCount
    )
    return FlowAssessment(
        key: FlowKey(
            transport: .tcp,
            local: Endpoint(host: "127.0.0.1", port: 51000),
            remote: Endpoint(host: host, port: port)
        ),
        direction: .outbound,
        identity: identity,
        process: process,
        signals: signals,
        score: score,
        verdict: verdict,
        rationale: rationale,
        firstSeen: firstSeen,
        lastSeen: firstSeen,
        packetCount: packetCount,
        byteCount: byteCount
    )
}

private let knownAssessment = makeAssessment(
    host: "142.250.185.78", verdict: .known, score: 0, name: "google.com",
    process: ProcessIdentity(
        pid: 501, name: "Safari",
        path: "/Applications/Safari.app/Contents/MacOS/Safari", signing: .apple
    )
)

private let unknownAssessment = makeAssessment(
    host: "203.0.113.9", port: 8443, verdict: .unknown, score: 30,
    signals: [Signal(
        kind: .unknownDestination, weight: 30,
        detail: "We could not identify who this destination belongs to."
    )],
    rationale: "Not sure about this connection because we could not identify who this destination belongs to."
)

private let suspiciousAssessment = makeAssessment(
    host: "93.184.216.34", verdict: .suspicious, score: 95, name: "example.com",
    process: ProcessIdentity(pid: 77, name: "curl", path: "/usr/bin/curl", signing: .unsigned),
    signals: [
        Signal(kind: .beaconing, weight: 35, detail: "It repeats on a regular timer."),
        Signal(kind: .unusualPort, weight: 25, detail: "It uses remote port 8443."),
    ],
    rationale: "Suspicious because it repeats on a regular timer."
)
