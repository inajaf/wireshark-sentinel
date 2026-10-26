import Foundation
import SentinelDomain

public enum ReportFormat: String, Sendable {
    case markdown, json
}

/// The plain-language answer to "what is this Mac talking to".
public struct SentinelReport: Sendable {
    public let assessments: [FlowAssessment]
    public let interfaceName: String?
    public let duration: TimeInterval
    public let generatedAt: Date

    public init(
        assessments: [FlowAssessment],
        interfaceName: String? = nil,
        duration: TimeInterval = 0,
        generatedAt: Date = Date()
    ) {
        self.assessments = assessments
        self.interfaceName = interfaceName
        self.duration = duration
        self.generatedAt = generatedAt
    }

    public func render(_ format: ReportFormat) -> String {
        switch format {
        case .markdown: return markdownText()
        case .json: return jsonText()
        }
    }

    public func write(to url: URL, format: ReportFormat) throws {
        try render(format).write(to: url, atomically: true, encoding: .utf8)
    }
}

extension SentinelReport {
    var ordered: [FlowAssessment] {
        assessments.sorted { lhs, rhs in
            if lhs.score != rhs.score { return lhs.score > rhs.score }
            if lhs.firstSeen != rhs.firstSeen { return lhs.firstSeen < rhs.firstSeen }
            return endpoint(of: lhs) < endpoint(of: rhs)
        }
    }

    var interfaceText: String {
        guard let interfaceName, !interfaceName.trimmingCharacters(in: .whitespaces).isEmpty else {
            return "interface not recorded"
        }
        return interfaceName
    }

    var durationText: String {
        let seconds = Int(duration.rounded())
        if seconds <= 0 { return "less than a second" }
        return seconds == 1 ? "1 second" : "\(seconds) seconds"
    }

    /// A fact marked unknown confidence is a reported address, not a name, so it never becomes one here.
    func name(of identity: EndpointIdentity) -> String? {
        let named = identity.facts
            .filter { $0.confidence != .unknown && !$0.value.trimmingCharacters(in: .whitespaces).isEmpty }
            .sorted { rank($0.confidence) < rank($1.confidence) }
        if let value = named.first?.value { return value }
        if let organization = identity.organization, !organization.trimmingCharacters(in: .whitespaces).isEmpty {
            return organization
        }
        if let service = identity.service, !service.trimmingCharacters(in: .whitespaces).isEmpty {
            return service
        }
        return nil
    }

    func host(of assessment: FlowAssessment) -> String {
        let host = assessment.key.remote.host
        return host.isEmpty ? "unknown" : host
    }

    func endpoint(of assessment: FlowAssessment) -> String {
        "\(host(of: assessment)):\(assessment.key.remote.port)"
    }

    func count(of verdict: Verdict) -> Int {
        assessments.filter { $0.verdict == verdict }.count
    }

    func verdictWord(_ verdict: Verdict) -> String {
        switch verdict {
        case .known: return "Identified"
        case .unknown: return "Unidentified"
        case .suspicious: return "Possibly spying"
        }
    }

    func signingText(_ status: SigningStatus) -> String {
        switch status {
        case .apple: return "signed by Apple"
        case .developerID(let team): return "signed with a Developer ID (\(team))"
        case .adHoc: return "ad-hoc signed"
        case .unsigned: return "unsigned"
        case .unknown: return "signing not checked"
        }
    }

    func signingKey(_ status: SigningStatus) -> String {
        switch status {
        case .apple: return "apple"
        case .developerID: return "developerID"
        case .adHoc: return "adHoc"
        case .unsigned: return "unsigned"
        case .unknown: return "unknown"
        }
    }

    func processText(_ process: ProcessIdentity?) -> String {
        guard let process else { return "not attributed" }
        return "\(process.name) (pid \(process.pid)), \(signingText(process.signing))"
    }

    func iso8601(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    private func rank(_ confidence: Confidence) -> Int {
        switch confidence {
        case .observed: return 0
        case .inferred: return 1
        case .unknown: return 2
        }
    }
}
