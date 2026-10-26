import Foundation
import SentinelDomain
import SentinelSuspicion

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

    public func render(_ format: ReportFormat) -> String { "" }

    public func write(to url: URL, format: ReportFormat) throws {
        try render(format).write(to: url, atomically: true, encoding: .utf8)
    }
}
