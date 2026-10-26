import Foundation
import SentinelDomain

extension SentinelReport {
    func jsonText() -> String {
        guard let data = try? JSONSerialization.data(
            withJSONObject: jsonObject(),
            options: [.prettyPrinted, .sortedKeys]
        ), let text = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return text + "\n"
    }

    private func jsonObject() -> [String: Any] {
        [
            "generatedAt": iso8601(generatedAt),
            "interface": interfaceName ?? "",
            "durationSeconds": duration,
            "summary": [
                "total": assessments.count,
                "known": count(of: .known),
                "unknown": count(of: .unknown),
                "suspicious": count(of: .suspicious),
            ] as [String: Any],
            "conversations": ordered.map(conversationObject),
        ]
    }

    private func conversationObject(_ assessment: FlowAssessment) -> [String: Any] {
        let displayName = name(of: assessment.identity)
        var object: [String: Any] = [
            "endpoint": endpoint(of: assessment),
            "host": host(of: assessment),
            "transport": assessment.key.transport.rawValue,
            "direction": assessment.direction.rawValue,
            "verdict": assessment.verdict.rawValue,
            "identified": displayName != nil,
            "signals": assessment.signals.map { signal in
                [
                    "kind": signal.kind.rawValue,
                    "title": signal.kind.title,
                    "detail": signal.detail,
                ] as [String: Any]
            },
            "score": assessment.score,
            "packetCount": assessment.packetCount,
            "byteCount": assessment.byteCount,
            "rationale": assessment.rationale,
        ]
        if let displayName {
            object["name"] = displayName
        } else {
            object["name"] = NSNull()
        }
        if let process = assessment.process {
            var processObject: [String: Any] = [
                "pid": Int(process.pid),
                "name": process.name,
                "signing": signingKey(process.signing),
            ]
            if let path = process.path {
                processObject["path"] = path
            } else {
                processObject["path"] = NSNull()
            }
            object["process"] = processObject
        } else {
            object["process"] = NSNull()
        }
        return object
    }
}
