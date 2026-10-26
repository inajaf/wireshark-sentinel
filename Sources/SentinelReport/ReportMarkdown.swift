import Foundation
import SentinelDomain

extension SentinelReport {
    func markdownText() -> String {
        let conversations = ordered
        let hosts = Set(conversations.map { $0.key.remote.host }.filter { !$0.isEmpty })
        var lines: [String] = [
            "# Wireshark Sentinel report: \(interfaceText), \(durationText)",
            "",
            "Generated \(iso8601(generatedAt)).",
            "",
            "## Summary",
            "",
            "- Conversations: \(conversations.count)",
            "- Known: \(count(of: .known))",
            "- Unknown: \(count(of: .unknown))",
            "- Suspicious: \(count(of: .suspicious))",
            "",
            "## Worth your attention",
            "",
        ]

        let attention = conversations.filter { $0.verdict != .known }
        if attention.isEmpty {
            lines.append("Nothing needed your attention.")
        } else {
            for assessment in attention {
                lines.append(contentsOf: attentionLines(assessment, hosts: hosts))
            }
        }

        lines.append("## Everything else")
        lines.append("")
        let rest = conversations.filter { $0.verdict == .known }
        if rest.isEmpty {
            lines.append("No other conversations were observed.")
        } else {
            for assessment in rest {
                lines.append(knownLine(assessment, hosts: hosts))
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private func attentionLines(_ assessment: FlowAssessment, hosts: Set<String>) -> [String] {
        let word = verdictWord(assessment.verdict)
        var lines = ["### \(word): \(endpoint(of: assessment))"]
        if let name = name(of: assessment.identity) {
            lines.append(tag("- Name: \(name)", hosts: hosts, word: word))
        } else {
            lines.append(tag("- Name: unidentified", hosts: hosts, word: word))
            lines.append(tag("- Reason: \(unidentifiedReason(assessment))", hosts: hosts, word: word))
        }
        lines.append(tag("- Process: \(processText(assessment.process))", hosts: hosts, word: word))
        lines.append(tag("- Signals: \(signalTitles(assessment.signals))", hosts: hosts, word: word))
        lines.append(tag("- Why: \(rationaleText(assessment))", hosts: hosts, word: word))
        lines.append("")
        return lines
    }

    private func knownLine(_ assessment: FlowAssessment, hosts: Set<String>) -> String {
        let word = verdictWord(assessment.verdict)
        let name = name(of: assessment.identity) ?? "unidentified"
        let text = "- \(word): \(endpoint(of: assessment)) (\(name)). Process: \(processText(assessment.process))."
        return tag(text, hosts: hosts, word: word)
    }

    /// Every line that names a remote host has to carry a verdict word, wherever the host came from.
    private func tag(_ text: String, hosts: Set<String>, word: String) -> String {
        guard !text.contains(word), hosts.contains(where: { text.contains($0) }) else { return text }
        return "\(word). \(text)"
    }

    private func signalTitles(_ signals: [Signal]) -> String {
        signals.isEmpty ? "none" : signals.map { $0.kind.title }.joined(separator: ", ")
    }

    private func rationaleText(_ assessment: FlowAssessment) -> String {
        let rationale = assessment.rationale.trimmingCharacters(in: .whitespacesAndNewlines)
        return rationale.isEmpty ? "No rationale was recorded." : rationale
    }

    private func unidentifiedReason(_ assessment: FlowAssessment) -> String {
        if let signal = assessment.signals.first(where: { $0.kind == .unknownDestination }) {
            return signal.detail
        }
        return "This connection carries no name evidence."
    }
}
