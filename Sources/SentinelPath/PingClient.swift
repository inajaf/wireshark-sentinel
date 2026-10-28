import Foundation
import SentinelDomain
import SentinelIdentity

/// One ICMP echo, used only to ask "does this address answer, and what name does
/// the network give it". The ping is not run when the graph opens.
public struct PingClient: Sendable {
    private let runner: PathCommandRunning
    private let ptr: PTRResolving

    public init(
        runner: PathCommandRunning = SystemPathCommandRunner(),
        ptr: PTRResolving = SystemPTRResolver()
    ) {
        self.runner = runner
        self.ptr = ptr
    }

    public func ping(
        _ host: String,
        localAddresses: Set<String> = [],
        broadcastAddresses: Set<String> = []
    ) async -> PingResult {
        let target = PathAddress.bare(host)
        if let problem = PathProbeSafety.problem(
            for: target,
            localAddresses: localAddresses,
            broadcastAddresses: broadcastAddresses
        ) {
            return PingResult(host: target, error: problem, method: "ICMP echo")
        }

        let isIPv6 = PathAddress.isIPv6(target)
        let executable = isIPv6 ? "/sbin/ping6" : "/sbin/ping"
        let arguments = ["-c", "1", "-W", "1500", "-t", "3", target]
        let command = await runner.run(executable: executable, arguments: arguments, timeout: 6)

        var result = PingOutputParser.parse(command.stdout, target: target)
        result.command = command.commandLine
        if !result.responded, result.hostname != nil {
            result.method = "reverse DNS only"
        }

        if command.timedOut {
            result.error = "Ping was stopped after 6 seconds without returning."
        } else if !command.succeeded {
            let stderr = command.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            if !stderr.isEmpty {
                result.error = stderr
            } else if result.error == nil {
                result.error = "\(executable) exited with status \(command.exitCode)."
            }
        }

        // ping without -n already asks reverse DNS for the first line. When that
        // fails (notably with macOS ping6 here), ask the system resolver directly
        // rather than losing the name the user pressed the button to find.
        if result.hostname == nil {
            let resolver = ptr
            let name = await Task.detached(priority: .userInitiated) {
                resolver.name(for: target)
            }.value
            if let cleaned = name.map(PathAddress.cleanName), !cleaned.isEmpty {
                result.hostname = cleaned
                if !result.responded {
                    result.method = "reverse DNS only"
                    let base = result.error ?? "No ICMP echo reply."
                    result.error = "\(base) The name comes from reverse DNS, not from the ICMP reply."
                }
            }
        }

        return result
    }
}

public enum PingOutputParser {
    public static func parse(_ output: String, target: String) -> PingResult {
        let address = PathAddress.bare(target)
        var result = PingResult(host: address)
        var received: Int?
        var transmitted: Int?
        var loss: Double?

        for rawLine in output.split(whereSeparator: { $0.isNewline }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("PING ") {
                if let open = line.firstIndex(of: "(") {
                    let name = line[line.index(line.startIndex, offsetBy: 5)..<open]
                        .trimmingCharacters(in: .whitespaces)
                    let cleaned = PathAddress.cleanName(name)
                    if !cleaned.isEmpty { result.hostname = cleaned }
                }
            }

            if line.contains("packets transmitted"), line.contains("packets received") {
                for component in line.split(separator: ",") {
                    if component.contains("packets transmitted") {
                        transmitted = firstInteger(in: component)
                    }
                    if component.contains("packets received") {
                        received = firstInteger(in: component)
                    }
                    if component.contains("packet loss") {
                        loss = firstDouble(in: component)
                    }
                }
            }

            if line.contains("round-trip") || line.contains("rtt") {
                if let equals = line.firstIndex(of: "=") {
                    let values = line[line.index(after: equals)...]
                        .split(separator: "/")
                        .compactMap { part -> Double? in
                            let first = part.split(separator: " ").first.map(String.init) ?? ""
                            return Double(first)
                        }
                    if values.count >= 2 {
                        result.rttMilliseconds = values[1]
                    } else if let first = values.first {
                        result.rttMilliseconds = first
                    }
                }
            }

            if line.contains("time="), result.rttMilliseconds == nil {
                if let range = line.range(of: "time=") {
                    let tail = line[range.upperBound...]
                    let number = tail.prefix { $0.isNumber || $0 == "." }
                    result.rttMilliseconds = Double(number)
                }
            }
        }

        if let received {
            result.responded = received > 0
            if received == 0, result.error == nil {
                result.error = "No ICMP echo reply."
            }
        } else {
            result.responded = result.rttMilliseconds != nil
            if !result.responded, result.error == nil {
                result.error = "The ping output contained no reply."
            }
        }
        result.packetLossPercent = loss

        if transmitted == nil, let received {
            result.packetLossPercent = received > 0 ? 0 : 100
        }
        return result
    }

    private static func firstInteger(in text: some StringProtocol) -> Int? {
        let digits = text.drop { !$0.isNumber }.prefix { $0.isNumber }
        return Int(digits)
    }

    private static func firstDouble(in text: some StringProtocol) -> Double? {
        let number = text.drop { !($0.isNumber || $0 == ".") }
            .prefix { $0.isNumber || $0 == "." }
        return Double(number)
    }
}
