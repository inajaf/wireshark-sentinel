import Foundation
import SentinelDomain

/// Sends one traceroute. Only called from the explicit Trace route button.
public struct TracerouteClient: Sendable {
    private let runner: PathCommandRunning

    public init(runner: PathCommandRunning = SystemPathCommandRunner()) {
        self.runner = runner
    }

    public func trace(
        to host: String,
        localAddresses: Set<String> = [],
        broadcastAddresses: Set<String> = [],
        maxHops: Int = 16,
        timeoutPerHop: TimeInterval = 1
    ) async -> PathTrace {
        let target = PathAddress.bare(host)
        if let problem = PathProbeSafety.problem(
            for: target,
            localAddresses: localAddresses,
            broadcastAddresses: broadcastAddresses
        ) {
            return PathTrace(error: problem)
        }

        let isIPv6 = PathAddress.isIPv6(target)
        let executable = isIPv6 ? "/usr/sbin/traceroute6" : "/usr/sbin/traceroute"
        let hops = max(1, min(maxHops, 32))
        let wait = max(1, Int(timeoutPerHop.rounded(.up)))
        let arguments = ["-n", "-w", "\(wait)", "-q", "1", "-m", "\(hops)", target]
        let timeout = Double(hops * wait) + 4
        let command = await runner.run(executable: executable, arguments: arguments, timeout: timeout)

        var trace = TracerouteOutputParser.parse(command.stdout, target: target)
        trace.command = command.commandLine

        if command.timedOut {
            trace.warnings.append("The traceroute was stopped after \(Int(timeout)) seconds; the path may be incomplete.")
        }

        let stderr = command.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if trace.hops.isEmpty {
            if !stderr.isEmpty {
                trace.error = stderr
            } else if !command.succeeded {
                trace.error = "\(executable) exited with status \(command.exitCode) and returned no hops."
            } else {
                trace.error = "Traceroute returned no hops."
            }
        } else if !stderr.isEmpty {
            trace.warnings.append(stderr)
        }

        if isIPv6, !trace.hops.isEmpty {
            trace.warnings.append("Traceroute ran over IPv6; a dual-stack service can use a different IPv4 path.")
        }
        return trace
    }
}

public enum TracerouteOutputParser {
    public static func parse(_ output: String, target: String) -> PathTrace {
        let wanted = PathAddress.bare(target)
        var hops: [PathHop] = []
        var sawHeader = false

        for rawLine in output.split(whereSeparator: { $0.isNewline }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.lowercased().hasPrefix("traceroute") {
                sawHeader = true
                continue
            }

            let parts = line
                .split(whereSeparator: { $0 == " " || $0 == "\t" })
                .map(String.init)
            guard parts.count > 1, let index = Int(parts[0]), index > 0 else { continue }

            let tokens = Array(parts.dropFirst())
            var address: String?
            var rtt: Double?
            var note: String?
            var offset = 0

            while offset < tokens.count {
                let token = tokens[offset]

                if token == "*" {
                    offset += 1
                    continue
                }
                if token == "ms" {
                    offset += 1
                    continue
                }
                if token.hasPrefix("!") {
                    note = unreachableNote(token)
                    offset += 1
                    continue
                }
                if let value = Double(token),
                   offset + 1 < tokens.count,
                   tokens[offset + 1] == "ms" {
                    if rtt == nil { rtt = value }
                    offset += 2
                    continue
                }
                if token.hasPrefix("("), token.hasSuffix(")") {
                    let inner = String(token.dropFirst().dropLast())
                    if PathAddress.isIPAddress(inner) {
                        address = PathAddress.bare(inner)
                    }
                    offset += 1
                    continue
                }
                if PathAddress.isIPAddress(token) {
                    address = PathAddress.bare(token)
                    offset += 1
                    continue
                }
                // Non-numeric output can say `name (address)`. Keep the address
                // for the graph and the name only as a note.
                if offset + 1 < tokens.count,
                   tokens[offset + 1].hasPrefix("("),
                   tokens[offset + 1].hasSuffix(")") {
                    let inner = String(tokens[offset + 1].dropFirst().dropLast())
                    if PathAddress.isIPAddress(inner) {
                        address = PathAddress.bare(inner)
                    }
                    note = note ?? token
                    offset += 2
                    continue
                }
                if address == nil, token.contains(where: { $0.isLetter }) {
                    address = token
                }
                offset += 1
            }

            let scope = address.map { IPClassifier.classify($0).scope } ?? .unknown
            hops.append(
                PathHop(
                    index: index,
                    address: address,
                    rttMilliseconds: rtt,
                    scope: scope,
                    note: note,
                    isDestination: address.map { PathAddress.same($0, wanted) } ?? false
                )
            )
        }

        let reached = hops.contains(where: { $0.isDestination })
        var trace = PathTrace(
            hops: hops.sorted { $0.index < $1.index },
            reachedDestination: reached
        )
        if hops.isEmpty {
            trace.error = sawHeader
                ? "Traceroute printed its header but no hop replies."
                : "Traceroute returned no readable hops."
        } else if !reached {
            trace.warnings.append("The destination did not answer within \(hops.count) hops. The path is partial.")
        }
        return trace
    }

    private static func unreachableNote(_ token: String) -> String {
        switch token.uppercased() {
        case "!H": return "host unreachable"
        case "!N": return "network unreachable"
        case "!P": return "protocol unreachable"
        case "!X": return "administratively prohibited"
        case "!F": return "fragmentation needed"
        default: return token
        }
    }
}
