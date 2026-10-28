import Foundation
import SentinelDomain

/// A read of the system routing table. This is local state, not a network probe.
public protocol RouteResolving: Sendable {
    func route(to host: String) async -> RouteInfo?
}

public enum RouteOutputParser {
    /// Reads `route -n get <address>` output. An on-link destination has no
    /// gateway, which is information rather than a missing value.
    public static func parse(_ output: String) -> RouteInfo? {
        var destination: String?
        var gateway: String?
        var interfaceName: String?

        for rawLine in output.split(whereSeparator: { $0.isNewline }) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty else { continue }

            switch key {
            case "destination":
                destination = value
            case "gateway":
                // A link-layer gateway such as `link#16` means there is no IP
                // next hop to display; the destination is directly reachable.
                gateway = value.hasPrefix("link#") ? nil : value
            case "interface":
                interfaceName = value
            default:
                break
            }
        }

        guard let destination else { return nil }
        return RouteInfo(
            destination: destination,
            gateway: gateway,
            interfaceName: interfaceName
        )
    }
}

public struct SystemRouteResolver: RouteResolving {
    private let runner: PathCommandRunning

    public init(runner: PathCommandRunning = SystemPathCommandRunner()) {
        self.runner = runner
    }

    public func route(to host: String) async -> RouteInfo? {
        let target = PathAddress.bare(host)
        guard PathAddress.isIPAddress(target) else { return nil }
        let result = await runner.run(
            executable: "/sbin/route",
            arguments: ["-n", "get", target],
            timeout: 3
        )
        guard result.succeeded else { return nil }
        return RouteOutputParser.parse(result.stdout)
    }
}
