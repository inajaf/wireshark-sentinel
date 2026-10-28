import Foundation
import Darwin
import SentinelDomain

/// Address and name handling shared by the route, traceroute and ping readers.
/// Everything here is local string work; none of it performs a lookup.
public enum PathAddress {
    /// The address without brackets, a zone, or a trailing port. IPv6 literals
    /// keep their colons, which is why a port is only stripped from a single-colon
    /// host such as `1.1.1.1:443` or `example.com:443`.
    public static func bare(_ raw: String) -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return "" }

        if value.hasPrefix("["), let close = value.firstIndex(of: "]") {
            value = String(value[value.index(after: value.startIndex)..<close])
        } else if value.filter({ $0 == ":" }).count == 1, let colon = value.lastIndex(of: ":") {
            let port = value[value.index(after: colon)...]
            if !port.isEmpty, port.allSatisfy({ $0.isNumber }) {
                value = String(value[..<colon])
            }
        }

        if let percent = value.firstIndex(of: "%") {
            value = String(value[..<percent])
        }
        return value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public static func isIPv6(_ raw: String) -> Bool {
        var address = in6_addr()
        return inet_pton(AF_INET6, bare(raw), &address) == 1
    }

    public static func isIPv4(_ raw: String) -> Bool {
        var address = in_addr()
        return inet_pton(AF_INET, bare(raw), &address) == 1
    }

    public static func isIPAddress(_ raw: String) -> Bool {
        isIPv4(raw) || isIPv6(raw)
    }

    /// Canonical equality, not string equality: `::1` and `0:0:0:0:0:0:0:1`
    /// are the same target. Hostnames compare case-insensitively.
    public static func same(_ lhs: String, _ rhs: String) -> Bool {
        let left = bare(lhs)
        let right = bare(rhs)
        var v4a = in_addr()
        var v4b = in_addr()
        if inet_pton(AF_INET, left, &v4a) == 1, inet_pton(AF_INET, right, &v4b) == 1 {
            return withUnsafeBytes(of: v4a) { a in
                withUnsafeBytes(of: v4b) { b in a.elementsEqual(b) }
            }
        }
        var v6a = in6_addr()
        var v6b = in6_addr()
        if inet_pton(AF_INET6, left, &v6a) == 1, inet_pton(AF_INET6, right, &v6b) == 1 {
            return withUnsafeBytes(of: v6a) { a in
                withUnsafeBytes(of: v6b) { b in a.elementsEqual(b) }
            }
        }
        return left.caseInsensitiveCompare(right) == .orderedSame
    }

    public static func family(of raw: String) -> String {
        if isIPv4(raw) { return "IPv4" }
        if isIPv6(raw) { return "IPv6" }
        return "unknown"
    }

    /// A display name from evidence. Address literals, empty values and host:port
    /// pairs are rejected or reduced here so the graph never labels a service with
    /// an address wearing a hostname's clothes.
    public static func cleanName(_ raw: String) -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return "" }

        // A certificate SAN or DNS answer can end in the root dot.
        while value.hasSuffix(".") { value.removeLast() }
        value = value.trimmingCharacters(in: .whitespacesAndNewlines)

        // HTTP Host and certificate entries occasionally carry a port.
        if value.filter({ $0 == ":" }).count == 1, let colon = value.lastIndex(of: ":") {
            let port = value[value.index(after: colon)...]
            if !port.isEmpty, port.allSatisfy({ $0.isNumber }) {
                value = String(value[..<colon])
            }
        }

        value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return "" }
        guard !EndpointIdentity.isAddressLiteral(value) else { return "" }
        // A bare label is a name, but punctuation-only strings are not.
        guard value.contains(where: { $0.isLetter }) else { return "" }
        return value
    }
}
