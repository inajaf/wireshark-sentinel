import Foundation
import Darwin
import SentinelDomain

/// Turns a person's request ("block 203.0.113.9 on 443") into pf rules, and
/// refuses the requests that could cut this Mac off from itself. It is pure and
/// testable; nothing here runs a command or touches the firewall.
public struct BlockPlanBuilder: Sendable {
    public init() {}

    public static func plan(
        targets: [BlockTarget],
        localAddresses: Set<String> = [],
        broadcastAddresses: Set<String> = []
    ) -> BlockPlan {
        var errors: [String] = []
        var warnings: [String] = []
        var normalized: [BlockTarget] = []
        var seen = Set<String>()

        for target in targets {
            switch parse(target.address) {
            case .failure(let reason):
                errors.append("\(target.address): \(reason)")
                continue
            case .success(let address):
                if let reason = safetyProblem(
                    address,
                    localAddresses: localAddresses,
                    broadcastAddresses: broadcastAddresses
                ) {
                    errors.append("\(target.address): \(reason)")
                    continue
                }
                if target.port == 0 {
                    errors.append("\(target.address): port 0 is not a service port.")
                    continue
                }

                var clean = target
                clean.address = address.display
                if !seen.insert(clean.id).inserted { continue }

                if address.isCIDR {
                    warnings.append("\(address.display) is a range, not one address. Every address in it will be blocked.")
                }
                if !address.isCIDR || address.prefix < address.maxPrefix {
                    if target.port == nil {
                        warnings.append("\(address.display) will be blocked on every port and every protocol.")
                    }
                }
                if address.scope == .privateNetwork || address.scope == .linkLocal || address.scope == .carrierGradeNAT {
                    warnings.append("\(address.display) is \(address.scope.label). Blocking it may make a local device or service unreachable.")
                }
                if address.scope == .documentation || address.scope == .benchmark || address.scope == .reserved {
                    warnings.append("\(address.display) is \(address.scope.label); real traffic is unlikely to match it.")
                }
                if address.broad {
                    warnings.append("\(address.display) is a broad range. Check it before applying.")
                }
                if target.port != nil {
                    warnings.append("Applying this closes existing connections to \(address.display) on every port; pf can only kill states by address.")
                }
                normalized.append(clean)
            }
        }

        if normalized.isEmpty, errors.isEmpty, !targets.isEmpty {
            errors.append("No usable target was left after validation.")
        }

        let rules = render(normalized)
        return BlockPlan(
            targets: normalized,
            rules: rules,
            warnings: unique(warnings),
            errors: errors,
            killExistingStates: !normalized.isEmpty
        )
    }

    // MARK: - Address parsing

    struct ParsedAddress {
        var display: String
        var family: String
        var inet: String
        var isCIDR: Bool
        var prefix: Int
        var maxPrefix: Int
        var bytes: [UInt8]
        var scope: IPScope
        var broad: Bool
    }

    enum ParseResult {
        case success(ParsedAddress)
        case failure(String)
    }

    static func parse(_ raw: String) -> ParseResult {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return .failure("the address is empty.") }
        if text.hasPrefix("["), text.hasSuffix("]") {
            text = String(text.dropFirst().dropLast())
        }
        if text.contains("%") {
            return .failure("a zone suffix is not valid in a firewall rule.")
        }
        if text.contains(where: { $0.isWhitespace }) {
            return .failure("an address cannot contain spaces.")
        }

        let pieces = text.split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.count <= 2 else {
            return .failure("more than one prefix separator.")
        }
        let host = String(pieces[0])
        guard !host.isEmpty else { return .failure("the address is empty.") }

        var bytes: [UInt8]
        let family: String
        let maxPrefix: Int
        var v4 = in_addr()
        var v6 = in6_addr()
        if inet_pton(AF_INET, host, &v4) == 1 {
            bytes = withUnsafeBytes(of: &v4) { Array($0) }
            family = "IPv4"
            maxPrefix = 32
        } else if inet_pton(AF_INET6, host, &v6) == 1 {
            bytes = withUnsafeBytes(of: &v6) { Array($0) }
            family = "IPv6"
            maxPrefix = 128
        } else {
            return .failure("not an IPv4 or IPv6 address.")
        }

        let isCIDR = pieces.count == 2
        let prefix: Int
        if isCIDR {
            guard let value = Int(pieces[1]), (0...maxPrefix).contains(value) else {
                return .failure("the prefix length must be between 0 and \(maxPrefix).")
            }
            prefix = value
        } else {
            prefix = maxPrefix
        }

        let minimum = family == "IPv4" ? 8 : 32
        if prefix < minimum {
            return .failure("refusing to block more than a /\(minimum) \(family) range.")
        }

        let classification = IPClassifier.classify(host)
        switch classification.scope {
        case .loopback:
            return .failure("loopback belongs to this Mac and cannot be blocked.")
        case .multicast:
            return .failure("a multicast group is not a host that can be blocked.")
        case .broadcast:
            return .failure("a broadcast address is not a host that can be blocked.")
        case .unspecified:
            return .failure("the unspecified address is not a host that can be blocked.")
        case .unknown:
            return .failure("the address could not be classified.")
        default:
            break
        }

        mask(&bytes, prefix: prefix)
        guard let network = format(bytes, family: family) else {
            return .failure("the address could not be normalized.")
        }

        let display = prefix == maxPrefix ? network : "\(network)/\(prefix)"
        let broad = (family == "IPv4" && prefix <= 16) || (family == "IPv6" && prefix <= 48)

        return .success(ParsedAddress(
            display: display,
            family: family,
            inet: family == "IPv4" ? "inet" : "inet6",
            isCIDR: isCIDR && prefix != maxPrefix,
            prefix: prefix,
            maxPrefix: maxPrefix,
            bytes: bytes,
            scope: classification.scope,
            broad: broad
        ))
    }

    private static func safetyProblem(
        _ address: ParsedAddress,
        localAddresses: Set<String>,
        broadcastAddresses: Set<String>
    ) -> String? {
        // Only an exact local address is refused. A range that happens to contain
        // this Mac is a different request: the person may be blocking a whole LAN,
        // and the rules can still be valid. Exact self is the dangerous mistake.
        guard address.prefix == address.maxPrefix else { return nil }
        for local in localAddresses {
            if let other = hostBytes(local), other.family == address.family,
               address.bytes == other.bytes {
                return "this is \(local), this Mac's own address."
            }
        }
        for broadcast in broadcastAddresses {
            if let other = hostBytes(broadcast), other.family == address.family,
               address.bytes == other.bytes {
                return "this is the broadcast address \(broadcast)."
            }
        }
        return nil
    }

    private static func hostBytes(_ raw: String) -> (family: String, bytes: [UInt8])? {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("["), text.hasSuffix("]") {
            text = String(text.dropFirst().dropLast())
        }
        if let percent = text.firstIndex(of: "%") { text = String(text[..<percent]) }
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            return ("IPv4", withUnsafeBytes(of: &v4) { Array($0) })
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            return ("IPv6", withUnsafeBytes(of: &v6) { Array($0) })
        }
        return nil
    }

    private static func contains(_ network: [UInt8], _ address: [UInt8], prefix: Int) -> Bool {
        guard network.count == address.count else { return false }
        let full = prefix / 8
        let remainder = prefix % 8
        guard full <= network.count else { return false }
        if Array(network.prefix(full)) != Array(address.prefix(full)) { return false }
        guard remainder > 0, full < network.count else { return true }
        let mask: UInt8 = UInt8(truncatingIfNeeded: 0xFF << (8 - remainder))
        return (network[full] & mask) == (address[full] & mask)
    }

    private static func mask(_ bytes: inout [UInt8], prefix: Int) {
        for index in bytes.indices {
            let start = index * 8
            if prefix >= start + 8 {
                continue
            }
            if prefix <= start {
                bytes[index] = 0
            } else {
                let bits = prefix - start
                bytes[index] &= UInt8(truncatingIfNeeded: 0xFF << (8 - bits))
            }
        }
    }

    private static func format(_ bytes: [UInt8], family: String) -> String? {
        if family == "IPv4" {
            var value = in_addr()
            withUnsafeMutableBytes(of: &value) { $0.copyBytes(from: bytes) }
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &value, &buffer, socklen_t(buffer.count)) != nil else { return nil }
            return String(cString: buffer)
        }
        var value = in6_addr()
        withUnsafeMutableBytes(of: &value) { $0.copyBytes(from: bytes) }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &value, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return String(cString: buffer)
    }

    // MARK: - Rules

    static func render(_ targets: [BlockTarget]) -> [PFRule] {
        var outV4: [String] = []
        var inV4: [String] = []
        var outV6: [String] = []
        var inV6: [String] = []
        var rules: [PFRule] = []

        for target in targets {
            guard let parsed = addressInfo(target.address) else { continue }

            if target.port == nil, target.transport == .any {
                switch target.direction {
                case .outbound:
                    if parsed.family == "IPv4" { outV4.append(parsed.display) } else { outV6.append(parsed.display) }
                case .inbound:
                    if parsed.family == "IPv4" { inV4.append(parsed.display) } else { inV6.append(parsed.display) }
                case .both:
                    if parsed.family == "IPv4" {
                        outV4.append(parsed.display)
                        inV4.append(parsed.display)
                    } else {
                        outV6.append(parsed.display)
                        inV6.append(parsed.display)
                    }
                }
                continue
            }

            let protocols: [BlockTransport]
            if target.transport == .any {
                protocols = [.tcp, .udp]
            } else {
                protocols = [target.transport]
            }

            for proto in protocols {
                let protoName = proto.pfName ?? ""
                let port = target.port.map { " port = \($0)" } ?? ""
                let protoPart = protoName.isEmpty ? "" : " proto \(protoName)"

                switch target.direction {
                case .outbound:
                    rules.append(PFRule(
                        section: "rule",
                        text: "block drop quick \(parsed.inet)\(protoPart) from any to \(parsed.display)\(port)"
                    ))
                case .inbound:
                    rules.append(PFRule(
                        section: "rule",
                        text: "block drop quick \(parsed.inet)\(protoPart) from \(parsed.display)\(port) to any"
                    ))
                case .both:
                    rules.append(PFRule(
                        section: "rule",
                        text: "block drop quick \(parsed.inet)\(protoPart) from any to \(parsed.display)\(port)"
                    ))
                    rules.append(PFRule(
                        section: "rule",
                        text: "block drop quick \(parsed.inet)\(protoPart) from \(parsed.display)\(port) to any"
                    ))
                }
            }
        }

        let tables: [(String, [String])] = [
            ("sentinel_block_out_v4", unique(outV4)),
            ("sentinel_block_in_v4", unique(inV4)),
            ("sentinel_block_out_v6", unique(outV6)),
            ("sentinel_block_in_v6", unique(inV6)),
        ]

        for (name, addresses) in tables where !addresses.isEmpty {
            rules.append(PFRule(
                section: "table",
                text: "table <\(name)> persist { \(addresses.joined(separator: ", ")) }"
            ))
        }
        if !outV4.isEmpty {
            rules.append(PFRule(section: "rule", text: "block drop quick inet from any to <sentinel_block_out_v4>"))
        }
        if !inV4.isEmpty {
            rules.append(PFRule(section: "rule", text: "block drop quick inet from <sentinel_block_in_v4> to any"))
        }
        if !outV6.isEmpty {
            rules.append(PFRule(section: "rule", text: "block drop quick inet6 from any to <sentinel_block_out_v6>"))
        }
        if !inV6.isEmpty {
            rules.append(PFRule(section: "rule", text: "block drop quick inet6 from <sentinel_block_in_v6> to any"))
        }

        return rules
    }

    private struct AddressInfo {
        var display: String
        var family: String
        var inet: String
    }

    private static func addressInfo(_ display: String) -> AddressInfo? {
        if display.contains(":") {
            return AddressInfo(display: display, family: "IPv6", inet: "inet6")
        }
        return AddressInfo(display: display, family: "IPv4", inet: "inet")
    }

    private static func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}
