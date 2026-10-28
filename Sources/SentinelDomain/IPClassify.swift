import Foundation
import Darwin

/// A pure, offline classifier. It never performs a lookup, so it is safe to call
/// for every packet, in tests and without a network.
public enum IPClassifier {
    public static func classify(_ raw: String) -> IPClassification {
        var host = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.hasPrefix("["), host.hasSuffix("]") {
            host = String(host.dropFirst().dropLast())
        }
        // A link-local IPv6 address may carry a zone suffix such as %en0.
        if let percent = host.firstIndex(of: "%") {
            host = String(host[..<percent])
        }

        var v4 = in_addr()
        if inet_pton(AF_INET, host, &v4) == 1 {
            let bytes = withUnsafeBytes(of: &v4) { Array($0) }
            return classifyIPv4(host: host, bytes: bytes)
        }

        var v6 = in6_addr()
        if inet_pton(AF_INET6, host, &v6) == 1 {
            let bytes = withUnsafeBytes(of: &v6) { Array($0) }
            return classifyIPv6(host: host, bytes: bytes)
        }

        return IPClassification(
            address: raw,
            family: "unknown",
            scope: .unknown,
            explanation: "\(raw) is not an IPv4 or IPv6 address."
        )
    }

    private static func make(_ host: String, _ family: String, _ scope: IPScope, _ why: String) -> IPClassification {
        IPClassification(address: host, family: family, scope: scope, explanation: why)
    }

    private static func classifyIPv4(host: String, bytes: [UInt8]) -> IPClassification {
        func isIn(_ prefix: [UInt8]) -> Bool {
            guard bytes.count >= prefix.count else { return false }
            return Array(bytes.prefix(prefix.count)) == prefix
        }
        func isIn(_ first: UInt8, _ second: UInt8? = nil) -> Bool {
            guard let a = bytes.first else { return false }
            if let second { return a == first && bytes.count > 1 && bytes[1] == second }
            return a == first
        }

        if isIn([0, 0, 0, 0]) {
            return make(host, "IPv4", .unspecified, "\(host) is the unspecified address.")
        }
        if isIn([0]) {
            return make(host, "IPv4", .reserved, "\(host) is in 0.0.0.0/8, the 'this network' range.")
        }
        if isIn([10]) {
            return make(host, "IPv4", .privateNetwork, "\(host) is in 10.0.0.0/8, a private network.")
        }
        if isIn([172]) && bytes.count > 1 && (16...31).contains(bytes[1]) {
            return make(host, "IPv4", .privateNetwork, "\(host) is in 172.16.0.0/12, a private network.")
        }
        if isIn([192, 168]) {
            return make(host, "IPv4", .privateNetwork, "\(host) is in 192.168.0.0/16, a private network.")
        }
        if isIn([100]) && bytes.count > 1 && (64...127).contains(bytes[1]) {
            return make(host, "IPv4", .carrierGradeNAT, "\(host) is in 100.64.0.0/10, carrier-grade NAT.")
        }
        if isIn([127]) {
            return make(host, "IPv4", .loopback, "\(host) is in 127.0.0.0/8, this Mac's loopback.")
        }
        if isIn([169, 254]) {
            return make(host, "IPv4", .linkLocal, "\(host) is in 169.254.0.0/16, link-local (APIPA).")
        }
        if bytes.count == 4 && bytes == [255, 255, 255, 255] {
            return make(host, "IPv4", .broadcast, "\(host) is the limited broadcast address.")
        }
        if isIn([224]) || isIn([225]) || isIn([226]) || isIn([227])
            || isIn([228]) || isIn([229]) || isIn([230]) || isIn([231])
            || isIn([232]) || isIn([233]) || isIn([234]) || isIn([235])
            || isIn([236]) || isIn([237]) || isIn([238]) || isIn([239]) {
            return make(host, "IPv4", .multicast, "\(host) is in 224.0.0.0/4, a multicast group.")
        }
        if isIn([192, 0, 2]) || isIn([198, 51, 100]) || isIn([203, 0, 113]) {
            return make(host, "IPv4", .documentation, "\(host) is in a documentation range (TEST-NET).")
        }
        if isIn([198, 18]) || isIn([198, 19]) {
            return make(host, "IPv4", .benchmark, "\(host) is in 198.18.0.0/15, a benchmarking range.")
        }
        if isIn([192, 0, 0]) || isIn([192, 88, 99]) || isIn([198, 51, 100]) || isIn([203, 0, 113]) {
            return make(host, "IPv4", .reserved, "\(host) is in a special-use IPv4 range.")
        }
        if let first = bytes.first, first >= 240 {
            return make(host, "IPv4", .reserved, "\(host) is in 240.0.0.0/4, a reserved range.")
        }
        return make(host, "IPv4", .publicInternet, "\(host) is a public internet address.")
    }

    private static func classifyIPv6(host: String, bytes: [UInt8]) -> IPClassification {
        func isIn(_ prefix: [UInt8], _ length: Int) -> Bool {
            guard bytes.count >= length else { return false }
            return Array(bytes.prefix(length)) == prefix
        }

        // ::ffff:a.b.c.d is an IPv4-mapped address; classify the embedded IPv4.
        if isIn([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], 12) {
            let v4 = Array(bytes[12..<16])
            return classifyIPv4(host: v4.map(String.init).joined(separator: "."), bytes: v4)
        }
        if bytes.allSatisfy({ $0 == 0 }) {
            return make(host, "IPv6", .unspecified, "\(host) is the unspecified IPv6 address.")
        }
        if isIn([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 16) {
            return make(host, "IPv6", .loopback, "\(host) is ::1, this Mac's loopback.")
        }
        if isIn([0xfe, 0x80], 2) || isIn([0xfe, 0x90], 2)
            || isIn([0xfe, 0xa0], 2) || isIn([0xfe, 0xb0], 2) {
            return make(host, "IPv6", .linkLocal, "\(host) is in fe80::/10, link-local.")
        }
        if isIn([0xfc], 1) || isIn([0xfd], 1) {
            return make(host, "IPv6", .privateNetwork, "\(host) is in fc00::/7, a unique local address.")
        }
        if isIn([0xff], 1) {
            return make(host, "IPv6", .multicast, "\(host) is in ff00::/8, a multicast group.")
        }
        if isIn([0x20, 0x01, 0x0d, 0xb8], 4) {
            return make(host, "IPv6", .documentation, "\(host) is in 2001:db8::/32, a documentation range.")
        }
        if isIn([0x20, 0x01, 0x00, 0x02], 4) {
            return make(host, "IPv6", .benchmark, "\(host) is in 2001:2::/48, a benchmarking range.")
        }
        if isIn([0x20, 0x01, 0x00, 0x00], 4) || isIn([0x20, 0x02], 2) {
            return make(host, "IPv6", .reserved, "\(host) is in a special-use IPv6 range (Teredo or 6to4).")
        }
        if isIn([0x00, 0x64, 0xff, 0x9b], 4) {
            return make(host, "IPv6", .reserved, "\(host) is in 64:ff9b::/96, a NAT64 translation range.")
        }
        return make(host, "IPv6", .publicInternet, "\(host) is a public IPv6 address.")
    }
}
