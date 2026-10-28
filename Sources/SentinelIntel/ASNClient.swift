import Foundation
import Darwin
import SentinelDomain

public struct ASNRecord: Sendable, Equatable {
    public var asn: String
    public var prefix: String?
    public var country: String?
    public var registry: String?
    public var description: String?
    public var fetchedAt: Date

    public init(
        asn: String,
        prefix: String? = nil,
        country: String? = nil,
        registry: String? = nil,
        description: String? = nil,
        fetchedAt: Date = Date()
    ) {
        self.asn = asn
        self.prefix = prefix
        self.country = country
        self.registry = registry
        self.description = description
        self.fetchedAt = fetchedAt
    }
}

public protocol ASNLookingUp: Sendable {
    func lookup(address: String) async -> ASNRecord?
}

/// Team Cymru's DNS service answers "which AS announces this address" without an
/// API key. It is still an external lookup, so the caller gates it behind an
/// explicit option just like RDAP.
public struct TeamCymruASNClient: ASNLookingUp, Sendable {
    private let digPath: String
    private let timeoutSeconds: Int

    public init(digPath: String = "/usr/bin/dig", timeoutSeconds: Int = 2) {
        self.digPath = digPath
        self.timeoutSeconds = timeoutSeconds
    }

    public func lookup(address: String) async -> ASNRecord? {
        guard IPClassifier.classify(address).isPublic else { return nil }
        guard let query = Self.queryName(for: address) else { return nil }
        guard let text = runTXT(query),
              let record = Self.record(fromOriginTXT: text, address: address)
        else { return nil }

        if let description = description(forASN: record.n, timeoutSeconds: timeoutSeconds, digPath: digPath) {
            return ASNRecord(
                asn: "AS\(record.n)",
                prefix: record.prefix,
                country: record.country,
                registry: record.registry,
                description: description
            )
        }
        return ASNRecord(
            asn: "AS\(record.n)",
            prefix: record.prefix,
            country: record.country,
            registry: record.registry
        )
    }

    // MARK: - DNS

    static func queryName(for address: String) -> String? {
        var v4 = in_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            let bytes = withUnsafeBytes(of: &v4) { Array($0) }
            return bytes.reversed().map(String.init).joined(separator: ".") + ".origin.asn.cymru.com"
        }

        var v6 = in6_addr()
        if inet_pton(AF_INET6, address, &v6) == 1 {
            let bytes = withUnsafeBytes(of: &v6) { Array($0) }
            let hex = bytes.map { String(format: "%02x", $0) }.joined()
            return hex.reversed().map(String.init).joined(separator: ".") + ".origin6.asn.cymru.com"
        }
        return nil
    }

    private func runTXT(_ name: String) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: digPath)
        process.arguments = ["+short", "+time=\(timeoutSeconds)", "+tries=1", "TXT", name]
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return nil
        }
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    struct OriginAnswer {
        var n: Int
        var prefix: String?
        var country: String?
        var registry: String?
    }

    static func record(fromOriginTXT text: String, address: String) -> OriginAnswer? {
        guard let line = text.split(separator: "\n").first(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty }) else {
            return nil
        }
        let fields = line
            .replacingOccurrences(of: "\"", with: "")
            .split(separator: "|", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = fields.first, let asn = Int(first), asn > 0 else { return nil }
        return OriginAnswer(
            n: asn,
            prefix: fields.count > 1 ? fields[1] : nil,
            country: fields.count > 2 ? fields[2] : nil,
            registry: fields.count > 3 ? fields[3] : nil
        )
    }

    static func description(fromASNTXT text: String) -> String? {
        guard let line = text.split(separator: "\n").first(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty }) else {
            return nil
        }
        let fields = line
            .replacingOccurrences(of: "\"", with: "")
            .split(separator: "|", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard fields.count >= 5 else { return nil }
        let description = fields[4]
        return description.isEmpty ? nil : description
    }

    private func description(forASN asn: Int, timeoutSeconds: Int, digPath: String) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: digPath)
        process.arguments = ["+short", "+time=\(timeoutSeconds)", "+tries=1", "TXT", "AS\(asn).asn.cymru.com"]
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return nil
        }
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return Self.description(fromASNTXT: String(decoding: data, as: UTF8.self))
    }
}

// MARK: - Combined enrichment

public struct IntelReport: Sendable, Equatable {
    public var rdap: RDAPRecord?
    public var asn: ASNRecord?
    public var warnings: [String]

    public init(rdap: RDAPRecord? = nil, asn: ASNRecord? = nil, warnings: [String] = []) {
        self.rdap = rdap
        self.asn = asn
        self.warnings = warnings
    }
}

public struct IntelClient: Sendable {
    private let rdap: RDAPLookingUp
    private let asn: ASNLookingUp

    public init(
        rdap: RDAPLookingUp = RDAPClient(),
        asn: ASNLookingUp = TeamCymruASNClient()
    ) {
        self.rdap = rdap
        self.asn = asn
    }

    public func enrich(
        address: String,
        includeRDAP: Bool = true,
        includeASN: Bool = true
    ) async -> IntelReport {
        let classification = IPClassifier.classify(address)
        guard classification.isPublic else {
            return IntelReport(warnings: [
                "\(address) is \(classification.scope.label), so it was not sent to an external registry."
            ])
        }

        var report = IntelReport()
        if includeRDAP {
            do {
                report.rdap = try await rdap.lookup(address: address)
            } catch {
                report.warnings.append("Registry lookup failed. \(error)")
            }
        }
        if includeASN {
            report.asn = await asn.lookup(address: address)
            if report.asn == nil {
                report.warnings.append("The ASN lookup returned no answer.")
            }
        }
        return report
    }
}
