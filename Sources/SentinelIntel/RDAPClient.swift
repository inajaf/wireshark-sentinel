import Foundation
import SentinelDomain

/// One IP registry answer. RDAP is opt-in: the address leaves this Mac only when
/// the person running the scan turns it on for that scan.
public protocol RDAPLookingUp: Sendable {
    func lookup(address: String) async throws -> RDAPRecord
}

public enum RDAPError: Error, CustomStringConvertible, Sendable {
    case notPublic(String)
    case badURL(String)
    case http(status: Int, address: String)
    case malformed(String)

    public var description: String {
        switch self {
        case .notPublic(let address):
            return "\(address) is not a public address, so it was not sent to a registry."
        case .badURL(let address):
            return "could not build a registry URL for \(address)."
        case .http(let status, let address):
            return "the registry answered HTTP \(status) for \(address)."
        case .malformed(let address):
            return "the registry answer for \(address) was not valid RDAP."
        }
    }
}

/// Uses the public RDAP redirector, which forwards to the authoritative registry
/// for the address. The final URL tells us which registry answered.
public struct RDAPClient: RDAPLookingUp, @unchecked Sendable {
    private let endpoint: String
    private let session: URLSession

    public init(
        endpoint: String = "https://rdap.org/ip/",
        session: URLSession? = nil
    ) {
        self.endpoint = endpoint
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = 8
            configuration.timeoutIntervalForResource = 12
            configuration.httpAdditionalHeaders = [
                "Accept": "application/rdap+json, application/json",
                "User-Agent": "WiresharkSentinel/1.0",
            ]
            self.session = URLSession(configuration: configuration)
        }
    }

    public func lookup(address: String) async throws -> RDAPRecord {
        let classification = IPClassifier.classify(address)
        guard classification.isPublic else {
            throw RDAPError.notPublic(address)
        }
        guard let url = URL(string: endpoint + address) else {
            throw RDAPError.badURL(address)
        }

        var request = URLRequest(url: url)
        request.setValue("application/rdap+json, application/json", forHTTPHeaderField: "Accept")
        request.setValue("WiresharkSentinel/1.0", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw RDAPError.malformed(address)
        }
        guard (200...299).contains(http.statusCode) else {
            throw RDAPError.http(status: http.statusCode, address: address)
        }
        return try Self.record(
            from: data,
            address: address,
            registry: Self.registryName(from: http.url)
        )
    }

    // MARK: - Parsing

    static func record(from data: Data, address: String, registry: String?) throws -> RDAPRecord {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw RDAPError.malformed(address)
        }

        let handle = object["handle"] as? String
        let name = object["name"] as? String
        let country = object["country"] as? String
        let entities = object["entities"] as? [[String: Any]] ?? []

        var organization: String?
        var abuseContact: String?
        var asn: String?

        for entity in entities {
            let roles = (entity["roles"] as? [String] ?? []).map { $0.lowercased() }
            if organization == nil,
               roles.contains("registrant") || roles.contains("administrative") || roles.contains("technical") {
                organization = vcardValue(entity, key: "fn")
            }
            if roles.contains("abuse") {
                abuseContact = vcardValue(entity, key: "email") ?? vcardValue(entity, key: "fn")
            }
            if asn == nil, let handle = entity["handle"] as? String,
               let number = Int(handle.uppercased().dropFirst(2)),
               handle.uppercased().hasPrefix("AS") {
                asn = "AS\(number)"
            }
        }

        if organization == nil {
            organization = entities.compactMap { vcardValue($0, key: "fn") }.first
        }

        return RDAPRecord(
            address: address,
            asn: asn,
            networkName: name,
            organization: organization,
            country: country,
            abuseContact: abuseContact,
            registry: registry,
            handle: handle
        )
    }

    private static func vcardValue(_ entity: [String: Any], key: String) -> String? {
        guard let vcard = entity["vcardArray"] as? [Any],
              vcard.count > 1,
              let entries = vcard[1] as? [[Any]]
        else { return nil }
        for entry in entries {
            guard entry.count >= 4, (entry[0] as? String) == key else { continue }
            if let value = entry[3] as? String, !value.isEmpty {
                return value
            }
            if let values = entry[3] as? [Any], let value = values.first as? String, !value.isEmpty {
                return value
            }
        }
        return nil
    }

    static func registryName(from url: URL?) -> String {
        guard let host = url?.host?.lowercased() else { return "RDAP" }
        if host.contains("arin") { return "ARIN" }
        if host.contains("ripe") { return "RIPE NCC" }
        if host.contains("apnic") { return "APNIC" }
        if host.contains("lacnic") { return "LACNIC" }
        if host.contains("afrinic") { return "AFRINIC" }
        return "RDAP"
    }
}
