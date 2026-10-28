import Foundation

/// One network name with every radio that advertises it. A mesh or a dual-band
/// router commonly appears as several BSSIDs under one SSID.
public struct WiFiGroup: Sendable, Identifiable {
    public let id: String
    public let name: String
    public let hasVisibleName: Bool
    public let networks: [WiFiNetwork]

    public init(id: String, name: String, hasVisibleName: Bool, networks: [WiFiNetwork]) {
        self.id = id
        self.name = name
        self.hasVisibleName = hasVisibleName
        self.networks = networks.sorted {
            if $0.rssi == $1.rssi {
                return ($0.bssid ?? "") < ($1.bssid ?? "")
            }
            return $0.rssi > $1.rssi
        }
    }

    public var best: WiFiNetwork? { networks.first }
    public var accessPointCount: Int { networks.count }

    public var bands: [WiFiBand] {
        let present = Set(networks.map(\.band))
        return WiFiBand.allCases.filter { present.contains($0) }
    }

    public var securities: [WiFiSecurity] {
        let present = Set(networks.map(\.security))
        return WiFiSecurity.allCases
            .filter { present.contains($0) }
            .sorted { $0.rank < $1.rank }
    }
}

public struct WiFiChannelLoad: Sendable, Identifiable, Hashable {
    public let channel: Int
    public let band: WiFiBand
    public let networkCount: Int
    public let strongestRSSI: Int?

    public init(channel: Int, band: WiFiBand, networkCount: Int, strongestRSSI: Int? = nil) {
        self.channel = channel
        self.band = band
        self.networkCount = networkCount
        self.strongestRSSI = strongestRSSI
    }

    public var id: String { "\(band.rawValue)-\(channel)" }

    /// Zero is clear, three or more is busy. Used only to pick a colour.
    public var heat: Int {
        switch networkCount {
        case 0: return 0
        case 1: return 1
        case 2: return 2
        default: return 3
        }
    }
}

public struct WiFiChannelAdvice: Sendable, Hashable {
    public let band: WiFiBand
    public let channel: Int
    public let networkCount: Int
}

public struct WiFiSecuritySummary: Sendable, Hashable {
    public let openCount: Int
    public let legacyCount: Int
    public let unknownCount: Int

    public var weakCount: Int { openCount + legacyCount }
    public var hasWeakNetworks: Bool { weakCount > 0 }
}

public enum WiFiDiagnostics {
    /// Groups a scan by name. Two radios with the same SSID become one row; a
    /// hidden network cannot be matched by name, so each radio stays separate
    /// instead of being merged into a fictitious "hidden" network.
    public static func groups(_ networks: [WiFiNetwork]) -> [WiFiGroup] {
        var order: [String] = []
        var buckets: [String: [WiFiNetwork]] = [:]

        for (index, network) in networks.enumerated() {
            let key: String
            if network.hasVisibleName {
                let name = network.displayName
                key = "ssid:\(name)"
            } else if let bssid = network.bssid, !bssid.isEmpty {
                key = "hidden:\(bssid)"
            } else {
                key = "hidden:scan:\(index)"
            }
            if buckets[key] == nil {
                order.append(key)
            }
            buckets[key, default: []].append(network)
        }

        return order.compactMap { key in
            guard let bucket = buckets[key], let first = bucket.first else { return nil }
            return WiFiGroup(
                id: key,
                name: first.displayName,
                hasVisibleName: first.hasVisibleName,
                networks: bucket
            )
        }
        .sorted {
            let left = $0.best?.rssi ?? Int.min
            let right = $1.best?.rssi ?? Int.min
            if left == right {
                return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            }
            return left > right
        }
    }

    /// Channel occupancy by primary channel. A 40/80/160 MHz network occupies
    /// more than its primary channel; this deliberately counts it once so the
    /// figure stays a readable "how many networks are advertising this channel"
    /// rather than a guess at airtime.
    public static func channelLoads(_ networks: [WiFiNetwork], band: WiFiBand) -> [WiFiChannelLoad] {
        let inBand = networks.filter { $0.band == band }
        let channels: [Int]
        switch band {
        case .twoPointFour:
            channels = Array(1...13)
        case .five, .six:
            channels = Array(Set(inBand.map(\.channel))).sorted()
        case .unknown:
            channels = []
        }

        return channels.map { channel in
            let matching = inBand.filter { $0.channel == channel }
            return WiFiChannelLoad(
                channel: channel,
                band: band,
                networkCount: matching.count,
                strongestRSSI: matching.map(\.rssi).max()
            )
        }
    }

    /// Picks a channel for the person's own access point. Only the primary
    /// channel is counted, and 5 GHz stays on non-DFS channels.
    public static func advice(_ networks: [WiFiNetwork], band: WiFiBand) -> WiFiChannelAdvice? {
        let candidates = band.channelAdviceCandidates
        guard !candidates.isEmpty else { return nil }
        let inBand = networks.filter { $0.band == band }
        guard !inBand.isEmpty else { return nil }

        let counts = candidates.map { channel in
            (channel, inBand.filter { $0.channel == channel }.count)
        }
        guard let best = counts.min(by: { $0.1 == $1.1 ? $0.0 < $1.0 : $0.1 < $1.1 }) else {
            return nil
        }
        return WiFiChannelAdvice(band: band, channel: best.0, networkCount: best.1)
    }

    public static func securitySummary(_ networks: [WiFiNetwork]) -> WiFiSecuritySummary {
        // One name should not count twice because a dual-band access point
        // advertises two radios. Use the strongest radio's security mode.
        let representatives = groups(networks).compactMap(\.best)
        return WiFiSecuritySummary(
            openCount: representatives.filter { $0.security == .open }.count,
            legacyCount: representatives.filter(\.security.isLegacy).count,
            unknownCount: representatives.filter { $0.security == .unknown }.count
        )
    }

    /// The connected radio's BSSID tells the list which group to mark. When
    /// macOS redacts the BSSID, no group is marked rather than guessing.
    public static func connectedGroupID(_ groups: [WiFiGroup], currentBSSID: String?) -> String? {
        guard let currentBSSID, !currentBSSID.isEmpty else { return nil }
        return groups.first { group in
            group.networks.contains { $0.bssid?.caseInsensitiveCompare(currentBSSID) == .orderedSame }
        }?.id
    }
}
