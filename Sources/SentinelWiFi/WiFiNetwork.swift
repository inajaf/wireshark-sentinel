import Foundation

/// The band a Wi-Fi channel belongs to. `unknown` is shown rather than guessed
/// when the driver does not report it.
public enum WiFiBand: String, Sendable, CaseIterable, Codable {
    case twoPointFour
    case five
    case six
    case unknown

    public var label: String {
        switch self {
        case .twoPointFour: return "2.4 GHz"
        case .five: return "5 GHz"
        case .six: return "6 GHz"
        case .unknown: return "unknown band"
        }
    }

    /// Channels on this band that a person can actually choose for their own
    /// access point. 5 GHz uses the non-DFS channels so a recommendation does
    /// not silently land on a radar channel.
    public var channelAdviceCandidates: [Int] {
        switch self {
        case .twoPointFour: return [1, 6, 11]
        case .five: return [36, 40, 44, 48, 149, 153, 157, 161, 165]
        case .six, .unknown: return []
        }
    }
}

public enum WiFiChannelWidth: String, Sendable, CaseIterable, Codable {
    case twenty
    case forty
    case eighty
    case oneSixty
    case unknown

    public var label: String {
        switch self {
        case .twenty: return "20 MHz"
        case .forty: return "40 MHz"
        case .eighty: return "80 MHz"
        case .oneSixty: return "160 MHz"
        case .unknown: return "unknown width"
        }
    }
}

/// The strongest security a network advertises. Mixed legacy modes are kept
/// separate so "WPA/WPA2" is not reported as plain WPA2.
public enum WiFiSecurity: String, Sendable, CaseIterable, Codable {
    case open
    case owe
    case wep
    case wpa
    case wpaMixed
    case wpa2
    case wpa3Transition
    case wpa3
    case wpaEnterprise
    case wpaEnterpriseMixed
    case wpa2Enterprise
    case wpa3Enterprise
    case unknown

    public var label: String {
        switch self {
        case .open: return "Open"
        case .owe: return "OWE (enhanced open)"
        case .wep: return "WEP"
        case .wpa: return "WPA"
        case .wpaMixed: return "WPA/WPA2"
        case .wpa2: return "WPA2"
        case .wpa3Transition: return "WPA2/WPA3"
        case .wpa3: return "WPA3"
        case .wpaEnterprise: return "WPA Enterprise"
        case .wpaEnterpriseMixed: return "WPA/WPA2 Enterprise"
        case .wpa2Enterprise: return "WPA2 Enterprise"
        case .wpa3Enterprise: return "WPA3 Enterprise"
        case .unknown: return "Unknown security"
        }
    }

    public var isOpen: Bool { self == .open }

    /// WEP and original WPA are the modes that are no longer safe to rely on.
    public var isLegacy: Bool {
        self == .wep || self == .wpa || self == .wpaMixed
            || self == .wpaEnterprise || self == .wpaEnterpriseMixed
    }

    /// A short rank used only for stable display ordering.
    public var rank: Int {
        switch self {
        case .open: return 0
        case .wep: return 1
        case .wpa: return 2
        case .wpaMixed: return 3
        case .owe: return 4
        case .wpa2: return 5
        case .wpaEnterprise: return 6
        case .wpaEnterpriseMixed: return 7
        case .wpa3Transition: return 8
        case .wpa2Enterprise: return 9
        case .wpa3: return 10
        case .wpa3Enterprise: return 11
        case .unknown: return -1
        }
    }
}

public enum WiFiSignalQuality: String, Sendable {
    case excellent
    case good
    case fair
    case weak
    case veryWeak

    public var label: String {
        switch self {
        case .excellent: return "excellent"
        case .good: return "good"
        case .fair: return "fair"
        case .weak: return "weak"
        case .veryWeak: return "very weak"
        }
    }
}

public enum WiFiSignal {
    public static func bars(for rssi: Int) -> Int {
        switch rssi {
        case (-50)...: return 4
        case (-60)...: return 3
        case (-70)...: return 2
        case (-80)...: return 1
        default: return 0
        }
    }

    public static func quality(for rssi: Int) -> WiFiSignalQuality {
        switch rssi {
        case (-50)...: return .excellent
        case (-60)...: return .good
        case (-70)...: return .fair
        case (-80)...: return .weak
        default: return .veryWeak
        }
    }
}

/// One radio, not one network name. Several access points can share an SSID;
/// see `WiFiGroup` for the name-level view.
public struct WiFiNetwork: Sendable, Identifiable, Hashable {
    public let ssid: String?
    public let bssid: String?
    public let rssi: Int
    public let noise: Int?
    public let channel: Int
    public let band: WiFiBand
    public let width: WiFiChannelWidth
    public let security: WiFiSecurity
    public let phy: String?
    public let isIBSS: Bool

    public init(
        ssid: String?,
        bssid: String? = nil,
        rssi: Int,
        noise: Int? = nil,
        channel: Int,
        band: WiFiBand = .unknown,
        width: WiFiChannelWidth = .unknown,
        security: WiFiSecurity = .unknown,
        phy: String? = nil,
        isIBSS: Bool = false
    ) {
        self.ssid = ssid
        self.bssid = bssid
        self.rssi = rssi
        self.noise = noise
        self.channel = channel
        self.band = band
        self.width = width
        self.security = security
        self.phy = phy
        self.isIBSS = isIBSS
    }

    public var id: String {
        bssid ?? "\(displayName)|\(channel)|\(rssi)"
    }

    public var displayName: String {
        guard let ssid else { return "Hidden network" }
        let trimmed = ssid.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "Hidden network" : trimmed
    }

    public var hasVisibleName: Bool {
        guard let ssid else { return false }
        return !ssid.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    public var signalBars: Int { WiFiSignal.bars(for: rssi) }
    public var quality: WiFiSignalQuality { WiFiSignal.quality(for: rssi) }

    /// Signal-to-noise ratio. Noise is a negative dBm value; zero means the
    /// driver did not report it, so no ratio is invented.
    public var snr: Int? {
        guard let noise, noise < 0, rssi < 0 else { return nil }
        return rssi - noise
    }
}

/// The result of one scan, including the current association. Nothing here is
/// persisted; the snapshot lives only in the running app.
public struct WiFiScanSnapshot: Sendable {
    public let networks: [WiFiNetwork]
    public let scannedAt: Date
    public let interfaceName: String
    public let currentSSID: String?
    public let currentBSSID: String?
    public let currentRSSI: Int?
    public let currentNoise: Int?
    public let currentChannel: Int?
    public let currentBand: WiFiBand?
    public let currentWidth: WiFiChannelWidth?
    public let currentSecurity: WiFiSecurity?
    public let currentPHY: String?

    public init(
        networks: [WiFiNetwork],
        scannedAt: Date = Date(),
        interfaceName: String,
        currentSSID: String? = nil,
        currentBSSID: String? = nil,
        currentRSSI: Int? = nil,
        currentNoise: Int? = nil,
        currentChannel: Int? = nil,
        currentBand: WiFiBand? = nil,
        currentWidth: WiFiChannelWidth? = nil,
        currentSecurity: WiFiSecurity? = nil,
        currentPHY: String? = nil
    ) {
        self.networks = networks
        self.scannedAt = scannedAt
        self.interfaceName = interfaceName
        self.currentSSID = currentSSID
        self.currentBSSID = currentBSSID
        self.currentRSSI = currentRSSI
        self.currentNoise = currentNoise
        self.currentChannel = currentChannel
        self.currentBand = currentBand
        self.currentWidth = currentWidth
        self.currentSecurity = currentSecurity
        self.currentPHY = currentPHY
    }

    /// The associated network as a value, built from the interface rather than
    /// assumed to be in the scan result. A redacted SSID can still be shown as
    /// an unnamed connection when the interface reports a channel and signal.
    public var currentNetwork: WiFiNetwork? {
        let associated = currentSSID != nil || currentBSSID != nil || (currentRSSI ?? 0) < 0
        guard associated else { return nil }
        return WiFiNetwork(
            ssid: currentSSID,
            bssid: currentBSSID,
            rssi: currentRSSI ?? 0,
            noise: currentNoise,
            channel: currentChannel ?? 0,
            band: currentBand ?? .unknown,
            width: currentWidth ?? .unknown,
            security: currentSecurity ?? .unknown,
            phy: currentPHY
        )
    }

    public var hiddenNameCount: Int {
        networks.filter { !$0.hasVisibleName }.count
    }
}
