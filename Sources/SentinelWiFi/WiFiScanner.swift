import Foundation
import CoreWLAN

public enum WiFiScanError: LocalizedError, Sendable {
    case noInterface
    case poweredOff
    case notPermitted
    case scanFailed(String)

    public var errorDescription: String? {
        switch self {
        case .noInterface:
            return "This Mac has no Wi-Fi interface."
        case .poweredOff:
            return "Wi-Fi is off. Turn it on in Control Center, then scan again."
        case .notPermitted:
            return "macOS did not permit the Wi-Fi scan. Check Location access for Wireshark Sentinel in System Settings."
        case .scanFailed(let detail):
            return "The Wi-Fi scan failed: \(detail)"
        }
    }
}

public protocol WiFiScanning: Sendable {
    func scan(includeHidden: Bool) async throws -> WiFiScanSnapshot
}

/// Reads what the Wi-Fi adapter can hear. The scan asks access points to
/// identify themselves; it never joins a network, associates, or transmits
/// credentials. The whole operation runs off the main actor because the
/// CoreWLAN call is synchronous.
public struct SystemWiFiScanner: WiFiScanning {
    public init() {}

    public func scan(includeHidden: Bool) async throws -> WiFiScanSnapshot {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    continuation.resume(returning: try Self.read(includeHidden: includeHidden))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private static func read(includeHidden: Bool) throws -> WiFiScanSnapshot {
        guard let interface = CWWiFiClient.shared().interface() else {
            throw WiFiScanError.noInterface
        }
        guard interface.powerOn() else {
            throw WiFiScanError.poweredOff
        }

        let scanned: Set<CWNetwork>
        do {
            scanned = try interface.scanForNetworks(withSSID: nil, includeHidden: includeHidden)
        } catch {
            let ns = error as NSError
            if ns.code == -3930 {
                throw WiFiScanError.notPermitted
            }
            throw WiFiScanError.scanFailed(error.localizedDescription)
        }

        let networks = dedupe(scanned.map(network(from:)))
            .sorted {
                if $0.rssi == $1.rssi {
                    return $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
                }
                return $0.rssi > $1.rssi
            }

        let channel = interface.wlanChannel()
        let noise = interface.noiseMeasurement()

        return WiFiScanSnapshot(
            networks: networks,
            interfaceName: interface.interfaceName ?? "Wi-Fi",
            currentSSID: interface.ssid(),
            currentBSSID: interface.bssid(),
            currentRSSI: interface.rssiValue(),
            currentNoise: noise < 0 ? noise : nil,
            currentChannel: channel?.channelNumber,
            currentBand: band(from: channel),
            currentWidth: width(from: channel),
            currentSecurity: security(from: interface.security()),
            currentPHY: phy(from: interface.activePHYMode())
        )
    }

    /// CoreWLAN occasionally returns the same radio more than once in one
    /// scan. A BSSID is the radio's identity, so keep the strongest report and
    /// drop the copies. Entries without a BSSID cannot be compared safely and
    /// are kept, because two hidden radios may be genuinely different.
    static func dedupe(_ networks: [WiFiNetwork]) -> [WiFiNetwork] {
        var byBSSID: [String: WiFiNetwork] = [:]
        var anonymous: [WiFiNetwork] = []

        for network in networks {
            guard let bssid = network.bssid?.lowercased(), !bssid.isEmpty else {
                anonymous.append(network)
                continue
            }
            if let existing = byBSSID[bssid] {
                if network.rssi > existing.rssi {
                    byBSSID[bssid] = network
                }
            } else {
                byBSSID[bssid] = network
            }
        }

        return Array(byBSSID.values) + anonymous
    }

    private static func network(from network: CWNetwork) -> WiFiNetwork {
        let channel = network.wlanChannel
        let noise = network.noiseMeasurement
        return WiFiNetwork(
            ssid: network.ssid,
            bssid: network.bssid,
            rssi: network.rssiValue,
            noise: noise < 0 ? noise : nil,
            channel: channel?.channelNumber ?? 0,
            band: band(from: channel),
            width: width(from: channel),
            security: security(of: network),
            phy: phy(of: network),
            isIBSS: network.ibss
        )
    }

    private static func band(from channel: CWChannel?) -> WiFiBand {
        guard let channel else { return .unknown }
        switch channel.channelBand {
        case .band2GHz: return .twoPointFour
        case .band5GHz: return .five
        case .band6GHz: return .six
        case .bandUnknown: return .unknown
        @unknown default: return .unknown
        }
    }

    private static func width(from channel: CWChannel?) -> WiFiChannelWidth {
        guard let channel else { return .unknown }
        switch channel.channelWidth {
        case .width20MHz: return .twenty
        case .width40MHz: return .forty
        case .width80MHz: return .eighty
        case .width160MHz: return .oneSixty
        case .widthUnknown: return .unknown
        @unknown default: return .unknown
        }
    }

    /// Checks the strongest known mode first. A network that advertises WPA3
    /// and WPA2 is reported as WPA3, because that is what a modern client uses.
    private static func security(of network: CWNetwork) -> WiFiSecurity {
        let candidates: [(CWSecurity, WiFiSecurity)] = [
            (.wpa3Enterprise, .wpa3Enterprise),
            (.wpa3Personal, .wpa3),
            (.wpa3Transition, .wpa3Transition),
            (.wpa2Enterprise, .wpa2Enterprise),
            (.enterprise, .wpa2Enterprise),
            (.wpa2Personal, .wpa2),
            (.personal, .wpa2),
            (.wpaEnterpriseMixed, .wpaEnterpriseMixed),
            (.wpaEnterprise, .wpaEnterprise),
            (.wpaPersonalMixed, .wpaMixed),
            (.wpaPersonal, .wpa),
            (.dynamicWEP, .wep),
            (.WEP, .wep),
            (.OWE, .owe),
            (.oweTransition, .owe),
        ]
        for (coreWLAN, reported) in candidates where network.supportsSecurity(coreWLAN) {
            return reported
        }
        if network.supportsSecurity(.none) { return .open }
        return .unknown
    }

    private static func security(from value: CWSecurity) -> WiFiSecurity {
        switch value {
        case .none: return .open
        case .WEP, .dynamicWEP: return .wep
        case .wpaPersonal: return .wpa
        case .wpaPersonalMixed: return .wpaMixed
        case .wpa2Personal, .personal: return .wpa2
        case .wpa3Personal: return .wpa3
        case .wpa3Transition: return .wpa3Transition
        case .wpaEnterprise: return .wpaEnterprise
        case .wpaEnterpriseMixed: return .wpaEnterpriseMixed
        case .wpa2Enterprise, .enterprise: return .wpa2Enterprise
        case .wpa3Enterprise: return .wpa3Enterprise
        case .OWE, .oweTransition: return .owe
        case .unknown: return .unknown
        @unknown default: return .unknown
        }
    }

    private static func phy(of network: CWNetwork) -> String? {
        let modes: [CWPHYMode] = [.mode11be, .mode11ax, .mode11ac, .mode11n, .mode11g, .mode11a, .mode11b]
        for mode in modes where network.supportsPHYMode(mode) {
            return label(for: mode)
        }
        return nil
    }

    private static func phy(from mode: CWPHYMode) -> String? {
        mode == .modeNone ? nil : label(for: mode)
    }

    private static func label(for mode: CWPHYMode) -> String {
        switch mode {
        case .mode11be: return "802.11be (Wi-Fi 7)"
        case .mode11ax: return "802.11ax (Wi-Fi 6)"
        case .mode11ac: return "802.11ac (Wi-Fi 5)"
        case .mode11n: return "802.11n (Wi-Fi 4)"
        case .mode11a: return "802.11a"
        case .mode11b: return "802.11b"
        case .mode11g: return "802.11g"
        case .modeNone: return "unknown"
        @unknown default: return "unknown"
        }
    }
}
