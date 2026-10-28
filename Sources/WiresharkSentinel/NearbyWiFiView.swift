import SwiftUI
import CoreLocation
import SentinelWiFi

/// Lists what the Wi-Fi adapter can hear: names, radios, channels and security.
/// Opening the sheet sends nothing; the Scan button is the only action that
/// touches the radio, and it never joins a network.
struct NearbyWiFiView: View {
    @ObservedObject var model: NearbyWiFiModel
    @Environment(\.dismiss) private var dismiss

    private var snapshot: WiFiScanSnapshot? { model.snapshot }
    private var groups: [WiFiGroup] { WiFiDiagnostics.groups(snapshot?.networks ?? []) }
    private var connectedGroupID: String? {
        guard let snapshot else { return nil }
        return WiFiDiagnostics.connectedGroupID(groups, currentBSSID: snapshot.currentBSSID)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let error = model.errorMessage {
                        errorBanner(error)
                    }
                    permissionBanner

                    if model.isScanning && snapshot == nil {
                        scanningState
                    } else if let snapshot {
                        if model.isScanning {
                            progressRow
                        }
                        connectedSection(snapshot)
                        nearbySection
                        channelSection(snapshot)
                        securitySection(snapshot)
                    } else if !model.isScanning {
                        welcomeState
                    }

                    boundaryNote
                }
                .padding(16)
            }
            Divider()
            footer
        }
        .frame(minWidth: 760, idealWidth: 880, minHeight: 580, idealHeight: 720)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Header and footer

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "wifi")
                .font(.title2)
                .foregroundStyle(.tint)
                .frame(width: 30)

            VStack(alignment: .leading, spacing: 4) {
                Text("Nearby Wi-Fi")
                    .font(.title3.weight(.semibold))
                Text("Read-only scan of the networks this Mac can hear. Nothing is joined.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let snapshot {
                    Text("\(snapshot.networks.count) radios · \(snapshot.interfaceName) · scanned \(Self.age(snapshot.scannedAt))")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }

            Spacer()

            Button {
                model.scan()
            } label: {
                Label(snapshot == nil ? "Scan" : "Rescan", systemImage: "arrow.clockwise")
            }
            .disabled(model.isScanning)

            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title3)
                    .foregroundStyle(.tertiary)
            }
            .buttonStyle(.plain)
            .help("Close the Wi-Fi view")
        }
        .padding(16)
    }

    private var footer: some View {
        HStack(spacing: 8) {
            if let snapshot {
                Text("Last scan \(Self.age(snapshot.scannedAt)). Results stay in memory and are not written to the report.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(2)
            }
            Spacer()
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(12)
    }

    // MARK: - States

    private var welcomeState: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "wifi")
                    .font(.title2)
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Scan nearby networks")
                        .font(.headline)
                    Text("One scan asks nearby access points to identify themselves. It does not join a network or send credentials.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Text("macOS asks for Location access during the first scan so the network names are not redacted. Signal, channel and security are shown even if access is declined.")
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                model.scan()
            } label: {
                Label("Scan nearby networks", systemImage: "wifi")
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private var scanningState: some View {
        HStack(spacing: 10) {
            ProgressView().controlSize(.small)
            VStack(alignment: .leading, spacing: 2) {
                Text("Scanning the Wi-Fi channels")
                    .font(.headline)
                Text("The radio is asking nearby access points to identify themselves. This can take a few seconds.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private var progressRow: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text("Rescanning; the previous results stay below until the new scan finishes.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
    }

    @ViewBuilder
    private var permissionBanner: some View {
        if model.authorization == .notDetermined {
            banner(
                icon: "location",
                tint: .blue,
                title: "Location access is not decided yet",
                message: "macOS hides Wi-Fi names until this app is allowed to use Location. The prompt appears when you scan, and names are redacted if it is declined.",
                actionTitle: "Allow Location Access"
            ) {
                model.requestLocationAccess()
            }
        } else if model.isPermissionDenied {
            banner(
                icon: "location.slash",
                tint: .orange,
                title: "Network names are hidden by macOS",
                message: "Location access is off, so SSIDs and BSSIDs are redacted. Signal, channel, width and security are still shown. Turn Location access on for Wireshark Sentinel to see the names.",
                actionTitle: "Open Location Settings"
            ) {
                model.openLocationSettings()
            }
        }
    }

    private func banner(
        icon: String,
        tint: Color,
        title: String,
        message: String,
        actionTitle: String? = nil,
        action: (() -> Void)? = nil
    ) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.callout.weight(.semibold))
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let actionTitle, let action {
                    Button(actionTitle, action: action)
                        .controlSize(.small)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
    }

    private func errorBanner(_ message: String) -> some View {
        banner(
            icon: "exclamationmark.triangle",
            tint: .orange,
            title: "Wi-Fi scan failed",
            message: message,
            actionTitle: "Try again"
        ) {
            model.scan()
        }
    }

    // MARK: - Connected

    private func connectedSection(_ snapshot: WiFiScanSnapshot) -> some View {
        InspectorSection("Connected", subtitle: "the network this Mac is using now") {
            if let current = snapshot.currentNetwork {
                HStack(alignment: .top, spacing: 10) {
                    SignalBarsView(bars: current.signalBars)
                        .padding(.top, 2)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(connectedName(current))
                                .font(.callout.weight(.semibold))
                            WiFiTag(text: current.security.label, tint: current.security.tint)
                            if !current.hasVisibleName && !model.isAuthorized {
                                WiFiTag(text: "name hidden by macOS", tint: .orange)
                            }
                        }
                        HStack(spacing: 10) {
                            Text("\(current.rssi) dBm")
                            if let snr = current.snr { Text("SNR \(snr) dB") }
                            if current.channel > 0 { Text("ch \(current.channel) · \(current.band.label)") }
                            if current.width != .unknown { Text(current.width.label) }
                            if let phy = current.phy { Text(phy) }
                        }
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        if let bssid = current.bssid {
                            Text(bssid)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.tertiary)
                                .textSelection(.enabled)
                        }
                    }
                    Spacer(minLength: 0)
                }
            } else {
                Text("No Wi-Fi association. The Mac may be using Ethernet, or Wi-Fi may be off.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func connectedName(_ network: WiFiNetwork) -> String {
        if network.hasVisibleName { return network.displayName }
        return model.isAuthorized ? "Hidden network" : "Connected network"
    }

    // MARK: - Nearby

    private var nearbySection: some View {
        InspectorSection(
            "Nearby",
            subtitle: groups.isEmpty
                ? "no networks in range"
                : "\(groups.count) names · \(snapshot?.networks.count ?? 0) radios"
        ) {
            if groups.isEmpty {
                Text("The scan found no networks. Wi-Fi may be off, or the radio may be busy.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                VStack(spacing: 6) {
                    ForEach(groups) { group in
                        NearbyGroupRow(
                            group: group,
                            isConnected: group.id == connectedGroupID,
                            namesRedacted: !model.isAuthorized
                        )
                    }
                }
            }
        }
    }

    // MARK: - Channels

    private func channelSection(_ snapshot: WiFiScanSnapshot) -> some View {
        let two = WiFiDiagnostics.channelLoads(snapshot.networks, band: .twoPointFour)
        let five = WiFiDiagnostics.channelLoads(snapshot.networks, band: .five)
        let six = WiFiDiagnostics.channelLoads(snapshot.networks, band: .six)
        let hasTwo = two.contains { $0.networkCount > 0 }
        let hasFive = !five.isEmpty
        let hasSix = !six.isEmpty

        return InspectorSection("Channel occupancy", subtitle: "primary channel, for your own access point") {
            VStack(alignment: .leading, spacing: 12) {
                if !hasTwo && !hasFive && !hasSix {
                    Text("No channel data to compare. Scan while at least one network is in range.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if hasTwo {
                    channelBand(.twoPointFour, loads: two, networks: snapshot.networks)
                }
                if hasFive {
                    channelBand(.five, loads: five, networks: snapshot.networks)
                }
                if hasSix {
                    channelBand(.six, loads: six, networks: snapshot.networks)
                }
                Text("A 40, 80 or 160 MHz network occupies more than its primary channel, so this is a count of advertising networks, not an airtime measurement.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func channelBand(_ band: WiFiBand, loads: [WiFiChannelLoad], networks: [WiFiNetwork]) -> some View {
        let advice = WiFiDiagnostics.advice(networks, band: band)
        var display = loads
        if let advice, !display.contains(where: { $0.channel == advice.channel }) {
            display.append(WiFiChannelLoad(channel: advice.channel, band: band, networkCount: 0))
            display.sort { $0.channel < $1.channel }
        }
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(band.label)
                    .font(.caption.weight(.semibold))
                if let advice {
                    Text(advice.networkCount == 0
                         ? "channel \(advice.channel) is clear"
                         : "least used: channel \(advice.channel) (\(advice.networkCount) nearby)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 48), spacing: 4)],
                alignment: .leading,
                spacing: 4
            ) {
                ForEach(display) { load in
                    VStack(spacing: 1) {
                        Text("\(load.channel)")
                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                        Text("\(load.networkCount)")
                            .font(.system(size: 9, design: .monospaced))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 3)
                    .background(
                        heatColor(load.heat).opacity(load.networkCount == 0 ? 0.06 : 0.18),
                        in: RoundedRectangle(cornerRadius: 4)
                    )
                    .accessibilityLabel("Channel \(load.channel), \(load.networkCount) networks")
                }
            }
        }
    }

    private func heatColor(_ heat: Int) -> Color {
        switch heat {
        case 0: return .secondary
        case 1: return .green
        case 2: return .yellow
        default: return .orange
        }
    }

    // MARK: - Security

    private func securitySection(_ snapshot: WiFiScanSnapshot) -> some View {
        let summary = WiFiDiagnostics.securitySummary(snapshot.networks)
        return InspectorSection("Security in range", subtitle: "observation only") {
            VStack(alignment: .leading, spacing: 6) {
                if summary.weakCount == 0 && summary.unknownCount == 0 {
                    Label("No open, WEP or original WPA networks were seen.", systemImage: "checkmark.shield")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    if summary.openCount > 0 {
                        securityLine(
                            "\(summary.openCount) open \(summary.openCount == 1 ? "network" : "networks") can be joined by anyone in range.",
                            tint: .red
                        )
                    }
                    if summary.legacyCount > 0 {
                        securityLine(
                            "\(summary.legacyCount) \(summary.legacyCount == 1 ? "network uses" : "networks use") WEP or original WPA, which are no longer safe.",
                            tint: .orange
                        )
                    }
                    if summary.unknownCount > 0 {
                        securityLine(
                            "\(summary.unknownCount) \(summary.unknownCount == 1 ? "network reported" : "networks reported") an unknown security mode.",
                            tint: .secondary
                        )
                    }
                    Text("Sentinel lists these networks only. It does not join them or test their credentials.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func securityLine(_ text: String, tint: Color) -> some View {
        Label(text, systemImage: "exclamationmark.shield")
            .font(.caption)
            .foregroundStyle(tint)
            .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: - Boundary

    private var boundaryNote: some View {
        Label(
            "This view only lists networks this Mac's adapter can hear. It never joins a network, captures a handshake, sends deauthentication, or tries a password.",
            systemImage: "lock.shield"
        )
        .font(.caption2)
        .foregroundStyle(.tertiary)
        .fixedSize(horizontal: false, vertical: true)
    }

    private static let relative: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter
    }()

    private static func age(_ date: Date) -> String {
        let seconds = max(0, Date().timeIntervalSince(date))
        if seconds < 5 { return "just now" }
        if seconds < 60 { return "\(Int(seconds)) seconds ago" }
        return relative.localizedString(for: date, relativeTo: Date())
    }
}

// MARK: - Rows

private struct NearbyGroupRow: View {
    let group: WiFiGroup
    let isConnected: Bool
    let namesRedacted: Bool

    @State private var expanded = false

    private var best: WiFiNetwork? { group.best }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                guard group.accessPointCount > 1 else { return }
                expanded.toggle()
            } label: {
                HStack(alignment: .center, spacing: 10) {
                    SignalBarsView(bars: best?.signalBars ?? 0)

                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text(group.name)
                                .font(.callout.weight(.medium))
                                .lineLimit(1)
                            if isConnected {
                                WiFiTag(text: "connected", tint: .blue)
                            }
                            if !group.hasVisibleName {
                                WiFiTag(
                                    text: namesRedacted ? "name hidden by macOS" : "hidden SSID",
                                    tint: .secondary
                                )
                            }
                            ForEach(group.securities, id: \.self) { security in
                                WiFiTag(text: security.label, tint: security.tint)
                            }
                        }

                        HStack(spacing: 10) {
                            if let best {
                                Text("\(best.rssi) dBm")
                                Text(best.quality.label)
                                if best.channel > 0 {
                                    Text("ch \(best.channel) · \(best.band.label)")
                                }
                                if best.width != .unknown {
                                    Text(best.width.label)
                                }
                            }
                            if group.accessPointCount > 1 {
                                Text("\(group.accessPointCount) access points")
                            }
                            if group.bands.count > 1 {
                                Text(group.bands.map(\.label).joined(separator: " + "))
                            }
                        }
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    }

                    Spacer(minLength: 4)

                    if group.accessPointCount > 1 {
                        Image(systemName: expanded ? "chevron.up" : "chevron.down")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(8)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(spacing: 4) {
                    ForEach(Array(group.networks.enumerated()), id: \.offset) { _, network in
                        radioRow(network)
                    }
                }
                .padding(.leading, 28)
                .padding(.trailing, 8)
                .padding(.bottom, 8)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .stroke(Color.primary.opacity(0.06), lineWidth: 1)
        )
    }

    private func radioRow(_ network: WiFiNetwork) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(network.bssid ?? "BSSID hidden")
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            Text("\(network.rssi) dBm")
                .font(.caption2.monospacedDigit())
            if network.channel > 0 {
                Text("ch \(network.channel)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            if let phy = network.phy {
                Text(phy)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 2)
    }
}

private struct SignalBarsView: View {
    let bars: Int

    private var tint: Color {
        switch bars {
        case 4, 3: return .green
        case 2: return .yellow
        case 1: return .orange
        default: return .red
        }
    }

    var body: some View {
        HStack(alignment: .bottom, spacing: 2) {
            ForEach(0..<4, id: \.self) { index in
                RoundedRectangle(cornerRadius: 1)
                    .fill(index < bars ? tint : Color.secondary.opacity(0.18))
                    .frame(width: 3, height: CGFloat(4 + index * 3))
            }
        }
        .frame(width: 18, height: 14, alignment: .bottom)
        .accessibilityLabel("Signal \(bars) of 4 bars")
    }
}

private struct WiFiTag: View {
    let text: String
    let tint: Color

    var body: some View {
        Text(text)
            .font(.system(size: 9, weight: .semibold))
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(tint.opacity(0.14), in: Capsule())
            .foregroundStyle(tint)
    }
}

private extension WiFiSecurity {
    var tint: Color {
        switch self {
        case .open, .wep: return .red
        case .wpa, .wpaMixed, .wpaEnterprise, .wpaEnterpriseMixed: return .orange
        case .owe, .wpa2: return .green
        case .wpa3Transition: return .teal
        case .wpa3, .wpa2Enterprise, .wpa3Enterprise: return .blue
        case .unknown: return .secondary
        }
    }
}
