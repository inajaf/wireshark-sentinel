import SwiftUI
import SentinelDomain

/// The detailed view of one conversation: what the packets say, what the socket
/// table says, and which of those two is speaking. Every value carries where it
/// came from, because a certificate name and a port guess must never look alike.
struct ConnectionInspector: View {
    let assessment: FlowAssessment

    @EnvironmentObject var model: SentinelModel
    @Environment(\.dismiss) private var dismiss
    @State private var options = ScanOptions.preset(.deep)
    @State private var showingBlock = false

    private var details: ConnectionDetails? {
        model.connectionDetails(for: assessment)
    }

    private var blockRecord: BlockRecord? {
        let host = assessment.key.remoteEndpoint.host
        return model.blockState.activeRecords.first { $0.target.address == host }
    }

    private var isScanning: Bool {
        model.scanningFlow == assessment.key
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    scanSettings

                    if let details {
                        report(details)
                    } else if !isScanning {
                        emptyState
                    }

                    probeSection

                    if isScanning {
                        HStack(spacing: 8) {
                            ProgressView().controlSize(.small)
                            Text("Reading the capture with Wireshark…")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                    }

                    if let error = model.scanError, details == nil {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 7))
                    }
                }
                .padding(16)
            }
            Divider()
            footer
        }
        .frame(minWidth: 660, idealWidth: 760, minHeight: 560, idealHeight: 700)
        .sheet(isPresented: $showingBlock) {
            BlockEditor(target: model.suggestedBlockTarget(for: assessment))
        }
        .task {
            if details == nil {
                await model.deepScan(assessment, options: options)
            }
        }
        .onChange(of: options.depth) { _, depth in
            guard depth != .active else { return }
            let ptr = options.resolvePTR
            let rdap = options.lookupRDAP
            let asn = options.lookupASN
            let tls = options.analyzeTLS
            let tcp = options.analyzeTCP
            options = .preset(depth)
            // A depth change is a preset, not a reason to forget an explicit
            // external-lookup consent the person already gave.
            if depth == .standard || depth == .deep {
                options.resolvePTR = ptr
                options.lookupRDAP = rdap
                options.lookupASN = asn
                options.analyzeTLS = tls
                options.analyzeTCP = tcp
            }
        }
    }

    // MARK: - Header and footer

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(assessment.identity.evidencedName ?? "Unidentified resource")
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                Text("\(assessment.key.transport.rawValue.uppercased()) \(assessment.key.remoteEndpoint.description)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                if let service = assessment.identity.serviceGuess {
                    Text("Port \(assessment.key.remote.port) looks like \(service). That is a guess, not a name.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 5) {
                Text(assessment.verdict.label)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(assessment.verdict.tint.opacity(0.18), in: Capsule())
                    .foregroundStyle(assessment.verdict.tint)
                Text(directionWord)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if blockRecord != nil {
                    Label("blocked in pf", systemImage: "hand.raised.fill")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.red)
                }
            }
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title3)
                    .foregroundStyle(.tertiary)
            }
            .buttonStyle(.plain)
            .help("Close the inspector")
        }
        .padding(16)
    }

    private var footer: some View {
        HStack(spacing: 8) {
            if isScanning {
                Text("Scanning…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if let details {
                Text("Scanned \(Self.relative.localizedString(for: details.scannedAt, relativeTo: Date()))")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }

            Spacer()

            Button {
                showingBlock = true
            } label: {
                Label("Block…", systemImage: "hand.raised")
            }
            .help("Create a pf block for this address")

            Button {
                model.focusPackets(on: assessment)
                dismiss()
            } label: {
                Label("Show packets", systemImage: "list.bullet.rectangle")
            }

            Button {
                Task { await model.deepScan(assessment, options: options) }
            } label: {
                Label("Rescan", systemImage: "arrow.clockwise")
            }
            .disabled(isScanning)

            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(12)
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No deep scan yet")
                .font(.headline)
            Text("The inspector reads this conversation out of the captured packets: TCP state, TLS handshake, certificates and application metadata. Reading the capture is local. Reverse DNS is on by default; registry and ASN lookups stay off until you turn them on below.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                Task { await model.deepScan(assessment, options: options) }
            } label: {
                Label("Scan this conversation", systemImage: "magnifyingglass")
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Scan controls

    private var scanSettings: some View {
        InspectorSection("Scan settings", subtitle: "external lookups stay off until you turn them on") {
            VStack(alignment: .leading, spacing: 8) {
                Picker("Depth", selection: $options.depth) {
                    ForEach([ScanDepth.passive, .standard, .deep], id: \.self) { depth in
                        Text(depth.title).tag(depth)
                    }
                }
                .pickerStyle(.menu)
                .font(.caption)

                Text(options.depth.summary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Toggle("Reverse DNS (PTR)", isOn: $options.resolvePTR)
                Toggle("Registry record (RDAP)", isOn: $options.lookupRDAP)
                Toggle("ASN lookup (Team Cymru DNS)", isOn: $options.lookupASN)
                Toggle("Read TLS handshake and certificates", isOn: $options.analyzeTLS)
                Toggle("Allow private and CGNAT targets", isOn: $options.includePrivate)

                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("Registry and ASN lookups send this IP address to an external service. That is why they are separate switches.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Apply and rescan") {
                        Task { await model.deepScan(assessment, options: options) }
                    }
                    .disabled(isScanning)
                }
            }
            .toggleStyle(.checkbox)
            .font(.caption)
        }
    }

    private var probeSection: some View {
        InspectorSection("Verify the service", subtitle: "sends new traffic") {
            VStack(alignment: .leading, spacing: 8) {
                Text("The scan above is passive. This probe opens one TCP connection to the observed port, records whether it answers, and closes it. Nothing is sent unless you press the button.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if let result = model.probeResults[assessment.key] {
                    probeSummary(result)
                }

                HStack(spacing: 8) {
                    Button {
                        Task { await model.runActiveProbe(assessment, options: options) }
                    } label: {
                        Label("Probe \(assessment.key.remoteEndpoint.description)", systemImage: "bolt.horizontal.circle")
                    }
                    .disabled(model.probingFlow != nil || assessment.key.transport != .tcp)

                    if model.probingFlow == assessment.key {
                        ProgressView().controlSize(.small)
                        Text("Connecting…").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                if assessment.key.transport != .tcp {
                    Text("Active probing supports TCP only.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                } else if !IPClassifier.classify(assessment.key.remoteEndpoint.host).isPublic, !options.includePrivate {
                    Text("This target is \(IPClassifier.classify(assessment.key.remoteEndpoint.host).scope.label). Turn on private targets above, or the probe will refuse it.")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    @ViewBuilder
    private func probeSummary(_ result: ActiveProbeResult) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Image(systemName: result.opened ? "checkmark.circle.fill" : "xmark.octagon.fill")
                    .foregroundStyle(result.opened ? Color.green : Color.orange)
                Text(result.opened ? "The port answered" : "No answer")
                    .font(.caption.weight(.semibold))
                if let elapsed = result.elapsed {
                    Text(String(format: "%.0f ms", elapsed * 1000))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text(result.kind.rawValue)
                    .font(.system(size: 9))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.12), in: Capsule())
                    .foregroundStyle(.secondary)
            }
            if let status = result.httpStatus {
                Text("HTTP \(status)").font(.system(.caption, design: .monospaced))
            }
            if let server = result.httpServer {
                Text("Server: \(server)").font(.caption).foregroundStyle(.secondary)
            }
            if let banner = result.banner {
                Text(banner)
                    .font(.system(.caption2, design: .monospaced))
                    .lineLimit(4)
                    .textSelection(.enabled)
            }
            if let error = result.error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(result.opened ? Color.secondary : Color.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
    }

    // MARK: - Report

    @ViewBuilder
    private func report(_ details: ConnectionDetails) -> some View {
        InspectorSection("Conversation") {
            InspectorRow("Remote address", details.network.address, source: .packets)
            InspectorRow("Direction", directionWord, source: .packets)
            InspectorRow("Transport", details.flow.transport.rawValue.uppercased(), source: .packets)
            InspectorRow("First seen", Self.date(details.firstSeen), source: .packets)
            InspectorRow("Last seen", Self.date(details.lastSeen), source: .packets)
            InspectorRow("Duration", details.duration.map(Self.seconds), source: .inferred)
            InspectorRow(
                "Sent / received",
                "\(Self.bytes(details.network.bytesSent)) / \(Self.bytes(details.network.bytesReceived))",
                source: .packets
            )
            InspectorRow(
                "Packets sent / received",
                "\(details.network.packetsSent) / \(details.network.packetsReceived)",
                source: .packets
            )
            InspectorRow("Matched frames", "\(details.packetCount)", source: .tshark)
        }

        InspectorSection("Who is on the other end") {
            InspectorRow("Address family", nonEmpty(details.network.family), source: .inferred)
            InspectorRow("Scope", nonEmpty(details.network.scope), source: .inferred)
            InspectorRow("Reverse DNS", details.network.reverseDNS, source: .dns)
            InspectorRow("Organization", details.network.organization, source: .rdap)
            InspectorRow("Network name", details.network.networkName, source: .rdap)
            InspectorRow("ASN", details.network.asn, source: .asn)
            InspectorRow("ASN description", details.network.asnDescription, source: .asn)
            InspectorRow("Registry", details.network.registry, source: .rdap)
            InspectorRow("Country", details.network.country, source: .rdap)
            InspectorRow("Abuse contact", details.network.abuseContact, source: .rdap)
            if let ttl = details.network.ttl {
                InspectorRow(
                    "TTL / estimated hops",
                    "\(ttl) / \(details.network.estimatedHops.map(String.init) ?? "unknown")",
                    source: .packets
                )
            }
            InspectorRow("Fragmentation", details.network.fragmentation, source: .packets)
            if let dscp = details.network.dscp, let ecn = details.network.ecn {
                InspectorRow("DSCP / ECN", "\(dscp) / \(ecn)", source: .packets)
            }
            InspectorRow("IPv6 flow label", details.network.ipv6FlowLabel, source: .packets)
        }

        if let tcp = details.transport.tcp {
            InspectorSection("TCP") {
                InspectorRow("State", tcp.state ?? "not in the socket table", source: .lsof)
                InspectorRow("Streams", tcp.streams.map(String.init).joined(separator: ", "), source: .tshark)
                InspectorRow("Handshake", "SYN \(tcp.synCount), SYN-ACK \(tcp.synAckCount), FIN \(tcp.finCount), RST \(tcp.rstCount)", source: .packets)
                InspectorRow("Retransmissions", "\(tcp.retransmissions) (fast \(tcp.fastRetransmissions))", source: .tshark)
                InspectorRow("Duplicate ACKs / out of order", "\(tcp.duplicateACKs) / \(tcp.outOfOrder)", source: .tshark)
                InspectorRow("Zero window / keep-alive", "\(tcp.zeroWindow) / \(tcp.keepAlives)", source: .tshark)
                InspectorRow("Initial RTT", tcp.initialRTT.map { String(format: "%.2f ms", $0 * 1000) }, source: .tshark)
                InspectorRow("Last ACK RTT", tcp.lastRTT.map { String(format: "%.2f ms", $0 * 1000) }, source: .tshark)
                InspectorRow("MSS", tcp.mss.map(String.init), source: .packets)
                InspectorRow("Window scale", tcp.windowScale.map(String.init), source: .packets)
                InspectorRow("SACK permitted", tcp.sackPermitted.map { $0 ? "yes" : "no" }, source: .packets)
                InspectorRow("Timestamps", tcp.timestamps.map { $0 ? "yes" : "no" }, source: .packets)
                InspectorRow("Completeness", tcp.completeness, source: .tshark)
            }
        }

        if let udp = details.transport.udp {
            InspectorSection("UDP") {
                InspectorRow("Streams", udp.streams.map(String.init).joined(separator: ", "), source: .tshark)
                InspectorRow("Sent / received", "\(udp.packetsSent) / \(udp.packetsReceived) packets", source: .packets)
            }
        }

        if let tls = details.tls, tls.hasEvidence {
            InspectorSection("TLS") {
                InspectorRow("Version", tls.version, source: .tshark)
                InspectorRow("Cipher suite", tls.cipherSuiteName ?? tls.cipherSuite, source: .tshark)
                InspectorRow("ALPN", tls.alpn.isEmpty ? nil : tls.alpn.joined(separator: ", "), source: .tshark)
                InspectorRow("Server name (SNI)", tls.serverName, source: .packets)
                InspectorRow("JA3", tls.ja3, source: .tshark)
                InspectorRow("JA3 full", tls.ja3Full, source: .tshark)
                InspectorRow("JA4", tls.ja4, source: .tshark)
                InspectorRow("JA4 raw", tls.ja4R, source: .tshark)
                InspectorRow("Handshake frames", tls.handshakeFrames.isEmpty ? nil : tls.handshakeFrames.map(String.init).joined(separator: ", "), source: .packets)
                InspectorRow("Supported groups", tls.supportedGroups.isEmpty ? nil : tls.supportedGroups.joined(separator: ", "), source: .tshark)
                InspectorRow("Signature algorithms", tls.signatureAlgorithms.isEmpty ? nil : tls.signatureAlgorithms.joined(separator: ", "), source: .tshark)
            }

            if !tls.certificates.isEmpty {
                InspectorSection("Certificate chain", subtitle: "\(tls.certificates.count) certificate\(tls.certificates.count == 1 ? "" : "s"), leaf first") {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(tls.certificates) { certificate in
                            CertificateCard(certificate: certificate)
                        }
                    }
                }
            }
        }

        if details.application.hasEvidence {
            InspectorSection("Application") {
                InspectorRow("Protocols", details.application.protocols.isEmpty ? nil : details.application.protocols.joined(separator: ", "), source: .tshark)
                InspectorRow("HTTP hosts", join(details.application.httpHosts), source: .packets)
                InspectorRow("HTTP methods", join(details.application.httpMethods), source: .packets)
                InspectorRow("HTTP paths", join(details.application.httpURIs), source: .packets)
                InspectorRow("HTTP status", join(details.application.httpStatusCodes), source: .packets)
                InspectorRow("HTTP server", join(details.application.httpServers), source: .packets)
                InspectorRow("User agent", join(details.application.httpUserAgents), source: .packets)
                InspectorRow("Content type", join(details.application.httpContentTypes), source: .packets)
                InspectorRow("DNS questions", join(details.application.dnsQueries), source: .packets)
                InspectorRow("DNS answers", join(details.application.dnsAnswers), source: .packets)
                InspectorRow("QUIC versions", join(details.application.quicVersions), source: .tshark)
                InspectorRow("SSH", join(details.application.sshProtocols), source: .tshark)
                InspectorRow("SSH key exchange", join(details.application.sshKeyExchange), source: .tshark)
                InspectorRow("DHCP hostnames", join(details.application.dhcpHostnames), source: .packets)
            }
        }

        if let process = details.process {
            InspectorSection("Process") {
                InspectorRow("Name", process.name, source: .process)
                InspectorRow("PID", "\(process.pid)", source: .process)
                InspectorRow("Path", process.path, source: .process)
                InspectorRow("Bundle ID", process.bundleID, source: .process)
                InspectorRow("Signature", process.signing.label, source: .process)
            }
        }

        if let socket = details.socket {
            InspectorSection("Socket") {
                InspectorRow("Command", socket.command, source: .lsof)
                InspectorRow("PID", "\(socket.pid)", source: .lsof)
                InspectorRow("UID", socket.uid.map(String.init), source: .lsof)
                InspectorRow("State", socket.state, source: .lsof)
                InspectorRow("Local", "\(socket.localAddress):\(socket.localPort)", source: .lsof)
                InspectorRow("Remote", "\(socket.remoteAddress):\(socket.remotePort)", source: .lsof)
                InspectorRow("File descriptor", socket.fileDescriptor.map(String.init), source: .lsof)
            }
        }

        if !details.warnings.isEmpty {
            InspectorSection("Scan notes") {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Array(details.warnings.enumerated()), id: \.offset) { _, warning in
                        Label(warning, systemImage: "info.circle")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }

        if let capture = details.captureFile {
            Text("Source: \(capture)")
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .textSelection(.enabled)
        }
    }

    // MARK: - Words and numbers

    private var directionWord: String {
        switch assessment.direction {
        case .inbound: return "inbound from this Mac's point of view"
        case .outbound: return "outbound from this Mac"
        case .loopback: return "loopback on this Mac"
        case .broadcast: return "broadcast by this Mac"
        case .multicast: return "multicast from this Mac"
        }
    }

    private func nonEmpty(_ value: String) -> String? {
        value.isEmpty ? nil : value
    }

    private func join(_ values: [String]) -> String? {
        values.isEmpty ? nil : values.joined(separator: ", ")
    }

    private static func date(_ value: Date?) -> String? {
        value.map { formatter.string(from: $0) }
    }

    private static func seconds(_ value: TimeInterval) -> String {
        if value < 1 { return String(format: "%.0f ms", value * 1000) }
        if value < 60 { return String(format: "%.2f s", value) }
        return String(format: "%.1f min", value / 60)
    }

    private static func bytes(_ value: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(value), countStyle: .file)
    }

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter
    }()

    private static let relative: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter
    }()
}

// MARK: - Pieces

struct InspectorSection<Content: View>: View {
    let title: String
    let subtitle: String?
    let content: Content

    init(_ title: String, subtitle: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.subtitle = subtitle
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                if let subtitle {
                    Text(subtitle)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                Spacer()
            }
            content
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                .overlay(
                    RoundedRectangle(cornerRadius: 7)
                        .stroke(Color.primary.opacity(0.08), lineWidth: 1)
                )
        }
    }
}

private struct InspectorRow: View {
    let label: String
    let value: String?
    let source: ObservationSource?

    init(_ label: String, _ value: String?, source: ObservationSource? = nil) {
        self.label = label
        self.value = value
        self.source = source
    }

    var body: some View {
        if let value, !value.isEmpty {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(minWidth: 132, alignment: .leading)
                Text(value)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 4)
                if let source {
                    Text(source.label)
                        .font(.system(size: 9))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(source.tint.opacity(0.12), in: Capsule())
                        .foregroundStyle(source.tint)
                }
            }
        }
    }
}

private struct CertificateCard: View {
    let certificate: CertificateSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Image(systemName: certificate.isCA == true ? "building.columns" : "checkmark.seal")
                    .foregroundStyle(certificate.isExpired == true ? .orange : .secondary)
                Text(certificate.commonName ?? certificate.subject ?? "certificate \(certificate.index + 1)")
                    .font(.callout.weight(.medium))
                    .lineLimit(2)
                Spacer()
                if certificate.isCA == true {
                    Tag(text: "CA", color: .secondary)
                }
                if certificate.isExpired == true {
                    Tag(text: "expired", color: .orange)
                } else if let days = certificate.daysRemaining, days <= 30 {
                    Tag(text: "expires in \(days)d", color: .orange)
                }
            }
            InspectorRow("Subject", certificate.subject, source: .certificate)
            InspectorRow("Issuer", certificate.issuer, source: .certificate)
            InspectorRow("Alternative names", certificate.subjectAlternativeNames.isEmpty ? nil : certificate.subjectAlternativeNames.joined(separator: ", "), source: .certificate)
            InspectorRow("Valid from", date(certificate.notBefore), source: .certificate)
            InspectorRow("Valid until", date(certificate.notAfter), source: .certificate)
            InspectorRow("Serial", certificate.serialNumber, source: .certificate)
            InspectorRow("Signature", certificate.signatureAlgorithm, source: .certificate)
            InspectorRow("Public key", certificate.publicKeyAlgorithm, source: .certificate)
            InspectorRow("Curve", certificate.curve, source: .certificate)
            InspectorRow("SHA-256", certificate.sha256, source: .certificate)
        }
        .padding(9)
        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
    }

    private func date(_ value: Date?) -> String? {
        guard let value else { return nil }
        return Self.formatter.string(from: value)
    }

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter
    }()
}

private struct Tag: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }
}

private extension ObservationSource {
    var tint: Color {
        switch self {
        case .packets, .tshark: return .blue
        case .certificate: return .green
        case .dns: return .teal
        case .lsof, .process: return .purple
        case .rdap: return .indigo
        case .asn: return .cyan
        case .userInput: return .primary
        case .inferred: return .secondary
        }
    }
}

private extension TLSDetails {
    var hasEvidence: Bool {
        version != nil || cipherSuite != nil || serverName != nil || ja3 != nil || ja4 != nil
            || !alpn.isEmpty || !certificates.isEmpty
    }
}

private extension ApplicationDetails {
    var hasEvidence: Bool {
        !protocols.isEmpty || !httpHosts.isEmpty || !httpMethods.isEmpty || !dnsQueries.isEmpty
            || !quicVersions.isEmpty || !sshProtocols.isEmpty || !dhcpHostnames.isEmpty
    }
}
