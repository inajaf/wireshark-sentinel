import SwiftUI
import SentinelDomain
import SentinelPath

/// The selected conversation as one path: the local process, its socket, the
/// gateway, every hop a trace found, and the service at the end. Trace and ping
/// are buttons here; opening the graph never sends a packet.
struct ConnectionGraphView: View {
    @EnvironmentObject var model: SentinelModel
    @Environment(\.dismiss) private var dismiss

    let assessment: FlowAssessment
    let options: ScanOptions

    private var key: FlowKey { assessment.key }
    private var path: ConnectionPath? { model.pathMaps[key] }
    private var isLoading: Bool { model.scanningFlow == key || model.pathBuildFlow == key }
    private var isProbing: Bool { model.tracingFlow != nil || model.pingingFlow != nil }
    private var probeProblem: String? {
        PathProbeSafety.problem(
            for: assessment.key.remoteEndpoint.host,
            localAddresses: model.blockLocalAddresses,
            broadcastAddresses: model.blockBroadcastAddresses
        )
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let error = model.pathError {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 7))
                    }

                    if isLoading, path == nil {
                        loadingState
                    } else if let path {
                        if isLoading {
                            HStack(spacing: 8) {
                                ProgressView().controlSize(.small)
                                Text(model.scanningFlow == key
                                     ? "Reading the capture before building the path…"
                                     : "Rebuilding the local route…")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                        }
                        routeRail(path)
                        probeSection(path)
                        namesSection(path)
                        serviceSection(path)
                        notesSection(path)
                        Text("Path built \(Self.relative.localizedString(for: path.builtAt, relativeTo: Date())). The gateway and hops are routing evidence; a hop that does not answer is left as a gap rather than filled in.")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else if !isLoading {
                        unavailableState
                    }
                }
                .padding(16)
            }
            Divider()
            footer
        }
        .frame(minWidth: 700, idealWidth: 800, minHeight: 560, idealHeight: 700)
        .task {
            await model.loadPath(assessment, options: options)
        }
        .onAppear {
            model.pathError = nil
        }
    }

    // MARK: - Header and footer

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "arrow.triangle.branch")
                .font(.title2)
                .foregroundStyle(.tint)
                .frame(width: 30)

            VStack(alignment: .leading, spacing: 4) {
                Text("Path to \(path?.bestName ?? assessment.key.remoteEndpoint.host)")
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                Text("\(assessment.key.transport.rawValue.uppercased()) \(assessment.key.remoteEndpoint.description)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                Text("Process → local socket → gateway → hops → service. Passive until you press an active check.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title3)
                    .foregroundStyle(.tertiary)
            }
            .buttonStyle(.plain)
            .help("Close the path map")
        }
        .padding(16)
    }

    private var footer: some View {
        HStack(spacing: 8) {
            if isProbing {
                ProgressView().controlSize(.small)
                Text(model.tracingFlow == key ? "Tracing…" : "Pinging…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if model.pathBuildFlow == key {
                Text("Building the path…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button {
                model.focusPackets(on: assessment)
                dismiss()
            } label: {
                Label("Show packets", systemImage: "list.bullet.rectangle")
            }

            Button {
                Task { await model.loadPath(assessment, options: options) }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(isLoading || isProbing)

            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(12)
    }

    // MARK: - States

    private var loadingState: some View {
        HStack(spacing: 10) {
            ProgressView().controlSize(.small)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.scanningFlow == key ? "Reading this conversation from the capture" : "Reading the system route")
                    .font(.headline)
                Text("The path is passive. Traceroute and ping do not start until you press their buttons.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private var unavailableState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No path yet")
                .font(.headline)
            Text("The path needs the deep scan to collect names, certificates and the socket. Nothing is sent to the network by building it.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                Task { await model.loadPath(assessment, options: options) }
            } label: {
                Label("Build the path", systemImage: "arrow.triangle.branch")
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    // MARK: - Rail

    private func routeRail(_ path: ConnectionPath) -> some View {
        InspectorSection("Path", subtitle: "from this Mac to the selected service") {
            VStack(alignment: .leading, spacing: 0) {
                processNode(path)
                connector

                localNode(path)
                connector

                routeNode(path)

                if let trace = path.trace {
                    if path.transitHops.isEmpty {
                        connector
                        PathNodeRow(
                            icon: "arrow.right",
                            tint: .secondary,
                            title: trace.reachedDestination ? "No intermediate hops" : "No transit hop answered",
                            subtitle: trace.reachedDestination
                                ? "The destination answered directly at hop \(trace.hops.first?.index ?? 1)."
                                : "The trace produced no hop between this Mac and the service."
                        ) {
                            EmptyView()
                        }
                    } else {
                        ForEach(path.transitHops) { hop in
                            connector
                            hopNode(hop)
                        }
                    }
                } else {
                    connector
                    PathNodeRow(
                        icon: "questionmark",
                        tint: .secondary,
                        title: "Transit not traced",
                        subtitle: "Run Trace route to fill in the routers between this Mac and the service. It sends probe packets."
                    ) {
                        EmptyView()
                    }
                }

                connector
                serviceNode(path)
            }
        }
    }

    private func processNode(_ path: ConnectionPath) -> some View {
        PathNodeRow(
            icon: "app.fill",
            tint: .purple,
            title: path.local.processName ?? "Local process not attributed",
            subtitle: path.local.processName == nil
                ? "The capture has no matching open socket or process entry."
                : "Process on this Mac"
        ) {
            PathFacts(facts: [
                ("PID", path.local.pid.map(String.init)),
                ("Signature", path.local.signing?.label),
                ("Direction", direction(path.local.direction)),
            ])
        }
    }

    private func localNode(_ path: ConnectionPath) -> some View {
        PathNodeRow(
            icon: "cable.connector",
            tint: .blue,
            title: "Local socket",
            subtitle: "\(path.local.address):\(path.local.port)"
        ) {
            PathFacts(facts: [
                ("Interface", path.local.interfaceName),
                ("Transport", path.flow.transport.rawValue.uppercased()),
                ("State", path.local.socketState),
            ])
        }
    }

    private func routeNode(_ path: ConnectionPath) -> some View {
        if let route = path.route, let gateway = route.gateway {
            return AnyView(PathNodeRow(
                icon: "network",
                tint: .teal,
                title: "Gateway \(gateway)",
                subtitle: route.interfaceName.map { "via \($0)" } ?? "Next hop from the routing table"
            ) {
                PathFacts(facts: [("Route", route.destination)])
            })
        } else if let route = path.route {
            return AnyView(PathNodeRow(
                icon: "arrow.right",
                tint: .teal,
                title: "Direct route",
                subtitle: route.interfaceName.map { "on \($0)" } ?? "The destination is on this link"
            ) {
                PathFacts(facts: [("Route", route.destination)])
            })
        } else {
            return AnyView(PathNodeRow(
                icon: "questionmark",
                tint: .secondary,
                title: "Route unavailable",
                subtitle: "The system routing table did not return a next hop."
            ) {
                EmptyView()
            })
        }
    }

    private func hopNode(_ hop: PathHop) -> some View {
        PathNodeRow(
            icon: "circle.dotted",
            tint: hop.address == nil ? .secondary : .indigo,
            title: hop.address.map { "Hop \(hop.index) · \($0)" } ?? "Hop \(hop.index) · no reply",
            subtitle: hop.note ?? (hop.address == nil ? "The router did not answer this probe." : hop.scope.label)
        ) {
            PathFacts(facts: [
                ("Address", hop.address),
                ("RTT", hop.rttMilliseconds.map { String(format: "%.1f ms", $0) }),
                ("Scope", hop.address == nil ? nil : hop.scope.label),
            ])
        }
    }

    private func serviceNode(_ path: ConnectionPath) -> some View {
        PathNodeRow(
            icon: "server.rack",
            tint: .green,
            title: path.bestName ?? path.remote.address,
            subtitle: "\(path.remote.transport.rawValue.uppercased()) \(path.remote.address):\(path.remote.port) · \(path.remote.scope.label)",
            emphasized: true
        ) {
            PathFacts(facts: [
                ("Service guess", path.remote.serviceGuess),
                ("ASN", [path.remote.asn, path.remote.asnDescription].compactMap { $0 }.joined(separator: " · ")),
                ("Organization", path.remote.organization ?? path.remote.networkName),
                ("Observed", path.remote.observedProtocols.isEmpty ? nil : path.remote.observedProtocols.joined(separator: ", ")),
                ("TTL / hops", path.remote.ttl.map { "\($0) / \(path.remote.estimatedHops.map(String.init) ?? "unknown")" }),
            ])
        }
    }

    private var connector: some View {
        HStack(spacing: 0) {
            Rectangle()
                .fill(Color.secondary.opacity(0.25))
                .frame(width: 2, height: 14)
                .padding(.leading, 9)
            Spacer()
        }
    }

    // MARK: - Active checks

    private func probeSection(_ path: ConnectionPath) -> some View {
        InspectorSection("Active checks", subtitle: "send new packets only when pressed") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Opening this path is passive. Ping sends one ICMP echo and then asks reverse DNS for a name. Trace sends traceroute probes and records the routers that answer. Neither runs by itself.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if let probeProblem {
                    Label(probeProblem, systemImage: "nosign")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }

                HStack(spacing: 8) {
                    Button {
                        Task { await model.pingRemote(for: assessment) }
                    } label: {
                        Label("Ping & resolve", systemImage: "waveform.path.ecg")
                    }
                    .disabled(isProbing || isLoading || probeProblem != nil)
                    .help("Send one ICMP echo and try to find a domain name for this address")

                    if model.pingingFlow == key {
                        ProgressView().controlSize(.small)
                        Text("Waiting for a reply…").font(.caption).foregroundStyle(.secondary)
                    }

                    Button {
                        Task { await model.traceRoute(for: assessment) }
                    } label: {
                        Label("Trace route", systemImage: "point.3.connected.trianglepath.dotted")
                    }
                    .disabled(isProbing || isLoading || probeProblem != nil)
                    .help("Send traceroute probes and add the answering hops to this path")

                    if model.tracingFlow == key {
                        ProgressView().controlSize(.small)
                        Text("Tracing…").font(.caption).foregroundStyle(.secondary)
                    }

                    Spacer()
                }

                if let ping = path.ping {
                    pingCard(ping)
                }
                if let trace = path.trace {
                    traceCard(trace)
                }
            }
        }
    }

    private func pingCard(_ ping: PingResult) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Image(systemName: ping.responded ? "checkmark.circle.fill" : "xmark.octagon.fill")
                    .foregroundStyle(ping.responded ? Color.green : Color.orange)
                Text(ping.responded ? "ICMP reply" : "No ICMP reply")
                    .font(.caption.weight(.semibold))
                if let rtt = ping.rttMilliseconds {
                    Text(String(format: "%.1f ms", rtt))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Spacer()
                PathTag(text: ping.method, color: ping.hostname == nil ? .secondary : .teal)
            }

            if let hostname = ping.hostname {
                Text("Name: \(hostname)")
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            } else {
                Text("No domain name was returned for this address.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }

            if let loss = ping.packetLossPercent {
                Text(String(format: "Packet loss %.1f%%", loss))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            if let error = ping.error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(ping.responded ? Color.secondary : Color.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text("\(ping.command) · \(Self.time.string(from: ping.ranAt))")
                .font(.system(size: 9, design: .monospaced))
                .foregroundStyle(.tertiary)
                .textSelection(.enabled)
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
    }

    private func traceCard(_ trace: PathTrace) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Image(systemName: trace.reachedDestination ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(trace.reachedDestination ? Color.green : Color.orange)
                Text(trace.reachedDestination
                     ? "Destination answered at hop \(trace.hops.last?.index ?? 0)"
                     : (trace.error == nil ? "Partial path" : "Trace failed"))
                    .font(.caption.weight(.semibold))
                Spacer()
                Text("\(trace.hops.count) hop\(trace.hops.count == 1 ? "" : "s")")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            ForEach(Array(trace.warnings.enumerated()), id: \.offset) { _, warning in
                Text(warning)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error = trace.error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text("\(trace.command) · \(Self.time.string(from: trace.ranAt))")
                .font(.system(size: 9, design: .monospaced))
                .foregroundStyle(.tertiary)
                .textSelection(.enabled)
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
    }

    // MARK: - Evidence

    private func namesSection(_ path: ConnectionPath) -> some View {
        InspectorSection("Names", subtitle: path.names.isEmpty ? "no captured name" : "\(path.names.count) distinct name\(path.names.count == 1 ? "" : "s")") {
            if path.names.isEmpty {
                Text("The capture did not contain SNI, a certificate name, an HTTP Host or a DNS name for this address. Ping & resolve can ask the network, but it sends new traffic.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(path.names) { name in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(name.value)
                                .font(.system(.callout, design: .monospaced))
                                .textSelection(.enabled)
                            FlowLayout(spacing: 4) {
                                ForEach(name.sources, id: \.rawValue) { source in
                                    PathTag(text: source.label, color: source.pathTint)
                                }
                            }
                            if !name.evidence.isEmpty {
                                Text(name.evidence.joined(separator: " · "))
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
                    }
                }
            }
        }
    }

    private func serviceSection(_ path: ConnectionPath) -> some View {
        InspectorSection("Service") {
            PathInfoRow("Address", path.remote.address)
            PathInfoRow("Scope", path.remote.scope.label)
            PathInfoRow("Port", "\(path.remote.port) / \(path.remote.transport.rawValue.uppercased())")
            PathInfoRow("Service guess", path.remote.serviceGuess)
            PathInfoRow("ASN", [path.remote.asn, path.remote.asnDescription].compactMap { $0 }.joined(separator: " · "))
            PathInfoRow("Network", path.remote.networkName)
            PathInfoRow("Organization", path.remote.organization)
            PathInfoRow("Registry", path.remote.registry)
            PathInfoRow("Country", path.remote.country)
            PathInfoRow("TTL / estimated hops", path.remote.ttl.map { "\($0) / \(path.remote.estimatedHops.map(String.init) ?? "unknown")" })
            PathInfoRow("Observed protocols", path.remote.observedProtocols.isEmpty ? nil : path.remote.observedProtocols.joined(separator: ", "))
            PathInfoRow("Route", path.route.map { route in
                if let gateway = route.gateway {
                    return "\(route.destination) via \(gateway)\(route.interfaceName.map { " on \($0)" } ?? "")"
                }
                return "\(route.destination) direct\(route.interfaceName.map { " on \($0)" } ?? "")"
            })
        }
    }

    private func notesSection(_ path: ConnectionPath) -> some View {
        if path.warnings.isEmpty {
            return AnyView(EmptyView())
        }
        return AnyView(InspectorSection("Path notes") {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Array(path.warnings.enumerated()), id: \.offset) { _, warning in
                    Label(warning, systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        })
    }

    private func direction(_ direction: FlowDirection) -> String? {
        switch direction {
        case .inbound: return "inbound from this Mac's point of view"
        case .outbound: return "outbound from this Mac"
        case .loopback: return "loopback on this Mac"
        case .broadcast: return "broadcast by this Mac"
        case .multicast: return "multicast from this Mac"
        }
    }

    private static let time: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .medium
        return formatter
    }()

    private static let relative: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter
    }()
}

// MARK: - Rail pieces

private struct PathNodeRow<Content: View>: View {
    let icon: String
    let tint: Color
    let title: String
    let subtitle: String?
    let content: Content
    var emphasized: Bool

    init(
        icon: String,
        tint: Color,
        title: String,
        subtitle: String? = nil,
        emphasized: Bool = false,
        @ViewBuilder content: () -> Content
    ) {
        self.icon = icon
        self.tint = tint
        self.title = title
        self.subtitle = subtitle
        self.emphasized = emphasized
        self.content = content()
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            ZStack {
                Circle()
                    .fill(tint.opacity(0.16))
                    .frame(width: 20, height: 20)
                Image(systemName: icon)
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(tint)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(emphasized ? .callout.weight(.semibold) : .callout.weight(.medium))
                    .lineLimit(2)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                content
            }
            .padding(9)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                Color(nsColor: .controlBackgroundColor),
                in: RoundedRectangle(cornerRadius: 7)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 7)
                    .stroke(tint.opacity(emphasized ? 0.35 : 0.12), lineWidth: 1)
            )
        }
    }
}

private struct PathFacts: View {
    let facts: [(String, String?)]

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(Array(facts.enumerated()), id: \.offset) { _, fact in
                if let value = fact.1, !value.isEmpty {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text(fact.0)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .frame(minWidth: 74, alignment: .leading)
                        Text(value)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }
}

private struct PathInfoRow: View {
    let label: String
    let value: String?

    init(_ label: String, _ value: String?) {
        self.label = label
        self.value = value
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
            }
        }
    }
}

private struct PathTag: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.system(size: 9, weight: .semibold))
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(color.opacity(0.14), in: Capsule())
            .foregroundStyle(color)
    }
}

private extension ObservationSource {
    var pathTint: Color {
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
