import Foundation
import AppKit
import Darwin
import SentinelDomain
import SentinelEngine
import SentinelIdentity
import SentinelAttribution
import SentinelSuspicion
import SentinelReport

/// A conversation as a person thinks about it: one remote service, one direction.
///
/// Keying on the whole 5-tuple made every DNS query from a fresh ephemeral port a
/// separate conversation, which turned 35 real conversations into 16 copies of the
/// same router lookup.
struct ConversationKey: Hashable, Sendable {
    let transport: TransportProtocol
    let remoteHost: String
    let remotePort: UInt16
    let direction: FlowDirection
}

/// One conversation, accumulated as packets arrive.
struct FlowAggregate: Sendable {
    var key: ConversationKey
    /// First-seen full key, kept for reporting and attribution.
    var representative: FlowKey
    /// Local ports seen, most recent first. A long-lived conversation rotates them.
    var localPorts: [UInt16]
    var packetTimes: [Date]
    var byteCount: Int
    var protocols: Set<String>
    var sawPlaintext: Bool
    var inboundInitiated: Bool

    init(key: ConversationKey, representative: FlowKey, inboundInitiated: Bool) {
        self.key = key
        self.representative = representative
        self.localPorts = []
        self.packetTimes = []
        self.byteCount = 0
        self.protocols = []
        self.sawPlaintext = false
        self.inboundInitiated = inboundInitiated
    }

    mutating func noteLocalPort(_ port: UInt16) {
        guard port != 0, !localPorts.contains(port) else { return }
        localPorts.insert(port, at: 0)
        if localPorts.count > 8 { localPorts.removeLast() }
    }

    var observation: FlowObservation {
        FlowObservation(
            key: representative,
            direction: key.direction,
            packetTimes: packetTimes,
            byteCount: byteCount,
            identity: EndpointIdentity(),
            process: nil,
            protocols: protocols,
            sawPlaintext: sawPlaintext,
            isInboundInitiated: inboundInitiated
        )
    }
}

@MainActor
final class SentinelModel: ObservableObject {
    @Published var packets: [CapturedPacket] = []
    @Published var assessments: [FlowAssessment] = []
    @Published var interfaces: [CaptureInterface] = []
    @Published var selectedInterfaceID: String = ""
    @Published var selectedPacketID: Int?
    @Published var detail: PacketDetail?
    @Published var isCapturing = false
    @Published var statusText = "Starting the Wireshark engine."
    @Published var engineMissing = false
    @Published var lastReportPath: String?

    let registry = UIRegistry()

    private var engine: CaptureEngine?
    private var install: WiresharkInstall?
    private let identity = IdentityResolver()
    private var attributor: ProcessAttributor?
    private let suspicion = SuspicionEngine()

    private var flows: [ConversationKey: FlowAggregate] = [:]
    private var factsByHost: [String: [IdentityFact]] = [:]
    private var streamTask: Task<Void, Never>?
    private var reaperTask: Task<Void, Never>?
    private var publisherTask: Task<Void, Never>?
    private var pendingPackets: [CapturedPacket] = []
    private var localAddresses: Set<String> = []
    private var captureStartedAt: Date?
    private var processedPackets = 0

    private static let packetLimit = 20_000

    /// Publishing every packet makes SwiftUI re-diff the whole table per packet, which
    /// throttled ingest to about 61 packets a second on this machine. Publishing in
    /// batches keeps the window responsive without dropping traffic.
    private static let publishBatch = 64
    private static let publishInterval: UInt64 = 250_000_000

    private func flushPackets() {
        guard !pendingPackets.isEmpty else { return }
        packets.append(contentsOf: pendingPackets)
        pendingPackets.removeAll(keepingCapacity: true)
    }

    private func startPublisher() {
        publisherTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: Self.publishInterval)
                guard let self else { return }
                await MainActor.run { self.flushPackets() }
            }
        }
    }

    func bootstrap(selfTestPath: String?, seconds: TimeInterval, interfaceID: String?) async {
        localAddresses = LocalAddresses.current()
        attributor = ProcessAttributor()

        if let install = WiresharkInstall.locate() {
            self.install = install
            let engine = TSharkEngine(install: install)
            self.engine = engine
            interfaces = await engine.interfaces()
            if let requested = interfaceID, interfaces.contains(where: { $0.id == requested }) {
                selectedInterfaceID = requested
            } else if let preferred = interfaces.first(where: { $0.name.hasPrefix("en") }) {
                selectedInterfaceID = preferred.id
            } else {
                selectedInterfaceID = interfaces.first?.id ?? ""
            }
        } else {
            engineMissing = true
            statusText = "Wireshark is not installed, so there is no engine to drive."
        }

        // The self test still runs without an engine: it proves the window and the
        // panes, which is a different claim from proving capture.
        if let path = selfTestPath {
            await runSelfTest(path: path, seconds: seconds)
            return
        }
        if engineMissing { return }
        statusText = interfaces.isEmpty
            ? "No capture interface was reported by dumpcap."
            : "Ready. \(interfaces.count) interfaces available."
    }

    func startCapture() async {
        guard let engine, !isCapturing, !selectedInterfaceID.isEmpty else { return }
        isCapturing = true
        captureStartedAt = Date()
        statusText = "Capturing on \(selectedInterfaceID)."
        do {
            let stream = try await engine.start(CaptureFilter(interfaceID: selectedInterfaceID))
            streamTask = Task { [weak self] in
                for await event in stream {
                    guard let self else { return }
                    await self.handle(event)
                }
            }
            startReaper()
            startPublisher()
        } catch {
            isCapturing = false
            statusText = "Capture failed: \(error)"
        }
    }

    func stopCapture() async {
        streamTask?.cancel()
        streamTask = nil
        reaperTask?.cancel()
        reaperTask = nil
        publisherTask?.cancel()
        publisherTask = nil
        await engine?.stop()
        flushPackets()
        isCapturing = false
        statusText = "Stopped after \(packets.count) packets and \(assessments.count) conversations."
    }

    private func handle(_ event: PacketEvent) async {
        switch event {
        case .packet(let packet):
            ingest(packet)
        case .error(let message):
            statusText = message
        case .finished:
            isCapturing = false
        }
    }

    private func ingest(_ packet: CapturedPacket) {
        processedPackets += 1
        if packets.count < Self.packetLimit {
            pendingPackets.append(packet)
        }
        if pendingPackets.count >= Self.publishBatch {
            flushPackets()
        }

        for (host, facts) in identity.observe(packet) {
            factsByHost[host, default: []].append(contentsOf: facts)
        }

        // A conversation needs a remote service. `orient` drops ARP and neighbour
        // discovery, which have neither host nor port and would surface as "unknown:0".
        guard let oriented = Self.orient(packet, localAddresses: localAddresses) else { return }

        let conversation = ConversationKey(
            transport: oriented.key.transport,
            remoteHost: oriented.key.remoteEndpoint.host,
            remotePort: oriented.key.remoteEndpoint.port,
            direction: oriented.direction
        )

        if flows[conversation] == nil {
            flows[conversation] = FlowAggregate(
                key: conversation,
                representative: oriented.key,
                inboundInitiated: oriented.inboundInitiated
            )
        }
        flows[conversation]?.noteLocalPort(oriented.key.localEndpoint.port)
        flows[conversation]?.packetTimes.append(packet.time)
        flows[conversation]?.byteCount += packet.length
        flows[conversation]?.protocols.insert(packet.proto)
        if Self.plaintextProtocols.contains(packet.proto) { flows[conversation]?.sawPlaintext = true }
        if oriented.inboundInitiated { flows[conversation]?.inboundInitiated = true }
    }

    /// Which side is this Mac, and who opened the connection.
    ///
    /// Capture usually starts mid-conversation, so the first packet of a flow is
    /// often a server reply. Treating packet order as initiation accused this Mac's
    /// own DNS queries and QUIC streams of being inbound connections. Initiation now
    /// needs evidence: a TCP SYN, or the port roles.
    static func orient(
        _ packet: CapturedPacket,
        localAddresses: Set<String>
    ) -> (key: FlowKey, direction: FlowDirection, inboundInitiated: Bool)? {
        let isLocal: (String) -> Bool = { host in
            !host.isEmpty && (localAddresses.contains(host) || host.hasPrefix("fe80"))
        }
        let sourceIsLocal = isLocal(packet.source)
        let destinationIsLocal = isLocal(packet.destination)

        let localHost: String
        let localPort: UInt16
        let remoteHost: String
        let remotePort: UInt16
        let baseDirection: FlowDirection

        if sourceIsLocal && destinationIsLocal {
            localHost = packet.source
            localPort = packet.sourcePort
            remoteHost = packet.destination
            remotePort = packet.destinationPort
            baseDirection = .loopback
        } else if sourceIsLocal {
            localHost = packet.source
            localPort = packet.sourcePort
            remoteHost = packet.destination
            remotePort = packet.destinationPort
            baseDirection = .outbound
        } else if destinationIsLocal {
            localHost = packet.destination
            localPort = packet.destinationPort
            remoteHost = packet.source
            remotePort = packet.sourcePort
            baseDirection = .inbound
        } else {
            // A neighbour talking to a broadcast or group address. Neither end is
            // this Mac, and the neighbour is the resource worth naming.
            localHost = packet.destination
            localPort = packet.destinationPort
            remoteHost = packet.source
            remotePort = packet.sourcePort
            baseDirection = AddressScope.isMulticastOrBroadcast(packet.destination) ? .broadcast : .outbound
        }

        guard !remoteHost.isEmpty, remotePort != 0 else { return nil }

        let key = FlowKey(
            transport: packet.transport,
            local: Endpoint(host: localHost, port: localPort),
            remote: Endpoint(host: remoteHost, port: remotePort)
        )

        if baseDirection == .loopback {
            return (key, .loopback, false)
        }

        let sawOpeningSYN = TCPFlags.synOnly(packet)
        if sawOpeningSYN {
            let inbound = !sourceIsLocal
            return (key, inbound ? .inbound : .outbound, inbound)
        }

        // Without a handshake in view, the port roles decide. An ephemeral local
        // port reaching a service port is a client, which is nearly every outbound
        // connection and every DNS query and QUIC stream on this Mac.
        let localIsService = isServicePort(localPort)
        let remoteIsService = isServicePort(remotePort)
        if remoteIsService && !localIsService {
            return (key, .outbound, false)
        }
        if localIsService && !remoteIsService {
            return (key, .inbound, true)
        }
        return (key, baseDirection, false)
    }

    private static let extraServicePorts: Set<UInt16> = [5223, 5228, 5353, 6679, 1900]

    private static func isServicePort(_ port: UInt16) -> Bool {
        port <= 1024 || extraServicePorts.contains(port)
    }

    private static let plaintextProtocols: Set<String> = [
        "HTTP", "FTP", "TELNET", "SMTP", "POP", "IMAP", "SMB", "SMB2", "LDAP", "SNMP", "TFTP",
    ]

    private func startReaper() {
        reaperTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard let self else { return }
                await self.reassess()
            }
        }
    }

    /// A conversation can hold several local ports over its life, and the one that
    /// was open when it started is often closed by the time we look. Try the recent
    /// ones before giving up.
    nonisolated private static func attribute(
        attributor: ProcessAttributor?,
        aggregate: FlowAggregate,
        remote: Endpoint,
        listeners: Set<UInt16>
    ) -> ProcessIdentity? {
        guard let attributor else { return nil }
        for port in aggregate.localPorts {
            if let process = attributor.process(remote: remote, localPort: port, transport: aggregate.key.transport) {
                return process
            }
        }
        // Inbound traffic is owned by whoever listens, not by an ephemeral port.
        if aggregate.key.direction == .inbound {
            for port in listeners where port == remote.port {
                return attributor.process(remote: remote, localPort: port, transport: aggregate.key.transport)
            }
        }
        return nil
    }

    private func reassess() async {
        let snapshot = flows.values.map { aggregate in
            (
                aggregate: aggregate,
                facts: dedupe(factsByHost[aggregate.key.remoteHost] ?? [])
            )
        }
        let listeners = await LocalListenerTable.current()
        let resolver = identity
        let engine = suspicion
        let attributor = self.attributor

        // lsof and codesign take hundreds of milliseconds. Doing that on the main
        // actor would stall the window every two seconds.
        let results = await Task.detached(priority: .utility) { () -> [FlowAssessment] in
            attributor?.refresh()
            return snapshot.map { item in
                var observation = item.aggregate.observation
                let remote = item.aggregate.representative.remoteEndpoint
                observation.identity = resolver.identity(host: item.aggregate.key.remoteHost, facts: item.facts)
                observation.process = Self.attribute(
                    attributor: attributor,
                    aggregate: item.aggregate,
                    remote: remote,
                    listeners: listeners
                )
                observation.hasLocalListener = listeners.contains(observation.key.localEndpoint.port)
                return engine.assess(observation)
            }
        }.value

        assessments = results.sorted { lhs, rhs in
            if lhs.score != rhs.score { return lhs.score > rhs.score }
            return lhs.firstSeen < rhs.firstSeen
        }
    }

    private func dedupe(_ facts: [IdentityFact]) -> [IdentityFact] {
        var seen = Set<String>()
        var output: [IdentityFact] = []
        for fact in facts {
            let token = "\(fact.source.rawValue)|\(fact.value)"
            if seen.insert(token).inserted { output.append(fact) }
        }
        return output
    }

    func selectPacket(_ id: Int) {
        selectedPacketID = id
        guard let engine else { return }
        Task {
            detail = try? await engine.detail(frameNumber: id)
        }
    }

    func exportReport() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "sentinel-report.md"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        writeReport(to: url)
    }

    @discardableResult
    func writeReport(to url: URL) -> String {
        let report = SentinelReport(
            assessments: assessments,
            interfaceName: selectedInterfaceID,
            duration: captureStartedAt.map { Date().timeIntervalSince($0) } ?? 0
        )
        let text = report.render(.markdown)
        try? text.write(to: url, atomically: true, encoding: .utf8)
        let jsonURL = url.deletingPathExtension().appendingPathExtension("json")
        try? report.render(.json).write(to: jsonURL, atomically: true, encoding: .utf8)
        lastReportPath = url.path
        return text
    }

    private func runSelfTest(path: String, seconds: TimeInterval) async {
        await startCapture()
        try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
        await reassess()
        await stopCapture()

        let directory = URL(fileURLWithPath: path)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let reportURL = directory.appendingPathComponent("sentinel-report.md")
        writeReport(to: reportURL)

        registry.measureWindow()
        let uiURL = directory.appendingPathComponent("ui.json")
        try? registry.json(packetCount: packets.count, assessmentCount: assessments.count)
            .write(to: uiURL, atomically: true, encoding: .utf8)

        FileHandle.standardError.write(Data("selftest packets=\(packets.count) assessments=\(assessments.count) report=\(reportURL.path)\n".utf8))
        exit(0)
    }
}

enum LocalAddresses {
    static func current() -> Set<String> {
        var addresses: Set<String> = ["127.0.0.1", "::1", "0.0.0.0"]
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return addresses }
        defer { freeifaddrs(pointer) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let family = entry.pointee.ifa_addr?.pointee.sa_family else { continue }
            guard family == UInt8(AF_INET) || family == UInt8(AF_INET6) else { continue }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(
                entry.pointee.ifa_addr,
                socklen_t(entry.pointee.ifa_addr.pointee.sa_len),
                &buffer, socklen_t(buffer.count),
                nil, 0, NI_NUMERICHOST
            )
            if result == 0 {
                addresses.insert(String(cString: buffer))
            }
        }
        return addresses
    }
}
