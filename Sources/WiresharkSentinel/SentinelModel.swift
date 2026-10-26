import Foundation
import AppKit
import Darwin
import SentinelDomain
import SentinelEngine
import SentinelIdentity
import SentinelAttribution
import SentinelSuspicion
import SentinelReport

/// One conversation, accumulated as packets arrive.
struct FlowAggregate: Sendable {
    var key: FlowKey
    var direction: FlowDirection
    var packetTimes: [Date]
    var byteCount: Int
    var protocols: Set<String>
    var sawPlaintext: Bool
    var firstWasInbound: Bool

    init(key: FlowKey, direction: FlowDirection, firstWasInbound: Bool) {
        self.key = key
        self.direction = direction
        self.packetTimes = []
        self.byteCount = 0
        self.protocols = []
        self.sawPlaintext = false
        self.firstWasInbound = firstWasInbound
    }

    var observation: FlowObservation {
        FlowObservation(
            key: key,
            direction: direction,
            packetTimes: packetTimes,
            byteCount: byteCount,
            identity: EndpointIdentity(),
            process: nil,
            protocols: protocols,
            sawPlaintext: sawPlaintext,
            isInboundInitiated: firstWasInbound
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

    private var flows: [FlowKey: FlowAggregate] = [:]
    private var factsByHost: [String: [IdentityFact]] = [:]
    private var streamTask: Task<Void, Never>?
    private var reaperTask: Task<Void, Never>?
    private var localAddresses: Set<String> = []
    private var captureStartedAt: Date?
    private var processedPackets = 0

    private static let packetLimit = 20_000

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
        await engine?.stop()
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
            packets.append(packet)
        }

        for (host, facts) in identity.observe(packet) {
            factsByHost[host, default: []].append(contentsOf: facts)
        }

        let isIPv6 = packet.source.contains(":")
        let sourceIsLocal = localAddresses.contains(packet.source) || packet.source.hasPrefix("fe80")
        let destinationIsLocal = localAddresses.contains(packet.destination)
        let transport: TransportProtocol = packet.transport
        _ = isIPv6

        let key: FlowKey
        let direction: FlowDirection
        var firstWasInbound = false

        if sourceIsLocal && !destinationIsLocal {
            key = FlowKey(
                transport: transport,
                local: Endpoint(host: packet.source, port: packet.sourcePort),
                remote: Endpoint(host: packet.destination, port: packet.destinationPort)
            )
            direction = .outbound
        } else if destinationIsLocal && !sourceIsLocal {
            key = FlowKey(
                transport: transport,
                local: Endpoint(host: packet.destination, port: packet.destinationPort),
                remote: Endpoint(host: packet.source, port: packet.sourcePort)
            )
            direction = .inbound
            firstWasInbound = true
        } else {
            key = FlowKey(
                transport: transport,
                local: Endpoint(host: packet.source, port: packet.sourcePort),
                remote: Endpoint(host: packet.destination, port: packet.destinationPort)
            )
            direction = .loopback
        }

        if flows[key] == nil {
            flows[key] = FlowAggregate(key: key, direction: direction, firstWasInbound: firstWasInbound)
        }
        flows[key]?.packetTimes.append(packet.time)
        flows[key]?.byteCount += packet.length
        flows[key]?.protocols.insert(packet.proto)
        if Self.plaintextProtocols.contains(packet.proto) { flows[key]?.sawPlaintext = true }
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

    private func reassess() async {
        let snapshot = flows.map { key, aggregate in
            (key: key, aggregate: aggregate, facts: dedupe(factsByHost[key.remoteEndpoint.host] ?? []))
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
                observation.identity = resolver.identity(host: item.key.remoteEndpoint.host, facts: item.facts)
                observation.process = attributor?.process(
                    remote: item.key.remoteEndpoint,
                    localPort: item.key.localEndpoint.port,
                    transport: item.key.transport
                )
                observation.hasLocalListener = listeners.contains(item.key.localEndpoint.port)
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
