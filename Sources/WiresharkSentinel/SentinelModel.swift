import Foundation
import AppKit
import Darwin
import SentinelDomain
import SentinelEngine
import SentinelIdentity
import SentinelAttribution
import SentinelIntel
import SentinelBlock
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
    var bytesSent: Int
    var bytesReceived: Int
    var packetsSent: Int
    var packetsReceived: Int
    var protocols: Set<String>
    var sawPlaintext: Bool
    var direction: FlowDirection
    var directionDecided: Bool
    var inboundInitiated: Bool

    init(key: ConversationKey, representative: FlowKey, direction: FlowDirection, directionDecided: Bool, inboundInitiated: Bool) {
        self.key = key
        self.representative = representative
        self.direction = direction
        self.directionDecided = directionDecided
        self.inboundInitiated = inboundInitiated
        self.localPorts = []
        self.packetTimes = []
        self.byteCount = 0
        self.bytesSent = 0
        self.bytesReceived = 0
        self.packetsSent = 0
        self.packetsReceived = 0
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
            direction: direction,
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
    @Published var scannedDetails: [FlowKey: ConnectionDetails] = [:]
    @Published var scanningFlow: FlowKey?
    @Published var scanError: String?
    @Published var packetFocus: FlowKey?
    @Published var probeResults: [FlowKey: ActiveProbeResult] = [:]
    @Published var probingFlow: FlowKey?
    @Published var blockState: BlockState
    @Published var blockError: String?
    @Published var blockOutput: String?
    @Published var isApplyingBlock = false

    let registry = UIRegistry()

    private var engine: TSharkEngine?
    private var install: WiresharkInstall?
    private let identity = IdentityResolver()
    private let intel = IntelClient()
    private let prober = ActiveProber()
    private let blockStore: BlockStore
    private let blockController = PFBlockController()
    private var attributor: ProcessAttributor?
    private let suspicion = SuspicionEngine()

    private var flows: [ConversationKey: FlowAggregate] = [:]
    private var factsByHost: [String: [IdentityFact]] = [:]
    private var streamTask: Task<Void, Never>?
    private var reaperTask: Task<Void, Never>?
    private var publisherTask: Task<Void, Never>?
    private var pendingPackets: [CapturedPacket] = []
    private var localAddresses: Set<String> = []
    private var broadcastAddresses: Set<String> = []
    private var captureStartedAt: Date?
    private var processedPackets = 0

    private static let packetLimit = 20_000

    init() {
        let support = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("WiresharkSentinel", isDirectory: true)
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/WiresharkSentinel", isDirectory: true)
        let store = BlockStore(url: support.appendingPathComponent("blocks.json"))
        blockStore = store
        blockState = store.load()
    }

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
        broadcastAddresses = LocalAddresses.currentBroadcasts()
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
        guard let oriented = Self.orient(
            packet,
            localAddresses: localAddresses,
            broadcastAddresses: broadcastAddresses
        ) else { return }

        let conversation = ConversationKey(
            transport: oriented.key.transport,
            remoteHost: oriented.key.remoteEndpoint.host,
            remotePort: oriented.key.remoteEndpoint.port
        )

        if flows[conversation] == nil {
            flows[conversation] = FlowAggregate(
                key: conversation,
                representative: oriented.key,
                direction: oriented.direction,
                directionDecided: oriented.decisive,
                inboundInitiated: oriented.inboundInitiated
            )
        }
        // A reply packet and the request it answers are one conversation. Only
        // decisive evidence, a handshake or the port roles, may set the direction.
        if oriented.decisive, flows[conversation]?.directionDecided != true {
            flows[conversation]?.direction = oriented.direction
            flows[conversation]?.directionDecided = true
            flows[conversation]?.inboundInitiated = oriented.inboundInitiated
            flows[conversation]?.representative = oriented.key
        }
        flows[conversation]?.noteLocalPort(oriented.key.localEndpoint.port)
        flows[conversation]?.packetTimes.append(packet.time)
        flows[conversation]?.byteCount += packet.length
        if oriented.key.localEndpoint.host == packet.source {
            flows[conversation]?.bytesSent += packet.length
            flows[conversation]?.packetsSent += 1
        } else {
            flows[conversation]?.bytesReceived += packet.length
            flows[conversation]?.packetsReceived += 1
        }
        flows[conversation]?.protocols.insert(packet.proto)
        if Self.plaintextProtocols.contains(packet.proto) { flows[conversation]?.sawPlaintext = true }
    }

    /// Which side is this Mac, and who opened the connection.
    ///
    /// Capture usually starts mid-conversation, so the first packet of a flow is
    /// often a server reply. Treating packet order as initiation accused this Mac's
    /// own DNS queries and QUIC streams of being inbound connections. Initiation now
    /// needs evidence: a TCP SYN, or the port roles.
    static func orient(
        _ packet: CapturedPacket,
        localAddresses: Set<String>,
        broadcastAddresses: Set<String> = []
    ) -> (key: FlowKey, direction: FlowDirection, inboundInitiated: Bool, decisive: Bool)? {
        let isLocal: (String) -> Bool = { host in
            !host.isEmpty && (localAddresses.contains(host) || host.hasPrefix("fe80"))
        }
        let sourceIsLocal = isLocal(packet.source)
        let destinationIsLocal = isLocal(packet.destination)
        // A subnet-directed broadcast such as 192.168.1.255 carries no 224.* prefix,
        // so the interfaces' own broadcast addresses are the only reliable source.
        let destinationIsGroup = AddressScope.isMulticastOrBroadcast(packet.destination)
            || broadcastAddresses.contains(packet.destination)
        let groupDirection: FlowDirection = packet.destination == "255.255.255.255"
            ? .broadcast
            : (packet.destination.lowercased().hasPrefix("ff") ? .multicast : .broadcast)

        if destinationIsGroup {
            // The group is addressed by whoever sent it. When this Mac is the sender
            // the group is the far end; when a neighbour is the sender, the neighbour
            // is the resource worth naming and the group is where it spoke.
            let key: FlowKey
            if sourceIsLocal {
                key = FlowKey(
                    transport: packet.transport,
                    local: Endpoint(host: packet.source, port: packet.sourcePort),
                    remote: Endpoint(host: packet.destination, port: packet.destinationPort)
                )
            } else {
                key = FlowKey(
                    transport: packet.transport,
                    local: Endpoint(host: packet.destination, port: packet.destinationPort),
                    remote: Endpoint(host: packet.source, port: packet.destinationPort)
                )
            }
            // Group traffic has no handshake and no service port; it is never an
            // accusation, so it carries no initiation claim.
            return (key, groupDirection, false, false)
        }

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
            // The port a broadcaster is addressing is the service; its own source
            // port is ephemeral and says nothing about what it is talking to.
            remotePort = packet.destinationPort
            baseDirection = .outbound
        }

        guard !remoteHost.isEmpty, remotePort != 0 else { return nil }

        let key = FlowKey(
            transport: packet.transport,
            local: Endpoint(host: localHost, port: localPort),
            remote: Endpoint(host: remoteHost, port: remotePort)
        )

        if baseDirection == .loopback {
            return (key, .loopback, false, true)
        }

        let sawOpeningSYN = TCPFlags.synOnly(packet)
        if sawOpeningSYN {
            let inbound = !sourceIsLocal
            return (key, inbound ? .inbound : .outbound, inbound, true)
        }

        // Without a handshake in view, the port roles decide. An ephemeral local
        // port reaching a service port is a client, which is nearly every outbound
        // connection and every DNS query and QUIC stream on this Mac.
        let localIsService = isServicePort(localPort)
        let remoteIsService = isServicePort(remotePort)
        if remoteIsService && !localIsService {
            return (key, .outbound, false, true)
        }
        if localIsService && !remoteIsService {
            return (key, .inbound, true, true)
        }
        // Neither port identifies the service, so this packet is not evidence of
        // who opened the connection. Wait for a packet that is.
        return (key, baseDirection, false, false)
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
        if aggregate.direction == .inbound {
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

    // MARK: - Deep scan

    /// Reads one conversation out of the capture file in depth. This is explicit
    /// and cached: running a second tshark pass per packet would make live capture
    /// slow, and the result for a finished conversation does not change.
    func deepScan(_ assessment: FlowAssessment, options: ScanOptions = .preset(.deep)) async {
        guard scanningFlow == nil else { return }
        guard let engine, let captureFile = engine.captureFileURL else {
            scanError = "There is no capture file yet. Start a capture, let some traffic arrive, then scan."
            return
        }
        guard let install else {
            scanError = "Wireshark is not installed, so there is no dissector to read the capture with."
            return
        }

        scanningFlow = assessment.key
        scanError = nil
        defer { scanningFlow = nil }

        let conversation = ConversationKey(
            transport: assessment.key.transport,
            remoteHost: assessment.key.remoteEndpoint.host,
            remotePort: assessment.key.remoteEndpoint.port
        )
        let aggregate = flows[conversation]
        let facts = dedupe(factsByHost[assessment.key.remoteEndpoint.host] ?? [])
        let hostIdentity = identity.identity(host: assessment.key.remoteEndpoint.host, facts: facts)
        let listeners = await LocalListenerTable.current()
        let attributor = self.attributor
        let intel = self.intel
        let flow = assessment.key
        let localPort = aggregate?.localPorts.first ?? flow.localEndpoint.port
        let localHost = flow.localEndpoint.host
        let remote = flow.remoteEndpoint

        do {
            let details = try await Task.detached(priority: .userInitiated) { () -> ConnectionDetails in
                // lsof, codesign and the resolver are blocking. A detached task
                // keeps all of that off the main actor while the sheet stays live.
                attributor?.refresh()
                let process = aggregate.flatMap {
                    Self.attribute(
                        attributor: attributor,
                        aggregate: $0,
                        remote: remote,
                        listeners: listeners
                    )
                }
                let reverseDNS = options.resolvePTR ? SystemPTRResolver().name(for: remote.host) : nil
                let socket = process.map {
                    SocketDetails(
                        pid: $0.pid,
                        command: $0.name,
                        localAddress: localHost,
                        localPort: localPort,
                        remoteAddress: remote.host,
                        remotePort: remote.port,
                        transport: flow.transport
                    )
                }
                let request = DeepScanRequest(
                    flow: flow,
                    captureFile: captureFile,
                    options: options,
                    socket: socket,
                    process: process,
                    identity: hostIdentity,
                    reverseDNS: reverseDNS
                )
                var details = try await TSharkDeepScanner(install: install).scan(request)
                if options.lookupRDAP || options.lookupASN {
                    let report = await intel.enrich(
                        address: remote.host,
                        includeRDAP: options.lookupRDAP,
                        includeASN: options.lookupASN
                    )
                    Self.apply(report, to: &details)
                }
                return details
            }.value
            scannedDetails[assessment.key] = details
        } catch {
            scanError = String(describing: error)
        }
    }

    func connectionDetails(for assessment: FlowAssessment) -> ConnectionDetails? {
        scannedDetails[assessment.key]
    }

    /// Merges registry answers into the packet-derived report without pretending
    /// they came from the capture. Each new value keeps its RDAP provenance.
    private nonisolated static func apply(_ report: IntelReport, to details: inout ConnectionDetails) {
        if let rdap = report.rdap {
            details.network.organization = rdap.organization ?? details.network.organization
            details.network.networkName = rdap.networkName ?? details.network.networkName
            details.network.asn = rdap.asn ?? details.network.asn
            details.network.registry = rdap.registry ?? details.network.registry
            details.network.country = rdap.country ?? details.network.country
            details.network.abuseContact = rdap.abuseContact ?? details.network.abuseContact
            if let handle = rdap.handle, let registry = rdap.registry {
                details.observations.append(
                    ConnectionObservation(
                        section: "Network",
                        label: "Registry handle",
                        value: "\(handle) at \(registry)",
                        source: .rdap,
                        confidence: .observed
                    )
                )
            }
            if let abuse = rdap.abuseContact {
                details.observations.append(
                    ConnectionObservation(
                        section: "Network",
                        label: "Abuse contact",
                        value: abuse,
                        source: .rdap,
                        confidence: .observed
                    )
                )
            }
        }

        if let asn = report.asn {
            details.network.asn = asn.asn
            details.network.asnDescription = asn.description
            if details.network.networkName == nil { details.network.networkName = asn.description }
            details.network.country = details.network.country ?? asn.country
            details.observations.append(
                ConnectionObservation(
                    section: "Network",
                    label: "Autonomous system",
                    value: [asn.asn, asn.description].compactMap { $0 }.joined(separator: " · "),
                    source: .asn,
                    confidence: .observed
                )
            )
        }

        details.warnings.append(contentsOf: report.warnings)
    }

    // MARK: - Active probe

    /// Sends one TCP connection to the observed port. Never called by a scan; only
    /// from the inspector's explicit probe button.
    func runActiveProbe(_ assessment: FlowAssessment, options: ScanOptions = .preset(.active)) async {
        guard probingFlow == nil else { return }
        let remote = assessment.key.remoteEndpoint
        guard assessment.key.transport == .tcp else {
            probeResults[assessment.key] = ActiveProbeResult(
                host: remote.host,
                port: remote.port,
                transport: assessment.key.transport,
                kind: .tcpConnect,
                opened: false,
                error: "Active probing supports TCP only. This conversation is \(assessment.key.transport.rawValue.uppercased())."
            )
            return
        }

        probingFlow = assessment.key
        defer { probingFlow = nil }
        let result = await prober.probe(
            host: remote.host,
            port: remote.port,
            kind: .tcpConnect,
            timeout: options.activeTimeout,
            allowPrivate: options.includePrivate
        )
        probeResults[assessment.key] = result
    }

    // MARK: - Blocking

    /// The addresses and broadcasts used for block safety. Bootstrap normally has
    /// them already; the fallback keeps validation correct before a capture starts.
    var blockLocalAddresses: Set<String> {
        localAddresses.isEmpty ? LocalAddresses.current() : localAddresses
    }

    var blockBroadcastAddresses: Set<String> {
        broadcastAddresses.isEmpty ? LocalAddresses.currentBroadcasts() : broadcastAddresses
    }

    /// The target a person most likely means when they press Block on a card.
    /// The observed remote port is included by default because "this service" is
    /// usually the intent; the editor lets them widen it to the whole address.
    func suggestedBlockTarget(for assessment: FlowAssessment, includePort: Bool = true) -> BlockTarget {
        let remote = assessment.key.remoteEndpoint
        let hasPort = includePort && remote.port != 0 && assessment.key.transport != .other
        let transport: BlockTransport
        if hasPort {
            switch assessment.key.transport {
            case .tcp: transport = .tcp
            case .udp: transport = .udp
            case .other: transport = .any
            }
        } else {
            transport = .any
        }
        return BlockTarget(
            address: remote.host,
            port: hasPort ? remote.port : nil,
            transport: transport,
            direction: .both,
            note: assessment.identity.evidencedName ?? assessment.verdict.label,
            sourceEndpoint: remote.description
        )
    }

    /// Validates the target and shows the whole plan that Apply will install:
    /// existing active targets plus the one being edited. The preview must show the
    /// same ruleset, not just the addition.
    func planBlock(adding target: BlockTarget) -> BlockPlan {
        BlockPlanBuilder.plan(
            targets: blockState.activeTargets + [target],
            localAddresses: blockLocalAddresses,
            broadcastAddresses: blockBroadcastAddresses
        )
    }

    @discardableResult
    func applyBlock(
        target: BlockTarget,
        persistAfterReboot: Bool? = nil,
        reason: String = "Blocked from Wireshark Sentinel"
    ) async -> Bool {
        await applyBlockTargets(
            blockState.activeTargets + [target],
            action: "block",
            reason: reason,
            persist: persistAfterReboot
        )
    }

    @discardableResult
    func unblock(recordIDs: Set<UUID>, persistAfterReboot: Bool? = nil) async -> Bool {
        guard !recordIDs.isEmpty else { return true }
        let removed = blockState.records.filter { recordIDs.contains($0.id) }
        let remaining = blockState.activeTargets.filter { target in
            !removed.contains(where: { $0.target.id == target.id })
        }
        return await applyBlockTargets(
            remaining,
            action: "unblock",
            reason: "Unblocked from Wireshark Sentinel",
            persist: persistAfterReboot
        )
    }

    @discardableResult
    func unblockAll(persistAfterReboot: Bool? = nil) async -> Bool {
        await applyBlockTargets(
            [],
            action: "unblock-all",
            reason: "All blocks removed from Wireshark Sentinel",
            persist: persistAfterReboot
        )
    }

    /// Reinstalls the current anchor after a reboot or after someone flushed pf.
    @discardableResult
    func reapplyBlocks() async -> Bool {
        await applyBlockTargets(
            blockState.activeTargets,
            action: "reapply",
            reason: "Reapplied from Wireshark Sentinel",
            persist: nil
        )
    }

    /// Changing persistence rewrites the rules, so it asks for the same one admin
    /// prompt as any other firewall change. It goes through the same path even when
    /// no blocks are active, because that is how an existing LaunchDaemon is removed.
    @discardableResult
    func setBlockPersistence(_ enabled: Bool) async -> Bool {
        guard blockState.persistAfterReboot != enabled else { return true }
        return await applyBlockTargets(
            blockState.activeTargets,
            action: "persistence",
            reason: "Persistence changed in Wireshark Sentinel",
            persist: enabled
        )
    }

    /// One path for every firewall change: validate, ask once, install, audit.
    private func applyBlockTargets(
        _ targets: [BlockTarget],
        action: String,
        reason: String,
        persist: Bool?
    ) async -> Bool {
        guard !isApplyingBlock else { return false }

        let plan = BlockPlanBuilder.plan(
            targets: targets,
            localAddresses: blockLocalAddresses,
            broadcastAddresses: blockBroadcastAddresses
        )
        guard plan.isValid else {
            blockError = plan.errors.joined(separator: "\n")
            return false
        }

        let persistence = persist ?? blockState.persistAfterReboot
        let previous = blockState
        isApplyingBlock = true
        blockError = nil
        defer { isApplyingBlock = false }

        do {
            let result = try await blockController.apply(plan: plan, persistAfterReboot: persistence)
            blockOutput = result.output
            blockState.persistAfterReboot = persistence
            reconcileRecords(with: plan.targets, reason: reason, rules: plan.rules)
            blockState.audit.append(
                BlockAuditEntry(
                    action: action,
                    targets: plan.targets.isEmpty ? ["all blocks"] : plan.targets.map(\.displayName),
                    result: "applied",
                    detail: result.anchorPath
                )
            )
            saveBlockState()
            return true
        } catch {
            let message = String(describing: error)
            blockError = message
            blockOutput = nil
            // The firewall did not change, so the stored state must not pretend it
            // did. Keep the failure in the audit trail, then restore the records.
            blockState = previous
            blockState.persistAfterReboot = previous.persistAfterReboot
            blockState.audit.append(
                BlockAuditEntry(
                    action: action,
                    targets: plan.targets.isEmpty ? ["all blocks"] : plan.targets.map(\.displayName),
                    result: "failed",
                    detail: message
                )
            )
            saveBlockState()
            return false
        }
    }

    /// Makes the stored records agree exactly with the rules that pf accepted.
    /// Targets that were removed become inactive history instead of disappearing.
    private func reconcileRecords(with targets: [BlockTarget], reason: String, rules: [PFRule]) {
        let ruleText = rules.map(\.text).joined(separator: "\n")
        let ids = Set(targets.map(\.id))
        let now = Date()

        for index in blockState.records.indices {
            if ids.contains(blockState.records[index].target.id) {
                blockState.records[index].active = true
                blockState.records[index].appliedAt = now
                blockState.records[index].ruleText = ruleText
            } else {
                blockState.records[index].active = false
            }
        }

        for target in targets where !blockState.records.contains(where: { $0.target.id == target.id }) {
            blockState.records.append(
                BlockRecord(
                    target: target,
                    reason: target.note ?? reason,
                    appliedAt: now,
                    active: true,
                    ruleText: ruleText
                )
            )
        }
    }

    private func saveBlockState() {
        do {
            try blockStore.save(blockState)
        } catch {
            blockError = (blockError.map { $0 + "\n" } ?? "")
                + "The block record could not be saved: \(error)"
        }
    }

    // MARK: - Packet focus

    /// Narrows the packet list to the frames behind one conversation. The remote
    /// address and service port are the stable identity; the local ephemeral port
    /// can rotate while the conversation is still the same one.
    func focusPackets(on assessment: FlowAssessment) {
        packetFocus = assessment.key
        if let first = packets.first(where: { Self.isFocused($0, on: assessment.key) }) {
            selectPacket(first.id)
        }
    }

    func clearPacketFocus() {
        packetFocus = nil
    }

    nonisolated static func isFocused(_ packet: CapturedPacket, on key: FlowKey) -> Bool {
        if packet.source == key.remoteEndpoint.host, packet.sourcePort == key.remoteEndpoint.port {
            return true
        }
        if packet.destination == key.remoteEndpoint.host, packet.destinationPort == key.remoteEndpoint.port {
            return true
        }
        return false
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
    /// The broadcast address of every broadcast-capable IPv4 interface.
    static func currentBroadcasts() -> Set<String> {
        var broadcasts: Set<String> = ["255.255.255.255"]
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return broadcasts }
        defer { freeifaddrs(pointer) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let address = entry.pointee.ifa_addr, address.pointee.sa_family == UInt8(AF_INET) else { continue }
            guard Int32(entry.pointee.ifa_flags) & IFF_BROADCAST != 0,
                  let broad = entry.pointee.ifa_dstaddr else { continue }
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(broad, socklen_t(broad.pointee.sa_len), &buffer, socklen_t(buffer.count),
                           nil, 0, NI_NUMERICHOST) == 0 {
                broadcasts.insert(String(cString: buffer))
            }
        }
        return broadcasts
    }

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
