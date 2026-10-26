import Foundation
import SentinelDomain

/// One conversation, aggregated over the capture.
public struct FlowObservation: Sendable {
    public var key: FlowKey
    public var direction: FlowDirection
    public var packetTimes: [Date]
    public var byteCount: Int
    public var identity: EndpointIdentity
    public var process: ProcessIdentity?
    public var protocols: Set<String>
    public var sawPlaintext: Bool
    public var isInboundInitiated: Bool
    /// Set when a local process listens on the local port. An inbound connection to a port
    /// nobody listens on is the one worth reporting; sshd accepting a session is not.
    public var hasLocalListener: Bool

    public init(
        key: FlowKey, direction: FlowDirection = .outbound, packetTimes: [Date] = [],
        byteCount: Int = 0, identity: EndpointIdentity = EndpointIdentity(),
        process: ProcessIdentity? = nil, protocols: Set<String> = [],
        sawPlaintext: Bool = false, isInboundInitiated: Bool = false,
        hasLocalListener: Bool = false
    ) {
        self.key = key
        self.direction = direction
        self.packetTimes = packetTimes
        self.byteCount = byteCount
        self.identity = identity
        self.process = process
        self.protocols = protocols
        self.sawPlaintext = sawPlaintext
        self.isInboundInitiated = isInboundInitiated
        self.hasLocalListener = hasLocalListener
    }
}

public struct SuspicionPolicy: Sendable {
    public var weights: [SignalKind: Int]
    public var suspiciousScore: Int
    public var unknownScore: Int

    public init(weights: [SignalKind: Int], suspiciousScore: Int = 60, unknownScore: Int = 25) {
        self.weights = weights
        self.suspiciousScore = suspiciousScore
        self.unknownScore = unknownScore
    }

    public static let `default` = SuspicionPolicy(weights: [
        .unknownDestination: 30,
        .inboundUnsolicited: 40,
        .beaconing: 35,
        .unsignedProcess: 30,
        .unusualPort: 25,
        .plaintextProtocol: 25,
        .dnsHighVolume: 25,
        .longLivedIdle: 25,
        .rawIPTraffic: 25,
    ])
}

/// Weighted signals in, one verdict out. Pure and offline.
public struct SuspicionEngine: Sendable {
    private let policy: SuspicionPolicy

    public init(policy: SuspicionPolicy = .default) {
        self.policy = policy
    }

    public func signals(for observation: FlowObservation) -> [Signal] {
        let protocols = Set(observation.protocols.map { $0.uppercased() })
        var fired: [Signal] = []

        if !observation.identity.isIdentified {
            fired.append(makeSignal(
                .unknownDestination,
                detail: "We could not identify who this destination belongs to.",
                evidence: ["no identity evidence for \(observation.key.remote)"]
            ))
        }

        if observation.isInboundInitiated, !observation.hasLocalListener, Self.carriesRepetition(observation) {
            fired.append(makeSignal(
                .inboundUnsolicited,
                detail: "Something outside this Mac opened the connection to a port with no local listener.",
                evidence: ["inbound initiated", "local port \(observation.key.local.port)"]
            ))
        }

        if let cadence = Self.cadence(of: observation.packetTimes) {
            fired.append(makeSignal(
                .beaconing,
                detail: "It repeats on a regular timer instead of when a person acts.",
                evidence: [
                    "\(cadence.count) intervals",
                    "mean \(Int(cadence.mean.rounded())) s",
                    "standard deviation \(Int((cadence.variation * 100).rounded())) percent of the mean",
                ]
            ))
        }

        if let process = observation.process, process.signing == .unsigned || process.signing == .adHoc {
            fired.append(makeSignal(
                .unsignedProcess,
                detail: "The program behind it is not signed by a known developer.",
                evidence: ["\(process.name) pid \(process.pid)"]
            ))
        }

        if !Self.wellKnownPorts.contains(observation.servicePort) {
            let side = observation.direction == .inbound ? "local" : "remote"
            fired.append(makeSignal(
                .unusualPort,
                detail: "It uses \(side) port \(observation.servicePort), which is not a usual service port.",
                evidence: ["\(side) port \(observation.servicePort)"]
            ))
        }

        if observation.sawPlaintext {
            fired.append(makeSignal(
                .plaintextProtocol,
                detail: "It sends data without encryption.",
                evidence: [protocols.isEmpty ? "plaintext traffic" : protocols.sorted().joined(separator: ", ")]
            ))
        }

        if let burst = Self.dnsBurst(observation, protocols: protocols) {
            fired.append(makeSignal(
                .dnsHighVolume,
                detail: "It sent \(burst.packets) DNS packets to one server in \(burst.seconds) seconds.",
                evidence: ["remote \(observation.key.remote)", "\(burst.packets) packets in \(burst.seconds) s"]
            ))
        }

        if let idle = Self.idleSpan(observation) {
            fired.append(makeSignal(
                .longLivedIdle,
                detail: "It stayed open for \(idle.minutes) minutes while sending almost nothing.",
                evidence: ["\(idle.minutes) minutes", "\(observation.byteCount) bytes"]
            ))
        }

        if Self.isTransportOnly(protocols, port: observation.servicePort) {
            fired.append(makeSignal(
                .rawIPTraffic,
                detail: "It carries raw \(protocols.sorted().joined(separator: " or ")) with no recognised application protocol.",
                evidence: ["service port \(observation.servicePort)"]
            ))
        }

        return fired
    }

    public func assess(_ observation: FlowObservation) -> FlowAssessment {
        let fired = signals(for: observation)
        let score = fired.reduce(0) { $0 + $1.weight }
        let verdict = verdict(score: score, signals: fired, observation: observation)
        return FlowAssessment(
            key: observation.key,
            direction: observation.direction,
            identity: observation.identity,
            process: observation.process,
            signals: fired,
            score: score,
            verdict: verdict,
            rationale: rationale(for: fired, verdict: verdict),
            firstSeen: observation.packetTimes.first ?? observation.identity.firstSeen ?? .distantPast,
            lastSeen: observation.packetTimes.last ?? observation.identity.lastSeen ?? .distantPast,
            packetCount: observation.packetTimes.count,
            byteCount: observation.byteCount
        )
    }

    // MARK: - Verdict

    private func verdict(score: Int, signals: [Signal], observation: FlowObservation) -> Verdict {
        let identityOnly = signals.allSatisfy { $0.kind == .unknownDestination }
        let capAtUnknown = observation.hasNonPublicDestination && identityOnly
        if score >= policy.suspiciousScore && !capAtUnknown { return .suspicious }
        if score >= policy.unknownScore { return .unknown }
        return .known
    }

    private func rationale(for signals: [Signal], verdict: Verdict) -> String {
        guard !signals.isEmpty else { return "" }
        let reasons = Self.strongestFirst(signals)
            .prefix(3)
            .map { Self.clause(from: $0.detail) }
        let listed = Self.listed(Array(reasons))
        switch verdict {
        case .suspicious: return "Suspicious because \(listed)."
        case .unknown: return "Not sure about this connection because \(listed)."
        case .known: return "Nothing serious, but \(listed)."
        }
    }

    private static func strongestFirst(_ signals: [Signal]) -> [Signal] {
        signals.sorted { lhs, rhs in
            if lhs.weight != rhs.weight { return lhs.weight > rhs.weight }
            return rank(lhs.kind) < rank(rhs.kind)
        }
    }

    private static func rank(_ kind: SignalKind) -> Int {
        SignalKind.allCases.firstIndex(of: kind) ?? SignalKind.allCases.count
    }

    private static func clause(from detail: String) -> String {
        let trimmed = detail.hasSuffix(".") ? String(detail.dropLast()) : detail
        guard let first = trimmed.first else { return trimmed }
        return first.lowercased() + trimmed.dropFirst()
    }

    private static func listed(_ parts: [String]) -> String {
        guard let last = parts.last else { return "" }
        guard parts.count > 1 else { return last }
        return parts.dropLast().joined(separator: ", ") + ", and " + last
    }

    // MARK: - Rules

    private func makeSignal(_ kind: SignalKind, detail: String, evidence: [String]) -> Signal {
        Signal(kind: kind, weight: policy.weights[kind] ?? 0, detail: detail, evidence: evidence)
    }

    private static let wellKnownPorts: Set<UInt16> = [443, 80, 53, 123, 22, 993, 587, 5223, 5228, 5353]

    private static let transportProtocols: Set<String> = ["TCP", "UDP"]

    private struct Cadence {
        let count: Int
        let mean: TimeInterval
        let variation: Double
    }

    /// Regularity only counts from four intervals up; two points make any line look straight.
    private static func cadence(of times: [Date]) -> Cadence? {
        let sorted = times.sorted()
        guard sorted.count >= 5 else { return nil }
        let intervals = zip(sorted, sorted.dropFirst()).map { $1.timeIntervalSince($0) }
        let mean = intervals.reduce(0, +) / Double(intervals.count)
        guard mean > 0 else { return nil }
        let variance = intervals.reduce(0) { $0 + ($1 - mean) * ($1 - mean) } / Double(intervals.count)
        let deviation = variance.squareRoot()
        guard deviation < 0.2 * mean else { return nil }
        return Cadence(count: intervals.count, mean: mean, variation: deviation / mean)
    }

    private static func dnsBurst(_ observation: FlowObservation, protocols: Set<String>) -> (packets: Int, seconds: Int)? {
        guard observation.key.remote.port == 53 || protocols.contains("DNS") else { return nil }
        guard let first = observation.packetTimes.min(), let last = observation.packetTimes.max() else { return nil }
        let span = last.timeIntervalSince(first)
        guard observation.packetTimes.count > 100, span < 60 else { return nil }
        return (observation.packetTimes.count, Int(span.rounded()))
    }

    private static func idleSpan(_ observation: FlowObservation) -> (minutes: Int, bytes: Int)? {
        guard let first = observation.packetTimes.min(), let last = observation.packetTimes.max() else { return nil }
        let span = last.timeIntervalSince(first)
        guard span > 600, observation.byteCount < 1024 else { return nil }
        return (Int(span / 60), observation.byteCount)
    }

    private static func isTransportOnly(_ protocols: Set<String>, port: UInt16) -> Bool {
        !protocols.isEmpty && protocols.isSubset(of: transportProtocols) && !wellKnownPorts.contains(port)
    }

    /// One stray datagram to a closed port is ordinary noise on a LAN and on the internet, so the
    /// unreliable transports need repetition before inbound traffic counts as someone knocking.
    private static func carriesRepetition(_ observation: FlowObservation) -> Bool {
        observation.key.transport == .tcp || observation.packetTimes.count >= 3
    }
}

private extension FlowObservation {
    /// The port a client connects to. In an inbound conversation the remote port is the sender's
    /// ephemeral port, so the service being reached sits on the local side.
    var servicePort: UInt16 {
        direction == .inbound ? key.local.port : key.remote.port
    }

    /// A private, loopback, broadcast or multicast destination is not a remote resource under
    /// investigation, so not knowing its name says nothing about the machine.
    var hasNonPublicDestination: Bool {
        let host = key.remote.host
        if AddressScope.isPrivate(host) || AddressScope.isMulticastOrBroadcast(host) { return true }
        switch direction {
        case .multicast, .broadcast, .loopback: return true
        case .inbound, .outbound: return false
        }
    }
}
