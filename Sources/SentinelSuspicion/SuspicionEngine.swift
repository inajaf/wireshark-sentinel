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

    public init(
        key: FlowKey, direction: FlowDirection = .outbound, packetTimes: [Date] = [],
        byteCount: Int = 0, identity: EndpointIdentity = EndpointIdentity(),
        process: ProcessIdentity? = nil, protocols: Set<String> = [],
        sawPlaintext: Bool = false, isInboundInitiated: Bool = false
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

    public static let `default` = SuspicionPolicy(weights: [:])
}

/// Weighted signals in, one verdict out. Pure and offline.
public struct SuspicionEngine: Sendable {
    public init(policy: SuspicionPolicy = .default) {}

    public func signals(for observation: FlowObservation) -> [Signal] { [] }

    public func assess(_ observation: FlowObservation) -> FlowAssessment {
        FlowAssessment(
            key: observation.key,
            direction: observation.direction,
            identity: observation.identity,
            process: observation.process,
            signals: [],
            score: 0,
            verdict: .unknown,
            rationale: "",
            firstSeen: observation.packetTimes.first ?? Date(),
            lastSeen: observation.packetTimes.last ?? Date(),
            packetCount: observation.packetTimes.count,
            byteCount: observation.byteCount
        )
    }
}
