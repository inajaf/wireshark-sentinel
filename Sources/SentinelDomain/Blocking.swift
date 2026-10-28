import Foundation

// MARK: - Block targets

public enum BlockDirection: String, Sendable, Codable, CaseIterable, Identifiable {
    case outbound
    case inbound
    case both

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .outbound: return "outbound"
        case .inbound: return "inbound"
        case .both: return "both directions"
        }
    }
}

public enum BlockTransport: String, Sendable, Codable, CaseIterable, Identifiable {
    case any
    case tcp
    case udp

    public var id: String { rawValue }
    public var pfName: String? {
        switch self {
        case .any: return nil
        case .tcp: return "tcp"
        case .udp: return "udp"
        }
    }

    public var label: String {
        switch self {
        case .any: return "TCP + UDP"
        case .tcp: return "TCP"
        case .udp: return "UDP"
        }
    }
}

/// The unit a person can block. pf understands addresses and ports, never a
/// process or a TLS server name, so the UI must not pretend otherwise.
public struct BlockTarget: Sendable, Codable, Hashable, Identifiable {
    public var address: String
    public var port: UInt16?
    public var transport: BlockTransport
    public var direction: BlockDirection
    public var note: String?
    public var sourceEndpoint: String?
    public var processName: String?

    public var id: String {
        "\(address)|\(port.map(String.init) ?? "*")|\(transport.rawValue)|\(direction.rawValue)"
    }

    public init(
        address: String,
        port: UInt16? = nil,
        transport: BlockTransport = .any,
        direction: BlockDirection = .both,
        note: String? = nil,
        sourceEndpoint: String? = nil,
        processName: String? = nil
    ) {
        self.address = address
        self.port = port
        self.transport = transport
        self.direction = direction
        self.note = note
        self.sourceEndpoint = sourceEndpoint
        self.processName = processName
    }

    public var displayName: String {
        let portText = port.map { ":\($0)" } ?? ""
        return "\(address)\(portText)"
    }

    public var isPortSpecific: Bool { port != nil }
    public var isCIDR: Bool { address.contains("/") }
}

// MARK: - Rules and plans

public struct PFRule: Sendable, Codable, Identifiable, Hashable {
    public var section: String
    public var text: String

    public var id: String { "\(section)|\(text)" }

    public init(section: String, text: String) {
        self.section = section
        self.text = text
    }
}

public struct BlockPlan: Sendable, Codable {
    public var targets: [BlockTarget]
    public var rules: [PFRule]
    public var warnings: [String]
    public var errors: [String]
    public var killExistingStates: Bool
    public var generatedAt: Date

    public init(
        targets: [BlockTarget],
        rules: [PFRule] = [],
        warnings: [String] = [],
        errors: [String] = [],
        killExistingStates: Bool = true,
        generatedAt: Date = Date()
    ) {
        self.targets = targets
        self.rules = rules
        self.warnings = warnings
        self.errors = errors
        self.killExistingStates = killExistingStates
        self.generatedAt = generatedAt
    }

    public var isValid: Bool { errors.isEmpty }
    public var isEmpty: Bool { targets.isEmpty }
}

public struct BlockState: Sendable, Codable {
    public var records: [BlockRecord]
    public var audit: [BlockAuditEntry]
    public var persistAfterReboot: Bool

    public init(
        records: [BlockRecord] = [],
        audit: [BlockAuditEntry] = [],
        persistAfterReboot: Bool = false
    ) {
        self.records = records
        self.audit = audit
        self.persistAfterReboot = persistAfterReboot
    }

    public var activeRecords: [BlockRecord] {
        records.filter { $0.active }
    }

    public var activeTargets: [BlockTarget] {
        var seen = Set<String>()
        return activeRecords.map { $0.target }.filter { seen.insert($0.id).inserted }
    }
}

public struct BlockRecord: Sendable, Codable, Identifiable, Hashable {
    public var id: UUID
    public var target: BlockTarget
    public var reason: String
    public var createdAt: Date
    public var appliedAt: Date?
    public var active: Bool
    public var ruleText: String

    public init(
        id: UUID = UUID(),
        target: BlockTarget,
        reason: String,
        createdAt: Date = Date(),
        appliedAt: Date? = nil,
        active: Bool = false,
        ruleText: String = ""
    ) {
        self.id = id
        self.target = target
        self.reason = reason
        self.createdAt = createdAt
        self.appliedAt = appliedAt
        self.active = active
        self.ruleText = ruleText
    }
}

public struct BlockAuditEntry: Sendable, Codable, Identifiable, Hashable {
    public var id: UUID
    public var at: Date
    public var action: String
    public var targets: [String]
    public var result: String
    public var detail: String?

    public init(
        id: UUID = UUID(),
        at: Date = Date(),
        action: String,
        targets: [String],
        result: String,
        detail: String? = nil
    ) {
        self.id = id
        self.at = at
        self.action = action
        self.targets = targets
        self.result = result
        self.detail = detail
    }
}
