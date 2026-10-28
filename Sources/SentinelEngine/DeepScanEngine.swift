import Foundation
import CryptoKit
import SentinelDomain

// MARK: - Errors

public enum DeepScanError: Error, CustomStringConvertible, Sendable {
    case noCaptureFile
    case invalidTarget(String)
    case engineFailed(String)
    case noPackets

    public var description: String {
        switch self {
        case .noCaptureFile:
            return "there is no capture file to scan"
        case .invalidTarget(let target):
            return "\(target) is not an IPv4 or IPv6 address"
        case .engineFailed(let message):
            return "the Wireshark engine failed: \(message)"
        case .noPackets:
            return "no packets in the capture matched this conversation"
        }
    }
}

// MARK: - Request

public struct DeepScanRequest: Sendable {
    public let flow: FlowKey
    public let captureFile: URL
    public let options: ScanOptions
    public let socket: SocketDetails?
    public let process: ProcessIdentity?
    public let identity: EndpointIdentity?
    public let reverseDNS: String?

    public init(
        flow: FlowKey,
        captureFile: URL,
        options: ScanOptions = .preset(.deep),
        socket: SocketDetails? = nil,
        process: ProcessIdentity? = nil,
        identity: EndpointIdentity? = nil,
        reverseDNS: String? = nil
    ) {
        self.flow = flow
        self.captureFile = captureFile
        self.options = options
        self.socket = socket
        self.process = process
        self.identity = identity
        self.reverseDNS = reverseDNS
    }
}

// MARK: - Scanner

/// Reads one conversation out of the capture file and turns it into a report a
/// person can read. It is deliberately on demand: doing this per packet would
/// make live capture slow and would scan the same bytes again and again.
public struct TSharkDeepScanner: Sendable {
    private let install: WiresharkInstall

    public init(install: WiresharkInstall) {
        self.install = install
    }

    public func scan(_ request: DeepScanRequest) async throws -> ConnectionDetails {
        guard FileManager.default.fileExists(atPath: request.captureFile.path) else {
            throw DeepScanError.noCaptureFile
        }

        let classification = IPClassifier.classify(request.flow.remote.host)
        guard classification.scope != .unknown else {
            throw DeepScanError.invalidTarget(request.flow.remote.host)
        }

        let filter = Self.displayFilter(for: request.flow)
        let fields = try Self.run(
            install.tshark,
            ["-r", request.captureFile.path, "-n", "-2", "-Y", filter, "-T", "fields",
             "-E", "occurrence=a"] + Self.fieldArguments
        )
        let rows = Self.rows(from: fields)

        var warnings: [String] = []
        var tlsMetadata: TLSMetadata?
        var certificates: [CertificateSummary] = []

        if request.options.analyzeTLS {
            do {
                let pdml = try Self.run(
                    install.tshark,
                    ["-r", request.captureFile.path, "-n", "-2", "-Y",
                     "(\(filter)) && (tls.handshake.type==1 || tls.handshake.type==2 || tls.handshake.type==11)",
                     "-T", "pdml"]
                )
                let parsed = Self.parsePDML(pdml)
                tlsMetadata = parsed.tls
                certificates = parsed.certificates
            } catch {
                warnings.append("The TLS handshake was present but its certificate chain could not be read from the capture.")
            }
        }

        if rows.isEmpty {
            warnings.append("No packets matched this conversation in the capture file. It may have rotated, or the conversation started before the capture.")
        }

        return Self.build(
            request: request,
            classification: classification,
            rows: rows,
            tlsMetadata: tlsMetadata,
            certificates: certificates,
            warnings: warnings
        )
    }

    // MARK: - tshark invocation

    private static func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        do {
            try process.run()
        } catch {
            throw DeepScanError.engineFailed("could not start \(executable)")
        }

        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorData = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let message = String(decoding: errorData, as: UTF8.self)
                .split(separator: "\n")
                .first.map(String.init) ?? "exit status \(process.terminationStatus)"
            throw DeepScanError.engineFailed(message)
        }
        return String(decoding: data, as: UTF8.self)
    }

    /// Exact stream filters are better than address filters when the capture
    /// started after the conversation began, but a conversation can rotate its
    /// local port. Address plus the remote service port is the stable identity.
    static func displayFilter(for flow: FlowKey) -> String {
        var host = flow.remote.host
        if host.hasPrefix("["), host.hasSuffix("]") {
            host = String(host.dropFirst().dropLast())
        }
        if let percent = host.firstIndex(of: "%") {
            host = String(host[..<percent])
        }

        let addressField = host.contains(":") ? "ipv6.addr" : "ip.addr"
        var clauses = ["\(addressField)==\(host)"]
        if flow.remote.port != 0 {
            switch flow.transport {
            case .tcp: clauses.append("tcp.port==\(flow.remote.port)")
            case .udp: clauses.append("udp.port==\(flow.remote.port)")
            case .other: break
            }
        }
        return clauses.joined(separator: " && ")
    }

    // MARK: - Field rows

    private static let fieldNames: [String] = [
        "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
        "ip.src", "ip.dst", "ip.ttl", "ip.flags.df", "ip.flags.mf", "ip.frag_offset",
        "ip.dsfield.dscp", "ip.dsfield.ecn",
        "ipv6.src", "ipv6.dst", "ipv6.hlim", "ipv6.flow",
        "tcp.stream", "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.flags.str",
        "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset", "tcp.len",
        "tcp.analysis.initial_rtt", "tcp.analysis.ack_rtt", "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission", "tcp.analysis.duplicate_ack",
        "tcp.analysis.out_of_order", "tcp.analysis.zero_window", "tcp.analysis.keep_alive",
        "tcp.options.mss_val", "tcp.options.wscale.shift", "tcp.options.sack_perm",
        "tcp.options.timestamp.tsval", "tcp.completeness",
        "udp.stream", "udp.length",
        "tls.handshake.type", "tls.handshake.version", "tls.handshake.ciphersuite",
        "tls.record.version", "tls.handshake.extensions_alpn_str",
        "tls.handshake.extensions_server_name", "tls.handshake.ja3", "tls.handshake.ja3_full",
        "tls.handshake.ja4", "tls.handshake.ja4_r",
        "tls.handshake.extensions_supported_group", "tls.handshake.sig_hash_alg",
        "http.request.method", "http.host", "http.request.uri", "http.user_agent",
        "http.server", "http.response.code", "http.content_type",
        "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.cname", "dns.resp.name",
        "quic.version", "ssh.protocol", "ssh.kex_algorithms",
        "dhcp.option.hostname", "dhcp.option.vendor_class_id",
    ]

    private static var fieldArguments: [String] {
        fieldNames.flatMap { ["-e", $0] }
    }

    private static func rows(from output: String) -> [Row] {
        output.split(separator: "\n", omittingEmptySubsequences: true).compactMap { line in
            let columns = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard !columns.allSatisfy({ $0.isEmpty }) else { return nil }
            var values: [String: String] = [:]
            for (index, name) in fieldNames.enumerated() where index < columns.count {
                let value = columns[index]
                if !value.isEmpty { values[name] = value }
            }
            return Row(values: values)
        }
    }

    private struct Row {
        let values: [String: String]

        func raw(_ name: String) -> String? {
            guard let value = values[name]?.trimmingCharacters(in: .whitespaces), !value.isEmpty else { return nil }
            return value
        }

        func first(_ name: String) -> String? {
            guard let value = raw(name) else { return nil }
            return value.split(separator: ",", omittingEmptySubsequences: true)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .first { !$0.isEmpty }
        }

        func list(_ name: String) -> [String] {
            guard let value = raw(name) else { return [] }
            return value.split(separator: ",", omittingEmptySubsequences: true)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }

        func int(_ name: String) -> Int? {
            guard let value = first(name) else { return nil }
            if let number = Int(value) { return number }
            if let number = Int(value, radix: 16) { return number }
            return nil
        }

        func double(_ name: String) -> Double? {
            first(name).flatMap { Double($0) }
        }

        func bool(_ name: String) -> Bool {
            guard let value = first(name)?.lowercased() else { return false }
            return value == "1" || value == "true" || value == "yes" || value == "set"
        }
    }

    // MARK: - Building the report

    private static func build(
        request: DeepScanRequest,
        classification: IPClassification,
        rows: [Row],
        tlsMetadata: TLSMetadata?,
        certificates: [CertificateSummary],
        warnings: [String]
    ) -> ConnectionDetails {
        let localHost = request.flow.local.host
        let remoteHost = request.flow.remote.host
        let times = rows.compactMap { $0.double("frame.time_epoch") }.map { Date(timeIntervalSince1970: $0) }
        let firstSeen = times.min()
        let lastSeen = times.max()

        var bytesSent = 0
        var bytesReceived = 0
        var packetsSent = 0
        var packetsReceived = 0
        var tcpStreams = Set<Int>()
        var udpStreams = Set<Int>()
        var synCount = 0
        var synAckCount = 0
        var finCount = 0
        var rstCount = 0
        var retransmissions = 0
        var fastRetransmissions = 0
        var duplicateACKs = 0
        var outOfOrder = 0
        var zeroWindow = 0
        var keepAlives = 0
        var initialRTT: Double?
        var lastRTT: Double?
        var mss: Int?
        var windowScale: Int?
        var sackPermitted = false
        var timestamps = false
        var completeness: String?
        var ttl: Int?
        var dontFragment: Bool?
        var fragmented = false
        var dscp: Int?
        var ecn: Int?
        var ipv6Flow: String?
        var versions = Set<String>()
        var cipher: String?
        var alpn: [String] = []
        var serverName: String?
        var ja3: String?
        var ja3Full: String?
        var ja4: String?
        var ja4R: String?
        var supportedGroups: [String] = []
        var signatureAlgorithms: [String] = []
        var handshakeFrames = Set<Int>()
        var protocols = Set<String>()
        var httpMethods: [String] = []
        var httpHosts: [String] = []
        var httpURIs: [String] = []
        var httpUserAgents: [String] = []
        var httpServers: [String] = []
        var httpStatusCodes: [String] = []
        var httpContentTypes: [String] = []
        var dnsQueries: [String] = []
        var dnsAnswers: [String] = []
        var dnsTypes: [String] = []
        var quicVersions: [String] = []
        var sshProtocols: [String] = []
        var sshKeyExchange: [String] = []
        var dhcpHostnames: [String] = []

        for row in rows {
            let source = row.first("ip.src") ?? row.first("ipv6.src") ?? ""
            let fromLocal = source == localHost || (localHost.isEmpty && source != remoteHost)
            let length = row.int("frame.len") ?? 0

            if fromLocal {
                bytesSent += length
                packetsSent += 1
            } else {
                bytesReceived += length
                packetsReceived += 1
            }

            if let stream = row.int("tcp.stream") { tcpStreams.insert(stream) }
            if let stream = row.int("udp.stream") { udpStreams.insert(stream) }

            let syn = row.bool("tcp.flags.syn")
            let ack = row.bool("tcp.flags.ack")
            if syn && ack { synAckCount += 1 } else if syn { synCount += 1 }
            if row.bool("tcp.flags.fin") { finCount += 1 }
            if row.bool("tcp.flags.reset") { rstCount += 1 }
            if row.bool("tcp.analysis.retransmission") { retransmissions += 1 }
            if row.bool("tcp.analysis.fast_retransmission") { fastRetransmissions += 1 }
            if row.bool("tcp.analysis.duplicate_ack") { duplicateACKs += 1 }
            if row.bool("tcp.analysis.out_of_order") { outOfOrder += 1 }
            if row.bool("tcp.analysis.zero_window") { zeroWindow += 1 }
            if row.bool("tcp.analysis.keep_alive") { keepAlives += 1 }
            if initialRTT == nil, let value = row.double("tcp.analysis.initial_rtt") { initialRTT = value }
            if let value = row.double("tcp.analysis.ack_rtt") { lastRTT = value }
            if mss == nil { mss = row.int("tcp.options.mss_val") }
            if windowScale == nil { windowScale = row.int("tcp.options.wscale.shift") }
            if row.bool("tcp.options.sack_perm") { sackPermitted = true }
            if row.bool("tcp.options.timestamp.tsval") { timestamps = true }
            if let value = row.raw("tcp.completeness") { completeness = value }

            if !fromLocal {
                if ttl == nil { ttl = row.int("ip.ttl") ?? row.int("ipv6.hlim") }
                if dontFragment == nil, let value = row.raw("ip.flags.df") {
                    dontFragment = value.lowercased() == "true" || value == "1"
                }
                if row.bool("ip.flags.mf") || (row.int("ip.frag_offset") ?? 0) > 0 { fragmented = true }
                if dscp == nil { dscp = row.int("ip.dsfield.dscp") }
                if ecn == nil { ecn = row.int("ip.dsfield.ecn") }
                if ipv6Flow == nil { ipv6Flow = row.raw("ipv6.flow") }
            }

            if let type = row.raw("tls.handshake.type"), !type.isEmpty {
                if let frame = row.int("frame.number") { handshakeFrames.insert(frame) }
            }
            for version in row.list("tls.handshake.version") { versions.insert(version) }
            if cipher == nil { cipher = row.first("tls.handshake.ciphersuite") }
            alpn.append(contentsOf: row.list("tls.handshake.extensions_alpn_str"))
            if serverName == nil { serverName = row.first("tls.handshake.extensions_server_name") }
            if ja3 == nil { ja3 = row.first("tls.handshake.ja3") }
            if ja3Full == nil { ja3Full = row.first("tls.handshake.ja3_full") }
            if ja4 == nil { ja4 = row.first("tls.handshake.ja4") }
            if ja4R == nil { ja4R = row.first("tls.handshake.ja4_r") }
            supportedGroups.append(contentsOf: row.list("tls.handshake.extensions_supported_group"))
            signatureAlgorithms.append(contentsOf: row.list("tls.handshake.sig_hash_alg"))

            if let value = row.raw("frame.protocols") {
                for proto in value.split(separator: ":") {
                    let name = String(proto)
                    if !["eth", "ethertype", "ip", "ipv6", "tcp", "udp", "frame"].contains(name) {
                        protocols.insert(name)
                    }
                }
            }

            appendUnique(row.first("http.request.method"), to: &httpMethods)
            appendUnique(row.first("http.host"), to: &httpHosts)
            appendUnique(row.first("http.request.uri"), to: &httpURIs)
            appendUnique(row.first("http.user_agent"), to: &httpUserAgents)
            appendUnique(row.first("http.server"), to: &httpServers)
            appendUnique(row.first("http.response.code"), to: &httpStatusCodes)
            appendUnique(row.first("http.content_type"), to: &httpContentTypes)
            dnsQueries.append(contentsOf: row.list("dns.qry.name"))
            dnsTypes.append(contentsOf: row.list("dns.qry.type"))
            dnsAnswers.append(contentsOf: row.list("dns.a"))
            dnsAnswers.append(contentsOf: row.list("dns.aaaa"))
            dnsAnswers.append(contentsOf: row.list("dns.cname"))
            appendUnique(row.first("quic.version"), to: &quicVersions)
            appendUnique(row.first("ssh.protocol"), to: &sshProtocols)
            appendUnique(row.first("ssh.kex_algorithms"), to: &sshKeyExchange)
            appendUnique(row.first("dhcp.option.hostname"), to: &dhcpHostnames)
        }

        let duration = firstSeen.flatMap { first in lastSeen.map { $0.timeIntervalSince(first) } }
        let tcp = request.flow.transport == .tcp ? TCPDetails(
            state: request.socket?.state,
            streams: tcpStreams.sorted(),
            synCount: synCount,
            synAckCount: synAckCount,
            finCount: finCount,
            rstCount: rstCount,
            retransmissions: retransmissions,
            fastRetransmissions: fastRetransmissions,
            duplicateACKs: duplicateACKs,
            outOfOrder: outOfOrder,
            zeroWindow: zeroWindow,
            keepAlives: keepAlives,
            initialRTT: initialRTT,
            lastRTT: lastRTT,
            mss: mss,
            windowScale: windowScale,
            sackPermitted: sackPermitted ? true : nil,
            timestamps: timestamps ? true : nil,
            completeness: completeness,
            bytesSent: bytesSent,
            bytesReceived: bytesReceived,
            packetsSent: packetsSent,
            packetsReceived: packetsReceived
        ) : nil

        let udp = request.flow.transport == .udp ? UDPDetails(
            streams: udpStreams.sorted(),
            bytesSent: bytesSent,
            bytesReceived: bytesReceived,
            packetsSent: packetsSent,
            packetsReceived: packetsReceived
        ) : nil

        let tls = TLSDetails(
            version: tlsMetadata?.version ?? highestTLSVersion(versions),
            cipherSuite: tlsMetadata?.cipherSuite ?? cipher,
            cipherSuiteName: tlsMetadata?.cipherName ?? cipher.map(Self.cipherName),
            alpn: unique(alpn),
            serverName: tlsMetadata?.serverName ?? serverName,
            ja3: tlsMetadata?.ja3 ?? ja3,
            ja3Full: tlsMetadata?.ja3Full ?? ja3Full,
            ja4: tlsMetadata?.ja4 ?? ja4,
            ja4R: tlsMetadata?.ja4R ?? ja4R,
            handshakeFrames: handshakeFrames.sorted(),
            supportedGroups: unique(supportedGroups),
            signatureAlgorithms: unique(signatureAlgorithms),
            certificates: certificates
        )

        let application = ApplicationDetails(
            protocols: protocols.sorted(),
            httpMethods: unique(httpMethods),
            httpHosts: unique(httpHosts),
            httpURIs: unique(httpURIs),
            httpUserAgents: unique(httpUserAgents),
            httpServers: unique(httpServers),
            httpStatusCodes: unique(httpStatusCodes),
            httpContentTypes: unique(httpContentTypes),
            dnsQueries: unique(dnsQueries),
            dnsAnswers: unique(dnsAnswers),
            dnsRecordTypes: unique(dnsTypes),
            quicVersions: unique(quicVersions),
            sshProtocols: unique(sshProtocols),
            sshKeyExchange: unique(sshKeyExchange),
            dhcpHostnames: unique(dhcpHostnames),
            mdnsNames: unique(dnsQueries.filter { _ in protocols.contains("mdns") })
        )

        var network = NetworkDetails(
            address: remoteHost,
            family: classification.family,
            scope: classification.scope.label,
            reverseDNS: request.reverseDNS,
            organization: request.identity?.organization,
            firstSeen: firstSeen,
            lastSeen: lastSeen,
            bytesSent: bytesSent,
            bytesReceived: bytesReceived,
            packetsSent: packetsSent,
            packetsReceived: packetsReceived
        )
        network.ttl = ttl
        network.estimatedHops = ttl.map { value in
            let initial = value <= 64 ? 64 : (value <= 128 ? 128 : 255)
            return max(0, initial - value)
        }
        network.dontFragment = dontFragment
        network.fragmentation = fragmented ? "fragmented" : "not fragmented"
        network.dscp = dscp
        network.ecn = ecn
        network.ipv6FlowLabel = ipv6Flow

        let transport = TransportDetails(tcp: tcp, udp: udp, duration: duration)

        var warnings = warnings
        if tlsMetadata == nil, !handshakeFrames.isEmpty {
            warnings.append("TLS metadata was read from fields only; the certificate chain is unavailable.")
        }
        if !handshakeFrames.isEmpty, certificates.isEmpty {
            warnings.append("A TLS handshake was seen but no certificate was available. TLS 1.3 usually encrypts certificates.")
        }

        let observations = makeObservations(
            request: request,
            classification: classification,
            network: network,
            transport: transport,
            tls: tls,
            application: application,
            certificates: certificates
        )

        return ConnectionDetails(
            flow: request.flow,
            scannedAt: Date(),
            captureFile: request.captureFile.path,
            packetCount: rows.count,
            firstSeen: firstSeen,
            lastSeen: lastSeen,
            network: network,
            transport: transport,
            tls: tls,
            application: application,
            socket: request.socket,
            process: request.process,
            observations: observations,
            warnings: warnings
        )
    }

    private static func appendUnique(_ value: String?, to list: inout [String]) {
        guard let value, !value.isEmpty, !list.contains(value) else { return }
        list.append(value)
    }

    private static func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    private static func highestTLSVersion(_ versions: Set<String>) -> String? {
        let rank: [String: Int] = [
            "0x0300": 0, "0x0301": 1, "0x0302": 2, "0x0303": 3, "0x0304": 4,
        ]
        guard let best = versions.max(by: { (rank[$0] ?? -1) < (rank[$1] ?? -1) }) else { return nil }
        return tlsVersionName(best)
    }

    private static func tlsVersionName(_ value: String) -> String {
        switch value.lowercased() {
        case "0x0300", "ssl3.0": return "SSL 3.0"
        case "0x0301", "tls1.0": return "TLS 1.0"
        case "0x0302", "tls1.1": return "TLS 1.1"
        case "0x0303", "tls1.2": return "TLS 1.2"
        case "0x0304", "tls1.3": return "TLS 1.3"
        default: return value
        }
    }

    private static func cipherName(_ value: String) -> String {
        cipherNames[value.lowercased()] ?? value
    }

    private static let cipherNames: [String: String] = [
        "0x1301": "TLS_AES_128_GCM_SHA256",
        "0x1302": "TLS_AES_256_GCM_SHA384",
        "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
        "0xcca8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "0xcca9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "0xc013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "0xc014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "0xc009": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "0xc00a": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "0x009c": "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "0x009d": "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
        "0x000a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    ]

    // MARK: - Observations

    private static func makeObservations(
        request: DeepScanRequest,
        classification: IPClassification,
        network: NetworkDetails,
        transport: TransportDetails,
        tls: TLSDetails,
        application: ApplicationDetails,
        certificates: [CertificateSummary]
    ) -> [ConnectionObservation] {
        var observations: [ConnectionObservation] = [
            ConnectionObservation(
                section: "Network",
                label: "Remote address",
                value: network.address,
                source: .packets
            ),
            ConnectionObservation(
                section: "Network",
                label: "Address scope",
                value: "\(network.family), \(network.scope)",
                source: .inferred,
                confidence: .observed
            ),
            ConnectionObservation(
                section: "Network",
                label: "Bytes sent / received",
                value: "\(network.bytesSent) / \(network.bytesReceived)",
                source: .packets
            ),
        ]
        if let reverse = network.reverseDNS {
            observations.append(ConnectionObservation(section: "Network", label: "Reverse DNS", value: reverse, source: .dns, confidence: .inferred))
        }
        if let hops = network.estimatedHops {
            observations.append(ConnectionObservation(section: "Network", label: "Estimated hops", value: "\(hops) (from TTL \(network.ttl ?? 0))", source: .inferred))
        }
        if let tcp = transport.tcp {
            observations.append(ConnectionObservation(section: "Transport", label: "TCP state", value: tcp.state ?? "not in the socket table", source: .lsof, confidence: tcp.state == nil ? .unknown : .observed))
            observations.append(ConnectionObservation(section: "Transport", label: "Streams", value: tcp.streams.map(String.init).joined(separator: ", "), source: .tshark))
            if let rtt = tcp.initialRTT {
                observations.append(ConnectionObservation(section: "Transport", label: "Initial RTT", value: String(format: "%.2f ms", rtt * 1000), source: .tshark))
            }
            observations.append(ConnectionObservation(section: "Transport", label: "Retransmissions", value: "\(tcp.retransmissions)", source: .tshark))
        }
        if let version = tls.version {
            observations.append(ConnectionObservation(section: "TLS", label: "Version", value: version, source: .tshark))
        }
        if let cipher = tls.cipherSuiteName ?? tls.cipherSuite {
            observations.append(ConnectionObservation(section: "TLS", label: "Cipher suite", value: cipher, source: .tshark))
        }
        if let alpn = tls.alpn.first {
            observations.append(ConnectionObservation(section: "TLS", label: "ALPN", value: tls.alpn.joined(separator: ", "), source: .tshark))
            _ = alpn
        }
        if let sni = tls.serverName {
            observations.append(ConnectionObservation(section: "TLS", label: "Server name (SNI)", value: sni, source: .packets))
        }
        if let ja4 = tls.ja4 {
            observations.append(ConnectionObservation(section: "TLS", label: "JA4 fingerprint", value: ja4, source: .tshark))
        }
        for certificate in certificates {
            if let subject = certificate.subject {
                observations.append(ConnectionObservation(section: "Certificate", label: "Subject", value: subject, source: .certificate))
            }
            if let issuer = certificate.issuer {
                observations.append(ConnectionObservation(section: "Certificate", label: "Issuer", value: issuer, source: .certificate))
            }
            if !certificate.subjectAlternativeNames.isEmpty {
                observations.append(ConnectionObservation(section: "Certificate", label: "Subject alternative names", value: certificate.subjectAlternativeNames.joined(separator: ", "), source: .certificate))
            }
        }
        if !application.httpHosts.isEmpty {
            observations.append(ConnectionObservation(section: "Application", label: "HTTP host", value: application.httpHosts.joined(separator: ", "), source: .packets))
        }
        if !application.dnsQueries.isEmpty {
            observations.append(ConnectionObservation(section: "Application", label: "DNS questions", value: application.dnsQueries.joined(separator: ", "), source: .packets))
        }
        if let process = request.process {
            observations.append(ConnectionObservation(section: "Process", label: "Owner", value: "\(process.name) (pid \(process.pid))", source: .process))
        }
        observations.append(ConnectionObservation(section: "Scan", label: "Depth", value: request.options.depth.title, source: .userInput))
        observations.append(ConnectionObservation(section: "Scan", label: "Scope note", value: classification.explanation, source: .inferred))
        return observations
    }

    // MARK: - PDML parsing

    private struct TLSMetadata {
        var version: String?
        var cipherSuite: String?
        var cipherName: String?
        var alpn: [String] = []
        var serverName: String?
        var ja3: String?
        var ja3Full: String?
        var ja4: String?
        var ja4R: String?
    }

    private static func parsePDML(_ text: String) -> (tls: TLSMetadata?, certificates: [CertificateSummary]) {
        guard !text.isEmpty, let data = text.data(using: .utf8) else { return (nil, []) }
        let delegate = PDMLDelegate()
        let parser = XMLParser(data: data)
        parser.delegate = delegate
        guard parser.parse(), let root = delegate.root else { return (nil, []) }

        var metadata = TLSMetadata()
        var sawTLS = false

        if let version = root.firstDescendant(named: "tls.handshake.version") {
            sawTLS = true
            metadata.version = labelValue(version.showname, prefix: "Version: ").flatMap(beforeParenthesis)
                ?? version.show
        }
        if let cipher = root.firstDescendant(named: "tls.handshake.ciphersuite") {
            sawTLS = true
            let label = labelValue(cipher.showname, prefix: "Cipher Suite: ").flatMap(beforeParenthesis)
            let hex = cipher.show
            metadata.cipherSuite = hex.isEmpty ? nil : hex
            metadata.cipherName = label
        }
        metadata.alpn = root.descendants(named: "tls.handshake.extensions_alpn_str")
            .compactMap { $0.show.isEmpty ? nil : $0.show }
        metadata.serverName = root.firstDescendant(named: "tls.handshake.extensions_server_name")?.show
        metadata.ja3 = root.firstDescendant(named: "tls.handshake.ja3")?.show
        metadata.ja3Full = root.firstDescendant(named: "tls.handshake.ja3_full")?.show
        metadata.ja4 = root.firstDescendant(named: "tls.handshake.ja4")?.show
        metadata.ja4R = root.firstDescendant(named: "tls.handshake.ja4_r")?.show
        if metadata.serverName?.isEmpty == true { metadata.serverName = nil }
        if metadata.ja3?.isEmpty == true { metadata.ja3 = nil }
        if metadata.ja4?.isEmpty == true { metadata.ja4 = nil }
        if !metadata.alpn.isEmpty || metadata.cipherSuite != nil || metadata.serverName != nil {
            sawTLS = true
        }

        var certificates: [CertificateSummary] = []
        var seen = Set<String>()
        let certNodes = root.descendants(named: "tls.handshake.certificate")
        for (index, node) in certNodes.enumerated() {
            guard let certificate = certificate(from: node, index: index) else { continue }
            let key = certificate.sha256 ?? certificate.serialNumber ?? certificate.subject ?? "\(index)"
            guard seen.insert(key).inserted else { continue }
            certificates.append(certificate)
        }

        return (sawTLS ? metadata : nil, certificates)
    }

    private static func certificate(from node: PDMLNode, index: Int) -> CertificateSummary? {
        guard !node.children.isEmpty || !node.value.isEmpty || !node.show.isEmpty else { return nil }

        let subjectNode = node.firstDescendant(named: "x509af.subject")
        let issuerNode = node.firstDescendant(named: "x509af.issuer")
        let subject = subjectNode.flatMap(rdnSequence)
        let issuer = issuerNode.flatMap(rdnSequence)
        let commonName = subject.flatMap { extractRDN($0, "id-at-commonName") }
        let organization = subject.flatMap { extractRDN($0, "id-at-organizationName") }
        let sans = subjectAlternativeNames(in: node)
        let notBefore = date(from: node.firstDescendant(named: "x509af.notBefore"))
        let notAfter = date(from: node.firstDescendant(named: "x509af.notAfter"))
        let serial = node.firstDescendant(named: "x509af.serialNumber").flatMap { valueAfterColon($0.showname) }
        let signature = node.firstDescendant(named: "x509af.signature_element").flatMap { valueAfterColon($0.showname) }
            ?? node.firstDescendant(named: "x509af.algorithm.id").flatMap { valueAfterColon($0.showname) }
        let keyAlgorithm = node.firstDescendant(named: "x509af.subjectPublicKeyInfo_element")?
            .firstDescendant(named: "x509af.algorithm.id").flatMap { valueAfterColon($0.showname) }
        let curve = node.firstDescendant(named: "pkixalgs.namedCurve").flatMap { valueAfterColon($0.showname) }
        let isCA = node.firstDescendant(named: "x509ce.cA").map { $0.show.lowercased() == "true" || $0.show == "1" }
        let sha256 = sha256(ofHex: node.value)

        let now = Date()
        let expired = notAfter.map { $0 < now }
        let days = notAfter.flatMap { Calendar.current.dateComponents([.day], from: now, to: $0).day }

        return CertificateSummary(
            index: index,
            subject: subject,
            issuer: issuer,
            commonName: commonName,
            organization: organization,
            subjectAlternativeNames: sans,
            notBefore: notBefore,
            notAfter: notAfter,
            serialNumber: serial,
            signatureAlgorithm: signature,
            publicKeyAlgorithm: keyAlgorithm,
            curve: curve,
            sha256: sha256,
            isCA: isCA,
            isExpired: expired,
            daysRemaining: days
        )
    }

    private static func rdnSequence(_ node: PDMLNode) -> String? {
        guard let rdn = node.firstDescendant(named: "x509af.rdnSequence")
            ?? node.firstDescendant(named: "x509if.rdnSequence") else { return nil }
        guard var text = labelValue(rdn.showname, prefix: "rdnSequence: ") else { return nil }
        if let open = text.firstIndex(of: "("), let close = text.lastIndex(of: ")"), open < close {
            text = String(text[text.index(after: open)..<close])
        }
        return text
            .replacingOccurrences(of: "id-at-commonName=", with: "CN=")
            .replacingOccurrences(of: "id-at-organizationName=", with: "O=")
            .replacingOccurrences(of: "id-at-organizationalUnitName=", with: "OU=")
            .replacingOccurrences(of: "id-at-countryName=", with: "C=")
            .replacingOccurrences(of: "id-at-localityName=", with: "L=")
            .replacingOccurrences(of: "id-at-stateOrProvinceName=", with: "ST=")
    }

    private static func extractRDN(_ text: String, _ key: String) -> String? {
        guard let range = text.range(of: "\(key)=") else { return nil }
        let tail = text[range.upperBound...]
        let value = tail.prefix { $0 != "," && $0 != ")" }
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// The SAN extension is a sibling of the subject, not a child of it. Scope the
    /// lookup to the extension with id-ce-subjectAltName so an issuer's names can
    /// never leak into the subject alternative names.
    private static func subjectAlternativeNames(in node: PDMLNode) -> [String] {
        for extensionNode in node.descendants(named: "x509af.Extension_element") {
            guard let identifier = extensionNode.firstDescendant(named: "x509af.extension.id"),
                  identifier.showname.contains("subjectAltName") else { continue }
            return extensionNode.descendants(named: "x509ce.dNSName")
                .compactMap { $0.show.isEmpty ? nil : $0.show }
        }
        return []
    }

    private static func date(from node: PDMLNode?) -> Date? {
        guard let node else { return nil }
        let timeNode = node.firstDescendant(named: "x509af.utcTime")
            ?? node.firstDescendant(named: "x509af.generalizedTime")
        guard let text = timeNode?.showname ?? timeNode?.show else { return nil }
        guard let value = labelValue(text, prefix: "utcTime: ")
            ?? labelValue(text, prefix: "generalizedTime: ") else { return nil }
        let cleaned = value.replacingOccurrences(of: " (UTC)", with: "").trimmingCharacters(in: .whitespaces)
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.date(from: cleaned)
    }

    private static func sha256(ofHex value: String) -> String? {
        var hex = value.replacingOccurrences(of: ":", with: "").replacingOccurrences(of: " ", with: "")
        guard !hex.isEmpty, hex.count % 2 == 0 else { return nil }
        if hex.hasPrefix("0x") { hex.removeFirst(2) }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func labelValue(_ text: String, prefix: String) -> String? {
        guard text.hasPrefix(prefix) else { return nil }
        let value = String(text.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
        return value.isEmpty ? nil : value
    }

    private static func beforeParenthesis(_ text: String) -> String {
        guard let range = text.range(of: " (") else { return text }
        return String(text[..<range.lowerBound]).trimmingCharacters(in: .whitespaces)
    }

    private static func valueAfterColon(_ text: String) -> String? {
        guard let colon = text.firstIndex(of: ":") else { return text.isEmpty ? nil : text }
        let value = text[text.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        return value.isEmpty ? nil : value
    }
}

// MARK: - PDML tree

private final class PDMLNode {
    let name: String
    let showname: String
    let show: String
    let value: String
    var children: [PDMLNode] = []

    init(name: String, showname: String = "", show: String = "", value: String = "") {
        self.name = name
        self.showname = showname
        self.show = show
        self.value = value
    }

    func descendants(named name: String) -> [PDMLNode] {
        var result: [PDMLNode] = []
        if self.name == name { result.append(self) }
        for child in children { result.append(contentsOf: child.descendants(named: name)) }
        return result
    }

    func firstDescendant(named name: String) -> PDMLNode? {
        if self.name == name { return self }
        for child in children {
            if let found = child.firstDescendant(named: name) { return found }
        }
        return nil
    }
}

private final class PDMLDelegate: NSObject, XMLParserDelegate {
    var root: PDMLNode?
    private var stack: [PDMLNode] = []

    func parser(
        _ parser: XMLParser,
        didStartElement elementName: String,
        namespaceURI: String?,
        qualifiedName qName: String?,
        attributes attributeDict: [String: String] = [:]
    ) {
        let node = PDMLNode(
            name: attributeDict["name"] ?? elementName,
            showname: attributeDict["showname"] ?? "",
            show: attributeDict["show"] ?? "",
            value: attributeDict["value"] ?? ""
        )
        if let parent = stack.last {
            parent.children.append(node)
        } else {
            root = node
        }
        stack.append(node)
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if !stack.isEmpty { stack.removeLast() }
    }
}
