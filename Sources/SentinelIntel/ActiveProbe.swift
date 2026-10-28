import Foundation
import Network
import SentinelDomain

/// Active checking is deliberately not part of a scan. It opens a new connection,
/// which is visible to the far end, so it only runs when a person clicks the probe
/// button for one conversation. Loopback, group, link-local and unspecified
/// targets are refused outright.
public struct ActiveProber: Sendable {
    public init() {}

    public func probe(
        host: String,
        port: UInt16,
        kind: ActiveProbeKind = .tcpConnect,
        timeout: TimeInterval = 2,
        allowPrivate: Bool = false
    ) async -> ActiveProbeResult {
        let classification = IPClassifier.classify(host)
        switch classification.scope {
        case .publicInternet:
            break
        case .privateNetwork, .carrierGradeNAT:
            guard allowPrivate else {
                return Self.refused(
                    host: host,
                    port: port,
                    kind: kind,
                    reason: "\(host) is \(classification.scope.label). Turn on private-address probing to include it."
                )
            }
        default:
            return Self.refused(
                host: host,
                port: port,
                kind: kind,
                reason: "\(host) is \(classification.scope.label) and will not be probed."
            )
        }

        guard port != 0, let networkPort = NWEndpoint.Port(rawValue: port) else {
            return Self.refused(host: host, port: port, kind: kind, reason: "Port \(port) is not a usable TCP port.")
        }
        guard kind != .tlsCertificate else {
            return Self.refused(
                host: host,
                port: port,
                kind: kind,
                reason: "A TLS certificate probe is not implemented. The passive deep scan already reads certificates from the capture."
            )
        }

        return await ProbeSession(
            host: host,
            port: networkPort,
            kind: kind,
            timeout: timeout
        ).run()
    }

    private static func refused(
        host: String,
        port: UInt16,
        kind: ActiveProbeKind,
        reason: String
    ) -> ActiveProbeResult {
        ActiveProbeResult(
            host: host,
            port: port,
            kind: kind,
            opened: false,
            error: reason
        )
    }
}

// MARK: - One connection

final class ProbeSession: @unchecked Sendable {
    private let host: String
    private let port: NWEndpoint.Port
    private let kind: ActiveProbeKind
    private let timeout: TimeInterval
    private let startedAt = Date()
    private let queue = DispatchQueue(label: "com.local.sentinel.active-probe")

    private let lock = NSLock()
    private var finished = false
    private var continuation: CheckedContinuation<ActiveProbeResult, Never>?
    private var connection: NWConnection?
    private var received = Data()

    init(host: String, port: NWEndpoint.Port, kind: ActiveProbeKind, timeout: TimeInterval) {
        self.host = host
        self.port = port
        self.kind = kind
        self.timeout = timeout
    }

    func run() async -> ActiveProbeResult {
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: .tcp)
            self.connection = connection
            connection.stateUpdateHandler = { [weak self] state in
                self?.handle(state)
            }
            connection.start(queue: queue)
            let deadline = timeout
            queue.asyncAfter(deadline: .now() + deadline) { [weak self] in
                self?.finish(
                    opened: false,
                    error: "The probe timed out after \(String(format: "%.1f", deadline)) seconds."
                )
            }
        }
    }

    private func handle(_ state: NWConnection.State) {
        switch state {
        case .ready:
            let elapsed = Date().timeIntervalSince(startedAt)
            switch kind {
            case .tcpConnect, .tlsCertificate:
                finish(opened: true, elapsed: elapsed)
            case .httpHead:
                sendHTTP(elapsed: elapsed)
            case .banner:
                receiveBanner(elapsed: elapsed)
            }
        case .waiting(let error):
            finish(opened: false, elapsed: Date().timeIntervalSince(startedAt), error: error.localizedDescription)
        case .failed(let error):
            finish(opened: false, elapsed: Date().timeIntervalSince(startedAt), error: error.localizedDescription)
        case .cancelled:
            finish(opened: connectionOpened, error: "The probe was cancelled.")
        default:
            break
        }
    }

    private var connectionOpened = false

    private func sendHTTP(elapsed: TimeInterval) {
        connectionOpened = true
        let hostHeader = port.rawValue == 80 ? host : "\(host):\(port.rawValue)"
        let request = "HEAD / HTTP/1.1\r\nHost: \(hostHeader)\r\nUser-Agent: WiresharkSentinel/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        connection?.send(content: Data(request.utf8), completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error {
                self.finish(opened: true, elapsed: elapsed, error: "Connected, but the request could not be sent: \(error.localizedDescription)")
            } else {
                self.receiveHTTP(elapsed: elapsed)
            }
        })
    }

    private func receiveHTTP(elapsed: TimeInterval) {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data { self.received.append(data) }
            if let response = Self.parseHTTP(self.received) {
                self.finish(
                    opened: true,
                    elapsed: elapsed,
                    httpStatus: response.status,
                    httpServer: response.server
                )
            } else if self.received.count > 64_000 {
                self.finish(opened: true, elapsed: elapsed, error: "The response was too large to read.")
            } else if let error {
                self.finish(opened: true, elapsed: elapsed, error: "Connected, but the response failed: \(error.localizedDescription)")
            } else if isComplete {
                self.finish(opened: true, elapsed: elapsed, error: "The server closed the connection without a complete HTTP response.")
            } else {
                self.receiveHTTP(elapsed: elapsed)
            }
        }
    }

    private func receiveBanner(elapsed: TimeInterval) {
        connectionOpened = true
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 2_048) { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                let text = String(decoding: data.prefix(512), as: UTF8.self)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                self.finish(
                    opened: true,
                    elapsed: elapsed,
                    banner: text.isEmpty ? nil : text,
                    error: text.isEmpty ? "The service sent bytes that are not readable text." : nil
                )
            } else {
                self.finish(
                    opened: true,
                    elapsed: elapsed,
                    error: error.map { "Connected, but no banner arrived: \($0.localizedDescription)" } ?? "Connected, but no banner arrived."
                )
            }
        }
    }

    private func finish(
        opened: Bool,
        elapsed: TimeInterval? = nil,
        banner: String? = nil,
        httpStatus: Int? = nil,
        httpServer: String? = nil,
        error: String? = nil
    ) {
        lock.lock()
        if finished {
            lock.unlock()
            return
        }
        finished = true
        let continuation = self.continuation
        self.continuation = nil
        let connection = self.connection
        self.connection = nil
        lock.unlock()

        connection?.stateUpdateHandler = nil
        connection?.cancel()

        let result = ActiveProbeResult(
            host: host,
            port: port.rawValue,
            kind: kind,
            opened: opened,
            elapsed: elapsed ?? Date().timeIntervalSince(startedAt),
            banner: banner,
            httpStatus: httpStatus,
            httpServer: httpServer,
            error: error
        )
        continuation?.resume(returning: result)
    }

    // MARK: - HTTP

    struct HTTPAnswer: Equatable {
        var status: Int
        var server: String?
    }

    static func parseHTTP(_ data: Data) -> HTTPAnswer? {
        guard let text = String(data: data, encoding: .utf8),
              let headerEnd = text.range(of: "\r\n\r\n")
        else { return nil }
        let head = text[..<headerEnd.lowerBound]
        let lines = head.components(separatedBy: "\r\n")
        guard let statusLine = lines.first else { return nil }
        let parts = statusLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/"), let status = Int(parts[1]) else { return nil }
        let server = lines.dropFirst()
            .first { $0.lowercased().hasPrefix("server:") }
            .map { String($0.dropFirst("server:".count)).trimmingCharacters(in: .whitespaces) }
        return HTTPAnswer(status: status, server: server?.isEmpty == true ? nil : server)
    }
}
