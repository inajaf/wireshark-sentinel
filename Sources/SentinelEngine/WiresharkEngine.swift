import Foundation
import SentinelDomain

/// Where the installed Wireshark engine lives.
public struct WiresharkInstall: Sendable {
    public let appPath: String
    public let tshark: String
    public let dumpcap: String
    public let capinfos: String

    public init(appPath: String, tshark: String, dumpcap: String, capinfos: String) {
        self.appPath = appPath
        self.tshark = tshark
        self.dumpcap = dumpcap
        self.capinfos = capinfos
    }

    /// Locate the installed engine. Searches /Applications and ~/Applications.
    public static func locate() -> WiresharkInstall? {
        locate(appPaths: [
            "/Applications/Wireshark.app",
            NSHomeDirectory() + "/Applications/Wireshark.app",
        ])
    }

    /// A bundle counts only when all three executables are present and runnable.
    public static func locate(appPaths: [String]) -> WiresharkInstall? {
        for appPath in appPaths {
            let macos = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/MacOS")
            let binaries = ["tshark", "dumpcap", "capinfos"]
                .map { macos.appendingPathComponent($0).path }
            guard binaries.allSatisfy({ FileManager.default.isExecutableFile(atPath: $0) }) else { continue }
            return WiresharkInstall(
                appPath: appPath,
                tshark: binaries[0],
                dumpcap: binaries[1],
                capinfos: binaries[2]
            )
        }
        return nil
    }
}

public enum EngineError: Error, CustomStringConvertible {
    case processFailedToStart(String)
    case processExited(status: Int32, command: String)
    case noCaptureFile

    public var description: String {
        switch self {
        case .processFailedToStart(let command): return "could not start \(command)"
        case .processExited(let status, let command): return "\(command) exited with status \(status)"
        case .noCaptureFile: return "no capture file: start a capture before asking for detail"
        }
    }
}

/// Live capture and lazy dissection through the installed engine.
public final class TSharkEngine: CaptureEngine, @unchecked Sendable {
    private let install: WiresharkInstall
    private let durationLimit: TimeInterval?
    private let configuredCaptureFile: URL?
    private let lock = NSLock()
    private var process: Process?
    private var continuation: AsyncStream<PacketEvent>.Continuation?
    private var lineBuffer = Data()
    private var captureFile: URL?

    public init(install: WiresharkInstall, durationLimit: TimeInterval? = nil, captureFile: URL? = nil) {
        self.install = install
        self.durationLimit = durationLimit
        self.configuredCaptureFile = captureFile
    }

    public func interfaces() async -> [CaptureInterface] {
        guard let output = try? Self.run(install.tshark, ["-D"], mergeStderr: true) else { return [] }
        return Self.parseInterfaces(output)
    }

    /// `-w` runs beside `-T ek` so a frame can be dissected from the file it was captured into.
    public func start(_ filter: CaptureFilter) async throws -> AsyncStream<PacketEvent> {
        await stop()

        let file = configuredCaptureFile ?? Self.temporaryCaptureURL()
        try? FileManager.default.removeItem(at: file)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: install.tshark)
        process.arguments = Self.captureArguments(filter: filter, captureFile: file, durationLimit: durationLimit)
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        let (stream, continuation) = AsyncStream<PacketEvent>.makeStream()
        lock.withLock {
            self.process = process
            self.continuation = continuation
            self.captureFile = file
            self.lineBuffer.removeAll()
        }

        stdout.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            for line in self?.appendAndDrain(data) ?? [] {
                if let packet = EKPacketParser.packet(fromEKLine: line) {
                    continuation.yield(.packet(packet))
                }
            }
        }
        stderr.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            for line in text.split(separator: "\n")
            where !line.hasPrefix("Capturing on") && !line.contains("packets captured") && !line.contains("packets dropped") {
                self?.emit(.error(String(line)))
            }
        }
        process.terminationHandler = { [weak self] _ in self?.finishStream() }

        do {
            try process.run()
        } catch {
            finishStream()
            throw EngineError.processFailedToStart("\(install.tshark): \(error)")
        }
        return stream
    }

    public func stop() async {
        let (process, continuation) = lock.withLock { () -> (Process?, AsyncStream<PacketEvent>.Continuation?) in
            defer {
                self.process = nil
                self.continuation = nil
            }
            return (self.process, self.continuation)
        }

        if process?.isRunning == true { process?.terminate() }
        continuation?.finish()
    }

    public func detail(frameNumber: Int) async throws -> PacketDetail {
        let file = lock.withLock { captureFile }
        guard let file, FileManager.default.fileExists(atPath: file.path) else { throw EngineError.noCaptureFile }

        let filter = "frame.number==\(frameNumber)"
        let json = try Self.run(install.tshark, ["-r", file.path, "-Y", filter, "-T", "json"])
        let hex = try Self.run(install.tshark, ["-r", file.path, "-x", "-Y", filter])
        return DetailParser.detail(json: Data(json.utf8), hexDump: hex, frameNumber: frameNumber)
    }

    static func parseInterfaces(_ output: String) -> [CaptureInterface] {
        output.split(separator: "\n").compactMap { rawLine in
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard let dot = line.firstIndex(of: ".") else { return nil }
            let id = String(line[line.startIndex..<dot])
            guard Int(id) != nil else { return nil }

            var name = line[line.index(after: dot)...].trimmingCharacters(in: .whitespaces)
            var detail: String?
            if name.hasSuffix(")"), let open = name.lastIndex(of: "(") {
                detail = String(name[name.index(after: open)..<name.index(before: name.endIndex)])
                name = name[..<open].trimmingCharacters(in: .whitespaces)
            }
            guard !name.isEmpty else { return nil }
            return CaptureInterface(id: id, name: name, detail: detail)
        }
    }

    static func captureArguments(filter: CaptureFilter, captureFile: URL, durationLimit: TimeInterval?) -> [String] {
        var arguments = ["-i", filter.interfaceID, "-l", "-w", captureFile.path, "-T", "ek"]
        for field in packetFields {
            arguments.append(contentsOf: ["-e", field])
        }
        if let displayFilter = filter.displayFilter, !displayFilter.isEmpty {
            arguments.append(contentsOf: ["-Y", displayFilter])
        }
        if let durationLimit {
            arguments.append(contentsOf: ["-a", "duration:\(Int(durationLimit.rounded()))"])
        }
        return arguments
    }

    private static let packetFields = [
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
        "_ws.col.Protocol", "_ws.col.Info", "frame.len",
        "dns.qry.name", "tls.handshake.extensions_server_name", "http.host",
    ]

    private func appendAndDrain(_ data: Data) -> [String] {
        lock.withLock {
            lineBuffer.append(data)

            var lines: [String] = []
            while let newline = lineBuffer.firstIndex(of: 0x0A) {
                let line = lineBuffer[lineBuffer.startIndex..<newline]
                lineBuffer.removeSubrange(lineBuffer.startIndex...newline)
                if let text = String(data: line, encoding: .utf8) { lines.append(text) }
            }
            return lines
        }
    }

    private func emit(_ event: PacketEvent) {
        let continuation = lock.withLock { self.continuation }
        continuation?.yield(event)
    }

    private func finishStream() {
        let continuation = lock.withLock { () -> AsyncStream<PacketEvent>.Continuation? in
            defer {
                self.continuation = nil
                self.process = nil
                self.lineBuffer.removeAll()
            }
            return self.continuation
        }
        continuation?.finish()
    }

    private static func temporaryCaptureURL() -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("WiresharkSentinel", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("engine-\(UUID().uuidString).pcapng")
    }

    @discardableResult
    private static func run(_ executable: String, _ arguments: [String], mergeStderr: Bool = false) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = mergeStderr ? pipe : FileHandle.nullDevice

        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let command = ([executable] + arguments).joined(separator: " ")
        guard process.terminationStatus == 0 else {
            throw EngineError.processExited(status: process.terminationStatus, command: command)
        }
        return String(decoding: data, as: UTF8.self)
    }
}
