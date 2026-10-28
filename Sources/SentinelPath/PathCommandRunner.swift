import Foundation
import Darwin

/// One completed process invocation. The trace and ping readers parse this rather
/// than the live pipe, so a test can feed them exact command output.
public struct PathCommandResult: Sendable, Equatable {
    public var executable: String
    public var arguments: [String]
    public var exitCode: Int32
    public var stdout: String
    public var stderr: String
    public var timedOut: Bool
    public var duration: TimeInterval

    public init(
        executable: String,
        arguments: [String],
        exitCode: Int32,
        stdout: String = "",
        stderr: String = "",
        timedOut: Bool = false,
        duration: TimeInterval = 0
    ) {
        self.executable = executable
        self.arguments = arguments
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.timedOut = timedOut
        self.duration = duration
    }

    public var commandLine: String {
        ([executable] + arguments).joined(separator: " ")
    }

    public var succeeded: Bool {
        exitCode == 0 && !timedOut
    }
}

public protocol PathCommandRunning: Sendable {
    func run(executable: String, arguments: [String], timeout: TimeInterval) async -> PathCommandResult
}

/// Runs one local system tool with a deadline. Output is small (a route lookup,
/// one ping or at most a few traceroute lines), so reading after exit is safe.
public struct SystemPathCommandRunner: PathCommandRunning {
    public init() {}

    public func run(executable: String, arguments: [String], timeout: TimeInterval) async -> PathCommandResult {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: Self.execute(
                    executable: executable,
                    arguments: arguments,
                    timeout: timeout
                ))
            }
        }
    }

    private static func execute(executable: String, arguments: [String], timeout: TimeInterval) -> PathCommandResult {
        let start = Date()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let outPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errorPipe

        let expired = LockedFlag()
        do {
            try process.run()
        } catch {
            return PathCommandResult(
                executable: executable,
                arguments: arguments,
                exitCode: -1,
                stderr: error.localizedDescription,
                duration: Date().timeIntervalSince(start)
            )
        }

        let delay = max(timeout, 0.1)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + delay) {
            guard process.isRunning else { return }
            expired.set()
            process.terminate()
            // A tool that ignores SIGTERM must not keep the window waiting forever.
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) {
                if process.isRunning {
                    kill(process.processIdentifier, SIGKILL)
                }
            }
        }

        process.waitUntilExit()

        let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let err = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

        return PathCommandResult(
            executable: executable,
            arguments: arguments,
            exitCode: process.terminationStatus,
            stdout: out,
            stderr: err,
            timedOut: expired.value,
            duration: Date().timeIntervalSince(start)
        )
    }
}

/// A tiny lock-protected flag. The timeout closure and the command run on
/// different queues, and this keeps the read/write race out of the result.
private final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = false

    var value: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func set() {
        lock.lock()
        stored = true
        lock.unlock()
    }
}
