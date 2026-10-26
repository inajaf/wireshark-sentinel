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
    public static func locate() -> WiresharkInstall? { nil }
}

/// Live capture and lazy dissection through the installed engine.
public final class TSharkEngine: CaptureEngine, @unchecked Sendable {
    public init(install: WiresharkInstall) {}

    public func interfaces() async -> [CaptureInterface] { [] }

    public func start(_ filter: CaptureFilter) async throws -> AsyncStream<PacketEvent> {
        AsyncStream { $0.finish() }
    }

    public func stop() async {}

    public func detail(frameNumber: Int) async throws -> PacketDetail {
        PacketDetail(frameNumber: frameNumber)
    }
}

/// One line of `tshark -T ek` becomes one packet. Pure, offline, testable.
public enum EKPacketParser {
    public static func packet(fromEKLine line: String) -> CapturedPacket? { nil }
}

/// `tshark -T json` plus `-x` becomes a detail tree and byte rows. Pure and offline.
public enum DetailParser {
    public static func detail(json: Data, hexDump: String, frameNumber: Int) -> PacketDetail {
        PacketDetail(frameNumber: frameNumber)
    }
}
