import XCTest
import SentinelDomain
import SentinelEngine

/// Drives a real capture on en0. `scripts/smoke-live.sh` sets the variable that unskips it.
final class LiveCaptureTests: XCTestCase {
    func testLiveCaptureOnEn0YieldsParsedPackets() async throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["SENTINEL_LIVE_SMOKE"] == "1",
            "run scripts/smoke-live.sh to exercise the live path"
        )
        let install = try XCTUnwrap(WiresharkInstall.locate(), "Wireshark is not installed")

        let engine = TSharkEngine(install: install, durationLimit: 10)
        let stream = try await engine.start(CaptureFilter(interfaceID: "en0"))

        var packets: [CapturedPacket] = []
        var errors: [String] = []
        for await event in stream {
            if case .packet(let packet) = event { packets.append(packet) }
            if case .error(let message) = event { errors.append(message) }
        }
        await engine.stop()
        print("live capture on en0: \(packets.count) packets, \(Set(packets.map(\.transport))) transports, "
            + "\(packets.filter(TCPFlags.synOnly).count) connection requests, "
            + "\(packets.filter(TCPFlags.synAndAck).count) accepts, errors: \(errors)")

        XCTAssertFalse(packets.isEmpty, "no packet arrived on en0 within 10 s; errors: \(errors)")
        XCTAssertTrue(errors.isEmpty, "normal capture progress reached the error channel: \(errors)")
        XCTAssertTrue(packets.contains { !$0.source.isEmpty && !$0.destination.isEmpty })
        XCTAssertTrue(packets.contains { $0.transport != .other })
        XCTAssertTrue(packets.contains { TCPFlags.syn($0) || TCPFlags.ack($0) })
    }
}
