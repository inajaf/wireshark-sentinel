import XCTest
import SentinelDomain
import SentinelEngine
import SentinelTestSupport

final class TCPFlagsTests: XCTestCase {
    func testRecordedSYNIsAConnectionRequest() throws {
        let packet = try packet(3)

        XCTAssertEqual(packet.field("tcp_flags_syn"), "True")
        XCTAssertEqual(packet.field("tcp_flags_ack"), "False")
        XCTAssertEqual(packet.field("tcp_flags_str"), "····CE····S·")
        XCTAssertTrue(TCPFlags.synOnly(packet))
        XCTAssertFalse(TCPFlags.synAndAck(packet))
    }

    func testRecordedSYNACKIsAnAccept() throws {
        let packet = try packet(4)

        XCTAssertTrue(TCPFlags.syn(packet))
        XCTAssertTrue(TCPFlags.ack(packet))
        XCTAssertTrue(TCPFlags.synAndAck(packet))
        XCTAssertFalse(TCPFlags.synOnly(packet))
    }

    func testRecordedMidStreamReplyIsNeitherRequestNorAccept() throws {
        let packet = try packet(6)

        XCTAssertFalse(TCPFlags.syn(packet))
        XCTAssertTrue(TCPFlags.ack(packet))
        XCTAssertFalse(TCPFlags.synOnly(packet))
        XCTAssertFalse(TCPFlags.synAndAck(packet))
    }

    func testPacketWithoutTCPFlagsIsNeither() throws {
        let packet = try packet(1)

        XCTAssertEqual(packet.proto, "DNS")
        XCTAssertFalse(TCPFlags.synOnly(packet))
        XCTAssertFalse(TCPFlags.synAndAck(packet))
    }

    private func packet(_ id: Int) throws -> CapturedPacket {
        let packets = try Fixture.text("engine-live.ek.ndjson")
            .split(separator: "\n")
            .compactMap { EKPacketParser.packet(fromEKLine: String($0)) }
        return try XCTUnwrap(packets.first { $0.id == id })
    }
}
