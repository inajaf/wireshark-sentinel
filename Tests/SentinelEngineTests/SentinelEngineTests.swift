import XCTest
import SentinelDomain
import SentinelEngine
import SentinelTestSupport

private func ekLines() throws -> [String] {
    try Fixture.text("engine-live.ek.ndjson").split(separator: "\n").map(String.init)
}

private func ekPackets() throws -> [CapturedPacket] {
    try ekLines().compactMap { EKPacketParser.packet(fromEKLine: $0) }
}

final class EKPacketParserTests: XCTestCase {
    func testRecordedEKYieldsOnePacketPerFrameAndSkipsIndexLines() throws {
        XCTAssertEqual(try ekLines().count, 86)
        XCTAssertEqual(try ekPackets().map(\.id), Array(1...43))
    }

    func testDNSFrameCarriesColumnsPortsAndQueryName() throws {
        let packet = try ekPackets()[0]

        XCTAssertEqual(packet.source, "192.168.1.80")
        XCTAssertEqual(packet.destination, "192.168.1.254")
        XCTAssertEqual(packet.proto, "DNS")
        XCTAssertEqual(packet.info, "Standard query 0xecae A example.com")
        XCTAssertEqual(packet.length, 71)
        XCTAssertEqual(packet.transport, .udp)
        XCTAssertEqual(packet.sourcePort, 61447)
        XCTAssertEqual(packet.destinationPort, 53)
        XCTAssertEqual(packet.field("dns_qry_name"), "example.com")
        XCTAssertEqual(packet.time, Date(timeIntervalSince1970: 1793052560.845414))
    }

    func testTLSFrameCarriesBothPortsAndSNI() throws {
        let packet = try ekPackets()[4]

        XCTAssertEqual(packet.transport, .tcp)
        XCTAssertEqual(packet.sourcePort, 53341)
        XCTAssertEqual(packet.destinationPort, 443)
        XCTAssertEqual(packet.field("tls_handshake_extensions_server_name"), "example.com")
        XCTAssertNil(packet.field("dns_qry_name"))
    }

    func testNonPacketLinesAreRejected() {
        XCTAssertNil(EKPacketParser.packet(fromEKLine: #"{"index":{"_index":"packets-2026-10-27"}}"#))
        XCTAssertNil(EKPacketParser.packet(fromEKLine: "Capturing on 'Wi-Fi: en0'"))
        XCTAssertNil(EKPacketParser.packet(fromEKLine: "{ not json"))
        XCTAssertNil(EKPacketParser.packet(fromEKLine: ""))
        XCTAssertNil(EKPacketParser.packet(fromEKLine: #"{"layers":{"ip_src":["192.168.1.80"]}}"#))
    }
}

final class FieldsParserTests: XCTestCase {
    func testRecordedFieldsLinesYieldPacketsWithPortsAndSNI() throws {
        let lines = try Fixture.text("sample-live.fields.tsv").split(separator: "\n").map(String.init)
        let packets = lines.compactMap { EKPacketParser.packet(fromFieldsLine: $0) }

        XCTAssertEqual(packets.map(\.id), Array(1...43))
        XCTAssertEqual(packets[0].transport, .udp)
        XCTAssertEqual(packets[0].destinationPort, 53)
        XCTAssertEqual(packets[0].field("dns_qry_name"), "example.com")
        XCTAssertEqual(packets[4].transport, .tcp)
        XCTAssertEqual(packets[4].destinationPort, 443)
        XCTAssertEqual(packets[4].field("tls_handshake_extensions_server_name"), "example.com")
        XCTAssertNil(EKPacketParser.packet(fromFieldsLine: "1\\2\\3"))
    }
}

final class DetailParserTests: XCTestCase {
    func testRecordedFrameDetailHasLayersTreeAndByteRows() throws {
        let detail = DetailParser.detail(
            json: try Fixture.data("engine-detail-frame5.json"),
            hexDump: try Fixture.text("engine-detail-frame5.hex.txt"),
            frameNumber: 5
        )
        let values = flattened(detail.tree)

        XCTAssertEqual(detail.frameNumber, 5)
        XCTAssertEqual(detail.tree.map(\.id), ["frame", "eth", "ip", "tcp", "tls"])
        XCTAssertEqual(values["frame.number"], "5")
        XCTAssertEqual(values["tls.handshake.type"], "1")
        XCTAssertGreaterThanOrEqual(detail.bytes.count, 3)
        XCTAssertTrue(detail.bytes[0].hasPrefix("0000"))
        XCTAssertTrue(detail.bytes[0].contains("f8 22 29 8c"))
    }

    func testWholeCaptureJSONIsSelectedByFrameNumber() throws {
        let detail = DetailParser.detail(
            json: try Fixture.data("sample-live.tree.json"),
            hexDump: "",
            frameNumber: 5
        )

        XCTAssertEqual(flattened(detail.tree)["frame.number"], "5")
    }

    func testUnusableJSONYieldsNoTree() throws {
        XCTAssertTrue(DetailParser.detail(
            json: try Fixture.data("sample-live.tree.json"), hexDump: "", frameNumber: 999
        ).tree.isEmpty)
        XCTAssertTrue(DetailParser.detail(json: Data("{".utf8), hexDump: "", frameNumber: 1).tree.isEmpty)
    }

    private func flattened(_ nodes: [DetailNode]) -> [String: String] {
        nodes.reduce(into: [:]) { result, node in
            if let value = node.value { result[node.id] = value }
            result.merge(flattened(node.children)) { first, _ in first }
        }
    }
}

final class WiresharkInstallTests: XCTestCase {
    func testLocateFindsTheInstalledEngine() throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: "/Applications/Wireshark.app/Contents/MacOS/tshark"))

        let install = try XCTUnwrap(WiresharkInstall.locate())

        XCTAssertEqual(install.appPath, "/Applications/Wireshark.app")
        for binary in [install.tshark, install.dumpcap, install.capinfos] {
            XCTAssertTrue(FileManager.default.isExecutableFile(atPath: binary), binary)
        }
        XCTAssertEqual(install.appPath + "/Contents/MacOS/tshark", install.tshark)
    }

    func testLocateReturnsNilWithoutACompleteBundle() throws {
        XCTAssertNil(WiresharkInstall.locate(appPaths: [
            "/nonexistent/Wireshark.app",
            NSTemporaryDirectory() + "engine-missing-Wireshark.app",
        ]))

        let app = FileManager.default.temporaryDirectory.appendingPathComponent("engine-\(UUID().uuidString).app")
        let macos = app.appendingPathComponent("Contents/MacOS")
        try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: app) }

        let tshark = macos.appendingPathComponent("tshark")
        try "#!/bin/sh\n".write(to: tshark, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tshark.path)
        XCTAssertNil(WiresharkInstall.locate(appPaths: [app.path]))

        for name in ["dumpcap", "capinfos"] {
            let binary = macos.appendingPathComponent(name)
            try "#!/bin/sh\n".write(to: binary, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binary.path)
        }
        XCTAssertEqual(WiresharkInstall.locate(appPaths: [app.path])?.tshark, tshark.path)
    }
}

final class TSharkEngineTests: XCTestCase {
    func testInterfacesListsEn0() async throws {
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: "/Applications/Wireshark.app/Contents/MacOS/tshark"))
        let install = try XCTUnwrap(WiresharkInstall.locate())
        let interfaces = await TSharkEngine(install: install).interfaces()

        XCTAssertTrue(interfaces.contains { $0.name == "en0" })
        XCTAssertTrue(interfaces.allSatisfy { !$0.id.isEmpty })
    }

    func testDetailBeforeAnyCaptureThrows() async throws {
        let engine = TSharkEngine(install: WiresharkInstall(
            appPath: "/Applications/Wireshark.app",
            tshark: "/usr/bin/true",
            dumpcap: "/usr/bin/true",
            capinfos: "/usr/bin/true"
        ))

        do {
            _ = try await engine.detail(frameNumber: 1)
            XCTFail("detail without a capture file must throw")
        } catch let error as EngineError {
            XCTAssertEqual(error.description, "no capture file: start a capture before asking for detail")
        }
    }
}
