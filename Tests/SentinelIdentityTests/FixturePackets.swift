import Foundation
import SentinelDomain
import SentinelTestSupport

/// `CapturedPacket` values built from the recorded dissections in `Fixtures/`.
///
/// `sample-live.fields.tsv` columns are, in order: `tshark -r Fixtures/sample-live.pcapng
/// -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport
/// -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info -e frame.len -e dns.qry.name
/// -e tls.handshake.extensions_server_name -e http.host -E 'separator=\'`.
/// `sample-tls12.ek.jsonl` holds `tshark -T ek -l` lines from the TLS 1.2 capture.
enum FixturePackets {
    struct MissingRow: Error {
        let frame: Int
    }

    static func packet(_ frameNumber: Int) throws -> CapturedPacket {
        for line in try Fixture.text("sample-live.fields.tsv").split(separator: "\n") {
            let columns = line.split(separator: "\\", omittingEmptySubsequences: false).map(String.init)
            guard columns.count == 12, Int(columns[0]) == frameNumber else { continue }
            return packet(from: columns)
        }
        throw MissingRow(frame: frameNumber)
    }

    /// The recorded EK layers for one frame of the TLS 1.2 capture.
    static func ekFields(frame: Int) throws -> [String: [String]] {
        for line in try Fixture.text("sample-tls12.ek.jsonl").split(separator: "\n") {
            guard let data = String(line).data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data),
                  let object = json as? [String: Any],
                  let layers = object["layers"] as? [String: [String]],
                  layers["frame_number"]?.first == String(frame) else { continue }
            return layers
        }
        throw MissingRow(frame: frame)
    }

    /// A packet for the fields the recorded captures do not carry.
    static func crafted(
        from source: String, to destination: String,
        sourcePort: UInt16 = 0, destinationPort: UInt16,
        proto: String = "TLSv1.2", info: String = "",
        fields: [String: [String]] = [:]
    ) -> CapturedPacket {
        CapturedPacket(
            id: 0, time: Date(timeIntervalSince1970: 0), source: source, destination: destination,
            proto: proto, length: 0, info: info, transport: .tcp,
            sourcePort: sourcePort, destinationPort: destinationPort, fields: fields
        )
    }

    private static func packet(from columns: [String]) -> CapturedPacket {
        var fields: [String: [String]] = [:]
        let named: [(String, Int)] = [
            ("ip_src", 2), ("ip_dst", 3), ("tcp_dstport", 4), ("udp_dstport", 5),
            ("dns_qry_name", 9), ("tls_handshake_extensions_server_name", 10), ("http_host", 11),
        ]
        for (name, index) in named where !columns[index].isEmpty {
            fields[name] = [columns[index]]
        }

        let transport: TransportProtocol = !columns[5].isEmpty ? .udp : (!columns[4].isEmpty ? .tcp : .other)
        return CapturedPacket(
            id: Int(columns[0]) ?? 0, time: Date(timeIntervalSince1970: Double(columns[1]) ?? 0),
            source: columns[2], destination: columns[3], proto: columns[6],
            length: Int(columns[8]) ?? 0, info: columns[7], transport: transport,
            sourcePort: 0,  // the recorded column list carries no source ports
            destinationPort: UInt16(columns[4]) ?? UInt16(columns[5]) ?? 0, fields: fields
        )
    }
}
