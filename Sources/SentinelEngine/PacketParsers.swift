import Foundation
import SentinelDomain

/// One line of `tshark -T ek` becomes one packet. Pure, offline, testable.
public enum EKPacketParser {
    /// With explicit `-e` flags tshark joins the key with underscores and wraps every value in an array.
    public static func packet(fromEKLine line: String) -> CapturedPacket? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let data = trimmed.data(using: .utf8) else { return nil }
        guard let raw = try? JSONSerialization.jsonObject(with: data),
              let object = raw as? [String: Any] else { return nil }
        guard object["index"] == nil, let layers = object["layers"] as? [String: Any] else { return nil }

        let fields = self.fields(from: layers)
        guard let number = fields["frame_number"]?.first.flatMap({ Int($0) }) else { return nil }

        return CapturedPacket(
            id: number,
            time: date(fields: fields, object: object),
            source: fields["ip_src"]?.first ?? fields["ipv6_src"]?.first ?? "",
            destination: fields["ip_dst"]?.first ?? fields["ipv6_dst"]?.first ?? "",
            proto: fields["_ws_col_protocol"]?.first ?? "",
            length: fields["frame_len"]?.first.flatMap({ Int($0) }) ?? 0,
            info: fields["_ws_col_info"]?.first ?? "",
            transport: transport(fields),
            sourcePort: port(fields, "tcp_srcport", "udp_srcport") ?? 0,
            destinationPort: port(fields, "tcp_dstport", "udp_dstport") ?? 0,
            fields: fields
        )
    }

    /// The recorded `-T fields -E separator=\` layout. It carries destination ports only.
    public static let fieldsColumns = [
        "frame_number", "frame_time_epoch", "ip_src", "ip_dst", "tcp_dstport", "udp_dstport",
        "_ws_col_protocol", "_ws_col_info", "frame_len", "dns_qry_name",
        "tls_handshake_extensions_server_name", "http_host",
    ]

    public static func packet(fromFieldsLine line: String) -> CapturedPacket? {
        let columns = line.trimmingCharacters(in: .whitespacesAndNewlines).components(separatedBy: "\\")
        guard columns.count == fieldsColumns.count else { return nil }

        var fields: [String: [String]] = [:]
        for (name, value) in zip(fieldsColumns, columns) where !value.isEmpty {
            fields[name] = [value]
        }
        guard let number = fields["frame_number"]?.first.flatMap({ Int($0) }) else { return nil }

        let tcpPort = fields["tcp_dstport"]?.first.flatMap { UInt16($0) }
        let udpPort = fields["udp_dstport"]?.first.flatMap { UInt16($0) }
        return CapturedPacket(
            id: number,
            time: fields["frame_time_epoch"]?.first.flatMap { Double($0) }
                .map { Date(timeIntervalSince1970: $0) } ?? Date(timeIntervalSince1970: 0),
            source: fields["ip_src"]?.first ?? "",
            destination: fields["ip_dst"]?.first ?? "",
            proto: fields["_ws_col_protocol"]?.first ?? "",
            length: fields["frame_len"]?.first.flatMap({ Int($0) }) ?? 0,
            info: fields["_ws_col_info"]?.first ?? "",
            transport: tcpPort != nil ? .tcp : (udpPort != nil ? .udp : .other),
            sourcePort: 0,
            destinationPort: tcpPort ?? udpPort ?? 0,
            fields: fields
        )
    }

    static func fields(from layers: [String: Any]) -> [String: [String]] {
        var fields: [String: [String]] = [:]
        for (key, value) in layers {
            if let list = value as? [Any] {
                let values = list.compactMap { $0 as? String }
                if !values.isEmpty { fields[key] = values }
            } else if let single = value as? String {
                fields[key] = [single]
            }
        }
        return fields
    }

    static func date(fields: [String: [String]], object: [String: Any]) -> Date {
        if let epoch = fields["frame_time_epoch"]?.first.flatMap({ Double($0) }) {
            return Date(timeIntervalSince1970: epoch)
        }
        if let millis = object["timestamp"] as? String, let value = Double(millis) {
            return Date(timeIntervalSince1970: value / 1000)
        }
        return Date(timeIntervalSince1970: 0)
    }

    static func transport(_ fields: [String: [String]]) -> TransportProtocol {
        if fields["tcp_srcport"] != nil || fields["tcp_dstport"] != nil { return .tcp }
        if fields["udp_srcport"] != nil || fields["udp_dstport"] != nil { return .udp }
        if let number = fields["ip_proto"]?.first.flatMap({ Int($0) }) {
            return TransportProtocol(ipProtocolNumber: number)
        }
        return .other
    }

    static func port(_ fields: [String: [String]], _ names: String...) -> UInt16? {
        for name in names {
            if let value = fields[name]?.first, let port = UInt16(value) { return port }
        }
        return nil
    }
}

/// `tshark -T json` plus `-x` becomes a detail tree and byte rows. Pure and offline.
public enum DetailParser {
    public static func detail(json: Data, hexDump: String, frameNumber: Int) -> PacketDetail {
        PacketDetail(
            frameNumber: frameNumber,
            tree: tree(from: json, frameNumber: frameNumber),
            bytes: byteRows(from: hexDump)
        )
    }

    static func tree(from json: Data, frameNumber: Int) -> [DetailNode] {
        guard let raw = try? JSONSerialization.jsonObject(with: json),
              let entries = raw as? [[String: Any]] else { return [] }

        let matched = entries.first { layers(of: $0)?["frame"] is [String: Any]
            && (layers(of: $0)?["frame"] as? [String: Any])?["frame.number"] as? String == String(frameNumber) }
        let entry = matched ?? (entries.count == 1 ? entries[0] : nil)
        guard let layers = entry.flatMap(layers(of:)) else { return [] }

        return layers.keys.sorted(by: isOrderedBefore).compactMap { key in
            (layers[key] as? [String: Any]).map { node(id: key, value: $0) }
        }
    }

    static func layers(of entry: [String: Any]) -> [String: Any]? {
        (entry["_source"] as? [String: Any])?["layers"] as? [String: Any]
    }

    static func node(id: String, value: [String: Any]) -> DetailNode {
        var children: [DetailNode] = []
        for key in value.keys.sorted() {
            let child = value[key]
            if let nested = child as? [String: Any] {
                children.append(node(id: key, value: nested))
            } else if let text = child as? String {
                children.append(DetailNode(id: key, label: key, value: text))
            } else if let number = child as? NSNumber {
                children.append(DetailNode(id: key, label: key, value: number.stringValue))
            } else if let list = child as? [Any] {
                for (index, element) in list.enumerated() {
                    children.append(DetailNode(id: "\(key).\(index)", label: key, value: String(describing: element)))
                }
            }
        }
        return DetailNode(id: id, label: id, children: children)
    }

    static func byteRows(from hexDump: String) -> [String] {
        hexDump.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private static let knownLayerOrder = [
        "frame", "eth", "ip", "ipv6", "tcp", "udp", "tls", "http", "dns",
    ]

    static func isOrderedBefore(_ lhs: String, _ rhs: String) -> Bool {
        let left = knownLayerOrder.firstIndex(of: lhs) ?? knownLayerOrder.count
        let right = knownLayerOrder.firstIndex(of: rhs) ?? knownLayerOrder.count
        return left == right ? lhs < rhs : left < right
    }
}
