import Foundation
import SentinelDomain

/// TCP control flags as tshark reports them, so direction comes from the connection
/// rather than from whichever packet the capture happened to see first.
public enum TCPFlags {
    public static func syn(_ packet: CapturedPacket) -> Bool { isSet(packet, "tcp_flags_syn") }

    public static func ack(_ packet: CapturedPacket) -> Bool { isSet(packet, "tcp_flags_ack") }

    /// A connection attempt from the sender: SYN set, ACK clear.
    public static func synOnly(_ packet: CapturedPacket) -> Bool { syn(packet) && !ack(packet) }

    /// The peer accepting a connection attempt: SYN and ACK both set.
    public static func synAndAck(_ packet: CapturedPacket) -> Bool { syn(packet) && ack(packet) }

    static func isSet(_ packet: CapturedPacket, _ field: String) -> Bool {
        guard let value = packet.field(field)?.lowercased() else { return false }
        return value == "true" || value == "1"
    }
}
