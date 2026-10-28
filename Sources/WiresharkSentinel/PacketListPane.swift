import SwiftUI
import SentinelDomain

/// Wireshark's packet list: the configured columns, one row per frame.
struct PacketListPane: View {
    @EnvironmentObject var model: SentinelModel

    private var visiblePackets: [CapturedPacket] {
        guard let focus = model.packetFocus else { return model.packets }
        return model.packets.filter { SentinelModel.isFocused($0, on: focus) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            PaneHeader(
                title: "Packet list",
                detail: model.packetFocus == nil
                    ? "\(model.packets.count) frames"
                    : "\(visiblePackets.count) of \(model.packets.count) frames"
            )
            if let focus = model.packetFocus {
                HStack(spacing: 6) {
                    Text("Only \(focus.remoteEndpoint.description), \(focus.transport.rawValue.uppercased())")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Show all") { model.clearPacketFocus() }
                        .buttonStyle(.link)
                        .font(.caption)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 3)
                .background(Color.accentColor.opacity(0.08))
            }
            Table(visiblePackets, selection: $model.selectedPacketID) {
                TableColumn("No.") { packet in
                    Text("\(packet.id)").monospacedDigit()
                }
                .width(min: 44, ideal: 56)

                TableColumn("Time") { packet in
                    Text(Self.formatter.string(from: packet.time)).monospacedDigit()
                }
                .width(min: 90, ideal: 110)

                TableColumn("Source") { packet in
                    Text(packet.source).monospaced()
                }
                .width(min: 110, ideal: 160)

                TableColumn("Destination") { packet in
                    Text(packet.destination).monospaced()
                }
                .width(min: 110, ideal: 160)

                TableColumn("Protocol") { packet in
                    Text(packet.proto)
                }
                .width(min: 60, ideal: 80)

                TableColumn("Length") { packet in
                    Text("\(packet.length)").monospacedDigit()
                }
                .width(min: 50, ideal: 64)

                TableColumn("Info") { packet in
                    Text(packet.info).lineLimit(1)
                }
                .width(min: 200, ideal: 420)
            }
            .onChange(of: model.selectedPacketID) { _, newValue in
                if let id = newValue { model.selectPacket(id) }
            }
        }
        .onAppear { model.registry.note("packet-list") }
        .accessibilityIdentifier("packet-list")
    }

    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter
    }()
}

struct PaneHeader: View {
    let title: String
    let detail: String

    var body: some View {
        HStack {
            Text(title).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            Spacer()
            Text(detail).font(.caption.monospacedDigit()).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(Color(nsColor: .underPageBackgroundColor))
    }
}
