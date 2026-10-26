import SwiftUI
import SentinelDomain

/// Wireshark's protocol detail tree for the selected frame.
struct DetailPane: View {
    @EnvironmentObject var model: SentinelModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            PaneHeader(
                title: "Packet details",
                detail: model.selectedPacketID.map { "frame \($0)" } ?? "no frame selected"
            )
            if let detail = model.detail, !detail.tree.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(detail.tree) { node in
                            DetailNodeRow(node: node, depth: 0)
                        }
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else {
                EmptyPaneHint(text: "Select a frame to see its protocol layers.")
            }
        }
        .onAppear { model.registry.note("packet-details") }
        .accessibilityIdentifier("packet-details")
    }
}

struct DetailNodeRow: View {
    let node: DetailNode
    let depth: Int

    var body: some View {
        if node.children.isEmpty {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(String(repeating: "  ", count: depth) + node.label)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                if let value = node.value, !value.isEmpty {
                    Text(value)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        } else {
            DisclosureGroup {
                ForEach(node.children) { child in
                    DetailNodeRow(node: child, depth: depth + 1)
                }
            } label: {
                Text(String(repeating: "  ", count: depth) + node.label)
                    .font(.system(.caption, design: .monospaced).weight(.medium))
            }
        }
    }
}

/// Wireshark's packet bytes pane.
struct BytesPane: View {
    @EnvironmentObject var model: SentinelModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            PaneHeader(
                title: "Packet bytes",
                detail: model.detail.map { "\($0.bytes.count) rows" } ?? "no frame selected"
            )
            if let rows = model.detail?.bytes, !rows.isEmpty {
                ScrollView([.vertical, .horizontal]) {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                            Text(row)
                                .font(.system(.caption2, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else {
                EmptyPaneHint(text: "Select a frame to see its bytes.")
            }
        }
        .onAppear { model.registry.note("packet-bytes") }
        .accessibilityIdentifier("packet-bytes")
    }
}

struct EmptyPaneHint: View {
    let text: String

    var body: some View {
        VStack {
            Spacer()
            Text(text)
                .font(.callout)
                .foregroundStyle(.tertiary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}
