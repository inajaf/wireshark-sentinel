import SwiftUI
import SentinelDomain

/// The new pane. One row per conversation, with the answer to "who is this, who
/// started it, and is it expected".
struct SentinelPane: View {
    @EnvironmentObject var model: SentinelModel
    @State private var showOnlyAttention = true

    private var visible: [FlowAssessment] {
        showOnlyAttention
            ? model.assessments.filter { $0.verdict != .known }
            : model.assessments
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            PaneHeader(title: "Sentinel", detail: "\(visible.count) of \(model.assessments.count)")
            Toggle("Only what needs attention", isOn: $showOnlyAttention)
                .toggleStyle(.checkbox)
                .font(.caption)
                .padding(.horizontal, 10)
                .padding(.vertical, 4)

            if visible.isEmpty {
                EmptyPaneHint(
                    text: model.assessments.isEmpty
                        ? "Start a capture. Every remote resource will be identified here."
                        : "Nothing needs your attention right now."
                )
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(visible) { assessment in
                            AssessmentCard(assessment: assessment)
                        }
                    }
                    .padding(8)
                }
            }
        }
        .onAppear { model.registry.note("sentinel") }
        .accessibilityIdentifier("sentinel")
    }
}

struct AssessmentCard: View {
    let assessment: FlowAssessment

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Circle()
                    .fill(assessment.verdict.tint)
                    .frame(width: 8, height: 8)
                Text(assessment.identity.evidencedName ?? "unidentified resource")
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                Spacer()
                Text(assessment.verdict.label)
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(assessment.verdict.tint.opacity(0.18), in: Capsule())
                    .foregroundStyle(assessment.verdict.tint)
            }

            Text("\(assessment.key.transport.rawValue.uppercased()) \(directionWord) \(assessment.key.remoteEndpoint.description)")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)

            if let service = assessment.identity.serviceGuess {
                Label("port \(assessment.key.remote.port) looks like \(service), a guess not a name",
                      systemImage: "questionmark.diamond")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }

            if let process = assessment.process {
                Label(
                    "\(process.name) (pid \(process.pid)), \(process.signing.label)",
                    systemImage: process.signing == .unsigned || process.signing == .adHoc
                        ? "exclamationmark.triangle"
                        : "checkmark.seal"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            } else {
                Label("not attributed to a local program yet", systemImage: "questionmark.circle")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }

            if !assessment.signals.isEmpty {
                FlowLayout(spacing: 4) {
                    ForEach(assessment.signals, id: \.kind) { signal in
                        Text(signal.kind.title)
                            .font(.caption2)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(assessment.verdict.tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 4))
                    }
                }
            }

            if !assessment.rationale.isEmpty {
                Text(assessment.rationale)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
        .overlay(
            RoundedRectangle(cornerRadius: 7)
                .stroke(assessment.verdict.tint.opacity(0.35), lineWidth: 1)
        )
    }

    private var directionWord: String {
        switch assessment.direction {
        case .inbound: return "inbound from"
        case .outbound: return "to"
        case .loopback: return "on this Mac to"
        case .broadcast: return "broadcast by"
        case .multicast: return "multicast to"
        }
    }
}

/// Wraps chips onto as many lines as they need.
struct FlowLayout: Layout {
    var spacing: CGFloat = 4

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > maxWidth, x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: maxWidth == .infinity ? x : maxWidth, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX, x > bounds.minX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            subview.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}
