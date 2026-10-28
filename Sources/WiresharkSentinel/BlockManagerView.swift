import SwiftUI
import SentinelDomain
import SentinelBlock

/// The audit view for every firewall change. Blocks are manual by design: there is
/// no automatic blocking anywhere in the app, only what a person reviewed and
/// approved here.
struct BlockManagerView: View {
    @EnvironmentObject var model: SentinelModel
    @Environment(\.dismiss) private var dismiss

    @State private var adding = false
    @State private var pendingUnblock: BlockRecord?
    @State private var confirmingUnblockAll = false
    @State private var showRules = false

    private var active: [BlockRecord] {
        model.blockState.activeRecords
    }

    private var history: [BlockRecord] {
        model.blockState.records
            .filter { !$0.active }
            .sorted { ($0.appliedAt ?? $0.createdAt) > ($1.appliedAt ?? $1.createdAt) }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let error = model.blockError {
                        banner(error, color: .orange, icon: "exclamationmark.triangle.fill")
                    }

                    activeSection
                    persistenceSection
                    auditSection
                    if let output = model.blockOutput, !output.isEmpty {
                        outputSection(output)
                    }
                }
                .padding(16)
            }
            Divider()
            footer
        }
        .frame(minWidth: 680, idealWidth: 800, minHeight: 560, idealHeight: 700)
        .sheet(isPresented: $adding) {
            BlockEditor(target: BlockTarget(address: ""))
        }
        .confirmationDialog(
            pendingUnblock.map { "Unblock \($0.target.displayName)?" } ?? "Unblock this target?",
            isPresented: Binding(
                get: { pendingUnblock != nil },
                set: { if !$0 { pendingUnblock = nil } }
            ),
            presenting: pendingUnblock
        ) { record in
            Button("Unblock", role: .destructive) {
                Task { _ = await model.unblock(recordIDs: [record.id]) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { record in
            Text("The rules are rewritten without \(record.target.displayName). Existing connections to it are not revived.")
        }
        .confirmationDialog(
            "Remove all blocks?",
            isPresented: $confirmingUnblockAll
        ) {
            Button("Remove All", role: .destructive) {
                Task { _ = await model.unblockAll() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The Sentinel anchor will be emptied and every block in this list will be removed. The audit log keeps the history.")
        }
    }

    // MARK: - Header and footer

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "hand.raised.fill")
                .font(.title2)
                .foregroundStyle(.red)
            VStack(alignment: .leading, spacing: 4) {
                Text("Firewall blocks")
                    .font(.title3.weight(.semibold))
                Text("pf anchor \(PFBlockController.anchorName) · \(active.count) active")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title3)
                    .foregroundStyle(.tertiary)
            }
            .buttonStyle(.plain)
            .help("Close the block manager")
        }
        .padding(16)
    }

    private var footer: some View {
        HStack(spacing: 8) {
            if model.isApplyingBlock {
                ProgressView().controlSize(.small)
                Text("Waiting for administrator approval…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button {
                adding = true
            } label: {
                Label("Add Address…", systemImage: "plus")
            }
            .disabled(model.isApplyingBlock)

            Button {
                Task { _ = await model.reapplyBlocks() }
            } label: {
                Label("Reapply", systemImage: "arrow.clockwise")
            }
            .disabled(active.isEmpty || model.isApplyingBlock)

            Button(role: .destructive) {
                confirmingUnblockAll = true
            } label: {
                Label("Remove All…", systemImage: "trash")
            }
            .disabled(active.isEmpty || model.isApplyingBlock)

            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(12)
    }

    // MARK: - Active blocks

    private var activeSection: some View {
        InspectorSection("Active", subtitle: "only what you approved") {
            if active.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("No blocks are active.")
                        .font(.callout)
                    Text("Open a conversation in Sentinel and use Block…, or add an address from the footer. Blocks cover an IP address or CIDR range and an optional port; they do not cover a domain name or one application.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                VStack(spacing: 0) {
                    ForEach(active) { record in
                        activeRow(record)
                        if record.id != active.last?.id {
                            Divider()
                        }
                    }
                }
                Text("This list is what the app last applied. Use Reapply after a restart or if pf was flushed by something else.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .padding(.top, 8)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func activeRow(_ record: BlockRecord) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "nosign")
                .foregroundStyle(.red)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 3) {
                Text(record.target.displayName)
                    .font(.system(.body, design: .monospaced))
                HStack(spacing: 6) {
                    Text(record.target.direction.label)
                    Text("·")
                    Text(record.target.port == nil ? "all protocols" : record.target.transport.label)
                    if let applied = record.appliedAt {
                        Text("·")
                        Text(Self.relative.localizedString(for: applied, relativeTo: Date()))
                    }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
                if let note = record.target.note, !note.isEmpty {
                    Text(note)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .lineLimit(2)
                }
            }
            Spacer()
            Button("Unblock") {
                pendingUnblock = record
            }
            .disabled(model.isApplyingBlock)
        }
        .padding(.vertical, 7)
    }

    // MARK: - Persistence

    private var persistenceSection: some View {
        InspectorSection("After a restart", subtitle: "off by default") {
            VStack(alignment: .leading, spacing: 6) {
                Toggle(
                    "Keep these blocks after this Mac restarts",
                    isOn: Binding(
                        get: { model.blockState.persistAfterReboot },
                        set: { enabled in
                            Task { _ = await model.setBlockPersistence(enabled) }
                        }
                    )
                )
                .toggleStyle(.checkbox)
                .font(.callout)
                .disabled(model.isApplyingBlock)

                Text("When on, a LaunchDaemon loads the Sentinel anchor at boot. Changing this requires the same administrator approval as applying a block.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: - Audit

    private var auditSection: some View {
        InspectorSection("Audit log", subtitle: "kept on this Mac") {
            VStack(alignment: .leading, spacing: 8) {
                if model.blockState.audit.isEmpty {
                    Text("No block changes have been made yet.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.blockState.audit.suffix(30).reversed()) { entry in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(entry.action)
                                    .font(.caption.weight(.semibold))
                                Text(entry.targets.joined(separator: ", "))
                                    .font(.system(.caption2, design: .monospaced))
                                    .lineLimit(2)
                                Spacer()
                                Text(Self.date.string(from: entry.at))
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                            HStack(spacing: 6) {
                                Text(entry.result)
                                    .font(.caption2.weight(.semibold))
                                    .foregroundStyle(entry.result == "applied" ? Color.green : Color.orange)
                                if let detail = entry.detail, entry.result != "applied" {
                                    Text(detail)
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(2)
                                }
                            }
                        }
                        .padding(.vertical, 3)
                    }
                }

                if !history.isEmpty {
                    Divider()
                    Text("\(history.count) previous target\(history.count == 1 ? "" : "s")")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }

    private func outputSection(_ output: String) -> some View {
        InspectorSection("Last apply output") {
            DisclosureGroup("Show pf output", isExpanded: $showRules) {
                Text(output)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 6)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .font(.caption)
        }
    }

    private func banner(_ text: String, color: Color, icon: String) -> some View {
        Label(text, systemImage: icon)
            .font(.caption)
            .foregroundStyle(color)
            .fixedSize(horizontal: false, vertical: true)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(color.opacity(0.1), in: RoundedRectangle(cornerRadius: 7))
    }

    private static let date: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter
    }()

    private static let relative: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return formatter
    }()
}
