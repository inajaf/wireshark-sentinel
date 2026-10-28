import SwiftUI
import SentinelDomain

struct MainWindow: View {
    @EnvironmentObject var model: SentinelModel

    var body: some View {
        VStack(spacing: 0) {
            ControlBar()
            Divider()
            HSplitView {
                VSplitView {
                    PacketListPane()
                        .frame(minHeight: 200)
                    DetailPane()
                        .frame(minHeight: 140)
                    BytesPane()
                        .frame(minHeight: 120)
                }
                .frame(minWidth: 620)
                SentinelPane()
                    .frame(minWidth: 320, idealWidth: 400)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

struct ControlBar: View {
    @EnvironmentObject var model: SentinelModel
    @State private var showingBlocks = false
    @State private var showingWiFi = false
    @StateObject private var wifi = NearbyWiFiModel()

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled")
                .foregroundStyle(.tint)

            Picker("Interface", selection: $model.selectedInterfaceID) {
                ForEach(model.interfaces) { interface in
                    Text(interface.detail.map { "\(interface.name) (\($0))" } ?? interface.name)
                        .tag(interface.id)
                }
            }
            .frame(width: 260)
            .disabled(model.isCapturing)

            if model.isCapturing {
                Button {
                    Task { await model.stopCapture() }
                } label: {
                    Label("Stop", systemImage: "stop.fill")
                }
            } else {
                Button {
                    Task { await model.startCapture() }
                } label: {
                    Label("Start", systemImage: "play.fill")
                }
                .disabled(model.selectedInterfaceID.isEmpty || model.engineMissing)
            }

            Button {
                model.exportReport()
            } label: {
                Label("Export", systemImage: "square.and.arrow.down")
            }
            .disabled(model.assessments.isEmpty)

            Button {
                showingBlocks = true
            } label: {
                Label(
                    model.blockState.activeRecords.isEmpty
                        ? "Blocks"
                        : "Blocks (\(model.blockState.activeRecords.count))",
                    systemImage: "hand.raised"
                )
            }
            .help("Review firewall blocks, persistence and the audit log")
            .sheet(isPresented: $showingBlocks) {
                BlockManagerView()
            }

            Button {
                showingWiFi = true
            } label: {
                Label("Wi-Fi", systemImage: "wifi")
            }
            .help("List nearby Wi-Fi networks, channel occupancy and security")
            .sheet(isPresented: $showingWiFi) {
                NearbyWiFiView(model: wifi)
            }

            Spacer()

            Text(model.statusText)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(1)

            if !model.assessments.isEmpty {
                VerdictTally(assessments: model.assessments)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

struct VerdictTally: View {
    let assessments: [FlowAssessment]

    var body: some View {
        HStack(spacing: 8) {
            ForEach([Verdict.suspicious, .unknown, .known], id: \.self) { verdict in
                let count = assessments.filter { $0.verdict == verdict }.count
                Text("\(count) \(verdict.rawValue)")
                    .font(.caption.monospacedDigit())
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(verdict.tint.opacity(0.18), in: Capsule())
                    .foregroundStyle(verdict.tint)
            }
        }
    }
}

extension Verdict {
    var tint: Color {
        switch self {
        case .suspicious: return .red
        case .unknown: return .orange
        case .known: return .green
        }
    }

    var label: String {
        switch self {
        case .suspicious: return "Possibly spying"
        case .unknown: return "Not sure yet"
        case .known: return "Expected"
        }
    }
}

extension SigningStatus {
    var label: String {
        switch self {
        case .apple: return "Apple signed"
        case .developerID(let team): return "Developer ID \(team)"
        case .adHoc: return "ad-hoc signed"
        case .unsigned: return "unsigned"
        case .unknown: return "signature unknown"
        }
    }
}
