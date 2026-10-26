import Foundation
import AppKit
import SwiftUI
import SentinelDomain
import SentinelEngine
import SentinelIdentity
import SentinelAttribution
import SentinelSuspicion
import SentinelReport

/// Which parts of the window actually rendered. Written out for verification.
@MainActor
final class UIRegistry: ObservableObject {
    @Published var renderedPanes: Set<String> = []
    @Published var windowSize: CGSize = .zero

    func note(_ pane: String) { renderedPanes.insert(pane) }

    func measureWindow() {
        if let frame = NSApplication.shared.windows.first(where: { $0.isVisible })?.frame {
            windowSize = frame.size
        }
    }

    func json(packetCount: Int, assessmentCount: Int) -> String {
        let payload: [String: Any] = [
            "panes": renderedPanes.sorted(),
            "windowWidth": Int(windowSize.width),
            "windowHeight": Int(windowSize.height),
            "packets": packetCount,
            "assessments": assessmentCount,
        ]
        let data = (try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])) ?? Data()
        return String(data: data, encoding: .utf8) ?? "{}"
    }
}

struct CommandLineOptions {
    var selfTestPath: String?
    var seconds: TimeInterval = 15
    var interfaceID: String?
    var checkListeners = false

    static func parse(_ args: [String]) -> CommandLineOptions {
        var options = CommandLineOptions()
        var index = 0
        while index < args.count {
            switch args[index] {
            case "--selftest":
                if index + 1 < args.count { options.selfTestPath = args[index + 1]; index += 1 }
            case "--seconds":
                if index + 1 < args.count, let value = Double(args[index + 1]) { options.seconds = value; index += 1 }
            case "--interface":
                if index + 1 < args.count { options.interfaceID = args[index + 1]; index += 1 }
            case "--check-listeners":
                options.checkListeners = true
            default:
                break
            }
            index += 1
        }
        return options
    }
}

@main
struct WiresharkSentinelApp: App {
    @StateObject private var model = SentinelModel()
    private let options = CommandLineOptions.parse(Array(CommandLine.arguments.dropFirst()))

    init() {
        let options = CommandLineOptions.parse(Array(CommandLine.arguments.dropFirst()))
        if options.checkListeners {
            print(LocalListenerTable.snapshot().sorted().map(String.init).joined(separator: " "))
            exit(0)
        }
    }

    var body: some Scene {
        WindowGroup("Wireshark Sentinel") {
            MainWindow()
                .environmentObject(model)
                .frame(minWidth: 1100, minHeight: 700)
                .task {
                    await model.bootstrap(
                        selfTestPath: options.selfTestPath,
                        seconds: options.seconds,
                        interfaceID: options.interfaceID
                    )
                }
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button("Export Sentinel Report") { model.exportReport() }
                    .keyboardShortcut("e", modifiers: [.command, .shift])
            }
        }
    }
}
