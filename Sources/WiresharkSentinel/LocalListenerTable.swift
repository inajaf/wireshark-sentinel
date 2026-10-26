import Foundation

/// Which local ports something is actually listening on.
///
/// An inbound connection to a port nobody listens on is worth reporting. An inbound
/// connection to a port with a listener is a service doing its job, and flagging it
/// would make the verdicts meaningless.
enum LocalListenerTable {
    static func current() async -> Set<UInt16> {
        await Task.detached(priority: .utility) { snapshot() }.value
    }

    static func snapshot() -> Set<UInt16> {
        var ports: Set<UInt16> = []
        ports.formUnion(portsFrom(arguments: ["-nP", "-iTCP", "-sTCP:LISTEN"]))
        ports.formUnion(portsFrom(arguments: ["-nP", "-iUDP"]))
        return ports
    }

    private static func portsFrom(arguments: [String]) -> Set<UInt16> {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return []
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard let text = String(data: data, encoding: .utf8) else { return [] }
        return parse(text)
    }

    /// Reads the `NAME` column of `lsof -i` output and keeps the local port of each row.
    static func parse(_ text: String) -> Set<UInt16> {
        var ports: Set<UInt16> = []
        for line in text.split(separator: "\n").dropFirst() {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            guard let name = fields.last(where: { $0.contains(":") }) else { continue }
            if let port = port(inNameField: String(name)) {
                ports.insert(port)
            }
        }
        return ports
    }

    private static func port(inNameField field: String) -> UInt16? {
        let cleaned = field.hasSuffix("(LISTEN)") ? field.replacingOccurrences(of: "(LISTEN)", with: "") : field
        let localSide = cleaned.split(separator: ">").first.map(String.init) ?? cleaned
        guard let colon = localSide.lastIndex(of: ":") else { return nil }
        let digits = localSide[localSide.index(after: colon)...].prefix { $0.isNumber }
        guard !digits.isEmpty else { return nil }
        return UInt16(digits)
    }
}
