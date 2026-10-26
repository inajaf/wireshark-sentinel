import Darwin
import Foundation
import SentinelAttribution
import SentinelDomain
import XCTest

final class LsofSocketTableTests: XCTestCase {
    func testParsesTheMeasuredLsofShapes() throws {
        let lsof = try FakeLsof(rows: [
            "COMMAND     PID  USER   FD   TYPE             DEVICE SIZE/OFF   NODE NAME",
            "identitys   870 eldar    7u  IPv4 0x382a29eb59741d0e      0t0    UDP *:*",
            "sharingd    917 eldar   10u  IPv4 0x5541d715bd68d4f7      0t0    UDP *:64029",
            "DeepSeek 15843 eldar   33u  IPv4 0x6b34aa0c1f5d2e11      0t0    TCP 127.0.0.1:53275->127.0.0.1:62498 (ESTABLISHED)",
            "ControlCe   833 eldar    9u  IPv6 0xce13809c5efbed37      0t0    TCP [::1]:7000->[::1]:53275 (ESTABLISHED)",
            "rapportd    836 eldar    4u  IPv4 0xff4ca39b5cbc5a57      0t0    TCP *:64074 (LISTEN)",
        ])
        let attributor = ProcessAttributor(
            table: LsofSocketTable(lsofPath: lsof.path),
            signing: FixedSigning(.apple),
            paths: FixedPaths("/usr/bin/true")
        )
        attributor.refresh()

        XCTAssertEqual(
            attributor.process(remote: Endpoint(host: "127.0.0.1", port: 62498), localPort: 53275, transport: .tcp)?.pid,
            15843
        )
        XCTAssertEqual(
            attributor.process(remote: Endpoint(host: "::1", port: 53275), localPort: 7000, transport: .tcp)?.pid,
            833
        )
        XCTAssertEqual(
            attributor.process(remote: Endpoint(host: "8.8.8.8", port: 53), localPort: 64029, transport: .udp)?.pid,
            917
        )
    }

    func testIdentityCarriesResolvedPathNameAndSigning() throws {
        let lsof = try FakeLsof(rows: [
            "DeepSeek 15843 eldar   33u  IPv4 0x6b34aa0c1f5d2e11      0t0    TCP 127.0.0.1:53275->127.0.0.1:62498 (ESTABLISHED)",
        ])
        let attributor = ProcessAttributor(
            table: LsofSocketTable(lsofPath: lsof.path),
            signing: FixedSigning(.developerID(team: "ABCDE12345")),
            paths: FixedPaths("/Applications/DeepSeek.app/Contents/MacOS/DeepSeek")
        )
        attributor.refresh()

        let identity = try XCTUnwrap(
            attributor.process(remote: Endpoint(host: "127.0.0.1", port: 62498), localPort: 53275, transport: .tcp)
        )
        XCTAssertEqual(identity.pid, 15843)
        XCTAssertEqual(identity.name, "DeepSeek")
        XCTAssertEqual(identity.path, "/Applications/DeepSeek.app/Contents/MacOS/DeepSeek")
        XCTAssertEqual(identity.signing, .developerID(team: "ABCDE12345"))
    }

    func testRefusesToGuessWhenTheKeyIsMissing() throws {
        let lsof = try FakeLsof(rows: [
            "identitys   870 eldar    7u  IPv4 0x382a29eb59741d0e      0t0    UDP *:*",
            "rapportd    836 eldar    4u  IPv4 0xff4ca39b5cbc5a57      0t0    TCP *:64074 (LISTEN)",
        ])
        let attributor = ProcessAttributor(
            table: LsofSocketTable(lsofPath: lsof.path),
            signing: FixedSigning(.apple),
            paths: FixedPaths(nil)
        )
        attributor.refresh()

        XCTAssertNil(attributor.process(remote: Endpoint(host: "127.0.0.1", port: 443), localPort: 53275, transport: .tcp))
        XCTAssertNil(attributor.process(remote: Endpoint(host: "1.2.3.4", port: 443), localPort: 64074, transport: .tcp))
        XCTAssertNil(attributor.process(remote: Endpoint(host: "8.8.8.8", port: 53), localPort: 0, transport: .udp))
    }
}

final class ProcessAttributorLiveTests: XCTestCase {
    func testAttributesARealLoopbackConnectionToThisProcess() throws {
        let pair = try LoopbackPair()
        defer { pair.shutDown() }

        let remote = Endpoint(host: "127.0.0.1", port: pair.listenerPort)
        let attributor = ProcessAttributor()
        XCTAssertNil(attributor.process(remote: remote, localPort: pair.clientPort, transport: .tcp))

        attributor.refresh()

        let identity = try XCTUnwrap(attributor.process(remote: remote, localPort: pair.clientPort, transport: .tcp))
        XCTAssertEqual(identity.pid, ProcessInfo.processInfo.processIdentifier)
        XCTAssertNotNil(identity.path)
        XCTAssertNil(attributor.process(remote: Endpoint(host: "127.0.0.1", port: 9), localPort: pair.clientPort, transport: .tcp))
    }
}

final class CodesignSigningCheckerTests: XCTestCase {
    func testAppleSignedSystemBinary() {
        XCTAssertEqual(CodesignSigningChecker().status(forPath: "/bin/ls"), .apple)
    }

    func testAdHocSignedCopy() throws {
        let copy = try temporaryCopy(of: "/usr/bin/true")
        defer { try? FileManager.default.removeItem(at: copy) }
        XCTAssertEqual(try runTool("/usr/bin/codesign", ["-s", "-", "--force", copy.path]), 0)
        XCTAssertEqual(CodesignSigningChecker().status(forPath: copy.path), .adHoc)
    }

    func testUnsignedCopyIsUnsignedNotUnknown() throws {
        let copy = try temporaryCopy(of: "/bin/ls")
        defer { try? FileManager.default.removeItem(at: copy) }
        XCTAssertEqual(try runTool("/usr/bin/codesign", ["--remove-signature", copy.path]), 0)
        XCTAssertEqual(CodesignSigningChecker().status(forPath: copy.path), .unsigned)
    }

    func testUnreadablePathIsUnknown() {
        let missing = "/nonexistent/\(UUID().uuidString)"
        XCTAssertEqual(CodesignSigningChecker().status(forPath: missing), .unknown)
    }
}

private struct FixedSigning: SigningChecking {
    let value: SigningStatus
    init(_ value: SigningStatus) { self.value = value }
    func status(forPath path: String) -> SigningStatus { value }
}

private struct FixedPaths: ProcessPathResolving {
    let value: String?
    init(_ value: String?) { self.value = value }
    func path(forPID pid: Int32) -> String? { value }
}

private struct FakeLsof {
    let path: String

    init(rows: [String]) throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("fake-lsof-\(UUID().uuidString).sh")
        let script = "#!/bin/sh\ncat <<'LSOF_EOF'\n" + rows.joined(separator: "\n") + "\nLSOF_EOF\n"
        try script.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        path = url.path
    }
}

private struct LoopbackError: Error, CustomStringConvertible {
    let step: String
    var description: String { "loopback \(step) failed: \(String(cString: strerror(errno)))" }
}

private final class LoopbackPair {
    let listener: Int32
    let client: Int32
    let accepted: Int32
    let listenerPort: UInt16
    let clientPort: UInt16

    init() throws {
        let listenerFD = socket(AF_INET, SOCK_STREAM, 0)
        guard listenerFD >= 0 else { throw LoopbackError(step: "socket(listener)") }
        var reuse: Int32 = 1
        _ = setsockopt(listenerFD, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var listenerAddress = LoopbackPair.address(port: 0)
        guard bindSocket(listenerFD, to: &listenerAddress) == 0 else { throw LoopbackError(step: "bind") }
        guard listen(listenerFD, 1) == 0 else { throw LoopbackError(step: "listen") }
        let listeningPort = localPort(of: listenerFD)
        guard listeningPort != 0 else { throw LoopbackError(step: "getsockname(listener)") }

        let clientFD = socket(AF_INET, SOCK_STREAM, 0)
        guard clientFD >= 0 else { throw LoopbackError(step: "socket(client)") }
        var remote = LoopbackPair.address(port: listeningPort)
        guard connectSocket(clientFD, to: &remote) == 0 else { throw LoopbackError(step: "connect") }
        let acceptedFD = accept(listenerFD, nil, nil)
        guard acceptedFD >= 0 else { throw LoopbackError(step: "accept") }

        listener = listenerFD
        client = clientFD
        accepted = acceptedFD
        listenerPort = listeningPort
        clientPort = localPort(of: clientFD)
    }

    func shutDown() {
        Darwin.close(listener)
        Darwin.close(client)
        Darwin.close(accepted)
    }

    private static func address(port: UInt16) -> sockaddr_in {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        return address
    }
}

private func bindSocket(_ fd: Int32, to address: inout sockaddr_in) -> Int32 {
    withUnsafeMutablePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
            bind(fd, socketAddress, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
}

private func connectSocket(_ fd: Int32, to address: inout sockaddr_in) -> Int32 {
    withUnsafeMutablePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
            connect(fd, socketAddress, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
}

private func localPort(of fd: Int32) -> UInt16 {
    var address = sockaddr_in()
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let result = withUnsafeMutablePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
            getsockname(fd, socketAddress, &length)
        }
    }
    return result == 0 ? UInt16(bigEndian: address.sin_port) : 0
}

private func temporaryCopy(of path: String) throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("attribution-\(UUID().uuidString)")
    try FileManager.default.copyItem(at: URL(fileURLWithPath: path), to: url)
    return url
}

@discardableResult
private func runTool(_ executable: String, _ arguments: [String]) throws -> Int32 {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = Pipe()
    process.standardError = Pipe()
    try process.run()
    process.waitUntilExit()
    return process.terminationStatus
}
