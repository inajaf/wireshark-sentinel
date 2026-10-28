import XCTest
import SentinelDomain
@testable import SentinelBlock

final class BlockPlannerTests: XCTestCase {
    func testLoopbackMulticastBroadcastAndUnknownTargetsAreRefused() {
        for address in ["127.0.0.1", "224.0.0.251", "255.255.255.255", "not-an-ip", "0.0.0.0", "::1"] {
            let plan = BlockPlanBuilder.plan(targets: [BlockTarget(address: address)])
            XCTAssertFalse(plan.isValid, "\(address) must be refused")
            XCTAssertTrue(plan.targets.isEmpty)
            XCTAssertFalse(plan.errors.isEmpty)
        }
    }

    func testThisMacIsRefusedByExactAddress() {
        let plan = BlockPlanBuilder.plan(
            targets: [BlockTarget(address: "192.168.1.10")],
            localAddresses: ["192.168.1.10", "127.0.0.1"]
        )
        XCTAssertFalse(plan.isValid)
        XCTAssertTrue(plan.errors.joined().contains("this Mac"))
    }

    func testRangeContainingThisMacIsAllowedWithAWarning() {
        let plan = BlockPlanBuilder.plan(
            targets: [BlockTarget(address: "192.168.1.0/24")],
            localAddresses: ["192.168.1.10"]
        )
        XCTAssertTrue(plan.isValid)
        XCTAssertEqual(plan.targets.first?.address, "192.168.1.0/24")
        XCTAssertTrue(plan.warnings.joined().contains("local device"))
    }

    func testBroadAndPortZeroRangesAreRefused() {
        XCTAssertFalse(BlockPlanBuilder.plan(targets: [BlockTarget(address: "0.0.0.0/0")]).isValid)
        XCTAssertFalse(BlockPlanBuilder.plan(targets: [BlockTarget(address: "1.0.0.0/4")]).isValid)
        XCTAssertFalse(BlockPlanBuilder.plan(targets: [BlockTarget(address: "2001:db8::/16")]).isValid)
        XCTAssertFalse(BlockPlanBuilder.plan(targets: [BlockTarget(address: "203.0.113.9", port: 0)]).isValid)
    }

    func testBothDirectionsUseTablesAndQuickRules() {
        let plan = BlockPlanBuilder.plan(targets: [BlockTarget(address: "203.0.113.9")])
        XCTAssertTrue(plan.isValid)
        let text = plan.rules.map(\.text).joined(separator: "\n")
        XCTAssertTrue(text.contains("table <sentinel_block_out_v4> persist { 203.0.113.9 }"))
        XCTAssertTrue(text.contains("table <sentinel_block_in_v4> persist { 203.0.113.9 }"))
        XCTAssertTrue(text.contains("block drop quick inet from any to <sentinel_block_out_v4>"))
        XCTAssertTrue(text.contains("block drop quick inet from <sentinel_block_in_v4> to any"))
    }

    func testPortSpecificRulesNameTheProtocolAndPort() {
        let plan = BlockPlanBuilder.plan(targets: [
            BlockTarget(address: "203.0.113.9", port: 443, transport: .tcp, direction: .outbound),
        ])
        XCTAssertTrue(plan.isValid)
        let text = plan.rules.map(\.text).joined(separator: "\n")
        XCTAssertTrue(text.contains("block drop quick inet proto tcp from any to 203.0.113.9 port = 443"))
        XCTAssertFalse(text.contains("<sentinel_block_out_v4>"))
    }

    func testIPv6RulesUseInet6() {
        let plan = BlockPlanBuilder.plan(targets: [
            BlockTarget(address: "2606:4700:4700::1111", port: 443, transport: .tcp, direction: .inbound),
        ])
        XCTAssertTrue(plan.isValid)
        XCTAssertTrue(plan.rules.map(\.text).contains {
            $0.contains("block drop quick inet6 proto tcp from 2606:4700:4700::1111 port = 443 to any")
        })
    }

    func testCIDRIsNormalizedAndWarnedAbout() {
        let plan = BlockPlanBuilder.plan(targets: [BlockTarget(address: "192.168.10.77/24")])
        XCTAssertTrue(plan.isValid)
        XCTAssertEqual(plan.targets.first?.address, "192.168.10.0/24")
        XCTAssertTrue(plan.warnings.joined().contains("range"))
    }

    func testEmptyPlanIsValidForClearing() {
        let plan = BlockPlanBuilder.plan(targets: [])
        XCTAssertTrue(plan.isValid)
        XCTAssertTrue(plan.isEmpty)
        XCTAssertTrue(plan.rules.isEmpty)
    }
}

final class BlockScriptTests: XCTestCase {
    func testScriptIsValidShell() throws {
        let plan = BlockPlanBuilder.plan(targets: [
            BlockTarget(address: "203.0.113.9"),
            BlockTarget(address: "2606:4700:4700::1111", port: 443, transport: .tcp),
        ])
        XCTAssertTrue(plan.isValid)
        let script = PFBlockController.script(plan: plan, persistAfterReboot: true)

        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("sentinel-script-\(UUID().uuidString).sh")
        try script.write(to: file, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: file) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-n", file.path]
        let pipe = Pipe()
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let error = String(decoding: data, as: UTF8.self)
        XCTAssertEqual(process.terminationStatus, 0, "shell syntax error: \(error)")
    }

    func testScriptContainsOneAnchorLoadAndThePersistenceSwitch() {
        let plan = BlockPlanBuilder.plan(targets: [BlockTarget(address: "203.0.113.9")])
        let persistent = PFBlockController.script(plan: plan, persistAfterReboot: true)
        XCTAssertTrue(persistent.contains("pfctl -a com.local.sentinel -f \"$ANCHOR\""))
        XCTAssertTrue(persistent.contains("pfctl -a com.local.sentinel -F Tables"))
        XCTAssertTrue(persistent.contains("com.local.sentinel.pf.plist"))
        XCTAssertTrue(persistent.contains("SENTINEL_ANCHOR_BEGIN"))
        XCTAssertTrue(persistent.contains("pfctl -k '203.0.113.9'"))

        let temporary = PFBlockController.script(plan: plan, persistAfterReboot: false)
        XCTAssertTrue(temporary.contains("rm -f \"$DAEMON\""))
    }

    func testAnchorNamesEveryTarget() {
        let plan = BlockPlanBuilder.plan(targets: [BlockTarget(address: "203.0.113.9", note: "test")])
        let anchor = PFBlockController.anchorText(plan: plan)
        XCTAssertTrue(anchor.contains("# Targets: 203.0.113.9"))
        XCTAssertTrue(anchor.contains("block drop quick inet"))
    }

    func testControllerRunsOneScriptThroughTheInjectedRunner() async throws {
        let runner = RecordingRunner()
        let plan = BlockPlanBuilder.plan(targets: [BlockTarget(address: "203.0.113.9")])
        let result = try await PFBlockController(runner: runner).apply(plan: plan, persistAfterReboot: false)
        XCTAssertEqual(result.output, "applied")
        XCTAssertEqual(runner.scripts.count, 1)
        XCTAssertTrue(runner.scripts[0].contains("pfctl"))
    }

    func testControllerRefusesAnInvalidPlanWithoutRunningAnything() async {
        let runner = RecordingRunner()
        let plan = BlockPlanBuilder.plan(targets: [BlockTarget(address: "127.0.0.1")])
        XCTAssertFalse(plan.isValid)

        do {
            _ = try await PFBlockController(runner: runner).apply(plan: plan, persistAfterReboot: false)
            XCTFail("an invalid plan must not reach the firewall")
        } catch {
            XCTAssertTrue(String(describing: error).contains("invalid block plan"))
        }
        XCTAssertTrue(runner.scripts.isEmpty)
    }
}

private final class RecordingRunner: PrivilegedRunning, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    var scripts: [String] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    func run(script: String) async throws -> String {
        lock.lock()
        storage.append(script)
        lock.unlock()
        return "applied"
    }
}

final class BlockStoreTests: XCTestCase {
    func testRecordsAndAuditSurviveARoundTrip() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("sentinel-store-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = BlockStore(url: directory.appendingPathComponent("blocks.json"))

        let record = BlockRecord(
            target: BlockTarget(address: "203.0.113.9", port: 443, transport: .tcp, direction: .outbound, note: "manual"),
            reason: "test",
            appliedAt: Date(),
            active: true,
            ruleText: "block drop quick inet proto tcp from any to 203.0.113.9 port = 443"
        )
        let audit = BlockAuditEntry(action: "block", targets: ["203.0.113.9:443"], result: "applied")
        try store.save(BlockState(records: [record], audit: [audit], persistAfterReboot: true))

        let loaded = store.load()
        XCTAssertEqual(loaded.records.count, 1)
        XCTAssertEqual(loaded.records.first?.target.address, "203.0.113.9")
        XCTAssertEqual(loaded.records.first?.target.port, 443)
        XCTAssertEqual(loaded.records.first?.active, true)
        XCTAssertEqual(loaded.audit.first?.action, "block")
        XCTAssertTrue(loaded.persistAfterReboot)
    }
}
