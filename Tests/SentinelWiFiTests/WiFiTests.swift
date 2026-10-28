import XCTest
@testable import SentinelWiFi

final class SentinelWiFiTests: XCTestCase {
    // MARK: - Signal

    func testSignalBarsAndQualityUseTheStatedThresholds() {
        XCTAssertEqual(WiFiSignal.bars(for: -45), 4)
        XCTAssertEqual(WiFiSignal.bars(for: -50), 4)
        XCTAssertEqual(WiFiSignal.bars(for: -51), 3)
        XCTAssertEqual(WiFiSignal.bars(for: -60), 3)
        XCTAssertEqual(WiFiSignal.bars(for: -61), 2)
        XCTAssertEqual(WiFiSignal.bars(for: -70), 2)
        XCTAssertEqual(WiFiSignal.bars(for: -71), 1)
        XCTAssertEqual(WiFiSignal.bars(for: -80), 1)
        XCTAssertEqual(WiFiSignal.bars(for: -81), 0)

        XCTAssertEqual(WiFiSignal.quality(for: -45), .excellent)
        XCTAssertEqual(WiFiSignal.quality(for: -65), .fair)
        XCTAssertEqual(WiFiSignal.quality(for: -75), .weak)
        XCTAssertEqual(WiFiSignal.quality(for: -90), .veryWeak)
    }

    func testSNRIsOnlyReportedWhenNoiseIsReal() {
        let measured = WiFiNetwork(ssid: "home", rssi: -60, noise: -92, channel: 6)
        XCTAssertEqual(measured.snr, 32)

        XCTAssertNil(WiFiNetwork(ssid: "home", rssi: -60, channel: 6).snr)
        XCTAssertNil(WiFiNetwork(ssid: "home", rssi: -60, noise: 0, channel: 6).snr)
        XCTAssertNil(WiFiNetwork(ssid: "home", rssi: 0, noise: -90, channel: 6).snr)
    }

    // MARK: - Names and grouping

    func testGroupsMergeTheSameSSIDAndKeepHiddenRadiosSeparate() {
        let networks = [
            WiFiNetwork(ssid: "Home", bssid: "aa:00:00:00:00:01", rssi: -70, channel: 1, band: .twoPointFour),
            WiFiNetwork(ssid: "Home", bssid: "aa:00:00:00:00:02", rssi: -45, channel: 44, band: .five),
            WiFiNetwork(ssid: nil, bssid: "bb:00:00:00:00:01", rssi: -55, channel: 6, band: .twoPointFour),
            WiFiNetwork(ssid: nil, bssid: "bb:00:00:00:00:02", rssi: -66, channel: 11, band: .twoPointFour),
        ]

        let groups = WiFiDiagnostics.groups(networks)
        XCTAssertEqual(groups.count, 3)

        let home = try? XCTUnwrap(groups.first { $0.name == "Home" })
        XCTAssertEqual(home?.accessPointCount, 2)
        XCTAssertEqual(home?.best?.bssid, "aa:00:00:00:00:02")
        XCTAssertEqual(home?.bands, [.twoPointFour, .five])
        XCTAssertTrue(home?.hasVisibleName == true)

        let hidden = groups.filter { !$0.hasVisibleName }
        XCTAssertEqual(hidden.count, 2)
        XCTAssertTrue(hidden.allSatisfy { $0.name == "Hidden network" })
        XCTAssertTrue(hidden.allSatisfy { $0.accessPointCount == 1 })
        XCTAssertTrue(groups[0].best?.rssi == -45)
    }

    func testGroupsSortByBestSignalThenName() {
        let networks = [
            WiFiNetwork(ssid: "zulu", rssi: -70, channel: 1),
            WiFiNetwork(ssid: "alpha", rssi: -70, channel: 6),
            WiFiNetwork(ssid: "bravo", rssi: -40, channel: 11),
        ]
        let groups = WiFiDiagnostics.groups(networks)
        XCTAssertEqual(groups.map(\.name), ["bravo", "alpha", "zulu"])
    }

    func testEmptyAndWhitespaceSSIDIsHidden() {
        let network = WiFiNetwork(ssid: "   ", rssi: -50, channel: 1)
        XCTAssertFalse(network.hasVisibleName)
        XCTAssertEqual(network.displayName, "Hidden network")
        XCTAssertEqual(WiFiDiagnostics.groups([network]).first?.hasVisibleName, false)
    }

    // MARK: - Channels

    func testTwoPointFourLoadsAlwaysShowThirteenChannels() {
        let networks = [
            WiFiNetwork(ssid: "a", rssi: -50, channel: 1, band: .twoPointFour),
            WiFiNetwork(ssid: "b", rssi: -60, channel: 1, band: .twoPointFour),
            WiFiNetwork(ssid: "c", rssi: -70, channel: 6, band: .twoPointFour),
        ]
        let loads = WiFiDiagnostics.channelLoads(networks, band: .twoPointFour)

        XCTAssertEqual(loads.count, 13)
        XCTAssertEqual(loads.first?.channel, 1)
        XCTAssertEqual(loads.first?.networkCount, 2)
        XCTAssertEqual(loads.first?.strongestRSSI, -50)
        XCTAssertEqual(loads[5].networkCount, 1)
        XCTAssertEqual(loads[11].networkCount, 0)
        XCTAssertEqual(loads.first?.heat, 2)
    }

    func testFiveGigahertzLoadsOnlyShowChannelsWithNetworks() {
        let networks = [
            WiFiNetwork(ssid: "a", rssi: -50, channel: 44, band: .five),
            WiFiNetwork(ssid: "b", rssi: -55, channel: 149, band: .five),
            WiFiNetwork(ssid: "c", rssi: -60, channel: 6, band: .twoPointFour),
        ]
        let loads = WiFiDiagnostics.channelLoads(networks, band: .five)
        XCTAssertEqual(loads.map(\.channel), [44, 149])
        XCTAssertTrue(WiFiDiagnostics.channelLoads(networks, band: .six).isEmpty)
    }

    func testAdvicePicksTheLeastUsedChannelInTheBand() {
        let networks = [
            WiFiNetwork(ssid: "a", rssi: -50, channel: 1, band: .twoPointFour),
            WiFiNetwork(ssid: "b", rssi: -55, channel: 1, band: .twoPointFour),
            WiFiNetwork(ssid: "c", rssi: -60, channel: 6, band: .twoPointFour),
        ]
        let advice = WiFiDiagnostics.advice(networks, band: .twoPointFour)
        XCTAssertEqual(advice?.channel, 11)
        XCTAssertEqual(advice?.networkCount, 0)

        XCTAssertNil(WiFiDiagnostics.advice(networks, band: .five))
        XCTAssertNil(WiFiDiagnostics.advice([], band: .twoPointFour))
        XCTAssertNil(WiFiDiagnostics.advice(networks, band: .six))
    }

    func testFiveGigahertzAdviceDoesNotChooseADFSChannel() {
        let networks = [WiFiNetwork(ssid: "a", rssi: -50, channel: 36, band: .five)]
        let advice = WiFiDiagnostics.advice(networks, band: .five)
        XCTAssertEqual(advice?.channel, 40)
        XCTAssertFalse([52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144].contains(advice?.channel ?? 0))
    }

    // MARK: - Security

    func testSecuritySummaryCountsOpenLegacyAndUnknown() {
        let networks = [
            WiFiNetwork(ssid: "open", rssi: -40, channel: 1, security: .open),
            WiFiNetwork(ssid: "wep", rssi: -50, channel: 6, security: .wep),
            WiFiNetwork(ssid: "wpa", rssi: -55, channel: 11, security: .wpa),
            WiFiNetwork(ssid: "modern", rssi: -60, channel: 44, security: .wpa3),
            WiFiNetwork(ssid: "odd", rssi: -70, channel: 149, security: .unknown),
        ]
        let summary = WiFiDiagnostics.securitySummary(networks)

        XCTAssertEqual(summary.openCount, 1)
        XCTAssertEqual(summary.legacyCount, 2)
        XCTAssertEqual(summary.unknownCount, 1)
        XCTAssertEqual(summary.weakCount, 3)
        XCTAssertTrue(summary.hasWeakNetworks)
    }

    func testSecurityLabelsAndLegacyFlags() {
        XCTAssertEqual(WiFiSecurity.wpa3Transition.label, "WPA2/WPA3")
        XCTAssertEqual(WiFiSecurity.wpa2Enterprise.label, "WPA2 Enterprise")
        XCTAssertTrue(WiFiSecurity.wpaMixed.isLegacy)
        XCTAssertFalse(WiFiSecurity.wpa2.isLegacy)
        XCTAssertFalse(WiFiSecurity.owe.isOpen)
        XCTAssertTrue(WiFiSecurity.open.isOpen)
        XCTAssertEqual(WiFiSecurity.open.rank, 0)
        XCTAssertGreaterThan(WiFiSecurity.wpa3Enterprise.rank, WiFiSecurity.wpa2.rank)
    }

    // MARK: - Current network

    func testCurrentNetworkIsBuiltFromTheInterfaceAndCanBeAbsent() {
        let snapshot = WiFiScanSnapshot(
            networks: [],
            interfaceName: "en0",
            currentSSID: "Home",
            currentBSSID: "aa:00:00:00:00:01",
            currentRSSI: -52,
            currentNoise: -90,
            currentChannel: 44,
            currentBand: .five,
            currentWidth: .eighty,
            currentSecurity: .wpa3,
            currentPHY: "802.11ax (Wi-Fi 6)"
        )
        let current = snapshot.currentNetwork

        XCTAssertEqual(current?.ssid, "Home")
        XCTAssertEqual(current?.band, .five)
        XCTAssertEqual(current?.width, .eighty)
        XCTAssertEqual(current?.security, .wpa3)
        XCTAssertEqual(current?.snr, 38)

        let empty = WiFiScanSnapshot(
            networks: [],
            interfaceName: "en0",
            currentRSSI: 0,
            currentSecurity: .unknown
        )
        XCTAssertNil(empty.currentNetwork)
    }

    func testConnectedGroupIDMatchesTheBSSIDAndRefusesToGuess() {
        let networks = [
            WiFiNetwork(ssid: "Home", bssid: "AA:00:00:00:00:01", rssi: -52, channel: 44, band: .five),
            WiFiNetwork(ssid: "Home", bssid: "AA:00:00:00:00:02", rssi: -70, channel: 1, band: .twoPointFour),
        ]
        let groups = WiFiDiagnostics.groups(networks)
        XCTAssertEqual(
            WiFiDiagnostics.connectedGroupID(groups, currentBSSID: "aa:00:00:00:00:02"),
            groups.first?.id
        )
        XCTAssertNil(WiFiDiagnostics.connectedGroupID(groups, currentBSSID: nil))
        XCTAssertNil(WiFiDiagnostics.connectedGroupID(groups, currentBSSID: "cc:00:00:00:00:01"))
    }

    func testHiddenNameCountUsesOnlyNonEmptyNames() {
        let snapshot = WiFiScanSnapshot(
            networks: [
                WiFiNetwork(ssid: "Home", rssi: -40, channel: 1),
                WiFiNetwork(ssid: nil, rssi: -60, channel: 6),
                WiFiNetwork(ssid: "", rssi: -70, channel: 11),
            ],
            interfaceName: "en0"
        )
        XCTAssertEqual(snapshot.hiddenNameCount, 2)
    }

    // MARK: - Duplicate scan entries

    func testDuplicateBSSIDsKeepTheStrongestReport() {
        let networks = [
            WiFiNetwork(ssid: nil, bssid: "FA:22:29:CC:10:4D", rssi: -49, channel: 44, band: .five),
            WiFiNetwork(ssid: nil, bssid: "fa:22:29:cc:10:4d", rssi: -45, channel: 44, band: .five),
            WiFiNetwork(ssid: nil, bssid: "fa:22:29:cc:10:4d", rssi: -52, channel: 44, band: .five),
            WiFiNetwork(ssid: "Home", bssid: "AA:00:00:00:00:01", rssi: -60, channel: 1, band: .twoPointFour),
        ]

        let deduped = SystemWiFiScanner.dedupe(networks)
        XCTAssertEqual(deduped.count, 2)
        let hidden = deduped.first { $0.bssid?.lowercased() == "fa:22:29:cc:10:4d" }
        XCTAssertEqual(hidden?.rssi, -45)
        XCTAssertEqual(WiFiDiagnostics.groups(deduped).filter { !$0.hasVisibleName }.count, 1)
    }

    func testDedupeKeepsEntriesWithoutABSSID() {
        let networks = [
            WiFiNetwork(ssid: nil, rssi: -50, channel: 1),
            WiFiNetwork(ssid: nil, rssi: -70, channel: 6),
            WiFiNetwork(ssid: "Home", bssid: "", rssi: -60, channel: 11),
        ]

        XCTAssertEqual(SystemWiFiScanner.dedupe(networks).count, 3)
    }
}
