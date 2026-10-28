import AppKit
import Combine
import CoreLocation
import Foundation
import SentinelWiFi

/// UI state for the nearby Wi-Fi sheet. The scanner is injected so the sheet
/// can be exercised without a real radio, and the model owns the Location
/// authorization because macOS uses it to decide whether SSIDs are visible.
@MainActor
final class NearbyWiFiModel: NSObject, ObservableObject {
    @Published private(set) var snapshot: WiFiScanSnapshot?
    @Published private(set) var isScanning = false
    @Published private(set) var errorMessage: String?
    @Published private(set) var authorization: CLAuthorizationStatus = .notDetermined

    private let scanner: WiFiScanning
    private let locationManager = CLLocationManager()
    private var hasScanned = false
    private var pendingRescan = false

    init(scanner: WiFiScanning = SystemWiFiScanner()) {
        self.scanner = scanner
        super.init()
        locationManager.delegate = self
        authorization = locationManager.authorizationStatus
    }

    var isAuthorized: Bool {
        authorization == .authorized || authorization == .authorizedAlways
    }

    var isPermissionDenied: Bool {
        authorization == .denied || authorization == .restricted
    }

    /// One scan per press. If this is the first scan, macOS is asked for
    /// Location access so the names are not redacted; the scan still runs and
    /// shows redacted results if the prompt is declined. A grant after the
    /// prompt triggers one follow-up scan because the person already asked.
    func scan() {
        guard !isScanning else { return }
        hasScanned = true
        if authorization == .notDetermined {
            locationManager.requestWhenInUseAuthorization()
        }

        isScanning = true
        errorMessage = nil
        Task {
            do {
                snapshot = try await scanner.scan(includeHidden: true)
            } catch {
                let description = (error as? LocalizedError)?.errorDescription
                errorMessage = description ?? error.localizedDescription
            }
            isScanning = false
            if pendingRescan {
                pendingRescan = false
                scan()
            }
        }
    }

    func requestLocationAccess() {
        guard authorization == .notDetermined else { return }
        locationManager.requestWhenInUseAuthorization()
    }

    func openLocationSettings() {
        let candidates = [
            "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices",
            "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_LocationServices",
        ]
        for candidate in candidates {
            guard let url = URL(string: candidate) else { continue }
            if NSWorkspace.shared.open(url) { return }
        }
    }

    private func authorizationChanged(_ status: CLAuthorizationStatus) {
        let wasAuthorized = isAuthorized
        authorization = status
        guard hasScanned, !wasAuthorized, isAuthorized else { return }
        if isScanning {
            pendingRescan = true
        } else {
            scan()
        }
    }
}

extension NearbyWiFiModel: CLLocationManagerDelegate {
    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = manager.authorizationStatus
        Task { @MainActor [weak self] in
            self?.authorizationChanged(status)
        }
    }
}
