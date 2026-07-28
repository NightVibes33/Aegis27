import Foundation

@MainActor
final class PatchDiffViewModel: ObservableObject {
    @Published var baseBuild = ""
    @Published var targetBuild: String
    @Published var selectedSurfaces = PatchDiffSurface.recommended
    @Published var maximumCandidates = 100

    @Published private(set) var isSubmitting = false
    @Published private(set) var requestURL: URL?
    @Published private(set) var report: PatchDiffReport?
    @Published private(set) var lastError: String?
    @Published private(set) var message = "Enter the adjacent build immediately before this device build."

    init(profile: DeviceProfile) {
        targetBuild = profile.buildVersion
    }

    func set(_ surface: PatchDiffSurface, enabled: Bool) {
        if enabled {
            selectedSurfaces.insert(surface)
        } else {
            selectedSurfaces.remove(surface)
        }
    }

    func submit(profile: DeviceProfile, logger: AuditLogger) async {
        let bridge = GitHubRunnerBridge.shared
        guard bridge.isConnected else {
            lastError = PatchDiffRequestError.runnerNotConnected.localizedDescription
            return
        }
        guard !bridge.isWorking else {
            lastError = PatchDiffRequestError.runnerBusy.localizedDescription
            return
        }

        isSubmitting = true
        defer { isSubmitting = false }
        do {
            let request = try PatchDiffRequestService.makeRequest(
                device: profile.hardwareIdentifier,
                baseBuild: baseBuild,
                targetBuild: targetBuild,
                surfaces: selectedSurfaces,
                maximumCandidates: maximumCandidates
            )
            let url = try PatchDiffRequestService.save(request)
            requestURL = url
            report = nil
            lastError = nil
            message = "Request uploaded. The macOS runner will download both exact IPSWs and perform the selected static comparisons."

            logger.record(ResearchEvent(
                severity: .info,
                subsystem: "ipsw-patch-diff",
                message: "Submitted bounded IPSW patch-diff request",
                details: [
                    "device": request.device,
                    "baseBuild": request.baseBuild,
                    "targetBuild": request.targetBuild,
                    "surfaces": request.surfaces.map(\.rawValue).joined(separator: ","),
                ]
            ))

            await bridge.submitIfConnected(
                fileURL: url,
                kind: "ipsw-patch-diff",
                profile: profile,
                logger: logger
            )
            loadLatestResultIfAvailable()
        } catch {
            lastError = error.localizedDescription
            message = "The request was not submitted."
        }
    }

    func refresh(logger: AuditLogger) async {
        await GitHubRunnerBridge.shared.resumePending(logger: logger)
        loadLatestResultIfAvailable()
    }

    func loadLatestResultIfAvailable() {
        guard let url = GitHubRunnerBridge.shared.lastResultURL else { return }
        do {
            let loaded = try PatchDiffRequestService.loadReport(from: url)
            report = loaded
            lastError = nil
            message = "Static patch-diff report received. Review the ranking before creating bounded regression tests."
        } catch PatchDiffRequestError.invalidReport {
            // The runner bridge is shared with other report types. Ignore unrelated results.
        } catch {
            lastError = error.localizedDescription
        }
    }
}
