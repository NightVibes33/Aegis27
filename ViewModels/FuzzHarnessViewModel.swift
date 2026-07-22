import Foundation

@MainActor
final class FuzzHarnessViewModel: ObservableObject {
    @Published var intensity: FuzzIntensity = .standard
    @Published var iterations = 60
    @Published var seed = UInt64(Date().timeIntervalSince1970 * 1_000)
    @Published var parserEnabled = true
    @Published var sandboxFileEnabled = true
    @Published var xpcEnabled = true
    @Published var allowDestructiveSandboxMutations = false

    @Published private(set) var isRunning = false
    @Published private(set) var completedCases = 0
    @Published private(set) var totalCases = 0
    @Published private(set) var recentResults: [FuzzCaseResult] = []
    @Published private(set) var report: FuzzHarnessReport?
    @Published private(set) var exportURL: URL?
    @Published private(set) var pendingRecovery: FuzzCaseJournal?
    @Published private(set) var lastError: String?

    private var runTask: Task<Void, Never>?
    private var appliedAutomaticXPCCatalogDefaults = false

    init() {
        pendingRecovery = FuzzJournalStore.pendingIncompleteCase()
    }

    var enabledKinds: [FuzzCampaignKind] {
        var values: [FuzzCampaignKind] = []
        if parserEnabled { values.append(.parserMutation) }
        if sandboxFileEnabled { values.append(.sandboxFileMutation) }
        if xpcEnabled { values.append(.xpcSchemaMutation) }
        return values
    }

    func configureForAvailableXPCCatalog(_ catalog: FirmwareProbeCatalog) {
        guard !appliedAutomaticXPCCatalogDefaults,
              pendingRecovery == nil,
              !catalog.services.flatMap(\.requests).isEmpty else {
            return
        }

        appliedAutomaticXPCCatalogDefaults = true
        iterations = 300
        parserEnabled = false
        sandboxFileEnabled = false
        xpcEnabled = true
        allowDestructiveSandboxMutations = false
        lastError = nil
    }

    func useRecoveredCase() {
        guard let pendingRecovery else { return }
        seed = pendingRecovery.caseSeed
        parserEnabled = pendingRecovery.kind == .parserMutation
        sandboxFileEnabled = pendingRecovery.kind == .sandboxFileMutation
        xpcEnabled = pendingRecovery.kind == .xpcSchemaMutation
        iterations = 1
    }

    func run(catalog: FirmwareProbeCatalog, profile: DeviceProfile, logger: AuditLogger) {
        guard !isRunning else { return }
        guard !enabledKinds.isEmpty else {
            lastError = "Enable at least one campaign."
            return
        }
        guard !xpcEnabled || !catalog.services.flatMap(\.requests).isEmpty else {
            lastError = "No exact-build XPC catalog is available."
            return
        }
        guard !sandboxFileEnabled || allowDestructiveSandboxMutations else {
            lastError = "Arm destructive Aegis-corpus mutations or disable the sandbox file campaign."
            return
        }

        let configuration = FuzzHarnessConfiguration(
            campaignKinds: enabledKinds,
            intensity: intensity,
            seed: seed,
            iterations: iterations,
            timeoutMilliseconds: intensity.timeoutMilliseconds,
            maximumInputBytes: intensity.maximumInputBytes,
            allowDestructiveSandboxMutations: allowDestructiveSandboxMutations
        )

        isRunning = true
        completedCases = 0
        totalCases = iterations
        recentResults = []
        report = nil
        exportURL = nil
        lastError = nil

        runTask = Task {
            let newReport = await FuzzHarnessService.run(
                configuration: configuration,
                catalog: catalog
            ) { [weak self] completed, total, result in
                await MainActor.run {
                    guard let self else { return }
                    self.completedCases = completed
                    self.totalCases = total
                    self.recentResults.insert(result, at: 0)
                    self.recentResults = Array(self.recentResults.prefix(20))
                }
            }

            report = newReport
            exportURL = save(report: newReport)
            pendingRecovery = FuzzJournalStore.pendingIncompleteCase()
            log(report: newReport, logger: logger)
            if let exportURL {
                await GitHubRunnerBridge.shared.submitIfConnected(
                    fileURL: exportURL,
                    kind: "fuzz-harness",
                    profile: profile,
                    logger: logger
                )
            }
            isRunning = false
            runTask = nil
        }
    }

    func stop() {
        runTask?.cancel()
    }

    private func save(report: FuzzHarnessReport) -> URL? {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(report)
            let directory = FileManager.default.urls(
                for: .documentDirectory,
                in: .userDomainMask
            )[0].appendingPathComponent("ResearchLogs", isDirectory: true)
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true
            )
            let url = directory.appendingPathComponent("fuzz-harness-latest.json")
            try data.write(to: url, options: .atomic)
            return url
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    private func log(report: FuzzHarnessReport, logger: AuditLogger) {
        logger.record(ResearchEvent(
            severity: report.anomalousResults.isEmpty ? .success : .warning,
            subsystem: "fuzz-harness",
            message: report.cancelled ? "Fuzz campaign cancelled" : "Fuzz campaign completed",
            details: [
                "seed": String(report.configuration.seed),
                "cases": String(report.results.count),
                "anomalies": String(report.anomalousResults.count),
                "interesting": String(report.interestingCount),
                "timeouts": String(report.timeoutCount),
                "recoveredIncompleteCase": String(report.recoveredIncompleteCase != nil)
            ]
        ))

        for result in report.anomalousResults.prefix(25) {
            logger.record(ResearchEvent(
                severity: result.outcome == .failed ? .failure : .warning,
                subsystem: "fuzz-case",
                message: "\(result.kind.title): \(result.outcome.title)",
                details: [
                    "case": String(result.caseIndex),
                    "seed": String(result.caseSeed),
                    "label": result.label,
                    "fingerprint": result.inputFingerprint,
                    "elapsedMilliseconds": String(format: "%.2f", result.elapsedMilliseconds)
                ].merging(result.details) { current, _ in current }
            ))
        }
    }
}
