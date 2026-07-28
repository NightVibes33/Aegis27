import Foundation

@MainActor
final class CrashTriageViewModel: ObservableObject {
    @Published var parser: CrashTriageParser = .imageIO
    @Published var seed = UInt64(Date().timeIntervalSince1970 * 1_000)
    @Published var iterations = 60
    @Published var selectedCorpusID: UUID?

    @Published private(set) var corpus: [CrashCorpusItem] = []
    @Published private(set) var recentCases: [CrashCaseResult] = []
    @Published private(set) var crashLogs: [ImportedCrashLog] = []
    @Published private(set) var findings: [CrashFinding] = []
    @Published private(set) var pendingCase: CrashCaseJournal?
    @Published private(set) var minimization: CrashMinimizationSession?
    @Published private(set) var completedCases = 0
    @Published private(set) var totalCases = 0
    @Published private(set) var isRunning = false
    @Published private(set) var isMinimizing = false
    @Published private(set) var statusMessage = "Import a small image, plist, or keyed archive to begin."
    @Published private(set) var lastError: String?
    @Published private(set) var exportURL: URL?
    @Published private(set) var minimizedURL: URL?

    private var task: Task<Void, Never>?

    init() {
        refresh()
    }

    var selectedCorpus: CrashCorpusItem? {
        guard let selectedCorpusID else { return corpus.first }
        return corpus.first(where: { $0.id == selectedCorpusID }) ?? corpus.first
    }

    func refresh() {
        try? CrashTriageStore.prepareDirectories()
        corpus = CrashTriageStore.loadCorpus()
        recentCases = CrashTriageStore.loadResults()
        crashLogs = CrashTriageStore.loadCrashLogs()
        findings = CrashTriageStore.loadFindings()
        pendingCase = CrashTriageStore.pendingCase()
        minimization = CrashTriageStore.loadMinimization()
        if selectedCorpusID == nil {
            selectedCorpusID = corpus.first?.id
            if let first = corpus.first {
                parser = first.suggestedParser
            }
        }
        minimizedURL = minimization.flatMap(CrashTriageService.minimizedFileURL)
        exportURL = try? CrashTriageService.exportSnapshot()

        if let pendingCase {
            statusMessage = pendingCase.minimizationSessionID == nil
                ? "Recovered an unfinished parser case. Import its .ips log before classifying it."
                : "A minimization candidate was still running when Aegis stopped. Confirm whether it reproduced the crash."
        } else if let minimization, minimization.status == .completed {
            statusMessage = "Minimization completed with a \(minimization.currentByteCount)-byte testcase."
        }
    }

    func importCorpus(from url: URL) {
        do {
            let item = try CrashTriageService.importCorpus(from: url)
            refresh()
            selectedCorpusID = item.id
            parser = item.suggestedParser
            statusMessage = "Imported \(item.originalFileName) (\(item.byteCount) bytes)."
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func deleteCorpus(_ item: CrashCorpusItem) {
        do {
            try CrashTriageService.deleteCorpus(item)
            if selectedCorpusID == item.id {
                selectedCorpusID = nil
            }
            refresh()
            statusMessage = "Removed \(item.originalFileName) from the Aegis corpus."
        } catch {
            lastError = error.localizedDescription
        }
    }

    func selectCorpus(_ item: CrashCorpusItem) {
        selectedCorpusID = item.id
        parser = item.suggestedParser
    }

    func run(profile: DeviceProfile, logger: AuditLogger) {
        guard !isRunning, !isMinimizing else { return }
        guard pendingCase == nil else {
            lastError = "Resolve the recovered case before starting another campaign."
            return
        }
        guard let corpus = selectedCorpus else {
            lastError = "Import and select a corpus file first."
            return
        }

        isRunning = true
        completedCases = 0
        totalCases = min(max(1, iterations), 300)
        lastError = nil
        statusMessage = "Running deterministic \(parser.title) mutations."
        let selectedParser = parser
        let selectedSeed = seed
        let selectedIterations = iterations
        let deviceDescription = profile.targetDescription

        task = Task {
            do {
                try await CrashTriageService.runCampaign(
                    corpus: corpus,
                    parser: selectedParser,
                    seed: selectedSeed,
                    iterations: selectedIterations,
                    deviceDescription: deviceDescription
                ) { [weak self] completed, total, result in
                    await MainActor.run {
                        guard let self else { return }
                        self.completedCases = completed
                        self.totalCases = total
                        self.recentCases.insert(result, at: 0)
                        self.recentCases = Array(self.recentCases.prefix(100))
                        self.statusMessage = "Case \(completed)/\(total): \(result.outcome.title)"
                    }
                }
                statusMessage = Task.isCancelled ? "Campaign stopped." : "Campaign completed."
                logger.record(ResearchEvent(
                    severity: .success,
                    subsystem: "crash-triage",
                    message: Task.isCancelled ? "Crash triage campaign stopped" : "Crash triage campaign completed",
                    details: [
                        "parser": selectedParser.rawValue,
                        "seed": String(selectedSeed),
                        "cases": String(completedCases),
                        "corpusSHA256": corpus.sha256
                    ]
                ))
            } catch {
                lastError = error.localizedDescription
                statusMessage = "Campaign failed before completion."
            }
            isRunning = false
            task = nil
            refresh()
        }
    }

    func replay(_ result: CrashCaseResult, profile: DeviceProfile, logger: AuditLogger) {
        guard !isRunning, !isMinimizing else { return }
        guard pendingCase == nil else {
            lastError = "Resolve the recovered case before replaying another input."
            return
        }
        guard let source = corpus.first(where: { $0.id == result.sourceCorpusID }) else {
            lastError = "The original corpus file for this case is no longer available."
            return
        }

        isRunning = true
        statusMessage = "Replaying case \(result.caseIndex) with seed \(result.seed)."
        task = Task {
            do {
                let replayed = try await CrashTriageService.replay(
                    result,
                    corpus: source,
                    deviceDescription: profile.targetDescription
                )
                recentCases.insert(replayed, at: 0)
                statusMessage = "Replay returned \(replayed.outcome.title.lowercased())."
                logger.record(ResearchEvent(
                    severity: replayed.outcome.isInteresting ? .warning : .info,
                    subsystem: "crash-triage-replay",
                    message: "Deterministic parser case replayed",
                    details: [
                        "seed": String(replayed.seed),
                        "parser": replayed.parser.rawValue,
                        "inputSHA256": replayed.inputSHA256,
                        "outcome": replayed.outcome.rawValue
                    ]
                ))
            } catch {
                lastError = error.localizedDescription
            }
            isRunning = false
            task = nil
            refresh()
        }
    }

    func importCrashLog(from url: URL, logger: AuditLogger) {
        do {
            let log = try CrashTriageService.importCrashLog(from: url, correlatedCase: pendingCase)
            refresh()
            statusMessage = "Imported \(log.classification.title) signature \(log.signature.prefix(12))."
            logger.record(ResearchEvent(
                severity: log.classification == .memoryCorruptionSignal ? .warning : .info,
                subsystem: "crash-log",
                message: "Crash log imported and deduplicated",
                details: [
                    "process": log.processName,
                    "classification": log.classification.rawValue,
                    "signature": log.signature,
                    "correlatedCase": String(log.correlatedJournalID != nil)
                ]
            ))
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func discardPending() {
        CrashTriageStore.discardPendingCase()
        refresh()
        statusMessage = "Recovered case discarded as unconfirmed."
    }

    func startMinimization() {
        guard !isRunning, !isMinimizing else { return }
        guard let pendingCase, pendingCase.minimizationSessionID == nil else {
            lastError = "No recovered campaign testcase is ready for minimization."
            return
        }
        guard crashLogs.contains(where: { $0.correlatedJournalID == pendingCase.id }) else {
            lastError = "Import the matching crash log before preparing minimization."
            return
        }
        do {
            minimization = try CrashTriageService.prepareMinimization(from: pendingCase)
            refresh()
            statusMessage = "Minimization prepared. Start it only after confirming this input reproduces the crash."
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func resumeMinimization(
        assumingPendingCandidateCrashed: Bool,
        profile: DeviceProfile,
        logger: AuditLogger
    ) {
        guard !isRunning, !isMinimizing else { return }
        guard let session = minimization else {
            lastError = "No minimization session is available."
            return
        }

        isMinimizing = true
        lastError = nil
        statusMessage = "Testing deletion candidates. Surviving candidates continue automatically."
        task = Task {
            do {
                let updated = try await CrashTriageService.resumeMinimization(
                    session,
                    assumingPendingCandidateCrashed: assumingPendingCandidateCrashed,
                    deviceDescription: profile.targetDescription
                ) { [weak self] value in
                    await MainActor.run {
                        self?.minimization = value
                        self?.statusMessage = "Minimization attempt \(value.attempts), best \(value.currentByteCount) bytes."
                    }
                }
                minimization = updated
                minimizedURL = CrashTriageService.minimizedFileURL(updated)
                statusMessage = updated.status == .completed
                    ? "Minimization completed: \(updated.originalByteCount) → \(updated.currentByteCount) bytes."
                    : "Minimization paused after \(updated.attempts) attempts."
                logger.record(ResearchEvent(
                    severity: updated.reproducedCount > 0 ? .warning : .info,
                    subsystem: "crash-minimizer",
                    message: "Restart-aware minimization updated",
                    details: [
                        "status": updated.status.rawValue,
                        "originalBytes": String(updated.originalByteCount),
                        "currentBytes": String(updated.currentByteCount),
                        "attempts": String(updated.attempts),
                        "reproduced": String(updated.reproducedCount)
                    ]
                ))
            } catch {
                lastError = error.localizedDescription
            }
            isMinimizing = false
            task = nil
            refresh()
        }
    }

    func export() {
        do {
            exportURL = try CrashTriageService.exportSnapshot()
            statusMessage = "Crash-triage snapshot exported."
        } catch {
            lastError = error.localizedDescription
        }
    }

    func stop() {
        task?.cancel()
    }
}
