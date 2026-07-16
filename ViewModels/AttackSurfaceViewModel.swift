import Foundation

@MainActor
final class AttackSurfaceViewModel: ObservableObject {
    @Published private(set) var report: AttackSurfaceReport?
    @Published private(set) var isRunning = false
    @Published private(set) var exportURL: URL?

    func run(logger: AuditLogger) {
        guard !isRunning else { return }
        isRunning = true
        report = nil
        exportURL = nil

        Task {
            let newReport = await AttackSurfaceProbeService.run()
            report = newReport
            exportURL = save(report: newReport)
            log(report: newReport, to: logger)
            isRunning = false
        }
    }

    private func save(report: AttackSurfaceReport) -> URL? {
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
            let url = directory.appendingPathComponent("attack-surface-latest.json")
            try data.write(to: url, options: .atomic)
            return url
        } catch {
            return nil
        }
    }

    private func log(report: AttackSurfaceReport, to logger: AuditLogger) {
        logger.record(ResearchEvent(
            severity: report.protectedAccessConfirmed
                ? .failure
                : (report.anomalyCount > 0 ? .warning : .success),
            subsystem: "attack-surface",
            message: report.protectedAccessConfirmed
                ? "Protected access changed after bounded probes"
                : "Bounded attack-surface probe completed",
            details: [
                "services": String(report.serviceResults.count),
                "probed": String(report.probedCount),
                "anomalies": String(report.anomalyCount),
                "protectedAccess": String(report.protectedAccessConfirmed),
                "timeoutMilliseconds": String(report.timeoutMilliseconds)
            ]
        ))

        for result in report.serviceResults where result.wasProbed {
            logger.record(ResearchEvent(
                severity: result.anomalous ? .warning : .info,
                subsystem: "attack-surface-service",
                message: "Bounded XPC probe: \(result.disposition?.title ?? "not run")",
                details: [
                    "service": result.service,
                    "candidateSubsystem": result.subsystem,
                    "lookupBefore": String(result.lookupBefore),
                    "lookupAfter": String(result.lookupAfter),
                    "elapsedMilliseconds": String(
                        format: "%.2f",
                        result.elapsedMilliseconds ?? 0
                    ),
                    "anomalous": String(result.anomalous)
                ]
            ))
        }

        for check in report.validation.checks {
            logger.record(ResearchEvent(
                severity: check.status == .passed ? .failure : .info,
                subsystem: "attack-surface-validation",
                message: "Post-probe \(check.label): \(check.status.title)",
                details: [
                    "path": check.path,
                    "operation": check.operation,
                    "status": check.status.rawValue,
                    "detail": check.detail
                ]
            ))
        }
    }
}
