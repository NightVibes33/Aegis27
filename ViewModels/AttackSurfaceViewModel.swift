import Foundation

@MainActor
final class AttackSurfaceViewModel: ObservableObject {
    private struct EvidenceExport: Encodable {
        let report: AttackSurfaceReport
        let crashCorrelations: [CrashCorrelationResult]
    }
    @Published private(set) var report: AttackSurfaceReport?
    @Published private(set) var isRunning = false
    @Published private(set) var exportURL: URL?
    @Published private(set) var catalog = FirmwareProbeCatalog.empty
    @Published private(set) var catalogFileName: String?
    @Published private(set) var catalogWarnings: [String] = []
    @Published private(set) var crashCorrelations: [CrashCorrelationResult] = []
    @Published private(set) var lastError: String?

    var hasCatalog: Bool { !catalog.services.isEmpty }

    func importCatalog(from url: URL, targetBuild: String, logger: AuditLogger) {
        do {
            let result = try FirmwareProbeCatalogImporter.load(
                from: url,
                targetBuild: targetBuild
            )
            catalog = result.catalog
            catalogFileName = result.fileName
            catalogWarnings = result.warnings
            lastError = nil
            logger.record(ResearchEvent(
                severity: result.warnings.isEmpty ? .success : .warning,
                subsystem: "firmware-catalog",
                message: "Firmware probe catalog imported",
                details: [
                    "file": result.fileName,
                    "sourceBuild": result.catalog.sourceBuild,
                    "services": String(result.catalog.services.count),
                    "schemas": String(result.catalog.services.flatMap(\.requests).count),
                    "iokitClasses": String(result.catalog.ioKitClasses.count),
                    "warnings": String(result.warnings.count)
                ]
            ))
        } catch {
            lastError = error.localizedDescription
            logger.record(ResearchEvent(
                severity: .failure,
                subsystem: "firmware-catalog",
                message: "Firmware probe catalog rejected",
                details: ["error": error.localizedDescription]
            ))
        }
    }

    func run(logger: AuditLogger) {
        guard !isRunning else { return }
        isRunning = true
        report = nil
        exportURL = nil
        crashCorrelations = []
        lastError = nil

        Task {
            let newReport = await AttackSurfaceProbeService.run(catalog: catalog)
            report = newReport
            exportURL = save(report: newReport)
            log(report: newReport, to: logger)
            isRunning = false
        }
    }

    func importCrashReport(from url: URL, logger: AuditLogger) {
        guard let report else {
            lastError = "Run the attack-surface suite before importing a diagnostic."
            return
        }
        do {
            let result = try CrashReportCorrelator.inspect(url: url, report: report)
            crashCorrelations.insert(result, at: 0)
            exportURL = save(report: report)
            lastError = nil
            logger.record(ResearchEvent(
                severity: result.classification == .matchingService && result.timingMatched
                    ? .warning : .info,
                subsystem: "crash-correlation",
                message: result.classification.title,
                details: [
                    "file": result.fileName,
                    "process": result.processName ?? "unknown",
                    "timingMatched": String(result.timingMatched),
                    "nearestService": result.nearestService ?? "none",
                    "nearestRequest": result.nearestRequestID ?? "none",
                    "sha256": result.sha256
                ]
            ))
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func save(report: AttackSurfaceReport) -> URL? {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(EvidenceExport(
                report: report,
                crashCorrelations: crashCorrelations
            ))
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
            lastError = error.localizedDescription
            return nil
        }
    }

    private func log(report: AttackSurfaceReport, to logger: AuditLogger) {
        logger.record(ResearchEvent(
            severity: report.protectedAccessConfirmed
                ? .failure
                : (report.stableProtocolLeadCount > 0 ? .warning : .success),
            subsystem: "attack-surface",
            message: report.protectedAccessConfirmed
                ? "Protected access changed after bounded probes"
                : "Bounded attack-surface suite completed",
            details: [
                "services": String(Set(report.serviceResults.map(\.service)).count),
                "requests": String(report.probedCount),
                "stableProtocolLeads": String(report.stableProtocolLeadCount),
                "protectedAccess": String(report.protectedAccessConfirmed),
                "parserChecks": String(report.parserResults.count),
                "iokitOpened": String(report.openedIOKitCount),
                "previousMatches": String(report.previousRunMatchedFingerprints),
                "differentBoot": String(report.previousRunWasDifferentBoot)
            ]
        ))

        for result in report.serviceResults where result.wasProbed {
            logger.record(ResearchEvent(
                severity: result.anomalous ? .warning : .info,
                subsystem: "attack-surface-service",
                message: "Bounded XPC probe: \(result.disposition?.title ?? "not run")",
                details: [
                    "service": result.service,
                    "request": result.requestID,
                    "repetition": String(result.repetition),
                    "lookupBefore": String(result.lookupBefore),
                    "lookupAfter": String(result.lookupAfter),
                    "elapsedMilliseconds": String(
                        format: "%.2f",
                        result.elapsedMilliseconds ?? 0
                    ),
                    "replyKeyCount": String(result.replyKeyCount),
                    "replyKeyHash": result.replyKeyHash,
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
