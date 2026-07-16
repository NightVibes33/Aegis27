import Foundation

@MainActor
final class ResearchViewModel: ObservableObject {
    @Published private(set) var profile = DeviceProfiler.current()
    @Published private(set) var gestaltValues: [MobileGestaltValue] = []
    @Published private(set) var capabilityResults: [CapabilityProbeResult] = []
    @Published private(set) var sandboxPolicyResults: [SandboxPolicyResult] = []
    @Published private(set) var machServiceResults: [MachServiceLookupResult] = []
    @Published private(set) var machConnectionResults: [MachServiceConnectionResult] = []
    @Published private(set) var runtimeCapabilities = RuntimeCapabilitySummary.pending
    @Published private(set) var snapshotDifferences: [SnapshotDifference] = []
    @Published private(set) var snapshotURL: URL?
    @Published private(set) var experimentRecords: [ExperimentRecord] = []
    @Published private(set) var importedDiagnostics: [ImportedDiagnostic] = []
    @Published var selectedExperiment: ResearchExperiment = .gestaltInventory
    @Published private(set) var isExperimentRunning = false
    @Published var isWriteTestingArmed = false
    @Published var selectedCanaryTarget = FileCapabilityProbe.researchTargets[0]
    @Published private(set) var primitiveSummary = "Not validated"

    let logger = AuditLogger()
    let canaryTargets = FileCapabilityProbe.researchTargets
    private let primitive: any PrivilegedAccessPrimitive = UnavailablePrimitive()

    func refreshBaseline() {
        profile = DeviceProfiler.current()
        gestaltValues = MobileGestaltReader.readBaseline()
        capabilityResults = canaryTargets.map(FileCapabilityProbe.inspect(path:))
        sandboxPolicyResults = SandboxPolicyProbe.run()
        machServiceResults = MachServiceReachabilityProbe.run()
        machConnectionResults = []
        updateRuntimeCapabilities()

        logger.record(ResearchEvent(
            severity: .success,
            subsystem: "target",
            message: "Runtime target profile captured",
            details: [
                "hardware": profile.hardwareIdentifier,
                "version": profile.systemVersion,
                "build": profile.buildVersion
            ]
        ))

        for value in gestaltValues {
            logger.record(ResearchEvent(
                severity: value.available ? .success : .info,
                subsystem: "mobilegestalt",
                message: value.available
                    ? "MobileGestalt value read"
                    : "MobileGestalt value unavailable",
                details: [
                    "key": value.key,
                    "value": value.value
                ]
            ))
        }

        for result in capabilityResults {
            logger.record(ResearchEvent(
                severity: result.readable ? .success : .info,
                subsystem: "filesystem-probe",
                message: result.readable ? "Directory metadata readable" : "Directory access denied",
                details: [
                    "path": result.path,
                    "readable": String(result.readable),
                    "writable": String(result.writableAccordingToMetadata),
                    "error": result.errorDescription ?? "none"
                ]
            ))
        }

        for result in sandboxPolicyResults {
            logger.record(ResearchEvent(
                severity: result.allowed ? .warning : .info,
                subsystem: "sandbox-policy",
                message: result.allowed
                    ? "Sandbox policy allows operation"
                    : "Sandbox policy denies operation",
                details: [
                    "kind": result.kind.rawValue,
                    "subject": result.subject,
                    "operation": result.operation,
                    "rawResult": String(result.rawResult),
                    "apiAvailable": String(result.apiAvailable)
                ]
            ))
        }

        for result in machServiceResults {
            logger.record(ResearchEvent(
                severity: result.reachable ? .warning : .info,
                subsystem: "mach-service",
                message: result.reachable
                    ? "Mach service resolved through bootstrap"
                    : "Mach service lookup failed",
                details: [
                    "service": result.service,
                    "rawResult": String(result.rawResult),
                    "reachable": String(result.reachable)
                ]
            ))
        }

        Task {
            let reachableServices = machServiceResults
                .filter(\.reachable)
                .map(\.service)
            let connectionResults = await MachServiceConnectionProbe.run(
                services: reachableServices
            )
            machConnectionResults = connectionResults
            updateRuntimeCapabilities()

            for result in connectionResults {
                logger.record(ResearchEvent(
                    severity: result.resolved ? .warning : .info,
                    subsystem: "xpc-connection",
                    message: result.resolved
                        ? "Mach service port inspected"
                        : "Mach service port inspection failed",
                    details: [
                        "service": result.service,
                        "lookupResult": String(result.lookupResult),
                        "portType": String(result.portType),
                        "sendRightRefs": String(result.sendRightRefs)
                    ]
                ))
            }

            let validation = await primitive.validate()
            primitiveSummary = validation.summary
            logger.record(ResearchEvent(
                severity: .info,
                subsystem: "primitive",
                message: validation.summary,
                details: ["availability": validation.availability.rawValue]
            ))
        }
    }

    func runCanaryWrite() {
        guard isWriteTestingArmed else {
            logger.record(ResearchEvent(
                severity: .warning,
                subsystem: "canary",
                message: "Blocked canary write because testing is not armed"
            ))
            return
        }

        let result = FileCapabilityProbe.writeCanary(to: selectedCanaryTarget)
        logger.record(ResearchEvent(
            severity: result.created && result.removed ? .success : .failure,
            subsystem: "canary",
            message: result.created
                ? "Canary creation reached target directory"
                : "Canary creation denied as expected under the stock sandbox",
            details: [
                "path": result.targetDirectory,
                "created": String(result.created),
                "removed": String(result.removed),
                "error": result.errorDescription ?? "none"
            ]
        ))

        isWriteTestingArmed = false
        capabilityResults = canaryTargets.map(FileCapabilityProbe.inspect(path:))
        sandboxPolicyResults = SandboxPolicyProbe.run()
        updateRuntimeCapabilities()
    }

    func runSelectedExperiment() {
        guard !isExperimentRunning else { return }
        isExperimentRunning = true

        switch selectedExperiment {
        case .gestaltInventory:
            gestaltValues = MobileGestaltReader.readBaseline()
            finishExperiment(
                summary: "\(gestaltValues.filter(\.available).count) of \(gestaltValues.count) curated keys available"
            )
        case .filesystemMetadata:
            capabilityResults = canaryTargets.map(FileCapabilityProbe.inspect(path:))
            finishExperiment(
                summary: "\(capabilityResults.filter(\.readable).count) of \(capabilityResults.count) protected directories readable"
            )
        case .sandboxPolicy:
            sandboxPolicyResults = SandboxPolicyProbe.run()
            finishExperiment(
                summary: "\(sandboxPolicyResults.filter(\.allowed).count) of \(sandboxPolicyResults.filter(\.apiAvailable).count) policy checks allowed"
            )
        case .machServices:
            machServiceResults = MachServiceReachabilityProbe.run()
            Task {
                machConnectionResults = await MachServiceConnectionProbe.run(
                    services: machServiceResults.filter(\.reachable).map(\.service)
                )
                finishExperiment(
                    summary: "\(machServiceResults.filter(\.reachable).count) services resolved; all acquired ports released"
                )
            }
        }
    }

    func saveSnapshot() {
        let previous = SnapshotStore.loadLatest()
        let snapshot = makeSnapshot()
        do {
            snapshotURL = try SnapshotStore.save(snapshot)
            snapshotDifferences = previous.map {
                SnapshotStore.differences(previous: $0, current: snapshot)
            } ?? []
            logger.record(ResearchEvent(
                severity: .success,
                subsystem: "snapshot",
                message: previous == nil
                    ? "Initial research snapshot saved"
                    : "Research snapshot saved and compared",
                details: [
                    "changes": String(snapshotDifferences.count),
                    "snapshot": snapshot.id.uuidString
                ]
            ))
        } catch {
            logger.record(ResearchEvent(
                severity: .failure,
                subsystem: "snapshot",
                message: "Research snapshot could not be saved",
                details: ["error": String(describing: error)]
            ))
        }
    }

    func importDiagnostic(from url: URL) {
        do {
            let diagnostic = try DiagnosticImporter.inspect(url: url)
            importedDiagnostics.insert(diagnostic, at: 0)
            logger.record(ResearchEvent(
                severity: .success,
                subsystem: "diagnostic-import",
                message: "Diagnostic metadata imported",
                details: [
                    "file": diagnostic.fileName,
                    "bytes": String(diagnostic.byteCount),
                    "sha256": diagnostic.sha256,
                    "signals": String(diagnostic.signalCounts.values.reduce(0, +))
                ]
            ))
        } catch {
            logger.record(ResearchEvent(
                severity: .failure,
                subsystem: "diagnostic-import",
                message: "Diagnostic import failed",
                details: ["error": String(describing: error)]
            ))
        }
    }

    private func finishExperiment(summary: String) {
        updateRuntimeCapabilities()
        let record = ExperimentRecord(
            experiment: selectedExperiment,
            summary: summary
        )
        experimentRecords.insert(record, at: 0)
        logger.record(ResearchEvent(
            severity: .success,
            subsystem: "experiment",
            message: record.experiment.title,
            details: ["summary": summary]
        ))
        isExperimentRunning = false
    }

    private func updateRuntimeCapabilities() {
        runtimeCapabilities = RuntimeCapabilityEvaluator.evaluate(
            gestaltValues: gestaltValues,
            capabilityResults: capabilityResults,
            sandboxPolicyResults: sandboxPolicyResults,
            machServiceResults: machServiceResults
        )
    }

    private func makeSnapshot() -> ResearchSnapshot {
        ResearchSnapshot(
            id: UUID(),
            timestamp: Date(),
            profile: profile,
            runtimeCapabilities: runtimeCapabilities,
            gestaltValues: gestaltValues,
            capabilityResults: capabilityResults,
            sandboxPolicyResults: sandboxPolicyResults,
            machServiceResults: machServiceResults,
            machConnectionResults: machConnectionResults
        )
    }
}
