import Foundation

@MainActor
final class ResearchViewModel: ObservableObject {
    @Published private(set) var profile = DeviceProfiler.current()
    @Published private(set) var gestaltValues: [MobileGestaltValue] = []
    @Published private(set) var capabilityResults: [CapabilityProbeResult] = []
    @Published private(set) var sandboxPolicyResults: [SandboxPolicyResult] = []
    @Published private(set) var machServiceResults: [MachServiceLookupResult] = []
    @Published private(set) var machConnectionResults: [MachServiceConnectionResult] = []
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

        logger.record(ResearchEvent(
            severity: profile.isAuthorizedTarget ? .success : .warning,
            subsystem: "target",
            message: profile.isAuthorizedTarget
                ? "Exact authorized target profile matched"
                : "Target profile mismatch; write tests remain blocked",
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

            for result in connectionResults {
                logger.record(ResearchEvent(
                    severity: result.stableAfterResume ? .warning : .info,
                    subsystem: "xpc-connection",
                    message: result.stableAfterResume
                        ? "Mach service connection stayed stable after resume"
                        : "Mach service connection interrupted or invalidated",
                    details: [
                        "service": result.service,
                        "resumed": String(result.resumed),
                        "interrupted": String(result.interrupted),
                        "invalidated": String(result.invalidated),
                        "error": result.errorDescription ?? "none"
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
        guard profile.isAuthorizedTarget else {
            logger.record(ResearchEvent(
                severity: .failure,
                subsystem: "canary",
                message: "Blocked canary write because target profile does not match",
                details: ["target": profile.targetDescription]
            ))
            return
        }

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
    }
}
