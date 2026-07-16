import Foundation

enum ResearchSeverity: String, Codable {
    case info
    case success
    case warning
    case failure
}

struct ResearchEvent: Identifiable, Codable {
    let id: UUID
    let timestamp: Date
    let severity: ResearchSeverity
    let subsystem: String
    let message: String
    let details: [String: String]

    init(
        severity: ResearchSeverity,
        subsystem: String,
        message: String,
        details: [String: String] = [:]
    ) {
        self.id = UUID()
        self.timestamp = Date()
        self.severity = severity
        self.subsystem = subsystem
        self.message = message
        self.details = details
    }
}

struct DeviceProfile: Codable {
    let hardwareIdentifier: String
    let systemName: String
    let systemVersion: String
    let buildVersion: String
    let majorVersion: Int

    var targetDescription: String {
        "\(hardwareIdentifier) • \(systemName) \(systemVersion) (\(buildVersion))"
    }
}

struct RuntimeCapabilitySummary: Codable {
    let publicGestaltRead: Bool
    let sandboxPolicyAPI: Bool
    let appContainerWrite: Bool
    let protectedMetadataRead: Bool
    let protectedDataPolicyAllowed: Bool
    let protectedWritePolicyAllowed: Bool
    let reachableMachServices: Int

    static let pending = RuntimeCapabilitySummary(
        publicGestaltRead: false,
        sandboxPolicyAPI: false,
        appContainerWrite: false,
        protectedMetadataRead: false,
        protectedDataPolicyAllowed: false,
        protectedWritePolicyAllowed: false,
        reachableMachServices: 0
    )
}

struct MobileGestaltValue: Identifiable, Codable {
    var id: String { key }
    let key: String
    let value: String
    let available: Bool
}

struct CapabilityProbeResult: Identifiable, Codable {
    let id: UUID
    let path: String
    let readable: Bool
    let writableAccordingToMetadata: Bool
    let visibleEntryCount: Int?
    let errorDescription: String?

    init(
        path: String,
        readable: Bool,
        writableAccordingToMetadata: Bool,
        visibleEntryCount: Int?,
        errorDescription: String?
    ) {
        self.id = UUID()
        self.path = path
        self.readable = readable
        self.writableAccordingToMetadata = writableAccordingToMetadata
        self.visibleEntryCount = visibleEntryCount
        self.errorDescription = errorDescription
    }
}

struct CanaryWriteResult: Codable {
    let targetDirectory: String
    let created: Bool
    let removed: Bool
    let errorDescription: String?
}

enum SandboxPolicySubjectKind: String, Codable {
    case path
    case machService
}

struct SandboxPolicyResult: Identifiable, Codable {
    let id: UUID
    let kind: SandboxPolicySubjectKind
    let subject: String
    let operation: String
    let rawResult: Int32

    init(
        kind: SandboxPolicySubjectKind,
        subject: String,
        operation: String,
        rawResult: Int32
    ) {
        self.id = UUID()
        self.kind = kind
        self.subject = subject
        self.operation = operation
        self.rawResult = rawResult
    }

    var apiAvailable: Bool { rawResult != Int32.min }
    var allowed: Bool { apiAvailable && rawResult == 0 }
}

struct MachServiceLookupResult: Identifiable, Codable {
    let id: UUID
    let service: String
    let rawResult: Int32

    init(service: String, rawResult: Int32) {
        self.id = UUID()
        self.service = service
        self.rawResult = rawResult
    }

    var reachable: Bool { rawResult == 0 }
}

struct MachServiceConnectionResult: Identifiable, Codable {
    let id: UUID
    let service: String
    let lookupResult: Int32
    let portType: UInt32
    let sendRightRefs: UInt32

    init(
        service: String,
        lookupResult: Int32,
        portType: UInt32,
        sendRightRefs: UInt32
    ) {
        self.id = UUID()
        self.service = service
        self.lookupResult = lookupResult
        self.portType = portType
        self.sendRightRefs = sendRightRefs
    }

    var resolved: Bool { lookupResult == 0 }
}

enum ResearchExperiment: String, CaseIterable, Identifiable, Codable {
    case gestaltInventory
    case filesystemMetadata
    case sandboxPolicy
    case machServices

    var id: String { rawValue }

    var title: String {
        switch self {
        case .gestaltInventory: return "MobileGestalt inventory"
        case .filesystemMetadata: return "Filesystem metadata"
        case .sandboxPolicy: return "Sandbox policy"
        case .machServices: return "Mach service inventory"
        }
    }

    var detail: String {
        switch self {
        case .gestaltInventory:
            return "Repeats the curated, non-unique read-only key inventory."
        case .filesystemMetadata:
            return "Checks protected-directory visibility without opening existing files."
        case .sandboxPolicy:
            return "Records policy decisions for the fixed path and service catalog."
        case .machServices:
            return "Resolves candidate services and inspects then releases returned ports."
        }
    }
}

struct ExperimentRecord: Identifiable, Codable {
    let id: UUID
    let timestamp: Date
    let experiment: ResearchExperiment
    let summary: String

    init(experiment: ResearchExperiment, summary: String) {
        self.id = UUID()
        self.timestamp = Date()
        self.experiment = experiment
        self.summary = summary
    }
}

struct ResearchSnapshot: Identifiable, Codable {
    let id: UUID
    let timestamp: Date
    let profile: DeviceProfile
    let runtimeCapabilities: RuntimeCapabilitySummary
    let gestaltValues: [MobileGestaltValue]
    let capabilityResults: [CapabilityProbeResult]
    let sandboxPolicyResults: [SandboxPolicyResult]
    let machServiceResults: [MachServiceLookupResult]
    let machConnectionResults: [MachServiceConnectionResult]
}

struct SnapshotDifference: Identifiable, Codable {
    var id: String { key }
    let key: String
    let previousValue: String
    let currentValue: String
}

struct ImportedDiagnostic: Identifiable, Codable {
    let id: UUID
    let importedAt: Date
    let fileName: String
    let byteCount: Int64
    let sha256: String
    let signalCounts: [String: Int]
}
