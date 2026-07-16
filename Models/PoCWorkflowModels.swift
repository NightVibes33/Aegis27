import Foundation

enum PoCLeadKind: String, Codable {
    case protectedAccess
    case serviceCrash
    case typedXPC
    case emptyXPC
    case parserBoundary
    case ioKitUserClient
    case none
}

enum PrimitiveHypothesis: String, Codable {
    case sandboxEscapeConfirmed
    case memorySafetyCandidate
    case confusedDeputyCandidate
    case kernelSurfaceCandidate
    case parserCandidate
    case unclassified

    var title: String {
        switch self {
        case .sandboxEscapeConfirmed: return "Sandbox escape confirmed"
        case .memorySafetyCandidate: return "Memory-safety candidate"
        case .confusedDeputyCandidate: return "Confused-deputy candidate"
        case .kernelSurfaceCandidate: return "Kernel-facing surface candidate"
        case .parserCandidate: return "Parser-boundary candidate"
        case .unclassified: return "No primitive classified"
        }
    }
}

enum PoCWorkflowStatus: String, Codable {
    case confirmedImpact
    case reproducibleCandidate
    case needsRebootConfirmation
    case leadOnly
    case noLead

    var title: String {
        switch self {
        case .confirmedImpact: return "Controlled security impact confirmed"
        case .reproducibleCandidate: return "Reproducible PoC candidate"
        case .needsRebootConfirmation: return "Reproduce after reboot"
        case .leadOnly: return "Lead requires more evidence"
        case .noLead: return "No PoC candidate found"
        }
    }
}

struct PoCLead: Identifiable, Codable {
    let id: String
    let kind: PoCLeadKind
    let title: String
    let service: String?
    let requestID: String?
    let fingerprint: String?
    let corpusID: String?
    let ioKitClass: String?
}

struct XPCMinimizationAttempt: Identifiable, Codable {
    let id: UUID
    let removedKey: String?
    let remainingKeys: [String]
    let fingerprints: [String]
    let preservedExpectedFingerprint: Bool
    let protectedAccessConfirmed: Bool

    init(
        removedKey: String?,
        remainingKeys: [String],
        fingerprints: [String],
        preservedExpectedFingerprint: Bool,
        protectedAccessConfirmed: Bool
    ) {
        self.id = UUID()
        self.removedKey = removedKey
        self.remainingKeys = remainingKeys
        self.fingerprints = fingerprints
        self.preservedExpectedFingerprint = preservedExpectedFingerprint
        self.protectedAccessConfirmed = protectedAccessConfirmed
    }
}

struct XPCMinimizationResult: Codable {
    let service: String
    let requestID: String
    let expectedFingerprint: String
    let originalFields: [XPCProbeField]
    let minimizedFields: [XPCProbeField]
    let initialReproductionStable: Bool
    let attempts: [XPCMinimizationAttempt]

    var removedFieldCount: Int {
        originalFields.count - minimizedFields.count
    }
}

struct PoCWorkflowReport: Identifiable, Codable {
    let id: UUID
    let createdAt: Date
    let sourceReportID: UUID
    let target: DeviceProfile
    let lead: PoCLead
    let primitiveHypothesis: PrimitiveHypothesis
    let status: PoCWorkflowStatus
    let minimization: XPCMinimizationResult?
    let crashEvidence: [CrashCorrelationResult]
    let validation: SandboxValidationReport
    let repeatedInDiscoveryRun: Bool
    let crossBootConfirmed: Bool
    let limitations: [String]

    var controlledImpactConfirmed: Bool { validation.accessConfirmed }
}
