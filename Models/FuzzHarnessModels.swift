import Foundation

enum FuzzCampaignKind: String, CaseIterable, Codable, Identifiable {
    case parserMutation
    case sandboxFileMutation
    case xpcSchemaMutation

    var id: String { rawValue }

    var title: String {
        switch self {
        case .parserMutation: return "Parser mutation"
        case .sandboxFileMutation: return "Sandbox file mutation"
        case .xpcSchemaMutation: return "XPC schema mutation"
        }
    }
}

enum FuzzIntensity: String, CaseIterable, Codable, Identifiable {
    case standard
    case aggressive

    var id: String { rawValue }

    var title: String {
        switch self {
        case .standard: return "Standard"
        case .aggressive: return "Aggressive"
        }
    }

    var maximumInputBytes: Int {
        switch self {
        case .standard: return 64 * 1024
        case .aggressive: return 256 * 1024
        }
    }

    var timeoutMilliseconds: UInt32 {
        switch self {
        case .standard: return 750
        case .aggressive: return 1_250
        }
    }
}

enum FuzzCaseOutcome: String, Codable {
    case completed
    case accepted
    case rejected
    case skipped
    case timedOut
    case slow
    case interesting
    case failed

    var title: String {
        switch self {
        case .completed: return "Completed"
        case .accepted: return "Accepted"
        case .rejected: return "Rejected"
        case .skipped: return "Skipped"
        case .timedOut: return "Timed out"
        case .slow: return "Slow"
        case .interesting: return "Interesting"
        case .failed: return "Failed"
        }
    }

    var isAnomalous: Bool {
        self == .timedOut || self == .slow || self == .interesting || self == .failed
    }
}

enum FuzzJournalStatus: String, Codable {
    case running
    case completed
    case cancelled
}

struct FuzzHarnessConfiguration: Codable {
    let campaignKinds: [FuzzCampaignKind]
    let intensity: FuzzIntensity
    let seed: UInt64
    let iterations: Int
    let timeoutMilliseconds: UInt32
    let maximumInputBytes: Int
    let allowDestructiveSandboxMutations: Bool
}

struct FuzzCaseJournal: Codable, Identifiable {
    let id: UUID
    let campaignID: UUID
    let caseIndex: Int
    let caseSeed: UInt64
    let kind: FuzzCampaignKind
    let startedAt: Date
    var finishedAt: Date?
    var status: FuzzJournalStatus
}

struct FuzzCaseResult: Identifiable, Codable {
    let id: UUID
    let caseIndex: Int
    let caseSeed: UInt64
    let kind: FuzzCampaignKind
    let label: String
    let outcome: FuzzCaseOutcome
    let elapsedMilliseconds: Double
    let inputFingerprint: String
    let details: [String: String]

    init(
        caseIndex: Int,
        caseSeed: UInt64,
        kind: FuzzCampaignKind,
        label: String,
        outcome: FuzzCaseOutcome,
        elapsedMilliseconds: Double,
        inputFingerprint: String,
        details: [String: String] = [:]
    ) {
        self.id = UUID()
        self.caseIndex = caseIndex
        self.caseSeed = caseSeed
        self.kind = kind
        self.label = label
        self.outcome = outcome
        self.elapsedMilliseconds = elapsedMilliseconds
        self.inputFingerprint = inputFingerprint
        self.details = details
    }
}

struct FuzzHarnessReport: Codable {
    let id: UUID
    let startedAt: Date
    let finishedAt: Date
    let configuration: FuzzHarnessConfiguration
    let recoveredIncompleteCase: FuzzCaseJournal?
    let cancelled: Bool
    let results: [FuzzCaseResult]

    var anomalousResults: [FuzzCaseResult] {
        results.filter { $0.outcome.isAnomalous }
    }

    var interestingCount: Int {
        results.filter { $0.outcome == .interesting }.count
    }

    var timeoutCount: Int {
        results.filter { $0.outcome == .timedOut }.count
    }
}
