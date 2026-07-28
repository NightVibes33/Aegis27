import Foundation

enum CrashTriageParser: String, CaseIterable, Codable, Identifiable {
    case imageIO
    case propertyList
    case keyedArchive

    var id: String { rawValue }

    var title: String {
        switch self {
        case .imageIO: return "ImageIO"
        case .propertyList: return "Property list"
        case .keyedArchive: return "Keyed archive"
        }
    }
}

enum CrashMutationKind: String, CaseIterable, Codable {
    case bitFlip
    case overwrite
    case insert
    case deleteRange
    case truncate
    case duplicateSlice

    var title: String {
        switch self {
        case .bitFlip: return "Bit flip"
        case .overwrite: return "Overwrite"
        case .insert: return "Insert"
        case .deleteRange: return "Delete range"
        case .truncate: return "Truncate"
        case .duplicateSlice: return "Duplicate slice"
        }
    }
}

struct CrashMutationOperation: Codable, Hashable {
    let kind: CrashMutationKind
    let offset: Int
    let length: Int
    let value: UInt8?
}

struct CrashCorpusItem: Identifiable, Codable, Hashable {
    let id: UUID
    let importedAt: Date
    let originalFileName: String
    let storedFileName: String
    let byteCount: Int
    let sha256: String
    let suggestedParser: CrashTriageParser
}

enum CrashCaseStatus: String, Codable {
    case running
    case survived
    case recoveredTermination
    case discarded
}

enum CrashCaseOutcome: String, Codable {
    case accepted
    case rejected
    case slow
    case failed

    var title: String {
        switch self {
        case .accepted: return "Accepted"
        case .rejected: return "Rejected"
        case .slow: return "Slow"
        case .failed: return "Failed"
        }
    }

    var isInteresting: Bool {
        self == .slow || self == .failed
    }
}

struct CrashCaseJournal: Identifiable, Codable {
    let id: UUID
    let campaignID: UUID
    let sourceCorpusID: UUID
    let sourceSHA256: String
    let parser: CrashTriageParser
    let caseIndex: Int
    let seed: UInt64
    let inputFileName: String
    let inputSHA256: String
    let inputByteCount: Int
    let operations: [CrashMutationOperation]
    let deviceDescription: String
    let startedAt: Date
    var finishedAt: Date?
    var status: CrashCaseStatus
    let minimizationSessionID: UUID?
}

struct CrashCaseResult: Identifiable, Codable {
    let id: UUID
    let journalID: UUID
    let campaignID: UUID
    let sourceCorpusID: UUID
    let parser: CrashTriageParser
    let caseIndex: Int
    let seed: UInt64
    let inputFileName: String
    let inputSHA256: String
    let inputByteCount: Int
    let operations: [CrashMutationOperation]
    let outcome: CrashCaseOutcome
    let elapsedMilliseconds: Double
    let detail: String
    let finishedAt: Date

    init(journal: CrashCaseJournal, outcome: CrashCaseOutcome, elapsedMilliseconds: Double, detail: String) {
        self.id = UUID()
        self.journalID = journal.id
        self.campaignID = journal.campaignID
        self.sourceCorpusID = journal.sourceCorpusID
        self.parser = journal.parser
        self.caseIndex = journal.caseIndex
        self.seed = journal.seed
        self.inputFileName = journal.inputFileName
        self.inputSHA256 = journal.inputSHA256
        self.inputByteCount = journal.inputByteCount
        self.operations = journal.operations
        self.outcome = outcome
        self.elapsedMilliseconds = elapsedMilliseconds
        self.detail = detail
        self.finishedAt = Date()
    }
}

enum CrashFindingClassification: String, Codable {
    case appCrash
    case systemServiceCrash
    case memoryCorruptionSignal
    case resourceTermination
    case assertionFailure
    case unknown

    var title: String {
        switch self {
        case .appCrash: return "App crash"
        case .systemServiceCrash: return "System-service crash"
        case .memoryCorruptionSignal: return "Memory-corruption signal"
        case .resourceTermination: return "Resource termination"
        case .assertionFailure: return "Assertion failure"
        case .unknown: return "Unknown termination"
        }
    }
}

struct ImportedCrashLog: Identifiable, Codable {
    let id: UUID
    let importedAt: Date
    let originalFileName: String
    let storedFileName: String
    let byteCount: Int
    let sha256: String
    let processName: String
    let exceptionType: String
    let terminationReason: String
    let incidentIdentifier: String
    let operatingSystem: String
    let topFrames: [String]
    let signature: String
    let classification: CrashFindingClassification
    let correlatedJournalID: UUID?
}

struct CrashFinding: Identifiable, Codable {
    let id: UUID
    let signature: String
    let classification: CrashFindingClassification
    let processName: String
    let exceptionType: String
    let terminationReason: String
    var occurrences: Int
    var firstSeen: Date
    var lastSeen: Date
    var crashLogIDs: [UUID]
    var journalIDs: [UUID]
}

enum CrashMinimizationStatus: String, Codable {
    case active
    case awaitingRelaunch
    case completed
    case stalled
}

struct CrashMinimizationSession: Identifiable, Codable {
    let id: UUID
    let sourceJournalID: UUID
    let sourceCorpusID: UUID
    let parser: CrashTriageParser
    let originalFileName: String
    var currentFileName: String
    var currentSHA256: String
    let originalByteCount: Int
    var currentByteCount: Int
    var chunkSize: Int
    var nextOffset: Int
    var attempts: Int
    var reproducedCount: Int
    var lastCandidateFileName: String?
    var status: CrashMinimizationStatus
    var updatedAt: Date

    var reductionPercent: Double {
        guard originalByteCount > 0 else { return 0 }
        return 100 - (Double(currentByteCount) / Double(originalByteCount) * 100)
    }
}

struct CrashTriageExport: Codable {
    let formatVersion: Int
    let generatedAt: Date
    let corpus: [CrashCorpusItem]
    let recentCases: [CrashCaseResult]
    let importedCrashLogs: [ImportedCrashLog]
    let findings: [CrashFinding]
    let pendingCase: CrashCaseJournal?
    let minimization: CrashMinimizationSession?
}
