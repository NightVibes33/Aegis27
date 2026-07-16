import Foundation

enum FileProviderKind: String, CaseIterable, Identifiable, Codable {
    case stock
    case escaped

    var id: String { rawValue }

    var title: String {
        switch self {
        case .stock: return "Stock sandbox"
        case .escaped: return "Escaped provider"
        }
    }
}

struct FileEntry: Identifiable, Codable {
    var id: String { path }
    let name: String
    let path: String
    let isDirectory: Bool
    let isSymbolicLink: Bool
    let isRegularFile: Bool
    let byteCount: Int64?
    let modificationDate: Date?
    let readable: Bool
    let writable: Bool
}

enum FileAccessOutcome: String, Codable {
    case success
    case permissionDenied
    case missing
    case providerUnavailable
    case notTested
    case failed

    var title: String {
        switch self {
        case .success: return "Succeeded"
        case .permissionDenied: return "Permission denied"
        case .missing: return "Missing"
        case .providerUnavailable: return "Provider unavailable"
        case .notTested: return "Not tested"
        case .failed: return "Failed"
        }
    }
}

struct FileMetadataResult: Codable {
    let path: String
    let entry: FileEntry?
    let outcome: FileAccessOutcome
    let errorDescription: String?

    var succeeded: Bool { outcome == .success }
}

struct DirectoryListingResult: Codable {
    let path: String
    let entries: [FileEntry]
    let outcome: FileAccessOutcome
    let errorDescription: String?

    var succeeded: Bool { outcome == .success }
}

struct FilePreviewResult: Codable {
    let path: String
    let bytesRead: Int
    let truncated: Bool
    let text: String?
    let hex: String
    let outcome: FileAccessOutcome
    let errorDescription: String?

    var succeeded: Bool { outcome == .success }
}

struct ProviderAccessCheck: Identifiable, Codable {
    let id: UUID
    let label: String
    let path: String
    let operation: String
    let succeeded: Bool
    let outcome: FileAccessOutcome
    let detail: String

    init(
        label: String,
        path: String,
        operation: String,
        outcome: FileAccessOutcome,
        detail: String
    ) {
        self.id = UUID()
        self.label = label
        self.path = path
        self.operation = operation
        self.succeeded = outcome == .success
        self.outcome = outcome
        self.detail = detail
    }
}

struct ProviderCapabilityReport: Codable {
    let provider: FileProviderKind
    let timestamp: Date
    let checks: [ProviderAccessCheck]

    var passedCount: Int { checks.filter(\.succeeded).count }
    var containerPassedCount: Int {
        checks.filter { $0.label.hasPrefix("App container") && $0.succeeded }.count
    }
    var protectedMetadataVisible: Bool {
        checks.first { $0.label == "Protected metadata" }?.succeeded ?? false
    }
    var protectedDataPassedCount: Int {
        checks.filter {
            ($0.label == "Protected listing" || $0.label == "Protected file preview") &&
            $0.succeeded
        }.count
    }
}

enum ResearchTargetCategory: String, Codable {
    case mobileGestalt = "MobileGestalt"
    case preferences = "Preferences"
    case database = "System database"
    case personalData = "Personal data"
}

struct FileResearchTarget: Identifiable, Codable {
    var id: String { path }
    let name: String
    let path: String
    let category: ResearchTargetCategory
    let sensitive: Bool
    let intendedOperations: String
}

struct FileTargetObservation: Identifiable, Codable {
    var id: String { target.id }
    let target: FileResearchTarget
    let provider: FileProviderKind
    let metadataReadable: Bool
    let errorDescription: String?
}
