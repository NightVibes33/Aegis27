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
    let byteCount: Int64?
    let modificationDate: Date?
    let readable: Bool
    let writable: Bool
}

struct FileMetadataResult: Codable {
    let path: String
    let entry: FileEntry?
    let errorDescription: String?

    var succeeded: Bool { entry != nil }
}

struct DirectoryListingResult: Codable {
    let path: String
    let entries: [FileEntry]
    let errorDescription: String?

    var succeeded: Bool { errorDescription == nil }
}

struct FilePreviewResult: Codable {
    let path: String
    let bytesRead: Int
    let truncated: Bool
    let text: String?
    let hex: String
    let errorDescription: String?

    var succeeded: Bool { errorDescription == nil }
}

struct ProviderAccessCheck: Identifiable, Codable {
    let id: UUID
    let label: String
    let path: String
    let operation: String
    let succeeded: Bool
    let detail: String

    init(
        label: String,
        path: String,
        operation: String,
        succeeded: Bool,
        detail: String
    ) {
        self.id = UUID()
        self.label = label
        self.path = path
        self.operation = operation
        self.succeeded = succeeded
        self.detail = detail
    }
}

struct ProviderCapabilityReport: Codable {
    let provider: FileProviderKind
    let timestamp: Date
    let checks: [ProviderAccessCheck]

    var passedCount: Int { checks.filter(\.succeeded).count }
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
