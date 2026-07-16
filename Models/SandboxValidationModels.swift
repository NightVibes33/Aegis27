import Foundation

enum SandboxValidationStatus: String, Codable {
    case passed
    case denied
    case missing
    case unavailable
    case inconclusive

    var title: String {
        switch self {
        case .passed: return "Passed"
        case .denied: return "Permission denied"
        case .missing: return "File missing"
        case .unavailable: return "Provider unavailable"
        case .inconclusive: return "Inconclusive"
        }
    }
}

struct SandboxValidationCheck: Identifiable, Codable {
    let id: UUID
    let label: String
    let path: String
    let operation: String
    let status: SandboxValidationStatus
    let detail: String

    init(
        label: String,
        path: String,
        operation: String,
        status: SandboxValidationStatus,
        detail: String
    ) {
        self.id = UUID()
        self.label = label
        self.path = path
        self.operation = operation
        self.status = status
        self.detail = detail
    }
}

struct SandboxValidationReport: Codable {
    let provider: FileProviderKind
    let timestamp: Date
    let checks: [SandboxValidationCheck]
    let foreignContainerCount: Int

    var passedCount: Int { checks.filter { $0.status == .passed }.count }
    var accessConfirmed: Bool { passedCount > 0 }
}
