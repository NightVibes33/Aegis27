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

    var isAuthorizedTarget: Bool {
        hardwareIdentifier == "iPhone17,3" && majorVersion == 27
    }

    var targetDescription: String {
        "\(hardwareIdentifier) • \(systemName) \(systemVersion) (\(buildVersion))"
    }
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

