import Foundation

enum CrashClassification: String, Codable {
    case matchingService
    case aegisApp
    case jetsam
    case kernelPanic
    case unrelatedProcess
    case unknown

    var title: String {
        switch self {
        case .matchingService: return "Matching service termination"
        case .aegisApp: return "Aegis27 termination"
        case .jetsam: return "Memory-pressure termination"
        case .kernelPanic: return "Kernel panic marker"
        case .unrelatedProcess: return "Unrelated process"
        case .unknown: return "Unclassified diagnostic"
        }
    }
}

struct CrashCorrelationResult: Identifiable, Codable {
    let id: UUID
    let importedAt: Date
    let fileName: String
    let sha256: String
    let processName: String?
    let incidentTimestamp: Date?
    let classification: CrashClassification
    let timingMatched: Bool
    let nearestService: String?
    let nearestRequestID: String?
    let markerCounts: [String: Int]
}
