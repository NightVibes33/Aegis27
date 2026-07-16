import Foundation

enum XPCProbeDisposition: Int32, Codable {
    case dictionaryReply = 0
    case errorReply = 1
    case otherReply = 2
    case timedOut = 3
    case apiUnavailable = 4
    case setupFailed = 5

    var title: String {
        switch self {
        case .dictionaryReply: return "Dictionary reply"
        case .errorReply: return "Rejected by service"
        case .otherReply: return "Non-dictionary reply"
        case .timedOut: return "No reply before timeout"
        case .apiUnavailable: return "XPC probe unavailable"
        case .setupFailed: return "Probe setup failed"
        }
    }
}

struct AttackSurfaceServiceResult: Identifiable, Codable {
    let id: UUID
    let service: String
    let subsystem: String
    let lookupBefore: Int32
    let lookupAfter: Int32
    let disposition: XPCProbeDisposition?
    let elapsedMilliseconds: Double?

    init(
        service: String,
        subsystem: String,
        lookupBefore: Int32,
        lookupAfter: Int32,
        disposition: XPCProbeDisposition?,
        elapsedMilliseconds: Double?
    ) {
        self.id = UUID()
        self.service = service
        self.subsystem = subsystem
        self.lookupBefore = lookupBefore
        self.lookupAfter = lookupAfter
        self.disposition = disposition
        self.elapsedMilliseconds = elapsedMilliseconds
    }

    var wasProbed: Bool { disposition != nil }
    var reachabilityChanged: Bool { lookupBefore != lookupAfter }
    var unexpectedReply: Bool {
        disposition == .dictionaryReply || disposition == .otherReply
    }
    var anomalous: Bool { reachabilityChanged || unexpectedReply }
}

struct AttackSurfaceReport: Codable {
    let startedAt: Date
    let finishedAt: Date
    let timeoutMilliseconds: UInt32
    let serviceResults: [AttackSurfaceServiceResult]
    let validation: SandboxValidationReport

    var probedCount: Int { serviceResults.filter(\.wasProbed).count }
    var anomalyCount: Int { serviceResults.filter(\.anomalous).count }
    var protectedAccessConfirmed: Bool { validation.accessConfirmed }
}
