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
    let timestamp: Date
    let repetition: Int
    let service: String
    let subsystem: String
    let requestID: String
    let requestLabel: String
    let lookupBefore: Int32
    let lookupAfter: Int32
    let disposition: XPCProbeDisposition?
    let elapsedMilliseconds: Double?
    let replyKeyCount: UInt32
    let replyKeyHash: String

    init(
        timestamp: Date = Date(),
        repetition: Int,
        service: String,
        subsystem: String,
        requestID: String,
        requestLabel: String,
        lookupBefore: Int32,
        lookupAfter: Int32,
        disposition: XPCProbeDisposition?,
        elapsedMilliseconds: Double?,
        replyKeyCount: UInt32,
        replyKeyHash: String
    ) {
        self.id = UUID()
        self.timestamp = timestamp
        self.repetition = repetition
        self.service = service
        self.subsystem = subsystem
        self.requestID = requestID
        self.requestLabel = requestLabel
        self.lookupBefore = lookupBefore
        self.lookupAfter = lookupAfter
        self.disposition = disposition
        self.elapsedMilliseconds = elapsedMilliseconds
        self.replyKeyCount = replyKeyCount
        self.replyKeyHash = replyKeyHash
    }

    var wasProbed: Bool { disposition != nil }
    var reachabilityChanged: Bool { lookupBefore != lookupAfter }
    var unexpectedReply: Bool {
        disposition == .dictionaryReply || disposition == .otherReply
    }
    var anomalous: Bool { reachabilityChanged || unexpectedReply }

    var fingerprint: String {
        "\(disposition?.rawValue ?? -1):\(replyKeyCount):\(replyKeyHash)"
    }
}

struct AttackSurfaceReport: Codable {
    let id: UUID
    let startedAt: Date
    let finishedAt: Date
    let bootSessionStartedAt: Date
    let timeoutMilliseconds: UInt32
    let repetitionCount: Int
    let catalogBuild: String?
    let serviceResults: [AttackSurfaceServiceResult]
    let parserResults: [ParserBoundaryResult]
    let catalogParserSurfaces: [FirmwareParserSurface]
    let ioKitResults: [IOKitProbeResult]
    let validation: SandboxValidationReport
    let previousRunMatchedFingerprints: Int
    let previousRunWasDifferentBoot: Bool

    var probedCount: Int { serviceResults.filter(\.wasProbed).count }
    var anomalyCount: Int { serviceResults.filter(\.anomalous).count }
    var protectedAccessConfirmed: Bool { validation.accessConfirmed }

    var stableProtocolLeadCount: Int {
        let grouped = Dictionary(grouping: serviceResults.filter(\.wasProbed)) {
            "\($0.service)|\($0.requestID)"
        }
        return grouped.values.filter { values in
            values.count == repetitionCount &&
                Set(values.map(\.fingerprint)).count == 1 &&
                values.first?.unexpectedReply == true
        }.count
    }

    var openedIOKitCount: Int { ioKitResults.filter(\.opened).count }
    var crossBootMatchedFingerprints: Int {
        previousRunWasDifferentBoot ? previousRunMatchedFingerprints : 0
    }
}
