import Foundation

enum BoundaryProbeOutcome: String, Codable {
    case accepted
    case rejected
    case timedOut
    case unavailable
    case failed
}

struct ParserBoundaryResult: Identifiable, Codable {
    let id: UUID
    let corpusID: String
    let label: String
    let boundary: String
    let byteCount: Int
    let outcome: BoundaryProbeOutcome
    let elapsedMilliseconds: Double
    let detail: String

    init(
        corpusID: String,
        label: String,
        boundary: String,
        byteCount: Int,
        outcome: BoundaryProbeOutcome,
        elapsedMilliseconds: Double,
        detail: String
    ) {
        self.id = UUID()
        self.corpusID = corpusID
        self.label = label
        self.boundary = boundary
        self.byteCount = byteCount
        self.outcome = outcome
        self.elapsedMilliseconds = elapsedMilliseconds
        self.detail = detail
    }
}

struct IOKitProbeResult: Identifiable, Codable {
    let id: UUID
    let className: String
    let apiResult: Int32
    let matched: Bool
    let openResult: Int32

    init(
        className: String,
        apiResult: Int32,
        matched: Bool,
        openResult: Int32
    ) {
        self.id = UUID()
        self.className = className
        self.apiResult = apiResult
        self.matched = matched
        self.openResult = openResult
    }

    var opened: Bool { apiResult == 0 && matched && openResult == 0 }
}
