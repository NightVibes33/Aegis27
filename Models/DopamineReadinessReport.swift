import Foundation

struct DopamineReadinessCheck: Identifiable, Codable, Hashable {
    enum Status: String, Codable {
        case ready
        case blocked
        case info
    }

    let id: UUID
    let title: String
    let status: Status
    let detail: String

    init(id: UUID = UUID(), title: String, status: Status, detail: String) {
        self.id = id
        self.title = title
        self.status = status
        self.detail = detail
    }
}

struct DopamineReadinessReport: Codable, Hashable {
    let generatedAt: Date
    let dopamineVersion: String
    let deviceIdentifier: String
    let cpuFamilyName: String
    let cpuFamilyValue: UInt32
    let systemVersion: String
    let buildVersion: String
    let expectsSPTM: Bool
    let checks: [DopamineReadinessCheck]

    var blockerCount: Int {
        checks.filter { $0.status == .blocked }.count
    }

    var summary: String {
        if blockerCount == 0 {
            return "No known Dopamine 3.0.1 prerequisite is blocked by this probe."
        }
        return "\(blockerCount) prerequisite\(blockerCount == 1 ? "" : "s") currently block the stock Dopamine 3.0.1 real-device path."
    }

    func jsonString() -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(self),
              let string = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return string
    }
}
