import Foundation

enum AttackSurfaceHistoryStore {
    private static var url: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ResearchLogs", isDirectory: true)
            .appendingPathComponent("attack-surface-previous.json")
    }

    static func load() -> AttackSurfaceReport? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(AttackSurfaceReport.self, from: data)
    }

    static func save(_ report: AttackSurfaceReport) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(report) else { return }
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try? data.write(to: url, options: .atomic)
    }

    static func matchedFingerprintKeys(
        previous: AttackSurfaceReport?,
        current: [AttackSurfaceServiceResult]
    ) -> [String] {
        guard let previous else { return [] }
        let prior = Set(previous.serviceResults.filter(\.wasProbed).map {
            "\($0.service)|\($0.requestID)|\($0.fingerprint)"
        })
        return Array(Set(current.filter(\.wasProbed).map {
            "\($0.service)|\($0.requestID)|\($0.fingerprint)"
        }).intersection(prior)).sorted()
    }
}
