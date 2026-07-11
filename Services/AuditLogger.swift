import Foundation

@MainActor
final class AuditLogger: ObservableObject {
    @Published private(set) var events: [ResearchEvent] = []

    let logURL: URL
    private let encoder: JSONEncoder

    init() {
        let documentDirectory = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first!
        let logDirectory = documentDirectory.appendingPathComponent(
            "ResearchLogs",
            isDirectory: true
        )
        try? FileManager.default.createDirectory(
            at: logDirectory,
            withIntermediateDirectories: true
        )
        self.logURL = logDirectory.appendingPathComponent("aegis27.jsonl")
        self.encoder = JSONEncoder()
        self.encoder.dateEncodingStrategy = .iso8601
    }

    func record(_ event: ResearchEvent) {
        events.insert(event, at: 0)

        guard let encoded = try? encoder.encode(event) else { return }
        var line = encoded
        line.append(0x0A)

        if !FileManager.default.fileExists(atPath: logURL.path) {
            FileManager.default.createFile(atPath: logURL.path, contents: line)
            return
        }

        guard let handle = try? FileHandle(forWritingTo: logURL) else { return }
        do {
            try handle.seekToEnd()
            try handle.write(contentsOf: line)
            try handle.close()
        } catch {
            try? handle.close()
        }
    }
}

