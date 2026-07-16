import Foundation

@MainActor
final class SandboxValidationViewModel: ObservableObject {
    @Published var selectedProvider = FileProviderKind.stock
    @Published private(set) var report: SandboxValidationReport?
    @Published private(set) var exportURL: URL?
    @Published private(set) var isRunning = false

    var provider: any FileAccessProvider {
        FileAccessProviderRegistry.provider(for: selectedProvider)
    }

    func run() {
        isRunning = true
        report = SandboxValidationService.run(provider: provider)
        exportURL = report.flatMap(save)
        isRunning = false
    }

    func switchProvider(to kind: FileProviderKind) {
        selectedProvider = kind
        report = nil
        exportURL = nil
    }

    private func save(_ report: SandboxValidationReport) -> URL? {
        let directory = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        )[0].appendingPathComponent("ResearchLogs", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("sandbox-validation-latest.json")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        do {
            let data = try encoder.encode(report)
            try data.write(to: url, options: .atomic)
            return url
        } catch {
            return nil
        }
    }
}
