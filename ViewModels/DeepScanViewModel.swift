import Foundation

@MainActor
final class DeepScanViewModel: ObservableObject {
    @Published var selectedProvider = FileProviderKind.stock
    @Published var scanAllReachablePaths = true
    @Published var maximumNodes = 25_000
    @Published var maximumDepth = 8
    @Published var includeReadProbe = true
    @Published var includeWriteProbe = false
    @Published var resultFilter = DeepScanResultFilter.accessible
    @Published var searchText = ""
    @Published private(set) var report: DeepScanReport?
    @Published private(set) var exportURL: URL?
    @Published private(set) var isRunning = false

    private var scanTask: Task<Void, Never>?

    var filteredObservations: [DeepScanObservation] {
        guard let observations = report?.observations else { return [] }
        return observations.filter { observation in
            let matchesFilter: Bool
            switch resultFilter {
            case .accessible:
                matchesFilter = observation.readable || observation.writable
            case .writable:
                matchesFilter = observation.writable
            case .denied:
                matchesFilter = observation.metadataOutcome == .permissionDenied ||
                    observation.listingOutcome == .permissionDenied ||
                    observation.readOutcome == .permissionDenied ||
                    observation.writeOutcome == .permissionDenied
            case .all:
                matchesFilter = true
            }
            return matchesFilter && (searchText.isEmpty ||
                observation.path.localizedCaseInsensitiveContains(searchText))
        }
    }

    func start(onCompletion: @escaping (DeepScanReport) -> Void) {
        cancel()
        report = nil
        exportURL = nil
        isRunning = true
        let provider = selectedProvider
        let configuration = DeepScanConfiguration(
            maximumNodes: scanAllReachablePaths ? 0 : maximumNodes,
            maximumDepth: scanAllReachablePaths ? 0 : maximumDepth,
            includeReadProbe: includeReadProbe,
            includeWriteProbe: includeWriteProbe,
            maximumWriteProbes: scanAllReachablePaths ? 0 : 100
        )

        scanTask = Task {
            let result = await DeepScanService.run(
                providerKind: provider,
                configuration: configuration
            )
            report = result
            exportURL = save(result)
            isRunning = false
            onCompletion(result)
        }
    }

    func cancel() {
        scanTask?.cancel()
        scanTask = nil
        if isRunning { isRunning = false }
    }

    private func save(_ report: DeepScanReport) -> URL? {
        let documents = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first!
        let directory = documents.appendingPathComponent(
            "ResearchLogs",
            isDirectory: true
        )
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let url = directory.appendingPathComponent("deep-scan-latest.json")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(report) else { return nil }
        do {
            try data.write(to: url, options: .atomic)
            return url
        } catch {
            return nil
        }
    }
}

enum DeepScanResultFilter: String, CaseIterable, Identifiable {
    case accessible
    case writable
    case denied
    case all

    var id: String { rawValue }
    var title: String { rawValue.capitalized }
}
