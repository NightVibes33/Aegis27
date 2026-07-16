import Foundation

struct DeepScanConfiguration: Codable {
    /// Zero means continue until every reachable queue is exhausted.
    var maximumNodes = 0
    /// Zero means descend until the reachable tree is exhausted.
    var maximumDepth = 0
    var includeReadProbe = true
    var includeWriteProbe = false
    /// Zero means probe every discovered directory.
    var maximumWriteProbes = 0
}

struct DeepScanObservation: Identifiable, Codable {
    var id: String { path }
    let path: String
    let depth: Int
    let isDirectory: Bool?
    let metadataOutcome: FileAccessOutcome
    let listingOutcome: FileAccessOutcome
    let readOutcome: FileAccessOutcome
    let writeOutcome: FileAccessOutcome
    let childCount: Int
    let detail: String?

    var readable: Bool {
        listingOutcome == .success || readOutcome == .success
    }

    var writable: Bool { writeOutcome == .success }
}

struct DeepScanReport: Codable {
    let provider: FileProviderKind
    let startedAt: Date
    let finishedAt: Date
    let configuration: DeepScanConfiguration
    let observations: [DeepScanObservation]
    let serviceResults: [MachServiceConnectionResult]
    let cancelled: Bool
    let nodeLimitReached: Bool

    var metadataVisibleCount: Int {
        observations.filter { $0.metadataOutcome == .success }.count
    }

    /// Files whose contents were actually opened and read by the probe.
    var readableFileCount: Int {
        observations.filter { $0.readOutcome == .success }.count
    }

    /// Directories whose children were actually enumerated.
    var listableDirectoryCount: Int {
        observations.filter { $0.listingOutcome == .success }.count
    }

    var accessibleCount: Int { observations.filter(\.readable).count }
    var writableCount: Int { observations.filter(\.writable).count }
    var deniedCount: Int {
        observations.filter {
            $0.metadataOutcome == .permissionDenied ||
                $0.listingOutcome == .permissionDenied ||
                $0.readOutcome == .permissionDenied ||
                $0.writeOutcome == .permissionDenied
        }.count
    }
    var reachableServiceCount: Int { serviceResults.filter(\.resolved).count }
}
