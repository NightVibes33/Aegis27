import Foundation

enum DeepScanService {
    private struct PendingPath {
        let path: String
        let depth: Int
    }

    static let seedPaths = [
        "/",
        "/Applications",
        "/System",
        "/System/Library",
        "/Library",
        "/usr",
        "/bin",
        "/sbin",
        "/private",
        "/private/var",
        "/private/var/db",
        "/var",
        "/var/mobile",
        "/var/mobile/Library",
        "/var/mobile/Library/Preferences",
        "/var/mobile/Library/Caches",
        "/var/mobile/Documents",
        "/var/mobile/Media",
        "/var/mobile/Containers",
        "/var/mobile/Containers/Data/Application",
        "/var/containers",
        "/var/containers/Bundle/Application",
        "/var/containers/Shared/SystemGroup",
        NSHomeDirectory()
    ]

    static func run(
        providerKind: FileProviderKind,
        configuration: DeepScanConfiguration
    ) async -> DeepScanReport {
        let startedAt = Date()
        let provider = FileAccessProviderRegistry.provider(for: providerKind)
        var queue = seedPaths.map { PendingPath(path: $0, depth: 0) }
        var cursor = 0
        var visited = Set<String>()
        var observations: [DeepScanObservation] = []
        var writeProbeCount = 0

        while cursor < queue.count && observations.count < configuration.maximumNodes {
            if Task.isCancelled { break }
            let pending = queue[cursor]
            cursor += 1
            let path = NSString(string: pending.path).standardizingPath
            guard visited.insert(path).inserted else { continue }

            let metadata = provider.metadata(at: path)
            guard let entry = metadata.entry else {
                observations.append(DeepScanObservation(
                    path: path,
                    depth: pending.depth,
                    isDirectory: nil,
                    metadataOutcome: metadata.outcome,
                    listingOutcome: .notTested,
                    readOutcome: .notTested,
                    writeOutcome: .notTested,
                    childCount: 0,
                    detail: metadata.errorDescription
                ))
                await Task.yield()
                continue
            }

            if entry.isSymbolicLink {
                observations.append(DeepScanObservation(
                    path: path,
                    depth: pending.depth,
                    isDirectory: entry.isDirectory,
                    metadataOutcome: metadata.outcome,
                    listingOutcome: .notTested,
                    readOutcome: .notTested,
                    writeOutcome: .notTested,
                    childCount: 0,
                    detail: "Symbolic link not followed."
                ))
                continue
            }

            if entry.isDirectory {
                let listing = provider.listDirectory(at: path)
                var writeOutcome = FileAccessOutcome.notTested
                var detail = listing.errorDescription

                if configuration.includeWriteProbe &&
                    writeProbeCount < configuration.maximumWriteProbes {
                    writeProbeCount += 1
                    let canary = provider.createAndRemoveCanary(in: path)
                    if canary.created && canary.removed {
                        writeOutcome = .success
                    } else if canary.created {
                        writeOutcome = .failed
                        detail = "Canary was created but could not be removed: \(canary.errorDescription ?? "unknown error")"
                    } else {
                        writeOutcome = writeFailureOutcome(canary.errorDescription)
                    }
                }

                observations.append(DeepScanObservation(
                    path: path,
                    depth: pending.depth,
                    isDirectory: true,
                    metadataOutcome: metadata.outcome,
                    listingOutcome: listing.outcome,
                    readOutcome: .notTested,
                    writeOutcome: writeOutcome,
                    childCount: listing.entries.count,
                    detail: detail
                ))

                if listing.succeeded && pending.depth < configuration.maximumDepth {
                    for child in listing.entries where !child.isSymbolicLink {
                        guard queue.count < configuration.maximumNodes + seedPaths.count else {
                            break
                        }
                        queue.append(PendingPath(
                            path: child.path,
                            depth: pending.depth + 1
                        ))
                    }
                }
            } else {
                let read = configuration.includeReadProbe && entry.isRegularFile
                    ? provider.readPreview(at: path, limit: 1)
                    : FilePreviewResult(
                        path: path,
                        bytesRead: 0,
                        truncated: false,
                        text: nil,
                        hex: "",
                        outcome: .notTested,
                        errorDescription: entry.isRegularFile
                            ? nil
                            : "Special filesystem object; content probe skipped."
                    )
                observations.append(DeepScanObservation(
                    path: path,
                    depth: pending.depth,
                    isDirectory: false,
                    metadataOutcome: metadata.outcome,
                    listingOutcome: .notTested,
                    readOutcome: read.outcome,
                    writeOutcome: .notTested,
                    childCount: 0,
                    detail: read.errorDescription
                ))
            }

            await Task.yield()
        }

        let cancelledBeforeServices = Task.isCancelled
        let services: [MachServiceConnectionResult]
        if cancelledBeforeServices {
            services = []
        } else {
            services = await MachServiceConnectionProbe.run(
                services: ServiceResearchCatalog.serviceNames
            )
        }
        let cancelled = cancelledBeforeServices || Task.isCancelled

        return DeepScanReport(
            provider: providerKind,
            startedAt: startedAt,
            finishedAt: Date(),
            configuration: configuration,
            observations: observations,
            serviceResults: services,
            cancelled: cancelled,
            nodeLimitReached: observations.count >= configuration.maximumNodes && cursor < queue.count
        )
    }

    private static func writeFailureOutcome(_ error: String?) -> FileAccessOutcome {
        let value = error?.lowercased() ?? ""
        if value.contains("permission") ||
            value.contains("operation not permitted") {
            return .permissionDenied
        }
        if value.contains("no such file") { return .missing }
        return .failed
    }
}
