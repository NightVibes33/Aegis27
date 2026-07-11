import Foundation

enum FileCapabilityProbe {
    static let researchTargets = [
        "/var/mobile/Library/Preferences",
        "/var/mobile/Library/Caches",
        "/var/containers/Shared/SystemGroup",
        "/private/var/db"
    ]

    static func inspect(path: String) -> CapabilityProbeResult {
        let manager = FileManager.default
        let readable = manager.isReadableFile(atPath: path)
        let writable = manager.isWritableFile(atPath: path)

        do {
            let entries = try manager.contentsOfDirectory(atPath: path)
            return CapabilityProbeResult(
                path: path,
                readable: readable,
                writableAccordingToMetadata: writable,
                visibleEntryCount: entries.count,
                errorDescription: nil
            )
        } catch {
            return CapabilityProbeResult(
                path: path,
                readable: readable,
                writableAccordingToMetadata: writable,
                visibleEntryCount: nil,
                errorDescription: String(describing: error)
            )
        }
    }

    /// Creates a uniquely named canary and immediately removes it. Existing
    /// files are never opened, overwritten, truncated, renamed, or deleted.
    static func writeCanary(to targetDirectory: String) -> CanaryWriteResult {
        let markerName = ".aegis27-canary-\(UUID().uuidString)"
        let markerURL = URL(fileURLWithPath: targetDirectory, isDirectory: true)
            .appendingPathComponent(markerName, isDirectory: false)
        let payload = Data("Aegis27 authorized capability canary\n".utf8)

        do {
            try payload.write(to: markerURL, options: .withoutOverwriting)
            do {
                try FileManager.default.removeItem(at: markerURL)
                return CanaryWriteResult(
                    targetDirectory: targetDirectory,
                    created: true,
                    removed: true,
                    errorDescription: nil
                )
            } catch {
                return CanaryWriteResult(
                    targetDirectory: targetDirectory,
                    created: true,
                    removed: false,
                    errorDescription: "Canary created but cleanup failed: \(error)"
                )
            }
        } catch {
            return CanaryWriteResult(
                targetDirectory: targetDirectory,
                created: false,
                removed: false,
                errorDescription: String(describing: error)
            )
        }
    }
}

