import CryptoKit
import Foundation

enum DiagnosticImporter {
    private static let signals = [
        "MobileGestalt", "Sandbox", "EXC_BAD_ACCESS", "Exception Type",
        "panic", "Jetsam", "Termination Reason", "SIGABRT"
    ]
    private static let previewLimit = 4 * 1_024 * 1_024

    static func inspect(url: URL) throws -> ImportedDiagnostic {
        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped { url.stopAccessingSecurityScopedResource() }
        }

        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let byteCount = (attributes[.size] as? NSNumber)?.int64Value ?? 0
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        var hasher = SHA256()
        var preview = Data()
        while true {
            let chunk = try handle.read(upToCount: 256 * 1_024) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
            if preview.count < previewLimit {
                preview.append(chunk.prefix(previewLimit - preview.count))
            }
        }

        let text = String(decoding: preview, as: UTF8.self)
        var counts: [String: Int] = [:]
        for signal in signals {
            counts[signal] = text.components(separatedBy: signal).count - 1
        }

        return ImportedDiagnostic(
            id: UUID(),
            importedAt: Date(),
            fileName: url.lastPathComponent,
            byteCount: byteCount,
            sha256: hasher.finalize().map { String(format: "%02x", $0) }.joined(),
            signalCounts: counts.filter { $0.value > 0 }
        )
    }
}
