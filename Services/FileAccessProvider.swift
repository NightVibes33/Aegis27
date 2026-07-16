import Foundation

protocol FileAccessProvider {
    var kind: FileProviderKind { get }
    var availabilitySummary: String { get }
    var isAvailable: Bool { get }

    func metadata(at path: String) -> FileMetadataResult
    func listDirectory(at path: String) -> DirectoryListingResult
    func readPreview(at path: String, limit: Int) -> FilePreviewResult
    func createAndRemoveCanary(in directory: String) -> CanaryWriteResult
}

enum FileAccessProviderRegistry {
    static func provider(for kind: FileProviderKind) -> any FileAccessProvider {
        switch kind {
        case .stock: return StockFileAccessProvider()
        case .escaped: return UnavailableEscapedFileAccessProvider()
        }
    }
}

struct StockFileAccessProvider: FileAccessProvider {
    let kind = FileProviderKind.stock
    let availabilitySummary = "Available through ordinary sandboxed filesystem APIs"
    let isAvailable = true

    func metadata(at path: String) -> FileMetadataResult {
        let normalized = normalizedPath(path)
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: normalized)
            return FileMetadataResult(
                path: normalized,
                entry: makeEntry(path: normalized, attributes: attributes),
                errorDescription: nil
            )
        } catch {
            return FileMetadataResult(
                path: normalized,
                entry: nil,
                errorDescription: String(describing: error)
            )
        }
    }

    func listDirectory(at path: String) -> DirectoryListingResult {
        let normalized = normalizedPath(path)
        do {
            let names = try FileManager.default.contentsOfDirectory(atPath: normalized)
            let entries = names.compactMap { name -> FileEntry? in
                let child = URL(fileURLWithPath: normalized, isDirectory: true)
                    .appendingPathComponent(name).path
                guard let attributes = try? FileManager.default.attributesOfItem(
                    atPath: child
                ) else { return nil }
                return makeEntry(path: child, attributes: attributes)
            }.sorted {
                if $0.isDirectory != $1.isDirectory { return $0.isDirectory }
                return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            }
            return DirectoryListingResult(
                path: normalized,
                entries: entries,
                errorDescription: nil
            )
        } catch {
            return DirectoryListingResult(
                path: normalized,
                entries: [],
                errorDescription: String(describing: error)
            )
        }
    }

    func readPreview(at path: String, limit: Int) -> FilePreviewResult {
        let normalized = normalizedPath(path)
        let boundedLimit = min(max(limit, 1), 256 * 1_024)
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: normalized)
            let expectedSize = (attributes[.size] as? NSNumber)?.intValue ?? 0
            let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: normalized))
            defer { try? handle.close() }
            let data = try handle.read(upToCount: boundedLimit) ?? Data()
            let text = String(data: data, encoding: .utf8)
            return FilePreviewResult(
                path: normalized,
                bytesRead: data.count,
                truncated: expectedSize > data.count,
                text: text,
                hex: hexPreview(data),
                errorDescription: nil
            )
        } catch {
            return FilePreviewResult(
                path: normalized,
                bytesRead: 0,
                truncated: false,
                text: nil,
                hex: "",
                errorDescription: String(describing: error)
            )
        }
    }

    func createAndRemoveCanary(in directory: String) -> CanaryWriteResult {
        FileCapabilityProbe.writeCanary(to: normalizedPath(directory))
    }

    private func normalizedPath(_ path: String) -> String {
        NSString(string: path).standardizingPath
    }

    private func makeEntry(
        path: String,
        attributes: [FileAttributeKey: Any]
    ) -> FileEntry {
        let type = attributes[.type] as? FileAttributeType
        return FileEntry(
            name: URL(fileURLWithPath: path).lastPathComponent.isEmpty
                ? path
                : URL(fileURLWithPath: path).lastPathComponent,
            path: path,
            isDirectory: type == .typeDirectory,
            isSymbolicLink: type == .typeSymbolicLink,
            byteCount: (attributes[.size] as? NSNumber)?.int64Value,
            modificationDate: attributes[.modificationDate] as? Date,
            readable: FileManager.default.isReadableFile(atPath: path),
            writable: FileManager.default.isWritableFile(atPath: path)
        )
    }

    private func hexPreview(_ data: Data) -> String {
        data.prefix(512).enumerated().map { index, byte in
            let separator = index > 0 && index.isMultiple(of: 16) ? "\n" : " "
            return "\(separator)\(String(format: "%02x", byte))"
        }.joined().trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

struct UnavailableEscapedFileAccessProvider: FileAccessProvider {
    let kind = FileProviderKind.escaped
    let availabilitySummary = "No independently validated sandbox-escape primitive is integrated"
    let isAvailable = false

    func metadata(at path: String) -> FileMetadataResult {
        FileMetadataResult(path: path, entry: nil, errorDescription: availabilitySummary)
    }

    func listDirectory(at path: String) -> DirectoryListingResult {
        DirectoryListingResult(path: path, entries: [], errorDescription: availabilitySummary)
    }

    func readPreview(at path: String, limit: Int) -> FilePreviewResult {
        FilePreviewResult(
            path: path,
            bytesRead: 0,
            truncated: false,
            text: nil,
            hex: "",
            errorDescription: availabilitySummary
        )
    }

    func createAndRemoveCanary(in directory: String) -> CanaryWriteResult {
        CanaryWriteResult(
            targetDirectory: directory,
            created: false,
            removed: false,
            errorDescription: availabilitySummary
        )
    }
}
