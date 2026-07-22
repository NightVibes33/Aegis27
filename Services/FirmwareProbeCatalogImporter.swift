import Foundation

enum FirmwareProbeCatalogError: LocalizedError {
    case unsupportedVersion(Int)
    case oversized
    case invalid(String)

    var errorDescription: String? {
        switch self {
        case .unsupportedVersion(let version):
            return "Unsupported catalog format version \(version)."
        case .oversized:
            return "Catalog exceeds the 4 MiB import limit."
        case .invalid(let detail):
            return "Invalid probe catalog: \(detail)"
        }
    }
}

enum FirmwareProbeCatalogImporter {
    private static let byteLimit = 4 * 1_024 * 1_024
    private static let maximumServices = 64
    private static let maximumRequestsPerService = 8
    private static let maximumFieldsPerRequest = 8

    static func load(
        from url: URL,
        targetBuild: String
    ) throws -> FirmwareCatalogImportResult {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        return try decode(
            data: data,
            fileName: url.lastPathComponent,
            targetBuild: targetBuild
        )
    }

    static func loadBundled(
        targetBuild: String
    ) -> FirmwareCatalogImportResult? {
        let candidates = [
            Bundle.main.url(
                forResource: targetBuild,
                withExtension: "json",
                subdirectory: "FirmwareCatalogs"
            ),
            Bundle.main.url(
                forResource: targetBuild,
                withExtension: "json"
            )
        ]

        guard let url = candidates.compactMap({ $0 }).first else { return nil }
        return try? load(from: url, targetBuild: targetBuild)
    }

    private static func decode(
        data: Data,
        fileName: String,
        targetBuild: String
    ) throws -> FirmwareCatalogImportResult {
        guard data.count <= byteLimit else { throw FirmwareProbeCatalogError.oversized }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(FirmwareProbeCatalog.self, from: data)
        guard decoded.formatVersion == 1 else {
            throw FirmwareProbeCatalogError.unsupportedVersion(decoded.formatVersion)
        }

        let sanitized = try sanitize(decoded)
        var warnings: [String] = []
        if sanitized.sourceBuild != targetBuild {
            warnings.append(
                "Catalog build \(sanitized.sourceBuild) does not match target \(targetBuild)."
            )
        }
        return FirmwareCatalogImportResult(
            catalog: sanitized,
            fileName: fileName,
            warnings: warnings
        )
    }

    private static func sanitize(
        _ catalog: FirmwareProbeCatalog
    ) throws -> FirmwareProbeCatalog {
        guard catalog.services.count <= maximumServices else {
            throw FirmwareProbeCatalogError.invalid("too many services")
        }

        var seenServices = Set<String>()
        let services = try catalog.services.map { service -> FirmwareServiceSchema in
            try validateToken(service.service, label: "service", maximum: 160)
            guard seenServices.insert(service.service).inserted else {
                throw FirmwareProbeCatalogError.invalid("duplicate service \(service.service)")
            }
            guard service.requests.count <= maximumRequestsPerService else {
                throw FirmwareProbeCatalogError.invalid("too many requests for \(service.service)")
            }

            let requests = try service.requests.map { request -> XPCRequestSchema in
                try validateToken(request.id, label: "request id", maximum: 80)
                guard request.fields.count <= maximumFieldsPerRequest else {
                    throw FirmwareProbeCatalogError.invalid("too many fields in \(request.id)")
                }
                let fields = try request.fields.map { field -> XPCProbeField in
                    try validateToken(field.key, label: "field key", maximum: 96)
                    if let value = field.stringValue {
                        guard value.utf8.count <= 256 && !value.contains("\0") else {
                            throw FirmwareProbeCatalogError.invalid("unsafe string value length")
                        }
                    }
                    return field
                }
                return XPCRequestSchema(
                    id: request.id,
                    label: String(request.label.prefix(120)),
                    source: String(request.source.prefix(240)),
                    fields: fields
                )
            }
            return FirmwareServiceSchema(
                service: service.service,
                subsystem: String(service.subsystem.prefix(80)),
                binaryPath: service.binaryPath.map { String($0.prefix(512)) },
                requests: requests
            )
        }

        let ioKitClasses = try Array(catalog.ioKitClasses.prefix(64)).map { value in
            try validateToken(value, label: "IOKit class", maximum: 128)
            return value
        }
        return FirmwareProbeCatalog(
            formatVersion: 1,
            sourceBuild: String(catalog.sourceBuild.prefix(64)),
            generatedAt: catalog.generatedAt,
            services: services,
            parserSurfaces: Array(catalog.parserSurfaces.prefix(32)),
            ioKitClasses: ioKitClasses
        )
    }

    private static func validateToken(
        _ value: String,
        label: String,
        maximum: Int
    ) throws {
        let allowed = CharacterSet(
            charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        )
        guard !value.isEmpty, value.utf8.count <= maximum,
              value.unicodeScalars.allSatisfy(allowed.contains) else {
            throw FirmwareProbeCatalogError.invalid("bad \(label)")
        }
    }
}
