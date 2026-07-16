import Foundation

enum XPCProbeFieldType: String, Codable, CaseIterable {
    case string
    case unsignedInteger
    case boolean
}

struct XPCProbeField: Codable, Hashable {
    let key: String
    let type: XPCProbeFieldType
    let stringValue: String?
    let unsignedIntegerValue: UInt64?
    let booleanValue: Bool?
}

struct XPCRequestSchema: Identifiable, Codable, Hashable {
    let id: String
    let label: String
    let source: String
    let fields: [XPCProbeField]

    static let empty = XPCRequestSchema(
        id: "empty-dictionary",
        label: "Empty dictionary baseline",
        source: "Built in",
        fields: []
    )
}

struct FirmwareServiceSchema: Identifiable, Codable {
    var id: String { service }
    let service: String
    let subsystem: String
    let binaryPath: String?
    let requests: [XPCRequestSchema]
}

struct FirmwareParserSurface: Identifiable, Codable {
    let id: String
    let label: String
    let uniformType: String
    let boundary: String
    let source: String
}

struct FirmwareProbeCatalog: Codable {
    let formatVersion: Int
    let sourceBuild: String
    let generatedAt: Date
    let services: [FirmwareServiceSchema]
    let parserSurfaces: [FirmwareParserSurface]
    let ioKitClasses: [String]

    static let empty = FirmwareProbeCatalog(
        formatVersion: 1,
        sourceBuild: "none",
        generatedAt: .distantPast,
        services: [],
        parserSurfaces: [],
        ioKitClasses: []
    )
}

struct FirmwareCatalogImportResult {
    let catalog: FirmwareProbeCatalog
    let fileName: String
    let warnings: [String]
}
