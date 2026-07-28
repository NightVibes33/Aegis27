import Foundation

enum PatchDiffRequestService {
    private static let buildExpression = try! NSRegularExpression(
        pattern: "^[A-Za-z0-9]{3,24}$"
    )
    private static let deviceExpression = try! NSRegularExpression(
        pattern: "^[A-Za-z0-9]+,[0-9]+$"
    )

    static func makeRequest(
        device: String,
        baseBuild: String,
        targetBuild: String,
        surfaces: Set<PatchDiffSurface>,
        maximumCandidates: Int
    ) throws -> PatchDiffRequest {
        let cleanDevice = device.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanBase = baseBuild.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanTarget = targetBuild.trimmingCharacters(in: .whitespacesAndNewlines)

        guard matches(deviceExpression, cleanDevice) else {
            throw PatchDiffRequestError.invalidDevice
        }
        guard matches(buildExpression, cleanBase) else {
            throw PatchDiffRequestError.invalidBuild("base")
        }
        guard matches(buildExpression, cleanTarget) else {
            throw PatchDiffRequestError.invalidBuild("target")
        }
        guard cleanBase != cleanTarget else {
            throw PatchDiffRequestError.identicalBuilds
        }
        guard !surfaces.isEmpty else {
            throw PatchDiffRequestError.noSurfaces
        }

        let ordered = PatchDiffSurface.allCases.filter(surfaces.contains)
        return PatchDiffRequest(
            device: cleanDevice,
            baseBuild: cleanBase,
            targetBuild: cleanTarget,
            surfaces: ordered,
            maximumCandidates: min(200, max(10, maximumCandidates))
        )
    }

    static func save(_ request: PatchDiffRequest) throws -> URL {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(request)
        guard data.count <= 64 * 1024 else {
            throw CocoaError(.fileWriteOutOfSpace)
        }

        let directory = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        )[0].appendingPathComponent("ResearchLogs", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let url = directory.appendingPathComponent("ipsw-patch-diff-request.json")
        try data.write(to: url, options: [.atomic])
        return url
    }

    static func loadReport(from url: URL) throws -> PatchDiffReport {
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        guard data.count <= 4 * 1024 * 1024 else {
            throw PatchDiffRequestError.invalidReport
        }
        let report = try JSONDecoder().decode(PatchDiffReport.self, from: data)
        guard report.formatVersion == 1, report.kind == "ipsw-patch-diff" else {
            throw PatchDiffRequestError.invalidReport
        }
        return report
    }

    private static func matches(_ expression: NSRegularExpression, _ value: String) -> Bool {
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return expression.firstMatch(in: value, range: range)?.range == range
    }
}
