import Foundation

enum PatchDiffSurface: String, CaseIterable, Codable, Identifiable, Hashable {
    case firmware
    case launchd
    case entitlements
    case featureFlags
    case sandbox
    case functionStarts
    case cStrings
    case files

    var id: String { rawValue }

    var title: String {
        switch self {
        case .firmware: return "Firmware components"
        case .launchd: return "Launchd services"
        case .entitlements: return "Entitlements"
        case .featureFlags: return "Feature flags"
        case .sandbox: return "Sandbox profiles"
        case .functionStarts: return "Function starts"
        case .cStrings: return "C strings"
        case .files: return "Filesystem inventory"
        }
    }

    var detail: String {
        switch self {
        case .firmware: return "Boot, coprocessor, and packaged firmware metadata."
        case .launchd: return "Changed service definitions and executable mappings."
        case .entitlements: return "Added, removed, or changed code-signing entitlements."
        case .featureFlags: return "Changed feature and experiment configuration."
        case .sandbox: return "Compiled sandbox-policy differences."
        case .functionStarts: return "Changed Mach-O function boundaries for manual review."
        case .cStrings: return "Changed embedded strings that may reveal validation paths."
        case .files: return "Broad filesystem changes; slower and more storage-intensive."
        }
    }

    static let recommended: Set<PatchDiffSurface> = [
        .firmware,
        .launchd,
        .entitlements,
        .featureFlags,
        .sandbox,
        .functionStarts,
        .cStrings,
    ]
}

struct PatchDiffRequest: Codable {
    let formatVersion: Int
    let kind: String
    let requestID: UUID
    let device: String
    let baseBuild: String
    let targetBuild: String
    let surfaces: [PatchDiffSurface]
    let generatedAt: Date
    let sourceBundleIdentifier: String
    let maximumCandidates: Int

    init(
        device: String,
        baseBuild: String,
        targetBuild: String,
        surfaces: [PatchDiffSurface],
        maximumCandidates: Int
    ) {
        self.formatVersion = 1
        self.kind = "ipsw-patch-diff"
        self.requestID = UUID()
        self.device = device
        self.baseBuild = baseBuild
        self.targetBuild = targetBuild
        self.surfaces = surfaces
        self.generatedAt = Date()
        self.sourceBundleIdentifier = "com.nightvibes33.Aegis27.v08"
        self.maximumCandidates = maximumCandidates
    }
}

struct PatchDiffReport: Decodable {
    struct Request: Decodable {
        let requestID: String
        let device: String
        let baseBuild: String
        let targetBuild: String
        let surfaces: [String]
        let generatedAt: String
        let maximumCandidates: Int
    }

    struct Tool: Decodable {
        let summarizerVersion: String
        let ipswVersion: String
    }

    struct Summary: Decodable {
        let artifactFiles: Int
        let jsonFiles: Int
        let markdownFiles: Int
        let candidateCount: Int
        let categoryCounts: [String: Int]
    }

    struct Candidate: Decodable, Identifiable {
        let id: String
        let rank: Int
        let score: Int
        let category: String
        let subject: String
        let sources: [String]
        let changedFields: [String]
        let evidence: [String]
        let regressionFocus: String
        let classification: String
    }

    let formatVersion: Int
    let kind: String
    let generatedAt: String
    let request: Request
    let tool: Tool
    let summary: Summary
    let candidates: [Candidate]
    let limitations: [String]
    let rawArtifacts: [String]
}

enum PatchDiffRequestError: LocalizedError {
    case invalidDevice
    case invalidBuild(String)
    case identicalBuilds
    case noSurfaces
    case runnerNotConnected
    case runnerBusy
    case invalidReport

    var errorDescription: String? {
        switch self {
        case .invalidDevice:
            return "The hardware identifier is not valid."
        case .invalidBuild(let label):
            return "Enter a valid \(label) build identifier."
        case .identicalBuilds:
            return "The base and target builds must be different."
        case .noSurfaces:
            return "Select at least one static diff surface."
        case .runnerNotConnected:
            return "Connect the GitHub runner before submitting an IPSW diff."
        case .runnerBusy:
            return "The GitHub runner bridge is already processing another request."
        case .invalidReport:
            return "The downloaded runner result is not an IPSW patch-diff report."
        }
    }
}
