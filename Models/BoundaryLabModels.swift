import Foundation

struct BoundaryCanaryManifest: Codable {
    struct FileCanary: Codable {
        let path: String
        let sha256: String
    }

    struct DatabaseCanary: Codable {
        let path: String
        let sha256: String
    }

    struct PreferencesCanary: Codable {
        let domain: String
        let secretKey: String
        let probeKey: String
        let sha256: String
    }

    struct KeychainCanary: Codable {
        let service: String
        let account: String
        let sha256: String
    }

    let formatVersion: Int
    let bundleIdentifier: String
    let generatedAt: Date
    let file: FileCanary
    let database: DatabaseCanary
    let preferences: PreferencesCanary
    let keychain: KeychainCanary
}

enum BoundaryCheckStatus: String, Codable {
    case matched
    case accessible
    case denied
    case changed
    case unchanged
    case failed
}

struct BoundaryCheckResult: Codable, Identifiable {
    let id: UUID
    let check: String
    let status: BoundaryCheckStatus
    let detail: String
    let osStatus: Int32?

    init(
        check: String,
        status: BoundaryCheckStatus,
        detail: String,
        osStatus: Int32? = nil
    ) {
        self.id = UUID()
        self.check = check
        self.status = status
        self.detail = detail
        self.osStatus = osStatus
    }
}

struct BoundaryLabReport: Codable {
    let formatVersion: Int
    let startedAt: Date
    let finishedAt: Date
    let sourceBundleIdentifier: String
    let sourceGeneratedAt: Date
    let checks: [BoundaryCheckResult]
}

enum BoundaryManifestError: LocalizedError {
    case invalidFormat
    case invalidBundleIdentifier
    case invalidFilePath
    case invalidDatabasePath
    case invalidPreferenceNamespace
    case invalidKeychainNamespace
    case invalidDigest

    var errorDescription: String? {
        switch self {
        case .invalidFormat:
            return "The manifest format is not supported."
        case .invalidBundleIdentifier:
            return "The manifest is not from CanaryBox."
        case .invalidFilePath:
            return "The private-file path is outside CanaryBox's synthetic BoundaryCanary directory."
        case .invalidDatabasePath:
            return "The database path is outside CanaryBox's synthetic BoundaryCanary directory."
        case .invalidPreferenceNamespace:
            return "The preferences namespace is not a CanaryBox boundary-test namespace."
        case .invalidKeychainNamespace:
            return "The Keychain namespace is not a CanaryBox boundary-test namespace."
        case .invalidDigest:
            return "The manifest contains an invalid SHA-256 digest."
        }
    }
}

enum BoundaryManifestValidator {
    static let bundleIdentifier = "com.nightvibes33.CanaryBox"
    static let boundaryDirectoryMarker = "/Documents/BoundaryCanary/"
    static let keychainPrefix = "com.nightvibes33.CanaryBox.boundary."
    static let preferenceSecretPrefix = "boundary.secret."
    static let preferenceProbePrefix = "boundary.probe."

    static func validate(_ manifest: BoundaryCanaryManifest) throws {
        guard manifest.formatVersion == 1 else {
            throw BoundaryManifestError.invalidFormat
        }
        guard manifest.bundleIdentifier == bundleIdentifier else {
            throw BoundaryManifestError.invalidBundleIdentifier
        }
        guard isAllowedPath(
            manifest.file.path,
            requiredFileName: "private-canary.bin"
        ) else {
            throw BoundaryManifestError.invalidFilePath
        }
        guard isAllowedPath(
            manifest.database.path,
            requiredFileName: "canary.sqlite3"
        ) else {
            throw BoundaryManifestError.invalidDatabasePath
        }
        guard manifest.preferences.domain == bundleIdentifier,
              manifest.preferences.secretKey.hasPrefix(preferenceSecretPrefix),
              manifest.preferences.probeKey.hasPrefix(preferenceProbePrefix),
              manifest.preferences.secretKey.count <= 128,
              manifest.preferences.probeKey.count <= 128 else {
            throw BoundaryManifestError.invalidPreferenceNamespace
        }
        guard manifest.keychain.service.hasPrefix(keychainPrefix),
              manifest.keychain.service.count <= 160,
              manifest.keychain.account == "secret" else {
            throw BoundaryManifestError.invalidKeychainNamespace
        }
        guard [
            manifest.file.sha256,
            manifest.database.sha256,
            manifest.preferences.sha256,
            manifest.keychain.sha256
        ].allSatisfy(isDigest) else {
            throw BoundaryManifestError.invalidDigest
        }
    }

    private static func isAllowedPath(
        _ path: String,
        requiredFileName: String
    ) -> Bool {
        guard path.hasPrefix("/"),
              !path.contains("\0"),
              !path.contains("/../"),
              path.contains(boundaryDirectoryMarker) else {
            return false
        }
        let url = URL(fileURLWithPath: path).standardizedFileURL
        guard url.lastPathComponent == requiredFileName,
              url.deletingLastPathComponent().lastPathComponent == "BoundaryCanary" else {
            return false
        }
        return url.path == path
    }

    private static func isDigest(_ value: String) -> Bool {
        value.count == 64 && value.unicodeScalars.allSatisfy {
            (48...57).contains($0.value) || (97...102).contains($0.value)
        }
    }
}
