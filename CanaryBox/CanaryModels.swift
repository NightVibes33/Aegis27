import Foundation

struct CanaryManifest: Codable {
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

struct VerificationResult: Identifiable {
    let id = UUID()
    let label: String
    let value: String
    let changed: Bool
}
