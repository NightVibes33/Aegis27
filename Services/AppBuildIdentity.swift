import Foundation

struct AppBuildIdentity {
    let version: String
    let build: String
    let sourceRevision: String
    let bundleIdentifier: String

    static var current: AppBuildIdentity {
        let info = Bundle.main.infoDictionary ?? [:]
        return AppBuildIdentity(
            version: info["CFBundleShortVersionString"] as? String ?? "unknown",
            build: info["CFBundleVersion"] as? String ?? "unknown",
            sourceRevision: info["AegisSourceRevision"] as? String ?? "unknown",
            bundleIdentifier: Bundle.main.bundleIdentifier ?? "unknown"
        )
    }
}
