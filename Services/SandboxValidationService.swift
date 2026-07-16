import Foundation

enum SandboxValidationService {
    static let springBoardPreferences =
        "/var/mobile/Library/Preferences/com.apple.springboard.plist"
    static let applicationContainers =
        "/var/mobile/Containers/Data/Application"

    static func run(
        provider: any FileAccessProvider
    ) -> SandboxValidationReport {
        let preferencesRead = provider.readPreview(
            at: springBoardPreferences,
            limit: 4_096
        )
        let containerListing = provider.listDirectory(at: applicationContainers)
        let ownContainer = ownApplicationContainerPath()
        let foreignContainers = containerListing.entries.filter { entry in
            entry.isDirectory && !isOwnContainer(entry.path, ownContainer: ownContainer)
        }

        let preferencesCheck = SandboxValidationCheck(
            label: "SpringBoard preferences",
            path: springBoardPreferences,
            operation: "bounded read",
            status: status(for: preferencesRead.outcome),
            detail: preferencesRead.succeeded
                ? "Read \(preferencesRead.bytesRead) bytes."
                : (preferencesRead.errorDescription ?? preferencesRead.outcome.title)
        )

        let containerStatus: SandboxValidationStatus
        let containerDetail: String
        if containerListing.succeeded {
            if foreignContainers.isEmpty {
                containerStatus = .inconclusive
                containerDetail = "Directory listed, but no foreign application containers were visible."
            } else {
                containerStatus = .passed
                containerDetail = "Listed \(containerListing.entries.count) entries, including \(foreignContainers.count) foreign application container(s)."
            }
        } else {
            containerStatus = status(for: containerListing.outcome)
            containerDetail = containerListing.errorDescription ?? containerListing.outcome.title
        }

        return SandboxValidationReport(
            provider: provider.kind,
            timestamp: Date(),
            checks: [
                preferencesCheck,
                SandboxValidationCheck(
                    label: "Other app containers",
                    path: applicationContainers,
                    operation: "directory list",
                    status: containerStatus,
                    detail: containerDetail
                )
            ],
            foreignContainerCount: foreignContainers.count
        )
    }

    private static func ownApplicationContainerPath() -> String {
        let home = NSString(string: NSHomeDirectory()).standardizingPath
        let marker = "/Containers/Data/Application/"
        guard let range = home.range(of: marker) else { return home }
        let suffix = home[range.upperBound...]
        guard let identifier = suffix.split(separator: "/").first else { return home }
        return String(home[..<range.upperBound]) + String(identifier)
    }

    private static func isOwnContainer(
        _ path: String,
        ownContainer: String
    ) -> Bool {
        let normalized = NSString(string: path).standardizingPath
        return normalized == ownContainer || normalized.hasPrefix(ownContainer + "/")
    }

    private static func status(
        for outcome: FileAccessOutcome
    ) -> SandboxValidationStatus {
        switch outcome {
        case .success: return .passed
        case .permissionDenied: return .denied
        case .missing: return .missing
        case .providerUnavailable: return .unavailable
        case .notTested, .failed: return .inconclusive
        }
    }
}
