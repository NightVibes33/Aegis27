import Foundation

enum ProviderCapabilityValidator {
    static func validate(
        provider: any FileAccessProvider
    ) -> ProviderCapabilityReport {
        let home = NSHomeDirectory()
        let protectedDirectory = "/var/mobile/Library/Preferences"
        let homeMetadata = provider.metadata(at: home)
        let homeListing = provider.listDirectory(at: home)
        let protectedMetadata = provider.metadata(at: protectedDirectory)
        let protectedListing = provider.listDirectory(at: protectedDirectory)

        let protectedReadCheck: ProviderAccessCheck
        if protectedListing.succeeded,
           let file = protectedListing.entries.first(where: {
               !$0.isDirectory && !$0.isSymbolicLink
           }) {
            let protectedRead = provider.readPreview(at: file.path, limit: 4_096)
            protectedReadCheck = check(
                "Protected file preview",
                protectedRead.path,
                "read",
                protectedRead.outcome,
                protectedRead.errorDescription
            )
        } else {
            protectedReadCheck = ProviderAccessCheck(
                label: "Protected file preview",
                path: protectedDirectory,
                operation: "read",
                outcome: .notTested,
                detail: "Not run because the protected directory could not be listed."
            )
        }

        return ProviderCapabilityReport(
            provider: provider.kind,
            timestamp: Date(),
            checks: [
                check("App container metadata", homeMetadata.path, "stat", homeMetadata.outcome, homeMetadata.errorDescription),
                check("App container listing", homeListing.path, "list", homeListing.outcome, homeListing.errorDescription),
                check("Protected metadata", protectedMetadata.path, "stat", protectedMetadata.outcome, protectedMetadata.errorDescription),
                check("Protected listing", protectedListing.path, "list", protectedListing.outcome, protectedListing.errorDescription),
                protectedReadCheck
            ]
        )
    }

    private static func check(
        _ label: String,
        _ path: String,
        _ operation: String,
        _ outcome: FileAccessOutcome,
        _ error: String?
    ) -> ProviderAccessCheck {
        ProviderAccessCheck(
            label: label,
            path: path,
            operation: operation,
            outcome: outcome,
            detail: outcome == .success ? "Operation completed" : (error ?? outcome.title)
        )
    }
}
