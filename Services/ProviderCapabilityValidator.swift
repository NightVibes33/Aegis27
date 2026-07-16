import Foundation

enum ProviderCapabilityValidator {
    static func validate(
        provider: any FileAccessProvider
    ) -> ProviderCapabilityReport {
        let home = NSHomeDirectory()
        let protectedDirectory = "/var/mobile/Library/Preferences"
        let protectedFile = "/var/mobile/Library/Preferences/com.apple.MobileGestalt.plist"

        let homeMetadata = provider.metadata(at: home)
        let homeListing = provider.listDirectory(at: home)
        let protectedMetadata = provider.metadata(at: protectedDirectory)
        let protectedListing = provider.listDirectory(at: protectedDirectory)
        let protectedRead = provider.readPreview(at: protectedFile, limit: 4_096)

        return ProviderCapabilityReport(
            provider: provider.kind,
            timestamp: Date(),
            checks: [
                check("App container metadata", homeMetadata.path, "stat", homeMetadata.succeeded, homeMetadata.errorDescription),
                check("App container listing", homeListing.path, "list", homeListing.succeeded, homeListing.errorDescription),
                check("Protected metadata", protectedMetadata.path, "stat", protectedMetadata.succeeded, protectedMetadata.errorDescription),
                check("Protected listing", protectedListing.path, "list", protectedListing.succeeded, protectedListing.errorDescription),
                check("Protected file preview", protectedRead.path, "read", protectedRead.succeeded, protectedRead.errorDescription)
            ]
        )
    }

    private static func check(
        _ label: String,
        _ path: String,
        _ operation: String,
        _ succeeded: Bool,
        _ error: String?
    ) -> ProviderAccessCheck {
        ProviderAccessCheck(
            label: label,
            path: path,
            operation: operation,
            succeeded: succeeded,
            detail: succeeded ? "Operation completed" : (error ?? "Operation failed")
        )
    }
}
