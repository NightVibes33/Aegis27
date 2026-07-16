import Foundation

enum FileResearchTargetCatalog {
    static let targets = [
        FileResearchTarget(
            name: "MobileGestalt system group",
            path: "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache",
            category: .mobileGestalt,
            sensitive: false,
            intendedOperations: "metadata, list, bounded read"
        ),
        FileResearchTarget(
            name: "MobileGestalt preferences cache",
            path: "/var/mobile/Library/Preferences/com.apple.MobileGestalt.plist",
            category: .mobileGestalt,
            sensitive: false,
            intendedOperations: "metadata, bounded read"
        ),
        FileResearchTarget(
            name: "MobileGestalt library cache",
            path: "/var/mobile/Library/Caches/com.apple.MobileGestalt.plist",
            category: .mobileGestalt,
            sensitive: false,
            intendedOperations: "metadata, bounded read"
        ),
        FileResearchTarget(
            name: "Mobile preferences",
            path: "/var/mobile/Library/Preferences",
            category: .preferences,
            sensitive: false,
            intendedOperations: "metadata, list"
        ),
        FileResearchTarget(
            name: "System database directory",
            path: "/private/var/db",
            category: .database,
            sensitive: false,
            intendedOperations: "metadata, list"
        ),
        FileResearchTarget(
            name: "Legacy Notes directory",
            path: "/var/mobile/Library/Notes",
            category: .personalData,
            sensitive: true,
            intendedOperations: "metadata only"
        )
    ]

    static func observe(
        provider: any FileAccessProvider,
        includeSensitive: Bool
    ) -> [FileTargetObservation] {
        targets.filter { includeSensitive || !$0.sensitive }.map { target in
            let result = provider.metadata(at: target.path)
            return FileTargetObservation(
                target: target,
                provider: provider.kind,
                metadataReadable: result.succeeded,
                errorDescription: result.errorDescription
            )
        }
    }
}
