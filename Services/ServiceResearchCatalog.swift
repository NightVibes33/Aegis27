import Foundation

struct ServiceResearchCandidate: Identifiable {
    enum Confidence: String {
        case observed = "Observed"
        case firmware = "Firmware-derived"
        case naming = "Name candidate"
    }

    var id: String { service }
    let service: String
    let subsystem: String
    let confidence: Confidence
    let evidence: String
}

struct FirmwareServiceFinding: Identifiable {
    var id: String { title }
    let title: String
    let buildDelta: String
    let significance: String
    let services: [String]
}

enum ServiceResearchCatalog {
    static let candidates: [ServiceResearchCandidate] = [
        .init(
            service: "com.apple.mobilegestalt.xpc",
            subsystem: "MobileGestalt",
            confidence: .observed,
            evidence: "Resolved on the target through its stock bootstrap namespace."
        ),
        .init(
            service: "com.apple.cfprefsd.daemon",
            subsystem: "Preferences",
            confidence: .observed,
            evidence: "Resolved on the target; a send right alone does not grant preference access."
        ),
        .init(
            service: "com.apple.cfprefsd.agent",
            subsystem: "Preferences",
            confidence: .observed,
            evidence: "Policy permits lookup on the target, while bootstrap lookup currently fails."
        ),
        .init(
            service: "com.apple.mobileassetd",
            subsystem: "MobileAsset",
            confidence: .observed,
            evidence: "Resolved on the target and its beta-3 sandbox profile changed extension path handling."
        ),
        .init(
            service: "com.apple.mobileassetd.v2",
            subsystem: "MobileAsset",
            confidence: .firmware,
            evidence: "Named in beta-3 system-binary Mach lookup entitlements."
        ),
        .init(
            service: "com.apple.mobileasset.autoasset",
            subsystem: "MobileAsset",
            confidence: .firmware,
            evidence: "Named alongside mobileassetd.v2 in system-binary Mach lookup entitlements."
        ),
        .init(
            service: "com.apple.MobileAsset.DownloadService.Builtin",
            subsystem: "MobileAsset",
            confidence: .firmware,
            evidence: "Present as a beta-3 MobileAsset XPC service binary."
        ),
        .init(
            service: "com.apple.bookassetd",
            subsystem: "Books",
            confidence: .naming,
            evidence: "Daemon gained temporary-sandbox and platform-application in beta 3; listener name is not established."
        ),
        .init(
            service: "com.apple.iBooks.bookassetd",
            subsystem: "Books",
            confidence: .naming,
            evidence: "Bounded listener-name candidate for the beta-3 bookassetd entitlement change."
        ),
        .init(
            service: "com.apple.backupd",
            subsystem: "MobileBackup",
            confidence: .firmware,
            evidence: "Named in bookassetd Mach lookup entitlements and present in the firmware diff."
        ),
        .init(
            service: "com.apple.mobilebackup",
            subsystem: "MobileBackup",
            confidence: .naming,
            evidence: "Bounded daemon listener-name candidate; no request messages are sent."
        ),
        .init(
            service: "com.apple.CacheDelete",
            subsystem: "CacheDelete",
            confidence: .naming,
            evidence: "CacheDelete app-container policy and daemon interfaces changed in beta 3."
        ),
        .init(
            service: "com.apple.deleted",
            subsystem: "CacheDelete",
            confidence: .naming,
            evidence: "Bounded listener-name candidate for the updated deleted daemon."
        ),
        .init(
            service: "com.apple.fileproviderd",
            subsystem: "FileProvider",
            confidence: .naming,
            evidence: "FileProvider daemon updated in beta 3; lookup only, with no protocol messages."
        ),
        .init(
            service: "com.apple.FileProvider",
            subsystem: "FileProvider",
            confidence: .naming,
            evidence: "Bounded listener-name candidate for the updated FileProvider surface."
        ),
        .init(
            service: "com.apple.containermanagerd",
            subsystem: "Containers",
            confidence: .naming,
            evidence: "Container management is relevant to cross-container file access; lookup only."
        ),
        .init(
            service: "com.apple.mobile.file_relay",
            subsystem: "File relay",
            confidence: .observed,
            evidence: "Stock sandbox policy and bootstrap lookup both deny this service on the target."
        ),
        .init(
            service: "com.apple.afc",
            subsystem: "AFC",
            confidence: .firmware,
            evidence: "The beta-3 afcd sandbox profile changed sandbox-extension issuance rules."
        ),
        .init(
            service: "com.apple.afcd",
            subsystem: "AFC",
            confidence: .naming,
            evidence: "Bounded listener-name candidate for the updated afcd profile."
        ),
        .init(
            service: "com.apple.itunesstored",
            subsystem: "Media services",
            confidence: .observed,
            evidence: "Previously probed target service and a bookassetd preference dependency."
        )
    ]

    static let findings: [FirmwareServiceFinding] = [
        .init(
            title: "MobileAsset extension paths",
            buildDelta: "24A5370h → 24A5380h",
            significance: "The mobileassetd profile changed the paths accepted while issuing several sandbox-extension classes. The stock service is reachable on the target, making this the strongest current interface lead.",
            services: [
                "com.apple.mobileassetd",
                "com.apple.mobileassetd.v2",
                "com.apple.mobileasset.autoasset"
            ]
        ),
        .init(
            title: "bookassetd privilege expansion",
            buildDelta: "24A5370h → 24A5380h",
            significance: "bookassetd gained platform-application, temporary-sandbox, protected Gestalt keys and additional filesystem exceptions. Its externally reachable listener has not been identified.",
            services: ["com.apple.bookassetd", "com.apple.iBooks.bookassetd"]
        ),
        .init(
            title: "Backup and cache policy changes",
            buildDelta: "24A5370h → 24A5380h",
            significance: "MobileBackup mount rules and CacheDelete app-container matching changed. These are secondary candidates until the target resolves a related service.",
            services: [
                "com.apple.backupd",
                "com.apple.mobilebackup",
                "com.apple.CacheDelete",
                "com.apple.deleted"
            ]
        )
    ]

    static var serviceNames: [String] {
        candidates.map(\.service)
    }

    static func candidate(for service: String) -> ServiceResearchCandidate? {
        candidates.first { $0.service == service }
    }
}
