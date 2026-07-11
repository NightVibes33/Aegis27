import Foundation

enum SandboxPolicyProbe {
    private static let pathOperations = [
        "file-read-metadata",
        "file-read-data",
        "file-write-create",
        "file-write-data"
    ]

    private static let paths = [
        "/var/mobile/Library/Preferences",
        "/var/mobile/Library/Caches",
        "/var/containers/Shared/SystemGroup",
        "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache",
        "/private/var/db",
        "/var/mobile/Library/Preferences/com.apple.MobileGestalt.plist",
        "/var/mobile/Library/Caches/com.apple.MobileGestalt.plist"
    ]

    // Candidate names are policy probes, not claims that every service exists
    // on this build. An allowed mach-lookup rule is only a lead for later
    // interface inventory; it is not itself a vulnerability.
    static let machServices = [
        "com.apple.mobilegestalt.xpc",
        "com.apple.cfprefsd.daemon",
        "com.apple.cfprefsd.agent",
        "com.apple.bookassetd",
        "com.apple.itunesstored",
        "com.apple.mobileassetd",
        "com.apple.mobile.file_relay",
        "com.apple.backupd"
    ]

    static func run() -> [SandboxPolicyResult] {
        var results: [SandboxPolicyResult] = []

        for path in paths {
            for operation in pathOperations {
                let raw = operation.withCString { operationPointer in
                    path.withCString { pathPointer in
                        aegis_sandbox_check_path(operationPointer, pathPointer)
                    }
                }
                results.append(SandboxPolicyResult(
                    kind: .path,
                    subject: path,
                    operation: operation,
                    rawResult: raw
                ))
            }
        }

        for service in machServices {
            let raw = "mach-lookup".withCString { operationPointer in
                service.withCString { servicePointer in
                    aegis_sandbox_check_global_name(operationPointer, servicePointer)
                }
            }
            results.append(SandboxPolicyResult(
                kind: .machService,
                subject: service,
                operation: "mach-lookup",
                rawResult: raw
            ))
        }

        return results
    }
}

enum MachServiceReachabilityProbe {
    static func run() -> [MachServiceLookupResult] {
        SandboxPolicyProbe.machServices.map { service in
            let raw = service.withCString { pointer in
                aegis_bootstrap_lookup_service(pointer)
            }
            return MachServiceLookupResult(service: service, rawResult: raw)
        }
    }
}
