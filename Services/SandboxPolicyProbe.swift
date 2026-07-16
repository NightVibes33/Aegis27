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

    // Every entry is either observed on the target, named by the public
    // firmware diff, or explicitly marked as a bounded name candidate.
    // Lookup never sends a protocol message to the returned port.
    static let machServices = ServiceResearchCatalog.serviceNames

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
