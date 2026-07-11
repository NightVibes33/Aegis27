import Foundation

enum MachServiceConnectionProbe {
    static func run(services: [String]) async -> [MachServiceConnectionResult] {
        services.map { service in
            var portType: UInt32 = 0
            var sendRightRefs: UInt32 = 0
            let raw = service.withCString { pointer in
                aegis_bootstrap_probe_service(pointer, &portType, &sendRightRefs)
            }
            return MachServiceConnectionResult(
                service: service,
                lookupResult: raw,
                portType: portType,
                sendRightRefs: sendRightRefs
            )
        }
    }
}
