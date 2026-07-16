import Foundation

enum AttackSurfaceProbeService {
    static let timeoutMilliseconds: UInt32 = 750

    static func run() async -> AttackSurfaceReport {
        let startedAt = Date()
        let before = MachServiceReachabilityProbe.run()
        let beforeByService = Dictionary(
            uniqueKeysWithValues: before.map { ($0.service, $0.rawResult) }
        )

        var provisional: [(String, String, Int32, XPCProbeDisposition?, Double?)] = []
        for candidate in ServiceResearchCatalog.candidates {
            let lookup = beforeByService[candidate.service] ?? Int32.min
            guard lookup == 0 else {
                provisional.append((
                    candidate.service,
                    candidate.subsystem,
                    lookup,
                    nil,
                    nil
                ))
                continue
            }

            var elapsedNanoseconds: UInt64 = 0
            let raw = candidate.service.withCString { name in
                aegis_xpc_empty_dictionary_probe(
                    name,
                    timeoutMilliseconds,
                    &elapsedNanoseconds
                )
            }
            provisional.append((
                candidate.service,
                candidate.subsystem,
                lookup,
                XPCProbeDisposition(rawValue: raw) ?? .setupFailed,
                Double(elapsedNanoseconds) / 1_000_000
            ))
        }

        let after = MachServiceReachabilityProbe.run()
        let afterByService = Dictionary(
            uniqueKeysWithValues: after.map { ($0.service, $0.rawResult) }
        )
        let results = provisional.map { item in
            AttackSurfaceServiceResult(
                service: item.0,
                subsystem: item.1,
                lookupBefore: item.2,
                lookupAfter: afterByService[item.0] ?? Int32.min,
                disposition: item.3,
                elapsedMilliseconds: item.4
            )
        }

        // Always validate after the suite. A privilege change is more important
        // than whether the service returned a syntactically interesting reply.
        let validation = SandboxValidationService.run(
            provider: StockFileAccessProvider()
        )
        return AttackSurfaceReport(
            startedAt: startedAt,
            finishedAt: Date(),
            timeoutMilliseconds: timeoutMilliseconds,
            serviceResults: results,
            validation: validation
        )
    }
}
