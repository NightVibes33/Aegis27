import Foundation

enum AttackSurfaceProbeService {
    static let timeoutMilliseconds: UInt32 = 750
    static let repetitionCount = 3
    static let maximumImportedRequestsPerService = 4

    private struct Candidate {
        let service: String
        let subsystem: String
        let requests: [XPCRequestSchema]
    }

    static func run(catalog: FirmwareProbeCatalog = .empty) async -> AttackSurfaceReport {
        let startedAt = Date()
        let previous = AttackSurfaceHistoryStore.load()
        let candidates = combinedCandidates(catalog)
        let beforeByService = lookup(services: candidates.map(\.service))
        var provisional: [AttackSurfaceServiceResult] = []
        var earlyValidation: SandboxValidationReport?

        for repetition in 1...repetitionCount {
            for candidate in candidates {
                let lookupBefore = beforeByService[candidate.service] ?? Int32.min
                guard lookupBefore == 0 else {
                    if repetition == 1 {
                        provisional.append(AttackSurfaceServiceResult(
                            repetition: 0,
                            service: candidate.service,
                            subsystem: candidate.subsystem,
                            requestID: XPCRequestSchema.empty.id,
                            requestLabel: XPCRequestSchema.empty.label,
                            lookupBefore: lookupBefore,
                            lookupAfter: lookupBefore,
                            disposition: nil,
                            elapsedMilliseconds: nil,
                            replyKeyCount: 0,
                            replyKeyHash: "0"
                        ))
                    }
                    continue
                }

                for request in candidate.requests {
                    provisional.append(probe(
                        candidate: candidate,
                        request: request,
                        repetition: repetition,
                        lookupBefore: lookupBefore
                    ))
                    await Task.yield()
                }
            }

            let validation = SandboxValidationService.run(
                provider: StockFileAccessProvider()
            )
            if validation.accessConfirmed {
                earlyValidation = validation
                break
            }
        }

        let parserResults: [ParserBoundaryResult]
        let ioKitResults: [IOKitProbeResult]
        if earlyValidation == nil {
            parserResults = await ParserBoundaryProbe.run()
            ioKitResults = IOKitSurfaceProbe.run(
                additionalClasses: catalog.ioKitClasses
            )
        } else {
            parserResults = []
            ioKitResults = []
        }

        let afterByService = lookup(services: candidates.map(\.service))
        let results = provisional.map { item in
            AttackSurfaceServiceResult(
                timestamp: item.timestamp,
                repetition: item.repetition,
                service: item.service,
                subsystem: item.subsystem,
                requestID: item.requestID,
                requestLabel: item.requestLabel,
                lookupBefore: item.lookupBefore,
                lookupAfter: afterByService[item.service] ?? Int32.min,
                disposition: item.disposition,
                elapsedMilliseconds: item.elapsedMilliseconds,
                replyKeyCount: item.replyKeyCount,
                replyKeyHash: item.replyKeyHash
            )
        }
        let validation = earlyValidation ?? SandboxValidationService.run(
            provider: StockFileAccessProvider()
        )
        let boot = Date().addingTimeInterval(-ProcessInfo.processInfo.systemUptime)
        let report = AttackSurfaceReport(
            id: UUID(),
            startedAt: startedAt,
            finishedAt: Date(),
            bootSessionStartedAt: boot,
            timeoutMilliseconds: timeoutMilliseconds,
            repetitionCount: repetitionCount,
            catalogBuild: catalog.services.isEmpty ? nil : catalog.sourceBuild,
            serviceResults: results,
            parserResults: parserResults,
            catalogParserSurfaces: catalog.parserSurfaces,
            ioKitResults: ioKitResults,
            validation: validation,
            previousRunMatchedFingerprints: AttackSurfaceHistoryStore.matchedFingerprints(
                previous: previous,
                current: results
            ),
            previousRunWasDifferentBoot: previous.map {
                abs($0.bootSessionStartedAt.timeIntervalSince(boot)) > 120
            } ?? false
        )
        AttackSurfaceHistoryStore.save(report)
        return report
    }

    private static func combinedCandidates(
        _ catalog: FirmwareProbeCatalog
    ) -> [Candidate] {
        var ordered: [Candidate] = ServiceResearchCatalog.candidates.map { builtIn in
            let imported = catalog.services.first { $0.service == builtIn.service }
            return Candidate(
                service: builtIn.service,
                subsystem: imported?.subsystem ?? builtIn.subsystem,
                requests: [XPCRequestSchema.empty] + Array(
                    (imported?.requests ?? []).prefix(maximumImportedRequestsPerService)
                )
            )
        }
        let existing = Set(ordered.map(\.service))
        ordered.append(contentsOf: catalog.services.filter {
            !existing.contains($0.service)
        }.map {
            Candidate(
                service: $0.service,
                subsystem: $0.subsystem,
                requests: [XPCRequestSchema.empty] + Array(
                    $0.requests.prefix(maximumImportedRequestsPerService)
                )
            )
        })
        return Array(ordered.prefix(64))
    }

    private static func lookup(services: [String]) -> [String: Int32] {
        Dictionary(uniqueKeysWithValues: services.map { service in
            let raw = service.withCString(aegis_bootstrap_lookup_service)
            return (service, raw)
        })
    }

    private static func probe(
        candidate: Candidate,
        request: XPCRequestSchema,
        repetition: Int,
        lookupBefore: Int32
    ) -> AttackSurfaceServiceResult {
        var elapsedNanoseconds: UInt64 = 0
        var replyKeyCount: UInt32 = 0
        var replyKeyHash: UInt64 = 0
        let specification = fieldSpecification(request.fields)
        let raw = candidate.service.withCString { name in
            specification.withCString { fields in
                aegis_xpc_dictionary_probe(
                    name,
                    fields,
                    timeoutMilliseconds,
                    &elapsedNanoseconds,
                    &replyKeyCount,
                    &replyKeyHash
                )
            }
        }
        return AttackSurfaceServiceResult(
            repetition: repetition,
            service: candidate.service,
            subsystem: candidate.subsystem,
            requestID: request.id,
            requestLabel: request.label,
            lookupBefore: lookupBefore,
            lookupAfter: lookupBefore,
            disposition: XPCProbeDisposition(rawValue: raw) ?? .setupFailed,
            elapsedMilliseconds: Double(elapsedNanoseconds) / 1_000_000,
            replyKeyCount: replyKeyCount,
            replyKeyHash: String(replyKeyHash, radix: 16)
        )
    }

    private static func fieldSpecification(_ fields: [XPCProbeField]) -> String {
        fields.prefix(8).map { field in
            switch field.type {
            case .string:
                return "s:\(field.key)=\(field.stringValue ?? "")"
            case .unsignedInteger:
                return "u:\(field.key)=\(field.unsignedIntegerValue ?? 0)"
            case .boolean:
                return "b:\(field.key)=\((field.booleanValue ?? false) ? 1 : 0)"
            }
        }.joined(separator: "\n")
    }
}
