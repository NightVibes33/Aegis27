import Foundation

enum XPCSchemaMinimizer {
    static let timeoutMilliseconds: UInt32 = 750
    static let repetitions = 3

    static func run(
        service: String,
        schema: XPCRequestSchema,
        expectedFingerprint: String
    ) async -> XPCMinimizationResult {
        let originalFields = Array(schema.fields.prefix(8))
        var currentFields = originalFields
        var attempts: [XPCMinimizationAttempt] = []

        let initial = probeRepeatedly(service: service, fields: currentFields)
        let initialValidation = SandboxValidationService.run(
            provider: StockFileAccessProvider()
        )
        let initialStable = preserves(
            samples: initial,
            expectedFingerprint: expectedFingerprint
        )
        attempts.append(XPCMinimizationAttempt(
            removedKey: nil,
            remainingKeys: currentFields.map(\.key),
            fingerprints: initial.map(\.fingerprint),
            preservedExpectedFingerprint: initialStable,
            protectedAccessConfirmed: initialValidation.accessConfirmed
        ))

        guard initialStable, !initialValidation.accessConfirmed else {
            return XPCMinimizationResult(
                service: service,
                requestID: schema.id,
                expectedFingerprint: expectedFingerprint,
                originalFields: originalFields,
                minimizedFields: currentFields,
                initialReproductionStable: initialStable,
                attempts: attempts
            )
        }

        var index = 0
        while index < currentFields.count && attempts.count <= 9 {
            let removed = currentFields[index]
            var candidate = currentFields
            candidate.remove(at: index)
            let samples = probeRepeatedly(service: service, fields: candidate)
            let validation = SandboxValidationService.run(
                provider: StockFileAccessProvider()
            )
            let kept = preserves(
                samples: samples,
                expectedFingerprint: expectedFingerprint
            )
            attempts.append(XPCMinimizationAttempt(
                removedKey: removed.key,
                remainingKeys: candidate.map(\.key),
                fingerprints: samples.map(\.fingerprint),
                preservedExpectedFingerprint: kept,
                protectedAccessConfirmed: validation.accessConfirmed
            ))
            if validation.accessConfirmed { break }
            if kept {
                currentFields = candidate
            } else {
                index += 1
            }
            await Task.yield()
        }

        return XPCMinimizationResult(
            service: service,
            requestID: schema.id,
            expectedFingerprint: expectedFingerprint,
            originalFields: originalFields,
            minimizedFields: currentFields,
            initialReproductionStable: initialStable,
            attempts: attempts
        )
    }

    private struct Sample {
        let disposition: XPCProbeDisposition
        let keyCount: UInt32
        let keyHash: String

        var fingerprint: String {
            "\(disposition.rawValue):\(keyCount):\(keyHash)"
        }
    }

    private static func probeRepeatedly(
        service: String,
        fields: [XPCProbeField]
    ) -> [Sample] {
        let specification = fieldSpecification(fields)
        return (0..<repetitions).map { _ in
            var elapsed: UInt64 = 0
            var keyCount: UInt32 = 0
            var keyHash: UInt64 = 0
            let raw = service.withCString { servicePointer in
                specification.withCString { fieldPointer in
                    aegis_xpc_dictionary_probe(
                        servicePointer,
                        fieldPointer,
                        timeoutMilliseconds,
                        &elapsed,
                        &keyCount,
                        &keyHash
                    )
                }
            }
            return Sample(
                disposition: XPCProbeDisposition(rawValue: raw) ?? .setupFailed,
                keyCount: keyCount,
                keyHash: String(keyHash, radix: 16)
            )
        }
    }

    private static func preserves(
        samples: [Sample],
        expectedFingerprint: String
    ) -> Bool {
        samples.count == repetitions &&
            Set(samples.map(\.fingerprint)).count == 1 &&
            samples.first?.fingerprint == expectedFingerprint
    }

    private static func fieldSpecification(_ fields: [XPCProbeField]) -> String {
        fields.prefix(8).map { field in
            switch field.type {
            case .string: return "s:\(field.key)=\(field.stringValue ?? "")"
            case .unsignedInteger:
                return "u:\(field.key)=\(field.unsignedIntegerValue ?? 0)"
            case .boolean:
                return "b:\(field.key)=\((field.booleanValue ?? false) ? 1 : 0)"
            }
        }.joined(separator: "\n")
    }
}
