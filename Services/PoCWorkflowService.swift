import Foundation

enum PoCWorkflowService {
    static func run(
        source: AttackSurfaceReport,
        catalog: FirmwareProbeCatalog,
        crashes: [CrashCorrelationResult],
        profile: DeviceProfile
    ) async -> PoCWorkflowReport {
        let lead = strongestLead(source: source, crashes: crashes)
        let hypothesis = hypothesis(for: lead, source: source)
        var minimization: XPCMinimizationResult?

        if lead.kind == .typedXPC,
           let service = lead.service,
           let requestID = lead.requestID,
           let fingerprint = lead.fingerprint,
           let schema = catalog.services
            .first(where: { $0.service == service })?
            .requests.first(where: { $0.id == requestID }) {
            minimization = await XPCSchemaMinimizer.run(
                service: service,
                schema: schema,
                expectedFingerprint: fingerprint
            )
        }

        let validation = SandboxValidationService.run(
            provider: StockFileAccessProvider()
        )
        let repeated = isRepeated(lead: lead, source: source)
        let expectedCrossBootKey = [
            lead.service,
            lead.requestID,
            lead.fingerprint
        ].compactMap { $0 }.joined(separator: "|")
        let crossBoot = source.previousRunWasDifferentBoot &&
            !expectedCrossBootKey.isEmpty &&
            source.previousRunMatchedFingerprintKeys.contains(expectedCrossBootKey)
        let matchingCrashes = crashes.filter {
            $0.timingMatched && $0.classification == .matchingService
        }
        let status: PoCWorkflowStatus
        if validation.accessConfirmed {
            status = .confirmedImpact
        } else if lead.kind == .none {
            status = .noLead
        } else if repeated && crossBoot &&
                    (minimization?.initialReproductionStable != false) {
            status = .reproducibleCandidate
        } else if repeated {
            status = .needsRebootConfirmation
        } else {
            status = .leadOnly
        }

        return PoCWorkflowReport(
            id: UUID(),
            createdAt: Date(),
            sourceReportID: source.id,
            target: profile,
            lead: lead,
            primitiveHypothesis: validation.accessConfirmed
                ? .sandboxEscapeConfirmed : hypothesis,
            status: status,
            minimization: minimization,
            crashEvidence: matchingCrashes,
            validation: validation,
            repeatedInDiscoveryRun: repeated,
            crossBootConfirmed: crossBoot,
            limitations: limitations(
                lead: lead,
                validation: validation,
                crashes: matchingCrashes
            )
        )
    }

    private static func strongestLead(
        source: AttackSurfaceReport,
        crashes: [CrashCorrelationResult]
    ) -> PoCLead {
        if source.protectedAccessConfirmed {
            return PoCLead(
                id: "protected-access",
                kind: .protectedAccess,
                title: "Protected filesystem access",
                service: nil,
                requestID: nil,
                fingerprint: nil,
                corpusID: nil,
                ioKitClass: nil
            )
        }
        if let crash = crashes.first(where: {
            $0.timingMatched && $0.classification == .matchingService
        }) {
            return PoCLead(
                id: "crash-\(crash.id.uuidString)",
                kind: .serviceCrash,
                title: crash.classification.title,
                service: crash.nearestService,
                requestID: crash.nearestRequestID,
                fingerprint: nil,
                corpusID: nil,
                ioKitClass: nil
            )
        }

        let grouped = Dictionary(grouping: source.serviceResults.filter(\.wasProbed)) {
            "\($0.service)|\($0.requestID)"
        }
        let stable = grouped.values.compactMap { values -> AttackSurfaceServiceResult? in
            guard values.count == source.repetitionCount,
                  Set(values.map(\.fingerprint)).count == 1,
                  values.first?.unexpectedReply == true else { return nil }
            return values.first
        }
        if let typed = stable.first(where: { $0.requestID != XPCRequestSchema.empty.id }) {
            return PoCLead(
                id: "xpc-\(typed.service)-\(typed.requestID)",
                kind: .typedXPC,
                title: typed.requestLabel,
                service: typed.service,
                requestID: typed.requestID,
                fingerprint: typed.fingerprint,
                corpusID: nil,
                ioKitClass: nil
            )
        }
        if let opened = source.ioKitResults.first(where: \.opened) {
            return PoCLead(
                id: "iokit-\(opened.className)",
                kind: .ioKitUserClient,
                title: "Open IOKit user client",
                service: nil,
                requestID: nil,
                fingerprint: nil,
                corpusID: nil,
                ioKitClass: opened.className
            )
        }
        if let parser = source.parserResults.first(where: {
            $0.outcome == .timedOut || $0.outcome == .failed
        }) {
            return PoCLead(
                id: "parser-\(parser.corpusID)-\(parser.boundary)",
                kind: .parserBoundary,
                title: "Abnormal parser outcome",
                service: nil,
                requestID: nil,
                fingerprint: nil,
                corpusID: parser.corpusID,
                ioKitClass: nil
            )
        }
        if let empty = stable.first {
            return PoCLead(
                id: "xpc-empty-\(empty.service)",
                kind: .emptyXPC,
                title: "Stable empty-dictionary response",
                service: empty.service,
                requestID: empty.requestID,
                fingerprint: empty.fingerprint,
                corpusID: nil,
                ioKitClass: nil
            )
        }
        return PoCLead(
            id: "none",
            kind: .none,
            title: "No reproducible lead",
            service: nil,
            requestID: nil,
            fingerprint: nil,
            corpusID: nil,
            ioKitClass: nil
        )
    }

    private static func hypothesis(
        for lead: PoCLead,
        source: AttackSurfaceReport
    ) -> PrimitiveHypothesis {
        switch lead.kind {
        case .protectedAccess: return .sandboxEscapeConfirmed
        case .serviceCrash: return .memorySafetyCandidate
        case .typedXPC, .emptyXPC: return .confusedDeputyCandidate
        case .ioKitUserClient: return .kernelSurfaceCandidate
        case .parserBoundary: return .parserCandidate
        case .none: return .unclassified
        }
    }

    private static func isRepeated(
        lead: PoCLead,
        source: AttackSurfaceReport
    ) -> Bool {
        guard let service = lead.service, let request = lead.requestID else {
            return lead.kind == .protectedAccess
        }
        let matches = source.serviceResults.filter {
            $0.service == service && $0.requestID == request && $0.wasProbed
        }
        return matches.count == source.repetitionCount &&
            Set(matches.map(\.fingerprint)).count == 1
    }

    private static func limitations(
        lead: PoCLead,
        validation: SandboxValidationReport,
        crashes: [CrashCorrelationResult]
    ) -> [String] {
        var values: [String] = []
        if !validation.accessConfirmed {
            values.append("No unauthorized protected read or foreign-container listing was confirmed.")
        }
        if lead.kind == .serviceCrash && crashes.isEmpty {
            values.append("A crash without a matching timestamp/process diagnostic is not attributed to the probe.")
        }
        if lead.kind == .ioKitUserClient {
            values.append("Opening a user client does not establish a vulnerable external method or kernel primitive.")
        }
        if lead.kind == .typedXPC || lead.kind == .emptyXPC {
            values.append("A stable reply proves protocol handling, not unauthorized service behavior.")
        }
        values.append("This package contains a bounded reproducer manifest, not an exploit payload or persistence mechanism.")
        return values
    }
}
