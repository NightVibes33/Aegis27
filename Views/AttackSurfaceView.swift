import SwiftUI
import UniformTypeIdentifiers

struct AttackSurfaceView: View {
    @EnvironmentObject private var researchViewModel: ResearchViewModel
    @StateObject private var viewModel = AttackSurfaceViewModel()
    @State private var showConfirmation = false
    @State private var showCatalogImporter = false
    @State private var showCrashImporter = false

    var body: some View {
        List {
            catalogSection
            runSection
            if let report = viewModel.report {
                resultSection(report)
                serviceSection(report)
                parserSection(report)
                ioKitSection(report)
                crashSection
                pocWorkflowSection(report)
                validationSection(report)
            }
            if let error = viewModel.lastError {
                Section("Last error") {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Attack Surface")
        .alert("Run bounded research suite?", isPresented: $showConfirmation) {
            Button("Cancel", role: .cancel) { }
            Button("Run") {
                viewModel.run(
                    logger: researchViewModel.logger,
                    profile: researchViewModel.profile
                )
            }
        } message: {
            Text("Each XPC request is repeated three times. Parser inputs are tiny and controlled. IOKit probes only match, open type 0, and immediately close; no external methods are called.")
        }
        .fileImporter(
            isPresented: $showCatalogImporter,
            allowedContentTypes: [.json],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                viewModel.importCatalog(
                    from: url,
                    targetBuild: researchViewModel.profile.buildVersion,
                    logger: researchViewModel.logger
                )
            }
        }
        .fileImporter(
            isPresented: $showCrashImporter,
            allowedContentTypes: [.item],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                viewModel.importCrashReport(
                    from: url,
                    logger: researchViewModel.logger
                )
            }
        }
    }

    private var catalogSection: some View {
        Section("Matching firmware catalog") {
            Button {
                showCatalogImporter = true
            } label: {
                Label("Import probe catalog", systemImage: "shippingbox.and.arrow.backward")
            }
            if viewModel.hasCatalog {
                LabeledContent("File", value: viewModel.catalogFileName ?? "Imported")
                LabeledContent("Source build", value: viewModel.catalog.sourceBuild)
                LabeledContent("Services", value: String(viewModel.catalog.services.count))
                LabeledContent(
                    "Typed schemas",
                    value: String(viewModel.catalog.services.flatMap(\.requests).count)
                )
            } else {
                Text("Without a catalog, the suite runs empty-dictionary baselines only. Generate a catalog from the exact extracted firmware with scripts/build_probe_catalog.py.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            ForEach(viewModel.catalogWarnings, id: \.self) { warning in
                Label(warning, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
    }

    private var runSection: some View {
        Section("Bounded suite") {
            Text("Measures typed XPC response fingerprints, controlled parser boundaries, IOKit open-only visibility, cross-run stability, and protected filesystem access. Reply values and parser outputs are never retained.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Button {
                showConfirmation = true
            } label: {
                if viewModel.isRunning {
                    ProgressView()
                } else {
                    Label("Run complete attack-surface suite", systemImage: "scope")
                }
            }
            .disabled(viewModel.isRunning)
        }
    }

    private func resultSection(_ report: AttackSurfaceReport) -> some View {
        Section("Result") {
            Label(
                resultTitle(report),
                systemImage: report.protectedAccessConfirmed
                    ? "exclamationmark.shield.fill" : "lock.shield.fill"
            )
            .font(.headline)
            .foregroundStyle(report.protectedAccessConfirmed ? .red : .secondary)
            LabeledContent("XPC requests", value: String(report.probedCount))
            LabeledContent("Stable protocol leads", value: String(report.stableProtocolLeadCount))
            LabeledContent("Parser checks", value: String(report.parserResults.count))
            LabeledContent("IOKit opens", value: String(report.openedIOKitCount))
            LabeledContent("Previous-run matches", value: String(report.previousRunMatchedFingerprints))
            LabeledContent("Cross-boot matches", value: String(report.crossBootMatchedFingerprints))
            LabeledContent(
                "Previous run",
                value: report.previousRunWasDifferentBoot ? "Different boot" : "Same/unknown boot"
            )
            if let url = viewModel.exportURL {
                ShareLink(item: url) {
                    Label("Export compact report", systemImage: "square.and.arrow.up")
                }
            }
        }
    }

    private func serviceSection(_ report: AttackSurfaceReport) -> some View {
        Section("XPC response fingerprints") {
            ForEach(report.serviceResults.filter { $0.wasProbed && $0.repetition == 1 }) { result in
                VStack(alignment: .leading, spacing: 4) {
                    Text(result.service).font(.caption.monospaced())
                    Text("\(result.requestLabel) • \(result.disposition?.title ?? "Not run")")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text("keys \(result.replyKeyCount) • fingerprint \(result.replyKeyHash)")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func parserSection(_ report: AttackSurfaceReport) -> some View {
        Section("Controlled parser boundaries") {
            ForEach(report.catalogParserSurfaces) { surface in
                VStack(alignment: .leading, spacing: 3) {
                    Label(surface.label, systemImage: "map")
                        .font(.caption.weight(.semibold))
                    Text("\(surface.boundary) • \(surface.uniformType)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            ForEach(report.parserResults) { result in
                VStack(alignment: .leading, spacing: 3) {
                    Text(result.label).font(.caption.weight(.semibold))
                    Text("\(result.boundary) • \(result.outcome.rawValue) • \(formatted(result.elapsedMilliseconds)) ms")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func ioKitSection(_ report: AttackSurfaceReport) -> some View {
        Section("IOKit open-only inventory") {
            ForEach(report.ioKitResults) { result in
                HStack {
                    Image(systemName: result.opened ? "exclamationmark.circle.fill" : "circle")
                        .foregroundStyle(result.opened ? .orange : .secondary)
                    VStack(alignment: .leading) {
                        Text(result.className).font(.caption.monospaced())
                        Text("matched \(result.matched) • open result \(result.openResult)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Text("An open user client is an attack-surface lead, not an escape. This mode never calls external methods.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private var crashSection: some View {
        Section("Crash correlation") {
            Button {
                showCrashImporter = true
            } label: {
                Label("Import .ips or diagnostic", systemImage: "waveform.badge.magnifyingglass")
            }
            ForEach(viewModel.crashCorrelations) { result in
                VStack(alignment: .leading, spacing: 3) {
                    Text(result.classification.title).font(.caption.weight(.semibold))
                    Text("\(result.processName ?? "unknown process") • timing match \(result.timingMatched)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    if let service = result.nearestService {
                        Text("Nearest: \(service) / \(result.nearestRequestID ?? "unknown request")")
                            .font(.caption2.monospaced())
                    }
                }
            }
        }
    }

    private func pocWorkflowSection(_ report: AttackSurfaceReport) -> some View {
        Section("PoC candidate workflow") {
            Text("Ranks the strongest lead, reproduces and minimizes imported typed XPC schemas, checks impact after every variant, applies the reboot gate, and exports a self-contained evidence manifest.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Button {
                viewModel.buildPoCWorkflow(
                    profile: researchViewModel.profile,
                    logger: researchViewModel.logger
                )
            } label: {
                if viewModel.isBuildingPoC {
                    ProgressView()
                } else {
                    Label("Build PoC candidate package", systemImage: "hammer.fill")
                }
            }
            .disabled(viewModel.isBuildingPoC || viewModel.isRunning)

            if let workflow = viewModel.pocWorkflow {
                Label(
                    workflow.status.title,
                    systemImage: workflow.controlledImpactConfirmed
                        ? "exclamationmark.shield.fill" : "doc.badge.gearshape"
                )
                .font(.headline)
                .foregroundStyle(workflow.controlledImpactConfirmed ? .red : .secondary)
                LabeledContent("Lead", value: workflow.lead.title)
                LabeledContent("Hypothesis", value: workflow.primitiveHypothesis.title)
                LabeledContent("Repeated", value: String(workflow.repeatedInDiscoveryRun))
                LabeledContent("Cross-boot", value: String(workflow.crossBootConfirmed))
                LabeledContent("Controlled impact", value: String(workflow.controlledImpactConfirmed))

                if let minimization = workflow.minimization {
                    LabeledContent(
                        "Schema fields",
                        value: "\(minimization.originalFields.count) → \(minimization.minimizedFields.count)"
                    )
                    LabeledContent(
                        "Reproduced",
                        value: String(minimization.initialReproductionStable)
                    )
                    ForEach(minimization.attempts) { attempt in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(attempt.removedKey.map { "Remove \($0)" } ?? "Full-schema reproduction")
                                .font(.caption.weight(.semibold))
                            Text("preserved \(attempt.preservedExpectedFingerprint) • fields \(attempt.remainingKeys.count) • impact \(attempt.protectedAccessConfirmed)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                ForEach(workflow.limitations, id: \.self) { limitation in
                    Label(limitation, systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let url = viewModel.pocExportURL {
                    ShareLink(item: url) {
                        Label("Export PoC candidate JSON", systemImage: "square.and.arrow.up")
                    }
                }
            }
        }
    }

    private func validationSection(_ report: AttackSurfaceReport) -> some View {
        Section("Post-probe validation") {
            ForEach(report.validation.checks) { check in
                VStack(alignment: .leading, spacing: 3) {
                    Text(check.label).font(.subheadline.weight(.semibold))
                    Text(check.path).font(.caption2.monospaced())
                    Text("\(check.status.title) • \(check.detail)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func resultTitle(_ report: AttackSurfaceReport) -> String {
        if report.protectedAccessConfirmed { return "Protected access changed" }
        if report.stableProtocolLeadCount > 0 { return "Repeatable leads; no escape confirmed" }
        return "No escape detected"
    }

    private func formatted(_ value: Double?) -> String {
        String(format: "%.1f", value ?? 0)
    }
}
