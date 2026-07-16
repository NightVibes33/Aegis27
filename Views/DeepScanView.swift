import SwiftUI

struct DeepScanView: View {
    @EnvironmentObject private var researchViewModel: ResearchViewModel
    @StateObject private var viewModel = DeepScanViewModel()
    @State private var showWriteConfirmation = false

    var body: some View {
        NavigationStack {
            List {
                configurationSection
                if let report = viewModel.report {
                    summarySection(report)
                    resultsSection
                    serviceSection(report)
                } else if !viewModel.isRunning {
                    scopeSection
                }
            }
            .navigationTitle("Deep Scan")
            .searchable(text: $viewModel.searchText, prompt: "Filter scanned paths")
            .toolbar {
                if viewModel.isRunning {
                    Button("Cancel", role: .cancel) { viewModel.cancel() }
                }
            }
            .alert("Enable write verification?", isPresented: $showWriteConfirmation) {
                Button("Cancel", role: .cancel) { }
                Button("Run canaries", role: .destructive) { startScan() }
            } message: {
                Text(viewModel.scanAllReachablePaths
                    ? "Every discovered directory will receive a uniquely named empty canary that is immediately removed. Existing files are never modified. This can make the scan substantially slower."
                    : "Up to 100 discovered directories will receive a uniquely named empty canary that is immediately removed. Existing files are never modified.")
            }
        }
    }

    private var configurationSection: some View {
        Section("Scan configuration") {
            Picker("Provider", selection: $viewModel.selectedProvider) {
                ForEach(FileProviderKind.allCases) { provider in
                    Text(provider.title).tag(provider)
                }
            }
            Toggle("Scan all reachable paths", isOn: $viewModel.scanAllReachablePaths)
            if !viewModel.scanAllReachablePaths {
                Stepper(
                    "Maximum paths: \(viewModel.maximumNodes)",
                    value: $viewModel.maximumNodes,
                    in: 1_000...100_000,
                    step: 1_000
                )
                Stepper(
                    "Maximum depth: \(viewModel.maximumDepth)",
                    value: $viewModel.maximumDepth,
                    in: 1...64
                )
            }
            Toggle("One-byte read probes", isOn: $viewModel.includeReadProbe)
            Toggle("Create-and-remove write canaries", isOn: $viewModel.includeWriteProbe)

            Button {
                if viewModel.includeWriteProbe {
                    showWriteConfirmation = true
                } else {
                    startScan()
                }
            } label: {
                if viewModel.isRunning {
                    ProgressView()
                } else {
                    Label("Start deep scan", systemImage: "magnifyingglass.circle.fill")
                }
            }
            .disabled(viewModel.isRunning)
        }
    }

    private var scopeSection: some View {
        Section("Coverage") {
            Text("The scan starts from \(DeepScanService.seedPaths.count) system and container roots. It advances each root in turn so one large public tree cannot starve the others. All-reachable mode continues until every listable path is exhausted.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Text("It does not follow symbolic links, retain file contents, send private service messages, or bypass a denied parent directory. Mach-service coverage is limited to the evidence-backed candidate catalog because the bootstrap namespace is not publicly enumerable.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private func summarySection(_ report: DeepScanReport) -> some View {
        Section("Summary") {
            LabeledContent("Paths scanned", value: String(report.observations.count))
            LabeledContent("Metadata visible", value: String(report.metadataVisibleCount))
            LabeledContent("Files actually read", value: String(report.readableFileCount))
            LabeledContent("Directories listed", value: String(report.listableDirectoryCount))
            LabeledContent("Accessible entries", value: String(report.accessibleCount))
            LabeledContent("Writable", value: String(report.writableCount))
            LabeledContent("Denied", value: String(report.deniedCount))
            LabeledContent("Services reachable", value: "\(report.reachableServiceCount) of \(report.serviceResults.count)")
            if let exportURL = viewModel.exportURL {
                ShareLink(item: exportURL) {
                    Label("Export full scan JSON", systemImage: "square.and.arrow.up")
                }
            }
            if report.nodeLimitReached {
                Label("Path limit reached; increase it for broader coverage.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            if report.cancelled {
                Label("Scan cancelled", systemImage: "stop.circle")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var resultsSection: some View {
        Section {
            Picker("Results", selection: $viewModel.resultFilter) {
                ForEach(DeepScanResultFilter.allCases) { filter in
                    Text(filter.title).tag(filter)
                }
            }
            .pickerStyle(.segmented)

            ForEach(viewModel.filteredObservations.prefix(500)) { observation in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Image(systemName: observation.writable
                            ? "pencil.circle.fill"
                            : (observation.readable
                                ? "eye.circle.fill"
                                : "lock.circle"))
                            .foregroundStyle(observation.writable
                                ? .orange
                                : (observation.readable ? .green : .secondary))
                        Text(observation.path)
                            .font(.caption.monospaced())
                            .lineLimit(2)
                    }
                    Text(resultDetail(observation))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Filesystem results")
        } footer: {
            if viewModel.filteredObservations.count > 500 {
                Text("Showing the first 500 matching paths.")
            }
        }
    }

    private func serviceSection(_ report: DeepScanReport) -> some View {
        Section("Candidate services") {
            ForEach(report.serviceResults) { result in
                Label(
                    result.service,
                    systemImage: result.resolved
                        ? "checkmark.circle.fill"
                        : "xmark.circle"
                )
                .font(.caption.monospaced())
                .foregroundStyle(result.resolved ? .orange : .secondary)
            }
        }
    }

    private func resultDetail(_ result: DeepScanObservation) -> String {
        let values = [
            "metadata \(result.metadataOutcome.rawValue)",
            result.listingOutcome == .notTested ? nil : "list \(result.listingOutcome.rawValue)",
            result.readOutcome == .notTested ? nil : "read \(result.readOutcome.rawValue)",
            result.writeOutcome == .notTested ? nil : "write \(result.writeOutcome.rawValue)"
        ].compactMap { $0 }
        return values.joined(separator: " • ")
    }

    private func startScan() {
        viewModel.start { report in
            researchViewModel.logger.record(ResearchEvent(
                severity: report.writableCount > 0 ? .warning : .success,
                subsystem: "deep-scan",
                message: "Bounded device capability scan completed",
                details: [
                    "provider": report.provider.rawValue,
                    "paths": String(report.observations.count),
                    "metadataVisible": String(report.metadataVisibleCount),
                    "filesRead": String(report.readableFileCount),
                    "directoriesListed": String(report.listableDirectoryCount),
                    "accessible": String(report.accessibleCount),
                    "writable": String(report.writableCount),
                    "denied": String(report.deniedCount),
                    "reachableServices": String(report.reachableServiceCount),
                    "cancelled": String(report.cancelled),
                    "nodeLimitReached": String(report.nodeLimitReached)
                ]
            ))
            if let exportURL = viewModel.exportURL {
                Task {
                    await GitHubRunnerBridge.shared.submitIfConnected(
                        fileURL: exportURL,
                        kind: "deep-scan",
                        profile: researchViewModel.profile,
                        logger: researchViewModel.logger
                    )
                }
            }
        }
    }
}
