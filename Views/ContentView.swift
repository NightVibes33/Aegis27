import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject private var viewModel: ResearchViewModel
    @State private var showCanaryConfirmation = false
    @State private var showDiagnosticImporter = false
    private let buildIdentity = AppBuildIdentity.current

    var body: some View {
        TabView {
            researchDashboard
                .tabItem {
                    Label("Research", systemImage: "waveform.path.ecg")
                }
            FileBrowserView()
                .tabItem {
                    Label("Files", systemImage: "folder")
                }
            SandboxValidationView()
                .tabItem {
                    Label("Verify", systemImage: "checkmark.shield")
                }
            DeepScanView()
                .tabItem {
                    Label("Scan", systemImage: "magnifyingglass.circle")
                }
        }
    }

    private var researchDashboard: some View {
        NavigationStack {
            List {
                targetSection
                runtimeCapabilitySection
                primitiveSection
                experimentSection
                gestaltSection
                filesystemSection
                sandboxPolicySection
                firmwareFocusSection
                machServiceSection
                xpcConnectionSection
                canarySection
                snapshotSection
                diagnosticSection
                logSection
            }
            .navigationTitle("Aegis27")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Refresh") {
                        viewModel.refreshBaseline()
                    }
                }
            }
            .task {
                if viewModel.capabilityResults.isEmpty {
                    viewModel.refreshBaseline()
                }
            }
            .alert("Run strict-folder canary?", isPresented: $showCanaryConfirmation) {
                Button("Cancel", role: .cancel) { }
                Button("Run", role: .destructive) {
                    viewModel.runCanaryWrite()
                }
            } message: {
                Text("A unique file will be created only if access is available, then immediately deleted. Existing files are never modified.")
            }
            .fileImporter(
                isPresented: $showDiagnosticImporter,
                allowedContentTypes: [.item],
                allowsMultipleSelection: false
            ) { result in
                if case .success(let urls) = result, let url = urls.first {
                    viewModel.importDiagnostic(from: url)
                }
            }
        }
    }

    private var targetSection: some View {
        Section("Runtime target") {
            LabeledContent("Hardware", value: viewModel.profile.hardwareIdentifier)
            LabeledContent("iOS", value: viewModel.profile.systemVersion)
            LabeledContent("Build", value: viewModel.profile.buildVersion)
            Label("Differential research build", systemImage: "waveform.path.ecg.rectangle.fill")
                .font(.headline)
                .foregroundStyle(.blue)
            LabeledContent(
                "App version",
                value: "\(buildIdentity.version) (\(buildIdentity.build))"
            )
            LabeledContent(
                "Source",
                value: String(buildIdentity.sourceRevision.prefix(12))
            )
            Text(buildIdentity.bundleIdentifier)
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
            Text("No device model or beta build is hard-coded. Capabilities are measured at runtime.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private var runtimeCapabilitySection: some View {
        Section("Observed capabilities") {
            CapabilityRow(
                label: "Curated Gestalt reads",
                enabled: viewModel.runtimeCapabilities.publicGestaltRead
            )
            CapabilityRow(
                label: "Sandbox policy API",
                enabled: viewModel.runtimeCapabilities.sandboxPolicyAPI
            )
            CapabilityRow(
                label: "App-container write",
                enabled: viewModel.runtimeCapabilities.appContainerWrite
            )
            CapabilityRow(
                label: "Policy permits protected read",
                enabled: viewModel.runtimeCapabilities.protectedDataPolicyAllowed
            )
            CapabilityRow(
                label: "Policy permits protected write",
                enabled: viewModel.runtimeCapabilities.protectedWritePolicyAllowed
            )
            LabeledContent(
                "Reachable Mach services",
                value: String(viewModel.runtimeCapabilities.reachableMachServices)
            )
        }
    }

    private var primitiveSection: some View {
        Section("Privileged primitive") {
            LabeledContent("Status", value: viewModel.primitiveSummary)
            Text("This build does not claim a sandbox escape, kernel read/write, PPL bypass, or code-signing bypass.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private var experimentSection: some View {
        Section("Repeatable experiment") {
            Picker("Experiment", selection: $viewModel.selectedExperiment) {
                ForEach(ResearchExperiment.allCases) { experiment in
                    Text(experiment.title).tag(experiment)
                }
            }
            Text(viewModel.selectedExperiment.detail)
                .font(.footnote)
                .foregroundStyle(.secondary)
            Button {
                viewModel.runSelectedExperiment()
            } label: {
                if viewModel.isExperimentRunning {
                    ProgressView()
                } else {
                    Label("Run experiment", systemImage: "play.fill")
                }
            }
            .disabled(viewModel.isExperimentRunning)

            ForEach(viewModel.experimentRecords.prefix(3)) { record in
                VStack(alignment: .leading, spacing: 2) {
                    Text(record.experiment.title)
                        .font(.caption.weight(.semibold))
                    Text(record.summary)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var gestaltSection: some View {
        Section("Read-only MobileGestalt baseline") {
            ForEach(viewModel.gestaltValues) { item in
                LabeledContent(item.key, value: item.value)
            }
        }
    }

    private var filesystemSection: some View {
        Section("Strict-folder capability probes") {
            ForEach(viewModel.capabilityResults) { result in
                VStack(alignment: .leading, spacing: 5) {
                    Text(result.path)
                        .font(.caption.monospaced())
                    HStack {
                        CapabilityBadge(label: "read", enabled: result.readable)
                        CapabilityBadge(
                            label: "write metadata",
                            enabled: result.writableAccordingToMetadata
                        )
                    }
                    if let error = result.errorDescription {
                        Text(error)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(3)
                    }
                }
                .padding(.vertical, 3)
            }
        }
    }

    private var sandboxPolicySection: some View {
        Section("Sandbox policy inventory") {
            let available = viewModel.sandboxPolicyResults.filter(\.apiAvailable)
            let allowed = available.filter(\.allowed)

            LabeledContent("Checks", value: String(available.count))
            LabeledContent("Allowed", value: String(allowed.count))

            if allowed.isEmpty {
                Text("No candidate protected-path or Mach-service operation was allowed.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(allowed) { result in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(result.operation)
                            .font(.caption.weight(.semibold))
                        Text(result.subject)
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var machServiceSection: some View {
        Section("Mach service resolution") {
            ForEach(viewModel.machServiceResults) { result in
                HStack {
                    Image(systemName: result.reachable
                        ? "checkmark.circle.fill"
                        : "xmark.circle")
                        .foregroundStyle(result.reachable ? .orange : .secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(result.service)
                            .font(.caption.monospaced())
                        if let candidate = ServiceResearchCatalog.candidate(
                            for: result.service
                        ) {
                            Text("\(candidate.subsystem) • \(candidate.confidence.rawValue)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Text(result.reachable
                            ? "Resolved"
                            : "Lookup error \(result.rawResult)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var firmwareFocusSection: some View {
        Section("Beta 3 firmware focus") {
            Text("Public device-class diff: iPhone18,1, 24A5370h → 24A5380h. Runtime lookup results below are measured on this device.")
                .font(.footnote)
                .foregroundStyle(.secondary)

            ForEach(ServiceResearchCatalog.findings) { finding in
                DisclosureGroup {
                    Text(finding.significance)
                        .font(.caption)
                    ForEach(finding.services, id: \.self) { service in
                        HStack {
                            Image(systemName: serviceResolved(service)
                                ? "checkmark.circle.fill"
                                : "circle")
                                .foregroundStyle(serviceResolved(service)
                                    ? .orange
                                    : .secondary)
                            Text(service)
                                .font(.caption2.monospaced())
                        }
                    }
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(finding.title)
                        Text(finding.buildDelta)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private func serviceResolved(_ service: String) -> Bool {
        viewModel.machServiceResults.first {
            $0.service == service
        }?.reachable ?? false
    }

    private var xpcConnectionSection: some View {
        Section("Mach port lifecycle") {
            if viewModel.machConnectionResults.isEmpty {
                Text("Refresh inspects and releases service ports that resolve through bootstrap.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.machConnectionResults) { result in
                    HStack {
                        Image(systemName: result.resolved
                            ? "checkmark.circle.fill"
                            : "exclamationmark.circle")
                            .foregroundStyle(result.resolved ? .orange : .secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(result.service)
                                .font(.caption.monospaced())
                            Text(connectionStatus(for: result))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    private func connectionStatus(for result: MachServiceConnectionResult) -> String {
        if result.resolved {
            return "type \(result.portType) • send refs \(result.sendRightRefs) • released"
        }
        return "Lookup error \(result.lookupResult)"
    }

    private var canarySection: some View {
        Section {
            Picker("Target", selection: $viewModel.selectedCanaryTarget) {
                ForEach(viewModel.canaryTargets, id: \.self) { path in
                    Text(path).tag(path)
                }
            }

            Toggle("Arm one-shot canary", isOn: $viewModel.isWriteTestingArmed)
                .tint(.red)

            Button("Run canary write", role: .destructive) {
                showCanaryConfirmation = true
            }
            .disabled(
                !viewModel.isWriteTestingArmed
            )
        } header: {
            Text("Controlled write validation")
        } footer: {
            Text("The stock sandbox should deny this. A successful create-and-delete proves only filesystem access to the selected directory, not a jailbreak.")
        }
    }

    private var snapshotSection: some View {
        Section("Snapshot comparison") {
            Button {
                viewModel.saveSnapshot()
            } label: {
                Label("Save and compare snapshot", systemImage: "arrow.triangle.2.circlepath")
            }

            if let url = viewModel.snapshotURL {
                ShareLink(item: url) {
                    Label("Export latest snapshot", systemImage: "square.and.arrow.up")
                }
            }

            if viewModel.snapshotDifferences.isEmpty {
                Text("Save a baseline, then save again after an OS update or controlled experiment.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                LabeledContent("Changed fields", value: String(viewModel.snapshotDifferences.count))
                ForEach(viewModel.snapshotDifferences.prefix(12)) { difference in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(difference.key)
                            .font(.caption.monospaced())
                        Text("\(difference.previousValue) → \(difference.currentValue)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(3)
                    }
                }
            }
        }
    }

    private var diagnosticSection: some View {
        Section("Diagnostic correlation") {
            Button {
                showDiagnosticImporter = true
            } label: {
                Label("Import crash report or diagnostic", systemImage: "doc.badge.plus")
            }
            Text("The app hashes the complete selected file and counts security-relevant markers in only its first 4 MB. It does not upload the file.")
                .font(.footnote)
                .foregroundStyle(.secondary)

            ForEach(viewModel.importedDiagnostics.prefix(5)) { diagnostic in
                VStack(alignment: .leading, spacing: 3) {
                    Text(diagnostic.fileName)
                        .font(.caption.weight(.semibold))
                    Text("\(diagnostic.byteCount) bytes • \(diagnostic.signalCounts.values.reduce(0, +)) markers")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text(diagnostic.sha256)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
        }
    }

    private var logSection: some View {
        Section("Research log") {
            ShareLink(item: viewModel.logger.logURL) {
                Label("Export JSONL log", systemImage: "square.and.arrow.up")
            }

            ForEach(viewModel.logger.events.prefix(12)) { event in
                VStack(alignment: .leading, spacing: 3) {
                    Text(event.message)
                    Text("\(event.subsystem) • \(event.timestamp.formatted())")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

private struct CapabilityBadge: View {
    let label: String
    let enabled: Bool

    var body: some View {
        Text("\(enabled ? "✓" : "×") \(label)")
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 4)
            .background(enabled ? Color.green.opacity(0.18) : Color.secondary.opacity(0.15))
            .clipShape(Capsule())
    }
}

private struct CapabilityRow: View {
    let label: String
    let enabled: Bool

    var body: some View {
        Label(label, systemImage: enabled ? "checkmark.circle.fill" : "xmark.circle")
            .foregroundStyle(enabled ? .green : .secondary)
    }
}
