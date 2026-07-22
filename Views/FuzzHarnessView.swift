import SwiftUI

struct FuzzHarnessView: View {
    let catalog: FirmwareProbeCatalog
    let profile: DeviceProfile
    let logger: AuditLogger

    @StateObject private var viewModel = FuzzHarnessViewModel()
    @State private var showRunConfirmation = false

    var body: some View {
        List {
            recoverySection
            configurationSection
            executionSection
            resultSection
            recentCasesSection
            if let error = viewModel.lastError {
                Section("Last error") {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Fuzzer Harness")
        .alert("Run real fuzz campaign?", isPresented: $showRunConfirmation) {
            Button("Cancel", role: .cancel) { }
            Button("Run", role: .destructive) {
                viewModel.run(catalog: catalog, profile: profile, logger: logger)
            }
        } message: {
            Text("This executes malformed parser inputs, destructive mutations inside Aegis's generated corpus, and imported typed XPC requests. It can crash Aegis, crash a reachable service, or reboot the device. Every case is journaled before execution.")
        }
    }

    private var recoverySection: some View {
        Section("Crash recovery") {
            if let pending = viewModel.pendingRecovery {
                Label("Unfinished case recovered", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                LabeledContent("Campaign", value: pending.kind.title)
                LabeledContent("Case", value: String(pending.caseIndex))
                LabeledContent("Seed", value: String(pending.caseSeed))
                Button("Load exact recovered seed") {
                    viewModel.useRecoveredCase()
                }
            } else {
                Label("No unfinished case", systemImage: "checkmark.circle")
                    .foregroundStyle(.secondary)
            }
            Text("An unfinished journal means the app stopped after the case began but before it completed. Re-run the exact seed, then import the related .ips or panic log for correlation.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private var configurationSection: some View {
        Section("Campaign configuration") {
            Picker("Intensity", selection: $viewModel.intensity) {
                ForEach(FuzzIntensity.allCases) { intensity in
                    Text(intensity.title).tag(intensity)
                }
            }
            Stepper("Cases: \(viewModel.iterations)", value: $viewModel.iterations, in: 1...300, step: 10)
            TextField("Seed", value: $viewModel.seed, format: .number)
                .keyboardType(.numberPad)

            Toggle("Parser mutation", isOn: $viewModel.parserEnabled)
            Toggle("Sandbox file mutation", isOn: $viewModel.sandboxFileEnabled)
            Toggle("XPC schema mutation", isOn: $viewModel.xpcEnabled)
                .disabled(catalog.services.isEmpty)

            if catalog.services.isEmpty {
                Text("Import a firmware probe catalog on the Attack Surface screen to enable typed XPC mutation.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                LabeledContent("Imported XPC schemas", value: String(catalog.services.flatMap(\.requests).count))
            }

            if viewModel.sandboxFileEnabled {
                Toggle(
                    "Arm destructive Aegis-corpus mutations",
                    isOn: $viewModel.allowDestructiveSandboxMutations
                )
                .tint(.red)
                Text("Only Aegis-generated files under its own Caches container are corrupted, renamed, truncated, raced, and deleted.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var executionSection: some View {
        Section("Execution") {
            if viewModel.isRunning {
                ProgressView(
                    value: Double(viewModel.completedCases),
                    total: Double(max(1, viewModel.totalCases))
                )
                LabeledContent(
                    "Progress",
                    value: "\(viewModel.completedCases) / \(viewModel.totalCases)"
                )
                Button("Stop after current case", role: .destructive) {
                    viewModel.stop()
                }
            } else {
                Button {
                    showRunConfirmation = true
                } label: {
                    Label("Start fuzz campaign", systemImage: "bolt.shield.fill")
                }
            }
        }
    }

    @ViewBuilder
    private var resultSection: some View {
        if let report = viewModel.report {
            Section("Latest report") {
                LabeledContent("Executed", value: String(report.results.count))
                LabeledContent("Anomalies", value: String(report.anomalousResults.count))
                LabeledContent("Differential XPC leads", value: String(report.interestingCount))
                LabeledContent("Timeouts", value: String(report.timeoutCount))
                LabeledContent("Cancelled", value: String(report.cancelled))
                if let recovered = report.recoveredIncompleteCase {
                    Label(
                        "Recovered prior \(recovered.kind.title) case \(recovered.caseIndex)",
                        systemImage: "arrow.counterclockwise.circle"
                    )
                    .font(.caption)
                    .foregroundStyle(.orange)
                }
                if let url = viewModel.exportURL {
                    ShareLink(item: url) {
                        Label("Export fuzz report", systemImage: "square.and.arrow.up")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var recentCasesSection: some View {
        if !viewModel.recentResults.isEmpty {
            Section("Recent cases") {
                ForEach(viewModel.recentResults) { result in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text("#\(result.caseIndex) \(result.label)")
                                .font(.caption.weight(.semibold))
                            Spacer()
                            Text(result.outcome.title)
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(result.outcome.isAnomalous ? .orange : .secondary)
                        }
                        Text("\(result.kind.title) • seed \(result.caseSeed) • \(String(format: "%.1f", result.elapsedMilliseconds)) ms")
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                        Text("fingerprint \(result.inputFingerprint)")
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}
