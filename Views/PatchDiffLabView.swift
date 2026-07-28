import SwiftUI

struct PatchDiffLabView: View {
    let profile: DeviceProfile
    let logger: AuditLogger

    @StateObject private var viewModel: PatchDiffViewModel
    @ObservedObject private var bridge = GitHubRunnerBridge.shared

    init(profile: DeviceProfile, logger: AuditLogger) {
        self.profile = profile
        self.logger = logger
        _viewModel = StateObject(wrappedValue: PatchDiffViewModel(profile: profile))
    }

    var body: some View {
        Form {
            Section("What this does") {
                Label("Real static firmware comparison", systemImage: "checkmark.shield.fill")
                    .foregroundStyle(.green)
                Text("The cloud runner downloads two exact Apple IPSWs and compares firmware, services, entitlements, feature flags, sandbox profiles, function starts, strings, and optionally the filesystem. It ranks changed components for regression research; it does not call a static difference a vulnerability.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Section("Exact builds") {
                LabeledContent("Device", value: profile.hardwareIdentifier)
                LabeledContent("Installed build", value: profile.buildVersion)
                TextField("Base build, for example 24A5378a", text: $viewModel.baseBuild)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                TextField("Target build", text: $viewModel.targetBuild)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                Text("Use two builds for the same hardware identifier. Adjacent builds produce the most useful patch signal.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Static diff surfaces") {
                ForEach(PatchDiffSurface.allCases) { surface in
                    Toggle(isOn: Binding(
                        get: { viewModel.selectedSurfaces.contains(surface) },
                        set: { viewModel.set(surface, enabled: $0) }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(surface.title)
                            Text(surface.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                Stepper(
                    "Maximum ranked candidates: \(viewModel.maximumCandidates)",
                    value: $viewModel.maximumCandidates,
                    in: 10...200,
                    step: 10
                )
            }

            Section("Runner") {
                Label(
                    bridge.isConnected ? "Runner connected" : "Runner not connected",
                    systemImage: bridge.isConnected ? "checkmark.icloud.fill" : "icloud.slash"
                )
                .foregroundStyle(bridge.isConnected ? .green : .secondary)

                Text(bridge.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Button {
                    Task { await viewModel.submit(profile: profile, logger: logger) }
                } label: {
                    if viewModel.isSubmitting || bridge.isWorking {
                        ProgressView()
                    } else {
                        Label("Run exact IPSW patch diff", systemImage: "arrow.left.arrow.right.square")
                    }
                }
                .disabled(
                    !bridge.isConnected ||
                    bridge.isWorking ||
                    viewModel.baseBuild.isEmpty ||
                    viewModel.targetBuild.isEmpty ||
                    viewModel.selectedSurfaces.isEmpty
                )

                Button("Check for finished report") {
                    Task { await viewModel.refresh(logger: logger) }
                }
                .disabled(!bridge.isConnected || bridge.isWorking)

                Text(viewModel.message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                if let url = viewModel.requestURL {
                    ShareLink(item: url) {
                        Label("Export submitted request", systemImage: "square.and.arrow.up")
                    }
                }
                if let url = bridge.lastResultURL, viewModel.report != nil {
                    ShareLink(item: url) {
                        Label("Export compact patch-diff report", systemImage: "doc.text.magnifyingglass")
                    }
                }
            }

            if let report = viewModel.report {
                Section("Latest comparison") {
                    LabeledContent("Builds", value: "\(report.request.baseBuild) → \(report.request.targetBuild)")
                    LabeledContent("Candidates", value: String(report.summary.candidateCount))
                    LabeledContent("Raw artifacts", value: String(report.summary.artifactFiles))
                    LabeledContent("ipsw", value: report.tool.ipswVersion)
                    Text("Static review only. A candidate becomes meaningful only after a reproducible test affects an Apple process on the exact device build.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Highest-ranked changes") {
                    ForEach(report.candidates.prefix(30)) { candidate in
                        VStack(alignment: .leading, spacing: 5) {
                            HStack(alignment: .firstTextBaseline) {
                                Text("#\(candidate.rank) \(candidate.subject)")
                                    .font(.caption.weight(.semibold))
                                Spacer()
                                Text(String(candidate.score))
                                    .font(.caption2.monospacedDigit())
                            }
                            Text(candidate.category)
                                .font(.caption2.weight(.medium))
                                .foregroundStyle(.orange)
                            if let evidence = candidate.evidence.first {
                                Text(evidence)
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.secondary)
                                    .lineLimit(4)
                            }
                            Text(candidate.regressionFocus)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 3)
                    }
                }

                Section("Limitations") {
                    ForEach(report.limitations, id: \.self) { limitation in
                        Text(limitation)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if let error = viewModel.lastError {
                Section("Error") {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("IPSW Patch Diff")
        .task { await viewModel.refresh(logger: logger) }
        .onChange(of: bridge.lastResultURL) { _, _ in
            viewModel.loadLatestResultIfAvailable()
        }
    }
}
