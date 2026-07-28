import SwiftUI
import UniformTypeIdentifiers

struct CrashTriageView: View {
    let profile: DeviceProfile
    let logger: AuditLogger

    @StateObject private var viewModel = CrashTriageViewModel()
    @State private var showingCorpusImporter = false
    @State private var showingCrashLogImporter = false
    @State private var showingRunConfirmation = false

    var body: some View {
        List {
            scopeSection
            recoveredSection
            corpusSection
            campaignSection
            minimizationSection
            findingsSection
            recentCasesSection
            exportSection

            if let error = viewModel.lastError {
                Section("Last error") {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Crash Triage")
        .alert("Run parser campaign?", isPresented: $showingRunConfirmation) {
            Button("Cancel", role: .cancel) { }
            Button("Run") {
                viewModel.run(profile: profile, logger: logger)
            }
        } message: {
            Text("Each mutated input is written and journaled before ImageIO or an archive parser receives it. A malformed case can terminate Aegis. Only imported corpus bytes inside Aegis are used.")
        }
        .fileImporter(
            isPresented: $showingCorpusImporter,
            allowedContentTypes: [.data, .image],
            allowsMultipleSelection: false
        ) { result in
            guard case .success(let urls) = result, let url = urls.first else { return }
            viewModel.importCorpus(from: url)
        }
        .fileImporter(
            isPresented: $showingCrashLogImporter,
            allowedContentTypes: [.data, .plainText, .json],
            allowsMultipleSelection: false
        ) { result in
            guard case .success(let urls) = result, let url = urls.first else { return }
            viewModel.importCrashLog(from: url, logger: logger)
        }
        .task {
            viewModel.refresh()
        }
    }

    private var scopeSection: some View {
        Section("Research scope") {
            Label("Aegis-owned corpus only", systemImage: "shippingbox.fill")
                .foregroundStyle(.green)
            Text(profile.targetDescription)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
            Text("A parser rejection is normal. A pending journal plus a matching .ips log is treated as a crash candidate. Only imported crash evidence can classify a memory-corruption signal or a system-service termination.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var recoveredSection: some View {
        if let pending = viewModel.pendingCase {
            Section("Recovered unfinished case") {
                Label(
                    pending.minimizationSessionID == nil ? "Campaign case did not finish" : "Minimization candidate did not finish",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .foregroundStyle(.orange)
                LabeledContent("Parser", value: pending.parser.title)
                LabeledContent("Case", value: String(pending.caseIndex))
                LabeledContent("Seed", value: String(pending.seed))
                LabeledContent("Bytes", value: pending.inputByteCount.formatted())
                Text(pending.inputSHA256)
                    .font(.caption2.monospaced())
                    .textSelection(.enabled)

                Button {
                    showingCrashLogImporter = true
                } label: {
                    Label("Import matching .ips or panic log", systemImage: "doc.badge.plus")
                }

                if pending.minimizationSessionID == nil {
                    Button("Confirm crash candidate and prepare minimization") {
                        viewModel.startMinimization()
                    }
                    Text("Prepare minimization only after reproducing the same termination and importing the related crash log. An unfinished journal can also result from force-quitting the app.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Button("Candidate reproduced the crash") {
                        viewModel.resumeMinimization(
                            assumingPendingCandidateCrashed: true,
                            profile: profile,
                            logger: logger
                        )
                    }
                    Button("Candidate survived or Aegis was closed") {
                        viewModel.resumeMinimization(
                            assumingPendingCandidateCrashed: false,
                            profile: profile,
                            logger: logger
                        )
                    }
                    Text("The first choice keeps the smaller candidate. The second rejects it and continues testing other deletion ranges.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Button("Discard as unconfirmed", role: .destructive) {
                    viewModel.discardPending()
                }
            }
        }
    }

    private var corpusSection: some View {
        Section("Corpus") {
            Button {
                showingCorpusImporter = true
            } label: {
                Label("Import corpus file", systemImage: "square.and.arrow.down")
            }

            if viewModel.corpus.isEmpty {
                Text("No corpus files imported.")
                    .foregroundStyle(.secondary)
            }

            ForEach(viewModel.corpus) { item in
                Button {
                    viewModel.selectCorpus(item)
                } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(item.originalFileName)
                                .foregroundStyle(.primary)
                            Text("\(item.byteCount.formatted()) bytes • \(item.suggestedParser.title)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(String(item.sha256.prefix(20)))
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if viewModel.selectedCorpus?.id == item.id {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        }
                    }
                }
                .swipeActions {
                    Button("Delete", role: .destructive) {
                        viewModel.deleteCorpus(item)
                    }
                }
            }
        }
    }

    private var campaignSection: some View {
        Section("Deterministic campaign") {
            Picker("Parser", selection: $viewModel.parser) {
                ForEach(CrashTriageParser.allCases) { parser in
                    Text(parser.title).tag(parser)
                }
            }
            Stepper(
                "Cases: \(viewModel.iterations)",
                value: $viewModel.iterations,
                in: 1...300,
                step: 10
            )
            TextField("Seed", value: $viewModel.seed, format: .number)
                .keyboardType(.numberPad)

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
                    showingRunConfirmation = true
                } label: {
                    Label("Start crash-triage campaign", systemImage: "waveform.path.ecg.rectangle")
                }
                .disabled(viewModel.selectedCorpus == nil || viewModel.pendingCase != nil)
            }

            Text(viewModel.statusMessage)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var minimizationSection: some View {
        if let minimization = viewModel.minimization {
            Section("Restart-aware minimizer") {
                LabeledContent("Status", value: minimization.status.rawValue)
                LabeledContent(
                    "Best size",
                    value: "\(minimization.originalByteCount.formatted()) → \(minimization.currentByteCount.formatted())"
                )
                LabeledContent(
                    "Reduction",
                    value: String(format: "%.1f%%", minimization.reductionPercent)
                )
                LabeledContent("Attempts", value: minimization.attempts.formatted())
                LabeledContent("Crash reproductions", value: minimization.reproducedCount.formatted())
                LabeledContent("Current chunk", value: minimization.chunkSize.formatted())

                if viewModel.pendingCase == nil && minimization.status != .completed {
                    Button {
                        viewModel.resumeMinimization(
                            assumingPendingCandidateCrashed: false,
                            profile: profile,
                            logger: logger
                        )
                    } label: {
                        Label("Run or resume minimization", systemImage: "scissors")
                    }
                    .disabled(viewModel.isMinimizing)
                }

                if viewModel.isMinimizing {
                    ProgressView()
                    Button("Pause after current candidate", role: .destructive) {
                        viewModel.stop()
                    }
                }

                if let minimizedURL = viewModel.minimizedURL {
                    ShareLink(item: minimizedURL) {
                        Label("Export best testcase", systemImage: "square.and.arrow.up")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var findingsSection: some View {
        if !viewModel.findings.isEmpty {
            Section("Deduplicated crash findings") {
                ForEach(viewModel.findings) { finding in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(finding.classification.title)
                                .font(.subheadline.weight(.semibold))
                            Spacer()
                            Text("×\(finding.occurrences)")
                                .font(.caption.weight(.semibold))
                        }
                        Text(finding.processName)
                            .font(.caption)
                        Text(finding.exceptionType)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(String(finding.signature.prefix(24)))
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var recentCasesSection: some View {
        if !viewModel.recentCases.isEmpty {
            Section("Recent parser cases") {
                ForEach(viewModel.recentCases.prefix(40)) { result in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text("#\(result.caseIndex) \(result.parser.title)")
                                .font(.caption.weight(.semibold))
                            Spacer()
                            Text(result.outcome.title)
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(result.outcome.isInteresting ? .orange : .secondary)
                        }
                        Text("seed \(result.seed) • \(result.inputByteCount.formatted()) bytes • \(String(format: "%.1f", result.elapsedMilliseconds)) ms")
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                        Text(String(result.inputSHA256.prefix(24)))
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                        Button("Replay exact seed") {
                            viewModel.replay(result, profile: profile, logger: logger)
                        }
                        .font(.caption)
                        .disabled(viewModel.pendingCase != nil || viewModel.isRunning || viewModel.isMinimizing)
                    }
                }
            }
        }
    }

    private var exportSection: some View {
        Section("Export") {
            Button {
                viewModel.export()
            } label: {
                Label("Refresh triage snapshot", systemImage: "arrow.clockwise")
            }
            if let exportURL = viewModel.exportURL {
                ShareLink(item: exportURL) {
                    Label("Export crash-triage-latest.json", systemImage: "square.and.arrow.up")
                }
            }
        }
    }
}
