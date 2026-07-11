import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var viewModel: ResearchViewModel
    @State private var showCanaryConfirmation = false

    var body: some View {
        NavigationStack {
            List {
                targetSection
                primitiveSection
                gestaltSection
                filesystemSection
                canarySection
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
        }
    }

    private var targetSection: some View {
        Section("Authorized target") {
            LabeledContent("Hardware", value: viewModel.profile.hardwareIdentifier)
            LabeledContent("iOS", value: viewModel.profile.systemVersion)
            LabeledContent("Build", value: viewModel.profile.buildVersion)
            Label(
                viewModel.profile.isAuthorizedTarget
                    ? "iPhone 16 / iOS 27 target matched"
                    : "Target mismatch — mutations blocked",
                systemImage: viewModel.profile.isAuthorizedTarget
                    ? "checkmark.shield.fill"
                    : "exclamationmark.triangle.fill"
            )
            .foregroundStyle(viewModel.profile.isAuthorizedTarget ? .green : .orange)
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
                !viewModel.profile.isAuthorizedTarget ||
                !viewModel.isWriteTestingArmed
            )
        } header: {
            Text("Controlled write validation")
        } footer: {
            Text("The stock sandbox should deny this. A successful create-and-delete proves only filesystem access to the selected directory, not a jailbreak.")
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
