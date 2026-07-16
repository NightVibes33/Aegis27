import SwiftUI

struct AttackSurfaceView: View {
    @EnvironmentObject private var researchViewModel: ResearchViewModel
    @StateObject private var viewModel = AttackSurfaceViewModel()
    @State private var showConfirmation = false

    var body: some View {
        List {
            Section("Bounded protocol probes") {
                Text("Sends one empty XPC dictionary to each service that already resolves, waits up to 750 ms, then repeats reachability and protected-access checks. No service-specific commands or file paths are sent.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                Button {
                    showConfirmation = true
                } label: {
                    if viewModel.isRunning {
                        ProgressView()
                    } else {
                        Label("Run attack-surface probe", systemImage: "scope")
                    }
                }
                .disabled(viewModel.isRunning)
            }

            if let report = viewModel.report {
                Section("Result") {
                    Label(
                        resultTitle(report),
                        systemImage: report.protectedAccessConfirmed
                            ? "exclamationmark.shield.fill"
                            : "lock.shield.fill"
                    )
                    .font(.headline)
                    .foregroundStyle(report.protectedAccessConfirmed ? .red : .secondary)
                    LabeledContent("Services probed", value: String(report.probedCount))
                    LabeledContent("Protocol anomalies", value: String(report.anomalyCount))
                    LabeledContent(
                        "Protected checks passed",
                        value: "\(report.validation.passedCount) of \(report.validation.checks.count)"
                    )
                    if let url = viewModel.exportURL {
                        ShareLink(item: url) {
                            Label("Export compact report", systemImage: "square.and.arrow.up")
                        }
                    }
                }

                Section("Reachable service responses") {
                    ForEach(report.serviceResults.filter(\.wasProbed)) { result in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: result.anomalous
                                    ? "exclamationmark.triangle.fill"
                                    : "checkmark.circle")
                                    .foregroundStyle(result.anomalous ? .orange : .secondary)
                                Text(result.service)
                                    .font(.caption.monospaced())
                            }
                            Text("\(result.subsystem) • \(result.disposition?.title ?? "Not run") • \(formatted(result.elapsedMilliseconds)) ms")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            if result.reachabilityChanged {
                                Text("Reachability changed: \(result.lookupBefore) → \(result.lookupAfter)")
                                    .font(.caption2.weight(.semibold))
                                    .foregroundStyle(.orange)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }

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
        }
        .navigationTitle("Attack Surface")
        .alert("Run bounded XPC probes?", isPresented: $showConfirmation) {
            Button("Cancel", role: .cancel) { }
            Button("Run") {
                viewModel.run(logger: researchViewModel.logger)
            }
        } message: {
            Text("One empty dictionary is sent only to services already reachable from this app. A reply is a lead for further analysis, not proof of an escape.")
        }
    }

    private func resultTitle(_ report: AttackSurfaceReport) -> String {
        if report.protectedAccessConfirmed { return "Protected access changed" }
        if report.anomalyCount > 0 { return "Protocol leads found; no access change" }
        return "No access change detected"
    }

    private func formatted(_ value: Double?) -> String {
        String(format: "%.1f", value ?? 0)
    }
}
