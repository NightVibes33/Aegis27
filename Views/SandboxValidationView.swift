import SwiftUI

struct SandboxValidationView: View {
    @EnvironmentObject private var researchViewModel: ResearchViewModel
    @StateObject private var viewModel = SandboxValidationViewModel()

    var body: some View {
        NavigationStack {
            List {
                Section("Validation mode") {
                    Picker("Provider", selection: Binding(
                        get: { viewModel.selectedProvider },
                        set: { viewModel.switchProvider(to: $0) }
                    )) {
                        ForEach(FileProviderKind.allCases) { provider in
                            Text(provider.title).tag(provider)
                        }
                    }

                    Text("A pass requires actual protected file data or a foreign application-container listing. Metadata alone does not count.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)

                    Button {
                        runValidation()
                    } label: {
                        if viewModel.isRunning {
                            ProgressView()
                        } else {
                            Label("Run access check", systemImage: "checkmark.shield")
                        }
                    }
                    .disabled(viewModel.isRunning)
                }

                if let report = viewModel.report {
                    Section("Result") {
                        Label(
                            report.accessConfirmed
                                ? "Protected access confirmed"
                                : "Protected access not confirmed",
                            systemImage: report.accessConfirmed
                                ? "checkmark.shield.fill"
                                : "lock.shield.fill"
                        )
                        .font(.headline)
                        .foregroundStyle(report.accessConfirmed ? .green : .secondary)

                        LabeledContent("Checks passed", value: "\(report.passedCount) of \(report.checks.count)")
                        LabeledContent("Foreign containers", value: String(report.foreignContainerCount))
                    }

                    Section("Checks") {
                        ForEach(report.checks) { check in
                            VStack(alignment: .leading, spacing: 6) {
                                Label(check.label, systemImage: icon(for: check.status))
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(color(for: check.status))
                                Text(check.path)
                                    .font(.caption2.monospaced())
                                    .textSelection(.enabled)
                                Text("\(check.status.title) • \(check.detail)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .padding(.vertical, 3)
                        }
                    }
                } else {
                    Section("Targets") {
                        targetRow(
                            "SpringBoard preferences",
                            SandboxValidationService.springBoardPreferences,
                            "Read up to 4 KiB"
                        )
                        targetRow(
                            "Application containers",
                            SandboxValidationService.applicationContainers,
                            "List and detect foreign containers"
                        )
                    }
                }
            }
            .navigationTitle("Access Check")
        }
    }

    private func targetRow(
        _ label: String,
        _ path: String,
        _ operation: String
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.subheadline.weight(.semibold))
            Text(path).font(.caption2.monospaced()).textSelection(.enabled)
            Text(operation).font(.caption).foregroundStyle(.secondary)
        }
    }

    private func runValidation() {
        viewModel.run()
        guard let report = viewModel.report else { return }

        researchViewModel.logger.record(ResearchEvent(
            severity: report.accessConfirmed ? .success : .info,
            subsystem: "sandbox-validation",
            message: report.accessConfirmed
                ? "Protected filesystem access confirmed"
                : "Protected filesystem access not confirmed",
            details: [
                "provider": report.provider.rawValue,
                "passed": String(report.passedCount),
                "checks": String(report.checks.count),
                "foreignContainers": String(report.foreignContainerCount)
            ]
        ))

        for check in report.checks {
            researchViewModel.logger.record(ResearchEvent(
                severity: check.status == .passed ? .success : .info,
                subsystem: "sandbox-validation-check",
                message: "\(check.label): \(check.status.title)",
                details: [
                    "provider": report.provider.rawValue,
                    "path": check.path,
                    "operation": check.operation,
                    "status": check.status.rawValue,
                    "detail": check.detail
                ]
            ))
        }
        if let exportURL = viewModel.exportURL {
            Task {
                await GitHubRunnerBridge.shared.submitIfConnected(
                    fileURL: exportURL,
                    kind: "sandbox-validation",
                    profile: researchViewModel.profile,
                    logger: researchViewModel.logger
                )
            }
        }
    }

    private func icon(for status: SandboxValidationStatus) -> String {
        switch status {
        case .passed: return "checkmark.circle.fill"
        case .denied: return "lock.circle.fill"
        case .missing: return "questionmark.circle"
        case .unavailable: return "nosign"
        case .inconclusive: return "minus.circle"
        }
    }

    private func color(for status: SandboxValidationStatus) -> Color {
        status == .passed ? .green : .secondary
    }
}
