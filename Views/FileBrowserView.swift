import SwiftUI

struct FileBrowserView: View {
    @EnvironmentObject private var researchViewModel: ResearchViewModel
    @StateObject private var viewModel = FileBrowserViewModel()

    var body: some View {
        NavigationStack {
            List {
                providerSection
                pathSection
                capabilitySection
                targetSection
                directorySection
                previewSection
            }
            .navigationTitle("File research")
            .searchable(text: $viewModel.searchText, prompt: "Filter current directory")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        refreshDirectory()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
            .task {
                if viewModel.capabilityReport == nil {
                    refreshDirectory()
                    validateProvider()
                    inventoryTargets()
                }
            }
        }
    }

    private var providerSection: some View {
        Section("File access provider") {
            Picker("Provider", selection: Binding(
                get: { viewModel.selectedProvider },
                set: { switchProvider(to: $0) }
            )) {
                ForEach(FileProviderKind.allCases) { provider in
                    Text(provider.title).tag(provider)
                }
            }
            Label(
                viewModel.provider.availabilitySummary,
                systemImage: viewModel.provider.isAvailable
                    ? "checkmark.shield.fill"
                    : "lock.shield.fill"
            )
            .font(.footnote)
            .foregroundStyle(viewModel.provider.isAvailable ? .green : .secondary)
        }
    }

    private var pathSection: some View {
        Section("Path") {
            TextField("Absolute path", text: $viewModel.pathInput)
                .font(.caption.monospaced())
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .onSubmit { navigateToInput() }
            HStack {
                Button("Up", systemImage: "arrow.up") {
                    viewModel.navigateToParent()
                    recordDirectoryResult()
                }
                Spacer()
                Button("Go", systemImage: "arrow.right.circle.fill") {
                    navigateToInput()
                }
            }
            if let error = viewModel.listingError {
                Text(error)
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .lineLimit(4)
            }
        }
    }

    private var capabilitySection: some View {
        Section("Provider validation") {
            Button("Run capability validation", systemImage: "checklist") {
                validateProvider()
            }
            if let report = viewModel.capabilityReport {
                LabeledContent(
                    "Passed",
                    value: "\(report.passedCount) of \(report.checks.count)"
                )
                ForEach(report.checks) { check in
                    VStack(alignment: .leading, spacing: 2) {
                        Label(
                            check.label,
                            systemImage: check.succeeded
                                ? "checkmark.circle.fill"
                                : "xmark.circle"
                        )
                        .foregroundStyle(check.succeeded ? .green : .secondary)
                        Text("\(check.operation) • \(check.path)")
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                        if !check.succeeded {
                            Text(check.detail)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                        }
                    }
                }
            }
        }
    }

    private var targetSection: some View {
        Section {
            Toggle(
                "Include personal-data metadata targets",
                isOn: $viewModel.includeSensitiveTargets
            )
            .onChange(of: viewModel.includeSensitiveTargets) {
                inventoryTargets()
            }
            Button("Inventory target metadata", systemImage: "scope") {
                inventoryTargets()
            }
            ForEach(viewModel.targetObservations) { observation in
                VStack(alignment: .leading, spacing: 3) {
                    Label(
                        observation.target.name,
                        systemImage: observation.metadataReadable
                            ? "checkmark.circle.fill"
                            : "lock.circle"
                    )
                    .foregroundStyle(observation.metadataReadable ? .orange : .secondary)
                    Text(observation.target.path)
                        .font(.caption2.monospaced())
                    Text(observation.target.intendedOperations)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Research target catalog")
        } footer: {
            Text("Inventory performs metadata checks only. Personal-data targets remain excluded until explicitly enabled.")
        }
    }

    private var directorySection: some View {
        Section("Directory contents (\(viewModel.filteredEntries.count))") {
            if viewModel.filteredEntries.isEmpty, viewModel.listingError == nil {
                Text("This directory is empty.")
                    .foregroundStyle(.secondary)
            }
            ForEach(viewModel.filteredEntries) { entry in
                Button {
                    open(entry)
                } label: {
                    HStack {
                        Image(systemName: entry.isSymbolicLink
                            ? "link"
                            : (entry.isDirectory ? "folder.fill" : "doc"))
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.name)
                                .foregroundStyle(.primary)
                            Text(entry.byteCount.map { String($0) } ?? "size unavailable")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if entry.isDirectory {
                            Image(systemName: "chevron.right")
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var previewSection: some View {
        if let preview = viewModel.preview {
            Section("Bounded preview") {
                Text(preview.path)
                    .font(.caption2.monospaced())
                if let error = preview.errorDescription {
                    Text(error)
                        .foregroundStyle(.orange)
                } else {
                    LabeledContent("Bytes read", value: String(preview.bytesRead))
                    LabeledContent("Truncated", value: preview.truncated ? "Yes" : "No")
                    if let text = preview.text, !text.isEmpty {
                        Text(text)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .lineLimit(40)
                    } else {
                        Text(preview.hex)
                            .font(.caption2.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private func switchProvider(to kind: FileProviderKind) {
        viewModel.switchProvider(to: kind)
        researchViewModel.logger.record(ResearchEvent(
            severity: viewModel.provider.isAvailable ? .success : .info,
            subsystem: "file-provider",
            message: "File access provider selected",
            details: [
                "provider": kind.rawValue,
                "available": String(viewModel.provider.isAvailable),
                "summary": viewModel.provider.availabilitySummary
            ]
        ))
        recordDirectoryResult()
        recordCapabilityReport()
        recordTargetObservations()
    }

    private func navigateToInput() {
        viewModel.navigateToInput()
        recordDirectoryResult()
    }

    private func refreshDirectory() {
        viewModel.refreshDirectory()
        recordDirectoryResult()
    }

    private func open(_ entry: FileEntry) {
        viewModel.open(entry)
        if entry.isDirectory {
            recordDirectoryResult()
            return
        }
        let preview = viewModel.preview
        researchViewModel.logger.record(ResearchEvent(
            severity: preview?.succeeded == true ? .success : .info,
            subsystem: "file-preview",
            message: preview?.succeeded == true
                ? "Bounded file preview completed"
                : "Bounded file preview denied",
            details: [
                "provider": viewModel.selectedProvider.rawValue,
                "path": entry.path,
                "bytesRead": String(preview?.bytesRead ?? 0),
                "truncated": String(preview?.truncated ?? false),
                "error": preview?.errorDescription ?? "none"
            ]
        ))
    }

    private func validateProvider() {
        viewModel.validateProvider()
        recordCapabilityReport()
    }

    private func inventoryTargets() {
        viewModel.inventoryTargets()
        recordTargetObservations()
    }

    private func recordDirectoryResult() {
        researchViewModel.logger.record(ResearchEvent(
            severity: viewModel.listingError == nil ? .success : .info,
            subsystem: "file-browser",
            message: viewModel.listingError == nil
                ? "Directory listing completed"
                : "Directory listing denied",
            details: [
                "provider": viewModel.selectedProvider.rawValue,
                "path": viewModel.currentPath,
                "entries": String(viewModel.entries.count),
                "error": viewModel.listingError ?? "none"
            ]
        ))
    }

    private func recordCapabilityReport() {
        guard let report = viewModel.capabilityReport else { return }
        researchViewModel.logger.record(ResearchEvent(
            severity: .success,
            subsystem: "file-provider-validation",
            message: "File provider capability validation completed",
            details: [
                "provider": report.provider.rawValue,
                "passed": String(report.passedCount),
                "checks": String(report.checks.count)
            ]
        ))
        for check in report.checks {
            researchViewModel.logger.record(ResearchEvent(
                severity: check.succeeded ? .success : .info,
                subsystem: "file-provider-check",
                message: check.succeeded
                    ? "Provider operation completed"
                    : "Provider operation denied",
                details: [
                    "provider": report.provider.rawValue,
                    "label": check.label,
                    "operation": check.operation,
                    "path": check.path,
                    "detail": check.detail
                ]
            ))
        }
    }

    private func recordTargetObservations() {
        for observation in viewModel.targetObservations {
            researchViewModel.logger.record(ResearchEvent(
                severity: observation.metadataReadable ? .warning : .info,
                subsystem: "file-target",
                message: observation.metadataReadable
                    ? "Target metadata readable"
                    : "Target metadata denied",
                details: [
                    "provider": observation.provider.rawValue,
                    "name": observation.target.name,
                    "category": observation.target.category.rawValue,
                    "path": observation.target.path,
                    "sensitive": String(observation.target.sensitive),
                    "error": observation.errorDescription ?? "none"
                ]
            ))
        }
    }
}
