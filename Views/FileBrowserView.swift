import SwiftUI

struct FileBrowserView: View {
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
                        viewModel.refreshDirectory()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
            .task {
                viewModel.refreshDirectory()
                viewModel.validateProvider()
                viewModel.inventoryTargets()
            }
        }
    }

    private var providerSection: some View {
        Section("File access provider") {
            Picker("Provider", selection: Binding(
                get: { viewModel.selectedProvider },
                set: { viewModel.switchProvider(to: $0) }
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
                .onSubmit { viewModel.navigateToInput() }
            HStack {
                Button("Up", systemImage: "arrow.up") {
                    viewModel.navigateToParent()
                }
                Spacer()
                Button("Go", systemImage: "arrow.right.circle.fill") {
                    viewModel.navigateToInput()
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
                viewModel.validateProvider()
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
                viewModel.inventoryTargets()
            }
            Button("Inventory target metadata", systemImage: "scope") {
                viewModel.inventoryTargets()
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
                    viewModel.open(entry)
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
}
