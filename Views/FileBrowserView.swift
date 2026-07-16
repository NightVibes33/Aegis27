import SwiftUI
import UIKit

struct FileBrowserView: View {
    @EnvironmentObject private var researchViewModel: ResearchViewModel
    @StateObject private var viewModel = FileBrowserViewModel()
    @State private var layout = BrowserLayout.list
    @State private var sort = BrowserSort.name
    @State private var showHiddenFiles = false
    @State private var showInspector = false
    @State private var showPreview = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                providerBanner
                addressBar
                breadcrumbs
                browserContent
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle(directoryTitle)
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $viewModel.searchText, prompt: "Search this folder")
            .toolbar { browserToolbar }
            .task {
                if viewModel.capabilityReport == nil {
                    refreshDirectory()
                    validateProvider()
                    inventoryTargets()
                }
            }
            .sheet(isPresented: $showInspector) {
                inspectorSheet
            }
            .sheet(isPresented: $showPreview) {
                previewSheet
            }
        }
    }

    private var directoryTitle: String {
        let name = URL(fileURLWithPath: viewModel.currentPath).lastPathComponent
        return name.isEmpty ? "Files" : name
    }

    private var visibleEntries: [FileEntry] {
        let filtered = viewModel.filteredEntries.filter {
            showHiddenFiles || !$0.name.hasPrefix(".")
        }
        return filtered.sorted { left, right in
            if left.isDirectory != right.isDirectory { return left.isDirectory }
            switch sort {
            case .name:
                return left.name.localizedCaseInsensitiveCompare(right.name) == .orderedAscending
            case .modified:
                return (left.modificationDate ?? .distantPast) >
                    (right.modificationDate ?? .distantPast)
            case .size:
                return (left.byteCount ?? 0) > (right.byteCount ?? 0)
            }
        }
    }

    private var providerBanner: some View {
        HStack(spacing: 10) {
            Image(systemName: viewModel.provider.isAvailable
                ? "checkmark.shield.fill"
                : "lock.shield.fill")
                .foregroundStyle(viewModel.provider.isAvailable ? .green : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(viewModel.selectedProvider.title)
                    .font(.subheadline.weight(.semibold))
                Text(viewModel.provider.isAvailable
                    ? "Read-only access active"
                    : "Provider unavailable")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text("READ ONLY")
                .font(.caption2.weight(.bold))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .foregroundStyle(.blue)
                .background(Color.blue.opacity(0.12), in: Capsule())
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color(uiColor: .secondarySystemGroupedBackground))
    }

    private var addressBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "location.fill")
                .font(.caption)
                .foregroundStyle(.secondary)
            TextField("Absolute path", text: $viewModel.pathInput)
                .font(.caption.monospaced())
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.go)
                .onSubmit { navigateToInput() }
            Button {
                navigateToInput()
            } label: {
                Image(systemName: "arrow.right.circle.fill")
                    .font(.title3)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(Color(uiColor: .systemBackground), in: RoundedRectangle(cornerRadius: 11))
        .overlay {
            RoundedRectangle(cornerRadius: 11)
                .stroke(Color.secondary.opacity(0.18))
        }
        .padding(.horizontal, 12)
        .padding(.top, 10)
    }

    private var breadcrumbs: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 5) {
                ForEach(pathCrumbs) { crumb in
                    Button {
                        viewModel.navigate(to: crumb.path)
                        recordDirectoryResult()
                    } label: {
                        HStack(spacing: 5) {
                            if crumb.path == "/" {
                                Image(systemName: "internaldrive")
                            } else {
                                Text(crumb.name)
                            }
                            if crumb.id != pathCrumbs.last?.id {
                                Image(systemName: "chevron.right")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                        .font(.caption.weight(.medium))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
        }
    }

    @ViewBuilder
    private var browserContent: some View {
        if let error = viewModel.listingError {
            ContentUnavailableView {
                Label("Folder unavailable", systemImage: "folder.badge.questionmark")
            } description: {
                Text(error)
            } actions: {
                Button("Try again") { refreshDirectory() }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if visibleEntries.isEmpty {
            ContentUnavailableView(
                viewModel.searchText.isEmpty ? "Empty folder" : "No matching files",
                systemImage: viewModel.searchText.isEmpty ? "folder" : "magnifyingglass",
                description: Text(viewModel.searchText.isEmpty
                    ? "There are no visible items here."
                    : "Try a different search term.")
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                if layout == .list {
                    LazyVStack(spacing: 7) {
                        ForEach(visibleEntries) { entry in
                            fileRow(entry)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.bottom, 24)
                } else {
                    LazyVGrid(
                        columns: [GridItem(.adaptive(minimum: 104), spacing: 12)],
                        spacing: 12
                    ) {
                        ForEach(visibleEntries) { entry in
                            fileTile(entry)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.bottom, 24)
                }
            }
            .refreshable { refreshDirectory() }
        }
    }

    private func fileRow(_ entry: FileEntry) -> some View {
        Button {
            open(entry)
        } label: {
            HStack(spacing: 12) {
                fileIcon(entry, size: 34)
                VStack(alignment: .leading, spacing: 4) {
                    Text(entry.name)
                        .font(.body.weight(.medium))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    HStack(spacing: 6) {
                        Text(entry.isDirectory ? "Folder" : formattedSize(entry.byteCount))
                        if let date = entry.modificationDate {
                            Text("•")
                            Text(date.formatted(date: .abbreviated, time: .shortened))
                        }
                    }
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                }
                Spacer(minLength: 4)
                if entry.isSymbolicLink {
                    Image(systemName: "link")
                        .foregroundStyle(.secondary)
                } else if entry.isDirectory {
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(11)
            .background(Color(uiColor: .secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 13))
        }
        .buttonStyle(.plain)
        .contextMenu {
            Button {
                UIPasteboard.general.string = entry.path
            } label: {
                Label("Copy path", systemImage: "doc.on.doc")
            }
            ShareLink(item: entry.path) {
                Label("Share path", systemImage: "square.and.arrow.up")
            }
        }
    }

    private func fileTile(_ entry: FileEntry) -> some View {
        Button {
            open(entry)
        } label: {
            VStack(spacing: 9) {
                fileIcon(entry, size: 48)
                    .frame(height: 52)
                Text(entry.name)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.primary)
                    .lineLimit(2)
                    .multilineTextAlignment(.center)
                Text(entry.isDirectory ? "Folder" : formattedSize(entry.byteCount))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, minHeight: 126)
            .padding(8)
            .background(Color(uiColor: .secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 15))
        }
        .buttonStyle(.plain)
        .contextMenu {
            Button {
                UIPasteboard.general.string = entry.path
            } label: {
                Label("Copy path", systemImage: "doc.on.doc")
            }
        }
    }

    private func fileIcon(_ entry: FileEntry, size: CGFloat) -> some View {
        Image(systemName: iconName(for: entry))
            .font(.system(size: size, weight: .medium))
            .symbolRenderingMode(.hierarchical)
            .foregroundStyle(iconColor(for: entry))
            .frame(width: size + 8)
    }

    @ToolbarContentBuilder
    private var browserToolbar: some ToolbarContent {
        ToolbarItem(placement: .topBarLeading) {
            Button {
                viewModel.navigateToParent()
                recordDirectoryResult()
            } label: {
                Image(systemName: "chevron.up")
            }
            .disabled(viewModel.currentPath == "/")
        }
        ToolbarItemGroup(placement: .topBarTrailing) {
            Menu {
                Picker("Sort", selection: $sort) {
                    ForEach(BrowserSort.allCases) { option in
                        Label(option.title, systemImage: option.icon).tag(option)
                    }
                }
                Divider()
                Toggle("Show hidden files", isOn: $showHiddenFiles)
                Divider()
                Picker("Layout", selection: $layout) {
                    ForEach(BrowserLayout.allCases) { option in
                        Label(option.title, systemImage: option.icon).tag(option)
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            Button {
                layout = layout == .list ? .grid : .list
            } label: {
                Image(systemName: layout == .list ? "square.grid.2x2" : "list.bullet")
            }
            Button {
                showInspector = true
            } label: {
                Image(systemName: "info.circle")
            }
        }
    }

    private var inspectorSheet: some View {
        NavigationStack {
            List {
                providerSection
                capabilitySection
                targetSection
            }
            .navigationTitle("Research inspector")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { showInspector = false }
                }
            }
        }
        .presentationDetents([.medium, .large])
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
            Text(viewModel.provider.availabilitySummary)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private var capabilitySection: some View {
        Section("Provider validation") {
            Button("Run capability validation", systemImage: "checklist") {
                validateProvider()
            }
            if let report = viewModel.capabilityReport {
                LabeledContent("Passed", value: "\(report.passedCount) of \(report.checks.count)")
                ForEach(report.checks) { check in
                    VStack(alignment: .leading, spacing: 3) {
                        Label(
                            check.label,
                            systemImage: check.succeeded ? "checkmark.circle.fill" : "xmark.circle"
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
            Toggle("Include personal-data metadata", isOn: $viewModel.includeSensitiveTargets)
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
            Text("Research targets")
        } footer: {
            Text("Inventory performs metadata checks only. Personal-data targets remain opt-in.")
        }
    }

    @ViewBuilder
    private var previewSheet: some View {
        NavigationStack {
            Group {
                if let preview = viewModel.preview {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 16) {
                            VStack(alignment: .leading, spacing: 5) {
                                Text(preview.path)
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                                HStack {
                                    Label("\(preview.bytesRead) bytes", systemImage: "doc")
                                    if preview.truncated {
                                        Label("Truncated", systemImage: "scissors")
                                    }
                                }
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            }
                            Divider()
                            if let error = preview.errorDescription {
                                ContentUnavailableView(
                                    "Preview unavailable",
                                    systemImage: "lock.doc",
                                    description: Text(error)
                                )
                            } else if let text = preview.text, !text.isEmpty {
                                Text(text)
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            } else {
                                Text(preview.hex)
                                    .font(.caption2.monospaced())
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .padding()
                    }
                } else {
                    ContentUnavailableView("No preview", systemImage: "doc")
                }
            }
            .navigationTitle("Preview")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { showPreview = false }
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private var pathCrumbs: [PathCrumb] {
        let components = URL(fileURLWithPath: viewModel.currentPath).pathComponents
        var crumbs = [PathCrumb(name: "Root", path: "/")]
        var path = "/"
        for component in components where component != "/" {
            path = URL(fileURLWithPath: path, isDirectory: true)
                .appendingPathComponent(component, isDirectory: true).path
            crumbs.append(PathCrumb(name: component, path: path))
        }
        return crumbs
    }

    private func formattedSize(_ bytes: Int64?) -> String {
        guard let bytes else { return "Size unavailable" }
        return ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    private func iconName(for entry: FileEntry) -> String {
        if entry.isSymbolicLink { return "link.circle.fill" }
        if entry.isDirectory { return "folder.fill" }
        switch URL(fileURLWithPath: entry.path).pathExtension.lowercased() {
        case "plist", "json", "yaml", "yml": return "curlybraces.square.fill"
        case "sqlite", "db": return "cylinder.fill"
        case "png", "jpg", "jpeg", "heic", "gif": return "photo.fill"
        case "zip", "ipa", "gz", "tar": return "archivebox.fill"
        case "txt", "log", "md": return "doc.text.fill"
        default: return "doc.fill"
        }
    }

    private func iconColor(for entry: FileEntry) -> Color {
        if entry.isSymbolicLink { return .purple }
        if entry.isDirectory { return .blue }
        switch URL(fileURLWithPath: entry.path).pathExtension.lowercased() {
        case "plist", "json", "yaml", "yml": return .orange
        case "sqlite", "db": return .indigo
        case "png", "jpg", "jpeg", "heic", "gif": return .pink
        case "zip", "ipa", "gz", "tar": return .brown
        default: return .secondary
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
        showPreview = true
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

private enum BrowserLayout: String, CaseIterable, Identifiable {
    case list
    case grid

    var id: String { rawValue }
    var title: String { rawValue.capitalized }
    var icon: String { self == .list ? "list.bullet" : "square.grid.2x2" }
}

private enum BrowserSort: String, CaseIterable, Identifiable {
    case name
    case modified
    case size

    var id: String { rawValue }
    var title: String { rawValue.capitalized }
    var icon: String {
        switch self {
        case .name: return "textformat"
        case .modified: return "calendar"
        case .size: return "arrow.up.arrow.down"
        }
    }
}

private struct PathCrumb: Identifiable {
    var id: String { path }
    let name: String
    let path: String
}
