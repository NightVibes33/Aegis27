import Foundation

@MainActor
final class FileBrowserViewModel: ObservableObject {
    @Published var selectedProvider = FileProviderKind.stock
    @Published var currentPath = NSHomeDirectory()
    @Published var pathInput = NSHomeDirectory()
    @Published var searchText = ""
    @Published var includeSensitiveTargets = false
    @Published private(set) var entries: [FileEntry] = []
    @Published private(set) var listingError: String?
    @Published private(set) var preview: FilePreviewResult?
    @Published private(set) var capabilityReport: ProviderCapabilityReport?
    @Published private(set) var targetObservations: [FileTargetObservation] = []

    var provider: any FileAccessProvider {
        FileAccessProviderRegistry.provider(for: selectedProvider)
    }

    var filteredEntries: [FileEntry] {
        guard !searchText.isEmpty else { return entries }
        return entries.filter {
            $0.name.localizedCaseInsensitiveContains(searchText)
        }
    }

    func switchProvider(to kind: FileProviderKind) {
        selectedProvider = kind
        preview = nil
        refreshDirectory()
        validateProvider()
        inventoryTargets()
    }

    func navigateToInput() {
        navigate(to: pathInput)
    }

    func navigate(to path: String) {
        let normalized = NSString(string: path).standardizingPath
        currentPath = normalized
        pathInput = normalized
        preview = nil
        refreshDirectory()
    }

    func navigateToParent() {
        let parent = URL(fileURLWithPath: currentPath)
            .deletingLastPathComponent().path
        navigate(to: parent.isEmpty ? "/" : parent)
    }

    func open(_ entry: FileEntry) {
        if entry.isSymbolicLink {
            preview = FilePreviewResult(
                path: entry.path,
                bytesRead: 0,
                truncated: false,
                text: nil,
                hex: "",
                errorDescription: "Symbolic links are not followed by the browser."
            )
        } else if entry.isDirectory {
            navigate(to: entry.path)
        } else {
            preview = provider.readPreview(at: entry.path, limit: 64 * 1_024)
        }
    }

    func refreshDirectory() {
        let result = provider.listDirectory(at: currentPath)
        entries = result.entries
        listingError = result.errorDescription
    }

    func validateProvider() {
        capabilityReport = ProviderCapabilityValidator.validate(provider: provider)
    }

    func inventoryTargets() {
        targetObservations = FileResearchTargetCatalog.observe(
            provider: provider,
            includeSensitive: includeSensitiveTargets
        )
    }
}
