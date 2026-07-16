import Foundation

@MainActor
final class SandboxValidationViewModel: ObservableObject {
    @Published var selectedProvider = FileProviderKind.stock
    @Published private(set) var report: SandboxValidationReport?
    @Published private(set) var isRunning = false

    var provider: any FileAccessProvider {
        FileAccessProviderRegistry.provider(for: selectedProvider)
    }

    func run() {
        isRunning = true
        report = SandboxValidationService.run(provider: provider)
        isRunning = false
    }

    func switchProvider(to kind: FileProviderKind) {
        selectedProvider = kind
        report = nil
    }
}
