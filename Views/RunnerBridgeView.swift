import SwiftUI

struct RunnerBridgeView: View {
    @EnvironmentObject private var researchViewModel: ResearchViewModel
    @ObservedObject private var bridge = GitHubRunnerBridge.shared
    @State private var token = ""
    @State private var error: String?

    var body: some View {
        Form {
            Section("Connection") {
                Label(
                    bridge.isConnected ? "Runner connected" : "Runner not connected",
                    systemImage: bridge.isConnected ? "checkmark.icloud.fill" : "icloud.slash"
                )
                .foregroundStyle(bridge.isConnected ? .green : .secondary)
                Text(bridge.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if bridge.isConnected {
                    Button("Disconnect", role: .destructive) { bridge.disconnect() }
                } else {
                    SecureField("Fine-grained GitHub token", text: $token)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button {
                        Task {
                            do {
                                try await bridge.connect(token: token)
                                token = ""
                                error = nil
                            } catch {
                                self.error = error.localizedDescription
                            }
                        }
                    } label: {
                        if bridge.isWorking { ProgressView() } else { Text("Connect runner") }
                    }
                    .disabled(token.isEmpty || bridge.isWorking)
                }
                if let error { Text(error).font(.caption).foregroundStyle(.red) }
            }

            Section("Automatic flow") {
                Text("After a deep scan or attack-surface run, Aegis27 uploads the generated report to an unpublished draft release, triggers the free public-repository runner, waits for its compact analysis, and downloads that result automatically.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                if let url = bridge.lastResultURL {
                    ShareLink(item: url) {
                        Label("Open latest runner analysis", systemImage: "doc.text.magnifyingglass")
                    }
                }
            }

            Section("Required token scope") {
                Text("Create a fine-grained token restricted to NightVibes33/Aegis27 with Contents: Read and write. The token is stored as a this-device-only Keychain item and is never written to reports or bundled in the IPA.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Runner Bridge")
        .task { await bridge.resumePending(logger: researchViewModel.logger) }
    }
}
