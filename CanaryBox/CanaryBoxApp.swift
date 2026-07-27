import SwiftUI

@main
struct CanaryBoxApp: App {
    @StateObject private var viewModel = CanaryBoxViewModel()

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                List {
                    Section("Synthetic isolation canaries") {
                        Label("No App Group", systemImage: "person.2.slash")
                        Label("No shared Keychain group", systemImage: "key.slash")
                        Text("Only random synthetic bytes are generated. manifest.json contains paths, identifiers, and SHA-256 hashes—not secret bytes.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    Section("Generate") {
                        Button {
                            viewModel.generate()
                        } label: {
                            Label("Generate fresh canaries", systemImage: "sparkles")
                        }
                        if let manifestURL = viewModel.manifestURL {
                            ShareLink(item: manifestURL) {
                                Label("Share manifest.json", systemImage: "square.and.arrow.up")
                            }
                        }
                    }

                    Section("Verify") {
                        Button {
                            viewModel.verify()
                        } label: {
                            Label("Verify after Aegis test", systemImage: "checkmark.shield")
                        }
                        .disabled(viewModel.manifest == nil)

                        ForEach(viewModel.verification) { result in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(result.label)
                                    Text(result.value)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Image(systemName: result.changed ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                                    .foregroundStyle(result.changed ? .orange : .green)
                            }
                        }
                    }

                    Section("Status") {
                        Text(viewModel.message)
                            .font(.footnote)
                    }
                }
                .navigationTitle("CanaryBox")
            }
        }
    }
}
