import SwiftUI

@main
struct CanaryBoxApp: App {
    @StateObject private var viewModel = CanaryBoxViewModel()
    @StateObject private var transportViewModel = CanaryTransportViewModel()

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                List {
                    Section("Synthetic isolation canaries") {
                        Label("No App Group", systemImage: "person.2.slash")
                        Label("No shared Keychain group", systemImage: "key.slash")
                        Text("Private canaries remain inside CanaryBox. manifest.json contains only paths, identifiers, and SHA-256 hashes—not secret bytes.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    Section("Private baseline") {
                        Button {
                            viewModel.generate()
                        } label: {
                            Label("Generate fresh private canaries", systemImage: "sparkles")
                        }
                        if let manifestURL = viewModel.manifestURL {
                            ShareLink(item: manifestURL) {
                                Label("Share private manifest.json", systemImage: "square.and.arrow.up")
                            }
                        }
                    }

                    Section("Public transport challenge") {
                        Text("This separate envelope contains random public bytes intentionally meant to cross through Files, the share sheet, pasteboard, and URL callbacks. It never contains the private canary secrets.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)

                        Button {
                            transportViewModel.generate()
                        } label: {
                            Label("Generate transport session", systemImage: "arrow.left.arrow.right.square")
                        }

                        if let envelopeURL = transportViewModel.envelopeURL {
                            ShareLink(item: envelopeURL) {
                                Label("Share public challenge", systemImage: "square.and.arrow.up")
                            }
                        }

                        Button {
                            transportViewModel.publishToPasteboard()
                        } label: {
                            Label("Copy public challenge to pasteboard", systemImage: "doc.on.clipboard")
                        }
                        .disabled(transportViewModel.envelope == nil)

                        if let envelope = transportViewModel.envelope {
                            LabeledContent("Session", value: envelope.sessionID)
                            LabeledContent("Expires", value: envelope.expiresAt.formatted())
                        }
                        Text(transportViewModel.message)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Section("Verify private boundaries") {
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

                    Section("Private status") {
                        Text(viewModel.message)
                            .font(.footnote)
                    }
                }
                .navigationTitle("CanaryBox")
                .onOpenURL { url in
                    transportViewModel.handleIncomingURL(url)
                }
            }
        }
    }
}
