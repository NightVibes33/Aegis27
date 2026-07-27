import SwiftUI
import UniformTypeIdentifiers

struct BoundaryTransportView: View {
    @EnvironmentObject private var coordinator: BoundaryTransportCoordinator
    @State private var showingImporter = false

    var body: some View {
        List {
            Section("Supported boundary paths") {
                Label("Document providers + file coordination", systemImage: "folder.badge.gearshape")
                Label("System Share / Open In", systemImage: "square.and.arrow.up.on.square")
                Label("User-initiated pasteboard", systemImage: "doc.on.clipboard")
                Label("Allow-listed URL callback", systemImage: "link.badge.plus")
                Text("iOS does not expose public third-party app-to-app XPC. This lab instead performs strict reply validation on supported URL, share-extension, pasteboard, and document-provider handoffs.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Section("Receive public challenge") {
                Button {
                    showingImporter = true
                } label: {
                    Label("Import from Files provider", systemImage: "folder")
                }

                Button {
                    coordinator.importFromPasteboard()
                } label: {
                    Label("Read CanaryBox pasteboard envelope", systemImage: "doc.on.clipboard")
                }

                Text("In CanaryBox, use Share public challenge and choose Aegis Boundary Share or Open in Aegis27. The result is delivered here automatically.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("URL handler challenge") {
                if let envelope = coordinator.activeEnvelope {
                    LabeledContent("Session", value: envelope.sessionID)
                    LabeledContent("Expires", value: envelope.expiresAt.formatted())
                    LabeledContent(
                        "Payload hash",
                        value: String(envelope.payloadSHA256.prefix(16)) + "…"
                    )
                } else {
                    Text("Import or receive a valid challenge envelope first.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Button {
                    coordinator.launchURLChallenge()
                } label: {
                    Label("Launch CanaryBox and validate reply", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(coordinator.activeEnvelope == nil)
            }

            if !coordinator.checks.isEmpty {
                Section("Transport results") {
                    ForEach(coordinator.checks) { result in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(result.channel)
                                    .font(.subheadline.weight(.semibold))
                                Spacer()
                                Text(result.status.rawValue)
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(color(for: result.status))
                            }
                            Text(result.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(result.timestamp.formatted())
                                .font(.caption2.monospaced())
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
            }

            Section("Report") {
                Text(coordinator.message)
                    .font(.footnote)
                if let reportURL = coordinator.reportURL {
                    ShareLink(item: reportURL) {
                        Label("Export boundary-transport-latest.json", systemImage: "square.and.arrow.up")
                    }
                }
                Button("Reset Transport Lab", role: .destructive) {
                    coordinator.reset()
                }
            }
        }
        .navigationTitle("Transport Lab")
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [.canaryBoundaryEnvelope, .json],
            allowsMultipleSelection: false
        ) { result in
            guard case .success(let urls) = result, let url = urls.first else {
                return
            }
            coordinator.importFromDocumentProvider(url)
        }
    }

    private func color(for status: BoundaryTransportStatus) -> Color {
        switch status {
        case .validated, .delivered:
            return .green
        case .rejected, .expired:
            return .orange
        case .unavailable:
            return .secondary
        case .failed:
            return .red
        }
    }
}
