import SwiftUI
import UniformTypeIdentifiers

struct BoundaryLabView: View {
    @State private var manifest: BoundaryCanaryManifest?
    @State private var manifestMessage = "Import manifest.json exported by CanaryBox."
    @State private var showingImporter = false
    @State private var report: BoundaryLabReport?
    @State private var reportURL: URL?
    @State private var isRunning = false

    var body: some View {
        List {
            Section("Isolation boundary") {
                Label("Synthetic CanaryBox data only", systemImage: "lock.shield.fill")
                    .foregroundStyle(.green)
                Text("Aegis accepts only CanaryBox's fixed bundle identifier, BoundaryCanary paths, preference prefixes, and synthetic Keychain namespace. Raw bytes are hashed in memory and discarded.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Section("Manifest") {
                Button {
                    showingImporter = true
                } label: {
                    Label("Import CanaryBox manifest", systemImage: "doc.badge.arrow.up")
                }
                Text(manifestMessage)
                    .font(.caption)
                    .foregroundStyle(manifest == nil ? Color.secondary : Color.green)

                if let manifest {
                    LabeledContent("Bundle", value: manifest.bundleIdentifier)
                    LabeledContent("Generated", value: manifest.generatedAt.formatted())
                    LabeledContent("File", value: URL(fileURLWithPath: manifest.file.path).lastPathComponent)
                    LabeledContent("Database", value: URL(fileURLWithPath: manifest.database.path).lastPathComponent)
                }
            }

            Section("Boundary checks") {
                Button {
                    run()
                } label: {
                    Label("Run eight bounded checks", systemImage: "lock.open.trianglebadge.exclamationmark")
                }
                .disabled(manifest == nil || isRunning)

                if isRunning {
                    ProgressView()
                }
            }

            if let report {
                Section("Latest report") {
                    ForEach(report.checks) { result in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(result.check)
                                    .font(.subheadline.weight(.semibold))
                                Spacer()
                                Text(result.status.rawValue)
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(color(for: result.status))
                            }
                            Text(result.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            if let osStatus = result.osStatus {
                                Text("status \(osStatus)")
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }

                    if let reportURL {
                        ShareLink(item: reportURL) {
                            Label("Export boundary-lab-latest.json", systemImage: "square.and.arrow.up")
                        }
                    }
                }
            }
        }
        .navigationTitle("Boundary Lab")
        .fileImporter(
            isPresented: $showingImporter,
            allowedContentTypes: [.json],
            allowsMultipleSelection: false
        ) { result in
            guard case .success(let urls) = result, let url = urls.first else {
                return
            }
            do {
                let imported = try BoundaryLabService.loadManifest(from: url)
                manifest = imported
                report = nil
                reportURL = nil
                manifestMessage = "Validated CanaryBox manifest."
            } catch {
                manifest = nil
                manifestMessage = error.localizedDescription
            }
        }
    }

    private func run() {
        guard let manifest else { return }
        isRunning = true
        let output = BoundaryLabService.run(manifest: manifest)
        report = output.report
        reportURL = output.exportURL
        isRunning = false
    }

    private func color(for status: BoundaryCheckStatus) -> Color {
        switch status {
        case .matched, .accessible, .changed:
            return .orange
        case .denied, .unchanged:
            return .green
        case .failed:
            return .red
        }
    }
}
