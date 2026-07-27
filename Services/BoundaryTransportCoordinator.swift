import Foundation
import Combine
import UIKit

@MainActor
final class BoundaryTransportCoordinator: ObservableObject {
    @Published private(set) var activeEnvelope: BoundaryTransportEnvelope?
    @Published private(set) var checks: [BoundaryTransportCheckResult] = []
    @Published private(set) var message = "Import or receive a public CanaryBox transport envelope."
    @Published private(set) var reportURL: URL?

    private struct PendingChallenge {
        let sessionID: String
        let nonce: String
    }

    private var pendingChallenge: PendingChallenge?
    private var startedAt = Date()

    func reset() {
        activeEnvelope = nil
        checks = []
        pendingChallenge = nil
        reportURL = nil
        startedAt = Date()
        message = "Transport Lab reset. Import or receive a new CanaryBox envelope."
    }

    func importFromDocumentProvider(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped {
                url.stopAccessingSecurityScopedResource()
            }
        }

        var coordinationError: NSError?
        var coordinatedData: Data?
        var readError: Error?
        let coordinator = NSFileCoordinator(filePresenter: nil)
        coordinator.coordinate(
            readingItemAt: url,
            options: [.withoutChanges],
            error: &coordinationError
        ) { coordinatedURL in
            do {
                coordinatedData = try Data(contentsOf: coordinatedURL, options: [.mappedIfSafe])
            } catch {
                readError = error
            }
        }

        if let coordinationError {
            append(
                channel: "document-provider-file-coordination",
                status: .failed,
                detail: coordinationError.localizedDescription
            )
            return
        }
        if let readError {
            append(
                channel: "document-provider-file-coordination",
                status: .failed,
                detail: readError.localizedDescription
            )
            return
        }
        guard let coordinatedData else {
            append(
                channel: "document-provider-file-coordination",
                status: .unavailable,
                detail: "The coordinated document provider did not return data."
            )
            return
        }
        accept(
            data: coordinatedData,
            channel: "document-provider-file-coordination",
            detail: scoped
                ? "Security-scoped, coordinated read succeeded."
                : "Coordinated read succeeded without a security-scoped lease."
        )
    }

    func importFromPasteboard() {
        guard let data = UIPasteboard.general.data(
            forPasteboardType: BoundaryTransportValidator.typeIdentifier
        ) else {
            append(
                channel: "pasteboard",
                status: .unavailable,
                detail: "No CanaryBox boundary envelope was present on the general pasteboard."
            )
            return
        }
        accept(
            data: data,
            channel: "pasteboard",
            detail: "User-initiated pasteboard read returned the custom boundary-envelope type."
        )
    }

    func launchURLChallenge() {
        guard let envelope = activeEnvelope else {
            append(
                channel: "url-handler-request",
                status: .unavailable,
                detail: "Import a valid transport envelope before launching CanaryBox."
            )
            return
        }
        guard Date() <= envelope.expiresAt else {
            append(
                channel: "url-handler-request",
                status: .expired,
                detail: "The active CanaryBox transport session expired."
            )
            return
        }

        let nonce = UUID().uuidString.lowercased()
        pendingChallenge = PendingChallenge(
            sessionID: envelope.sessionID,
            nonce: nonce
        )

        var components = URLComponents()
        components.scheme = BoundaryTransportValidator.canaryURLScheme
        components.host = "challenge"
        components.queryItems = [
            URLQueryItem(name: "session", value: envelope.sessionID),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(
                name: "callback",
                value: BoundaryTransportValidator.callbackURLScheme
            )
        ]
        guard let url = components.url else {
            append(
                channel: "url-handler-request",
                status: .failed,
                detail: "Could not construct the fixed CanaryBox challenge URL."
            )
            return
        }

        UIApplication.shared.open(url, options: [:]) { [weak self] opened in
            Task { @MainActor in
                guard let self else { return }
                self.append(
                    channel: "url-handler-request",
                    status: opened ? .delivered : .unavailable,
                    detail: opened
                        ? "iOS delivered the fixed challenge URL to CanaryBox."
                        : "iOS could not open CanaryBox's registered URL scheme."
                )
            }
        }
    }

    func handleIncomingURL(_ url: URL) {
        if url.isFileURL || url.pathExtension.lowercased() == BoundaryTransportValidator.fileExtension {
            importFromDocumentProvider(url)
            return
        }

        guard url.scheme == BoundaryTransportValidator.callbackURLScheme else {
            append(
                channel: "incoming-url",
                status: .rejected,
                detail: "Rejected an URL outside the fixed Aegis Boundary callback scheme."
            )
            return
        }

        switch url.host {
        case "reply":
            validateURLReply(url)
        case "share-import":
            validateShareExtensionURL(url)
        default:
            append(
                channel: "incoming-url",
                status: .rejected,
                detail: "Rejected an unknown callback action."
            )
        }
    }

    private func validateURLReply(_ url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            append(
                channel: "url-reply-schema",
                status: .rejected,
                detail: "The CanaryBox callback URL could not be parsed."
            )
            return
        }
        let items = components.queryItems ?? []
        let names = items.map(\.name)
        guard Set(names) == Set(["session", "nonce", "receipt", "source"]),
              names.count == 4,
              let session = items.first(where: { $0.name == "session" })?.value,
              let nonce = items.first(where: { $0.name == "nonce" })?.value,
              let receipt = items.first(where: { $0.name == "receipt" })?.value,
              let source = items.first(where: { $0.name == "source" })?.value,
              source == "CanaryBox" else {
            append(
                channel: "url-reply-schema",
                status: .rejected,
                detail: "The callback reply contained missing, duplicated, extra, or invalid fields."
            )
            return
        }
        guard let pendingChallenge,
              pendingChallenge.sessionID == session,
              pendingChallenge.nonce == nonce,
              activeEnvelope?.sessionID == session else {
            append(
                channel: "url-reply-schema",
                status: .rejected,
                detail: "The callback did not match the active challenge session and nonce."
            )
            return
        }
        let expected = BoundaryTransportValidator.receipt(
            sessionID: session,
            nonce: nonce
        )
        guard receipt == expected else {
            append(
                channel: "url-reply-schema",
                status: .rejected,
                detail: "The callback receipt hash did not match the fixed reply schema."
            )
            return
        }
        self.pendingChallenge = nil
        append(
            channel: "url-reply-schema",
            status: .validated,
            detail: "The CanaryBox URL callback matched the exact allow-listed reply fields, session, nonce, and receipt hash."
        )
    }

    private func validateShareExtensionURL(_ url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let items = components.queryItems,
              items.count == 1,
              items.first?.name == "payload",
              let encoded = items.first?.value,
              encoded.count <= 180_000,
              let data = Data(base64URLString: encoded) else {
            append(
                channel: "share-extension",
                status: .rejected,
                detail: "The share-extension callback did not contain one bounded base64url payload."
            )
            return
        }
        accept(
            data: data,
            channel: "share-extension",
            detail: "The embedded Aegis share extension forwarded one user-selected envelope through the fixed callback scheme."
        )
    }

    private func accept(data: Data, channel: String, detail: String) {
        do {
            let envelope = try BoundaryTransportValidator.decodeAndValidate(data)
            activeEnvelope = envelope
            append(
                channel: channel,
                status: .validated,
                detail: "\(detail) Strict JSON schema, fixed identifiers, lifetime, payload bounds, and SHA-256 all validated."
            )
        } catch BoundaryTransportError.expired {
            append(
                channel: channel,
                status: .expired,
                detail: BoundaryTransportError.expired.localizedDescription
            )
        } catch {
            append(
                channel: channel,
                status: .rejected,
                detail: error.localizedDescription
            )
        }
    }

    private func append(
        channel: String,
        status: BoundaryTransportStatus,
        detail: String
    ) {
        checks.insert(
            BoundaryTransportCheckResult(
                channel: channel,
                status: status,
                detail: detail
            ),
            at: 0
        )
        checks = Array(checks.prefix(50))
        message = detail
        reportURL = saveReport()
    }

    private func saveReport() -> URL? {
        do {
            let directory = FileManager.default.urls(
                for: .documentDirectory,
                in: .userDomainMask
            )[0].appendingPathComponent("ResearchLogs", isDirectory: true)
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true
            )
            let report = BoundaryTransportReport(
                formatVersion: 1,
                startedAt: startedAt,
                updatedAt: Date(),
                activeSessionID: activeEnvelope?.sessionID,
                checks: checks
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let url = directory.appendingPathComponent("boundary-transport-latest.json")
            try encoder.encode(report).write(to: url, options: [.atomic])
            return url
        } catch {
            return nil
        }
    }
}

private extension Data {
    init?(base64URLString: String) {
        var value = base64URLString
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = value.count % 4
        if remainder != 0 {
            value.append(String(repeating: "=", count: 4 - remainder))
        }
        self.init(base64Encoded: value)
    }
}
