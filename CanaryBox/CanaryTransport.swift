import Foundation
import Combine
import CryptoKit
import Security
import UIKit

struct CanaryTransportEnvelope: Codable {
    let formatVersion: Int
    let kind: String
    let sessionID: String
    let issuedAt: Date
    let expiresAt: Date
    let payloadBase64: String
    let payloadSHA256: String
    let pasteboardType: String
    let canaryURLScheme: String
    let callbackURLScheme: String
}

@MainActor
final class CanaryTransportViewModel: ObservableObject {
    @Published private(set) var envelope: CanaryTransportEnvelope?
    @Published private(set) var envelopeURL: URL?
    @Published private(set) var message = "Generate a public synthetic transport challenge."

    static let typeIdentifier = "com.nightvibes33.canarybox.boundary-envelope"
    static let fileName = "canarybox-transport.aegisboundary"
    static let kind = "canarybox-boundary-challenge"
    static let canaryURLScheme = "canarybox-boundary"
    static let callbackURLScheme = "aegis27-boundary"

    func generate() {
        do {
            let payload = randomData(count: 256)
            let issuedAt = Date()
            let newEnvelope = CanaryTransportEnvelope(
                formatVersion: 1,
                kind: Self.kind,
                sessionID: UUID().uuidString.lowercased(),
                issuedAt: issuedAt,
                expiresAt: issuedAt.addingTimeInterval(30 * 60),
                payloadBase64: payload.base64EncodedString(),
                payloadSHA256: sha256(payload),
                pasteboardType: Self.typeIdentifier,
                canaryURLScheme: Self.canaryURLScheme,
                callbackURLScheme: Self.callbackURLScheme
            )
            let data = try encode(newEnvelope)
            let directory = FileManager.default.urls(
                for: .documentDirectory,
                in: .userDomainMask
            )[0].appendingPathComponent("BoundaryCanary", isDirectory: true)
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true
            )
            let url = directory.appendingPathComponent(Self.fileName)
            try data.write(to: url, options: [.atomic])
            envelope = newEnvelope
            envelopeURL = url
            message = "Public transport challenge generated. It contains synthetic payload bytes intended for explicit sharing."
        } catch {
            message = error.localizedDescription
        }
    }

    func publishToPasteboard() {
        guard let envelope else {
            message = "Generate a transport challenge first."
            return
        }
        do {
            let data = try encode(envelope)
            UIPasteboard.general.setItems(
                [[Self.typeIdentifier: data]],
                options: [
                    .expirationDate: envelope.expiresAt,
                    .localOnly: false
                ]
            )
            message = "The public synthetic envelope is on the pasteboard until it expires."
        } catch {
            message = error.localizedDescription
        }
    }

    func handleIncomingURL(_ url: URL) {
        guard url.scheme == Self.canaryURLScheme,
              url.host == "challenge",
              let envelope,
              Date() <= envelope.expiresAt,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            message = "Rejected an invalid or expired boundary challenge URL."
            return
        }

        let items = components.queryItems ?? []
        let names = items.map(\.name)
        guard Set(names) == Set(["session", "nonce", "callback"]),
              names.count == 3,
              let session = items.first(where: { $0.name == "session" })?.value,
              let nonce = items.first(where: { $0.name == "nonce" })?.value,
              let callback = items.first(where: { $0.name == "callback" })?.value,
              session == envelope.sessionID,
              UUID(uuidString: nonce) != nil,
              callback == Self.callbackURLScheme else {
            message = "Rejected a challenge URL with unexpected fields or identifiers."
            return
        }

        let receipt = sha256(Data("CanaryBox|\(session)|\(nonce)|v1".utf8))
        var response = URLComponents()
        response.scheme = Self.callbackURLScheme
        response.host = "reply"
        response.queryItems = [
            URLQueryItem(name: "session", value: session),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "receipt", value: receipt),
            URLQueryItem(name: "source", value: "CanaryBox")
        ]
        guard let callbackURL = response.url else {
            message = "Could not construct the fixed Aegis callback URL."
            return
        }

        UIApplication.shared.open(callbackURL, options: [:]) { [weak self] opened in
            Task { @MainActor in
                self?.message = opened
                    ? "Returned the strict challenge receipt to Aegis27."
                    : "iOS could not open Aegis27's callback scheme."
            }
        }
    }

    private func encode(_ envelope: CanaryTransportEnvelope) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(envelope)
    }

    private func randomData(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        if status != errSecSuccess {
            for index in bytes.indices {
                bytes[index] = UInt8.random(in: .min ... .max)
            }
        }
        return Data(bytes)
    }

    private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
