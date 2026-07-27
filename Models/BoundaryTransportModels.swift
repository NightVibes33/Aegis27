import Foundation
import CryptoKit
import UniformTypeIdentifiers

extension UTType {
    static let canaryBoundaryEnvelope = UTType(importedAs: BoundaryTransportValidator.typeIdentifier)
}

struct BoundaryTransportEnvelope: Codable {
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

enum BoundaryTransportStatus: String, Codable {
    case validated
    case delivered
    case rejected
    case unavailable
    case expired
    case failed
}

struct BoundaryTransportCheckResult: Codable, Identifiable {
    let id: UUID
    let timestamp: Date
    let channel: String
    let status: BoundaryTransportStatus
    let detail: String

    init(
        channel: String,
        status: BoundaryTransportStatus,
        detail: String
    ) {
        self.id = UUID()
        self.timestamp = Date()
        self.channel = channel
        self.status = status
        self.detail = detail
    }
}

struct BoundaryTransportReport: Codable {
    let formatVersion: Int
    let startedAt: Date
    let updatedAt: Date
    let activeSessionID: String?
    let checks: [BoundaryTransportCheckResult]
}

enum BoundaryTransportError: LocalizedError {
    case oversized
    case malformedJSON
    case unexpectedSchema
    case unsupportedFormat
    case invalidKind
    case invalidSession
    case invalidLifetime
    case expired
    case invalidPayload
    case invalidDigest
    case invalidTransportIdentifiers

    var errorDescription: String? {
        switch self {
        case .oversized:
            return "The transport envelope is larger than 128 KB."
        case .malformedJSON:
            return "The transport envelope is not valid JSON."
        case .unexpectedSchema:
            return "The transport envelope contains missing, extra, or incorrectly typed fields."
        case .unsupportedFormat:
            return "The transport envelope format is not supported."
        case .invalidKind:
            return "The transport envelope is not a CanaryBox boundary challenge."
        case .invalidSession:
            return "The transport session identifier is invalid."
        case .invalidLifetime:
            return "The transport envelope lifetime is invalid."
        case .expired:
            return "The transport envelope has expired. Generate a new session in CanaryBox."
        case .invalidPayload:
            return "The public synthetic payload is invalid."
        case .invalidDigest:
            return "The public synthetic payload hash did not match."
        case .invalidTransportIdentifiers:
            return "The transport envelope requested an unapproved pasteboard type or URL scheme."
        }
    }
}

enum BoundaryTransportValidator {
    static let typeIdentifier = "com.nightvibes33.canarybox.boundary-envelope"
    static let fileExtension = "aegisboundary"
    static let kind = "canarybox-boundary-challenge"
    static let canaryURLScheme = "canarybox-boundary"
    static let callbackURLScheme = "aegis27-boundary"

    private static let exactKeys: Set<String> = [
        "formatVersion",
        "kind",
        "sessionID",
        "issuedAt",
        "expiresAt",
        "payloadBase64",
        "payloadSHA256",
        "pasteboardType",
        "canaryURLScheme",
        "callbackURLScheme"
    ]

    static func decodeAndValidate(
        _ data: Data,
        now: Date = Date()
    ) throws -> BoundaryTransportEnvelope {
        guard data.count <= 128 * 1024 else {
            throw BoundaryTransportError.oversized
        }

        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw BoundaryTransportError.malformedJSON
        }

        guard let dictionary = object as? [String: Any],
              Set(dictionary.keys) == exactKeys,
              dictionary["formatVersion"] is NSNumber,
              dictionary["kind"] is String,
              dictionary["sessionID"] is String,
              dictionary["issuedAt"] is String,
              dictionary["expiresAt"] is String,
              dictionary["payloadBase64"] is String,
              dictionary["payloadSHA256"] is String,
              dictionary["pasteboardType"] is String,
              dictionary["canaryURLScheme"] is String,
              dictionary["callbackURLScheme"] is String else {
            throw BoundaryTransportError.unexpectedSchema
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let envelope: BoundaryTransportEnvelope
        do {
            envelope = try decoder.decode(BoundaryTransportEnvelope.self, from: data)
        } catch {
            throw BoundaryTransportError.unexpectedSchema
        }

        guard envelope.formatVersion == 1 else {
            throw BoundaryTransportError.unsupportedFormat
        }
        guard envelope.kind == kind else {
            throw BoundaryTransportError.invalidKind
        }
        guard UUID(uuidString: envelope.sessionID) != nil else {
            throw BoundaryTransportError.invalidSession
        }
        let lifetime = envelope.expiresAt.timeIntervalSince(envelope.issuedAt)
        guard lifetime > 0, lifetime <= 60 * 60 else {
            throw BoundaryTransportError.invalidLifetime
        }
        guard now <= envelope.expiresAt else {
            throw BoundaryTransportError.expired
        }
        guard envelope.pasteboardType == typeIdentifier,
              envelope.canaryURLScheme == canaryURLScheme,
              envelope.callbackURLScheme == callbackURLScheme else {
            throw BoundaryTransportError.invalidTransportIdentifiers
        }
        guard isDigest(envelope.payloadSHA256),
              let payload = Data(base64Encoded: envelope.payloadBase64),
              (32...4096).contains(payload.count) else {
            throw BoundaryTransportError.invalidPayload
        }
        guard sha256(payload) == envelope.payloadSHA256 else {
            throw BoundaryTransportError.invalidDigest
        }
        return envelope
    }

    static func receipt(sessionID: String, nonce: String) -> String {
        sha256(Data("CanaryBox|\(sessionID)|\(nonce)|v1".utf8))
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func isDigest(_ value: String) -> Bool {
        value.count == 64 && value.unicodeScalars.allSatisfy {
            (48...57).contains($0.value) || (97...102).contains($0.value)
        }
    }
}
