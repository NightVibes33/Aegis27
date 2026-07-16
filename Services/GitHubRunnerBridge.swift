import CryptoKit
import Foundation
import Security

struct RunnerSubmission: Codable {
    let assetID: Int64
    let releaseID: Int64
    let sourceName: String
    let analysisName: String
    let submittedAt: Date
}

enum RunnerBridgeError: LocalizedError {
    case notConnected
    case invalidResponse(Int)
    case malformedResponse

    var errorDescription: String? {
        switch self {
        case .notConnected: return "Connect the GitHub runner first."
        case .invalidResponse(let status): return "GitHub returned HTTP \(status)."
        case .malformedResponse: return "GitHub returned an unexpected response."
        }
    }
}

@MainActor
final class GitHubRunnerBridge: ObservableObject {
    static let shared = GitHubRunnerBridge()

    @Published private(set) var isConnected = false
    @Published private(set) var isWorking = false
    @Published private(set) var status = "Not connected"
    @Published private(set) var lastResultURL: URL?

    private let owner = "NightVibes33"
    private let repository = "Aegis27"
    private let keychainService = "com.nightvibes33.Aegis27.github-runner"
    private let keychainAccount = "fine-grained-token"
    private let inboxTag = "aegis27-device-inbox"
    private let session = URLSession.shared

    private init() {
        isConnected = token() != nil
        status = isConnected ? "Connected; uploads are automatic" : "Not connected"
    }

    func connect(token: String) async throws {
        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw RunnerBridgeError.notConnected }
        isWorking = true
        defer { isWorking = false }
        let releaseID = try await inboxReleaseID(token: trimmed)
        let verification = try JSONSerialization.data(withJSONObject: [
            "name": "Aegis27 device report inbox",
            "draft": true,
        ])
        let (_, response) = try await request(
            path: "/repos/\(owner)/\(repository)/releases/\(releaseID)",
            method: "PATCH",
            token: trimmed,
            body: verification
        )
        guard response.statusCode == 200 else {
            throw RunnerBridgeError.invalidResponse(response.statusCode)
        }
        try storeToken(trimmed)
        isConnected = true
        status = "Connected; uploads are automatic"
    }

    func disconnect() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        SecItemDelete(query as CFDictionary)
        isConnected = false
        status = "Not connected"
        lastResultURL = nil
    }

    func submitIfConnected(
        fileURL: URL,
        kind: String,
        profile: DeviceProfile,
        logger: AuditLogger
    ) async {
        guard let token = token(), !isWorking else { return }
        isWorking = true
        status = "Uploading \(kind)…"
        defer { isWorking = false }
        do {
            let releaseID = try await inboxReleaseID(token: token)
            let digest = try fileSHA256(fileURL)
            let safeKind = sanitize(kind)
            let sourceName = "\(safeKind)-\(profile.buildVersion)-\(UUID().uuidString).json"
            let assetID = try await upload(
                fileURL: fileURL,
                name: sourceName,
                releaseID: releaseID,
                token: token
            )
            let analysisName = "analysis-\(assetID).json"
            try await dispatch(
                assetID: assetID,
                releaseID: releaseID,
                sourceName: sourceName,
                digest: digest,
                kind: safeKind,
                profile: profile,
                token: token
            )
            savePending(RunnerSubmission(
                assetID: assetID,
                releaseID: releaseID,
                sourceName: sourceName,
                analysisName: analysisName,
                submittedAt: Date()
            ))
            status = "Runner queued; waiting for analysis"
            logger.record(ResearchEvent(
                severity: .success,
                subsystem: "runner-bridge",
                message: "Report uploaded and public runner triggered",
                details: [
                    "kind": safeKind,
                    "assetID": String(assetID),
                    "sha256": digest,
                    "sourceName": sourceName,
                ]
            ))
            await pollPending(logger: logger)
        } catch {
            status = "Runner bridge failed: \(error.localizedDescription)"
            logger.record(ResearchEvent(
                severity: .failure,
                subsystem: "runner-bridge",
                message: "Automatic runner submission failed",
                details: ["kind": kind, "error": error.localizedDescription]
            ))
        }
    }

    func resumePending(logger: AuditLogger) async {
        guard isConnected, !isWorking, pending() != nil else { return }
        isWorking = true
        defer { isWorking = false }
        await pollPending(logger: logger)
    }

    private func pollPending(logger: AuditLogger) async {
        guard let token = token(), let submission = pending() else { return }
        for _ in 0..<30 {
            if let asset = try? await findAsset(
                releaseID: submission.releaseID,
                named: submission.analysisName,
                token: token
            ) {
                do {
                    let data = try await download(assetID: asset.id, token: token)
                    let directory = FileManager.default.urls(
                        for: .documentDirectory,
                        in: .userDomainMask
                    )[0].appendingPathComponent("ResearchLogs", isDirectory: true)
                    try FileManager.default.createDirectory(
                        at: directory,
                        withIntermediateDirectories: true
                    )
                    let url = directory.appendingPathComponent("runner-analysis-latest.json")
                    try data.write(to: url, options: .atomic)
                    try? await deleteAsset(assetID: asset.id, token: token)
                    lastResultURL = url
                    status = "Runner analysis received"
                    clearPending()
                    logger.record(ResearchEvent(
                        severity: .success,
                        subsystem: "runner-bridge",
                        message: "Runner analysis downloaded automatically",
                        details: ["assetID": String(asset.id), "file": url.lastPathComponent]
                    ))
                    return
                } catch {
                    status = "Analysis download failed: \(error.localizedDescription)"
                    return
                }
            }
            try? await Task.sleep(for: .seconds(10))
            if Task.isCancelled { return }
        }
        status = "Runner is still processing; the app will check again later"
    }

    private struct Release: Decodable { let id: Int64; let tag_name: String }
    private struct Asset: Decodable { let id: Int64; let name: String }

    private func inboxReleaseID(token: String) async throws -> Int64 {
        let (data, response) = try await request(
            path: "/repos/\(owner)/\(repository)/releases?per_page=100",
            method: "GET",
            token: token
        )
        guard response.statusCode == 200 else {
            throw RunnerBridgeError.invalidResponse(response.statusCode)
        }
        let releases = try JSONDecoder().decode([Release].self, from: data)
        if let existing = releases.first(where: { $0.tag_name == inboxTag }) {
            return existing.id
        }
        let payload: [String: Any] = [
            "tag_name": inboxTag,
            "target_commitish": "main",
            "name": "Aegis27 device report inbox",
            "body": "Unpublished machine-to-machine research report inbox.",
            "draft": true,
            "prerelease": true,
        ]
        let body = try JSONSerialization.data(withJSONObject: payload)
        let (created, createResponse) = try await request(
            path: "/repos/\(owner)/\(repository)/releases",
            method: "POST",
            token: token,
            body: body
        )
        guard createResponse.statusCode == 201 else {
            throw RunnerBridgeError.invalidResponse(createResponse.statusCode)
        }
        return try JSONDecoder().decode(Release.self, from: created).id
    }

    private func upload(
        fileURL: URL,
        name: String,
        releaseID: Int64,
        token: String
    ) async throws -> Int64 {
        var components = URLComponents(
            string: "https://uploads.github.com/repos/\(owner)/\(repository)/releases/\(releaseID)/assets"
        )!
        components.queryItems = [URLQueryItem(name: "name", value: name)]
        var request = URLRequest(url: components.url!)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 600
        let (data, response) = try await session.upload(for: request, fromFile: fileURL)
        guard let http = response as? HTTPURLResponse else {
            throw RunnerBridgeError.malformedResponse
        }
        guard http.statusCode == 201 else {
            throw RunnerBridgeError.invalidResponse(http.statusCode)
        }
        return try JSONDecoder().decode(Asset.self, from: data).id
    }

    private func dispatch(
        assetID: Int64,
        releaseID: Int64,
        sourceName: String,
        digest: String,
        kind: String,
        profile: DeviceProfile,
        token: String
    ) async throws {
        let payload: [String: Any] = [
            "event_type": "aegis27-device-report",
            "client_payload": [
                "asset_id": String(assetID),
                "release_id": String(releaseID),
                "source_name": sourceName,
                "sha256": digest,
                "kind": kind,
                "hardware": profile.hardwareIdentifier,
                "build": profile.buildVersion,
            ],
        ]
        let body = try JSONSerialization.data(withJSONObject: payload)
        let (_, response) = try await request(
            path: "/repos/\(owner)/\(repository)/dispatches",
            method: "POST",
            token: token,
            body: body
        )
        guard response.statusCode == 204 else {
            throw RunnerBridgeError.invalidResponse(response.statusCode)
        }
    }

    private func findAsset(releaseID: Int64, named name: String, token: String) async throws -> Asset? {
        let (data, response) = try await request(
            path: "/repos/\(owner)/\(repository)/releases/\(releaseID)/assets?per_page=100",
            method: "GET",
            token: token
        )
        guard response.statusCode == 200 else {
            throw RunnerBridgeError.invalidResponse(response.statusCode)
        }
        return try JSONDecoder().decode([Asset].self, from: data).first { $0.name == name }
    }

    private func download(assetID: Int64, token: String) async throws -> Data {
        let (data, response) = try await request(
            path: "/repos/\(owner)/\(repository)/releases/assets/\(assetID)",
            method: "GET",
            token: token,
            accept: "application/octet-stream"
        )
        guard response.statusCode == 200 else {
            throw RunnerBridgeError.invalidResponse(response.statusCode)
        }
        return data
    }

    private func deleteAsset(assetID: Int64, token: String) async throws {
        let (_, response) = try await request(
            path: "/repos/\(owner)/\(repository)/releases/assets/\(assetID)",
            method: "DELETE",
            token: token
        )
        guard response.statusCode == 204 else {
            throw RunnerBridgeError.invalidResponse(response.statusCode)
        }
    }

    private func request(
        path: String,
        method: String,
        token: String,
        body: Data? = nil,
        accept: String = "application/vnd.github+json"
    ) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: URL(string: "https://api.github.com\(path)")!)
        request.httpMethod = method
        request.httpBody = body
        request.timeoutInterval = 60
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(accept, forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw RunnerBridgeError.malformedResponse
        }
        return (data, http)
    }

    private func fileSHA256(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let data = try handle.read(upToCount: 1024 * 1024), !data.isEmpty {
            hasher.update(data: data)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private func sanitize(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        let scalars = value.unicodeScalars.map { allowed.contains($0) ? Character(String($0)) : "-" }
        return String(scalars).prefix(48).lowercased()
    }

    private func storeToken(_ token: String) throws {
        disconnect()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: Data(token.utf8),
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    private func token() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private var pendingURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("runner-submission.json")
    }

    private func savePending(_ submission: RunnerSubmission) {
        try? FileManager.default.createDirectory(
            at: pendingURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        if let data = try? JSONEncoder().encode(submission) {
            try? data.write(to: pendingURL, options: .atomic)
        }
    }

    private func pending() -> RunnerSubmission? {
        guard let data = try? Data(contentsOf: pendingURL) else { return nil }
        return try? JSONDecoder().decode(RunnerSubmission.self, from: data)
    }

    private func clearPending() { try? FileManager.default.removeItem(at: pendingURL) }
}
