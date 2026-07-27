import Foundation
import CryptoKit
import Security
import SQLite3

private enum CanarySQLite {
    static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
}

@MainActor
final class CanaryBoxViewModel: ObservableObject {
    @Published private(set) var manifest: CanaryManifest?
    @Published private(set) var manifestURL: URL?
    @Published private(set) var verification: [VerificationResult] = []
    @Published private(set) var message = "Generate fresh synthetic canaries before running Aegis Boundary Lab."

    private let bundleIdentifier = "com.nightvibes33.CanaryBox"

    func generate() {
        do {
            let directory = try resetBoundaryDirectory()
            let suffix = UUID().uuidString.lowercased()

            let fileSecret = randomData(count: 64)
            let fileURL = directory.appendingPathComponent("private-canary.bin")
            try fileSecret.write(to: fileURL, options: [.atomic])

            let databaseSecret = randomData(count: 64)
            let databaseURL = directory.appendingPathComponent("canary.sqlite3")
            try createDatabase(at: databaseURL, secret: databaseSecret)

            let preferenceSecret = randomData(count: 64)
            let preferenceKey = "boundary.secret.\(suffix)"
            let preferenceProbeKey = "boundary.probe.\(suffix)"
            UserDefaults.standard.removeObject(forKey: preferenceProbeKey)
            UserDefaults.standard.set(preferenceSecret, forKey: preferenceKey)
            guard UserDefaults.standard.synchronize() else {
                throw NSError(
                    domain: "CanaryBox",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Could not synchronize the synthetic preference secret."]
                )
            }

            let keychainSecret = randomData(count: 64)
            let keychainService = "com.nightvibes33.CanaryBox.boundary.\(suffix)"
            try storeKeychainSecret(
                keychainSecret,
                service: keychainService,
                account: "secret"
            )

            let newManifest = CanaryManifest(
                formatVersion: 1,
                bundleIdentifier: bundleIdentifier,
                generatedAt: Date(),
                file: .init(path: fileURL.path, sha256: sha256(fileSecret)),
                database: .init(path: databaseURL.path, sha256: sha256(databaseSecret)),
                preferences: .init(
                    domain: bundleIdentifier,
                    secretKey: preferenceKey,
                    probeKey: preferenceProbeKey,
                    sha256: sha256(preferenceSecret)
                ),
                keychain: .init(
                    service: keychainService,
                    account: "secret",
                    sha256: sha256(keychainSecret)
                )
            )
            let exportURL = directory.appendingPathComponent("manifest.json")
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            try encoder.encode(newManifest).write(to: exportURL, options: [.atomic])

            manifest = newManifest
            manifestURL = exportURL
            verification = []
            message = "Fresh synthetic canaries generated. Share manifest.json with Aegis27."
        } catch {
            message = error.localizedDescription
        }
    }

    func verify() {
        guard let manifest else {
            message = "Generate canaries first."
            return
        }

        var results: [VerificationResult] = []
        let fileData = try? Data(contentsOf: URL(fileURLWithPath: manifest.file.path))
        results.append(.init(
            label: "Private file secret",
            value: digestState(fileData, expected: manifest.file.sha256),
            changed: fileData.map(sha256) != manifest.file.sha256
        ))

        let probeURL = URL(fileURLWithPath: manifest.file.path)
            .deletingLastPathComponent()
            .appendingPathComponent("aegis-boundary-probe.bin")
        let fileProbeExists = FileManager.default.fileExists(atPath: probeURL.path)
        results.append(.init(
            label: "Private file probe",
            value: fileProbeExists ? "Aegis probe exists" : "No Aegis probe",
            changed: fileProbeExists
        ))

        let databaseData = readDatabaseSecret(at: URL(fileURLWithPath: manifest.database.path))
        results.append(.init(
            label: "SQLite secret",
            value: digestState(databaseData, expected: manifest.database.sha256),
            changed: databaseData.map(sha256) != manifest.database.sha256
        ))

        let databaseProbeExists = hasDatabaseProbe(at: URL(fileURLWithPath: manifest.database.path))
        results.append(.init(
            label: "SQLite probe row",
            value: databaseProbeExists ? "Aegis probe exists" : "No Aegis probe",
            changed: databaseProbeExists
        ))

        let preferenceData = UserDefaults.standard.data(forKey: manifest.preferences.secretKey)
        results.append(.init(
            label: "Preferences secret",
            value: digestState(preferenceData, expected: manifest.preferences.sha256),
            changed: preferenceData.map(sha256) != manifest.preferences.sha256
        ))

        let preferenceProbeExists = UserDefaults.standard.object(
            forKey: manifest.preferences.probeKey
        ) != nil
        results.append(.init(
            label: "Preferences probe",
            value: preferenceProbeExists ? "Aegis probe exists" : "No Aegis probe",
            changed: preferenceProbeExists
        ))

        let keychainData = readKeychainSecret(
            service: manifest.keychain.service,
            account: manifest.keychain.account
        )
        results.append(.init(
            label: "Keychain secret",
            value: digestState(keychainData, expected: manifest.keychain.sha256),
            changed: keychainData.map(sha256) != manifest.keychain.sha256
        ))

        verification = results
        message = results.contains(where: \.changed)
            ? "At least one synthetic CanaryBox boundary changed or became visible. Preserve both reports."
            : "No synthetic CanaryBox boundary change was verified."
    }

    private func resetBoundaryDirectory() throws -> URL {
        let directory = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        )[0].appendingPathComponent("BoundaryCanary", isDirectory: true)
        if FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.removeItem(at: directory)
        }
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return directory
    }

    private func createDatabase(at url: URL, secret: Data) throws {
        var database: OpaquePointer?
        guard sqlite3_open(url.path, &database) == SQLITE_OK, let database else {
            throw sqliteError(database, fallback: "Could not create the synthetic SQLite canary.")
        }
        defer { sqlite3_close(database) }
        guard sqlite3_exec(
            database,
            "CREATE TABLE boundary_canary (id INTEGER PRIMARY KEY, secret BLOB NOT NULL)",
            nil,
            nil,
            nil
        ) == SQLITE_OK else {
            throw sqliteError(database, fallback: "Could not create the synthetic canary table.")
        }

        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            "INSERT INTO boundary_canary (id, secret) VALUES (1, ?)",
            -1,
            &statement,
            nil
        ) == SQLITE_OK else {
            throw sqliteError(database, fallback: "Could not prepare the synthetic canary insert.")
        }
        defer { sqlite3_finalize(statement) }
        let bindStatus = secret.withUnsafeBytes { buffer in
            sqlite3_bind_blob(
                statement,
                1,
                buffer.baseAddress,
                Int32(buffer.count),
                CanarySQLite.transient
            )
        }
        guard bindStatus == SQLITE_OK, sqlite3_step(statement) == SQLITE_DONE else {
            throw sqliteError(database, fallback: "Could not insert the synthetic canary row.")
        }
    }

    private func readDatabaseSecret(at url: URL) -> Data? {
        var database: OpaquePointer?
        guard sqlite3_open_v2(url.path, &database, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let database else {
            return nil
        }
        defer { sqlite3_close(database) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            "SELECT secret FROM boundary_canary WHERE id = 1 LIMIT 1",
            -1,
            &statement,
            nil
        ) == SQLITE_OK else {
            return nil
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW,
              let bytes = sqlite3_column_blob(statement, 0) else {
            return nil
        }
        return Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
    }

    private func hasDatabaseProbe(at url: URL) -> Bool {
        var database: OpaquePointer?
        guard sqlite3_open_v2(url.path, &database, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let database else {
            return false
        }
        defer { sqlite3_close(database) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            database,
            "SELECT value FROM aegis_boundary_probe WHERE id = 1 LIMIT 1",
            -1,
            &statement,
            nil
        ) == SQLITE_OK else {
            return false
        }
        defer { sqlite3_finalize(statement) }
        return sqlite3_step(statement) == SQLITE_ROW
    }

    private func storeKeychainSecret(
        _ data: Data,
        service: String,
        account: String
    ) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        SecItemDelete(query as CFDictionary)
        var item = query
        item[kSecValueData] = data
        item[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(
                domain: NSOSStatusErrorDomain,
                code: Int(status),
                userInfo: [
                    NSLocalizedDescriptionKey:
                        SecCopyErrorMessageString(status, nil) as String? ?? "Could not store the synthetic Keychain canary."
                ]
            )
        }
    }

    private func readKeychainSecret(service: String, account: String) -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: true
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else {
            return nil
        }
        return result as? Data
    }

    private func digestState(_ data: Data?, expected: String) -> String {
        guard let data else { return "Unavailable" }
        return sha256(data) == expected ? "Original hash intact" : "Hash changed"
    }

    private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
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

    private func sqliteError(
        _ database: OpaquePointer?,
        fallback: String
    ) -> NSError {
        let message: String
        if let database, let raw = sqlite3_errmsg(database) {
            message = String(cString: raw)
        } else {
            message = fallback
        }
        return NSError(
            domain: "CanaryBox.SQLite",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}
