import Foundation
import CryptoKit
import Security
import SQLite3

private enum BoundarySQLite {
    static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
}

enum BoundaryLabService {
    static func loadManifest(from url: URL) throws -> BoundaryCanaryManifest {
        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped {
                url.stopAccessingSecurityScopedResource()
            }
        }

        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        guard data.count <= 128 * 1024 else {
            throw BoundaryManifestError.invalidFormat
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(BoundaryCanaryManifest.self, from: data)
        try BoundaryManifestValidator.validate(manifest)
        return manifest
    }

    static func run(
        manifest: BoundaryCanaryManifest
    ) -> (report: BoundaryLabReport, exportURL: URL?) {
        let startedAt = Date()
        var checks: [BoundaryCheckResult] = []

        checks.append(readPrivateFile(manifest.file))
        checks.append(writePrivateFileProbe(manifest.file))
        checks.append(readSQLiteSecret(manifest.database))
        checks.append(writeSQLiteProbe(manifest.database))
        checks.append(readPreferencesSecret(manifest.preferences))
        checks.append(writePreferencesProbe(manifest.preferences))
        checks.append(readKeychainSecret(manifest.keychain))
        checks.append(updateKeychainSecret(manifest.keychain))

        let report = BoundaryLabReport(
            formatVersion: 1,
            startedAt: startedAt,
            finishedAt: Date(),
            sourceBundleIdentifier: manifest.bundleIdentifier,
            sourceGeneratedAt: manifest.generatedAt,
            checks: checks
        )
        return (report, save(report: report))
    }

    private static func readPrivateFile(
        _ canary: BoundaryCanaryManifest.FileCanary
    ) -> BoundaryCheckResult {
        do {
            let data = try Data(
                contentsOf: URL(fileURLWithPath: canary.path),
                options: [.mappedIfSafe]
            )
            let digest = sha256(data)
            return BoundaryCheckResult(
                check: "private-file-read",
                status: digest == canary.sha256 ? .matched : .accessible,
                detail: digest == canary.sha256
                    ? "Read succeeded and the SHA-256 matched the synthetic CanaryBox secret."
                    : "Read succeeded, but the SHA-256 did not match. Raw bytes were discarded."
            )
        } catch {
            return BoundaryCheckResult(
                check: "private-file-read",
                status: .denied,
                detail: error.localizedDescription
            )
        }
    }

    private static func writePrivateFileProbe(
        _ canary: BoundaryCanaryManifest.FileCanary
    ) -> BoundaryCheckResult {
        let directory = URL(fileURLWithPath: canary.path).deletingLastPathComponent()
        let probeURL = directory.appendingPathComponent("aegis-boundary-probe.bin")
        do {
            let payload = randomData(count: 32)
            try payload.write(to: probeURL, options: [.atomic])
            return BoundaryCheckResult(
                check: "private-file-write",
                status: .accessible,
                detail: "Created the fixed synthetic probe file. CanaryBox must independently verify it."
            )
        } catch {
            return BoundaryCheckResult(
                check: "private-file-write",
                status: .denied,
                detail: error.localizedDescription
            )
        }
    }

    private static func readSQLiteSecret(
        _ canary: BoundaryCanaryManifest.DatabaseCanary
    ) -> BoundaryCheckResult {
        var database: OpaquePointer?
        let openStatus = sqlite3_open_v2(
            canary.path,
            &database,
            SQLITE_OPEN_READONLY,
            nil
        )
        defer { if database != nil { sqlite3_close(database) } }
        guard openStatus == SQLITE_OK, let database else {
            return BoundaryCheckResult(
                check: "sqlite-read",
                status: .denied,
                detail: sqliteMessage(database, fallback: "SQLite open denied."),
                osStatus: openStatus
            )
        }

        var statement: OpaquePointer?
        let prepareStatus = sqlite3_prepare_v2(
            database,
            "SELECT secret FROM boundary_canary WHERE id = 1 LIMIT 1",
            -1,
            &statement,
            nil
        )
        defer { if statement != nil { sqlite3_finalize(statement) } }
        guard prepareStatus == SQLITE_OK,
              sqlite3_step(statement) == SQLITE_ROW else {
            return BoundaryCheckResult(
                check: "sqlite-read",
                status: .failed,
                detail: sqliteMessage(database, fallback: "The fixed canary row was unavailable."),
                osStatus: prepareStatus
            )
        }

        let byteCount = Int(sqlite3_column_bytes(statement, 0))
        guard byteCount >= 0,
              let bytes = sqlite3_column_blob(statement, 0) else {
            return BoundaryCheckResult(
                check: "sqlite-read",
                status: .failed,
                detail: "The fixed canary row did not contain a blob."
            )
        }
        let digest = sha256(Data(bytes: bytes, count: byteCount))
        return BoundaryCheckResult(
            check: "sqlite-read",
            status: digest == canary.sha256 ? .matched : .accessible,
            detail: digest == canary.sha256
                ? "SQLite read succeeded and the synthetic secret hash matched."
                : "SQLite read succeeded, but the hash differed. Raw bytes were discarded."
        )
    }

    private static func writeSQLiteProbe(
        _ canary: BoundaryCanaryManifest.DatabaseCanary
    ) -> BoundaryCheckResult {
        var database: OpaquePointer?
        let openStatus = sqlite3_open_v2(
            canary.path,
            &database,
            SQLITE_OPEN_READWRITE,
            nil
        )
        defer { if database != nil { sqlite3_close(database) } }
        guard openStatus == SQLITE_OK, let database else {
            return BoundaryCheckResult(
                check: "sqlite-write",
                status: .denied,
                detail: sqliteMessage(database, fallback: "SQLite write-open denied."),
                osStatus: openStatus
            )
        }

        let schemaStatus = sqlite3_exec(
            database,
            "CREATE TABLE IF NOT EXISTS aegis_boundary_probe (id INTEGER PRIMARY KEY, value BLOB NOT NULL)",
            nil,
            nil,
            nil
        )
        guard schemaStatus == SQLITE_OK else {
            return BoundaryCheckResult(
                check: "sqlite-write",
                status: .failed,
                detail: sqliteMessage(database, fallback: "Could not create the fixed probe table."),
                osStatus: schemaStatus
            )
        }

        var statement: OpaquePointer?
        let prepareStatus = sqlite3_prepare_v2(
            database,
            "INSERT OR REPLACE INTO aegis_boundary_probe (id, value) VALUES (1, ?)",
            -1,
            &statement,
            nil
        )
        defer { if statement != nil { sqlite3_finalize(statement) } }
        guard prepareStatus == SQLITE_OK else {
            return BoundaryCheckResult(
                check: "sqlite-write",
                status: .failed,
                detail: sqliteMessage(database, fallback: "Could not prepare the fixed probe insert."),
                osStatus: prepareStatus
            )
        }

        let payload = randomData(count: 32)
        let bindStatus = payload.withUnsafeBytes { buffer in
            sqlite3_bind_blob(
                statement,
                1,
                buffer.baseAddress,
                Int32(buffer.count),
                BoundarySQLite.transient
            )
        }
        guard bindStatus == SQLITE_OK else {
            return BoundaryCheckResult(
                check: "sqlite-write",
                status: .failed,
                detail: sqliteMessage(database, fallback: "Could not bind the fixed probe payload."),
                osStatus: bindStatus
            )
        }
        let stepStatus = sqlite3_step(statement)
        return BoundaryCheckResult(
            check: "sqlite-write",
            status: stepStatus == SQLITE_DONE ? .accessible : .failed,
            detail: stepStatus == SQLITE_DONE
                ? "The fixed synthetic probe row was inserted. CanaryBox must independently verify it."
                : sqliteMessage(database, fallback: "The fixed probe insert failed."),
            osStatus: stepStatus
        )
    }

    private static func readPreferencesSecret(
        _ canary: BoundaryCanaryManifest.PreferencesCanary
    ) -> BoundaryCheckResult {
        guard let value = CFPreferencesCopyAppValue(
            canary.secretKey as CFString,
            canary.domain as CFString
        ) else {
            return BoundaryCheckResult(
                check: "preferences-read",
                status: .denied,
                detail: "The CanaryBox preference value was unavailable."
            )
        }

        let data: Data?
        if let raw = value as? Data {
            data = raw
        } else if let text = value as? String {
            data = Data(text.utf8)
        } else {
            data = nil
        }
        guard let data else {
            return BoundaryCheckResult(
                check: "preferences-read",
                status: .failed,
                detail: "The preference existed but was not a supported synthetic value type."
            )
        }
        let digest = sha256(data)
        return BoundaryCheckResult(
            check: "preferences-read",
            status: digest == canary.sha256 ? .matched : .accessible,
            detail: digest == canary.sha256
                ? "Cross-domain preference read succeeded and the hash matched."
                : "Cross-domain preference read succeeded, but the hash differed. Raw data was discarded."
        )
    }

    private static func writePreferencesProbe(
        _ canary: BoundaryCanaryManifest.PreferencesCanary
    ) -> BoundaryCheckResult {
        let marker = "aegis-probe-\(UUID().uuidString)"
        CFPreferencesSetAppValue(
            canary.probeKey as CFString,
            marker as CFString,
            canary.domain as CFString
        )
        let synchronized = CFPreferencesAppSynchronize(canary.domain as CFString)
        return BoundaryCheckResult(
            check: "preferences-write",
            status: synchronized ? .accessible : .denied,
            detail: synchronized
                ? "The fixed synthetic preference probe synchronized. CanaryBox must independently verify it."
                : "The cross-domain preference probe did not synchronize."
        )
    }

    private static func readKeychainSecret(
        _ canary: BoundaryCanaryManifest.KeychainCanary
    ) -> BoundaryCheckResult {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: canary.service,
            kSecAttrAccount: canary.account,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return BoundaryCheckResult(
                check: "keychain-read",
                status: .denied,
                detail: SecCopyErrorMessageString(status, nil) as String? ?? "Keychain read denied.",
                osStatus: status
            )
        }
        let digest = sha256(data)
        return BoundaryCheckResult(
            check: "keychain-read",
            status: digest == canary.sha256 ? .matched : .accessible,
            detail: digest == canary.sha256
                ? "Keychain read succeeded and the synthetic secret hash matched."
                : "Keychain read succeeded, but the hash differed. Raw data was discarded.",
            osStatus: status
        )
    }

    private static func updateKeychainSecret(
        _ canary: BoundaryCanaryManifest.KeychainCanary
    ) -> BoundaryCheckResult {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: canary.service,
            kSecAttrAccount: canary.account
        ]
        let attributes: [CFString: Any] = [
            kSecValueData: randomData(count: 32)
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        return BoundaryCheckResult(
            check: "keychain-update",
            status: status == errSecSuccess ? .accessible : .denied,
            detail: status == errSecSuccess
                ? "The synthetic Keychain item update returned success. CanaryBox must independently verify it."
                : (SecCopyErrorMessageString(status, nil) as String? ?? "Keychain update denied."),
            osStatus: status
        )
    }

    private static func save(report: BoundaryLabReport) -> URL? {
        do {
            let directory = FileManager.default.urls(
                for: .documentDirectory,
                in: .userDomainMask
            )[0].appendingPathComponent("ResearchLogs", isDirectory: true)
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true
            )
            let url = directory.appendingPathComponent("boundary-lab-latest.json")
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            try encoder.encode(report).write(to: url, options: [.atomic])
            return url
        } catch {
            return nil
        }
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func randomData(count: Int) -> Data {
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

    private static func sqliteMessage(
        _ database: OpaquePointer?,
        fallback: String
    ) -> String {
        guard let database, let message = sqlite3_errmsg(database) else {
            return fallback
        }
        return String(cString: message)
    }
}
