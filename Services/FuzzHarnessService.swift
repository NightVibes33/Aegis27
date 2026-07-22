import Foundation
import Darwin
import ImageIO

// Every case is journaled before execution and fsynced. If the app is killed,
// crashes, or the device reboots, the unfinished seed is recovered next launch.
enum FuzzJournalStore {
    private static var directoryURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AegisFuzz", isDirectory: true)
    }

    private static var currentURL: URL {
        directoryURL.appendingPathComponent("current-case.json")
    }

    static func pendingIncompleteCase() -> FuzzCaseJournal? {
        guard let data = try? Data(contentsOf: currentURL),
              let value = try? decoder.decode(FuzzCaseJournal.self, from: data),
              value.status == .running else {
            return nil
        }
        return value
    }

    static func recoverAndArchive() -> FuzzCaseJournal? {
        guard let recovered = pendingIncompleteCase() else {
            try? FileManager.default.removeItem(at: currentURL)
            return nil
        }
        try? FileManager.default.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true
        )
        let archive = directoryURL.appendingPathComponent(
            "recovered-\(recovered.id.uuidString).json"
        )
        try? FileManager.default.removeItem(at: archive)
        try? FileManager.default.moveItem(at: currentURL, to: archive)
        return recovered
    }

    static func begin(_ journal: FuzzCaseJournal) throws {
        try writeDurably(journal, to: currentURL)
    }

    static func finish(_ journal: FuzzCaseJournal) {
        var completed = journal
        completed.finishedAt = Date()
        completed.status = .completed
        try? writeDurably(completed, to: currentURL)
        try? FileManager.default.removeItem(at: currentURL)
    }

    static func cancel(_ journal: FuzzCaseJournal) {
        var cancelled = journal
        cancelled.finishedAt = Date()
        cancelled.status = .cancelled
        try? writeDurably(cancelled, to: currentURL)
        try? FileManager.default.removeItem(at: currentURL)
    }

    private static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    private static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    private static func writeDurably<T: Encodable>(_ value: T, to url: URL) throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let data = try encoder.encode(value)
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        try handle.truncate(atOffset: 0)
        try handle.write(contentsOf: data)
        try handle.synchronize()
    }
}

enum FuzzHarnessService {
    typealias ProgressHandler = (Int, Int, FuzzCaseResult) async -> Void

    private struct XPCProbeSnapshot {
        let disposition: XPCProbeDisposition
        let elapsedMilliseconds: Double
        let replyKeyCount: UInt32
        let replyKeyHash: String

        var fingerprint: String {
            "\(disposition.rawValue):\(replyKeyCount):\(replyKeyHash)"
        }
    }

    private struct SplitMix64 {
        var state: UInt64

        mutating func next() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var value = state
            value = (value ^ (value >> 30)) &* 0xBF58476D1CE4E5B9
            value = (value ^ (value >> 27)) &* 0x94D049BB133111EB
            return value ^ (value >> 31)
        }

        mutating func integer(upperBound: Int) -> Int {
            guard upperBound > 0 else { return 0 }
            return Int(next() % UInt64(upperBound))
        }

        mutating func data(count: Int) -> Data {
            var bytes = [UInt8]()
            bytes.reserveCapacity(max(0, count))
            while bytes.count < count {
                var value = next()
                for _ in 0..<8 where bytes.count < count {
                    bytes.append(UInt8(truncatingIfNeeded: value))
                    value >>= 8
                }
            }
            return Data(bytes)
        }
    }

    static func run(
        configuration: FuzzHarnessConfiguration,
        catalog: FirmwareProbeCatalog,
        progress: @escaping ProgressHandler
    ) async -> FuzzHarnessReport {
        let campaignID = UUID()
        let startedAt = Date()
        let recovered = FuzzJournalStore.recoverAndArchive()
        let kinds = configuration.campaignKinds.isEmpty
            ? [FuzzCampaignKind.parserMutation]
            : configuration.campaignKinds
        var results: [FuzzCaseResult] = []
        let corpusRoot = makeCorpusRoot(campaignID: campaignID)
        try? FileManager.default.createDirectory(
            at: corpusRoot,
            withIntermediateDirectories: true
        )

        for caseIndex in 0..<max(1, configuration.iterations) {
            if Task.isCancelled { break }

            let kind = kinds[caseIndex % kinds.count]
            let caseSeed = configuration.seed
                &+ (UInt64(caseIndex) &* 0xD1B54A32D192ED03)
            let journal = FuzzCaseJournal(
                id: UUID(),
                campaignID: campaignID,
                caseIndex: caseIndex,
                caseSeed: caseSeed,
                kind: kind,
                startedAt: Date(),
                finishedAt: nil,
                status: .running
            )

            do {
                try FuzzJournalStore.begin(journal)
            } catch {
                let failed = FuzzCaseResult(
                    caseIndex: caseIndex,
                    caseSeed: caseSeed,
                    kind: kind,
                    label: "journal-write",
                    outcome: .failed,
                    elapsedMilliseconds: 0,
                    inputFingerprint: "0",
                    details: ["error": error.localizedDescription]
                )
                results.append(failed)
                await progress(results.count, configuration.iterations, failed)
                continue
            }

            let result: FuzzCaseResult
            switch kind {
            case .parserMutation:
                result = runParserCase(
                    caseIndex: caseIndex,
                    caseSeed: caseSeed,
                    configuration: configuration
                )
            case .sandboxFileMutation:
                result = runSandboxFileCase(
                    caseIndex: caseIndex,
                    caseSeed: caseSeed,
                    root: corpusRoot,
                    configuration: configuration
                )
            case .xpcSchemaMutation:
                result = runXPCCase(
                    caseIndex: caseIndex,
                    caseSeed: caseSeed,
                    catalog: catalog,
                    configuration: configuration
                )
            }

            if Task.isCancelled {
                FuzzJournalStore.cancel(journal)
                break
            }

            FuzzJournalStore.finish(journal)
            results.append(result)
            await progress(results.count, configuration.iterations, result)
            await Task.yield()
        }

        try? FileManager.default.removeItem(at: corpusRoot)
        return FuzzHarnessReport(
            id: campaignID,
            startedAt: startedAt,
            finishedAt: Date(),
            configuration: configuration,
            recoveredIncompleteCase: recovered,
            cancelled: Task.isCancelled,
            results: results
        )
    }

    private static func runParserCase(
        caseIndex: Int,
        caseSeed: UInt64,
        configuration: FuzzHarnessConfiguration
    ) -> FuzzCaseResult {
        var rng = SplitMix64(state: caseSeed)
        let parserIndex = caseIndex % 4
        let base: Data
        let parserLabel: String

        switch parserIndex {
        case 0:
            base = Data("{\"a\":[1,true,null],\"s\":\"Aegis27\"}".utf8)
            parserLabel = "JSONSerialization"
        case 1:
            base = (try? PropertyListSerialization.data(
                fromPropertyList: ["a": [1, 2, 3], "s": "Aegis27"],
                format: .binary,
                options: 0
            )) ?? Data()
            parserLabel = "PropertyListSerialization"
        case 2:
            base = Data(base64Encoded:
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9WlK0AAAAABJRU5ErkJggg=="
            ) ?? Data()
            parserLabel = "ImageIO"
        default:
            base = (try? NSKeyedArchiver.archivedData(
                withRootObject: ["name": "Aegis27", "values": [1, 2, 3]],
                requiringSecureCoding: false
            )) ?? Data()
            parserLabel = "NSKeyedUnarchiver"
        }

        let mutation = mutate(
            data: base,
            rng: &rng,
            maximumBytes: configuration.maximumInputBytes
        )
        let fingerprint = fnv1a(mutation.data)
        let started = DispatchTime.now().uptimeNanoseconds
        var outcome: FuzzCaseOutcome = .rejected
        var details: [String: String] = [
            "mutation": mutation.label,
            "bytes": String(mutation.data.count)
        ]

        do {
            switch parserIndex {
            case 0:
                _ = try JSONSerialization.jsonObject(with: mutation.data)
                outcome = .accepted
            case 1:
                _ = try PropertyListSerialization.propertyList(
                    from: mutation.data,
                    options: [],
                    format: nil
                )
                outcome = .accepted
            case 2:
                if let source = CGImageSourceCreateWithData(mutation.data as CFData, nil),
                   CGImageSourceGetCount(source) > 0 {
                    _ = CGImageSourceCreateImageAtIndex(source, 0, nil)
                    outcome = .accepted
                } else {
                    outcome = .rejected
                }
            default:
                _ = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(mutation.data)
                outcome = .accepted
            }
        } catch {
            details["error"] = String(error.localizedDescription.prefix(240))
            outcome = .rejected
        }

        let elapsed = milliseconds(since: started)
        if elapsed > Double(configuration.timeoutMilliseconds) {
            outcome = .slow
        }
        details["elapsedLimitMilliseconds"] = String(configuration.timeoutMilliseconds)

        return FuzzCaseResult(
            caseIndex: caseIndex,
            caseSeed: caseSeed,
            kind: .parserMutation,
            label: parserLabel,
            outcome: outcome,
            elapsedMilliseconds: elapsed,
            inputFingerprint: fingerprint,
            details: details
        )
    }

    private static func runSandboxFileCase(
        caseIndex: Int,
        caseSeed: UInt64,
        root: URL,
        configuration: FuzzHarnessConfiguration
    ) -> FuzzCaseResult {
        guard configuration.allowDestructiveSandboxMutations else {
            return FuzzCaseResult(
                caseIndex: caseIndex,
                caseSeed: caseSeed,
                kind: .sandboxFileMutation,
                label: "sandbox mutation disabled",
                outcome: .skipped,
                elapsedMilliseconds: 0,
                inputFingerprint: "0",
                details: ["scope": "Aegis-generated corpus only"]
            )
        }

        var rng = SplitMix64(state: caseSeed)
        let operation = caseIndex % 5
        let caseRoot = root.appendingPathComponent("case-\(caseIndex)", isDirectory: true)
        try? FileManager.default.removeItem(at: caseRoot)
        try? FileManager.default.createDirectory(
            at: caseRoot,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: caseRoot) }

        let started = DispatchTime.now().uptimeNanoseconds
        var details: [String: String] = ["scope": caseRoot.path]
        var label = "file-write-corrupt-delete"
        var outcome: FuzzCaseOutcome = .completed
        let corpus = rng.data(count: min(configuration.maximumInputBytes, 4_096 + rng.integer(upperBound: 32_768)))
        let fingerprint = fnv1a(corpus)

        do {
            switch operation {
            case 0:
                let file = caseRoot.appendingPathComponent("corpus.bin")
                try corpus.write(to: file, options: .atomic)
                let handle = try FileHandle(forWritingTo: file)
                try handle.seek(toOffset: UInt64(corpus.count / 3))
                try handle.write(contentsOf: rng.data(count: min(512, max(1, corpus.count))))
                try handle.synchronize()
                try handle.close()
                _ = try Data(contentsOf: file, options: .mappedIfSafe)
                try FileManager.default.removeItem(at: file)
            case 1:
                label = "file-truncate-reopen"
                let file = caseRoot.appendingPathComponent("truncate.bin")
                try corpus.write(to: file)
                let handle = try FileHandle(forWritingTo: file)
                try handle.truncate(atOffset: UInt64(rng.integer(upperBound: max(1, corpus.count))))
                try handle.synchronize()
                try handle.close()
                _ = try Data(contentsOf: file)
            case 2:
                label = "rename-read-race"
                let first = caseRoot.appendingPathComponent("race-a.bin")
                let second = caseRoot.appendingPathComponent("race-b.bin")
                try corpus.write(to: first)
                let group = DispatchGroup()
                let lock = NSLock()
                var raceErrors = 0
                group.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    defer { group.leave() }
                    for _ in 0..<32 {
                        do {
                            if FileManager.default.fileExists(atPath: first.path) {
                                try FileManager.default.moveItem(at: first, to: second)
                            } else if FileManager.default.fileExists(atPath: second.path) {
                                try FileManager.default.moveItem(at: second, to: first)
                            }
                        } catch {
                            lock.lock(); raceErrors += 1; lock.unlock()
                        }
                    }
                }
                group.enter()
                DispatchQueue.global(qos: .userInitiated).async {
                    defer { group.leave() }
                    for _ in 0..<32 {
                        _ = try? Data(contentsOf: first, options: .mappedIfSafe)
                        _ = try? Data(contentsOf: second, options: .mappedIfSafe)
                    }
                }
                let wait = group.wait(timeout: .now() + 2)
                details["raceErrors"] = String(raceErrors)
                if wait == .timedOut { outcome = .timedOut }
            case 3:
                label = "symlink-no-follow"
                let target = caseRoot.appendingPathComponent("target.bin")
                let link = caseRoot.appendingPathComponent("link.bin")
                try corpus.write(to: target)
                try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
                errno = 0
                let descriptor = open(link.path, O_RDONLY | O_NOFOLLOW)
                let resultErrno = errno
                if descriptor >= 0 { close(descriptor) }
                details["openNoFollow"] = String(descriptor)
                details["errno"] = String(resultErrno)
                _ = try Data(contentsOf: link)
            default:
                label = "directory-churn"
                var current = caseRoot
                for level in 0..<32 {
                    current.appendPathComponent("d\(level)", isDirectory: true)
                    try FileManager.default.createDirectory(
                        at: current,
                        withIntermediateDirectories: false
                    )
                    let leaf = current.appendingPathComponent("leaf.bin")
                    try rng.data(count: 128).write(to: leaf)
                }
                try FileManager.default.removeItem(at: caseRoot)
            }
        } catch {
            details["error"] = String(error.localizedDescription.prefix(240))
            outcome = .failed
        }

        let elapsed = milliseconds(since: started)
        if elapsed > Double(configuration.timeoutMilliseconds) && outcome == .completed {
            outcome = .slow
        }

        return FuzzCaseResult(
            caseIndex: caseIndex,
            caseSeed: caseSeed,
            kind: .sandboxFileMutation,
            label: label,
            outcome: outcome,
            elapsedMilliseconds: elapsed,
            inputFingerprint: fingerprint,
            details: details
        )
    }

    private static func runXPCCase(
        caseIndex: Int,
        caseSeed: UInt64,
        catalog: FirmwareProbeCatalog,
        configuration: FuzzHarnessConfiguration
    ) -> FuzzCaseResult {
        let pairs = catalog.services.flatMap { service in
            service.requests.map { (service, $0) }
        }
        guard !pairs.isEmpty else {
            return FuzzCaseResult(
                caseIndex: caseIndex,
                caseSeed: caseSeed,
                kind: .xpcSchemaMutation,
                label: "no imported XPC schemas",
                outcome: .skipped,
                elapsedMilliseconds: 0,
                inputFingerprint: "0",
                details: ["requirement": "Import a matching firmware probe catalog"]
            )
        }

        var rng = SplitMix64(state: caseSeed)
        let pair = pairs[rng.integer(upperBound: pairs.count)]
        let service = pair.0
        let schema = pair.1
        let lookup = service.service.withCString(aegis_bootstrap_lookup_service)
        guard lookup == 0 else {
            return FuzzCaseResult(
                caseIndex: caseIndex,
                caseSeed: caseSeed,
                kind: .xpcSchemaMutation,
                label: schema.label,
                outcome: .skipped,
                elapsedMilliseconds: 0,
                inputFingerprint: fnv1a(Data(service.service.utf8)),
                details: [
                    "service": service.service,
                    "lookup": String(lookup),
                    "request": schema.id
                ]
            )
        }

        let mutation = mutate(fields: schema.fields, rng: &rng)
        let baseline = probeXPC(
            service: service.service,
            fields: schema.fields,
            timeoutMilliseconds: configuration.timeoutMilliseconds
        )
        let mutated = probeXPC(
            service: service.service,
            fields: mutation.fields,
            timeoutMilliseconds: configuration.timeoutMilliseconds
        )
        let changed = baseline.fingerprint != mutated.fingerprint
        let outcome: FuzzCaseOutcome
        if mutated.disposition == .timedOut {
            outcome = .timedOut
        } else if mutated.disposition == .setupFailed || mutated.disposition == .apiUnavailable {
            outcome = .failed
        } else if changed {
            outcome = .interesting
        } else {
            outcome = .completed
        }

        let fieldSpec = fieldSpecification(mutation.fields)
        return FuzzCaseResult(
            caseIndex: caseIndex,
            caseSeed: caseSeed,
            kind: .xpcSchemaMutation,
            label: "\(schema.label) / \(mutation.label)",
            outcome: outcome,
            elapsedMilliseconds: baseline.elapsedMilliseconds + mutated.elapsedMilliseconds,
            inputFingerprint: fnv1a(Data(fieldSpec.utf8)),
            details: [
                "service": service.service,
                "subsystem": service.subsystem,
                "request": schema.id,
                "baseline": baseline.fingerprint,
                "mutated": mutated.fingerprint,
                "fieldCount": String(mutation.fields.count),
                "replyValuesRetained": "false"
            ]
        )
    }

    private static func probeXPC(
        service: String,
        fields: [XPCProbeField],
        timeoutMilliseconds: UInt32
    ) -> XPCProbeSnapshot {
        var elapsedNanoseconds: UInt64 = 0
        var replyKeyCount: UInt32 = 0
        var replyKeyHash: UInt64 = 0
        let specification = fieldSpecification(fields)
        let raw = service.withCString { name in
            specification.withCString { spec in
                aegis_xpc_dictionary_probe(
                    name,
                    spec,
                    timeoutMilliseconds,
                    &elapsedNanoseconds,
                    &replyKeyCount,
                    &replyKeyHash
                )
            }
        }
        return XPCProbeSnapshot(
            disposition: XPCProbeDisposition(rawValue: raw) ?? .setupFailed,
            elapsedMilliseconds: Double(elapsedNanoseconds) / 1_000_000,
            replyKeyCount: replyKeyCount,
            replyKeyHash: String(replyKeyHash, radix: 16)
        )
    }

    private static func mutate(
        fields: [XPCProbeField],
        rng: inout SplitMix64
    ) -> (fields: [XPCProbeField], label: String) {
        var output = Array(fields.prefix(8))
        let strategy = rng.integer(upperBound: 6)

        if output.isEmpty {
            output = [XPCProbeField(
                key: "request",
                type: .unsignedInteger,
                stringValue: nil,
                unsignedIntegerValue: rng.next(),
                booleanValue: nil
            )]
            return (output, "add-boundary-field")
        }

        let index = rng.integer(upperBound: output.count)
        let original = output[index]
        switch strategy {
        case 0:
            output.remove(at: index)
            return (output, "drop-field")
        case 1:
            output[index] = XPCProbeField(
                key: original.key,
                type: .unsignedInteger,
                stringValue: nil,
                unsignedIntegerValue: [UInt64(0), 1, UInt64.max, 1 << 63][rng.integer(upperBound: 4)],
                booleanValue: nil
            )
            return (output, "integer-boundary")
        case 2:
            output[index] = XPCProbeField(
                key: original.key,
                type: .string,
                stringValue: String(repeating: "A", count: [0, 1, 255, 1024][rng.integer(upperBound: 4)]),
                unsignedIntegerValue: nil,
                booleanValue: nil
            )
            return (output, "string-boundary")
        case 3:
            output[index] = XPCProbeField(
                key: original.key,
                type: .string,
                stringValue: "Aegis-🧪-\(rng.next())",
                unsignedIntegerValue: nil,
                booleanValue: nil
            )
            return (output, "unicode-value")
        case 4:
            output[index] = XPCProbeField(
                key: original.key,
                type: .boolean,
                stringValue: nil,
                unsignedIntegerValue: nil,
                booleanValue: !(original.booleanValue ?? false)
            )
            return (output, "boolean-flip")
        default:
            output.reverse()
            return (output, "field-reorder")
        }
    }

    private static func fieldSpecification(_ fields: [XPCProbeField]) -> String {
        fields.prefix(8).map { field in
            let key = sanitize(field.key, maximumLength: 128)
            switch field.type {
            case .string:
                let value = sanitize(field.stringValue ?? "", maximumLength: 2_048)
                return "s:\(key)=\(value)"
            case .unsignedInteger:
                return "u:\(key)=\(field.unsignedIntegerValue ?? 0)"
            case .boolean:
                return "b:\(key)=\((field.booleanValue ?? false) ? 1 : 0)"
            }
        }.joined(separator: "\n")
    }

    private static func sanitize(_ value: String, maximumLength: Int) -> String {
        let filtered = value.unicodeScalars.filter {
            $0.value != 0 && $0.value != 10 && $0.value != 13 && $0.value != 61
        }
        return String(String.UnicodeScalarView(filtered).prefix(maximumLength))
    }

    private static func mutate(
        data: Data,
        rng: inout SplitMix64,
        maximumBytes: Int
    ) -> (data: Data, label: String) {
        var bytes = [UInt8](data)
        let strategy = rng.integer(upperBound: 5)

        switch strategy {
        case 0:
            if bytes.isEmpty { bytes.append(0) }
            for _ in 0..<min(8, max(1, bytes.count)) {
                let index = rng.integer(upperBound: bytes.count)
                bytes[index] ^= UInt8(truncatingIfNeeded: rng.next()) | 1
            }
            return (Data(bytes.prefix(maximumBytes)), "bit-flip")
        case 1:
            let newCount = rng.integer(upperBound: max(1, bytes.count + 1))
            return (Data(bytes.prefix(newCount)), "truncate")
        case 2:
            let insertionCount = min(maximumBytes, 1 + rng.integer(upperBound: min(4_096, maximumBytes)))
            let insertion = [UInt8](repeating: UInt8(truncatingIfNeeded: rng.next()), count: insertionCount)
            let index = rng.integer(upperBound: bytes.count + 1)
            bytes.insert(contentsOf: insertion, at: index)
            return (Data(bytes.prefix(maximumBytes)), "repeat-insert")
        case 3:
            let replacementCount = min(maximumBytes, max(1, bytes.count / 2))
            bytes = [UInt8](rng.data(count: replacementCount))
            return (Data(bytes), "random-replace")
        default:
            let appendCount = min(maximumBytes - min(maximumBytes, bytes.count), 4_096)
            if appendCount > 0 {
                bytes.append(contentsOf: rng.data(count: appendCount))
            }
            return (Data(bytes.prefix(maximumBytes)), "random-append")
        }
    }

    private static func makeCorpusRoot(campaignID: UUID) -> URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AegisFuzzCorpus", isDirectory: true)
            .appendingPathComponent(campaignID.uuidString, isDirectory: true)
    }

    private static func milliseconds(since started: UInt64) -> Double {
        Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
    }

    private static func fnv1a(_ data: Data) -> String {
        var hash: UInt64 = 1469598103934665603
        for byte in data {
            hash ^= UInt64(byte)
            hash &*= 1099511628211
        }
        return String(hash, radix: 16)
    }
}
