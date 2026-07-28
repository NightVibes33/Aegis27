import Foundation
import CryptoKit
import ImageIO

private enum CrashTriageLimits {
    static let maximumCorpusBytes = 4 * 1024 * 1024
    static let maximumCrashLogBytes = 8 * 1024 * 1024
    static let slowCaseMilliseconds = 1_250.0
    static let retainedResults = 500
    static let maximumMinimizationAttemptsPerResume = 500
}

private struct CrashSplitMix64 {
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

    mutating func byte() -> UInt8 {
        UInt8(truncatingIfNeeded: next())
    }

    mutating func data(count: Int) -> Data {
        var output = Data()
        output.reserveCapacity(max(0, count))
        while output.count < count {
            var value = next()
            for _ in 0..<8 where output.count < count {
                output.append(UInt8(truncatingIfNeeded: value))
                value >>= 8
            }
        }
        return output
    }
}

enum CrashTriageStore {
    private static var rootURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AegisCrashTriage", isDirectory: true)
    }

    static var corpusURL: URL { rootURL.appendingPathComponent("Corpus", isDirectory: true) }
    static var casesURL: URL { rootURL.appendingPathComponent("Cases", isDirectory: true) }
    static var crashLogsURL: URL { rootURL.appendingPathComponent("CrashLogs", isDirectory: true) }
    static var minimizationURL: URL { rootURL.appendingPathComponent("Minimization", isDirectory: true) }
    static var exportsURL: URL { rootURL.appendingPathComponent("Exports", isDirectory: true) }

    private static var corpusIndexURL: URL { rootURL.appendingPathComponent("corpus-index.json") }
    private static var resultsIndexURL: URL { rootURL.appendingPathComponent("case-results.json") }
    private static var crashLogIndexURL: URL { rootURL.appendingPathComponent("crash-logs.json") }
    private static var findingsIndexURL: URL { rootURL.appendingPathComponent("findings.json") }
    private static var pendingCaseURL: URL { rootURL.appendingPathComponent("pending-case.json") }
    private static var minimizationIndexURL: URL { rootURL.appendingPathComponent("minimization-session.json") }

    static func prepareDirectories() throws {
        for url in [rootURL, corpusURL, casesURL, crashLogsURL, minimizationURL, exportsURL] {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        }
    }

    static func loadCorpus() -> [CrashCorpusItem] {
        load([CrashCorpusItem].self, from: corpusIndexURL) ?? []
    }

    static func saveCorpus(_ values: [CrashCorpusItem]) throws {
        try writeDurably(values, to: corpusIndexURL)
    }

    static func loadResults() -> [CrashCaseResult] {
        load([CrashCaseResult].self, from: resultsIndexURL) ?? []
    }

    static func appendResult(_ value: CrashCaseResult) throws {
        var values = loadResults()
        values.insert(value, at: 0)
        if values.count > CrashTriageLimits.retainedResults {
            values = Array(values.prefix(CrashTriageLimits.retainedResults))
        }
        try writeDurably(values, to: resultsIndexURL)
    }

    static func loadCrashLogs() -> [ImportedCrashLog] {
        load([ImportedCrashLog].self, from: crashLogIndexURL) ?? []
    }

    static func saveCrashLogs(_ values: [ImportedCrashLog]) throws {
        try writeDurably(values, to: crashLogIndexURL)
    }

    static func loadFindings() -> [CrashFinding] {
        load([CrashFinding].self, from: findingsIndexURL) ?? []
    }

    static func saveFindings(_ values: [CrashFinding]) throws {
        try writeDurably(values, to: findingsIndexURL)
    }

    static func pendingCase() -> CrashCaseJournal? {
        guard let value = load(CrashCaseJournal.self, from: pendingCaseURL), value.status == .running else {
            return nil
        }
        return value
    }

    static func beginCase(_ value: CrashCaseJournal) throws {
        try writeDurably(value, to: pendingCaseURL)
    }

    static func finishCase(_ value: CrashCaseJournal, status: CrashCaseStatus) {
        var completed = value
        completed.status = status
        completed.finishedAt = Date()
        try? writeDurably(completed, to: pendingCaseURL)
        try? FileManager.default.removeItem(at: pendingCaseURL)
    }

    static func discardPendingCase() {
        guard var pending = pendingCase() else { return }
        pending.status = .discarded
        pending.finishedAt = Date()
        let archive = casesURL.appendingPathComponent("discarded-\(pending.id.uuidString).json")
        try? writeDurably(pending, to: archive)
        try? FileManager.default.removeItem(at: pendingCaseURL)
    }

    static func archiveRecoveredCase(_ value: CrashCaseJournal) {
        var recovered = value
        recovered.status = .recoveredTermination
        recovered.finishedAt = Date()
        let archive = casesURL.appendingPathComponent("recovered-\(recovered.id.uuidString).json")
        try? writeDurably(recovered, to: archive)
        try? FileManager.default.removeItem(at: pendingCaseURL)
    }

    static func loadMinimization() -> CrashMinimizationSession? {
        load(CrashMinimizationSession.self, from: minimizationIndexURL)
    }

    static func saveMinimization(_ value: CrashMinimizationSession) throws {
        try writeDurably(value, to: minimizationIndexURL)
    }

    static func clearMinimization() {
        try? FileManager.default.removeItem(at: minimizationIndexURL)
    }

    static func corpusFileURL(_ item: CrashCorpusItem) -> URL {
        corpusURL.appendingPathComponent(item.storedFileName)
    }

    static func caseFileURL(_ fileName: String) -> URL {
        casesURL.appendingPathComponent(fileName)
    }

    static func minimizationFileURL(_ fileName: String) -> URL {
        minimizationURL.appendingPathComponent(fileName)
    }

    static func exportURL() -> URL {
        exportsURL.appendingPathComponent("crash-triage-latest.json")
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

    private static func load<T: Decodable>(_ type: T.Type, from url: URL) -> T? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? decoder.decode(type, from: data)
    }

    static func writeDurably<T: Encodable>(_ value: T, to url: URL) throws {
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

enum CrashTriageService {
    typealias CampaignProgress = (Int, Int, CrashCaseResult) async -> Void
    typealias MinimizationProgress = (CrashMinimizationSession) async -> Void

    static func importCorpus(from url: URL) throws -> CrashCorpusItem {
        try CrashTriageStore.prepareDirectories()
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        guard !data.isEmpty, data.count <= CrashTriageLimits.maximumCorpusBytes else {
            throw NSError(
                domain: "AegisCrashTriage",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Corpus files must be between 1 byte and 4 MB."]
            )
        }

        let ext = url.pathExtension.lowercased()
        let allowed = [
            "png", "jpg", "jpeg", "gif", "heic", "heif", "webp", "tif", "tiff", "bmp",
            "plist", "bplist", "archive", "keyedarchive", "bin", "dat"
        ]
        guard allowed.contains(ext) else {
            throw NSError(
                domain: "AegisCrashTriage",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Unsupported corpus type. Import an image, plist, keyed archive, .bin, or .dat file."]
            )
        }

        let digest = sha256(data)
        var corpus = CrashTriageStore.loadCorpus()
        if let existing = corpus.first(where: { $0.sha256 == digest }) {
            return existing
        }

        let id = UUID()
        let storedName = id.uuidString + (ext.isEmpty ? ".bin" : ".\(ext)")
        let destination = CrashTriageStore.corpusURL.appendingPathComponent(storedName)
        try data.write(to: destination, options: [.atomic])

        let item = CrashCorpusItem(
            id: id,
            importedAt: Date(),
            originalFileName: url.lastPathComponent,
            storedFileName: storedName,
            byteCount: data.count,
            sha256: digest,
            suggestedParser: suggestedParser(forExtension: ext)
        )
        corpus.insert(item, at: 0)
        try CrashTriageStore.saveCorpus(corpus)
        return item
    }

    static func deleteCorpus(_ item: CrashCorpusItem) throws {
        var corpus = CrashTriageStore.loadCorpus()
        corpus.removeAll { $0.id == item.id }
        try? FileManager.default.removeItem(at: CrashTriageStore.corpusFileURL(item))
        try CrashTriageStore.saveCorpus(corpus)
    }

    static func runCampaign(
        corpus: CrashCorpusItem,
        parser: CrashTriageParser,
        seed: UInt64,
        iterations: Int,
        deviceDescription: String,
        progress: @escaping CampaignProgress
    ) async throws {
        try CrashTriageStore.prepareDirectories()
        let source = try Data(contentsOf: CrashTriageStore.corpusFileURL(corpus), options: [.mappedIfSafe])
        let campaignID = UUID()
        let total = min(max(1, iterations), 300)

        for index in 0..<total {
            if Task.isCancelled { break }
            let caseSeed = seed &+ (UInt64(index) &* 0xD1B54A32D192ED03)
            let mutation = mutate(source, seed: caseSeed, maximumBytes: CrashTriageLimits.maximumCorpusBytes)
            let caseID = UUID()
            let inputFileName = "case-\(caseID.uuidString).bin"
            let inputURL = CrashTriageStore.caseFileURL(inputFileName)
            try mutation.data.write(to: inputURL, options: [.atomic])

            let journal = CrashCaseJournal(
                id: caseID,
                campaignID: campaignID,
                sourceCorpusID: corpus.id,
                sourceSHA256: corpus.sha256,
                parser: parser,
                caseIndex: index,
                seed: caseSeed,
                inputFileName: inputFileName,
                inputSHA256: sha256(mutation.data),
                inputByteCount: mutation.data.count,
                operations: mutation.operations,
                deviceDescription: deviceDescription,
                startedAt: Date(),
                finishedAt: nil,
                status: .running,
                minimizationSessionID: nil
            )
            try CrashTriageStore.beginCase(journal)

            let execution = executeParser(mutation.data, parser: parser)
            CrashTriageStore.finishCase(journal, status: .survived)
            let result = CrashCaseResult(
                journal: journal,
                outcome: execution.outcome,
                elapsedMilliseconds: execution.elapsedMilliseconds,
                detail: execution.detail
            )
            try CrashTriageStore.appendResult(result)

            if !result.outcome.isInteresting {
                try? FileManager.default.removeItem(at: inputURL)
            }
            await progress(index + 1, total, result)
            await Task.yield()
        }
    }

    static func replay(
        _ result: CrashCaseResult,
        corpus: CrashCorpusItem,
        deviceDescription: String
    ) async throws -> CrashCaseResult {
        let source = try Data(contentsOf: CrashTriageStore.corpusFileURL(corpus), options: [.mappedIfSafe])
        let regenerated = mutate(source, seed: result.seed, maximumBytes: CrashTriageLimits.maximumCorpusBytes)
        let replayData = regenerated.data
        guard sha256(replayData) == result.inputSHA256 else {
            throw NSError(
                domain: "AegisCrashTriage",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Replay regeneration did not match the recorded SHA-256."]
            )
        }

        let caseID = UUID()
        let fileName = "replay-\(caseID.uuidString).bin"
        let fileURL = CrashTriageStore.caseFileURL(fileName)
        try replayData.write(to: fileURL, options: [.atomic])
        let journal = CrashCaseJournal(
            id: caseID,
            campaignID: result.campaignID,
            sourceCorpusID: corpus.id,
            sourceSHA256: corpus.sha256,
            parser: result.parser,
            caseIndex: result.caseIndex,
            seed: result.seed,
            inputFileName: fileName,
            inputSHA256: result.inputSHA256,
            inputByteCount: replayData.count,
            operations: result.operations,
            deviceDescription: deviceDescription,
            startedAt: Date(),
            finishedAt: nil,
            status: .running,
            minimizationSessionID: nil
        )
        try CrashTriageStore.beginCase(journal)
        let execution = executeParser(replayData, parser: result.parser)
        CrashTriageStore.finishCase(journal, status: .survived)
        let replayResult = CrashCaseResult(
            journal: journal,
            outcome: execution.outcome,
            elapsedMilliseconds: execution.elapsedMilliseconds,
            detail: "Replay: \(execution.detail)"
        )
        try CrashTriageStore.appendResult(replayResult)
        if !replayResult.outcome.isInteresting {
            try? FileManager.default.removeItem(at: fileURL)
        }
        return replayResult
    }

    static func importCrashLog(
        from url: URL,
        correlatedCase: CrashCaseJournal?
    ) throws -> ImportedCrashLog {
        try CrashTriageStore.prepareDirectories()
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        guard !data.isEmpty, data.count <= CrashTriageLimits.maximumCrashLogBytes else {
            throw NSError(
                domain: "AegisCrashTriage",
                code: 4,
                userInfo: [NSLocalizedDescriptionKey: "Crash logs must be between 1 byte and 8 MB."]
            )
        }
        guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .ascii) else {
            throw NSError(
                domain: "AegisCrashTriage",
                code: 5,
                userInfo: [NSLocalizedDescriptionKey: "The selected crash log is not readable text."]
            )
        }

        let parsed = parseCrashLog(text)
        let id = UUID()
        let ext = url.pathExtension.isEmpty ? "ips" : url.pathExtension
        let storedName = "\(id.uuidString).\(ext)"
        try data.write(to: CrashTriageStore.crashLogsURL.appendingPathComponent(storedName), options: [.atomic])
        let log = ImportedCrashLog(
            id: id,
            importedAt: Date(),
            originalFileName: url.lastPathComponent,
            storedFileName: storedName,
            byteCount: data.count,
            sha256: sha256(data),
            processName: parsed.processName,
            exceptionType: parsed.exceptionType,
            terminationReason: parsed.terminationReason,
            incidentIdentifier: parsed.incidentIdentifier,
            operatingSystem: parsed.operatingSystem,
            topFrames: parsed.topFrames,
            signature: parsed.signature,
            classification: parsed.classification,
            correlatedJournalID: correlatedCase?.id
        )

        var logs = CrashTriageStore.loadCrashLogs()
        logs.insert(log, at: 0)
        try CrashTriageStore.saveCrashLogs(logs)
        try mergeFinding(for: log)
        return log
    }

    static func prepareMinimization(from journal: CrashCaseJournal) throws -> CrashMinimizationSession {
        try CrashTriageStore.prepareDirectories()
        let sourceURL = CrashTriageStore.caseFileURL(journal.inputFileName)
        let data = try Data(contentsOf: sourceURL, options: [.mappedIfSafe])
        guard sha256(data) == journal.inputSHA256 else {
            throw NSError(
                domain: "AegisCrashTriage",
                code: 6,
                userInfo: [NSLocalizedDescriptionKey: "Recovered testcase SHA-256 no longer matches its journal."]
            )
        }

        let sessionID = UUID()
        let currentName = "min-current-\(sessionID.uuidString).bin"
        try data.write(to: CrashTriageStore.minimizationFileURL(currentName), options: [.atomic])
        let session = CrashMinimizationSession(
            id: sessionID,
            sourceJournalID: journal.id,
            sourceCorpusID: journal.sourceCorpusID,
            parser: journal.parser,
            originalFileName: journal.inputFileName,
            currentFileName: currentName,
            currentSHA256: journal.inputSHA256,
            originalByteCount: data.count,
            currentByteCount: data.count,
            chunkSize: max(1, data.count / 2),
            nextOffset: 0,
            attempts: 0,
            reproducedCount: 0,
            lastCandidateFileName: nil,
            status: .active,
            updatedAt: Date()
        )
        CrashTriageStore.archiveRecoveredCase(journal)
        try CrashTriageStore.saveMinimization(session)
        return session
    }

    static func resumeMinimization(
        _ initial: CrashMinimizationSession,
        assumingPendingCandidateCrashed: Bool,
        deviceDescription: String,
        progress: @escaping MinimizationProgress
    ) async throws -> CrashMinimizationSession {
        var session = initial
        try CrashTriageStore.prepareDirectories()

        if let pending = CrashTriageStore.pendingCase(), pending.minimizationSessionID == session.id {
            if assumingPendingCandidateCrashed {
                let candidateURL = CrashTriageStore.caseFileURL(pending.inputFileName)
                let candidate = try Data(contentsOf: candidateURL, options: [.mappedIfSafe])
                let currentURL = CrashTriageStore.minimizationFileURL(session.currentFileName)
                try candidate.write(to: currentURL, options: [.atomic])
                session.currentSHA256 = sha256(candidate)
                session.currentByteCount = candidate.count
                session.reproducedCount += 1
                session.nextOffset = 0
                session.chunkSize = max(1, min(session.chunkSize, max(1, candidate.count / 2)))
                CrashTriageStore.archiveRecoveredCase(pending)
            } else {
                session.nextOffset += max(1, session.chunkSize)
                CrashTriageStore.discardPendingCase()
            }
            session.status = .active
            session.lastCandidateFileName = nil
            session.updatedAt = Date()
            try CrashTriageStore.saveMinimization(session)
        }

        var attemptsThisResume = 0
        while session.status == .active && attemptsThisResume < CrashTriageLimits.maximumMinimizationAttemptsPerResume {
            if Task.isCancelled { break }
            let currentURL = CrashTriageStore.minimizationFileURL(session.currentFileName)
            let current = try Data(contentsOf: currentURL, options: [.mappedIfSafe])

            if current.count <= 32 {
                session.status = .completed
                break
            }
            if session.nextOffset >= current.count {
                if session.chunkSize <= 1 {
                    session.status = .completed
                    break
                }
                session.chunkSize = max(1, session.chunkSize / 2)
                session.nextOffset = 0
                continue
            }

            let end = min(current.count, session.nextOffset + max(1, session.chunkSize))
            guard session.nextOffset < end else {
                session.status = .stalled
                break
            }
            var candidate = current
            candidate.removeSubrange(session.nextOffset..<end)
            if candidate.isEmpty || candidate.count == current.count {
                session.nextOffset = end
                continue
            }

            let caseID = UUID()
            let candidateName = "min-candidate-\(caseID.uuidString).bin"
            let candidateURL = CrashTriageStore.caseFileURL(candidateName)
            try candidate.write(to: candidateURL, options: [.atomic])
            let operation = CrashMutationOperation(
                kind: .deleteRange,
                offset: session.nextOffset,
                length: end - session.nextOffset,
                value: nil
            )
            let journal = CrashCaseJournal(
                id: caseID,
                campaignID: session.id,
                sourceCorpusID: session.sourceCorpusID,
                sourceSHA256: session.currentSHA256,
                parser: session.parser,
                caseIndex: session.attempts,
                seed: UInt64(session.attempts),
                inputFileName: candidateName,
                inputSHA256: sha256(candidate),
                inputByteCount: candidate.count,
                operations: [operation],
                deviceDescription: deviceDescription,
                startedAt: Date(),
                finishedAt: nil,
                status: .running,
                minimizationSessionID: session.id
            )

            session.attempts += 1
            attemptsThisResume += 1
            session.lastCandidateFileName = candidateName
            session.status = .awaitingRelaunch
            session.updatedAt = Date()
            try CrashTriageStore.saveMinimization(session)
            try CrashTriageStore.beginCase(journal)
            await progress(session)

            _ = executeParser(candidate, parser: session.parser)

            CrashTriageStore.finishCase(journal, status: .survived)
            try? FileManager.default.removeItem(at: candidateURL)
            session.status = .active
            session.lastCandidateFileName = nil
            session.nextOffset += max(1, session.chunkSize)
            session.updatedAt = Date()
            try CrashTriageStore.saveMinimization(session)
            await progress(session)
            await Task.yield()
        }

        session.updatedAt = Date()
        try CrashTriageStore.saveMinimization(session)
        return session
    }

    static func minimizedFileURL(_ session: CrashMinimizationSession) -> URL? {
        guard session.status == .completed || session.reproducedCount > 0 else { return nil }
        return CrashTriageStore.minimizationFileURL(session.currentFileName)
    }

    static func exportSnapshot() throws -> URL {
        try CrashTriageStore.prepareDirectories()
        let snapshot = CrashTriageExport(
            formatVersion: 1,
            generatedAt: Date(),
            corpus: CrashTriageStore.loadCorpus(),
            recentCases: CrashTriageStore.loadResults(),
            importedCrashLogs: CrashTriageStore.loadCrashLogs(),
            findings: CrashTriageStore.loadFindings(),
            pendingCase: CrashTriageStore.pendingCase(),
            minimization: CrashTriageStore.loadMinimization()
        )
        let url = CrashTriageStore.exportURL()
        try CrashTriageStore.writeDurably(snapshot, to: url)
        return url
    }

    private static func suggestedParser(forExtension ext: String) -> CrashTriageParser {
        if ["png", "jpg", "jpeg", "gif", "heic", "heif", "webp", "tif", "tiff", "bmp"].contains(ext) {
            return .imageIO
        }
        if ["plist", "bplist"].contains(ext) {
            return .propertyList
        }
        return .keyedArchive
    }

    private static func mutate(
        _ source: Data,
        seed: UInt64,
        maximumBytes: Int
    ) -> (data: Data, operations: [CrashMutationOperation]) {
        var rng = CrashSplitMix64(state: seed)
        var data = source
        var operations: [CrashMutationOperation] = []
        let operationCount = 1 + rng.integer(upperBound: 6)

        for _ in 0..<operationCount {
            let kind = CrashMutationKind.allCases[rng.integer(upperBound: CrashMutationKind.allCases.count)]
            guard !data.isEmpty else {
                let inserted = rng.data(count: 1 + rng.integer(upperBound: 32))
                data.append(inserted)
                operations.append(.init(kind: .insert, offset: 0, length: inserted.count, value: nil))
                continue
            }

            switch kind {
            case .bitFlip:
                let offset = rng.integer(upperBound: data.count)
                let bit = UInt8(1 << rng.integer(upperBound: 8))
                data[offset] ^= bit
                operations.append(.init(kind: kind, offset: offset, length: 1, value: bit))
            case .overwrite:
                let offset = rng.integer(upperBound: data.count)
                let length = min(data.count - offset, 1 + rng.integer(upperBound: 64))
                let byte = rng.byte()
                data.replaceSubrange(offset..<(offset + length), with: repeatElement(byte, count: length))
                operations.append(.init(kind: kind, offset: offset, length: length, value: byte))
            case .insert:
                guard data.count < maximumBytes else { continue }
                let offset = rng.integer(upperBound: data.count + 1)
                let length = min(maximumBytes - data.count, 1 + rng.integer(upperBound: 128))
                let inserted = rng.data(count: length)
                data.insert(contentsOf: inserted, at: offset)
                operations.append(.init(kind: kind, offset: offset, length: length, value: nil))
            case .deleteRange:
                guard data.count > 1 else { continue }
                let offset = rng.integer(upperBound: data.count)
                let length = min(data.count - offset, 1 + rng.integer(upperBound: min(256, data.count)))
                data.removeSubrange(offset..<(offset + length))
                operations.append(.init(kind: kind, offset: offset, length: length, value: nil))
            case .truncate:
                guard data.count > 1 else { continue }
                let newCount = rng.integer(upperBound: data.count)
                let removed = data.count - newCount
                data.removeSubrange(newCount..<data.count)
                operations.append(.init(kind: kind, offset: newCount, length: removed, value: nil))
            case .duplicateSlice:
                guard data.count < maximumBytes else { continue }
                let sourceOffset = rng.integer(upperBound: data.count)
                let length = min(
                    min(data.count - sourceOffset, maximumBytes - data.count),
                    1 + rng.integer(upperBound: min(128, data.count))
                )
                guard length > 0 else { continue }
                let slice = data.subdata(in: sourceOffset..<(sourceOffset + length))
                let destination = rng.integer(upperBound: data.count + 1)
                data.insert(contentsOf: slice, at: destination)
                operations.append(.init(kind: kind, offset: destination, length: length, value: nil))
            }
        }
        return (data, operations)
    }

    private static func executeParser(
        _ data: Data,
        parser: CrashTriageParser
    ) -> (outcome: CrashCaseOutcome, elapsedMilliseconds: Double, detail: String) {
        let started = DispatchTime.now().uptimeNanoseconds
        var outcome: CrashCaseOutcome = .rejected
        var detail = "Parser rejected the input."

        do {
            switch parser {
            case .imageIO:
                if let source = CGImageSourceCreateWithData(data as CFData, nil), CGImageSourceGetCount(source) > 0 {
                    _ = CGImageSourceCopyPropertiesAtIndex(source, 0, nil)
                    let options: [CFString: Any] = [
                        kCGImageSourceCreateThumbnailFromImageAlways: true,
                        kCGImageSourceThumbnailMaxPixelSize: 2048,
                        kCGImageSourceShouldCacheImmediately: true
                    ]
                    _ = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary)
                    outcome = .accepted
                    detail = "ImageIO created a source and attempted a bounded thumbnail decode."
                }
            case .propertyList:
                _ = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                outcome = .accepted
                detail = "PropertyListSerialization accepted the input."
            case .keyedArchive:
                _ = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
                outcome = .accepted
                detail = "NSKeyedUnarchiver accepted the input."
            }
        } catch {
            outcome = .rejected
            detail = String(error.localizedDescription.prefix(300))
        }

        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
        if elapsed >= CrashTriageLimits.slowCaseMilliseconds {
            outcome = .slow
            detail = "Parser returned after \(String(format: "%.1f", elapsed)) ms. \(detail)"
        }
        return (outcome, elapsed, detail)
    }

    private struct ParsedCrashLog {
        let processName: String
        let exceptionType: String
        let terminationReason: String
        let incidentIdentifier: String
        let operatingSystem: String
        let topFrames: [String]
        let signature: String
        let classification: CrashFindingClassification
    }

    private static func parseCrashLog(_ text: String) -> ParsedCrashLog {
        let process = firstMatch(in: text, patterns: [
            #"\"procName\"\s*:\s*\"([^\"]+)\""#,
            #"(?m)^Process:\s*([^\[\n]+)"#,
            #"\"process\"\s*:\s*\"([^\"]+)\""#
        ]) ?? "Unknown"
        let exception = firstMatch(in: text, patterns: [
            #"\"exceptionType\"\s*:\s*\"([^\"]+)\""#,
            #"(?m)^Exception Type:\s*([^\n]+)"#,
            #"\"signal\"\s*:\s*\"([^\"]+)\""#
        ]) ?? "Unknown"
        let termination = firstMatch(in: text, patterns: [
            #"(?m)^Termination Reason:\s*([^\n]+)"#,
            #"\"termination\"\s*:\s*\{[^}]*\"description\"\s*:\s*\"([^\"]+)\""#,
            #"\"terminationReason\"\s*:\s*\"([^\"]+)\""#
        ]) ?? "Unknown"
        let incident = firstMatch(in: text, patterns: [
            #"\"incident_id\"\s*:\s*\"([^\"]+)\""#,
            #"(?m)^Incident Identifier:\s*([^\n]+)"#
        ]) ?? "Unknown"
        let operatingSystem = firstMatch(in: text, patterns: [
            #"\"os_version\"\s*:\s*\"([^\"]+)\""#,
            #"(?m)^OS Version:\s*([^\n]+)"#,
            #"\"build_version\"\s*:\s*\"([^\"]+)\""#
        ]) ?? "Unknown"
        let frames = topFrameLines(text)
        let classification = classifyCrash(
            process: process,
            exception: exception,
            termination: termination,
            fullText: text
        )
        let normalizedFrames = frames.prefix(8).map(normalizeFrame)
        let signatureMaterial = ([
            classification.rawValue,
            process.lowercased().trimmingCharacters(in: .whitespacesAndNewlines),
            exception.lowercased().trimmingCharacters(in: .whitespacesAndNewlines),
            termination.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        ] + normalizedFrames).joined(separator: "|")

        return ParsedCrashLog(
            processName: process.trimmingCharacters(in: .whitespacesAndNewlines),
            exceptionType: exception.trimmingCharacters(in: .whitespacesAndNewlines),
            terminationReason: termination.trimmingCharacters(in: .whitespacesAndNewlines),
            incidentIdentifier: incident.trimmingCharacters(in: .whitespacesAndNewlines),
            operatingSystem: operatingSystem.trimmingCharacters(in: .whitespacesAndNewlines),
            topFrames: Array(frames.prefix(12)),
            signature: sha256(Data(signatureMaterial.utf8)),
            classification: classification
        )
    }

    private static func firstMatch(in text: String, patterns: [String]) -> String? {
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        for pattern in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]),
                  let match = regex.firstMatch(in: text, range: range),
                  match.numberOfRanges > 1,
                  let capture = Range(match.range(at: 1), in: text) else {
                continue
            }
            return String(text[capture])
        }
        return nil
    }

    private static func topFrameLines(_ text: String) -> [String] {
        let lines = text.split(whereSeparator: { $0.isNewline }).map(String.init)
        var frames: [String] = []
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let looksLikeFrame = trimmed.range(
                of: #"^\d+\s+\S+\s+0x[0-9a-f]+"#,
                options: [.regularExpression, .caseInsensitive]
            ) != nil || trimmed.contains("symbolLocation") || trimmed.contains("symbolName")
            if looksLikeFrame {
                frames.append(String(trimmed.prefix(500)))
            }
            if frames.count >= 12 { break }
        }
        return frames
    }

    private static func normalizeFrame(_ value: String) -> String {
        value
            .replacingOccurrences(of: #"0x[0-9a-f]+"#, with: "0xADDR", options: [.regularExpression, .caseInsensitive])
            .replacingOccurrences(of: #"\+\s*\d+"#, with: "+ OFFSET", options: .regularExpression)
            .replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
            .lowercased()
    }

    private static func classifyCrash(
        process: String,
        exception: String,
        termination: String,
        fullText: String
    ) -> CrashFindingClassification {
        let combined = "\(exception) \(termination) \(fullText.prefix(100_000))".lowercased()
        if [
            "exc_bad_access", "sigsegv", "sigbus", "kern_invalid_address", "memory corruption",
            "use-after-free", "use after free", "pac failure", "pointer authentication"
        ].contains(where: combined.contains) {
            return .memoryCorruptionSignal
        }
        if ["jetsam", "highwater", "memory-pressure", "watchdog", "cpu limit", "resource limit"].contains(where: combined.contains) {
            return .resourceTermination
        }
        if ["assertion", "fatal error", "sigabrt", "abort trap", "precondition failed"].contains(where: combined.contains) {
            return .assertionFailure
        }
        if process.localizedCaseInsensitiveContains("Aegis27") || process.localizedCaseInsensitiveContains("Aegis") {
            return .appCrash
        }
        if process != "Unknown" && !process.isEmpty {
            return .systemServiceCrash
        }
        return .unknown
    }

    private static func mergeFinding(for log: ImportedCrashLog) throws {
        var findings = CrashTriageStore.loadFindings()
        if let index = findings.firstIndex(where: { $0.signature == log.signature }) {
            findings[index].occurrences += 1
            findings[index].lastSeen = log.importedAt
            if !findings[index].crashLogIDs.contains(log.id) {
                findings[index].crashLogIDs.append(log.id)
            }
            if let journalID = log.correlatedJournalID,
               !findings[index].journalIDs.contains(journalID) {
                findings[index].journalIDs.append(journalID)
            }
        } else {
            findings.insert(CrashFinding(
                id: UUID(),
                signature: log.signature,
                classification: log.classification,
                processName: log.processName,
                exceptionType: log.exceptionType,
                terminationReason: log.terminationReason,
                occurrences: 1,
                firstSeen: log.importedAt,
                lastSeen: log.importedAt,
                crashLogIDs: [log.id],
                journalIDs: log.correlatedJournalID.map { [$0] } ?? []
            ), at: 0)
        }
        try CrashTriageStore.saveFindings(findings)
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
