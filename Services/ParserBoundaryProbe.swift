import Foundation
import ImageIO
import QuickLookThumbnailing

private typealias ThumbnailProbeOutcome = (BoundaryProbeOutcome, String)

private actor ThumbnailProbeGate {
    private var continuation: CheckedContinuation<ThumbnailProbeOutcome, Never>?
    private var pending: ThumbnailProbeOutcome?
    private var resolved = false

    func install(
        _ value: CheckedContinuation<ThumbnailProbeOutcome, Never>
    ) {
        if let pending {
            value.resume(returning: pending)
            self.pending = nil
        } else {
            continuation = value
        }
    }

    @discardableResult
    func resolve(_ value: ThumbnailProbeOutcome) -> Bool {
        guard !resolved else { return false }
        resolved = true
        if let continuation {
            continuation.resume(returning: value)
            self.continuation = nil
        } else {
            pending = value
        }
        return true
    }
}

enum ParserBoundaryProbe {
    private struct CorpusItem {
        let id: String
        let label: String
        let fileExtension: String
        let data: Data
    }

    static func run() async -> [ParserBoundaryResult] {
        let corpus = makeCorpus()
        var results: [ParserBoundaryResult] = []
        for item in corpus {
            results.append(localParse(item))
            results.append(await quickLookParse(item))
        }
        return results
    }

    private static func makeCorpus() -> [CorpusItem] {
        let validJSON = Data("{\"aegis\":true,\"value\":27}".utf8)
        let truncatedJSON = Data("{\"aegis\":[1,2,".utf8)
        let plistObject: [String: Any] = ["Aegis": true, "Build": "bounded"]
        let binaryPlist = (try? PropertyListSerialization.data(
            fromPropertyList: plistObject,
            format: .binary,
            options: 0
        )) ?? Data()
        let malformedPlist = Data("bplist00\u{0}\u{1}\u{2}bounded".utf8)
        let validPNG = Data(base64Encoded:
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
        ) ?? Data()
        let malformedPNG = Data([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xff])
        return [
            .init(id: "json-valid", label: "Valid JSON", fileExtension: "json", data: validJSON),
            .init(id: "json-truncated", label: "Truncated JSON", fileExtension: "json", data: truncatedJSON),
            .init(id: "plist-valid", label: "Valid binary plist", fileExtension: "plist", data: binaryPlist),
            .init(id: "plist-truncated", label: "Truncated binary plist", fileExtension: "plist", data: malformedPlist),
            .init(id: "png-valid", label: "Valid 1px PNG", fileExtension: "png", data: validPNG),
            .init(id: "png-truncated", label: "Truncated PNG", fileExtension: "png", data: malformedPNG)
        ]
    }

    private static func localParse(_ item: CorpusItem) -> ParserBoundaryResult {
        let clock = ContinuousClock()
        let started = clock.now
        let accepted: Bool
        switch item.fileExtension {
        case "json": accepted = (try? JSONSerialization.jsonObject(with: item.data)) != nil
        case "plist": accepted = (try? PropertyListSerialization.propertyList(
            from: item.data,
            options: [],
            format: nil
        )) != nil
        case "png":
            accepted = CGImageSourceCreateWithData(item.data as CFData, nil)
                .flatMap { CGImageSourceCreateImageAtIndex($0, 0, nil) } != nil
        default: accepted = false
        }
        let duration = started.duration(to: clock.now)
        return ParserBoundaryResult(
            corpusID: item.id,
            label: item.label,
            boundary: "In-process public parser",
            byteCount: item.data.count,
            outcome: accepted ? .accepted : .rejected,
            elapsedMilliseconds: durationMilliseconds(duration),
            detail: accepted ? "Accepted" : "Rejected without retained output"
        )
    }

    private static func quickLookParse(_ item: CorpusItem) async -> ParserBoundaryResult {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("AegisParserCorpus", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let url = directory.appendingPathComponent("\(item.id).\(item.fileExtension)")
        do {
            try item.data.write(to: url, options: .atomic)
        } catch {
            return ParserBoundaryResult(
                corpusID: item.id,
                label: item.label,
                boundary: "QuickLook thumbnail boundary",
                byteCount: item.data.count,
                outcome: .failed,
                elapsedMilliseconds: 0,
                detail: "Corpus staging failed"
            )
        }

        let clock = ContinuousClock()
        let started = clock.now
        let request = QLThumbnailGenerator.Request(
            fileAt: url,
            size: CGSize(width: 64, height: 64),
            scale: 1,
            representationTypes: .thumbnail
        )
        let gate = ThumbnailProbeGate()
        let generator = QLThumbnailGenerator.shared
        let outcome: ThumbnailProbeOutcome = await withCheckedContinuation { continuation in
            Task { await gate.install(continuation) }
            generator.generateBestRepresentation(
                for: request
            ) { representation, error in
                let value: ThumbnailProbeOutcome
                if representation != nil {
                    value = (.accepted, "Thumbnail representation returned")
                } else if error != nil {
                    value = (.rejected, "QuickLook rejected input")
                } else {
                    value = (.failed, "No representation or error")
                }
                Task { await gate.resolve(value) }
            }
            Task {
                try? await Task.sleep(for: .seconds(2))
                if await gate.resolve((.timedOut, "QuickLook exceeded 2 second limit")) {
                    generator.cancel(request)
                }
            }
        }
        try? FileManager.default.removeItem(at: url)
        return ParserBoundaryResult(
            corpusID: item.id,
            label: item.label,
            boundary: "QuickLook thumbnail boundary",
            byteCount: item.data.count,
            outcome: outcome.0,
            elapsedMilliseconds: durationMilliseconds(started.duration(to: clock.now)),
            detail: outcome.1
        )
    }

    private static func durationMilliseconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) * 1_000 +
            Double(components.attoseconds) / 1_000_000_000_000_000
    }
}
