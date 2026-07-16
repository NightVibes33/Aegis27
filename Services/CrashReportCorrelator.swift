import CryptoKit
import Foundation

enum CrashReportCorrelator {
    private static let byteLimit = 8 * 1_024 * 1_024
    private static let markers = [
        "EXC_BAD_ACCESS", "SIGABRT", "Jetsam", "memorystatus",
        "panicString", "Termination Reason", "Exception Type"
    ]

    static func inspect(
        url: URL,
        report: AttackSurfaceReport
    ) throws -> CrashCorrelationResult {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        let bounded = data.prefix(byteLimit)
        let text = String(decoding: bounded, as: UTF8.self)
        let hash = SHA256.hash(data: data).map {
            String(format: "%02x", $0)
        }.joined()
        let process = firstCapture(
            in: text,
            patterns: [
                #"\"procName\"\s*:\s*\"([^\"]+)\""#,
                #"Process:\s+([^\s\[]+)"#
            ]
        )
        let timestampText = firstCapture(
            in: text,
            patterns: [
                #"\"captureTime\"\s*:\s*\"([^\"]+)\""#,
                #"Date/Time:\s+([^\n]+)"#
            ]
        )
        let incidentTimestamp = timestampText.flatMap(parseDate)
        let markerCounts = Dictionary(uniqueKeysWithValues: markers.compactMap { marker in
            let count = text.components(separatedBy: marker).count - 1
            return count > 0 ? (marker, count) : nil
        })
        let timingMatched = incidentTimestamp.map {
            $0 >= report.startedAt.addingTimeInterval(-30) &&
                $0 <= report.finishedAt.addingTimeInterval(300)
        } ?? false
        let nearest = nearestProbe(
            to: incidentTimestamp,
            process: process,
            results: report.serviceResults
        )
        let classification = classify(
            process: process,
            text: text,
            nearestService: nearest?.service
        )
        return CrashCorrelationResult(
            id: UUID(),
            importedAt: Date(),
            fileName: url.lastPathComponent,
            sha256: hash,
            processName: process,
            incidentTimestamp: incidentTimestamp,
            classification: classification,
            timingMatched: timingMatched,
            nearestService: nearest?.service,
            nearestRequestID: nearest?.requestID,
            markerCounts: markerCounts
        )
    }

    private static func firstCapture(
        in text: String,
        patterns: [String]
    ) -> String? {
        for pattern in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern),
                  let match = regex.firstMatch(
                    in: text,
                    range: NSRange(text.startIndex..., in: text)
                  ), match.numberOfRanges > 1,
                  let range = Range(match.range(at: 1), in: text) else { continue }
            return String(text[range]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return nil
    }

    private static func parseDate(_ value: String) -> Date? {
        let iso = ISO8601DateFormatter()
        if let date = iso.date(from: value) { return date }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
        return formatter.date(from: value)
    }

    private static func nearestProbe(
        to date: Date?,
        process: String?,
        results: [AttackSurfaceServiceResult]
    ) -> AttackSurfaceServiceResult? {
        let filtered = results.filter { result in
            guard let process else { return true }
            return result.service.localizedCaseInsensitiveContains(process) ||
                process.localizedCaseInsensitiveContains(
                    result.service.split(separator: ".").last.map(String.init) ?? ""
                )
        }
        guard let date else { return filtered.last }
        return filtered.min {
            abs($0.timestamp.timeIntervalSince(date)) <
                abs($1.timestamp.timeIntervalSince(date))
        }
    }

    private static func classify(
        process: String?,
        text: String,
        nearestService: String?
    ) -> CrashClassification {
        if text.localizedCaseInsensitiveContains("panicString") {
            return .kernelPanic
        }
        if text.localizedCaseInsensitiveContains("jetsam") ||
            text.localizedCaseInsensitiveContains("memorystatus") {
            return .jetsam
        }
        if process?.localizedCaseInsensitiveContains("Aegis27") == true {
            return .aegisApp
        }
        if nearestService != nil { return .matchingService }
        if process != nil { return .unrelatedProcess }
        return .unknown
    }
}
