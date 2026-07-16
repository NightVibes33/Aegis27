import Foundation

enum SnapshotStore {
    private static var directory: URL {
        let documents = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first!
        return documents.appendingPathComponent("ResearchSnapshots", isDirectory: true)
    }

    static func save(_ snapshot: ResearchSnapshot) throws -> URL {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let url = directory.appendingPathComponent("\(snapshot.id.uuidString).json")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(snapshot).write(to: url, options: .atomic)
        return url
    }

    static func loadLatest() -> ResearchSnapshot? {
        guard let urls = try? FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else { return nil }

        let sorted = urls.sorted {
            let left = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate ?? .distantPast
            let right = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate ?? .distantPast
            return left > right
        }
        guard let url = sorted.first, let data = try? Data(contentsOf: url) else {
            return nil
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(ResearchSnapshot.self, from: data)
    }

    static func differences(
        previous: ResearchSnapshot,
        current: ResearchSnapshot
    ) -> [SnapshotDifference] {
        let old = flattened(previous)
        let new = flattened(current)
        return Set(old.keys).union(new.keys).sorted().compactMap { key in
            let before = old[key] ?? "missing"
            let after = new[key] ?? "missing"
            guard before != after else { return nil }
            return SnapshotDifference(
                key: key,
                previousValue: before,
                currentValue: after
            )
        }
    }

    private static func flattened(_ snapshot: ResearchSnapshot) -> [String: String] {
        var values: [String: String] = [
            "device.hardware": snapshot.profile.hardwareIdentifier,
            "device.version": snapshot.profile.systemVersion,
            "device.build": snapshot.profile.buildVersion,
            "capability.gestalt": String(snapshot.runtimeCapabilities.publicGestaltRead),
            "capability.protectedDataPolicyAllowed": String(snapshot.runtimeCapabilities.protectedDataPolicyAllowed),
            "capability.protectedWritePolicyAllowed": String(snapshot.runtimeCapabilities.protectedWritePolicyAllowed)
        ]
        for item in snapshot.gestaltValues {
            values["gestalt.\(item.key)"] = item.available ? item.value : "unavailable"
        }
        for item in snapshot.capabilityResults {
            values["path.\(item.path).readable"] = String(item.readable)
            values["path.\(item.path).writable"] = String(item.writableAccordingToMetadata)
        }
        for item in snapshot.sandboxPolicyResults {
            values["policy.\(item.kind.rawValue).\(item.subject).\(item.operation)"] =
                item.apiAvailable ? String(item.rawResult) : "unavailable"
        }
        for item in snapshot.machServiceResults {
            values["service.\(item.service).lookup"] = String(item.rawResult)
        }
        for item in snapshot.machConnectionResults {
            values["service.\(item.service).portType"] = String(item.portType)
            values["service.\(item.service).sendRefs"] = String(item.sendRightRefs)
        }
        return values
    }
}
