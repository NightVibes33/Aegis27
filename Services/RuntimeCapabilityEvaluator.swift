import Foundation

enum RuntimeCapabilityEvaluator {
    static func evaluate(
        gestaltValues: [MobileGestaltValue],
        capabilityResults: [CapabilityProbeResult],
        sandboxPolicyResults: [SandboxPolicyResult],
        machServiceResults: [MachServiceLookupResult]
    ) -> RuntimeCapabilitySummary {
        let protectedDataRules = sandboxPolicyResults.filter {
            $0.kind == .path && $0.operation == "file-read-data"
        }
        let protectedWriteRules = sandboxPolicyResults.filter {
            $0.kind == .path &&
            ($0.operation == "file-write-create" || $0.operation == "file-write-data")
        }

        let container = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first

        return RuntimeCapabilitySummary(
            publicGestaltRead: gestaltValues.contains(where: \.available),
            sandboxPolicyAPI: sandboxPolicyResults.contains(where: \.apiAvailable),
            appContainerWrite: container.map {
                FileManager.default.isWritableFile(atPath: $0.path)
            } ?? false,
            protectedMetadataRead: capabilityResults.contains(where: \.readable),
            protectedDataPolicyAllowed: protectedDataRules.contains(where: \.allowed),
            protectedWritePolicyAllowed: protectedWriteRules.contains(where: \.allowed),
            reachableMachServices: machServiceResults.filter(\.reachable).count
        )
    }
}
