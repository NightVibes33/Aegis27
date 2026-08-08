import Foundation
import UIKit
import Darwin

enum DopamineReadinessProbe {
    private static let cpuFamilyA14: UInt32 = 0x1b588bb3
    private static let cpuFamilyA15: UInt32 = 0xda33d83d
    private static let cpuFamilyA16: UInt32 = 0x8765edea
    private static let cpuFamilyA17: UInt32 = 0x2876f5b5
    private static let cpuFamilyA18: UInt32 = 0x204526d0
    private static let cpuFamilyA18Pro: UInt32 = 0x75d4acb9

    static func run() -> DopamineReadinessReport {
        let deviceIdentifier = machineIdentifier()
        let cpuFamilyValue = sysctlUInt32("hw.cpufamily") ?? 0
        let cpuFamilyName = cpuName(for: cpuFamilyValue)
        let systemVersion = UIDevice.current.systemVersion
        let buildVersion = sysctlString("kern.osversion") ?? "unknown"
        let majorVersion = Int(systemVersion.split(separator: ".").first ?? "0") ?? 0
        let expectsSPTM = majorVersion >= 17 && isModernSPTMCPU(cpuFamilyValue)

        var checks: [DopamineReadinessCheck] = []

        checks.append(
            DopamineReadinessCheck(
                title: "A18 device identification",
                status: (cpuFamilyValue == cpuFamilyA18 || cpuFamilyValue == cpuFamilyA18Pro) ? .ready : .info,
                detail: "Probe sees \(cpuFamilyName) (0x\(String(cpuFamilyValue, radix: 16))) on \(deviceIdentifier). Dopamine 3.0.1's libjailbreak defines A18/A18 Pro CPU-family constants, but its app-side exploit selector currently maps CPU families only through A17."
            )
        )

        let isIOS27 = majorVersion >= 27
        checks.append(
            DopamineReadinessCheck(
                title: "Public kernel exploit for this build",
                status: isIOS27 ? .blocked : .info,
                detail: isIOS27
                    ? "Dopamine 3.0.1's ClearSword/DarkSword framework metadata stops at iOS 26.0.1. No stock kernel exploit is selected for an iOS 27 real-device build."
                    : "Compare this build against the exploit metadata shipped with Dopamine 3.0.1 before attempting anything destructive."
            )
        )

        let titanSupportedCPU = [cpuFamilyA14, cpuFamilyA15, cpuFamilyA16, cpuFamilyA17].contains(cpuFamilyValue)
        let versionAtOrBelow1731 = compareVersions(systemVersion, "17.3.1") != .orderedDescending
        let titanEligible = titanSupportedCPU && versionAtOrBelow1731 && majorVersion >= 16
        checks.append(
            DopamineReadinessCheck(
                title: "SPTM/PPL bypass",
                status: titanEligible ? .ready : (expectsSPTM ? .blocked : .info),
                detail: titanEligible
                    ? "Titan's published Dopamine 3.0.1 support window includes this CPU/version combination."
                    : "Titan is declared for A14-A17 and iOS 16.1-17.3.1 (plus listed 17.4 beta builds). An A18 device on iOS 27 therefore has no stock SPTM bypass in Dopamine 3.0.1."
            )
        )

        checks.append(
            DopamineReadinessCheck(
                title: "Dopamine iOS 27 jailbreak engine",
                status: .ready,
                detail: "The 3.0 release adds general SPTM-era support through iOS 27 betas and provides a Corellium install path. That demonstrates the post-primitive jailbreak machinery can run once the required privileged primitives are supplied; it does not provide those primitives on a physical iPhone."
            )
        )

        checks.append(
            DopamineReadinessCheck(
                title: "Safe next research target",
                status: .info,
                detail: "Treat kernel code execution/read-write and the SPTM bypass as separate gates. This lab intentionally does not trigger a kernel exploit, patch page tables, modify trust caches, or write kernel memory."
            )
        )

        return DopamineReadinessReport(
            generatedAt: Date(),
            dopamineVersion: "3.0.1",
            deviceIdentifier: deviceIdentifier,
            cpuFamilyName: cpuFamilyName,
            cpuFamilyValue: cpuFamilyValue,
            systemVersion: systemVersion,
            buildVersion: buildVersion,
            expectsSPTM: expectsSPTM,
            checks: checks
        )
    }

    private static func machineIdentifier() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let mirror = Mirror(reflecting: systemInfo.machine)
        return mirror.children.reduce(into: "") { result, element in
            guard let value = element.value as? Int8, value != 0 else { return }
            result.append(Character(UnicodeScalar(UInt8(bitPattern: value))))
        }
    }

    private static func sysctlUInt32(_ name: String) -> UInt32? {
        var value: UInt32 = 0
        var size = MemoryLayout<UInt32>.size
        let result = name.withCString { pointer in
            sysctlbyname(pointer, &value, &size, nil, 0)
        }
        return result == 0 ? value : nil
    }

    private static func sysctlString(_ name: String) -> String? {
        var size: size_t = 0
        guard name.withCString({ sysctlbyname($0, nil, &size, nil, 0) }) == 0, size > 0 else {
            return nil
        }
        var buffer = [CChar](repeating: 0, count: size)
        guard name.withCString({ sysctlbyname($0, &buffer, &size, nil, 0) }) == 0 else {
            return nil
        }
        return String(cString: buffer)
    }

    private static func cpuName(for family: UInt32) -> String {
        switch family {
        case cpuFamilyA14: return "A14 / M1 family"
        case cpuFamilyA15: return "A15 / M2 family"
        case cpuFamilyA16: return "A16"
        case cpuFamilyA17: return "A17"
        case cpuFamilyA18: return "A18"
        case cpuFamilyA18Pro: return "A18 Pro"
        default: return "Unknown CPU family"
        }
    }

    private static func isModernSPTMCPU(_ family: UInt32) -> Bool {
        [cpuFamilyA14, cpuFamilyA15, cpuFamilyA16, cpuFamilyA17, cpuFamilyA18, cpuFamilyA18Pro].contains(family)
    }

    private static func compareVersions(_ lhs: String, _ rhs: String) -> ComparisonResult {
        lhs.compare(rhs, options: .numeric)
    }
}
