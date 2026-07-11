import Darwin
import Foundation
import UIKit

enum DeviceProfiler {
    static func current() -> DeviceProfile {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return DeviceProfile(
            hardwareIdentifier: sysctlString("hw.machine") ?? "unknown",
            systemName: UIDevice.current.systemName,
            systemVersion: UIDevice.current.systemVersion,
            buildVersion: sysctlString("kern.osversion") ?? "unknown",
            majorVersion: version.majorVersion
        )
    }

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else {
            return nil
        }

        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else {
            return nil
        }

        return String(cString: buffer)
    }
}

