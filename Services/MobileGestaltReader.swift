import CoreFoundation
import Darwin
import Foundation

enum MobileGestaltReader {
    private typealias MGCopyAnswerFunction = @convention(c) (CFString) -> Unmanaged<CFTypeRef>?

    // These values are deliberately limited to non-unique device/build metadata.
    static let baselineKeys = [
        "ProductType",
        "ProductVersion",
        "BuildVersion",
        "DeviceClass",
        "HardwarePlatform",
        "ArtworkDeviceProductDescription"
    ]

    static func readBaseline() -> [MobileGestaltValue] {
        guard let handle = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY) else {
            return baselineKeys.map {
                MobileGestaltValue(key: $0, value: "library unavailable", available: false)
            }
        }
        defer { dlclose(handle) }

        guard let symbol = dlsym(handle, "MGCopyAnswer") else {
            return baselineKeys.map {
                MobileGestaltValue(key: $0, value: "symbol unavailable", available: false)
            }
        }

        let copyAnswer = unsafeBitCast(symbol, to: MGCopyAnswerFunction.self)
        return baselineKeys.map { key in
            guard let unmanaged = copyAnswer(key as CFString) else {
                return MobileGestaltValue(key: key, value: "nil", available: false)
            }
            let value = unmanaged.takeRetainedValue()
            return MobileGestaltValue(
                key: key,
                value: String(describing: value),
                available: true
            )
        }
    }
}

