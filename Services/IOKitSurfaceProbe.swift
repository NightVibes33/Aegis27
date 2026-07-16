import Foundation

enum IOKitSurfaceProbe {
    static let builtInClasses = [
        "IOSurfaceRoot",
        "IOMobileFramebuffer",
        "AGXAccelerator",
        "AppleJPEGDriver",
        "AppleAVE2Driver"
    ]

    static func run(additionalClasses: [String]) -> [IOKitProbeResult] {
        var seen = Set<String>()
        let classes = (builtInClasses + additionalClasses).filter {
            seen.insert($0).inserted
        }.prefix(64)
        return classes.map { className in
            var matched: UInt32 = 0
            var openResult: Int32 = Int32.min
            let apiResult = className.withCString { pointer in
                aegis_iokit_open_probe(pointer, &matched, &openResult)
            }
            return IOKitProbeResult(
                className: className,
                apiResult: apiResult,
                matched: matched != 0,
                openResult: openResult
            )
        }
    }
}
