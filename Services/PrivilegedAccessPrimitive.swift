import Foundation

enum PrimitiveAvailability: String, Codable {
    case unavailable
    case validating
    case available
    case failed
}

struct PrimitiveValidation: Codable {
    let availability: PrimitiveAvailability
    let summary: String
}

protocol PrivilegedAccessPrimitive {
    var name: String { get }
    var availability: PrimitiveAvailability { get }
    func validate() async -> PrimitiveValidation
}

/// Integration boundary for a future, independently validated iOS 27
/// sandbox-escape primitive. This intentionally grants no extra access.
struct UnavailablePrimitive: PrivilegedAccessPrimitive {
    let name = "iOS 27 sandbox escape"
    let availability = PrimitiveAvailability.unavailable

    func validate() async -> PrimitiveValidation {
        PrimitiveValidation(
            availability: .unavailable,
            summary: "No public or locally validated primitive is integrated."
        )
    }
}

