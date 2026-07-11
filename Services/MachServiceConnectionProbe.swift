import Foundation

enum MachServiceConnectionProbe {
    private static let observationDelay: UInt64 = 350_000_000

    static func run(services: [String]) async -> [MachServiceConnectionResult] {
        var results: [MachServiceConnectionResult] = []

        for service in services {
            results.append(await probe(service: service))
        }

        return results
    }

    private static func probe(service: String) async -> MachServiceConnectionResult {
        final class State: @unchecked Sendable {
            var interrupted = false
            var invalidated = false
            var errorDescription: String?
        }

        let state = State()
        let connection = NSXPCConnection(machServiceName: service, options: [])

        connection.interruptionHandler = {
            state.interrupted = true
        }
        connection.invalidationHandler = {
            state.invalidated = true
        }

        do {
            connection.resume()
            try await Task.sleep(nanoseconds: observationDelay)
            connection.invalidate()
        } catch {
            state.errorDescription = error.localizedDescription
        }

        return MachServiceConnectionResult(
            service: service,
            resumed: true,
            interrupted: state.interrupted,
            invalidated: state.invalidated,
            errorDescription: state.errorDescription
        )
    }
}
