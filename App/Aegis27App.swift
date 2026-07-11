import SwiftUI

@main
struct Aegis27App: App {
    @StateObject private var viewModel = ResearchViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
        }
    }
}

