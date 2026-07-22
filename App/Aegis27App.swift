import SwiftUI

@main
struct Aegis27App: App {
    @StateObject private var viewModel = ResearchViewModel()
    @State private var showFuzzerHarness = false

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
                .overlay(alignment: .bottomTrailing) {
                    Button {
                        showFuzzerHarness = true
                    } label: {
                        Image(systemName: "bolt.shield.fill")
                            .font(.title3.weight(.semibold))
                            .frame(width: 52, height: 52)
                            .background(.ultraThinMaterial, in: Circle())
                            .shadow(radius: 5)
                    }
                    .accessibilityLabel("Open fuzzer harness")
                    .padding(.trailing, 16)
                    .padding(.bottom, 76)
                }
                .sheet(isPresented: $showFuzzerHarness) {
                    NavigationStack {
                        FuzzHarnessView(
                            catalog: .empty,
                            profile: viewModel.profile,
                            logger: viewModel.logger
                        )
                        .toolbar {
                            ToolbarItem(placement: .topBarTrailing) {
                                Button("Done") {
                                    showFuzzerHarness = false
                                }
                            }
                        }
                    }
                }
        }
    }
}
