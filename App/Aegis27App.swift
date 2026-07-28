import SwiftUI

@main
struct Aegis27App: App {
    @StateObject private var viewModel = ResearchViewModel()
    @StateObject private var transportCoordinator = BoundaryTransportCoordinator()
    @State private var showFuzzerHarness = false
    @State private var showCrashTriage = false
    @State private var showPatchDiffLab = false
    @State private var showBoundaryLab = false

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
                .environmentObject(transportCoordinator)
                .onOpenURL { url in
                    transportCoordinator.handleIncomingURL(url)
                }
                .overlay(alignment: .bottomTrailing) {
                    VStack(spacing: 12) {
                        Button {
                            showBoundaryLab = true
                        } label: {
                            Image(systemName: "lock.shield.fill")
                                .font(.title3.weight(.semibold))
                                .frame(width: 52, height: 52)
                                .background(.ultraThinMaterial, in: Circle())
                                .shadow(radius: 5)
                        }
                        .accessibilityLabel("Open Boundary Lab")

                        Button {
                            showPatchDiffLab = true
                        } label: {
                            Image(systemName: "arrow.left.arrow.right.square")
                                .font(.title3.weight(.semibold))
                                .frame(width: 52, height: 52)
                                .background(.ultraThinMaterial, in: Circle())
                                .shadow(radius: 5)
                        }
                        .accessibilityLabel("Open IPSW Patch-Diff Lab")

                        Button {
                            showCrashTriage = true
                        } label: {
                            Image(systemName: "waveform.path.ecg.rectangle.fill")
                                .font(.title3.weight(.semibold))
                                .frame(width: 52, height: 52)
                                .background(.ultraThinMaterial, in: Circle())
                                .shadow(radius: 5)
                        }
                        .accessibilityLabel("Open Crash Triage")

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
                    }
                    .padding(.trailing, 16)
                    .padding(.bottom, 76)
                }
                .sheet(isPresented: $showBoundaryLab) {
                    NavigationStack {
                        BoundaryLabView()
                            .environmentObject(transportCoordinator)
                            .toolbar {
                                ToolbarItem(placement: .topBarTrailing) {
                                    Button("Done") {
                                        showBoundaryLab = false
                                    }
                                }
                            }
                    }
                }
                .sheet(isPresented: $showPatchDiffLab) {
                    NavigationStack {
                        PatchDiffLabView(
                            profile: viewModel.profile,
                            logger: viewModel.logger
                        )
                        .toolbar {
                            ToolbarItem(placement: .topBarTrailing) {
                                Button("Done") {
                                    showPatchDiffLab = false
                                }
                            }
                        }
                    }
                }
                .sheet(isPresented: $showCrashTriage) {
                    NavigationStack {
                        CrashTriageView(
                            profile: viewModel.profile,
                            logger: viewModel.logger
                        )
                        .toolbar {
                            ToolbarItem(placement: .topBarTrailing) {
                                Button("Done") {
                                    showCrashTriage = false
                                }
                            }
                        }
                    }
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
