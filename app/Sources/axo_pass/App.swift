import SwiftUI

@main
struct AxoPassApp: App {
  @State private var model = VaultsModel()

  var body: some Scene {
    Window("Axo Pass", id: "main") {
      ContentView()
        .environment(model)
        .task {
          model.reload()
          await model.startBroker()
        }
    }
    .windowStyle(.hiddenTitleBar)
    .defaultSize(width: 960, height: 560)
  }
}
