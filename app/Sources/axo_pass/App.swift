import SwiftUI

@main
struct AxoPassApp: App {
  @State private var model = VaultsModel()

  var body: some Scene {
    Window("Axo Pass", id: "main") {
      ContentView()
        .environment(model)
        .task { model.reload() }
    }
    .defaultSize(width: 960, height: 560)
  }
}
