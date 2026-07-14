import SwiftUI

struct ContentView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    if model.isAppUnlocked {
      MainView()
    } else {
      LockScreen()
    }
  }
}

private struct MainView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    NavigationSplitView {
      VaultsSidebar()
    } content: {
      contentPane
    } detail: {
      VaultDetailView()
    }
  }

  @ViewBuilder
  private var contentPane: some View {
    if case .vault = model.sidebarSelection {
      ItemsPane()
    } else if case .ssh = model.sidebarSelection {
      PlaceholderPane(title: "SSH", icon: "asterisk")
    } else if case .gpg = model.sidebarSelection {
      PlaceholderPane(title: "Keys", icon: "key.fill")
    } else if case .setup = model.sidebarSelection {
      PlaceholderPane(title: "Setup", icon: "terminal")
    } else {
      ContentUnavailableView("Select a section", systemImage: "sidebar.left")
    }
  }
}

private struct PlaceholderPane: View {
  let title: String
  let icon: String

  var body: some View {
    ContentUnavailableView(title, systemImage: icon, description: Text("Coming soon"))
      .navigationSplitViewColumnWidth(min: 200, ideal: 240)
      .navigationTitle(title)
  }
}
