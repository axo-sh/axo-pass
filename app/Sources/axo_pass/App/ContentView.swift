import SwiftUI

struct ContentView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    Group {
      if model.isAppUnlocked {
        MainView()
      } else {
        LockScreen()
      }
    }
    .titleBarHidden(!model.isAppUnlocked)
  }
}

/// Sidebar, list, and detail columns. Page destinations such as Today are
/// shown in the detail column, and the list column is collapsed.
private struct MainView: View {
  @Environment(VaultsModel.self) private var model
  // Held here rather than inside the panes so the detail column can read the
  // same selection and key list.
  @State private var sshModel = SshModel()
  @State private var gpgModel = GpgModel()
  @State private var ageModel = AgeModel()
  @State private var deletedModel = RecentlyDeletedModel()

  var body: some View {
    NavigationSplitView {
      VaultsSidebar(sshModel: sshModel, gpgModel: gpgModel, ageModel: ageModel)
    } content: {
      contentPane
    } detail: {
      detailPane
        .splitColumnCollapsed(isPage, index: 1)
    }
  }

  /// Whether the selection is a page that uses the full width.
  private var isPage: Bool {
    switch model.sidebarSelection {
    case .today, .activity: return true
    default: return false
    }
  }

  @ViewBuilder
  private var detailPane: some View {
    if case .today = model.sidebarSelection {
      TodayPane(sshModel: sshModel, gpgModel: gpgModel)
    } else if case .activity = model.sidebarSelection {
      ActivityPane(sshModel: sshModel, gpgModel: gpgModel)
    } else if case .ssh = model.sidebarSelection {
      SshKeyDetailView(model: sshModel)
    } else if case .gpg = model.sidebarSelection {
      GpgKeyDetailView(model: gpgModel)
    } else if case .age = model.sidebarSelection {
      AgeKeyDetailView(model: ageModel)
    } else if case .recentlyDeleted = model.sidebarSelection {
      RecentlyDeletedDetailView(model: deletedModel)
    } else {
      VaultDetailView()
    }
  }

  @ViewBuilder
  private var contentPane: some View {
    if isPage {
      // Collapsed while a page is shown.
      Color.clear
    } else if model.selectedVaultKey != nil || model.selectedItemType != nil {
      ItemsPane()
    } else if case .ssh = model.sidebarSelection {
      SshPane(model: sshModel)
    } else if case .gpg = model.sidebarSelection {
      GpgPane(model: gpgModel)
    } else if case .age = model.sidebarSelection {
      AgePane(model: ageModel)
    } else if case .recentlyDeleted = model.sidebarSelection {
      RecentlyDeletedPane(model: deletedModel)
    } else {
      ContentUnavailableView("Select a section", systemImage: "sidebar.left")
        .paneBackground()
    }
  }
}
