import AxoPassFFI
import SwiftUI

struct VaultsSidebar: View {
  @Environment(VaultsModel.self) private var model

  private var selectionBinding: Binding<SidebarDestination?> {
    Binding(
      get: { model.sidebarSelection },
      set: { model.selectSidebarDestination($0) }
    )
  }

  var body: some View {
    List(selection: selectionBinding) {
      Section {
        vaultItems
      } header: {
        Label("Secrets", systemImage: "list.bullet.rectangle.fill")
      }

      Label("SSH", systemImage: "asterisk")
        .tag(SidebarDestination.ssh)
      Label("Keys", systemImage: "key.fill")
        .tag(SidebarDestination.gpg)
      Label("Setup", systemImage: "terminal")
        .tag(SidebarDestination.setup)
    }
    .navigationSplitViewColumnWidth(min: 160, ideal: 200)
  }

  @ViewBuilder
  private var vaultItems: some View {
    if let err = model.loadError {
      Label(err, systemImage: "exclamationmark.triangle")
        .font(.caption)
        .foregroundStyle(.red)
    } else if model.vaults.isEmpty {
      Text("No vaults")
        .font(.caption)
        .foregroundStyle(.secondary)
    } else {
      ForEach(model.vaults, id: \.key) { vault in
        Label(vault.name ?? vault.key, systemImage: "lock")
          .tag(SidebarDestination.vault(vault.key))
      }
    }
  }
}
