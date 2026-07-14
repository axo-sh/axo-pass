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
        // Label("Secrets", systemImage: "list.bullet.rectangle.fill")
        Text("Secrets")
      }

      Label("SSH", systemImage: "asterisk")
        .tag(SidebarDestination.ssh)
      Label("Keys", systemImage: "key.fill")
        .tag(SidebarDestination.gpg)
      Label("Setup", systemImage: "terminal")
        .tag(SidebarDestination.setup)
    }
    .navigationSplitViewColumnWidth(min: 160, ideal: 200)
    .safeAreaInset(edge: .bottom) {
      HStack(spacing: 8) {
        Button {
          model.reload()
        } label: {
          Label("Reload", systemImage: "arrow.clockwise")
        }
        Spacer()
        Button {
          model.lock()
        } label: {
          Label("Lock", systemImage: "lock")
        }
      }
      .labelStyle(.iconOnly)
      .buttonStyle(.borderless)
      .padding(.horizontal, 12)
      .padding(.vertical, 8)
    }
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
      Label("All", systemImage: "lock")
        .tag(SidebarDestination.vault("all"))
      ForEach(model.vaults, id: \.key) { vault in
        Label(vault.name ?? vault.key, systemImage: "lock")
          .tag(SidebarDestination.vault(vault.key))
      }
    }
  }
}
