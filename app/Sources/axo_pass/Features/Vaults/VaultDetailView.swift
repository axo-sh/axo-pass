import SwiftUI

struct VaultDetailView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    Group {
      if let selected = model.selectedItem {
        CredentialList(item: selected.item, vaultKey: selected.vaultKey)
      } else if model.isLoadingSelectedItems {
        DelayedProgressView()
          .stubItemToolbar()
      } else {
        ContentUnavailableView("Select an item", systemImage: "list.bullet.rectangle")
          .stubItemToolbar()
      }
    }
    .paneBackground()
  }
}

extension View {
  fileprivate func stubItemToolbar() -> some View {
    toolbar {
      ToolbarItemGroup(placement: .primaryAction) {
        // Push the item actions to the trailing edge of the toolbar.
        Spacer()
        Button("Edit") {}
          .disabled(true)
        Button {
        } label: {
          Label("Add Credential", systemImage: "plus")
        }
      }
    }
  }
}
