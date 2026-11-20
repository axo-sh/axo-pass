import SwiftUI

struct VaultDetailView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    Group {
      if let selected = model.selectedItem {
        // Credential keys repeat across items, so the list uses the item id as
        // its identity. Without it, switching items reuses rows with matching
        // keys, including their reveal and draft state, and animates them.
        CredentialList(item: selected.item, vaultKey: selected.vaultKey)
          .id(selected.id)
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
        Button {
        } label: {
          Label("Add", systemImage: "plus")
        }
        .disabled(true)
      }
    }
  }
}
