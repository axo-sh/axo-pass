import SwiftUI

struct VaultDetailView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    Group {
      if let selected = model.selectedItem {
        CredentialList(item: selected.item, vaultKey: selected.vaultKey)
      } else if model.isLoadingSelectedItems {
        DelayedProgressView()
      } else {
        ContentUnavailableView("Select an item", systemImage: "list.bullet.rectangle")
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(.windowBackground)
  }
}
