import AxoPassFFI
import SwiftUI

struct ItemsPane: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    @Bindable var model = model
    Group {
      // if model.selectedVaultKey == nil {
      //   ContentUnavailableView("Select a vault", systemImage: "sidebar.left")
      // } else if model.items.isEmpty {
      //   ProgressView()
      // } else {
      if model.selectedVault != nil && !model.items.isEmpty {
        List(selection: $model.selectedItemKey) {
          ForEach(model.items, id: \.key) { item in
            ItemRow(item: item).tag(item.key).padding(6)
          }
        }
      }
    }
    .navigationSplitViewColumnWidth(min: 200, ideal: 240)
    .navigationTitle(model.selectedVault.map { $0.name ?? $0.key } ?? "Items")
  }
}

private struct ItemRow: View {
  let item: ItemInfo
  var body: some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(item.title)
      Text("\(item.credentials.count) credential\(item.credentials.count == 1 ? "" : "s")")
        .font(.caption)
        .foregroundStyle(.secondary)
    }
  }
}
