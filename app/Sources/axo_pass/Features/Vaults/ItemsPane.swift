import AxoPassFFI
import SwiftUI

struct ItemsPane: View {
  @Environment(VaultsModel.self) private var model
  @State private var showingNewItemSheet = false

  var body: some View {
    @Bindable var model = model
    Group {
      if model.isLoadingSelectedItems {
        DelayedProgressView()
      } else if (model.selectedVault != nil || model.isAllSecrets) && !model.displayItems.isEmpty {
        List(selection: $model.selectedItemRef) {
          ForEach(model.displayItems) { display in
            ItemRow(item: display.item)
              .tag(display.id)
              .padding(6)
              .contextMenu {
                Button("Delete", role: .destructive) {
                  Task { await model.deleteItem(vaultKey: display.vaultKey, itemKey: display.item.key) }
                }
              }
          }
        }
      }
    }
    .paneBackground()
    .navigationSplitViewColumnWidth(min: 200, ideal: 240)
    .navigationTitle(model.selectedVault.map { $0.name ?? $0.key } ?? (model.isAllSecrets ? "All Secrets" : "Items"))
    .toolbar {
      if model.selectedVault != nil {
        ToolbarItem(placement: .primaryAction) {
          Button {
            showingNewItemSheet = true
          } label: {
            Label("New Item", systemImage: "plus")
          }
        }
      }
    }
    .sheet(isPresented: $showingNewItemSheet) {
      NewItemSheet { key, title in
        guard let vaultKey = model.selectedVaultKey else { return false }
        return await model.addOrUpdateItem(vaultKey: vaultKey, itemKey: key, itemTitle: title)
      }
    }
  }
}

private struct NewItemSheet: View {
  let onSubmit: (_ key: String, _ title: String) async -> Bool

  @Environment(\.dismiss) private var dismiss
  @State private var title: String = ""
  @State private var key: String = ""
  @State private var isSubmitting = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Item").font(.headline)
      TextField("Title", text: $title)
      TextField("Key (a-z, 0-9, -, _)", text: $key)

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Create") {
          Task {
            isSubmitting = true
            if await onSubmit(key, title) { dismiss() }
            isSubmitting = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || key.isEmpty || title.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 320)
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
