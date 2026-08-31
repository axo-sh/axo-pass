import AxoPassFFI
import SwiftUI

struct ItemsPane: View {
  @Environment(VaultsModel.self) private var model
  @State private var showingNewItemSheet = false

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
            ItemRow(item: item)
              .tag(item.key)
              .padding(6)
              .contextMenu {
                Button("Delete", role: .destructive) {
                  guard let vaultKey = model.selectedVaultKey else { return }
                  Task { await model.deleteItem(vaultKey: vaultKey, itemKey: item.key) }
                }
              }
          }
        }
      }
    }
    .navigationSplitViewColumnWidth(min: 200, ideal: 240)
    .navigationTitle(model.selectedVault.map { $0.name ?? $0.key } ?? "Items")
    .safeAreaInset(edge: .bottom) {
      if model.selectedVault != nil {
        HStack {
          Spacer()
          Button {
            showingNewItemSheet = true
          } label: {
            Label("New Item", systemImage: "plus")
          }
          .labelStyle(.iconOnly)
          .buttonStyle(.borderless)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
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
