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
                  Task {
                    await model.deleteItem(vaultKey: display.vaultKey, itemKey: display.item.key)
                  }
                }
              }
          }
        }
      }
    }
    .paneBackground()
    .navigationSplitViewColumnWidth(min: 200, ideal: 240)
    .navigationTitle(
      model.selectedVault.map { $0.name ?? $0.key }
        ?? (model.isAllSecrets ? "All Secrets" : "")
    )
    .toolbar {
      ToolbarItem(placement: .primaryAction) {
        Button {
          showingNewItemSheet = true
        } label: {
          Label("New Item", systemImage: "plus")
        }
        .disabled(model.selectedVault == nil)
      }
    }
    .sheet(isPresented: $showingNewItemSheet) {
      NewItemSheet { key, title in
        guard let vaultKey = model.selectedVaultKey else { return "No vault selected." }
        if await model.addOrUpdateItem(vaultKey: vaultKey, itemKey: key, itemTitle: title) {
          return nil
        }
        return model.actionError ?? "Failed to create item."
      }
    }
  }
}

private struct NewItemSheet: View {
  let onSubmit: (_ key: String, _ title: String) async -> String?

  @Environment(\.dismiss) private var dismiss
  @State private var title: String = ""
  @State private var key: String = ""
  @State private var isSubmitting = false
  @State private var errorMessage: String?

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Item").font(.headline)
      Form {
        TextField("Title", text: $title)
        TextField("Key", text: $key)
        LabeledContent("") {
          Text("a-z, 0-9, -, _")
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
      }

      if let errorMessage {
        Text(errorMessage)
          .font(.caption)
          .foregroundStyle(.red)
      }

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Create") {
          Task {
            isSubmitting = true
            errorMessage = nil
            if let error = await onSubmit(key, title) {
              errorMessage = error
            } else {
              dismiss()
            }
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
        .font(.subheadline)
        .foregroundStyle(.secondary)
    }
  }
}
