import AxoPassFFI
import SwiftUI

/// Deleted items of one vault. A deleted item stays in the vault, with its
/// credentials and their values, until it is deleted permanently here.
struct RecentlyDeletedItemsSheet: View {
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let vaultKey: String

  @State private var deleted: [DeletedItemInfo]? = nil
  @State private var errorMessage: String? = nil
  @State private var confirmingPurge: DeletedItemInfo? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Recently Deleted").font(.headline)

      Group {
        if let deleted {
          if deleted.isEmpty {
            Text("No deleted items")
              .foregroundStyle(.secondary)
              .frame(maxWidth: .infinity, maxHeight: .infinity)
          } else {
            List(deleted, id: \.id) { item in
              row(item)
            }
          }
        } else {
          ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        }
      }
      .frame(height: 260)

      Text(
        "Deleted items stay in the vault, with their credentials and values, until you delete them permanently."
      )
      .font(.caption)
      .foregroundStyle(.secondary)

      if let errorMessage {
        Text(errorMessage)
          .font(.caption)
          .foregroundStyle(.red)
          .textSelection(.enabled)
      }

      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(20)
    .frame(width: 460)
    .task { await load() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .confirmationDialog(
      "Delete \"\(confirmingPurge?.title ?? "")\" permanently?",
      isPresented: Binding(
        get: { confirmingPurge != nil }, set: { if !$0 { confirmingPurge = nil } }),
      presenting: confirmingPurge
    ) { item in
      Button("Delete Permanently", role: .destructive) { purge(item) }
    } message: { item in
      Text(
        "The item and its \(item.credentialCount + item.deletedCredentialCount) credential(s) are erased from the vault. This cannot be undone."
      )
    }
  }

  private func row(_ item: DeletedItemInfo) -> some View {
    HStack(spacing: 12) {
      VStack(alignment: .leading, spacing: 2) {
        Text(item.title)
        Text(item.key)
          .font(.callout)
          .foregroundStyle(.secondary)
        Text(Date(timeIntervalSince1970: TimeInterval(item.deletedAt)).formatted())
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer(minLength: 0)
      Button("Restore") { restore(item) }
      Button("Delete Permanently") { confirmingPurge = item }
    }
    .padding(.vertical, 2)
  }

  private func load() async {
    do {
      deleted = try await model.deletedItems(vaultKey: vaultKey)
    } catch {
      deleted = []
      errorMessage = String(describing: error)
    }
  }

  private func restore(_ item: DeletedItemInfo) {
    errorMessage = nil
    Task {
      errorMessage = await failureMessage {
        try await model.restoreDeletedItem(
          vaultKey: vaultKey, itemId: item.id, preferredKey: item.key)
      }
      await load()
    }
  }

  private func purge(_ item: DeletedItemInfo) {
    errorMessage = nil
    Task {
      errorMessage = await failureMessage {
        try await model.purgeDeletedItem(vaultKey: vaultKey, itemId: item.id)
      }
      await load()
    }
  }
}
