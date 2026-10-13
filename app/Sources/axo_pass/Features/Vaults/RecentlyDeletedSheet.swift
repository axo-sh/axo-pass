import AxoPassFFI
import SwiftUI

/// Deleted credentials of one item. A deleted credential stays in the vault,
/// with its value, until it is deleted permanently here.
struct RecentlyDeletedSheet: View {
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let vaultKey: String
  let itemKey: String

  @State private var deleted: [DeletedCredentialInfo]? = nil
  @State private var errorMessage: String? = nil
  @State private var confirmingPurge: DeletedCredentialInfo? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Recently Deleted").font(.headline)

      Group {
        if let deleted {
          if deleted.isEmpty {
            Text("No deleted credentials")
              .foregroundStyle(.secondary)
              .frame(maxWidth: .infinity, maxHeight: .infinity)
          } else {
            List(deleted, id: \.id) { cred in
              row(cred)
            }
          }
        } else {
          ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        }
      }
      .frame(height: 260)

      Text(
        "Deleted credentials stay in the vault, with their values, until you delete them permanently."
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
    ) { cred in
      Button("Delete Permanently", role: .destructive) { purge(cred) }
    } message: { _ in
      Text("Its value is erased from the vault. This cannot be undone.")
    }
  }

  private func row(_ cred: DeletedCredentialInfo) -> some View {
    HStack(spacing: 12) {
      VStack(alignment: .leading, spacing: 2) {
        Text(cred.title)
        Text(cred.key)
          .font(.callout)
          .foregroundStyle(.secondary)
        Text(Date(timeIntervalSince1970: TimeInterval(cred.deletedAt)).formatted())
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer(minLength: 0)
      Button("Restore") { restore(cred) }
      Button("Delete Permanently") { confirmingPurge = cred }
    }
    .padding(.vertical, 2)
  }

  private func load() async {
    do {
      deleted = try await model.deletedCredentials(vaultKey: vaultKey, itemKey: itemKey)
    } catch {
      deleted = []
      errorMessage = String(describing: error)
    }
  }

  private func restore(_ cred: DeletedCredentialInfo) {
    errorMessage = nil
    Task {
      errorMessage = await failureMessage {
        try await model.restoreDeletedCredential(
          vaultKey: vaultKey, itemKey: itemKey, cred)
      }
      await load()
    }
  }

  private func purge(_ cred: DeletedCredentialInfo) {
    errorMessage = nil
    Task {
      errorMessage = await failureMessage {
        try await model.purgeDeletedCredential(
          vaultKey: vaultKey, itemKey: itemKey, credId: cred.id)
      }
      await load()
    }
  }
}
