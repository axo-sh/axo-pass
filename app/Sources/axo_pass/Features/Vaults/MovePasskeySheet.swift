import AxoPassFFI
import SwiftUI

/// Chooses where a passkey moves to: a vault, and an item in it or a new login.
struct MovePasskeySheet: View {
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let sourceVaultKey: String
  let sourceItemKey: String
  /// Moves the passkey. Returns an error message, or `nil` on success.
  let onMove: (_ destVaultKey: String, _ destItemKey: String?) async -> String?

  @State private var vaultKey: String
  /// The destination item's key. `nil` means a new login.
  @State private var itemKey: String?
  @State private var items: [ItemInfo] = []
  @State private var isMoving = false
  @State private var errorMessage: String?

  init(
    sourceVaultKey: String, sourceItemKey: String,
    onMove: @escaping (_ destVaultKey: String, _ destItemKey: String?) async -> String?
  ) {
    self.sourceVaultKey = sourceVaultKey
    self.sourceItemKey = sourceItemKey
    self.onMove = onMove
    _vaultKey = State(initialValue: sourceVaultKey)
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Move Passkey").font(.headline)
      Form {
        Picker("Vault", selection: $vaultKey) {
          ForEach(model.vaults, id: \.key) { vault in
            Text(vault.name ?? vault.key).tag(vault.key)
          }
        }
        Picker("Move to", selection: $itemKey) {
          Text("New login").tag(String?.none)
          ForEach(destinations, id: \.key) { item in
            Text(item.title).tag(String?.some(item.key))
          }
        }
      }

      Text("The passkey is copied to the new place before it is removed from this item.")
        .font(.caption)
        .foregroundStyle(.secondary)

      if let errorMessage {
        Text(errorMessage)
          .font(.caption)
          .foregroundStyle(.red)
      }

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Move") {
          Task {
            isMoving = true
            errorMessage = nil
            if let error = await onMove(vaultKey, itemKey) {
              errorMessage = error
            } else {
              dismiss()
            }
            isMoving = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isMoving || isSameItem)
      }
    }
    .padding(20)
    .frame(width: 380)
    .task(id: vaultKey) {
      items = await model.destinationItems(in: vaultKey)
      itemKey = nil
    }
  }

  /// The items of the chosen vault, less the one the passkey is in.
  private var destinations: [ItemInfo] {
    items.filter { !(vaultKey == sourceVaultKey && $0.key == sourceItemKey) }
  }

  /// Moving a passkey into the item it is already in does nothing.
  private var isSameItem: Bool {
    vaultKey == sourceVaultKey && itemKey == sourceItemKey
  }
}
