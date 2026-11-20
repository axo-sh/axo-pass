import AxoPassFFI
import Foundation
import Observation

/// A deleted item or credential in the Recently Deleted list. Credentials are
/// ones deleted from an item that still exists. The credentials of a deleted
/// item are listed with the item.
enum DeletedEntry: Identifiable, Hashable {
  case item(vaultKey: String, DeletedItemInfo)
  case credential(vaultKey: String, DeletedCredentialInfo)

  var id: String {
    switch self {
    case .item(let vaultKey, let item): "item:\(vaultKey):\(item.id)"
    case .credential(let vaultKey, let cred): "credential:\(vaultKey):\(cred.id)"
    }
  }

  var vaultKey: String {
    switch self {
    case .item(let vaultKey, _), .credential(let vaultKey, _): vaultKey
    }
  }

  var title: String {
    switch self {
    case .item(_, let item): item.title
    case .credential(_, let cred): cred.title
    }
  }

  var key: String {
    switch self {
    case .item(_, let item): item.key
    case .credential(_, let cred): cred.key
    }
  }

  /// Deletion time.
  var deletedAt: Date {
    switch self {
    case .item(_, let item): Date(timeIntervalSince1970: TimeInterval(item.deletedAt))
    case .credential(_, let cred): Date(timeIntervalSince1970: TimeInterval(cred.deletedAt))
    }
  }
}

/// Deleted items and credentials of all vaults, for the Recently Deleted view.
/// The list is loaded when the view appears. It holds no secret values.
@Observable
@MainActor
final class RecentlyDeletedModel {
  private(set) var entries: [DeletedEntry] = []
  private(set) var isLoading = false
  /// Vaults that failed to load, with their errors.
  private(set) var loadError: String? = nil
  /// Result of the last restore that changed a key.
  var notice: String? = nil
  /// Error of the last failed restore or delete.
  var actionError: String? = nil
  var selection: String? = nil

  var selectedEntry: DeletedEntry? {
    entries.first { $0.id == selection }
  }

  /// Load the deleted items and credentials of every vault, most recently
  /// deleted first.
  func reload(using vaults: VaultsModel) async {
    isLoading = true
    defer { isLoading = false }

    var loaded: [DeletedEntry] = []
    var failures: [String] = []
    for vault in vaults.vaults {
      var failure: Error? = nil
      do {
        let items = try await vaults.deletedItems(vaultKey: vault.key)
        loaded += items.map { .item(vaultKey: vault.key, $0) }
      } catch {
        failure = error
      }
      do {
        let credentials = try await vaults.deletedCredentials(vaultKey: vault.key)
        loaded += credentials.map { .credential(vaultKey: vault.key, $0) }
      } catch {
        failure = failure ?? error
      }
      if let failure {
        failures.append("\(vault.name ?? vault.key): \(failure)")
      }
    }
    entries = loaded.sorted { $0.deletedAt > $1.deletedAt }
    loadError = failures.isEmpty ? nil : failures.joined(separator: "\n")
    if selectedEntry == nil { selection = nil }
  }

  /// Restore an entry. An item or credential whose key was reused is restored
  /// under a new key, reported in `notice`.
  func restore(_ entry: DeletedEntry, using vaults: VaultsModel) async {
    notice = nil
    actionError = nil
    do {
      let restoredKey: String
      switch entry {
      case .item(let vaultKey, let item):
        restoredKey = try await vaults.restoreDeletedItem(
          vaultKey: vaultKey, itemId: item.id, preferredKey: item.key)
      case .credential(let vaultKey, let cred):
        restoredKey = try await vaults.restoreDeletedCredential(vaultKey: vaultKey, cred)
      }
      if restoredKey != entry.key {
        notice = "\(entry.title) was restored as \(restoredKey) because \(entry.key) is in use."
      }
    } catch {
      actionError = "Restore failed. \(error)"
    }
    await reload(using: vaults)
  }

  /// Delete an entry permanently.
  func purge(_ entry: DeletedEntry, using vaults: VaultsModel) async {
    notice = nil
    actionError = nil
    do {
      switch entry {
      case .item(let vaultKey, let item):
        try await vaults.purgeDeletedItem(vaultKey: vaultKey, itemId: item.id)
      case .credential(let vaultKey, let cred):
        try await vaults.purgeDeletedCredential(vaultKey: vaultKey, cred)
      }
    } catch {
      actionError = "Delete failed. \(error)"
    }
    await reload(using: vaults)
  }
}
