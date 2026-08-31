import CryptoKit
import Foundation
import Observation
import AxoPassFFI

enum SidebarDestination: Hashable {
  case vault(String)
  case ssh
  case gpg
  case setup
}

@Observable
@MainActor
final class VaultsModel {
  private let core = AxoPass()

  // Sidebar navigation
  var sidebarSelection: SidebarDestination? = nil

  // Vault list
  var vaults: [VaultInfo] = []
  var loadError: String? = nil

  // Global lock state — mirrors LockStore in the Tauri app
  var isAppUnlocked = false
  var isUnlocking = false
  var unlockError: String? = nil

  // Per-vault item cache; populated lazily after global unlock
  private var itemCache: [String: [ItemInfo]] = [:]
  var selectedItemKey: String? = nil

  // Surfaces failures from vault/item/credential mutations (create, rename,
  // delete) to whichever pane triggered them.
  var actionError: String? = nil

  // MARK: - Vault list

  func reload() {
    do {
      vaults = try core.listVaults()
      loadError = nil
      if sidebarSelection == nil, let key = vaults.first?.key {
        sidebarSelection = .vault(key)
      }
    } catch {
      vaults = []
      loadError = String(describing: error)
    }
  }

  // MARK: - Global lock / unlock

  func unlock() async {
    guard !isUnlocking else { return }
    isUnlocking = true
    unlockError = nil
    do {
      try await core.unlock()
      isAppUnlocked = true
      if let key = selectedVaultKey { await loadItems(for: key) }
    } catch {
      unlockError = String(describing: error)
    }
    isUnlocking = false
  }

  func lock() {
    core.lock()
    isAppUnlocked = false
    itemCache = [:]
    selectedItemKey = nil
    unlockError = nil
  }

  // MARK: - Navigation

  func selectSidebarDestination(_ dest: SidebarDestination?) {
    guard dest != sidebarSelection else { return }
    let prevVaultKey = selectedVaultKey
    sidebarSelection = dest
    if selectedVaultKey != prevVaultKey {
      selectedItemKey = selectedVaultKey.flatMap { itemCache[$0]?.first?.key }
      if let key = selectedVaultKey, isAppUnlocked, itemCache[key] == nil {
        Task { await loadItems(for: key) }
      }
    }
  }

  // MARK: - Items

  private func loadItems(for vaultKey: String) async {
    do {
      let loaded = try await core.listItems(vaultKey: vaultKey)
      itemCache[vaultKey] = loaded
      if selectedVaultKey == vaultKey, selectedItemKey == nil {
        selectedItemKey = loaded.first?.key
      }
    } catch let e as FfiError {
      switch e {
      case .AuthExpired, .AuthCancelled: lock()
      default: break
      }
    } catch {}
  }

  // MARK: - Credentials

  func credentialSecret(itemKey: String, credKey: String) async throws -> SymmetricKey {
    guard let vaultKey = selectedVaultKey else { throw ModelError.noVaultSelected }
    var raw = try await core.getCredentialSecret(
      vaultKey: vaultKey, itemKey: itemKey, credKey: credKey
    )
    let key = SymmetricKey(data: raw)
    raw.resetBytes(in: raw.indices)
    return key
  }

  // MARK: - Vault CRUD

  @discardableResult
  func addVault(name: String?, key: String) async -> Bool {
    actionError = nil
    do {
      _ = try await core.addVault(name: name, vaultKey: key)
      reload()
      sidebarSelection = .vault(key)
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  @discardableResult
  func renameVault(vaultKey: String, newName: String?) async -> Bool {
    actionError = nil
    do {
      try await core.updateVault(vaultKey: vaultKey, newVaultKey: nil, newName: newName)
      reload()
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  @discardableResult
  func deleteVault(_ vaultKey: String) async -> Bool {
    actionError = nil
    do {
      try await core.deleteVault(vaultKey: vaultKey)
      itemCache.removeValue(forKey: vaultKey)
      if selectedVaultKey == vaultKey { sidebarSelection = nil }
      reload()
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  // MARK: - Item CRUD

  @discardableResult
  func addOrUpdateItem(vaultKey: String, itemKey: String, itemTitle: String) async -> Bool {
    actionError = nil
    do {
      try await core.addOrUpdateItem(vaultKey: vaultKey, itemKey: itemKey, itemTitle: itemTitle)
      await loadItems(for: vaultKey)
      selectedItemKey = itemKey
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  @discardableResult
  func deleteItem(vaultKey: String, itemKey: String) async -> Bool {
    actionError = nil
    do {
      try await core.deleteItem(vaultKey: vaultKey, itemKey: itemKey)
      if selectedItemKey == itemKey { selectedItemKey = nil }
      await loadItems(for: vaultKey)
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  // MARK: - Credential CRUD

  @discardableResult
  func addOrUpdateCredential(
    itemKey: String, credKey: String, title: String, value: String
  ) async -> Bool {
    guard let vaultKey = selectedVaultKey else {
      actionError = ModelError.noVaultSelected.errorDescription
      return false
    }
    actionError = nil
    do {
      try await core.addOrUpdateCredential(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, title: title, value: value
      )
      await loadItems(for: vaultKey)
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  @discardableResult
  func deleteCredential(itemKey: String, credKey: String) async -> Bool {
    guard let vaultKey = selectedVaultKey else {
      actionError = ModelError.noVaultSelected.errorDescription
      return false
    }
    actionError = nil
    do {
      try await core.deleteCredential(vaultKey: vaultKey, itemKey: itemKey, credKey: credKey)
      await loadItems(for: vaultKey)
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  // MARK: - Derived

  var selectedVaultKey: String? {
    if case .vault(let key) = sidebarSelection { return key }
    return nil
  }

  var selectedVault: VaultInfo? {
    vaults.first { $0.key == selectedVaultKey }
  }

  var items: [ItemInfo] {
    guard let key = selectedVaultKey else { return [] }
    return itemCache[key] ?? []
  }

  var selectedItem: ItemInfo? {
    items.first { $0.key == selectedItemKey }
  }

  enum ModelError: Error, LocalizedError {
    case noVaultSelected
    var errorDescription: String? { "No vault selected" }
  }
}
