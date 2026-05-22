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
