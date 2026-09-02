import CryptoKit
import Foundation
import LocalAuthentication
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
  // False until the first attempt finishes. The lock screen prompts as soon as
  // it appears, so without this the idle copy and the Unlock button show for a
  // frame on launch.
  private(set) var hasAttemptedUnlock = false

  // LAAuthenticationView replaces the system dialog only for the context it was
  // created with. This model owns that context, evaluates the policy on it, and
  // hands it to the core so keychain operations reuse the authentication.
  private(set) var authContext: LAContext
  // Selects the lock screen copy, which differs when this Mac has no Touch ID.
  private(set) var biometry: LABiometryType = .none
  private var unlockTask: Task<Void, Never>? = nil

  // Per-vault item cache; populated lazily after global unlock
  private var itemCache: [String: [ItemInfo]] = [:]
  var selectedItemKey: String? = nil

  // Surfaces failures from vault/item/credential mutations (create, rename,
  // delete) to whichever pane triggered them.
  var actionError: String? = nil

  init() {
    authContext = LAContext()
    biometry = Self.probeBiometry(authContext)
  }

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

  /// Unlock with the embedded biometric prompt. Without Touch ID the icon has
  /// no state to show, so this falls back to the system dialog and its password
  /// field.
  func unlock() {
    guard !isUnlocking else { return }
    // The model owns the task. The lock screen's `.task` would cancel the
    // attempt as soon as a successful unlock swapped the view out.
    unlockTask = Task { [self] in
      await authenticate(with: biometry == .touchID ? authContext : LAContext())
    }
  }

  /// Unlock through the system dialog, which offers the login password. It runs
  /// on a separate context because `LAAuthenticationView` suppresses that dialog
  /// for the context it is attached to.
  ///
  /// Callable while the embedded prompt is up, in which case it dismisses that
  /// prompt and waits for the attempt to finish first.
  func unlockWithPassword() {
    let pending = unlockTask
    if isUnlocking { resetAuthContext(invalidatingCurrent: true) }
    unlockTask = Task { [self] in
      await pending?.value
      await authenticate(with: LAContext())
    }
  }

  private func authenticate(with context: LAContext) async {
    guard !isUnlocking else { return }
    isUnlocking = true
    unlockError = nil
    defer {
      isUnlocking = false
      hasAttemptedUnlock = true
    }

    do {
      // The core holds this lock around its own prompts. Take it here too, or
      // a concurrent prompt from another axo-pass process cancels this one.
      try await core.beginEmbeddedAuth()
    } catch {
      unlockError = String(describing: error)
      return
    }

    do {
      try await context.evaluatePolicy(
        .deviceOwnerAuthentication, localizedReason: "unlock Axo Pass")
      try core.adoptAuthContext(
        contextPtr: UInt64(UInt(bitPattern: Unmanaged.passUnretained(context).toOpaque())))
      try? core.endEmbeddedAuth()
      isAppUnlocked = true
      if let key = selectedVaultKey { await loadItems(for: key) }
    } catch {
      try? core.endEmbeddedAuth()
      unlockError = Self.describeUnlockFailure(error)
      // An invalidated context cannot be evaluated again, so replace it.
      if (error as? LAError)?.code == .invalidContext, context === authContext {
        resetAuthContext()
      }
    }
  }

  private func resetAuthContext(invalidatingCurrent: Bool = false) {
    // Invalidating fails any evaluation in flight on the old context, which is
    // how an embedded prompt on screen gets dismissed.
    if invalidatingCurrent { authContext.invalidate() }
    authContext = LAContext()
    biometry = Self.probeBiometry(authContext)
  }

  // biometryType is only populated after a policy has been evaluated against
  // the context, so run canEvaluatePolicy first.
  private static func probeBiometry(_ context: LAContext) -> LABiometryType {
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
      return .none
    }
    return context.biometryType
  }

  /// True from the moment the lock screen appears until an attempt finishes.
  /// Covers the gap before the first `unlock()` sets `isUnlocking`.
  var isPrompting: Bool { isUnlocking || !hasAttemptedUnlock }

  /// What the lock screen asks the user to do, given the available
  /// authentication and whether a prompt is up.
  var unlockInstruction: String {
    if isPrompting {
      return biometry == .touchID
        ? "Touch the Touch ID sensor to unlock."
        : "Confirm with your login password to unlock."
    }
    return biometry == .touchID
      ? "Unlock with Touch ID, or use your login password, to open your vaults."
      : "Unlock with your login password to open your vaults."
  }

  /// Whether to show the password option separately. Without Touch ID the
  /// primary button already leads there.
  var offersPasswordUnlock: Bool { biometry == .touchID }

  private static func describeUnlockFailure(_ error: Error) -> String? {
    switch (error as? LAError)?.code {
    // The user dismissed the prompt. The lock screen is unchanged and there is
    // nothing to report.
    case .userCancel, .appCancel, .systemCancel: return nil
    case .userFallback: return nil
    case .biometryNotEnrolled:
      return "No fingerprints are enrolled. Use your login password, or add one in System Settings › Touch ID & Password."
    case .biometryLockout:
      return "Touch ID is locked after too many failed attempts. Use your login password instead."
    case .passcodeNotSet:
      return "Set a login password in System Settings to use Axo Pass."
    default: return String(describing: error)
    }
  }

  func lock() {
    // A failure here means the core's state is poisoned, not that the vaults
    // stayed decrypted. Lock the UI either way.
    do {
      try core.lock()
    } catch {
      actionError = String(describing: error)
    }
    unlockTask = nil
    resetAuthContext(invalidatingCurrent: true)
    isAppUnlocked = false
    itemCache = [:]
    selectedItemKey = nil
    unlockError = nil
    // The lock screen prompts again as soon as it reappears.
    hasAttemptedUnlock = false
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
