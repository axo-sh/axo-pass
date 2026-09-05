import AppKit
import AxoPassFFI
import CryptoKit
import Foundation
import LocalAuthentication
import Observation

enum SidebarDestination: Hashable {
  case vault(String)
  case ssh
  case gpg
  case setup
}

/// The sidebar's "All Secrets" row selects this key. It is not a real vault;
/// the model expands it to every vault.
let allSecretsKey = "all"

/// Identifies one item within one vault. Item keys are unique only inside a
/// vault, so the "All Secrets" list needs the vault key to disambiguate.
struct ItemRef: Hashable {
  var vaultKey: String
  var itemKey: String
}

/// An item paired with the vault it lives in, for display and selection.
struct DisplayItem: Identifiable, Hashable {
  let vaultKey: String
  let item: ItemInfo

  var id: ItemRef { ItemRef(vaultKey: vaultKey, itemKey: item.key) }

  static func == (lhs: DisplayItem, rhs: DisplayItem) -> Bool { lhs.id == rhs.id }
  func hash(into hasher: inout Hasher) { hasher.combine(id) }
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
  // Whether the lock screen should raise a prompt on its own when it appears.
  // True at launch and after a manual lock, false once an attempt has finished
  // and after an automatic lock, which requires a deliberate Unlock.
  private(set) var autoPromptPending = true

  // LAAuthenticationView replaces the system dialog only for the context it was
  // created with. This model owns that context, evaluates the policy on it, and
  // hands it to the core so keychain operations reuse the authentication.
  private(set) var authContext: LAContext
  // Selects the lock screen copy, which differs when this Mac has no Touch ID.
  private(set) var biometry: LABiometryType = .none
  private var unlockTask: Task<Void, Never>? = nil
  private var autoLock: AutoLock! = nil

  // Draws the prompt for SSH signatures the agent delegates to us.
  private let signingPrompt = SigningPromptModel()
  private var signingBridge: SigningPromptBridge? = nil

  // Draws the prompts `ap pinentry` delegates to us for GPG.
  private let passphrasePrompt = PassphrasePromptModel()
  private var passphraseBridge: PassphrasePromptBridge? = nil

  // Per-vault item cache; populated lazily after global unlock
  private var itemCache: [String: [ItemInfo]] = [:]
  var selectedItemRef: ItemRef? = nil

  // Surfaces failures from vault/item/credential mutations (create, rename,
  // delete) to whichever pane triggered them.
  var actionError: String? = nil

  init() {
    authContext = LAContext()
    biometry = Self.probeBiometry(authContext)
    autoLock = AutoLock { [weak self] in self?.lock(automatic: true) }
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

  // MARK: - App broker

  /// Serve the CLI's requests while the app is running: SSH signatures from
  /// the agent, GPG passphrases from `ap pinentry`. Both use their own keychain
  /// items, so this does not wait on the vault being unlocked. With the app
  /// unavailable the agent falls back to the system dialog.
  func startBroker() async {
    guard signingBridge == nil else { return }
    let signing = SigningPromptBridge(model: signingPrompt)
    let passphrase = PassphrasePromptBridge(model: passphrasePrompt)
    signingBridge = signing
    passphraseBridge = passphrase
    do {
      try await core.startAppBroker(signDelegate: signing, passphraseDelegate: passphrase)
      signingPrompt.start()
      // Authorizations also expire on their own clocks, but sleep and screen
      // lock belong to the broker's lifetime: requests are served with the
      // vault locked, where AutoLock does not run, so without these an approval
      // given to a locked app would only expire on its own clocks.
      observePromptExpiry(NSWorkspace.shared.notificationCenter, NSWorkspace.willSleepNotification)
      observePromptExpiry(
        DistributedNotificationCenter.default(),
        Notification.Name("com.apple.screenIsLocked"))
    } catch {
      signingBridge = nil
      passphraseBridge = nil
      NSLog("Failed to start the app broker: %@", String(describing: error))
    }
  }

  /// Drop every authorization the prompts are holding when `name` fires. The
  /// observers live as long as the app, like the broker they belong to.
  private func observePromptExpiry(_ center: NotificationCenter, _ name: Notification.Name) {
    center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
      MainActor.assumeIsolated {
        self?.signingPrompt.forgetAll()
        self?.passphrasePrompt.forgetAll()
      }
    }
  }

  // MARK: - Global lock / unlock

  /// Unlock with the embedded biometric prompt. Without Touch ID the icon has
  /// no state to show, so this falls back to the system dialog and its password
  /// field.
  /// Prompt when the lock screen appears, but only if a prompt is wanted and
  /// answerable: an automatic lock waits for a deliberate Unlock, and a prompt
  /// raised while the app is in the background fails at once.
  func unlockIfActive() {
    guard autoPromptPending, NSApp.isActive else { return }
    unlock()
  }

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
      autoPromptPending = false
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
      autoLock.start()
      await loadItemsForSelection()
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

  /// True while an attempt is in flight, or about to be. The second clause
  /// covers the gap between the lock screen appearing and its `onAppear`
  /// starting the attempt, and is false when the app is in the background,
  /// where `unlockIfActive` declines to prompt at all.
  var isPrompting: Bool { isUnlocking || (autoPromptPending && NSApp.isActive) }

  /// What to do about the prompt that is up. Only shown while one is.
  var unlockInstruction: String {
    biometry == .touchID
      ? "Touch the Touch ID sensor to unlock."
      : "Confirm with your login password to unlock."
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
      return
        "No fingerprints are enrolled. Use your login password, or add one in System Settings › Touch ID & Password."
    case .biometryLockout:
      return "Touch ID is locked after too many failed attempts. Use your login password instead."
    case .passcodeNotSet:
      return "Set a login password in System Settings to use Axo Pass."
    default: return String(describing: error)
    }
  }

  /// `automatic` marks a lock the user did not ask for: idle timeout, sleep, or
  /// screen lock. Those land on the lock screen without a prompt, so returning
  /// to the app takes a deliberate Unlock rather than a Touch ID prompt the user
  /// did not expect.
  func lock(automatic: Bool = false) {
    autoLock.stop()
    // A failure here means the core's state is poisoned, not that the vaults
    // stayed decrypted. Lock the UI either way.
    do {
      try core.lock()
    } catch {
      actionError = String(describing: error)
    }
    unlockTask = nil
    // A lock drops every authorization the user has given: signing, and the
    // GPG passphrases pinentry unlocked.
    signingPrompt.forgetAll()
    passphrasePrompt.forgetAll()
    resetAuthContext(invalidatingCurrent: true)
    isAppUnlocked = false
    itemCache = [:]
    selectedItemRef = nil
    unlockError = nil
    autoPromptPending = !automatic
  }

  // MARK: - Navigation

  func selectSidebarDestination(_ dest: SidebarDestination?) {
    guard dest != sidebarSelection else { return }
    let prevVaultKey = selectedVaultKey
    sidebarSelection = dest
    if selectedVaultKey != prevVaultKey {
      // Settle on a cached row synchronously so the detail pane does not flash
      // its "select an item" placeholder before the async load fixes it up.
      selectedItemRef = displayItems.first?.id
      if isAppUnlocked { Task { await loadItemsForSelection() } }
    }
  }

  // MARK: - Items

  /// Which vault keys the current selection covers: every vault for "All
  /// Secrets", otherwise the one selected vault.
  private var selectedVaultKeys: [String] {
    guard let key = selectedVaultKey else { return [] }
    return isAllSecrets ? vaults.map { $0.key } : [key]
  }

  /// Load the items every pane needs for the current selection, then settle
  /// `selectedItemRef` on a row that still exists.
  private func loadItemsForSelection() async {
    guard isAppUnlocked else { return }
    for vaultKey in selectedVaultKeys where itemCache[vaultKey] == nil {
      await loadItems(for: vaultKey)
    }
    if selectedItemRef == nil || !displayItems.contains(where: { $0.id == selectedItemRef }) {
      selectedItemRef = displayItems.first?.id
    }
  }

  private func loadItems(for vaultKey: String) async {
    do {
      itemCache[vaultKey] = try await core.listItems(vaultKey: vaultKey)
    } catch let e as FfiError {
      switch e {
      case .AuthExpired, .AuthCancelled:
        lock()
      default:
        // Record the failure so the pane stops spinning and shows it.
        itemCache[vaultKey] = []
        actionError = String(describing: e)
      }
    } catch {
      itemCache[vaultKey] = []
      actionError = String(describing: error)
    }
  }

  // MARK: - Credentials

  func credentialSecret(vaultKey: String, itemKey: String, credKey: String) async throws
    -> SymmetricKey
  {
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
      selectedItemRef = ItemRef(vaultKey: vaultKey, itemKey: itemKey)
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
      if selectedItemRef == ItemRef(vaultKey: vaultKey, itemKey: itemKey) { selectedItemRef = nil }
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
    vaultKey: String, itemKey: String, credKey: String, title: String, value: String
  ) async -> Bool {
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
  func deleteCredential(vaultKey: String, itemKey: String, credKey: String) async -> Bool {
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

  /// True when the sidebar's "All Secrets" row is selected.
  var isAllSecrets: Bool { selectedVaultKey == allSecretsKey }

  /// The items to show for the current selection, each tagged with its vault.
  /// "All Secrets" merges every vault and sorts by title.
  var displayItems: [DisplayItem] {
    guard selectedVaultKey != nil else { return [] }
    if isAllSecrets {
      return
        vaults
        .flatMap { vault in
          (itemCache[vault.key] ?? []).map { DisplayItem(vaultKey: vault.key, item: $0) }
        }
        .sorted {
          $0.item.title.localizedCaseInsensitiveCompare($1.item.title) == .orderedAscending
        }
    }
    guard let key = selectedVaultKey else { return [] }
    return (itemCache[key] ?? []).map { DisplayItem(vaultKey: key, item: $0) }
  }

  var selectedItem: DisplayItem? {
    guard let ref = selectedItemRef else { return nil }
    return displayItems.first { $0.id == ref }
  }

  /// A selection is active and its items have not finished loading yet. Panes
  /// use this to show a loading state instead of an empty "select" placeholder.
  var isLoadingSelectedItems: Bool {
    guard isAppUnlocked, selectedVaultKey != nil else { return false }
    if isAllSecrets {
      return !vaults.isEmpty && vaults.contains { itemCache[$0.key] == nil }
    }
    guard let key = selectedVaultKey else { return false }
    return itemCache[key] == nil
  }
}
