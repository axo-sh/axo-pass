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
  case age
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
  private(set) var sidebarSelection: SidebarDestination? = nil

  // Where the sidebar is headed while that destination's items load. The panes
  // keep showing the current selection until the load lands, so switching to a
  // vault that has to be decrypted does not blank them first.
  private(set) var pendingSelection: SidebarDestination? = nil
  private var selectionTask: Task<Void, Never>? = nil

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
  // Whether the user has started an unlock attempt since the last lock. Lets the
  // lock screen re-raise the Touch ID prompt when returning to the app, since
  // switching away cancels an evaluation in flight.
  private var unlockEngaged = false

  // LAAuthenticationView replaces the system dialog only for the context it was
  // created with. This model owns that context, evaluates the policy on it, and
  // hands it to the core so keychain operations reuse the authentication.
  private(set) var authContext: LAContext
  // Selects the lock screen copy, which differs when this Mac has no Touch ID.
  private(set) var biometry: LABiometryType = .none
  private var unlockTask: Task<Void, Never>? = nil
  // The context `authenticate` is currently evaluating on, which is not always
  // `authContext`: the password path runs on one of its own. Invalidating this
  // is how a prompt on screen gets taken down.
  private var evaluatingContext: LAContext? = nil
  private var autoLock: AutoLock! = nil

  // Draws the prompt for SSH signatures the agent delegates to us.
  private let signingPrompt = SigningPromptModel()
  private var signingBridge: SigningPromptBridge? = nil

  // Draws the prompts `ap pinentry` delegates to us for GPG.
  private let passphrasePrompt = PassphrasePromptModel()
  private var passphraseBridge: PassphrasePromptBridge? = nil

  // Draws the prompt `ap item list` and `ap read` delegate to us.
  private let vaultUnlockPrompt = VaultUnlockPromptModel()
  private var vaultUnlockBridge: VaultUnlockPromptBridge? = nil

  // Per-vault item cache; populated lazily after global unlock
  private var itemCache: [String: [ItemInfo]] = [:]
  var selectedItemRef: ItemRef? = nil

  // Surfaces failures from vault/item/credential mutations (create, rename,
  // delete) to whichever pane triggered them.
  var actionError: String? = nil

  init() {
    authContext = LAContext()
    biometry = Self.probeBiometry(authContext)
    autoLock = AutoLock { [weak self] trigger in self?.lock(automatic: trigger) }
  }

  // MARK: - Vault list

  func reload() {
    do {
      vaults = try core.listVaults().sorted {
        ($0.name ?? $0.key).localizedCaseInsensitiveCompare($1.name ?? $1.key) == .orderedAscending
      }
      loadError = nil
      if sidebarSelection == nil, let key = vaults.first?.key {
        selectSidebarDestination(.vault(key))
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
    let vaultUnlock = VaultUnlockPromptBridge(model: vaultUnlockPrompt)
    signingBridge = signing
    passphraseBridge = passphrase
    vaultUnlockBridge = vaultUnlock
    vaultUnlockPrompt.core = core

    // A broker panel carries its own biometric on its own context and takes the
    // cross-process auth lock. Step the lock screen's auto-unlock aside for it,
    // so the two do not deadlock on that lock with one panel hiding the other.
    // It does not resume on its own afterward: the user unlocks deliberately.
    let onPanel: (Bool) -> Void = { [weak self] visible in
      if visible { self?.suspendAutoUnlock() }
    }
    signingPrompt.panel.onVisibleChange = onPanel
    passphrasePrompt.panel.onVisibleChange = onPanel
    vaultUnlockPrompt.panel.onVisibleChange = onPanel
    do {
      try await core.startAppBroker(
        signDelegate: signing, passphraseDelegate: passphrase, vaultDelegate: vaultUnlock)
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
      vaultUnlockBridge = nil
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
        self?.vaultUnlockPrompt.forgetAll()
      }
    }
  }

  // MARK: - Global lock / unlock

  /// Prompt when the lock screen appears, but only if a prompt is wanted and
  /// answerable: an automatic lock waits for a deliberate Unlock, and a prompt
  /// raised while the app is in the background fails at once.
  func unlockIfActive() {
    guard autoPromptPending, NSApp.isActive else { return }
    // A broker panel holds the auth lock and carries its own biometric; the
    // lock screen must not raise a competing one behind it.
    guard !signingPrompt.panel.isVisible, !passphrasePrompt.panel.isVisible,
      !vaultUnlockPrompt.panel.isVisible
    else { return }
    unlock()
  }

  /// Handle the app regaining focus. Raises the first automatic prompt through
  /// `unlockIfActive`, then re-raises the Touch ID prompt if the user already
  /// started an unlock and switching away cancelled the evaluation.
  func handleBecameActive() {
    unlockIfActive()

    guard unlockEngaged, !isAppUnlocked, !isUnlocking, NSApp.isActive else { return }
    guard biometry == .touchID else { return }
    guard !signingPrompt.panel.isVisible, !passphrasePrompt.panel.isVisible,
      !vaultUnlockPrompt.panel.isVisible
    else { return }
    unlock()
  }

  /// Whether the broker started this app to serve a request, rather than a
  /// person opening it.
  func isBrokerLaunch() -> Bool {
    core.isBrokerLaunch()
  }

  /// Give up an auto-unlock in flight so a broker prompt can take the auth lock
  /// and the biometric hardware. The attempt cleans up after itself: the failed
  /// evaluation releases the lock and clears `isUnlocking` on its way out. The
  /// lock screen stays put; the user unlocks deliberately afterward.
  private func suspendAutoUnlock() {
    // Cancelling covers the window between `unlock` and the task reaching
    // `authenticate`, where there is no evaluation to fail yet.
    unlockTask?.cancel()
    cancelEvaluation()
  }

  /// Fail the evaluation in flight, which is how a prompt on screen gets
  /// dismissed. Does nothing when there is none.
  private func cancelEvaluation() {
    guard let context = evaluatingContext else { return }
    context.invalidate()
    // An invalidated context cannot be evaluated again, so replace it.
    if context === authContext { resetAuthContext() }
  }

  /// Unlock with the embedded biometric prompt. Without Touch ID the icon has
  /// no state to show, so this falls back to the system dialog and its password
  /// field.
  func unlock() {
    guard !isUnlocking else { return }
    unlockEngaged = true
    // The model owns the task. The lock screen's `.task` would cancel the
    // attempt as soon as a successful unlock swapped the view out.
    unlockTask = Task { [self] in
      guard !Task.isCancelled else { return }
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
    cancelEvaluation()
    unlockTask = Task { [self] in
      await pending?.value
      await authenticate(with: LAContext())
    }
  }

  private func authenticate(with context: LAContext) async {
    guard !isUnlocking else { return }
    isUnlocking = true
    unlockError = nil
    evaluatingContext = context
    defer {
      evaluatingContext = nil
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
      // Release the cross-process auth lock before adopting the context.
      // adoptAuthContext runs on the core's shared-auth thread, which takes the
      // same lock for its own work; holding it here while that call blocks
      // deadlocks the two. Evaluation is done, so the lock is no longer needed.
      try? core.endEmbeddedAuth()
      // adoptAuthContext blocks until the shared-auth thread services it, so
      // keep it off the main thread.
      let contextPtr = UInt64(UInt(bitPattern: Unmanaged.passUnretained(context).toOpaque()))
      try await Task.detached { [core] in try core.adoptAuthContext(contextPtr: contextPtr) }.value
      isAppUnlocked = true
      AuditBridge.recordVault(.unlocked)
      autoLock.start()
      await loadItemsForSelection()
    } catch {
      try? core.endEmbeddedAuth()
      unlockError = Self.describeUnlockFailure(error)
    }
  }

  private func resetAuthContext() {
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
  func lock(automatic trigger: AutoLockTrigger? = nil) {
    autoLock.stop()
    // A failure here means the core's state is poisoned, not that the vaults
    // stayed decrypted. Lock the UI either way.
    do {
      try core.lock()
    } catch {
      actionError = String(describing: error)
    }
    // `core.lock()` records `vault.lock`; add the automatic cause on top.
    if let trigger {
      AuditBridge.recordVault(.autolocked, trigger: trigger.rawValue)
    }
    unlockTask = nil
    // A lock drops every authorization the user has given: signing, and the
    // GPG passphrases pinentry unlocked.
    signingPrompt.forgetAll()
    passphrasePrompt.forgetAll()
    // Fail whatever prompt is on screen, which is not always on `authContext`,
    // then drop the authenticated context itself.
    cancelEvaluation()
    authContext.invalidate()
    resetAuthContext()
    isAppUnlocked = false
    // A vault switch waiting on a load has nothing to land on now.
    selectionTask?.cancel()
    selectionTask = nil
    pendingSelection = nil
    itemCache = [:]
    selectedItemRef = nil
    unlockError = nil
    autoPromptPending = trigger == nil
    unlockEngaged = false
  }

  // MARK: - Navigation

  /// What the sidebar highlights: the destination being loaded when there is
  /// one, so a click registers immediately even though the panes have not
  /// switched yet.
  var sidebarHighlight: SidebarDestination? { pendingSelection ?? sidebarSelection }

  /// True while `dest`'s items are loading and the panes still show the
  /// previous selection.
  func isPendingSelection(_ dest: SidebarDestination) -> Bool {
    pendingSelection == dest
  }

  func selectSidebarDestination(_ dest: SidebarDestination?) {
    guard dest != sidebarHighlight else { return }
    selectionTask?.cancel()
    selectionTask = nil
    pendingSelection = nil

    // Only a vault whose items are not cached has anything to wait for.
    let missing = vaultKeys(for: dest).filter { itemCache[$0] == nil }
    guard isAppUnlocked, !missing.isEmpty else {
      commitSelection(dest)
      return
    }

    pendingSelection = dest
    selectionTask = Task { [self] in
      for vaultKey in missing {
        await loadItems(for: vaultKey)
        if Task.isCancelled { return }
      }
      commitSelection(dest)
    }
  }

  /// Switch the panes to `dest`, settling on a row in one main-actor tick so no
  /// frame renders the new vault with nothing selected.
  private func commitSelection(_ dest: SidebarDestination?) {
    pendingSelection = nil
    let prevVaultKey = selectedVaultKey
    sidebarSelection = dest
    guard selectedVaultKey != prevVaultKey else { return }
    selectedItemRef = displayItems.first?.id
    // A vault added or imported since the last load still needs its items.
    if isAppUnlocked { Task { await loadItemsForSelection() } }
  }

  // MARK: - Items

  /// Which vault keys a destination covers: every vault for "All Secrets", the
  /// one vault otherwise, and none for the tool sections.
  private func vaultKeys(for dest: SidebarDestination?) -> [String] {
    guard case .vault(let key) = dest else { return [] }
    return key == allSecretsKey ? vaults.map { $0.key } : [key]
  }

  /// Which vault keys the current selection covers.
  private var selectedVaultKeys: [String] { vaultKeys(for: sidebarSelection) }

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
      selectSidebarDestination(.vault(key))
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
      if selectedVaultKey == vaultKey { selectSidebarDestination(nil) }
      reload()
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  // MARK: - Bundle export / import

  /// Export the given vaults to a passphrase-encrypted bundle file. Returns an
  /// error message on failure, nil on success. `onStage` is called on the main
  /// actor as the export progresses.
  func exportBundle(
    vaultKeys: [String],
    destination: URL,
    passphrase: String,
    workFactor: ExportWorkFactor,
    onStage: @escaping @MainActor (VaultExportStage, UInt32, UInt32) -> Void
  ) async -> String? {
    let delegate = ExportProgressForwarder(onStage)
    do {
      try await core.exportVaultBundle(
        vaultKeys: vaultKeys, destPath: destination.path, passphrase: passphrase,
        workFactor: workFactor, progress: delegate)
      return nil
    } catch {
      return String(describing: error)
    }
  }

  /// List the vaults in a bundle file without importing anything. Returns nil
  /// and sets `message` on failure.
  func inspectBundle(source: URL, passphrase: String) async -> (
    vaults: [BundleVaultInfo]?, message: String?
  ) {
    do {
      let vaults = try await core.inspectVaultBundle(srcPath: source.path, passphrase: passphrase)
      return (vaults, nil)
    } catch {
      return (nil, String(describing: error))
    }
  }

  /// Import the selected vaults from a bundle file. On success the vault list
  /// reloads and the sidebar selects the first imported vault. Returns the
  /// imported keys, or nil and a message on failure.
  func importBundle(
    source: URL, passphrase: String, selection: [BundleImportSelection]
  ) async -> (keys: [String]?, message: String?) {
    do {
      let keys = try await core.importVaultBundle(
        srcPath: source.path, passphrase: passphrase, selection: selection)
      reload()
      if let first = keys.first { selectSidebarDestination(.vault(first)) }
      return (keys, nil)
    } catch {
      return (nil, String(describing: error))
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
    vaultKey: String, itemKey: String, credKey: String, title: String, value: String,
    kind: FieldKindInfo? = nil
  ) async -> Bool {
    actionError = nil
    do {
      try await core.addOrUpdateCredential(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, title: title, value: value,
        kind: kind
      )
      await loadItems(for: vaultKey)
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  /// Change a credential's key. The FFI has no rename, so this writes the
  /// credential under `newKey` and deletes `oldKey`. If the delete fails the
  /// credential is left under both keys and the error is surfaced.
  @discardableResult
  func renameCredentialKey(
    vaultKey: String, itemKey: String, oldKey: String, newKey: String, title: String, value: String,
    kind: FieldKindInfo? = nil
  ) async -> Bool {
    actionError = nil
    do {
      try await core.addOrUpdateCredential(
        vaultKey: vaultKey, itemKey: itemKey, credKey: newKey, title: title, value: value,
        kind: kind
      )
      try await core.deleteCredential(vaultKey: vaultKey, itemKey: itemKey, credKey: oldKey)
      await loadItems(for: vaultKey)
      return true
    } catch {
      actionError = String(describing: error)
      await loadItems(for: vaultKey)
      return false
    }
  }

  /// Persist a new display order for an item's credentials. `orderedKeys` must
  /// list every credential key of the item, once each.
  @discardableResult
  func reorderCredentials(vaultKey: String, itemKey: String, orderedKeys: [String]) async -> Bool {
    actionError = nil
    do {
      try await core.reorderCredentials(
        vaultKey: vaultKey, itemKey: itemKey, orderedCredKeys: orderedKeys
      )
      await loadItems(for: vaultKey)
      return true
    } catch {
      actionError = String(describing: error)
      await loadItems(for: vaultKey)
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
