import AppKit
import AuthenticationServices
import AxoPassFFI
import CryptoKit
import Foundation
import LocalAuthentication
import Observation

enum SidebarDestination: Hashable {
  case today
  case activity
  case vault(String)
  case itemType(ItemType)
  case ssh
  case gpg
  case age
  case recentlyDeleted
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

/// Contents removed from an item by an undoable delete. Deleted credentials
/// keep their values in the vault, so only their ids are recorded.
struct DeletedEntries {
  struct Section {
    let id: String
    let title: String
  }

  struct Credential {
    let id: String
    let key: String
  }

  let vaultKey: String
  let itemKey: String
  /// Item arrangement before the delete.
  let before: [CredentialEntry]
  let sections: [Section]
  let credentials: [Credential]
}

/// Record of one undoable delete. Retained by the undo action and released
/// when the undo manager discards it.
@MainActor
final class DeletedEntriesBox {
  var entries: DeletedEntries?
}

/// Partial failure of a delete undo or redo. Shown on the affected item.
struct UndoFailure: Equatable {
  let vaultKey: String
  let itemKey: String
  let message: String
}

/// Vault action on an item missing from the item cache.
struct ItemNotLoadedError: Error, CustomStringConvertible {
  let itemKey: String
  var description: String { "Item \(itemKey) is not loaded." }
}

/// Error message for a failed action, or nil on success.
@MainActor
func failureMessage(_ action: () async throws -> Void) async -> String? {
  do {
    try await action()
    return nil
  } catch {
    return String(describing: error)
  }
}

extension UndoManager {
  /// Register an undo handler that runs on the main actor. The handler receives
  /// this undo manager so it can register its inverse. AppKit invokes undo
  /// handlers on the main thread.
  func registerMainActorUndo(
    named actionName: String, _ handler: @escaping @MainActor (UndoManager) -> Void
  ) {
    registerUndo(withTarget: self) { manager in
      MainActor.assumeIsolated { handler(manager) }
    }
    setActionName(actionName)
  }
}

@Observable
@MainActor
final class VaultsModel {
  /// Core of the vault panes. `SyncModel` calls it too, so the vault copies a
  /// sync call saves are the copies this model reads.
  let core = AxoPass()

  // Sidebar navigation
  private(set) var sidebarSelection: SidebarDestination? = nil

  /// Whether the selection is a page that uses the full width and has no title
  /// bar.
  var isPageSelected: Bool {
    switch sidebarSelection {
    case .today, .activity: return true
    default: return false
    }
  }

  // Where the sidebar is headed while that destination's items load. The panes
  // keep showing the current selection until the load lands, so switching to a
  // vault that has to be decrypted does not blank them first.
  private(set) var pendingSelection: SidebarDestination? = nil
  private var selectionTask: Task<Void, Never>? = nil

  // Vault list
  var vaults: [VaultInfo] = []
  /// Keys of the vaults left out of AutoFill suggestions on this Mac.
  private(set) var autofillExcludedVaults: Set<String> = []
  var loadError: String? = nil
  // Vault ids held by more than one file. None of these files is in `vaults`.
  var duplicateVaults: [DuplicateVaultInfo] = []
  // Vault keys claimed by more than one file. None of these files is in
  // `vaults`. A file can also be in `duplicateVaults`.
  var duplicateVaultKeys: [DuplicateVaultKeyInfo] = []

  // Number of vault files not shown for a duplicate id or key. A file in both
  // lists counts once.
  var hiddenVaultFileCount: Int {
    Set(duplicateVaults.flatMap(\.paths) + duplicateVaultKeys.flatMap(\.paths)).count
  }

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
  // Folders per vault in display order. Loaded with the items.
  private var folderCache: [String: [FolderInfo]] = [:]
  // Vaults whose last load failed, with the error. They are not cached, so the
  // next load of the vault retries them.
  private(set) var itemLoadFailures: [String: String] = [:]

  // Debounces the AutoFill re-index; see `scheduleAutofillRefresh`.
  private var autofillRefreshTask: Task<Void, Never>? = nil
  var selectedItemRef: ItemRef? = nil
  /// Rows selected together in the item list. Only used while two or more rows
  /// are selected and `selectedItemRef` is nil.
  var multiSelection: Set<ItemRef> = []

  // Surfaces failures from vault/item/credential mutations (create, rename,
  // delete) to whichever pane triggered them.
  var actionError: String? = nil

  // Last partially failed undo or redo of a delete.
  private(set) var undoFailure: UndoFailure? = nil

  init() {
    authContext = LAContext()
    biometry = Self.probeBiometry(authContext)
    autoLock = AutoLock { [weak self] trigger in self?.lock(automatic: trigger) }
    // Decrypted previews left by a run that quit or crashed.
    FilePreviews.removeAll()
  }

  // MARK: - Vault list

  /// Scan the vault files again and list them. Finds files added or moved
  /// outside this model, such as a vault of a pairing import or the move to
  /// `unreadable/` on new hardware. Drops the items of vaults no longer listed.
  func reload() {
    do {
      try core.rescanVaults()
      vaults = try core.listVaults().sorted {
        ($0.name ?? $0.key).localizedCaseInsensitiveCompare($1.name ?? $1.key) == .orderedAscending
      }
      duplicateVaults = try core.listDuplicateVaults()
      duplicateVaultKeys = try core.listDuplicateVaultKeys()
      autofillExcludedVaults = Set(core.listAutofillExcludedVaults())
      loadError = nil
      let keys = Set(vaults.map(\.key))
      itemCache = itemCache.filter { keys.contains($0.key) }
      folderCache = folderCache.filter { keys.contains($0.key) }
      itemLoadFailures = itemLoadFailures.filter { keys.contains($0.key) }
      if case .vault(let key) = sidebarSelection, key != allSecretsKey, !keys.contains(key) {
        selectSidebarDestination(vaults.first.map { .vault($0.key) })
      } else if sidebarSelection == nil {
        selectSidebarDestination(.today)
      }
    } catch {
      vaults = []
      duplicateVaults = []
      duplicateVaultKeys = []
      loadError = String(describing: error)
    }
  }

  // MARK: - App broker

  /// Serve the CLI's requests while the app is running: SSH signatures from
  /// the agent, GPG passphrases from `ap pinentry`. Both use their own keychain
  /// items, so this does not wait on the vault being unlocked. With the app
  /// unavailable the agent refuses to sign.
  func startBroker() async {
    guard signingBridge == nil else { return }
    let signing = SigningPromptBridge(model: signingPrompt)
    let passphrase = PassphrasePromptBridge(model: passphrasePrompt)
    let vaultUnlock = VaultUnlockPromptBridge(model: vaultUnlockPrompt) { [weak self] keys in
      await self?.brokerVaultsChanged(keys)
    }
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
    guard !isBrokerPromptVisible else { return }
    unlock()
  }

  /// Whether a broker prompt is on screen. Such a panel holds the auth lock and
  /// carries its own biometric, so no other unlock prompt should start.
  var isBrokerPromptVisible: Bool {
    signingPrompt.panel.isVisible || passphrasePrompt.panel.isVisible
      || vaultUnlockPrompt.panel.isVisible
  }

  /// Handle the app regaining focus. Raises the first automatic prompt through
  /// `unlockIfActive`, then re-raises the Touch ID prompt if the user already
  /// started an unlock and switching away cancelled the evaluation.
  func handleBecameActive() {
    unlockIfActive()

    guard unlockEngaged, !isAppUnlocked, !isUnlocking, NSApp.isActive else { return }
    biometry = Self.probeBiometry(authContext)
    guard biometry == .touchID else { return }
    guard !isBrokerPromptVisible else { return }
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
    // Clearing this tells an attempt still waiting on the auth lock that its
    // context is dead, so it does not evaluate it.
    evaluatingContext = nil
    // An invalidated context cannot be evaluated again, so replace it.
    if context === authContext { resetAuthContext() }
  }

  /// Unlock with the embedded biometric prompt. Without Touch ID the icon has
  /// no state to show, so this falls back to the system dialog and its password
  /// field.
  func unlock() {
    guard !isUnlocking else { return }
    unlockEngaged = true
    // Touch ID availability changes with the lid, displays, and lockout, so the
    // probe from init may be out of date.
    biometry = Self.probeBiometry(authContext)
    // The model owns the task. The lock screen's `.task` would cancel the
    // attempt as soon as a successful unlock swapped the view out.
    unlockTask = Task { [self] in
      guard !Task.isCancelled else { return }
      await authenticate(with: biometry == .touchID ? authContext : LAContext())
    }
  }

  /// Unlock and wait for the attempt to finish. Returns whether the app is
  /// unlocked. The welcome window uses this, since it has no lock screen.
  func unlockAndWait() async -> Bool {
    if isAppUnlocked { return true }
    guard !isBrokerPromptVisible else { return false }
    unlock()
    await unlockTask?.value
    return isAppUnlocked
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

  /// Unlock on `context`, which the caller has bound to an
  /// `LAAuthenticationView` it shows. The palette uses this so its prompt does
  /// not share a context with the lock screen's icon.
  ///
  /// Takes over from a prompt already in flight, such as the lock screen's:
  /// that prompt is dismissed, and this one starts once its attempt has
  /// finished and released the auth lock. Returns the attempt, or nil when a
  /// broker prompt is up and none was started.
  @discardableResult
  func unlock(on context: LAContext) -> Task<Void, Never>? {
    guard !isBrokerPromptVisible else { return nil }
    unlockEngaged = true
    let pending = unlockTask
    pending?.cancel()
    cancelEvaluation()
    let task = Task { [self] in
      await pending?.value
      // The attempt taken over may have succeeded before it could be
      // dismissed.
      guard !Task.isCancelled, !isAppUnlocked else { return }
      await authenticate(with: context)
    }
    unlockTask = task
    return task
  }

  /// Dismiss the lock screen's prompt. The lock screen returns to its idle
  /// state and does not prompt again until the user unlocks deliberately.
  func cancelUnlock() {
    guard isUnlocking else { return }
    unlockEngaged = false
    unlockTask?.cancel()
    cancelEvaluation()
  }

  /// Fail the evaluation running on `context`, if it is still in flight.
  func cancelUnlock(on context: LAContext) {
    guard evaluatingContext === context else { return }
    unlockTask?.cancel()
    cancelEvaluation()
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

    // The attempt may have been cancelled while waiting for the lock, which
    // invalidates the context.
    guard evaluatingContext === context else {
      try? core.endEmbeddedAuth()
      return
    }

    do {
      try await context.evaluatePolicy(
        .deviceOwnerAuthentication, localizedReason: "unlock Axo Pass")
      // The evaluation is over, so there is no prompt left to cancel, and the
      // context must not be invalidated while the core adopts it.
      evaluatingContext = nil
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
      // Re-index AutoFill on the same authentication, so the system's list of
      // sites tracks whatever the vaults hold now. Covers the case where the
      // selection is a tool pane and no vault load happens.
      scheduleAutofillRefresh()
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
        "This Mac does not have enrolled fingerprints. Use your login password, or add one in System Settings › Touch ID & Password."
    case .biometryLockout:
      return "Touch ID is locked after too many failed attempts. Use your login password instead."
    case .passcodeNotSet:
      return "Set a login password in System Settings to use Axo Pass."
    default: return String(describing: error)
    }
  }

  /// `automatic` marks a lock the user did not ask for: idle timeout, sleep, or
  /// screen lock. Recorded for the audit log. An automatic lock raises Touch ID
  /// on return. A manual lock shows the idle lock screen.
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
    // A lock drops every authorization the user has given: signing, the GPG
    // passphrases pinentry unlocked, and vault access for browser requests.
    signingPrompt.forgetAll()
    passphrasePrompt.forgetAll()
    vaultUnlockPrompt.forgetAll()
    undoFailure = nil
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
    folderCache = [:]
    itemLoadFailures = [:]
    fileFailures = [:]
    // Previews are decrypted copies on disk. A lock removes them.
    FilePreviews.removeAll()
    selectedItemRef = nil
    unlockError = nil
    // A manual lock waits for a deliberate Unlock.
    autoPromptPending = trigger != nil
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
    let prevItemList = itemListSelection
    sidebarSelection = dest
    guard itemListSelection != prevItemList else { return }
    selectedItemRef = displayItems.first?.id
    // A vault added or imported since the last load still needs its items.
    if isAppUnlocked { Task { await loadItemsForSelection() } }
  }

  // MARK: - Items

  /// Which vault keys a destination covers: every vault for "All Secrets" and
  /// the item types, the one vault for a vault, and none for the tool sections.
  private func vaultKeys(for dest: SidebarDestination?) -> [String] {
    switch dest {
    case .vault(let key): return key == allSecretsKey ? vaults.map { $0.key } : [key]
    case .itemType: return vaults.map { $0.key }
    default: return []
    }
  }

  /// Username of item `itemId` in vault `vaultKey`. Nil if the vault is not
  /// loaded, the item is gone, or it has no username.
  func cachedUsername(vaultKey: String, itemId: String) -> String? {
    let username = itemCache[vaultKey]?.first { $0.id == itemId }?.username
    return username?.isEmpty == false ? username : nil
  }

  /// Title of item `itemId` in vault `vaultKey`. Nil if the vault is not
  /// loaded or the item is gone.
  func cachedTitle(vaultKey: String, itemId: String) -> String? {
    let title = itemCache[vaultKey]?.first { $0.id == itemId }?.title
    return title?.isEmpty == false ? title : nil
  }

  /// Name of the listed vault with the short vault id `id`. Nil if the vault
  /// has no name.
  func vaultName(id: String) -> String? {
    let name = vaults.first { $0.id == id }?.name
    return name?.isEmpty == false ? name : nil
  }

  /// Number of items of `type` in all vaults. Nil until every vault is loaded.
  func itemCount(of type: ItemType) -> Int? {
    var count = 0
    for vault in vaults {
      guard let items = itemCache[vault.key] else { return nil }
      count += items.filter(type.contains).count
    }
    return count
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

  /// Re-index AutoFill shortly after the vaults change. Every mutation reloads
  /// its vault's items, so hanging the refresh off `loadItems` keeps the index
  /// current without threading a call through each of them. The delay coalesces
  /// a burst of edits into one pass over every vault.
  private func scheduleAutofillRefresh() {
    autofillRefreshTask?.cancel()
    autofillRefreshTask = Task { [core] in
      try? await Task.sleep(for: .seconds(2))
      guard !Task.isCancelled else { return }
      await AutofillIdentities.refresh(from: core)
    }
  }

  /// A broker request wrote to a vault behind the app's back: a passkey
  /// registration or assertion from the AutoFill extension, or `ap item set`.
  /// The core has already relocked its copy of each vault, so drop the matching
  /// cache entries to force a reload, then re-index AutoFill. An empty `keys`
  /// means the written vault could not be named, so clear the whole cache.
  func brokerVaultsChanged(_ keys: [String]) async {
    if keys.isEmpty {
      itemCache.removeAll()
    } else {
      for key in keys { itemCache.removeValue(forKey: key) }
    }
    guard isAppUnlocked else { return }
    await loadItemsForSelection()
    scheduleAutofillRefresh()
  }

  private func loadItems(for vaultKey: String) async {
    defer { scheduleAutofillRefresh() }
    do {
      let items = try await core.listItems(vaultKey: vaultKey)
      let folders = try await core.listFolders(vaultKey: vaultKey)
      itemCache[vaultKey] = items
      folderCache[vaultKey] = folders
      itemLoadFailures.removeValue(forKey: vaultKey)
    } catch let e as FfiError {
      switch e {
      case .AuthExpired, .AuthCancelled:
        lock()
      default:
        recordLoadFailure(vaultKey, String(describing: e))
      }
    } catch {
      recordLoadFailure(vaultKey, String(describing: error))
    }
  }

  /// Record a failed load so the pane stops spinning and shows it. The vault
  /// stays out of the cache, so the next load retries it.
  private func recordLoadFailure(_ vaultKey: String, _ message: String) {
    itemLoadFailures[vaultKey] = message
    actionError = message
  }

  /// Load the items of every vault not yet cached, retrying any whose last load
  /// failed. The palette searches all of them. Returns a message naming the
  /// vaults that still failed, or nil when every vault loaded.
  @discardableResult
  func loadAllItems() async -> String? {
    guard isAppUnlocked else { return nil }
    for vault in vaults where itemCache[vault.key] == nil {
      await loadItems(for: vault.key)
      if !isAppUnlocked { return nil }
    }
    let failed = vaults.filter { itemLoadFailures[$0.key] != nil }
    guard let first = failed.first, let error = itemLoadFailures[first.key] else { return nil }
    let names = failed.map { $0.name ?? $0.key }.joined(separator: ", ")
    return failed.count == 1
      ? "Could not load \(names): \(error)"
      : "Could not load \(names). \(first.name ?? first.key): \(error)"
  }

  /// Vault folders in display order. Empty until the vault items load.
  func folders(for vaultKey: String) -> [FolderInfo] {
    folderCache[vaultKey] ?? []
  }

  /// Every cached item across all vaults, in vault order.
  var allItems: [DisplayItem] {
    vaults.flatMap { vault in
      (itemCache[vault.key] ?? []).map { DisplayItem(vaultKey: vault.key, item: $0) }
    }
  }

  /// Select `ref` in the main window: its vault in the sidebar, then the item.
  /// Only an item whose vault is cached is selected, since a vault that has to
  /// load first settles on its first row instead.
  func showItem(_ ref: ItemRef) {
    selectSidebarDestination(.vault(ref.vaultKey))
    if itemCache[ref.vaultKey] != nil { selectedItemRef = ref }
  }

  /// Select the item with short id `itemId` in vault `vaultKey`. Loads the
  /// vault first if it is not cached. Selects only the vault if the item is
  /// not found.
  func showItem(vaultKey: String, itemId: String) async {
    if itemCache[vaultKey] == nil { await loadItems(for: vaultKey) }
    guard let item = itemCache[vaultKey]?.first(where: { $0.id == itemId }) else {
      selectSidebarDestination(.vault(vaultKey))
      return
    }
    showItem(ItemRef(vaultKey: vaultKey, itemKey: item.key))
  }

  // MARK: - Credentials

  /// Fetch a credential and put it on the pasteboard without keeping it.
  /// Returns an error message on failure, nil on success.
  func copyCredential(vaultKey: String, itemKey: String, credKey: String) async -> String? {
    do {
      let secret = try await credentialSecret(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey)
      return secureCopy(secret) ? nil : "Value is not text."
    } catch {
      return String(describing: error)
    }
  }

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

  /// Create the default vault, named "Personal" with key `personal`. The
  /// welcome window offers it as "Start fresh".
  @discardableResult
  func addPersonalVault() async -> Bool {
    await addVault(name: "Personal", key: "personal")
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

  /// Leave a vault out of AutoFill suggestions on this Mac, or include it again.
  /// Its logins stay available for manual selection. The system index is
  /// rebuilt shortly after.
  @discardableResult
  func setAutofillExcluded(vaultKey: String, excluded: Bool) -> Bool {
    actionError = nil
    do {
      try core.setVaultAutofillExcluded(vaultKey: vaultKey, excluded: excluded)
      autofillExcludedVaults = Set(core.listAutofillExcludedVaults())
      if isAppUnlocked { scheduleAutofillRefresh() }
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  /// Move a vault file to the Trash. A synced vault is deleted on this Mac only.
  /// Its sync is turned off first, which needs the app unlocked.
  @discardableResult
  func deleteVault(_ vaultKey: String) async -> Bool {
    actionError = nil
    do {
      try await core.deleteVault(vaultKey: vaultKey)
      itemCache.removeValue(forKey: vaultKey)
      folderCache.removeValue(forKey: vaultKey)
      itemLoadFailures.removeValue(forKey: vaultKey)
      if selectedVaultKey == vaultKey { selectSidebarDestination(nil) }
      reload()
      return true
    } catch FfiError.AuthExpired, FfiError.AuthCancelled {
      lock()
      return false
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  // MARK: - Sync

  /// Key of the listed vault with the short vault id `id`.
  func vaultKey(id: String) -> String? {
    vaults.first { $0.id == id }?.key
  }

  /// Reload vault `vaultKey` after a sync call or a sync transaction saved it.
  func syncedVaultChanged(_ vaultKey: String) async {
    folderCache.removeValue(forKey: vaultKey)
    await brokerVaultsChanged([vaultKey])
  }

  /// Titles of the items `ids` of vault `vaultKey`, live items first, then
  /// deleted items. An id of no item is left out.
  func itemTitles(ids: [String], vaultKey: String) async -> [String] {
    guard !ids.isEmpty else { return [] }
    let live = Dictionary(
      cachedItems(in: vaultKey).map { ($0.id, $0.title) }, uniquingKeysWith: { a, _ in a })
    let missing = ids.filter { live[$0] == nil }
    var deleted: [String: String] = [:]
    if !missing.isEmpty, let items = try? await deletedItems(vaultKey: vaultKey) {
      deleted = Dictionary(items.map { ($0.id, $0.title) }, uniquingKeysWith: { a, _ in a })
    }
    return ids.compactMap { live[$0] ?? deleted[$0] }
  }

  // MARK: - Previous versions

  /// Copies of a vault from before each save, newest first.
  func vaultVersions(_ vaultKey: String) async throws -> [RetainedVersionInfo] {
    try await core.listVaultVersions(vaultKey: vaultKey)
  }

  /// Load failure of vault `vaultKey`, or nil if it loads. Loads its items
  /// first if they are not cached.
  func loadFailure(_ vaultKey: String) async -> String? {
    if itemCache[vaultKey] == nil { await loadItems(for: vaultKey) }
    return itemLoadFailures[vaultKey]
  }

  /// Replace a vault with a previous version. The replaced vault becomes a
  /// previous version in turn. A vault file that fails to load is replaced
  /// with `refused` set, and is kept aside as an invalid file. A synced vault
  /// records the differences as edits. Needs the app unlocked. An expired
  /// authentication locks the app.
  func restoreVaultVersion(vaultKey: String, name: String, refused: Bool) async throws {
    do {
      if refused {
        try await core.restoreRefusedVaultVersion(vaultKey: vaultKey, name: name)
      } else {
        try await core.restoreVaultVersion(vaultKey: vaultKey, name: name)
      }
    } catch FfiError.AuthExpired {
      lock()
      throw FfiError.AuthExpired
    }
    folderCache.removeValue(forKey: vaultKey)
    itemLoadFailures.removeValue(forKey: vaultKey)
    reload()
    await brokerVaultsChanged([vaultKey])
  }

  /// Delete every previous version of a vault. Returns the number deleted.
  func eraseVaultVersions(_ vaultKey: String) async throws -> UInt32 {
    try await core.eraseVaultVersions(vaultKey: vaultKey)
  }

  // MARK: - Bundle export / import

  /// Export the given vaults to a passphrase-encrypted bundle file. Returns the
  /// export report on success, or nil and a message on failure. The report
  /// lists file blobs the bundle lacks. `onStage` is called on the main actor
  /// as the export progresses.
  func exportBundle(
    vaultKeys: [String],
    destination: URL,
    passphrase: String,
    workFactor: ExportWorkFactor,
    includePasskeys: Bool,
    onStage: @escaping @MainActor (VaultExportStage, UInt32, UInt32) -> Void
  ) async -> (report: VaultExportReport?, message: String?) {
    let delegate = ExportProgressForwarder(onStage)
    do {
      let report = try await core.exportVaultBundle(
        vaultKeys: vaultKeys, destPath: destination.path, passphrase: passphrase,
        workFactor: workFactor, includePasskeys: includePasskeys, progress: delegate)
      return (report, nil)
    } catch {
      return (nil, String(describing: error))
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

  /// Read a password manager export and report what an import would add.
  /// Writes nothing.
  func previewItemImport(
    source: URL, includeTrashed: Bool
  ) async -> (preview: ItemImportPreview?, message: String?) {
    do {
      let preview = try await core.previewItemImport(
        path: source.path, includeTrashed: includeTrashed)
      return (preview, nil)
    } catch {
      return (nil, String(describing: error))
    }
  }

  /// Import a password manager export into a new vault named `name`, then
  /// select the vault.
  func importItems(
    source: URL, name: String, includeTrashed: Bool
  ) async -> (result: ItemImportResult?, message: String?) {
    do {
      let result = try await core.importItemsIntoNewVault(
        path: source.path, name: name, includeTrashed: includeTrashed)
      reload()
      selectSidebarDestination(.vault(result.vaultKey))
      return (result, nil)
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

  /// Change the title and key of an item. Unchanged values are skipped. Throws
  /// if another item has the new key. The item stays selected under its new key.
  func renameItem(vaultKey: String, itemKey: String, title: String, newKey: String) async throws {
    let wasSelected = selectedItemRef == ItemRef(vaultKey: vaultKey, itemKey: itemKey)
    var currentKey = itemKey
    do {
      if let item = item(vaultKey: vaultKey, itemKey: itemKey), item.title != title {
        try await core.addOrUpdateItem(vaultKey: vaultKey, itemKey: itemKey, itemTitle: title)
      }
      if newKey != itemKey {
        try await core.changeItemKey(vaultKey: vaultKey, itemKey: itemKey, newKey: newKey)
        currentKey = newKey
      }
    } catch {
      await loadItems(for: vaultKey)
      throw error
    }
    await loadItems(for: vaultKey)
    if wasSelected { selectedItemRef = ItemRef(vaultKey: vaultKey, itemKey: currentKey) }
  }

  /// Move an item to another vault with its credentials and previous values.
  /// The item is purged from the source vault. It keeps its key unless
  /// `destItemKey` is given. Throws if the destination has the key.
  func moveItemToVault(
    vaultKey: String, itemKey: String, destVaultKey: String, destItemKey: String?
  ) async throws {
    let result: Result<Void, Error>
    do {
      try await core.moveItemToVault(
        vaultKey: vaultKey, itemKey: itemKey, destVaultKey: destVaultKey, destItemKey: destItemKey)
      result = .success(())
    } catch {
      result = .failure(error)
    }
    await loadItems(for: vaultKey)
    await loadItems(for: destVaultKey)
    try result.get()
  }

  /// Delete an item. It stays in the vault's deleted items until purged. If
  /// `undoManager` is given, an undo is registered that restores the item.
  @discardableResult
  func deleteItem(
    vaultKey: String, itemKey: String, undoManager: UndoManager? = nil
  ) async -> Bool {
    guard let itemId = item(vaultKey: vaultKey, itemKey: itemKey)?.id else {
      actionError = ItemNotLoadedError(itemKey: itemKey).description
      return false
    }
    guard await performItemDelete(vaultKey: vaultKey, itemKey: itemKey) else { return false }
    if let undoManager {
      registerItemUndo(
        after: nil, vaultKey: vaultKey, itemId: itemId, preferredKey: itemKey,
        undoManager: undoManager)
    }
    return true
  }

  /// Register an undo that restores the item after `pending` finishes. `pending`
  /// is the delete the undo reverses. Redo deletes the item again under the key
  /// it was restored with. Each inverse is registered during the undo or redo,
  /// since registering later would clear the redo stack.
  private func registerItemUndo(
    after pending: Task<Void, Never>?, vaultKey: String, itemId: String, preferredKey: String,
    undoManager: UndoManager
  ) {
    undoManager.registerMainActorUndo(named: "Delete") { [weak self] manager in
      guard let self else { return }
      let restored = Task { () -> String? in
        await pending?.value
        return await self.performItemRestore(
          vaultKey: vaultKey, itemId: itemId, preferredKey: preferredKey)
      }
      manager.registerMainActorUndo(named: "Delete") { [weak self] manager in
        guard let self else { return }
        let redo = Task {
          guard let key = await restored.value else { return }
          await self.performItemDelete(vaultKey: vaultKey, itemKey: key)
        }
        self.registerItemUndo(
          after: redo, vaultKey: vaultKey, itemId: itemId, preferredKey: preferredKey,
          undoManager: manager)
      }
    }
  }

  /// Restore a deleted item for an undo. Returns the key it was restored under,
  /// or nil if it could not be restored. Does nothing while locked. An item
  /// that was already restored or purged from Recently Deleted is skipped
  /// without an error.
  private func performItemRestore(
    vaultKey: String, itemId: String, preferredKey: String
  ) async -> String? {
    guard isAppUnlocked else { return nil }
    actionError = nil
    do {
      return try await restoreDeletedItem(
        vaultKey: vaultKey, itemId: itemId, preferredKey: preferredKey)
    } catch FfiError.NotFound {
      return nil
    } catch {
      actionError = String(describing: error)
      return nil
    }
  }

  /// Deleted items of a vault, most recently deleted first.
  func deletedItems(vaultKey: String) async throws -> [DeletedItemInfo] {
    try await core.listDeletedItems(vaultKey: vaultKey)
  }

  /// Restore a deleted item. If `preferredKey` has been reused, the item is
  /// restored under a new key. Returns the key it was restored under. Items
  /// are reloaded first so the new key is chosen from current keys.
  @discardableResult
  func restoreDeletedItem(vaultKey: String, itemId: String, preferredKey: String) async throws
    -> String
  {
    await loadItems(for: vaultKey)
    let taken = Set(itemCache[vaultKey]?.map(\.key) ?? [])
    let key = Self.unusedKey(preferredKey, taken: taken)
    try await mutate(vaultKey) {
      try await core.restoreItem(
        vaultKey: vaultKey, itemId: itemId, newKey: key == preferredKey ? nil : key)
    }
    return key
  }

  /// Delete a deleted item permanently.
  func purgeDeletedItem(vaultKey: String, itemId: String) async throws {
    try await core.purgeItem(vaultKey: vaultKey, itemId: itemId)
  }

  @discardableResult
  private func performItemDelete(vaultKey: String, itemKey: String) async -> Bool {
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

  /// Create a credential. Fails if the key is already taken in the item.
  @discardableResult
  func addCredential(
    vaultKey: String, itemKey: String, credKey: String, title: String, value: String,
    kind: FieldKindInfo? = nil
  ) async -> Bool {
    actionError = nil
    do {
      try await core.addCredential(
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

  /// Change the key, title, or kind of a credential without resubmitting its
  /// value. Nil arguments are left unchanged.
  func updateCredential(
    vaultKey: String, itemKey: String, credKey: String, newKey: String? = nil,
    title: String? = nil, kind: FieldKindInfo? = nil
  ) async throws {
    try await mutate(vaultKey) {
      try await core.updateCredential(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, newKey: newKey, title: title,
        kind: kind)
    }
  }

  /// Cached item, or nil if its vault is not loaded.
  func item(vaultKey: String, itemKey: String) -> ItemInfo? {
    itemCache[vaultKey]?.first { $0.key == itemKey }
  }

  /// Save the section order and credential placements described by `entries`.
  /// Sections save first. Each save is skipped if unchanged.
  func arrangeItem(vaultKey: String, itemKey: String, entries: [CredentialEntry]) async throws {
    let target = CredentialEntry.arrangement(of: entries)
    guard let before = item(vaultKey: vaultKey, itemKey: itemKey) else {
      throw ItemNotLoadedError(itemKey: itemKey)
    }
    if target.sectionIds != before.sections.map(\.id) {
      try await reorderSections(vaultKey: vaultKey, itemKey: itemKey, sectionIds: target.sectionIds)
    }
    // Compare after saving sections, since the model lists credentials in
    // section order.
    guard let current = item(vaultKey: vaultKey, itemKey: itemKey) else {
      throw ItemNotLoadedError(itemKey: itemKey)
    }
    let currentPlacements = CredentialEntry.arrangement(of: CredentialEntry.entries(of: current))
      .placements
    if target.placements != currentPlacements {
      try await arrangeCredentials(
        vaultKey: vaultKey, itemKey: itemKey, placements: target.placements)
    }
  }

  /// Persist display order and section assignments for item credentials.
  /// `placements` must list every credential key in the item exactly once.
  func arrangeCredentials(
    vaultKey: String, itemKey: String, placements: [CredentialPlacementInfo]
  ) async throws {
    try await mutate(vaultKey) {
      try await core.arrangeCredentials(
        vaultKey: vaultKey, itemKey: itemKey, placements: placements)
    }
  }

  // MARK: - SSH keys

  /// Generate an Ed25519 key. A nil `itemKey` stores it in a new item titled
  /// `itemTitle`. The core writes the public key file and the listing the
  /// broker reads. Throws the core error.
  func generateSshKey(
    vaultKey: String, itemKey: String?, itemTitle: String, comment: String
  ) async throws -> VaultSshKeyInfo {
    try await mutateSshKey(vaultKey) {
      try await core.generateVaultSshKey(
        vaultKey: vaultKey, itemKey: itemKey, itemTitle: itemTitle, comment: comment)
    }
  }

  /// Import the private key file at `url`. Throws `SshKeyPassphraseRequired` or
  /// `SshKeyWrongPassphrase` for an encrypted key, and `SshKeyDuplicate` for a
  /// key the vault already holds.
  func importSshKey(
    vaultKey: String, itemKey: String?, itemTitle: String, url: URL, passphrase: String?,
    comment: String?
  ) async throws -> VaultSshKeyInfo {
    try await mutateSshKey(vaultKey) {
      try await core.importVaultSshKey(
        vaultKey: vaultKey, itemKey: itemKey, itemTitle: itemTitle, path: url.path,
        passphrase: passphrase, comment: comment)
    }
  }

  /// Public key line of a vault key, for copying.
  func sshKeyPublicKey(location: SshVaultKeyLocation) async throws -> String {
    try await core.vaultSshKeyPublicKey(
      vaultKey: location.vaultKey, itemKey: location.itemKey, credKey: location.credentialKey)
  }

  /// Change the comment of a vault key. Returns the new public key line.
  @discardableResult
  func setSshKeyComment(location: SshVaultKeyLocation, comment: String) async throws -> String {
    try await mutateSshKey(location.vaultKey) {
      try await core.setVaultSshKeyComment(
        vaultKey: location.vaultKey, itemKey: location.itemKey, credKey: location.credentialKey,
        comment: comment)
    }
  }

  /// Set whether the agent advertises (`autoLoad`) and signs with (`sshUse`) a
  /// vault key. Turning off `sshUse` also turns off `autoLoad`.
  func setSshKeyAccess(
    location: SshVaultKeyLocation, autoLoad: Bool, sshUse: Bool
  ) async throws {
    try await mutateSshKey(location.vaultKey) {
      try await core.setVaultSshKeyAccess(
        vaultKey: location.vaultKey, itemKey: location.itemKey, credKey: location.credentialKey,
        autoLoad: autoLoad, sshUse: sshUse)
    }
  }

  /// Write the public key file of a vault key again. Returns its path.
  func writeSshKeyPubkey(location: SshVaultKeyLocation) async throws -> String {
    try await core.writeVaultSshKeyPubkey(
      vaultKey: location.vaultKey, itemKey: location.itemKey, credKey: location.credentialKey)
  }

  /// Write the private key of a vault key to `url` with mode `0600`. A
  /// non-empty `passphrase` encrypts the file.
  func exportSshKey(location: SshVaultKeyLocation, to url: URL, passphrase: String?) async throws {
    do {
      try await core.exportVaultSshKey(
        vaultKey: location.vaultKey, itemKey: location.itemKey, credKey: location.credentialKey,
        destPath: url.path, passphrase: passphrase)
    } catch FfiError.AuthExpired, FfiError.AuthCancelled {
      lock()
      throw FfiError.AuthExpired
    }
  }

  /// Add `passphrase` to the item of a vault key as a concealed credential
  /// titled "SSH key passphrase". The credential key is the key credential key
  /// with `-passphrase`, and a numeric suffix if the item has it. Returns an
  /// error message on failure, nil on success.
  func saveSshKeyPassphrase(location: SshVaultKeyLocation, passphrase: String) async -> String? {
    if itemCache[location.vaultKey] == nil { await loadItems(for: location.vaultKey) }
    let taken = Set(
      item(vaultKey: location.vaultKey, itemKey: location.itemKey)?.credentials.map(\.key) ?? [])
    let base = "\(location.credentialKey)-passphrase"
    var credKey = base
    var n = 2
    while taken.contains(credKey) {
      credKey = "\(base)-\(n)"
      n += 1
    }
    let saved = await addCredential(
      vaultKey: location.vaultKey, itemKey: location.itemKey, credKey: credKey,
      title: "SSH key passphrase", value: passphrase,
      kind: FieldKindInfo(kind: "text", concealed: true, multiline: false))
    return saved ? nil : (actionError ?? "The passphrase could not be saved.")
  }

  /// Select the item that holds a vault key. Loads the vault first if it is
  /// not cached.
  func showSshKeyItem(_ location: SshVaultKeyLocation) async {
    if itemCache[location.vaultKey] == nil { await loadItems(for: location.vaultKey) }
    showItem(ItemRef(vaultKey: location.vaultKey, itemKey: location.itemKey))
  }

  /// Vault name and item title of a vault key, for display. The item title is
  /// the item key until the vault's items are loaded.
  func sshKeyPlace(_ location: SshVaultKeyLocation) -> (vault: String, item: String) {
    let vault = vaults.first { $0.key == location.vaultKey }
    let item = item(vaultKey: location.vaultKey, itemKey: location.itemKey)
    return (vault?.name ?? location.vaultKey, item?.title ?? location.itemKey)
  }

  /// Load the items of the vaults that hold SSH keys, so `sshKeyPlace` can name
  /// the items.
  func loadItemsForSshKeys(_ keys: [SshKeyEntry]) async {
    let vaultKeys = Set(keys.compactMap { $0.vaultKey?.vaultKey })
    for vaultKey in vaultKeys where itemCache[vaultKey] == nil {
      await loadItems(for: vaultKey)
    }
  }

  /// A key change reloads the vault items. An expired authentication locks the
  /// app and still throws.
  private func mutateSshKey<T>(_ vaultKey: String, _ action: () async throws -> T) async throws
    -> T
  {
    do {
      return try await mutate(vaultKey, action)
    } catch FfiError.AuthExpired, FfiError.AuthCancelled {
      lock()
      throw FfiError.AuthExpired
    }
  }

  // MARK: - Files

  /// Why the contents of file credentials could not be read, by
  /// `vault/item/credential`. Set by a failed preview or save, and cleared by
  /// a successful read or a replace.
  private(set) var fileFailures: [String: FileFailure] = [:]

  func fileFailure(vaultKey: String, itemKey: String, credKey: String) -> FileFailure? {
    fileFailures[Self.fileKey(vaultKey, itemKey, credKey)]
  }

  private static func fileKey(_ vaultKey: String, _ itemKey: String, _ credKey: String) -> String {
    "\(vaultKey)/\(itemKey)/\(credKey)"
  }

  /// Add the file at `url` to an item as a new file credential titled with the
  /// file name. Returns an error message on failure, nil on success.
  func addFile(vaultKey: String, itemKey: String, url: URL) async -> String? {
    let taken = Set(item(vaultKey: vaultKey, itemKey: itemKey)?.credentials.map(\.key) ?? [])
    let source = FileSource(url: url)
    return await performFileChange(vaultKey) {
      try await core.addFile(
        vaultKey: vaultKey, itemKey: itemKey,
        credKey: fileCredentialKey(for: source.name, taken: taken), title: source.name,
        source: source)
    }
  }

  /// Replace the file of a file credential with the file at `url`. The replaced
  /// file goes to the credential's previous values. Returns an error message on
  /// failure, nil on success.
  func replaceFile(vaultKey: String, itemKey: String, credKey: String, url: URL) async -> String? {
    let error = await performFileChange(vaultKey) {
      try await core.replaceFile(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, source: FileSource(url: url))
    }
    if error == nil {
      fileFailures.removeValue(forKey: Self.fileKey(vaultKey, itemKey, credKey))
    }
    return error
  }

  /// Run a file change and reload the vault items. An expired authentication
  /// locks the app.
  private func performFileChange(_ vaultKey: String, _ change: () async throws -> Void) async
    -> String?
  {
    do {
      try await mutate(vaultKey, change)
      return nil
    } catch FfiError.AuthExpired, FfiError.AuthCancelled {
      lock()
      return "Authentication expired."
    } catch {
      return String(describing: error)
    }
  }

  /// Decrypt a file credential to `destination`, replacing a file there. The
  /// contents are verified before they appear. A failure that names the state
  /// of the contents is recorded in `fileFailures`. Returns nil on success, or
  /// the failure.
  func saveFile(vaultKey: String, itemKey: String, credKey: String, to destination: URL) async
    -> FileFailure?
  {
    let key = Self.fileKey(vaultKey, itemKey, credKey)
    do {
      _ = try await core.readFileToPath(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, destPath: destination.path)
      fileFailures.removeValue(forKey: key)
      return nil
    } catch {
      let failure = FileFailure(error)
      if case .authentication = failure {
        lock()
      } else {
        fileFailures[key] = failure
      }
      return failure
    }
  }

  /// Decrypt a file credential to a private temporary file for Quick Look.
  /// Returns the URL, or nil with the failure recorded. Remove the file with
  /// `FilePreviews.remove` when the preview closes.
  func previewFile(vaultKey: String, itemKey: String, credKey: String, name: String) async
    -> URL?
  {
    do {
      let url = try FilePreviews.makeFileURL(name: name)
      if let failure = await saveFile(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, to: url)
      {
        FilePreviews.remove(url)
        if case .other(let message) = failure { actionError = message }
        return nil
      }
      return url
    } catch {
      actionError = String(describing: error)
      return nil
    }
  }

  // MARK: - Undoable delete

  /// Delete item sections and credentials, and register an undo. The undo
  /// restores credentials from the vault's deleted credentials, recreates
  /// sections, and restores positions. It is only registered if something was
  /// deleted. The returned task yields an error message, or nil on success.
  @discardableResult
  func deleteEntries(
    vaultKey: String, itemKey: String, _ targets: Set<CredentialEntry>,
    undoManager: UndoManager?
  ) -> Task<String?, Never> {
    let box = DeletedEntriesBox()
    return Task {
      let error = await performDelete(
        into: box, vaultKey: vaultKey, itemKey: itemKey, targets: targets)
      if box.entries != nil, let undoManager {
        registerUndo(
          of: box, after: nil, vaultKey: vaultKey, itemKey: itemKey, undoManager: undoManager)
      }
      return error
    }
  }

  /// Register an undo that restores the contents of `box` after `pending`
  /// finishes. `pending` is the delete that fills `box`. Redo deletes the
  /// restored entries again and registers a new undo. Each inverse is
  /// registered during the undo or redo, since registering later would clear
  /// the redo stack. An undo while locked restores nothing and is registered
  /// again after it finishes. Re-registering clears the redo stack.
  private func registerUndo(
    of box: DeletedEntriesBox, after pending: Task<Void, Never>?, vaultKey: String,
    itemKey: String, undoManager: UndoManager
  ) {
    undoManager.registerMainActorUndo(named: "Delete") { [weak self] manager in
      guard let self else { return }
      guard self.isAppUnlocked else {
        Task { @MainActor in
          self.registerUndo(
            of: box, after: pending, vaultKey: vaultKey, itemKey: itemKey, undoManager: manager)
        }
        return
      }
      let restored = Task { () -> Set<CredentialEntry>? in
        await pending?.value
        return await self.performRestore(box)
      }
      manager.registerMainActorUndo(named: "Delete") { [weak self] manager in
        guard let self else { return }
        let redoBox = DeletedEntriesBox()
        let redo = Task {
          guard let targets = await restored.value, !targets.isEmpty else { return }
          if let error = await self.performDelete(
            into: redoBox, vaultKey: vaultKey, itemKey: itemKey, targets: targets)
          {
            self.undoFailure = UndoFailure(
              vaultKey: vaultKey, itemKey: itemKey, message: "Redo failed: \(error)")
          }
        }
        self.registerUndo(
          of: redoBox, after: redo, vaultKey: vaultKey, itemKey: itemKey, undoManager: manager)
      }
    }
  }

  /// Delete `targets` and record the deleted contents in `box` for undo.
  private func performDelete(
    into box: DeletedEntriesBox, vaultKey: String, itemKey: String,
    targets: Set<CredentialEntry>
  ) async -> String? {
    undoFailure = nil
    guard let item = item(vaultKey: vaultKey, itemKey: itemKey) else {
      return ItemNotLoadedError(itemKey: itemKey).description
    }
    let before = CredentialEntry.entries(of: item)

    var sections: [DeletedEntries.Section] = []
    var credentials: [DeletedEntries.Credential] = []
    for entry in before where targets.contains(entry) {
      switch entry {
      case .section(let id):
        if let section = item.sections.first(where: { $0.id == id }) {
          sections.append(.init(id: id, title: section.title))
        }
      case .credential(let key):
        if let cred = item.credentials.first(where: { $0.key == key }) {
          credentials.append(.init(id: cred.id, key: key))
        }
      }
    }

    var deletedSections: [DeletedEntries.Section] = []
    var deletedCredentials: [DeletedEntries.Credential] = []
    let error = await failureMessage {
      try await mutate(vaultKey) {
        for cred in credentials {
          if item.credentials.first(where: { $0.key == cred.key })?.kind.kind == "file" {
            try await core.deleteFile(vaultKey: vaultKey, itemKey: itemKey, credKey: cred.key)
          } else {
            try await core.deleteCredential(
              vaultKey: vaultKey, itemKey: itemKey, credKey: cred.key)
          }
          deletedCredentials.append(cred)
        }
        for section in sections {
          try await core.deleteSection(vaultKey: vaultKey, itemKey: itemKey, sectionId: section.id)
          deletedSections.append(section)
        }
      }
    }
    if !deletedSections.isEmpty || !deletedCredentials.isEmpty {
      box.entries = DeletedEntries(
        vaultKey: vaultKey, itemKey: itemKey, before: before, sections: deletedSections,
        credentials: deletedCredentials)
    }
    return error
  }

  /// Restore deleted contents, then the arrangement from before the delete.
  /// Returns the restored entries, or nil if there is nothing to restore. A
  /// credential whose key has since been reused is restored under a new key.
  /// A credential already restored from Recently Deleted is kept under its
  /// current key. A credential that fails to restore stays in the vault's
  /// deleted credentials. Failures, including credentials deleted
  /// permanently, are reported in `undoFailure`. Does nothing while locked.
  private func performRestore(_ box: DeletedEntriesBox) async -> Set<CredentialEntry>? {
    guard isAppUnlocked, let deleted = box.entries else { return nil }
    box.entries = nil
    let vaultKey = deleted.vaultKey
    let itemKey = deleted.itemKey
    let liveCredentials = item(vaultKey: vaultKey, itemKey: itemKey)?.credentials ?? []
    var takenKeys = Set(liveCredentials.map(\.key))
    let liveKeys = Dictionary(
      liveCredentials.map { ($0.id, $0.key) }, uniquingKeysWith: { first, _ in first })
    // Ids in the vault's deleted credentials, or nil if they could not be listed.
    let deletedIds = (try? await core.listDeletedCredentials(vaultKey: vaultKey))
      .map { Set($0.map(\.id)) }

    undoFailure = nil
    var failures: [String] = []
    var newSectionIds: [String: String] = [:]
    var newCredentialKeys: [String: String] = [:]
    var restored: Set<CredentialEntry> = []
    for section in deleted.sections {
      do {
        let id = try await core.createSection(
          vaultKey: vaultKey, itemKey: itemKey, title: section.title
        ).id
        newSectionIds[section.id] = id
        restored.insert(.section(id))
      } catch {
        failures.append("section \(section.title): \(error)")
      }
    }
    for cred in deleted.credentials {
      if let liveKey = liveKeys[cred.id] {
        newCredentialKeys[cred.key] = liveKey
        restored.insert(.credential(liveKey))
        continue
      }
      if let deletedIds, !deletedIds.contains(cred.id) {
        failures.append("\(cred.key) was deleted permanently")
        continue
      }
      let key = Self.unusedKey(cred.key, taken: takenKeys)
      do {
        try await core.restoreCredential(
          vaultKey: vaultKey, itemKey: itemKey, credId: cred.id,
          newKey: key == cred.key ? nil : key)
        takenKeys.insert(key)
        newCredentialKeys[cred.key] = key
        restored.insert(.credential(key))
      } catch {
        failures.append("\(cred.key): \(error)")
      }
    }
    await loadItems(for: vaultKey)

    // Old arrangement with restored entries under their new ids and keys.
    // Entries added after the delete go at the end.
    if let item = item(vaultKey: vaultKey, itemKey: itemKey) {
      let current = CredentialEntry.entries(of: item)
      let currentSet = Set(current)
      var arranged = deleted.before.map { entry -> CredentialEntry in
        switch entry {
        case .section(let id): return .section(newSectionIds[id] ?? id)
        case .credential(let key): return .credential(newCredentialKeys[key] ?? key)
        }
      }.filter { currentSet.contains($0) }
      let arrangedSet = Set(arranged)
      arranged += current.filter { !arrangedSet.contains($0) }
      if let error = await failureMessage({
        try await arrangeItem(vaultKey: vaultKey, itemKey: itemKey, entries: arranged)
      }) {
        failures.append("order: \(error)")
      }
    }

    if !failures.isEmpty {
      undoFailure = UndoFailure(
        vaultKey: vaultKey, itemKey: itemKey,
        message: "Undo did not restore everything. \(failures.joined(separator: "; "))")
    }
    return restored
  }

  /// Deleted credentials of an item, most recently deleted first.
  func deletedCredentials(vaultKey: String) async throws -> [DeletedCredentialInfo] {
    try await core.listDeletedCredentials(vaultKey: vaultKey)
  }

  /// Restore a deleted credential into the item it was deleted from. If its
  /// key has been reused, it is restored under a new key. Returns the key it
  /// was restored under. Items are reloaded first so the new key is chosen from
  /// current keys.
  @discardableResult
  func restoreDeletedCredential(vaultKey: String, _ deleted: DeletedCredentialInfo) async throws
    -> String
  {
    await loadItems(for: vaultKey)
    let taken = Set(
      item(vaultKey: vaultKey, itemKey: deleted.itemKey)?.credentials.map(\.key) ?? [])
    let key = Self.unusedKey(deleted.key, taken: taken)
    try await mutate(vaultKey) {
      try await core.restoreCredential(
        vaultKey: vaultKey, itemKey: deleted.itemKey, credId: deleted.id,
        newKey: key == deleted.key ? nil : key)
    }
    return key
  }

  /// History of an item, newest first, as stored in the vault.
  func itemHistory(vaultKey: String, itemKey: String) async throws -> [ItemHistoryEventInfo] {
    try await core.listItemHistory(vaultKey: vaultKey, itemKey: itemKey)
  }

  /// Previous values of a credential, most recently replaced first.
  func credentialHistory(vaultKey: String, itemKey: String, credKey: String) async throws
    -> [HistoryEntryInfo]
  {
    try await core.listCredentialHistory(vaultKey: vaultKey, itemKey: itemKey, credKey: credKey)
  }

  /// Fetch a previous value of a credential without keeping it in plain memory.
  func historyValue(vaultKey: String, itemKey: String, credKey: String, historyId: String)
    async throws -> SymmetricKey
  {
    var raw = try await core.getCredentialHistoryValue(
      vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, historyId: historyId)
    let key = SymmetricKey(data: raw)
    raw.resetBytes(in: raw.indices)
    return key
  }

  /// Make a previous value the current value. The value it replaces is added to
  /// the history.
  func restoreHistoryValue(
    vaultKey: String, itemKey: String, credKey: String, historyId: String
  ) async throws {
    try await core.restoreCredentialHistoryValue(
      vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, historyId: historyId)
  }

  /// Delete a previous value permanently.
  func purgeHistoryValue(
    vaultKey: String, itemKey: String, credKey: String, historyId: String
  ) async throws {
    try await core.purgeCredentialHistory(
      vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, historyId: historyId)
  }

  /// Delete a deleted credential permanently.
  func purgeDeletedCredential(vaultKey: String, _ deleted: DeletedCredentialInfo) async throws {
    try await core.purgeCredential(
      vaultKey: vaultKey, itemKey: deleted.itemKey, credId: deleted.id)
  }

  /// Fetch the value of a deleted credential, or of a credential in a deleted
  /// item, without keeping it in plain memory.
  func deletedCredentialSecret(vaultKey: String, itemId: String, credId: String) async throws
    -> SymmetricKey
  {
    var raw = try await core.getDeletedCredentialSecret(
      vaultKey: vaultKey, itemId: itemId, credId: credId)
    let key = SymmetricKey(data: raw)
    raw.resetBytes(in: raw.indices)
    return key
  }

  /// `key` if not in `taken`, otherwise the first free key of `key-restored`,
  /// `key-restored-2`, and so on.
  static func unusedKey(_ key: String, taken: Set<String>) -> String {
    guard taken.contains(key) else { return key }
    var candidate = "\(key)-restored"
    var suffix = 2
    while taken.contains(candidate) {
      candidate = "\(key)-restored-\(suffix)"
      suffix += 1
    }
    return candidate
  }

  // MARK: - Folders and sections

  func createFolder(vaultKey: String, title: String) async throws {
    try await mutate(vaultKey) {
      _ = try await core.createFolder(vaultKey: vaultKey, title: title)
    }
  }

  func renameFolder(vaultKey: String, folderId: String, title: String) async throws {
    try await mutate(vaultKey) {
      try await core.renameFolder(vaultKey: vaultKey, folderId: folderId, title: title)
    }
  }

  /// Delete a folder. Its items become unfiled.
  func deleteFolder(vaultKey: String, folderId: String) async throws {
    try await mutate(vaultKey) {
      try await core.deleteFolder(vaultKey: vaultKey, folderId: folderId)
    }
  }

  /// Move an item into a folder. A nil `folderId` removes it from its folder.
  func moveItem(vaultKey: String, itemKey: String, folderId: String?) async throws {
    try await mutate(vaultKey) {
      try await core.moveItem(vaultKey: vaultKey, itemKey: itemKey, folderId: folderId)
    }
  }

  /// Move items into a folder in one vault write. A nil `folderId` removes them
  /// from their folders.
  func moveItems(vaultKey: String, itemKeys: [String], folderId: String?) async throws {
    try await mutate(vaultKey) {
      for itemKey in itemKeys {
        try await core.moveItem(vaultKey: vaultKey, itemKey: itemKey, folderId: folderId)
      }
    }
  }

  /// Create a section at the end of the item. Returns its id.
  func createSection(vaultKey: String, itemKey: String, title: String) async throws -> String {
    try await mutate(vaultKey) {
      try await core.createSection(vaultKey: vaultKey, itemKey: itemKey, title: title).id
    }
  }

  /// Persist the display order of item sections. `sectionIds` must list every
  /// section in the item exactly once.
  func reorderSections(vaultKey: String, itemKey: String, sectionIds: [String]) async throws {
    try await mutate(vaultKey) {
      try await core.reorderSections(
        vaultKey: vaultKey, itemKey: itemKey, orderedSectionIds: sectionIds)
    }
  }

  func renameSection(vaultKey: String, itemKey: String, sectionId: String, title: String)
    async throws
  {
    try await mutate(vaultKey) {
      try await core.renameSection(
        vaultKey: vaultKey, itemKey: itemKey, sectionId: sectionId, title: title)
    }
  }

  /// Delete a section. Its credentials become unsectioned.
  func deleteSection(vaultKey: String, itemKey: String, sectionId: String) async throws {
    try await mutate(vaultKey) {
      try await core.deleteSection(vaultKey: vaultKey, itemKey: itemKey, sectionId: sectionId)
    }
  }

  /// Run a vault mutation, then reload the vault items so the panes show what
  /// was saved. Reloads on success and failure. Rethrows the mutation error.
  private func mutate<T>(_ vaultKey: String, _ action: () async throws -> T) async throws -> T {
    let result: Result<T, Error>
    do {
      result = .success(try await action())
    } catch {
      result = .failure(error)
    }
    await loadItems(for: vaultKey)
    return try result.get()
  }

  // MARK: - Passkeys

  /// The items of a vault, loading them first when they are not cached. For
  /// choosing where something moves to.
  func destinationItems(in vaultKey: String) async -> [ItemInfo] {
    if itemCache[vaultKey] == nil { await loadItems(for: vaultKey) }
    return itemCache[vaultKey] ?? []
  }

  /// Move a passkey to another item, which may be in another vault. With no
  /// `destItemKey` it moves into a new login for its relying party.
  @discardableResult
  func movePasskey(
    vaultKey: String, itemKey: String, credKey: String, destVaultKey: String, destItemKey: String?
  ) async -> Bool {
    actionError = nil
    do {
      try await core.movePasskey(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, destVaultKey: destVaultKey,
        destItemKey: destItemKey)
    } catch {
      actionError = String(describing: error)
      return false
    }
    await loadItems(for: vaultKey)
    if destVaultKey != vaultKey { await loadItems(for: destVaultKey) }
    return true
  }

  /// Give a passkey the account name its site reported.
  func applyPasskeyName(vaultKey: String, itemKey: String, credKey: String, name: String) async {
    actionError = nil
    do {
      try await core.applyPasskeyName(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, name: name)
    } catch {
      actionError = String(describing: error)
      return
    }
    await loadItems(for: vaultKey)
  }

  /// Dismiss a site report about a passkey. Keeping a passkey the site no
  /// longer accepts offers it in AutoFill again.
  func dismissPasskeyReport(
    vaultKey: String, itemKey: String, credKey: String, kind: PasskeyReportKind
  ) async {
    actionError = nil
    do {
      try await core.dismissPasskeyReport(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, kind: kind)
    } catch {
      actionError = String(describing: error)
      return
    }
    await loadItems(for: vaultKey)
  }

  /// The most recent sign-ins of one passkey, newest first. Events name the
  /// passkey by its WebAuthn credential id in base64url, which is unchanged
  /// by a rename or a move. Events without the id are left out.
  func recentSignIns(passkeyCredentialId: String, limit: UInt32) async -> [AuditLogRow] {
    let filter = AuditFilterInput(
      sinceRfc3339: nil,
      untilRfc3339: nil,
      actions: ["passkey.asserted"],
      categories: [],
      kind: nil,
      requesters: [],
      outcomes: [.succeeded],
      query: nil,
      detailId: AuditDetailIdInput(key: "passkey_credential_id", id: passkeyCredentialId),
      limit: limit,
      offset: 0
    )
    guard let events = try? await core.listAuditEvents(filter: filter) else { return [] }
    return events.map(AuditLogRow.init)
  }

  /// The items of a vault as last loaded, without loading. Empty when the
  /// vault is not cached.
  func cachedItems(in vaultKey: String) -> [ItemInfo] {
    itemCache[vaultKey] ?? []
  }

  /// Move every credential of `sourceItemKey` into `destItemKey` and delete
  /// the source item.
  @discardableResult
  func mergeItems(vaultKey: String, sourceItemKey: String, destItemKey: String) async -> Bool {
    actionError = nil
    do {
      try await core.mergeItems(
        vaultKey: vaultKey, sourceItemKey: sourceItemKey, destItemKey: destItemKey)
    } catch {
      actionError = String(describing: error)
      return false
    }
    await loadItems(for: vaultKey)
    return true
  }

  // MARK: - Logins

  /// Create a login and select it. Returns the new item's key, or nil with
  /// `actionError` set.
  func createLogin(
    vaultKey: String, website: String, username: String?, password: String, itemKey: String?,
    title: String?
  ) async -> String? {
    actionError = nil
    let key: String
    do {
      key = try await core.createLogin(
        vaultKey: vaultKey, website: website, username: username, password: password,
        itemKey: itemKey, title: title)
    } catch {
      actionError = String(describing: error)
      return nil
    }
    await loadItems(for: vaultKey)
    selectedItemRef = ItemRef(vaultKey: vaultKey, itemKey: key)
    await offerAutofillSetupIfNeeded()
    return key
  }

  func generatePassword(length: UInt32 = 20, symbols: Bool = true) -> String? {
    try? core.generatePassword(length: length, symbols: symbols)
  }

  /// Assign `role` ("username", "password", or "totp") to a credential, or
  /// clear it when `credKey` is nil.
  @discardableResult
  func setCredentialRole(vaultKey: String, itemKey: String, role: String, credKey: String?) async
    -> Bool
  {
    actionError = nil
    do {
      try await core.setCredentialRole(
        vaultKey: vaultKey, itemKey: itemKey, role: role, credKey: credKey)
      await loadItems(for: vaultKey)
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  @discardableResult
  func setItemWebsites(vaultKey: String, itemKey: String, websites: [WebsiteInfo]) async -> Bool {
    actionError = nil
    do {
      try await core.setItemWebsites(vaultKey: vaultKey, itemKey: itemKey, websites: websites)
      await loadItems(for: vaultKey)
      return true
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  @discardableResult
  func convertItemToLogin(vaultKey: String, itemKey: String) async -> Bool {
    actionError = nil
    do {
      let converted = try await core.convertItemToLogin(vaultKey: vaultKey, itemKey: itemKey)
      await loadItems(for: vaultKey)
      if converted { await offerAutofillSetupIfNeeded() }
      return converted
    } catch {
      actionError = String(describing: error)
      return false
    }
  }

  func currentTotpCode(vaultKey: String, itemKey: String, credKey: String) async throws
    -> TotpCodeInfo
  {
    try await core.currentTotpCode(vaultKey: vaultKey, itemKey: itemKey, credKey: credKey)
  }

  // MARK: - Conversion banner

  /// The ids of items whose "Use this item for AutoFill?" banner the user
  /// dismissed. An id survives renaming the item or moving it between vaults.
  /// Ids stored in the hyphenated form are read as short ids.
  private(set) var dismissedConversions: Set<String> = Set(
    (UserDefaults.standard.stringArray(forKey: Preferences.Key.dismissedConversions) ?? [])
      .map { shortId(id: $0) ?? $0 })

  func dismissConversion(_ item: ItemInfo) {
    dismissedConversions.insert(item.id)
    UserDefaults.standard.set(
      dismissedConversions.sorted(), forKey: Preferences.Key.dismissedConversions)
  }

  // MARK: - Merge banner

  /// Item pairs whose "Merge logins?" banner the user dismissed. Keys stored
  /// with hyphenated ids are read with short ids.
  private(set) var dismissedMerges: Set<String> = Set(
    (UserDefaults.standard.stringArray(forKey: Preferences.Key.dismissedMerges) ?? [])
      .map(shortMergeKey))

  /// The key a dismissed merge is stored under: the two item ids, sorted, so
  /// the order of the two items does not matter.
  static func mergeKey(_ a: ItemInfo, _ b: ItemInfo) -> String {
    [a.id, b.id].sorted().joined(separator: "|")
  }

  /// A stored merge key with each id in the short form, sorted again.
  nonisolated private static func shortMergeKey(_ key: String) -> String {
    key.split(separator: "|").map { shortId(id: String($0)) ?? String($0) }.sorted()
      .joined(separator: "|")
  }

  func dismissMerge(_ a: ItemInfo, _ b: ItemInfo) {
    dismissedMerges.insert(Self.mergeKey(a, b))
    UserDefaults.standard.set(
      dismissedMerges.sorted(), forKey: Preferences.Key.dismissedMerges)
  }

  // MARK: - AutoFill setup banner

  /// Whether to tell the user to turn Axo Pass on in System Settings. Shown once,
  /// after the first login is created or converted, and only while the provider
  /// is off.
  private(set) var showAutofillSetupBanner = false

  private func offerAutofillSetupIfNeeded() async {
    guard !UserDefaults.standard.bool(forKey: Preferences.Key.autofillSetupBannerSeen) else {
      return
    }
    let enabled = await ASCredentialIdentityStore.shared.state().isEnabled
    showAutofillSetupBanner = !enabled
    if enabled { UserDefaults.standard.set(true, forKey: Preferences.Key.autofillSetupBannerSeen) }
  }

  func dismissAutofillSetupBanner() {
    showAutofillSetupBanner = false
    UserDefaults.standard.set(true, forKey: Preferences.Key.autofillSetupBannerSeen)
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

  var selectedItemType: ItemType? {
    if case .itemType(let type) = sidebarSelection { return type }
    return nil
  }

  /// True when the selection lists items from every vault: "All Secrets" or an
  /// item type.
  var isAllVaults: Bool { isAllSecrets || selectedItemType != nil }

  /// Selection if it lists items. Nil for the tool sections and pages.
  private var itemListSelection: SidebarDestination? {
    switch sidebarSelection {
    case .vault, .itemType: return sidebarSelection
    default: return nil
    }
  }

  /// Title of the item list for the current selection.
  var itemListTitle: String {
    if let vault = selectedVault { return vault.name ?? vault.key }
    if let type = selectedItemType { return type.title }
    return isAllSecrets ? "All Secrets" : ""
  }

  /// The items to show for the current selection, each tagged with its vault.
  /// "All Secrets" and the item types merge every vault and sort by title.
  var displayItems: [DisplayItem] {
    guard itemListSelection != nil else { return [] }
    if isAllVaults {
      let type = selectedItemType
      return
        vaults
        .flatMap { vault in
          (itemCache[vault.key] ?? [])
            .filter { type?.contains($0) ?? true }
            .map { DisplayItem(vaultKey: vault.key, item: $0) }
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
  /// A vault whose load failed counts as finished.
  var isLoadingSelectedItems: Bool {
    guard isAppUnlocked, itemListSelection != nil else { return false }
    let isPending = { (key: String) in
      self.itemCache[key] == nil && self.itemLoadFailures[key] == nil
    }
    if isAllVaults {
      return !vaults.isEmpty && vaults.contains { isPending($0.key) }
    }
    guard let key = selectedVaultKey else { return false }
    return isPending(key)
  }
}
