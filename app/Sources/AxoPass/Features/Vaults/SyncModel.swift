import AppKit
import AxoPassFFI
import Foundation
import Observation

/// Sync state of one vault, read from its sync report.
enum VaultSyncState: Equatable {
  /// The vault does not sync.
  case off
  /// The vault syncs with the folder `root`. `root` is nil if the folder must
  /// be chosen again.
  case on(root: SyncRootInfo?)
  /// An earlier turn-off waits for the synced folder. Sync cannot be turned on
  /// until the change is copied there.
  case turningOff
  /// The report failed with `message`.
  case unknown(message: String)

  var isOn: Bool {
    if case .on = self { return true }
    return false
  }
}

/// Progress of a vault that this Mac receives by pairing.
enum VaultImportProgress: Equatable {
  /// The sync key has not arrived, for the reason in `message`.
  case awaitingKey(message: String)
  /// The sync key arrived.
  case paired
  /// The import waits for a state file of the Mac that paired.
  case waiting
  /// The import waits for the reason in `message`.
  case blocked(message: String)
  /// The vault was built or joined under `vaultKey`.
  case imported(vaultKey: String)
  case failed(message: String)

  /// Whether the import still runs.
  var isPending: Bool {
    switch self {
    case .awaitingKey, .paired, .waiting, .blocked: true
    case .imported, .failed: false
    }
  }

  /// Whether the sync key of the vault arrived.
  var hasKey: Bool {
    if case .awaitingKey = self { return false }
    return true
  }
}

/// Choice of the join offer, for a vault that the synced folder already holds.
enum SyncJoinChoice {
  case pair
  case recoveryKit
}

/// Vault that a sync sheet is for.
struct SyncVaultRef: Identifiable, Hashable {
  let key: String
  let name: String

  var id: String { key }
}

/// Sync sheet that `SyncModel` requests. A nil `root` is shown as the pointer
/// to the synced folder in Settings.
enum SyncSheet: Identifiable {
  /// Enable sheet of the vault.
  case enable(SyncVaultRef)
  /// Pairing of this Mac as the new Mac. `join` is the vault of the join
  /// offer.
  case pair(root: SyncRootInfo?, join: SyncVaultRef?)
  /// Kit import. `join` is the vault of the join offer, which the kit joins.
  case kitImport(root: SyncRootInfo?, join: SyncVaultRef?)
  /// Pairing prompt of the pairing requests under `root`.
  case pairingPrompt(root: SyncRootInfo)
  /// Pairing of this Mac and the pairing requests in the folder `root`, to
  /// cancel or delete.
  case pendingPairings(root: SyncRootInfo)
  /// Sync status of the vault, with its notices.
  case status(SyncVaultRef)
  /// New recovery kit for the current sync key of the vault.
  case newKit(SyncVaultRef)
  /// Synced vaults whose vault file is missing.
  case missingVaults
  /// Key state of this Mac: new hardware, signing key lost, or a keychain
  /// error.
  case keyState

  var id: String {
    switch self {
    case .enable(let vault): return "enable-\(vault.key)"
    case .pair(_, let join): return "pair-\(join?.key ?? "")"
    case .kitImport(_, let join): return "kit-\(join?.key ?? "")"
    case .pairingPrompt(let root): return "prompt-\(rootDescription(root))"
    case .pendingPairings(let root): return "pending-\(rootDescription(root))"
    case .status(let vault): return "status-\(vault.key)"
    case .newKit(let vault): return "new-kit-\(vault.key)"
    case .missingVaults: return "missing-vaults"
    case .keyState: return "key-state"
    }
  }
}

/// Sync of the vaults for the app. One instance registers the sync events
/// delegate at launch, and holds the sync state of each vault, the pairing
/// counts, and the pairing imports.
///
/// Calls go through the `AxoPass` of `VaultsModel`, so the vault copies that a
/// sync call saves are the copies the vault panes read.
@Observable
@MainActor
final class SyncModel {
  private let vaults: VaultsModel
  private var registered = false

  /// Sync state by vault key. A vault with no entry has not been read.
  private(set) var states: [String: VaultSyncState] = [:]

  /// Last sync report by vault key. A vault whose report failed has no entry.
  private(set) var reports: [String: SyncReportInfo] = [:]

  /// Synced vaults whose vault file is missing, as the core found them at its
  /// start and after each rebuild or turn-off.
  private(set) var missingVaults: [MissingVaultInfo] = []

  /// Key state of this Mac at the last read. Nil until read.
  private(set) var keyState: KeyStateInfo? = nil

  /// Synced vaults of the local sync states, read without verifying them, if
  /// the key state is new hardware.
  private(set) var newHardwareVaults: [SyncedVaultInfo] = []

  /// Whether the key state sheet opened on its own once in this process.
  private var keyStateShown = false

  /// Pairing requests that prompt, by synced folder. A folder with no request
  /// has no entry.
  private(set) var pairingCounts: [SyncRootInfo: UInt32] = [:]

  /// Pairing imports by vault id.
  private(set) var imports: [String: VaultImportProgress] = [:]

  /// Pairing of this Mac as the new Mac, while it runs. It continues if its
  /// sheet closes, until it ends or the user cancels it.
  private(set) var activePairing: PairingHandle? = nil

  /// Whether this Mac waits for a pairing or for the import of a vault it
  /// received.
  var isPairing: Bool {
    activePairing != nil || imports.values.contains { $0.isPending }
  }

  /// Short description of the pairing progress. Nil if nothing runs.
  var pairingStatus: String? {
    guard isPairing else { return nil }
    let pending = imports.values.filter(\.isPending).count
    if let activePairing {
      let total = activePairing.vaultIds().count
      let received = activePairing.vaultIds().filter { imports[$0]?.hasKey == true }.count
      if received < total { return "Pairing: \(received) of \(total) vaults received" }
    }
    return pending == 1 ? "Importing 1 vault" : "Importing \(pending) vaults"
  }

  /// Sync sheet that is shown. Setting another sheet replaces it.
  var sheet: SyncSheet? = nil

  /// Vault whose turn-off confirmation is shown.
  var disableRequest: SyncVaultRef? = nil

  /// Last failed turn-off, shown in an alert.
  private(set) var disableError: (vaultKey: String, message: String)? = nil

  /// Handler of the join offer. The join buttons are disabled while it is nil.
  /// Set at init to replace the enable sheet with the pairing or kit sheet.
  var onJoin: ((SyncJoinChoice, SyncVaultRef, SyncRootInfo) -> Void)? = nil

  /// Display name of this Mac for the other Macs.
  let macName: String = Host.current().localizedName ?? "Mac"

  /// Synced folder of the app, chosen in Settings. Each vault turned on syncs
  /// with it. The folder of a vault is set when sync is turned on, so a change
  /// applies to vaults turned on later. Nil until the user chooses one.
  private(set) var folder: SyncRootInfo? = SyncModel.savedRoot()

  init(vaults: VaultsModel) {
    self.vaults = vaults
    onJoin = { [weak self] choice, vault, root in
      switch choice {
      case .pair: self?.sheet = .pair(root: root, join: vault)
      case .recoveryKit: self?.sheet = .kitImport(root: root, join: vault)
      }
    }
  }

  /// Synced location chosen in Settings. An S3 location wins over a folder.
  private static func savedRoot() -> SyncRootInfo? {
    let defaults = UserDefaults.standard
    if let name = defaults.string(forKey: Preferences.Key.syncS3) { return .s3(name: name) }
    return defaults.string(forKey: Preferences.Key.syncFolder).map { .folder(path: $0) }
  }

  /// Set the synced folder of the app to `url`.
  func setFolder(_ url: URL) {
    UserDefaults.standard.set(url.path, forKey: Preferences.Key.syncFolder)
    UserDefaults.standard.removeObject(forKey: Preferences.Key.syncS3)
    folder = .folder(path: url.path)
  }

  /// Name of the S3 location of the app. Settings saved under it are
  /// replaced if the user saves again.
  static let s3Name = "default"

  /// Set the synced location of the app to the saved S3 location `s3Name`.
  func setS3() {
    UserDefaults.standard.set(Self.s3Name, forKey: Preferences.Key.syncS3)
    folder = .s3(name: Self.s3Name)
  }

  /// Test the bucket of `settings`. Saves nothing.
  func testS3(_ settings: S3SettingsInput) async throws -> S3TestInfo {
    try await vaults.core.s3Test(settings: settings)
  }

  /// Save `settings` as the S3 location of the app and make it the synced
  /// location.
  func saveS3(_ settings: S3SettingsInput) async throws {
    try await vaults.core.s3Save(name: Self.s3Name, settings: settings)
    setS3()
  }

  /// Saved S3 settings of the app, without the secret. Nil if none is saved.
  func loadS3() async throws -> S3SettingsInfo? {
    try await vaults.core.s3Load(name: Self.s3Name)
  }

  /// Show the pairing sheet that adds synced vaults from another Mac. The
  /// sidebar and the welcome window both start it here.
  func showPairing() {
    sheet = .pair(root: folder, join: nil)
  }

  /// Show the kit import sheet that adds a synced vault with a recovery kit.
  func showKitImport() {
    sheet = .kitImport(root: folder, join: nil)
  }

  /// Register the sync events delegate of the process. Call once at launch.
  /// The core replays the pairing counts held since its start.
  func register() {
    guard !registered else { return }
    registered = true
    setSyncEvents(delegate: SyncEventsBridge(model: self))
  }

  // MARK: - Sync state

  func state(_ vaultKey: String) -> VaultSyncState? {
    states[vaultKey]
  }

  func report(_ vaultKey: String) -> SyncReportInfo? {
    reports[vaultKey]
  }

  /// Read the key state, the sync state of every listed vault, and the missing
  /// vaults again. Drops the states of vaults no longer listed. The first read
  /// that finds a key state with a notice opens its sheet. Does nothing while
  /// locked.
  func reloadAll() async {
    guard vaults.isAppUnlocked else { return }
    await reloadKeyState()
    if !keyStateShown, hasKeyStateNotice, sheet == nil {
      keyStateShown = true
      sheet = .keyState
    }
    reloadMissingVaults()
    let keys = vaults.vaults.map(\.key)
    states = states.filter { keys.contains($0.key) }
    reports = reports.filter { keys.contains($0.key) }
    for key in keys {
      await reload(key)
      if !vaults.isAppUnlocked { return }
    }
  }

  /// Read the sync state of vault `vaultKey` from its sync report. Needs the
  /// app unlocked. An expired authentication locks the app.
  func reload(_ vaultKey: String) async {
    guard vaults.isAppUnlocked else { return }
    do {
      let report = try await vaults.core.syncReport(vaultKey: vaultKey)
      reports[vaultKey] = report
      if report.disableInProgress {
        states[vaultKey] = .turningOff
      } else if report.status != nil || report.root != nil {
        states[vaultKey] = .on(root: report.root)
      } else {
        states[vaultKey] = .off
      }
    } catch FfiError.AuthExpired, FfiError.AuthCancelled {
      vaults.lock()
    } catch {
      reports[vaultKey] = nil
      states[vaultKey] = .unknown(message: error.userMessage)
    }
  }

  // MARK: - Key state

  /// Whether the key state of this Mac needs a notice: new hardware, signing
  /// key lost, or a keychain error.
  var hasKeyStateNotice: Bool {
    switch keyState {
    case .newHardware, .signingKeyLost, .keychainError: return true
    case .normal, .noVaultFiles, nil: return false
    }
  }

  /// Read the key state again, and the synced vaults on new hardware. Probes
  /// the keychain without a prompt. A failed read clears both, since the core
  /// fails only if its state is poisoned.
  func reloadKeyState() async {
    do {
      let state = try await vaults.core.keyState()
      keyState = state
      newHardwareVaults =
        state == .newHardware ? try await vaults.core.newHardwareSyncedVaults() : []
    } catch {
      keyState = nil
      newHardwareVaults = []
    }
  }

  /// Create a new signing key and sign every vault file and previous version
  /// again, after the user confirmed. Then read the vaults and the key state
  /// again.
  func resign() async throws -> ResignedInfo {
    let resigned = try await vaults.core.resign()
    vaults.reload()
    await vaults.brokerVaultsChanged([])
    await reloadKeyState()
    return resigned
  }

  /// Vault files moved to `unreadable/` on new hardware.
  func movedVaults() async throws -> [MovedVaultInfo] {
    try await vaults.core.movedVaults()
  }

  // MARK: - Status actions

  /// Number of differences the override of vault `vaultKey` would show as
  /// conflicts. Needs the app unlocked.
  func overridePreview(vaultKey: String) async throws -> UInt32 {
    try await lockingOnExpiry { try await vaults.core.syncOverridePreview(vaultKey: vaultKey) }
  }

  /// Resume the sync of vault `vaultKey` stopped by drift, and show the
  /// differences as conflicts. Needs the app unlocked.
  func resumeWithConflicts(vaultKey: String) async throws {
    try await lockingOnExpiry { try await vaults.core.syncOverrideConfirm(vaultKey: vaultKey) }
    await reload(vaultKey)
    await vaults.syncedVaultChanged(vaultKey)
  }

  /// Set the synced folder of vault `vaultKey`, chosen again, to `url`. The
  /// folder must hold the vault. Reads no key.
  func setRoot(vaultKey: String, url: URL) async throws {
    try await vaults.core.syncSetRoot(vaultKey: vaultKey, root: .folder(path: url.path))
    await reload(vaultKey)
  }

  /// New recovery kit text for the current sync key of vault `vaultKey`.
  /// Writes nothing. Needs the app unlocked.
  func createKit(vaultKey: String) async throws -> String {
    try await lockingOnExpiry { try await vaults.core.recoveryKitCreate(vaultKey: vaultKey) }
  }

  /// Add the kit `kitText` to vault `vaultKey` after the user saved it. Needs
  /// the app unlocked.
  func confirmKit(vaultKey: String, kitText: String) async throws {
    try await lockingOnExpiry {
      try await vaults.core.recoveryKitConfirm(vaultKey: vaultKey, kitText: kitText)
    }
    await reload(vaultKey)
  }

  // MARK: - Missing vaults

  /// Read the missing vaults again. A failure leaves the list empty, since the
  /// core fails only if its state is poisoned.
  func reloadMissingVaults() {
    missingVaults = (try? vaults.core.listMissingVaults()) ?? []
  }

  /// Rebuild the missing vault `vaultId` from its sync state. Needs the app
  /// unlocked. Returns the key of the rebuilt vault.
  @discardableResult
  func rebuildMissingVault(_ vaultId: String) async throws -> String {
    let key = try await lockingOnExpiry {
      try await vaults.core.rebuildMissingVault(vaultId: vaultId)
    }
    reloadMissingVaults()
    vaults.reload()
    await reload(key)
    return key
  }

  /// Turn off sync of the missing vault `vaultId`. Needs the app unlocked.
  func disableMissingVault(_ vaultId: String) async throws {
    _ = try await lockingOnExpiry {
      try await vaults.core.disableMissingVault(vaultId: vaultId)
    }
    reloadMissingVaults()
  }

  // MARK: - Enable

  /// Start the sync setup of vault `vaultKey` with the folder `root`. Writes
  /// nothing.
  func prepare(vaultKey: String, root: SyncRootInfo) async throws -> SyncStartInfo {
    try await vaults.core.syncPrepare(vaultKey: vaultKey, root: root, name: macName)
  }

  /// Turn on sync with `setup` after the user saved the kit. Returns the titles
  /// of the items whose later duplicate websites were removed.
  func confirm(_ setup: SyncSetupHandle) async throws -> [String] {
    let vaultKey = setup.vaultKey()
    let ids: [String]
    do {
      ids = try await vaults.core.syncConfirm(setup: setup)
    } catch FfiError.AuthExpired {
      vaults.lock()
      throw FfiError.AuthExpired
    }
    await reload(vaultKey)
    await vaults.syncedVaultChanged(vaultKey)
    return await vaults.itemTitles(ids: ids, vaultKey: vaultKey)
  }

  /// Why the setup of vault `vaultKey` with `root` was refused, read from the
  /// state again, since the refusals reach the app as `InvalidInput`.
  func refusal(vaultKey: String, root: SyncRootInfo) async -> SetupRefusal? {
    await reload(vaultKey)
    switch states[vaultKey] {
    case .turningOff: return .disableInProgress
    case .on: return .alreadyEnabled
    default: break
    }
    if case .join(let root)? = try? await prepare(vaultKey: vaultKey, root: root) {
      return .folderHasVault(root)
    }
    return nil
  }

  /// Refusal of a sync setup.
  enum SetupRefusal {
    case disableInProgress
    case alreadyEnabled
    case folderHasVault(SyncRootInfo)
  }

  // MARK: - Disable

  /// Turn off sync of vault `vaultKey` on this Mac.
  func disable(vaultKey: String) async {
    disableError = nil
    do {
      _ = try await vaults.core.syncDisable(vaultKey: vaultKey)
    } catch FfiError.AuthExpired, FfiError.AuthCancelled {
      vaults.lock()
      return
    } catch {
      disableError = (vaultKey, error.userMessage)
    }
    await reload(vaultKey)
    await vaults.syncedVaultChanged(vaultKey)
  }

  func clearDisableError() {
    disableError = nil
  }

  // MARK: - Pairing on the new Mac

  /// Start pairing this Mac as the new Mac with the folder `root`. Reads
  /// `vault-encryption-key` once on the shared context. Clears the import
  /// progress of the vaults of the request. The sync manager reports each
  /// vault through the events. On new hardware the start moves every vault
  /// file to `unreadable/` and creates the keys, so the vaults and the key
  /// state are read again.
  func startPairing(root: SyncRootInfo) async throws -> PairingHandle {
    let handle = try await lockingOnExpiry {
      try await vaults.core.pairingStart(root: root, name: macName)
    }
    for id in handle.vaultIds() { imports[id] = nil }
    activePairing = handle
    vaults.reload()
    await reloadKeyState()
    return handle
  }

  /// Stop the running pairing and delete its request. Imports of vaults that
  /// already received their key continue.
  func cancelPairing() {
    try? activePairing?.finish()
    activePairing = nil
  }

  /// Show the pairing of this Mac and the requests in the synced folder.
  func showPendingPairings() {
    guard let folder else { return }
    sheet = .pendingPairings(root: folder)
  }

  /// Requests in the folder `root`, oldest first, with their age.
  func pairingRequestList(root: SyncRootInfo) async throws -> [PairingRequestInfo] {
    try await vaults.core.pairingRequestList(root: root)
  }

  /// Delete the request `requestId` in the folder `root`.
  func deletePairingRequest(root: SyncRootInfo, requestId: String) async throws {
    try await vaults.core.pairingRequestDelete(root: root, requestId: requestId)
  }

  /// Run the failed import of the vault again.
  func retryImport(_ vaultId: String) {
    imports[vaultId] = .waiting
    do {
      try vaults.core.pairingRetryImport(vaultId: vaultId)
    } catch {
      imports[vaultId] = .failed(message: error.userMessage)
    }
  }

  // MARK: - Pairing prompt

  /// Computer name of the request under `root` that `code` matches. Nil if no
  /// request matches. Reads no key.
  func matchCode(root: SyncRootInfo, code: String) async throws -> String? {
    try await vaults.core.pairingMatchCode(root: root, code: code)
  }

  /// Synced vaults of this Mac that the request matched by `code` asks for.
  func pairingVaults(root: SyncRootInfo, code: String) async throws -> [PairingVaultInfo] {
    try await vaults.core.pairingVaults(root: root, code: code)
  }

  /// Share the vaults `vaultIds` with the new Mac of the request matched by
  /// `code`. Needs the app unlocked.
  func grant(root: SyncRootInfo, code: String, vaultIds: [String]) async throws
    -> [PairingGrantInfo]
  {
    let results = try await lockingOnExpiry {
      try await vaults.core.pairingGrant(root: root, code: code, vaultIds: vaultIds)
    }
    // A granted request no longer prompts.
    let granted = results.contains { if case .granted = $0.outcome { true } else { false } }
    if granted, let count = pairingCounts[root] {
      pairingCounts[root] = count > 1 ? count - 1 : nil
    }
    return results
  }

  /// Dismiss the current pairing requests under `root` and clear their count.
  /// Only a request with a new id prompts again.
  func dismissPairing(root: SyncRootInfo) async throws {
    try await vaults.core.pairingDismiss(root: root)
    pairingCounts[root] = nil
  }

  // MARK: - Kit import

  /// Check the kit `kitText` against the folder `root`. Writes nothing other
  /// than download requests. Reads no key.
  func checkKit(root: SyncRootInfo, kitText: String) async throws -> RecoveryCheckInfo {
    try await vaults.core.recoveryCheck(root: root, kitText: kitText)
  }

  /// Import the vault of the kit `kitText` from the folder `root`, or join the
  /// vault `join` with it. The kit is checked again first. Reads
  /// `vault-encryption-key` once on the shared context. A kit of another vault
  /// than `join` is refused. On new hardware the import moves every vault file
  /// to `unreadable/` and creates the keys, so the key state is read again.
  func importKit(root: SyncRootInfo, kitText: String, join: SyncVaultRef?) async throws
    -> RecoveryImportInfo
  {
    let result = try await lockingOnExpiry {
      if let join {
        return try await vaults.core.syncJoinWithKit(
          vaultKey: join.key, root: root, kitText: kitText, name: macName)
      }
      return try await vaults.core.recoveryImport(root: root, kitText: kitText, name: macName)
    }
    if case .imported(let vaultKey, _) = result {
      vaults.reload()
      await reloadKeyState()
      await reload(vaultKey)
      await vaults.syncedVaultChanged(vaultKey)
    }
    return result
  }

  /// Run `call`. An expired authentication locks the app and is thrown again.
  private func lockingOnExpiry<T>(_ call: () async throws -> T) async throws -> T {
    do {
      return try await call()
    } catch FfiError.AuthExpired {
      vaults.lock()
      throw FfiError.AuthExpired
    }
  }

  // MARK: - Events

  /// A transaction joined a peer change of the vault.
  fileprivate func vaultSynced(_ vaultId: String) {
    guard let key = vaults.vaultKey(id: vaultId) else { return }
    Task {
      await vaults.syncedVaultChanged(key)
      await reload(key)
    }
  }

  fileprivate func pairingRequests(_ root: SyncRootInfo, _ count: UInt32) {
    pairingCounts[root] = count == 0 ? nil : count
  }

  fileprivate func pairingEnded() {
    activePairing = nil
  }

  fileprivate func importProgress(_ vaultId: String, _ progress: VaultImportProgress) {
    imports[vaultId] = progress
    guard case .imported(let key) = progress else { return }
    vaults.reload()
    Task {
      await vaults.syncedVaultChanged(key)
      await reload(key)
    }
  }
}

/// Forwards the sync events, which arrive on the sync manager thread, to the
/// main-actor model. Each method returns immediately.
final class SyncEventsBridge: SyncEventsDelegate {
  private let model: SyncModel

  init(model: SyncModel) {
    self.model = model
  }

  func vaultSynced(vaultId: String) {
    Task { @MainActor [model] in model.vaultSynced(vaultId) }
  }

  /// A peer change of a vault that waits for the next unlock. The unlock loads
  /// every vault, so nothing is shown.
  func peerChanged(vaultId: String) {}

  func pairingRequests(root: SyncRootInfo, count: UInt32) {
    Task { @MainActor [model] in model.pairingRequests(root, count) }
  }

  func vaultPaired(vaultId: String) {
    Task { @MainActor [model] in model.importProgress(vaultId, .paired) }
  }

  func importWaiting(vaultId: String) {
    Task { @MainActor [model] in model.importProgress(vaultId, .waiting) }
  }

  func vaultImported(vaultId: String, vaultKey: String) {
    Task { @MainActor [model] in model.importProgress(vaultId, .imported(vaultKey: vaultKey)) }
  }

  func importFailed(vaultId: String, message: String) {
    Task { @MainActor [model] in model.importProgress(vaultId, .failed(message: message)) }
  }

  func importBlocked(vaultId: String, message: String) {
    Task { @MainActor [model] in model.importProgress(vaultId, .blocked(message: message)) }
  }

  func pairingBlocked(vaultId: String, message: String) {
    Task { @MainActor [model] in model.importProgress(vaultId, .awaitingKey(message: message)) }
  }

  func pairingEnded() {
    Task { @MainActor [model] in model.pairingEnded() }
  }
}
