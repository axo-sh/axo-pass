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
  /// The sync key arrived.
  case paired
  /// The import waits for a state file of the Mac that paired.
  case waiting
  /// The vault was built or joined under `vaultKey`.
  case imported(vaultKey: String)
  case failed(message: String)
}

/// Choice of the join offer, for a vault that the synced folder already holds.
enum SyncJoinChoice {
  case pair
  case recoveryKit
}

/// Vault that a sync sheet is for.
struct SyncVaultRef: Identifiable, Equatable {
  let key: String
  let name: String

  var id: String { key }
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

  /// Pairing requests that prompt, by synced folder. A folder with no request
  /// has no entry.
  private(set) var pairingCounts: [SyncRootInfo: UInt32] = [:]

  /// Pairing imports by vault id.
  private(set) var imports: [String: VaultImportProgress] = [:]

  /// Vault whose enable sheet is shown.
  var enableRequest: SyncVaultRef? = nil

  /// Vault whose turn-off confirmation is shown.
  var disableRequest: SyncVaultRef? = nil

  /// Last failed turn-off, shown in an alert.
  private(set) var disableError: (vaultKey: String, message: String)? = nil

  /// Handler of the join offer. The join buttons are disabled while it is nil.
  var onJoin: ((SyncJoinChoice, SyncVaultRef, SyncRootInfo) -> Void)? = nil

  /// Display name of this Mac for the other Macs.
  let macName: String = Host.current().localizedName ?? "Mac"

  /// Synced folder of the app, chosen in Settings. Each vault turned on syncs
  /// with it. The folder of a vault is set when sync is turned on, so a change
  /// applies to vaults turned on later. Nil until the user chooses one.
  private(set) var folder: SyncRootInfo? =
    UserDefaults.standard.string(forKey: Preferences.Key.syncFolder).map { .folder(path: $0) }

  init(vaults: VaultsModel) {
    self.vaults = vaults
  }

  /// Set the synced folder of the app to `url`.
  func setFolder(_ url: URL) {
    UserDefaults.standard.set(url.path, forKey: Preferences.Key.syncFolder)
    folder = .folder(path: url.path)
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

  /// Read the sync state of every listed vault again. Drops the states of
  /// vaults no longer listed. Does nothing while locked.
  func reloadAll() async {
    guard vaults.isAppUnlocked else { return }
    let keys = vaults.vaults.map(\.key)
    states = states.filter { keys.contains($0.key) }
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
      states[vaultKey] = .unknown(message: String(describing: error))
    }
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
      disableError = (vaultKey, String(describing: error))
    }
    await reload(vaultKey)
    await vaults.syncedVaultChanged(vaultKey)
  }

  func clearDisableError() {
    disableError = nil
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
}
