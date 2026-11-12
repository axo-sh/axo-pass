import AuthenticationServices
import AxoPassFFI
import Foundation
import Observation

/// Issues of the app, most severe first. One instance for the app.
///
/// Vault and sync issues are read live from `VaultsModel` and `SyncModel`.
/// SSH agent, ssh config, shell, and gpg-agent config state is read from
/// `SetupStatus`. Browser and AutoFill state is read here. File and socket
/// checks run on a timer. The gpg key listing and the AutoFill state are read on
/// `refreshAll`, which runs at start and on each app activation.
@Observable
@MainActor
final class IssuesModel {
  /// GPG keys that expire within this interval are reported as expiring.
  static let gpgExpiryWarning: TimeInterval = 30 * 24 * 60 * 60

  private static let pollInterval: Duration = .seconds(10)

  private let core = AxoPass()
  private let vaults: VaultsModel
  private let sync: SyncModel
  private let agentService = AgentService.shared
  private let setup = SetupStatus.shared

  var agentStatus: SshAgentStatus? { setup.axoAgent?.status }
  var sshConf: SshAgentConfStatus? { setup.sshConf }
  var shell: ShellIntegrationStatus? { setup.shell }
  var gpgConf: GpgAgentConfStatus? { setup.gpgConf }
  private(set) var browsers: [BrowserManifestStatus] = []
  private(set) var autofillEnabled: Bool? = nil
  /// GPG keys from the last listing. Nil if the listing failed or has not run.
  private(set) var gpgKeys: [GpgKeyEntry]? = nil
  private(set) var passwords: [PasswordEntryInfo] = []

  /// Dismissed issues, as `Issue.id` to the end of the snooze. Nil for a
  /// dismissal without an end.
  private(set) var dismissals: [String: Date?] = [:]
  /// Time of the last check. Expired snoozes end at the next check.
  private(set) var now = Date()

  private var pollTask: Task<Void, Never>? = nil

  init(vaults: VaultsModel, sync: SyncModel) {
    self.vaults = vaults
    self.sync = sync
    dismissals = Self.loadDismissals()
  }

  /// Read all state, then poll the file and socket checks. Call once at
  /// launch.
  func start() {
    guard pollTask == nil else { return }
    pollTask = Task { [weak self] in
      await self?.refreshAll()
      while !Task.isCancelled {
        try? await Task.sleep(for: Self.pollInterval)
        self?.refreshChecks()
      }
    }
  }

  /// Re-read the agent status and the config files. Cheap enough for the
  /// timer.
  func refreshChecks() {
    now = Date()
    setup.refresh()
    browsers = browserManifestStatuses()
  }

  /// Re-read everything, including the gpg key listing and the AutoFill state.
  /// Saved passphrases are listed only while the app is unlocked. The listing
  /// authenticates on the shared auth thread, which the unlock also needs.
  func refreshAll() async {
    refreshChecks()
    gpgKeys = try? await core.listGpgKeys()
    if vaults.isAppUnlocked {
      passwords = (try? await core.listPasswords()) ?? []
    }
    autofillEnabled = await ASCredentialIdentityStore.shared.state().isEnabled
  }

  // MARK: - Issues

  /// Issues that are not dismissed, most severe first. Order within a severity
  /// follows the order of the checks.
  var issues: [Issue] {
    allIssues.filter { !isDismissed($0) }
  }

  /// Dismissed and snoozed issues whose condition still holds.
  var dismissedIssues: [Issue] {
    allIssues.filter { isDismissed($0) }
  }

  private var allIssues: [Issue] {
    let all = vaultIssues + sshIssues + shellIssues + gpgIssues + autofillIssues
    return all.sorted { $0.severity < $1.severity }
  }

  /// Issues that count toward the issue badge.
  var countedIssues: [Issue] {
    issues.filter { $0.severity.isCounted }
  }

  /// Most urgent severity among the counted issues. Nil if none.
  var worstSeverity: IssueSeverity? {
    countedIssues.first?.severity
  }

  // MARK: - Dismissal

  /// Whether `issue` is dismissed, or snoozed until after the last check.
  func isDismissed(_ issue: Issue) -> Bool {
    guard issue.isDismissible, let entry = dismissals[issue.id] else { return false }
    guard let until = entry else { return true }
    return until > now
  }

  /// End of the snooze of `issue`. Nil if the issue is dismissed without an
  /// end or not dismissed.
  func snoozedUntil(_ issue: Issue) -> Date? {
    dismissals[issue.id] ?? nil
  }

  /// Hide `issue` until `until`, or until restored if `until` is nil.
  func dismiss(_ issue: Issue, until: Date? = nil) {
    guard issue.isDismissible else { return }
    now = Date()
    dismissals[issue.id] = .some(until)
    saveDismissals()
  }

  /// Show a dismissed or snoozed issue again.
  func restore(_ issue: Issue) {
    dismissals[issue.id] = nil
    saveDismissals()
  }

  /// Dismissals from `UserDefaults`. Snoozes that have ended are dropped.
  private static func loadDismissals() -> [String: Date?] {
    let stored =
      UserDefaults.standard.dictionary(forKey: Preferences.Key.dismissedIssues)
      as? [String: Double] ?? [:]
    var result: [String: Date?] = [:]
    for (id, seconds) in stored {
      if seconds == 0 {
        result[id] = .some(nil)
      } else if seconds > Date().timeIntervalSince1970 {
        result[id] = Date(timeIntervalSince1970: seconds)
      }
    }
    return result
  }

  private func saveDismissals() {
    let stored = dismissals.mapValues { $0?.timeIntervalSince1970 ?? 0 }
    UserDefaults.standard.set(stored, forKey: Preferences.Key.dismissedIssues)
  }

  // MARK: - Checks

  private var vaultIssues: [Issue] {
    var list: [Issue] = []
    if let state = sync.keyState, keyStateTitle(state) != nil {
      list.append(.vaultKeyState(state))
    }
    if let message = vaults.loadError {
      list.append(.vaultLoadFailed(message: message))
    }
    if !sync.missingVaults.isEmpty {
      list.append(.syncedVaultsMissing(count: sync.missingVaults.count))
    }
    if vaults.hiddenVaultFileCount > 0 {
      list.append(.vaultFilesHidden(count: vaults.hiddenVaultFileCount))
    }
    for vault in vaults.vaults {
      let ref = SyncVaultRef(key: vault.key, name: vault.name ?? vault.key)
      if case .unknown(let message) = sync.state(vault.key) {
        list.append(.syncUnreadable(ref, message: message))
      }
      guard let report = sync.report(vault.key) else { continue }
      if report.needsFolder {
        list.append(.syncFolderNeeded(ref))
      }
      switch report.status {
      case .stopped(let cause)?: list.append(.syncStopped(ref, cause: cause))
      case .paused(let causes)?: list.append(.syncPaused(ref, causes: causes))
      case .active?, nil: break
      }
      if report.recoveryKitMissing {
        list.append(.recoveryKitMissing(ref))
      }
    }
    let roots = sync.pairingCounts.keys.sorted { rootDescription($0) < rootDescription($1) }
    for root in roots {
      if let count = sync.pairingCounts[root], count > 0 {
        list.append(.pairingRequests(root: root, count: count))
      }
    }
    return list
  }

  private var sshIssues: [Issue] {
    var list: [Issue] = []
    let inUse = sshConf?.state == .configured || shell?.configured == true
    switch agentStatus {
    case .notRunning: list.append(.agentNotRunning(staleSocket: false, inUse: inUse))
    case .staleSocket: list.append(.agentNotRunning(staleSocket: true, inUse: inUse))
    case .running, nil: break
    }
    if agentService.startsOnLogin && agentService.status == .requiresApproval {
      list.append(.agentNeedsApproval)
    }
    if let sshConf {
      switch sshConf.state {
      case .notConfigured: list.append(.identityAgentMissing(configPath: sshConf.configPath))
      case .otherAgent:
        list.append(
          .identityAgentOther(configPath: sshConf.configPath, agent: sshConf.currentAgent))
      case .configured: break
      }
    }
    return list
  }

  private var shellIssues: [Issue] {
    guard let shell, !shell.configured else { return [] }
    return [.shellIntegrationMissing(zshrcPath: shell.zshrcPath)]
  }

  private var gpgIssues: [Issue] {
    var list: [Issue] = []
    if let gpgConf {
      switch gpgConf.state {
      case .notConfigured: list.append(.pinentryMissing(confPath: gpgConf.confPath))
      case .otherProgram:
        list.append(.pinentryOther(confPath: gpgConf.confPath, program: gpgConf.currentProgram))
      case .configured: break
      }
    }
    // Without a key listing, every saved passphrase would look orphaned.
    guard let gpgKeys else { return list }
    // Expiry is checked on the primary key only. An expired subkey is often
    // replaced by a newer one, so it is not reported.
    let warnBefore = Int64(Date().timeIntervalSince1970 + Self.gpgExpiryWarning)
    for key in gpgKeys where key.secretState != .none && !key.isRevoked && !key.isDisabled {
      let ref = GpgKeyRef(fingerprint: key.fingerprint, name: key.name)
      if key.isExpired {
        list.append(.gpgKeyExpired(ref))
      } else if let expiresAt = key.expiresAt, expiresAt <= warnBefore {
        list.append(.gpgKeyExpiring(ref, expiresAt: expiresAt))
      }
    }
    let keygrips = Set(
      gpgKeys.flatMap { key in [key.keygrip].compactMap { $0 } + key.subkeys.compactMap(\.keygrip) }
    )
    let orphaned = passwords.filter { $0.passwordType == .gpgKey && !keygrips.contains($0.keyId) }
    if !orphaned.isEmpty {
      list.append(.gpgOrphanedPassphrases(count: orphaned.count))
    }
    return list
  }

  private var autofillIssues: [Issue] {
    var list: [Issue] = []
    if autofillEnabled == false {
      list.append(.autofillOff)
    }
    for status in browsers where status.browserInstalled {
      switch status.state {
      case .current: break
      case .notInstalled:
        list.append(.browserManifestMissing(browser: status.browser, name: status.name))
      case .foreign(let owner):
        list.append(
          .browserManifestForeign(browser: status.browser, name: status.name, owner: owner))
      case .pointsElsewhere, .outdated, .unreadable:
        list.append(
          .browserManifestBroken(browser: status.browser, name: status.name, state: status.state))
      }
    }
    return list
  }
}
