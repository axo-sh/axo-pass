import AuthenticationServices
import AxoPassFFI
import Foundation
import Observation

/// Issues of the app, most severe first. One instance for the app.
///
/// Vault and sync issues are read live from `VaultsModel` and `SyncModel`.
/// SSH, GPG, shell, and AutoFill state is read here. File and socket checks
/// run on a timer. The gpg key listing and the AutoFill state are read on
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

  private(set) var agentStatus: SshAgentStatus? = nil
  private(set) var sshConf: SshAgentConfStatus? = nil
  private(set) var shell: ShellIntegrationStatus? = nil
  private(set) var gpgConf: GpgAgentConfStatus? = nil
  private(set) var browsers: [BrowserManifestStatus] = []
  private(set) var autofillEnabled: Bool? = nil
  /// GPG keys from the last listing. Nil if the listing failed or has not run.
  private(set) var gpgKeys: [GpgKeyEntry]? = nil
  private(set) var passwords: [PasswordEntryInfo] = []

  private var pollTask: Task<Void, Never>? = nil

  init(vaults: VaultsModel, sync: SyncModel) {
    self.vaults = vaults
    self.sync = sync
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
    agentStatus = core.getSshAgentStatus(agentType: .axo).status
    agentService.refreshStatus()
    sshConf = core.checkSshAgentConf()
    shell = core.checkShellIntegration()
    gpgConf = core.checkGpgAgentConf()
    browsers = browserManifestStatuses()
  }

  /// Re-read everything, including the gpg key listing and the AutoFill state.
  func refreshAll() async {
    refreshChecks()
    gpgKeys = try? await core.listGpgKeys()
    passwords = (try? await core.listPasswords()) ?? []
    autofillEnabled = await ASCredentialIdentityStore.shared.state().isEnabled
  }

  // MARK: - Issues

  /// All issues, most severe first. Order within a severity follows the order
  /// of the checks.
  var issues: [Issue] {
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
