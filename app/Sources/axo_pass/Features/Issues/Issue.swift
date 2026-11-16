import AxoPassFFI
import Foundation

/// Issue severity, most urgent first.
enum IssueSeverity: Int, Comparable {
  /// Something the user set up has stopped working.
  case broken
  /// A request that waits for the user.
  case request
  /// A condition the user should act on soon.
  case advice
  /// A feature that is not set up.
  case setup
  /// A deliberate choice that differs from the default. Shown in status views
  /// only.
  case info

  static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }

  /// Whether issues of this severity count toward the issue badge.
  var isCounted: Bool { self <= .advice }
}

/// Sidebar source that an issue belongs to.
enum IssueSource {
  case ssh
  case gpg
}

/// GPG key named by an issue.
struct GpgKeyRef: Hashable {
  let fingerprint: String
  let name: String
}

/// Condition that needs the user, derived from current state. An issue clears
/// itself when the condition ends. Views map each case to its fix.
enum Issue: Hashable, Identifiable {
  // Vaults and sync.

  /// Vaults on this Mac cannot be opened. Never `.normal` or `.noVaultFiles`.
  case vaultKeyState(KeyStateInfo)
  case vaultLoadFailed(message: String)
  case syncedVaultsMissing(count: Int)
  /// Vault files not shown because they share a vault id or vault key.
  case vaultFilesHidden(count: Int)
  case syncFolderNeeded(SyncVaultRef)
  case syncStopped(SyncVaultRef, cause: StopCauseInfo)
  case syncPaused(SyncVaultRef, causes: [PausedCauseInfo])
  case syncUnreadable(SyncVaultRef, message: String)
  case recoveryKitMissing(SyncVaultRef)
  case pairingRequests(root: SyncRootInfo, count: UInt32)

  // SSH.

  /// Axo Pass agent is not running. `inUse` is true if ssh or the shell
  /// integration points at it.
  case agentNotRunning(staleSocket: Bool, inUse: Bool)
  /// Agent login item waits for approval, so launchd does not restart the
  /// agent.
  case agentNeedsApproval
  case identityAgentMissing(configPath: String)
  case identityAgentOther(configPath: String, agent: String?)

  // Shell.

  case shellIntegrationMissing(zshrcPath: String)

  // GPG.

  case pinentryMissing(confPath: String)
  case pinentryOther(confPath: String, program: String?)
  case gpgKeyExpiring(GpgKeyRef, expiresAt: Int64)
  case gpgKeyExpired(GpgKeyRef)
  /// Saved GPG passphrases whose keygrip belongs to no key in the keyring.
  case gpgOrphanedPassphrases(count: Int)

  // AutoFill.

  case autofillOff
  case browserManifestMissing(browser: BrowserKind, name: String)
  /// Manifest is outdated, points to another host, or cannot be read.
  case browserManifestBroken(browser: BrowserKind, name: String, state: BrowserManifestState)
  /// Manifest belongs to another app. Axo Pass does not replace it.
  case browserManifestForeign(browser: BrowserKind, name: String, owner: String)

  var id: String {
    switch self {
    case .vaultKeyState: return "vault-key-state"
    case .vaultLoadFailed: return "vault-load-failed"
    case .syncedVaultsMissing: return "synced-vaults-missing"
    case .vaultFilesHidden: return "vault-files-hidden"
    case .syncFolderNeeded(let vault): return "sync-folder-needed-\(vault.key)"
    case .syncStopped(let vault, _): return "sync-stopped-\(vault.key)"
    case .syncPaused(let vault, _): return "sync-paused-\(vault.key)"
    case .syncUnreadable(let vault, _): return "sync-unreadable-\(vault.key)"
    case .recoveryKitMissing(let vault): return "recovery-kit-missing-\(vault.key)"
    case .pairingRequests(let root, _): return "pairing-requests-\(rootDescription(root))"
    case .agentNotRunning: return "agent-not-running"
    case .agentNeedsApproval: return "agent-needs-approval"
    case .identityAgentMissing: return "identity-agent-missing"
    case .identityAgentOther: return "identity-agent-other"
    case .shellIntegrationMissing: return "shell-integration-missing"
    case .pinentryMissing: return "pinentry-missing"
    case .pinentryOther: return "pinentry-other"
    case .gpgKeyExpiring(let key, _): return "gpg-key-expiring-\(key.fingerprint)"
    case .gpgKeyExpired(let key): return "gpg-key-expired-\(key.fingerprint)"
    case .gpgOrphanedPassphrases: return "gpg-orphaned-passphrases"
    case .autofillOff: return "autofill-off"
    case .browserManifestMissing(let browser, _): return "browser-manifest-missing-\(browser)"
    case .browserManifestBroken(let browser, _, _): return "browser-manifest-broken-\(browser)"
    case .browserManifestForeign(let browser, _, _): return "browser-manifest-foreign-\(browser)"
    }
  }

  var severity: IssueSeverity {
    switch self {
    case .vaultKeyState, .vaultLoadFailed, .syncedVaultsMissing, .vaultFilesHidden,
      .syncFolderNeeded, .syncStopped, .syncPaused, .syncUnreadable:
      return .broken
    case .pairingRequests:
      return .request
    case .recoveryKitMissing:
      return .advice
    case .agentNotRunning(_, let inUse):
      return inUse ? .broken : .info
    case .agentNeedsApproval:
      return .advice
    case .identityAgentMissing, .shellIntegrationMissing, .pinentryMissing, .autofillOff,
      .browserManifestMissing:
      return .setup
    case .identityAgentOther, .pinentryOther, .browserManifestForeign:
      return .info
    case .gpgKeyExpiring, .gpgKeyExpired, .gpgOrphanedPassphrases:
      return .advice
    case .browserManifestBroken:
      return .broken
    }
  }

  /// Whether the user can dismiss or snooze the issue. Advice issues only.
  var isDismissible: Bool { severity == .advice }

  /// Sidebar source of the issue. Nil for vault, sync, and AutoFill issues.
  var source: IssueSource? {
    switch self {
    case .vaultKeyState, .vaultLoadFailed, .syncedVaultsMissing, .vaultFilesHidden,
      .syncFolderNeeded, .syncStopped, .syncPaused, .syncUnreadable, .recoveryKitMissing,
      .pairingRequests:
      return nil
    case .agentNotRunning, .agentNeedsApproval, .identityAgentMissing, .identityAgentOther,
      .shellIntegrationMissing:
      return .ssh
    case .pinentryMissing, .pinentryOther, .gpgKeyExpiring, .gpgKeyExpired,
      .gpgOrphanedPassphrases:
      return .gpg
    case .autofillOff, .browserManifestMissing, .browserManifestBroken, .browserManifestForeign:
      return nil
    }
  }

  /// One-line description for lists, menus, and notifications.
  var title: String {
    switch self {
    case .vaultKeyState(let state):
      return keyStateTitle(state) ?? "Vaults cannot be opened"
    case .vaultLoadFailed:
      return "Vaults could not be loaded"
    case .syncedVaultsMissing(let count):
      return count == 1 ? "1 synced vault missing" : "\(count) synced vaults missing"
    case .vaultFilesHidden(let count):
      return count == 1 ? "1 vault file not shown" : "\(count) vault files not shown"
    case .syncFolderNeeded(let vault):
      return "Choose the synced folder of \(vault.name) again"
    case .syncStopped(let vault, _):
      return "Sync stopped for \(vault.name)"
    case .syncPaused(let vault, _):
      return "Sync paused for \(vault.name)"
    case .syncUnreadable(let vault, _):
      return "Sync status of \(vault.name) could not be read"
    case .recoveryKitMissing(let vault):
      return "\(vault.name) does not open with any recovery kit"
    case .pairingRequests(_, let count):
      return count == 1 ? "1 pairing request" : "\(count) pairing requests"
    case .agentNotRunning(let staleSocket, _):
      return staleSocket
        ? "Axo Pass agent stopped and left its socket behind" : "Axo Pass agent is not running"
    case .agentNeedsApproval:
      return "Axo Pass agent needs approval in Login Items"
    case .identityAgentMissing:
      return "ssh does not use the Axo Pass agent"
    case .identityAgentOther:
      return "ssh uses another agent"
    case .shellIntegrationMissing:
      return "ap is not set up in zsh"
    case .pinentryMissing:
      return "gpg does not ask Axo Pass for passphrases"
    case .pinentryOther:
      return "gpg uses another pinentry"
    case .gpgKeyExpiring(let key, let expiresAt):
      return "\(key.name) expires \(GpgFormat.date(expiresAt) ?? "soon")"
    case .gpgKeyExpired(let key):
      return "\(key.name) has expired"
    case .gpgOrphanedPassphrases(let count):
      return count == 1
        ? "1 saved GPG passphrase does not have a key"
        : "\(count) saved GPG passphrases do not have a key"
    case .autofillOff:
      return "AutoFill is off"
    case .browserManifestMissing(_, let name):
      return "\(name) extension is not connected"
    case .browserManifestBroken(_, let name, _):
      return "\(name) extension cannot reach Axo Pass"
    case .browserManifestForeign(_, let name, let owner):
      return "\(name) extension connection belongs to \(owner)"
    }
  }
}
