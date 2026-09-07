import AxoPassFFI
import Foundation
import Observation

@Observable
@MainActor
final class SshModel {
  // SSH keys don't touch vault state, so this can be an independent
  // AxoPass instance rather than sharing VaultsModel's.
  private let core = AxoPass()

  var keys: [SshKeyEntry] = []
  /// SHA256 fingerprint of the key shown in the detail pane.
  var selectedFingerprint: String? = nil
  var axoAgentStatus: SshAgentStatusResponse? = nil
  var systemAgentStatus: SshAgentStatusResponse? = nil
  var loadError: String? = nil
  var isLoading = false

  /// State of the `IdentityAgent` directive in `~/.ssh/config`.
  var confStatus: SshAgentConfStatus? = nil
  var isConfiguring = false
  var configureError: String? = nil

  var isTogglingAgent = false
  var agentError: String? = nil

  var selectedKey: SshKeyEntry? {
    guard let selectedFingerprint else { return nil }
    return keys.first { $0.fingerprintSha256 == selectedFingerprint }
  }

  func reload() async {
    isLoading = true
    loadError = nil
    axoAgentStatus = core.getSshAgentStatus(agentType: .axo)
    systemAgentStatus = core.getSshAgentStatus(agentType: .system)
    refreshConfStatus()
    do {
      keys = try await core.listSshKeys()
    } catch {
      keys = []
      loadError = String(describing: error)
    }
    if let selectedFingerprint, !keys.contains(where: { $0.fingerprintSha256 == selectedFingerprint })
    {
      self.selectedFingerprint = nil
    }
    isLoading = false
  }

  /// Pick up edits made in the terminal, cheap enough to run whenever the pane appears or the app
  /// is reactivated.
  func refreshConfStatus() {
    confStatus = core.checkSshAgentConf()
  }

  func configureAgentConf() async {
    isConfiguring = true
    configureError = nil
    do {
      confStatus = try await core.configureSshAgentConf()
    } catch {
      configureError = String(describing: error)
    }
    isConfiguring = false
  }

  func startAgent() async {
    isTogglingAgent = true
    agentError = nil
    do {
      try await core.startSshAgent()
    } catch {
      agentError = String(describing: error)
    }
    await reload()
    isTogglingAgent = false
  }

  func stopAgent() async {
    isTogglingAgent = true
    agentError = nil
    do {
      try await core.stopSshAgent()
    } catch {
      agentError = String(describing: error)
    }
    await reload()
    isTogglingAgent = false
  }

  @discardableResult
  func addManagedKey() async -> Bool {
    do {
      let key = try await core.addManagedSshKey()
      await reload()
      selectedFingerprint = key.fingerprintSha256
      return true
    } catch {
      loadError = String(describing: error)
      return false
    }
  }

  @discardableResult
  func deleteManagedKey(fingerprintSha256: String) async -> Bool {
    do {
      try await core.deleteManagedSshKey(fingerprintSha256: fingerprintSha256)
      await reload()
      return true
    } catch {
      loadError = String(describing: error)
      return false
    }
  }

  /// Rewrite a managed key's public key file, for one whose file was deleted.
  /// Returns the path written.
  @discardableResult
  func writeManagedKeyPubkey(fingerprintSha256: String) async -> String? {
    do {
      let path = try await core.writeManagedSshKeyPubkey(fingerprintSha256: fingerprintSha256)
      await reload()
      return path
    } catch {
      loadError = String(describing: error)
      return nil
    }
  }

  /// The most recent SSH audit events for one key, newest first. Events name
  /// their key by SHA256 fingerprint, which the reader's query matches against
  /// the subject id.
  func recentEvents(fingerprintSha256: String, limit: UInt32) async -> [AuditLogRow] {
    let filter = AuditFilterInput(
      sinceRfc3339: nil,
      untilRfc3339: nil,
      actions: AuditActionGroup.ssh.actions,
      sources: [],
      outcomes: [],
      query: fingerprintSha256,
      limit: limit,
      offset: 0
    )
    guard let events = try? await core.listAuditEvents(filter: filter) else { return [] }
    return events.map(AuditLogRow.init)
  }

  @discardableResult
  func savePassword(fingerprint: String, password: String) async -> Bool {
    do {
      try await core.saveSshKeyPassword(fingerprint: fingerprint, password: password)
      await reload()
      return true
    } catch {
      loadError = String(describing: error)
      return false
    }
  }
}
