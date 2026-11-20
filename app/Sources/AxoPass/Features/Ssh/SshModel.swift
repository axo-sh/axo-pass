import AxoPassFFI
import Foundation
import Observation
import SwiftUI

@Observable
@MainActor
final class SshModel {
  // SSH keys don't touch vault state, so this can be an independent
  // AxoPass instance rather than sharing VaultsModel's.
  private let core = AxoPass()

  /// How the Axo Pass agent is run. Shared, since the main window and Settings
  /// each have a model.
  let agentService = AgentService.shared
  private let status = SetupStatus.shared

  var keys: [SshKeyEntry] = []
  /// SHA256 fingerprint of the key shown in the detail pane.
  var selectedFingerprint: String? = nil
  var axoAgentStatus: SshAgentStatusResponse? { status.axoAgent }
  var systemAgentStatus: SshAgentStatusResponse? { status.systemAgent }
  var loadError: String? = nil
  var isLoading = false

  /// State of the `IdentityAgent` directive in `~/.ssh/config`.
  var confStatus: SshAgentConfStatus? { status.sshConf }
  var isConfiguring = false
  var configureError: String? = nil

  enum TestResult {
    case success
    case failure(String)
  }

  var isTesting = false
  var testResult: TestResult? = nil
  private var fadeTask: Task<Void, Never>?

  /// Clear a success result after 3 seconds. A failure stays.
  private func fadeOutSuccess() {
    fadeTask = Task {
      try? await Task.sleep(for: .seconds(3))
      guard !Task.isCancelled else { return }
      withAnimation(.easeOut(duration: 0.4)) { testResult = nil }
    }
  }

  var isTogglingAgent = false
  var agentError: String? = nil

  var selectedKey: SshKeyEntry? {
    guard let selectedFingerprint else { return nil }
    return keys.first { $0.fingerprintSha256 == selectedFingerprint }
  }

  /// Key entry of the vault SSH key credential `credentialKey`. Nil if the
  /// listing does not hold it.
  func vaultKeyEntry(vaultKey: String, itemKey: String, credentialKey: String) -> SshKeyEntry? {
    keys.first { key in
      guard let location = key.vaultKey else { return false }
      return location.vaultKey == vaultKey && location.itemKey == itemKey
        && location.credentialKey == credentialKey
    }
  }

  /// Select the key with SHA256 fingerprint `fingerprintSha256` in the SSH pane.
  func show(fingerprintSha256: String, vaults: VaultsModel) {
    selectedFingerprint = fingerprintSha256
    vaults.selectSidebarDestination(.ssh)
  }

  func reload() async {
    isLoading = true
    loadError = nil
    refreshAgentStatus()
    refreshConfStatus()
    do {
      keys = try await core.listSshKeys()
    } catch {
      keys = []
      loadError = String(describing: error)
    }
    if let selectedFingerprint,
      !keys.contains(where: { $0.fingerprintSha256 == selectedFingerprint })
    {
      self.selectedFingerprint = nil
    }
    isLoading = false
  }

  /// Re-read agent state, which the CLI can change (`ap ssh-agent stop`) without the app knowing.
  func refreshAgentStatus() {
    status.refreshAgents()
  }

  /// Pick up edits made in the terminal, cheap enough to run whenever the pane appears or the app
  /// is reactivated.
  func refreshConfStatus() {
    status.refreshSshConf()
  }

  func configureAgentConf() async {
    isConfiguring = true
    configureError = nil
    testResult = nil
    do {
      try await status.configureSshConf()
    } catch {
      configureError = String(describing: error)
    }
    isConfiguring = false
  }

  func testIntegration() async {
    fadeTask?.cancel()
    isTesting = true
    testResult = nil
    do {
      try await core.sshTestIntegration()
      testResult = .success
      fadeOutSuccess()
    } catch {
      testResult = .failure(String(describing: error))
    }
    isTesting = false
  }

  func startAgent() async {
    isTogglingAgent = true
    agentError = nil
    do {
      try await agentService.start()
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
      try await agentService.stop()
    } catch {
      agentError = String(describing: error)
    }
    await reload()
    isTogglingAgent = false
  }

  @discardableResult
  func addManagedKey(alwaysRequireAuth: Bool) async -> Bool {
    do {
      let key = try await core.addManagedSshKey(alwaysRequireAuth: alwaysRequireAuth)
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

  /// The apps with lasting access to a key. Empty on failure.
  func appGrants(fingerprintSha256: String) async -> [SshAppGrant] {
    (try? await core.listSshAppGrants(fingerprintSha256: fingerprintSha256)) ?? []
  }

  /// Hosts a key signed in to, from the audit log. Empty on failure.
  func relatedHosts(fingerprintSha256: String) async -> [SshRelatedHost] {
    (try? await core.relatedSshHosts(fingerprintSha256: fingerprintSha256)) ?? []
  }

  @discardableResult
  func removeAppGrant(fingerprintSha256: String, app: SshGrantApp) async -> Bool {
    do {
      try await core.removeSshAppGrant(
        fingerprintSha256: fingerprintSha256, teamId: app.teamId, bundleId: app.bundleId)
      return true
    } catch {
      loadError = String(describing: error)
      return false
    }
  }

  /// Turn auto-load on or off for a `~/.ssh` key. Turning it off removes the
  /// key's app grants.
  @discardableResult
  func setAutoload(fingerprintSha256: String, path: String, enabled: Bool) async -> Bool {
    do {
      try await core.setSshAutoload(
        fingerprintSha256: fingerprintSha256, path: path, enabled: enabled)
      await reload()
      return true
    } catch {
      loadError = String(describing: error)
      return false
    }
  }

  /// The most recent SSH audit events for one key, newest first. Events name
  /// their key by SHA256 fingerprint, which the reader's query matches against
  /// the subject id.
  func recentEvents(fingerprintSha256: String, limit: UInt32) async -> [AuditLogRow] {
    let filter = AuditFilterInput(
      sinceRfc3339: nil,
      untilRfc3339: nil,
      actions: [],
      categories: [.ssh],
      kind: nil,
      requesters: [],
      outcomes: [],
      query: fingerprintSha256,
      detailId: nil,
      limit: limit,
      offset: 0
    )
    guard let events = try? await core.listAuditEvents(filter: filter) else { return [] }
    return events.map(AuditLogRow.init)
  }

  /// Read a key's saved passphrase back from the keychain on the app unlock.
  /// Does not prompt. Returns nil and sets `loadError` on failure.
  func revealPassword(fingerprint: String) async -> String? {
    do {
      return try await core.revealKeyPassword(passwordType: .sshKey, keyId: fingerprint)
    } catch {
      loadError = String(describing: error)
      return nil
    }
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

  /// Delete a key's saved passphrase from the keychain.
  @discardableResult
  func forgetPassword(fingerprint: String) async -> Bool {
    do {
      try await core.deletePassword(passwordType: .sshKey, keyId: fingerprint)
      await reload()
      return true
    } catch {
      loadError = String(describing: error)
      return false
    }
  }
}
