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
      _ = try await core.addManagedSshKey()
      await reload()
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
