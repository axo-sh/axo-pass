import AxoPassFFI
import Foundation
import Observation

@Observable
@MainActor
final class GpgModel {
  // Doesn't touch vault state, so this can be an independent AxoPass
  // instance rather than sharing VaultsModel's.
  private let core = AxoPass()

  enum TestResult {
    case success
    case failure(String)
  }

  var passwords: [PasswordEntryInfo] = []
  var loadError: String? = nil
  var isTesting = false
  var testResult: TestResult? = nil

  /// State of the `pinentry-program` line in `gpg-agent.conf`.
  var confStatus: GpgAgentConfStatus? = nil
  var isConfiguring = false
  var configureError: String? = nil

  func reload() async {
    refreshConfStatus()
    do {
      passwords = try await core.listPasswords()
      loadError = nil
    } catch {
      passwords = []
      loadError = String(describing: error)
    }
  }

  /// Pick up edits made in the terminal, cheap enough to run whenever the pane appears or the app
  /// is reactivated.
  func refreshConfStatus() {
    confStatus = core.checkGpgAgentConf()
  }

  func configureAgentConf() async {
    isConfiguring = true
    configureError = nil
    testResult = nil
    do {
      confStatus = try await core.configureGpgAgentConf()
    } catch {
      configureError = String(describing: error)
    }
    isConfiguring = false
  }

  func testIntegration() async {
    isTesting = true
    testResult = nil
    do {
      try await core.gpgTestIntegration()
      testResult = .success
    } catch {
      testResult = .failure(String(describing: error))
    }
    isTesting = false
  }

  @discardableResult
  func delete(_ entry: PasswordEntryInfo) async -> Bool {
    do {
      try await core.deletePassword(passwordType: entry.passwordType, keyId: entry.keyId)
      await reload()
      return true
    } catch {
      loadError = String(describing: error)
      return false
    }
  }
}
