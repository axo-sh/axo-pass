import AxoPassFFI
import Observation

@Observable
@MainActor
final class ShellIntegrationModel {
  private let setupStatus = SetupStatus.shared

  var status: ShellIntegrationStatus? { setupStatus.shell }
  var isConfiguring = false
  var configureError: String? = nil

  func refreshStatus() {
    setupStatus.refreshShell()
  }

  func configure() async {
    isConfiguring = true
    configureError = nil
    do {
      try await setupStatus.configureShell()
    } catch {
      configureError = error.userMessage
    }
    isConfiguring = false
  }

  /// Link `ap` and check a new zsh for the hook the user added by hand.
  /// Returns whether the hook was found.
  func linkAndVerify() async -> Bool {
    isConfiguring = true
    configureError = nil
    do {
      try await setupStatus.installApSymlink()
      try await setupStatus.verifyShellHook()
    } catch {
      configureError = error.userMessage
    }
    isConfiguring = false
    return status?.hookConfigured == true
  }
}
