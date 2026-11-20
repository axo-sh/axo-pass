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
      configureError = String(describing: error)
    }
    isConfiguring = false
  }
}
