import AxoPassFFI
import Observation

@Observable
@MainActor
final class ShellIntegrationModel {
  private let core = AxoPass()

  var status: ShellIntegrationStatus? = nil
  var isConfiguring = false
  var configureError: String? = nil

  func refreshStatus() {
    status = core.checkShellIntegration()
  }

  func configure() async {
    isConfiguring = true
    configureError = nil
    do {
      status = try await core.writeShellIntegration()
    } catch {
      configureError = String(describing: error)
    }
    isConfiguring = false
  }
}
