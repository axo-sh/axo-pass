import AxoPassFFI
import Foundation
import Observation

/// Backs the audit log controls of the General settings. The setting is stored
/// by the core in `config.toml`, so `ap` reads it too.
@Observable
@MainActor
final class AuditSettingsModel {
  private let core: AxoPass

  /// Whether the audit log records names, paths, and hosts.
  private(set) var includeDetails: Bool
  private(set) var isClearing = false
  /// Outcome of the last clear, for display next to the button.
  private(set) var clearResult: String? = nil
  private(set) var error: String? = nil

  init() {
    let core = AxoPass()
    self.core = core
    includeDetails = core.auditIncludeDetails()
  }

  func setIncludeDetails(_ on: Bool) {
    do {
      try core.setAuditIncludeDetails(on: on)
      error = nil
    } catch {
      self.error = error.userMessage
    }
    includeDetails = core.auditIncludeDetails()
  }

  /// Rewrite the audit files without account details.
  func clearDetails() async {
    isClearing = true
    defer { isClearing = false }
    clearResult = nil
    do {
      let changed = try await core.clearAuditDetails()
      clearResult = changed == 1 ? "Cleared 1 entry." : "Cleared \(changed) entries."
      error = nil
    } catch {
      self.error = error.userMessage
    }
  }
}
