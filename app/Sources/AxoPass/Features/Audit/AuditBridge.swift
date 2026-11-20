import AxoPassFFI
import Foundation

/// Thin entry point for the app to append audit events that only it knows
/// about: grant lifecycle, and vault lock state driven from the UI.
///
/// Reading and writing the log is not gated on an unlocked vault, so this
/// keeps its own `AxoPass` handle like the other independent models.
@MainActor
enum AuditBridge {
  private static let core = AxoPass()

  static func recordGrant(_ key: GrantKey, _ kind: GrantEventKind, peer: RequestActor?) {
    core.recordGrantEvent(
      kind: kind, subject: key.subject.ffiInput, caller: key.caller, scope: key.scope, peer: peer)
  }

  static func recordVault(_ kind: VaultEventKind, trigger: String? = nil) {
    core.recordVaultEvent(kind: kind, trigger: trigger)
  }
}
