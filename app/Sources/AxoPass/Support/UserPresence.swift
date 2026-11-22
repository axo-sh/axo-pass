import AxoPassFFI
import LocalAuthentication

/// A fresh check that the owner of this Mac is at the keyboard, for actions
/// that destroy data. The unlocked app does not count.
enum UserPresence {
  /// Ask for Touch ID or the login password with `reason`. Returns false if
  /// the user cancels. Throws on any other failure.
  static func confirm(core: AxoPass, reason: String) async throws -> Bool {
    // The core holds this lock around its own prompts. Take it here too, or a
    // concurrent prompt from another axo-pass process cancels this one.
    try await core.beginEmbeddedAuth()
    defer { try? core.endEmbeddedAuth() }
    do {
      return try await LAContext().evaluatePolicy(
        .deviceOwnerAuthentication, localizedReason: reason)
    } catch let error as LAError where Self.isCancel(error.code) {
      return false
    }
  }

  private static func isCancel(_ code: LAError.Code) -> Bool {
    switch code {
    case .userCancel, .appCancel, .systemCancel: true
    default: false
    }
  }
}
