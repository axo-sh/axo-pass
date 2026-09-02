import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// The system biometric icon, drawn in our own view rather than in the standard
/// Local Authentication dialog.
///
/// The icon tracks the authentication state of the `LAContext` it was created
/// with, so that must be the context the unlock evaluation runs on. Creating the
/// view also suppresses the system dialog for that context.
struct AuthenticationIcon: NSViewRepresentable {
  let context: LAContext

  func makeNSView(context _: Context) -> LAAuthenticationView {
    LAAuthenticationView(context: self.context)
  }

  func updateNSView(_: LAAuthenticationView, context _: Context) {}
}
