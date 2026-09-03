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
  private let make: () -> LAAuthenticationView

  init(context: LAContext) {
    make = { LAAuthenticationView(context: context) }
  }

  /// Adopt a view built ahead of time. The signing prompt creates its view
  /// before the evaluation starts, which is before the panel showing it
  /// appears.
  init(view: LAAuthenticationView) {
    make = { view }
  }

  func makeNSView(context _: Context) -> LAAuthenticationView {
    make()
  }

  func updateNSView(_: LAAuthenticationView, context _: Context) {}
}
