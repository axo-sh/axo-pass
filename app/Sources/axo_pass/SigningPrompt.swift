import AppKit
import AxoPassFFI
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI
import UserNotifications

/// Draws the authorization prompt for SSH signatures the agent delegates here.
///
/// The agent is headless, so on its own it can only raise the system dialog. It
/// hands the request to the core's broker instead, which calls in here for a
/// context to sign on. This process owns that context, so
/// `LAAuthenticationView` draws the biometric prompt in our panel, and the
/// broker's evaluation on that same context drives the icon.
@MainActor
final class SigningPromptModel {
  private let grants = AuthorizationGrants<String>(label: "SigningPrompt")
  private var showTask: Task<Void, Never>?

  /// Where the prompt is drawn. `VaultsModel` watches it, so the app can step
  /// aside while one is up. Watching the panel rather than the broker's
  /// `begin`/`end` pair means a signature served with no UI at all does not
  /// disturb the app's own unlock, and a caller that goes away mid-signature
  /// cannot leave the app stepped aside for good.
  let panel = PromptPanel()

  /// Ask for the notification permission used to report a signature. The events
  /// that drop an approval are watched by `VaultsModel`, which owns both
  /// prompts.
  func start() {
    UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { _, error in
      if let error {
        NSLog("SigningPrompt: notification permission failed: %@", String(describing: error))
      }
    }
  }

  // MARK: - Broker delegate

  /// Prepare a context for `keyLabel` and return its address for the broker.
  /// The context stays referenced here, so it outlives the signing attempt.
  func begin(keyLabel: String, caller: String?) -> UInt64 {
    let grant = grants.begin(keyLabel)
    grant.lastCaller = caller

    // A context that is still authenticated signs with no prompt at all. Delay
    // the panel briefly so that case does not flash a window on screen.
    showTask?.cancel()
    showTask = Task { [weak self] in
      try? await Task.sleep(for: .milliseconds(250))
      guard !Task.isCancelled else { return }
      self?.showPanel(keyLabel: keyLabel, caller: caller, view: grant.view)
    }

    return contextPointer(grant.context)
  }

  /// The signing attempt finished, successfully or not.
  func end(keyLabel: String, outcome: PromptOutcome) {
    showTask?.cancel()
    showTask = nil
    panel.hide()

    // Cancelling through our own button forgets the grant before the evaluation
    // fails, so there may be nothing left to settle.
    let grant = grants.end(keyLabel, outcome: outcome)
    report(keyLabel: keyLabel, caller: grant?.lastCaller, outcome: outcome)
  }

  /// Dismiss the prompt on the user's behalf. Invalidating the context fails
  /// the evaluation in flight, which the broker reports as a cancellation.
  func cancel(keyLabel: String) {
    grants.forget(keyLabel)
  }

  /// Drop every signing authorization, so the next signature prompts again.
  /// Called when the app locks, and when the machine sleeps or the screen
  /// locks.
  func forgetAll() {
    grants.forgetAll()
  }

  // MARK: - Reporting

  /// Tell the user a key was used. A signature served from a still-valid
  /// approval raises no prompt and shows no window, so this notification is the
  /// only indication it happened.
  private func report(keyLabel: String, caller: String?, outcome: PromptOutcome) {
    guard case .succeeded = outcome else { return }

    let content = UNMutableNotificationContent()
    content.title = "SSH key used"
    let name = Self.shortKeyName(keyLabel)
    if let caller, !caller.isEmpty {
      content.body = "Signed with Secure Enclave key \(name) for \(caller)."
    } else {
      content.body = "Signed with Secure Enclave key \(name)."
    }

    let request = UNNotificationRequest(
      identifier: UUID().uuidString, content: content, trigger: nil)
    UNUserNotificationCenter.current().add(request) { error in
      if let error {
        NSLog("SigningPrompt: could not post notification: %@", String(describing: error))
      }
    }
  }

  // MARK: - Panel

  private func showPanel(keyLabel: String, caller: String?, view: LAAuthenticationView) {
    let content = SigningPromptView(
      caller: caller,
      keyName: Self.shortKeyName(keyLabel),
      icon: AuthenticationIcon(view: view),
      onCancel: { [weak self] in self?.cancel(keyLabel: keyLabel) }
    )
    panel.show(NSHostingView(rootView: content), width: 320)
  }

  /// Shorten `ssh-key-<uuid>` for display. The leading characters are enough to
  /// tell two keys apart.
  private static func shortKeyName(_ keyLabel: String) -> String {
    let id =
      keyLabel.hasPrefix("ssh-key-") ? String(keyLabel.dropFirst("ssh-key-".count)) : keyLabel
    return String(id.prefix(6))
  }
}

private struct SigningPromptView: View {
  let caller: String?
  let keyName: String
  let icon: AuthenticationIcon
  let onCancel: () -> Void

  var body: some View {
    VStack(spacing: 14) {
      icon
        .frame(width: 64, height: 64)

      VStack(spacing: 4) {
        Text(title)
          .font(.headline)
          .multilineTextAlignment(.center)

        Text("Secure Enclave key \(keyName)")
          .font(.subheadline)
          .foregroundStyle(.secondary)
      }

      Button("Cancel", action: onCancel)
        .keyboardShortcut(.cancelAction)
    }
    .padding(24)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private var title: String {
    if let caller, !caller.isEmpty {
      return "\(caller) wants to sign with an SSH key"
    }
    return "Authorize an SSH signature"
  }
}

/// Bridges the core's delegate calls, which arrive off the main thread, onto
/// the main-actor model.
final class SigningPromptBridge: SignPromptDelegate {
  private let model: SigningPromptModel

  init(model: SigningPromptModel) {
    self.model = model
  }

  func beginAuthorization(keyLabel: String, caller: String?) async throws -> UInt64 {
    await model.begin(keyLabel: keyLabel, caller: caller)
  }

  func endAuthorization(keyLabel: String, outcome: PromptOutcome) async {
    await model.end(keyLabel: keyLabel, outcome: outcome)
  }
}
