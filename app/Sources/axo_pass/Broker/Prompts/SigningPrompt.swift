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
  private let grants = AuthorizationGrants(label: "SigningPrompt")

  private var showTask: Task<Void, Never>?

  /// The request being served. The broker serves requests serially and pairs
  /// each `begin` with an `end`, but `end` and `cancel` are handed only the key
  /// label, so what `begin` was given is stashed here.
  private var active: ActiveRequest?

  private struct ActiveRequest {
    /// Rebuilt from the fingerprint and caller, neither of which `end` is
    /// handed.
    let key: GrantKey

    /// Whether the key is managed, so `end` words its notification to match the
    /// panel `begin` put up.
    let managed: Bool
  }

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

  /// Prepare a context for the key and return its address for the broker. The
  /// context stays referenced here, so it outlives the signing attempt.
  func begin(
    keyLabel: String, fingerprint: String?, comment: String?, caller: String?,
    callerChain: [ProcessNode], callerIdentity: String?, managed: Bool, peer: RequestActor
  ) -> UInt64 {
    let subject = GrantSubject(kind: .ssh, id: fingerprint ?? keyLabel, label: comment)
    let key = GrantKey(subject: subject, caller: caller, callerIdentity: callerIdentity)
    active = ActiveRequest(key: key, managed: managed)
    // Confirm-on-use keys (`ssh-add -c`) prompt every time: the point of the
    // constraint is that every signature is approved, so no approval is reused.
    let grant = grants.begin(key, policy: managed ? .standard : .everyUse, peer: peer)
    let keyName = comment ?? Self.shortName(keyLabel: keyLabel, fingerprint: fingerprint)

    // A context that is still authenticated signs with no prompt at all. Delay
    // the panel briefly so that case does not flash a window on screen.
    showTask?.cancel()
    showTask = Task { [weak self] in
      try? await Task.sleep(for: .milliseconds(250))
      guard !Task.isCancelled else { return }
      self?.showPanel(
        key: key, keyName: keyName, managed: managed, callerChain: callerChain, view: grant.view)
    }

    return contextPointer(grant.context)
  }

  /// The signing attempt finished, successfully or not.
  func end(keyLabel: String, outcome: PromptOutcome) {
    showTask?.cancel()
    showTask = nil
    panel.hide()

    guard let active else { return }
    self.active = nil
    let key = active.key
    // Cancelling through our own button forgets the grant before the evaluation
    // fails, so there may be nothing left to settle.
    grants.end(key, outcome: outcome)
    let name = key.subject.label ?? Self.shortName(keyLabel: keyLabel, fingerprint: key.subject.id)
    report(name: name, caller: key.caller, managed: active.managed, outcome: outcome)
  }

  /// Dismiss the prompt on the user's behalf. Invalidating the context fails
  /// the evaluation in flight, which the broker reports as a cancellation.
  func cancel(key: GrantKey) {
    grants.forget(key)
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
  private func report(name: String, caller: String?, managed: Bool, outcome: PromptOutcome) {
    guard case .succeeded = outcome else { return }

    let content = UNMutableNotificationContent()
    content.title = "SSH key used"
    let kind = managed ? "Secure Enclave key" : "SSH key"
    if let caller, !caller.isEmpty {
      content.body = "Signed with \(kind) \(name) for \(caller)."
    } else {
      content.body = "Signed with \(kind) \(name)."
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

  private func showPanel(
    key: GrantKey, keyName: String, managed: Bool, callerChain: [ProcessNode],
    view: LAAuthenticationView
  ) {
    let content = SigningPromptView(
      caller: key.caller,
      keyName: keyName,
      managed: managed,
      callerChain: callerChain,
      icon: AuthenticationIcon(view: view),
      onCancel: { [weak self] in self?.cancel(key: key) }
    )
    panel.show(content)
  }

  /// A short display name for a key. Prefers the shortened `ssh-key-<uuid>`
  /// label of a managed key, and falls back to the tail of the fingerprint for
  /// a key the agent holds directly, which has no label.
  private static func shortName(keyLabel: String, fingerprint: String?) -> String {
    if !keyLabel.isEmpty {
      let id =
        keyLabel.hasPrefix("ssh-key-") ? String(keyLabel.dropFirst("ssh-key-".count)) : keyLabel
      return String(id.prefix(6))
    }
    guard let fingerprint, !fingerprint.isEmpty else { return "key" }
    let body = fingerprint.hasPrefix("SHA256:") ? String(fingerprint.dropFirst("SHA256:".count)) : fingerprint
    return String(body.suffix(8))
  }
}

private struct SigningPromptView: View {
  let caller: String?
  let keyName: String
  let managed: Bool
  let callerChain: [ProcessNode]
  let icon: AuthenticationIcon
  let onCancel: () -> Void

  var body: some View {
    VStack(spacing: 14) {
      icon
        .frame(width: 64, height: 64)

      VStack(spacing: 4) {
        PromptTitle(text: title, callerChain: callerChain)

        Text("\(managed ? "Secure Enclave key" : "SSH key") \(keyName)")
          .font(.subheadline)
          .foregroundStyle(.secondary)
      }

      CallerChainView(chain: callerChain)

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

  func beginAuthorization(
    keyLabel: String, fingerprint: String?, comment: String?, caller: String?,
    callerChain: [ProcessNode], callerIdentity: String?, managed: Bool, peer: RequestActor
  ) async throws -> UInt64 {
    await model.begin(
      keyLabel: keyLabel, fingerprint: fingerprint, comment: comment, caller: caller,
      callerChain: callerChain, callerIdentity: callerIdentity, managed: managed, peer: peer)
  }

  func endAuthorization(keyLabel: String, outcome: PromptOutcome) async {
    await model.end(keyLabel: keyLabel, outcome: outcome)
  }
}
