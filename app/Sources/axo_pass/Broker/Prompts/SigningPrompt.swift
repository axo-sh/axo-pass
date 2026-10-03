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
  private let grants = AuthorizationGrants(label: "SigningPrompt", controlSize: .small)

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

    /// The app the panel offers lasting access to, and whether the user ticked
    /// it. Acted on in `end` only when the signature succeeded.
    let grantCandidate: SshGrantApp?
    let grantChoice: GrantChoice
    let fingerprint: String?
    let peer: RequestActor
  }

  private let core = AxoPass()

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
    callerChain: [ProcessNode], callerIdentity: String?, managed: Bool, peer: RequestActor,
    grantCandidate: SshGrantApp?, purpose: SshSignPurpose?
  ) -> UInt64 {
    let subject = GrantSubject(kind: .ssh, id: fingerprint ?? keyLabel, label: comment)
    let key = GrantKey(subject: subject, caller: caller, callerIdentity: callerIdentity)
    let grantChoice = GrantChoice()
    active = ActiveRequest(
      key: key, managed: managed, grantCandidate: grantCandidate, grantChoice: grantChoice,
      fingerprint: fingerprint, peer: peer)
    // Every SSH signature prompts. An app the user allowed in the key's
    // details signs without reaching here, for as long as that grant lasts.
    let grant = grants.begin(key, policy: .everyUse, peer: peer)
    let keyName = comment ?? Self.shortName(keyLabel: keyLabel, fingerprint: fingerprint)

    // A context that is still authenticated signs with no prompt at all. Delay
    // the panel briefly so that case does not flash a window on screen.
    showTask?.cancel()
    showTask = Task { [weak self] in
      try? await Task.sleep(for: .milliseconds(250))
      guard !Task.isCancelled else { return }
      self?.showPanel(
        key: key, keyName: keyName, keyFingerprint: comment == nil ? nil : fingerprint,
        managed: managed, callerChain: callerChain, purpose: purpose,
        grantCandidate: grantCandidate, grantChoice: grantChoice, view: grant.view)
    }

    return contextPointer(grant.context)
  }

  /// The signing attempt finished, successfully or not.
  ///
  /// Saves a chosen app grant before returning. The broker holds the next
  /// request until this returns, and that request must find the grant.
  func end(keyLabel: String, outcome: PromptOutcome) async {
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

    if case .succeeded = outcome, active.grantChoice.allow,
      let app = active.grantCandidate, let fingerprint = active.fingerprint
    {
      let peer = active.peer
      let expiresIn = active.grantChoice.expiration.seconds
      do {
        try await core.addSshAppGrant(
          fingerprintSha256: fingerprint, app: app, expiresInSeconds: expiresIn, peer: peer)
      } catch {
        NSLog("SigningPrompt: could not save app grant: %@", String(describing: error))
      }
    }
  }

  /// The broker signed without a prompt for an app that holds a grant. The
  /// notification is the only sign that the key was used.
  func notifyPreapproved(
    keyLabel: String, fingerprint: String?, comment: String?, caller: String?, app: SshGrantApp
  ) {
    let name = comment ?? Self.shortName(keyLabel: keyLabel, fingerprint: fingerprint)
    // An auto-loaded key held by the agent has no key label.
    report(
      name: name, caller: caller ?? app.displayName, managed: !keyLabel.isEmpty,
      outcome: .succeeded)
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
    let kind = managed ? "Secure Enclave SSH key" : "SSH key"
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

  /// `keyFingerprint` is shown next to `keyName`, and is nil when `keyName`
  /// is already derived from the fingerprint.
  private func showPanel(
    key: GrantKey, keyName: String, keyFingerprint: String?, managed: Bool,
    callerChain: [ProcessNode], purpose: SshSignPurpose?, grantCandidate: SshGrantApp?,
    grantChoice: GrantChoice, view: LAAuthenticationView
  ) {
    let content = SigningPromptView(
      caller: key.caller,
      keyName: keyName,
      keyFingerprint: keyFingerprint,
      managed: managed,
      callerChain: callerChain,
      purpose: purpose,
      grantCandidate: grantCandidate,
      grantChoice: grantChoice,
      icon: AuthenticationIcon(view: view),
      touchID: PromptCaller.hasTouchID(),
      onCancel: { [weak self] in self?.cancel(key: key) }
    )
    panel.show(content)
  }

  /// `SHA256:AbCdEf...` -> `SHA256:AbCdEf12`.
  fileprivate static func shortFingerprint(_ fingerprint: String) -> String {
    let body =
      fingerprint.hasPrefix("SHA256:")
      ? String(fingerprint.dropFirst("SHA256:".count)) : fingerprint
    return "SHA256:\(body.prefix(8))"
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
    let body =
      fingerprint.hasPrefix("SHA256:")
      ? String(fingerprint.dropFirst("SHA256:".count)) : fingerprint
    return String(body.suffix(8))
  }
}

/// Whether the user ticked "Allow" in the panel, and for how long. A class so
/// the panel and the model share it.
@Observable
final class GrantChoice {
  var allow = false
  var expiration: GrantExpiration = .oneHour
}

/// How long an app grant lasts. The core accepts 30 seconds to 12 hours, or
/// no expiration.
enum GrantExpiration: CaseIterable, Hashable {
  case thirtySeconds
  case fiveMinutes
  case oneHour
  case twelveHours
  case never

  /// Nil for no expiration.
  var seconds: UInt32? {
    switch self {
    case .thirtySeconds: 30
    case .fiveMinutes: 5 * 60
    case .oneHour: 60 * 60
    case .twelveHours: 12 * 60 * 60
    case .never: nil
    }
  }

  var label: String {
    switch self {
    case .thirtySeconds: "30 seconds"
    case .fiveMinutes: "5 minutes"
    case .oneHour: "1 hour"
    case .twelveHours: "12 hours"
    case .never: "No expiration"
    }
  }
}

private struct SigningPromptView: View {
  let caller: String?
  let keyName: String
  let keyFingerprint: String?
  let managed: Bool
  let callerChain: [ProcessNode]
  let purpose: SshSignPurpose?
  let grantCandidate: SshGrantApp?
  @Bindable var grantChoice: GrantChoice
  let icon: AuthenticationIcon
  let touchID: Bool
  let onCancel: () -> Void

  var body: some View {
    VStack(spacing: 14) {
      PromptConnection(callerChain: callerChain)

      PromptHeadline(parts: title)

      VStack(spacing: 8) {
        PromptSubjectCard(systemImage: "key.fill", title: keyName, detail: keyDetail)
        CallerChainView(
          chain: callerChain, summary: PromptCaller.requesterName(chain: callerChain))
      }

      if let grantCandidate {
        VStack(alignment: .leading, spacing: 6) {
          Toggle(
            "Allow \(grantCandidate.displayName) to use this SSH key without confirmation",
            isOn: $grantChoice.allow
          )
          .toggleStyle(.checkbox)

          if grantChoice.allow {
            // Indent to line up with the checkbox label.
            VStack(alignment: .leading, spacing: 4) {
              Picker("Duration:", selection: $grantChoice.expiration) {
                ForEach(GrantExpiration.allCases, id: \.self) { expiration in
                  Text(expiration.label).tag(expiration)
                }
              }
              .pickerStyle(.menu)
              .fixedSize()
              Text(
                "Applies to this key and to all processes started by "
                  + "\(grantCandidate.displayName)."
              )
              .font(.caption)
              .foregroundStyle(.secondary)
            }
            .padding(.leading, 20)
          }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .help(
          "\(grantCandidate.displayName) and all processes it starts, such as git hooks, can "
            + "use this SSH key for any signature, including SSH logins, without confirmation. "
            + "Revoke access in the key's details.")
      }

      BiometricFooter(icon: icon, touchID: touchID, onCancel: onCancel)
    }
    .padding(24)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private var appName: String? {
    grantCandidate?.displayName ?? PromptCaller.appName(caller: caller, chain: callerChain)
  }

  private var keyDetail: String {
    let kind = managed ? "Secure Enclave SSH key" : "SSH key"
    guard let keyFingerprint else { return kind }
    return "\(kind) · \(SigningPromptModel.shortFingerprint(keyFingerprint))"
  }

  private var title: [HeadlinePart] {
    let who: HeadlinePart = appName.map { .bold($0) } ?? .plain("An app")
    switch purpose {
    case .sshsig(let namespace):
      switch namespace {
      case "git": return [who, .plain(" wants to sign a "), .bold("git"), .plain(" commit or tag")]
      case "file": return [who, .plain(" wants to sign a file")]
      default: return [who, .plain(" wants to sign data for "), .bold("“\(namespace)”")]
      }
    case .login(let user, let host):
      guard let host else { return [who, .plain(" wants to log in with an SSH key")] }
      if host.hasPrefix("SHA256:") {
        return [who, .plain(" wants to log in to an unknown host "), .bold("(\(host))")]
      }
      if let user, !user.isEmpty {
        return [who, .plain(" wants to log in to "), .bold("\(user)@\(host)")]
      }
      return [who, .plain(" wants to log in to "), .bold(host)]
    case nil:
      return [who, .plain(" wants to use an SSH key")]
    }
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
    callerChain: [ProcessNode], callerIdentity: String?, managed: Bool, peer: RequestActor,
    policy: SshKeyPolicy?, grantCandidate: SshGrantApp?, purpose: SshSignPurpose?
  ) async throws -> UInt64 {
    await model.begin(
      keyLabel: keyLabel, fingerprint: fingerprint, comment: comment, caller: caller,
      callerChain: callerChain, callerIdentity: callerIdentity, managed: managed, peer: peer,
      grantCandidate: grantCandidate, purpose: purpose)
  }

  func endAuthorization(keyLabel: String, outcome: PromptOutcome) async {
    await model.end(keyLabel: keyLabel, outcome: outcome)
  }

  func notifyPreapproved(
    keyLabel: String, fingerprint: String?, comment: String?, caller: String?, app: SshGrantApp
  ) async {
    await model.notifyPreapproved(
      keyLabel: keyLabel, fingerprint: fingerprint, comment: comment, caller: caller, app: app)
  }
}
