import AppKit
import AxoPassFFI
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// Draws the authorization prompt for `ap item list` and `ap read`, which the
/// core's broker delegates here.
///
/// `ap` holds no keychain entitlements, so it cannot read or create the vault
/// encryption key itself. It hands the request to the broker, which calls in
/// here for a context to unlock the vault on.
///
/// This model evaluates the biometric policy itself, the same way the lock
/// screen does, rather than letting the core evaluate. `LAAuthenticationView`
/// draws `evaluatePolicy` in our panel only when the evaluation is driven from
/// this process while the view is mounted; a `deviceOwnerAuthentication`
/// evaluation started by the core lands in the system dialog instead. The core
/// reads the key on the context this call authenticated and evaluates nothing
/// itself, so one request raises one prompt.
///
/// A read prompts every time. Nothing is cached for it: the grant is created
/// for the one request and dropped when it finishes, so a script that reads a
/// secret in a loop asks for a fingerprint each time round.
///
/// A listing exposes no secret values, so its approval is reused within the
/// standard window. Grants are keyed on the action as well as the vault, so a
/// listing's approval never satisfies a read.
@MainActor
final class VaultUnlockPromptModel {
  private let grants = AuthorizationGrants(label: "VaultUnlockPrompt")
  private var showTask: Task<Void, Never>?

  /// Holds the cross-process auth lock during an evaluation. Set by
  /// `VaultsModel` when the broker starts.
  var core: AxoPass?

  /// Where the prompt is drawn. `VaultsModel` watches it, so the app can step
  /// aside while one is up.
  let panel = PromptPanel()

  // MARK: - Broker delegate

  /// Authorize the access and return the address of the context the core should
  /// unlock on. Returns 0 when the user dismisses the prompt or the evaluation
  /// fails, which the broker reports as a cancellation.
  func begin(prompt: VaultAccessPrompt, peer: RequestActor) async -> UInt64 {
    let key = Self.grantKey(prompt)
    let grant = grants.begin(key, policy: Self.policy(for: prompt.action), peer: peer)

    // A listing that is still authorized re-evaluates instantly. Delay the
    // panel briefly so that case does not flash a window. A read always
    // prompts, so it does not wait.
    showTask?.cancel()
    if Self.promptsEveryTime(prompt.action) {
      showPanel(prompt: prompt, view: grant.view)
    } else {
      showTask = Task { [weak self] in
        try? await Task.sleep(for: .milliseconds(250))
        guard !Task.isCancelled else { return }
        self?.showPanel(prompt: prompt, view: grant.view)
      }
    }

    do {
      // The core holds this lock around its own prompts. Take it here too, or a
      // concurrent prompt from another axo-pass process cancels this one.
      try await core?.beginEmbeddedAuth()
    } catch {
      showTask?.cancel()
      panel.hide()
      grants.end(key, outcome: .failed(message: String(describing: error)))
      return 0
    }

    let reason = Self.reason(for: prompt)
    do {
      try await grant.context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
      // Release the lock before returning: the core reads the key on its own
      // auth thread, and another process's prompt may proceed once this
      // evaluation is done.
      try? core?.endEmbeddedAuth()
    } catch {
      try? core?.endEmbeddedAuth()
      showTask?.cancel()
      panel.hide()
      grants.end(key, outcome: .cancelled)
      return 0
    }

    return contextPointer(grant.context)
  }

  /// The access finished, successfully or not.
  func end(prompt: VaultAccessPrompt, outcome: PromptOutcome) {
    showTask?.cancel()
    showTask = nil
    panel.hide()
    grants.end(Self.grantKey(prompt), outcome: outcome)
  }

  /// Dismiss the prompt on the user's behalf. Invalidating the context fails
  /// the evaluation in flight, which surfaces as a cancellation.
  func cancel(prompt: VaultAccessPrompt) {
    grants.forget(Self.grantKey(prompt))
  }

  /// Drop every vault authorization, so the next request prompts again. Called
  /// when the app locks, and when the machine sleeps or the screen locks.
  func forgetAll() {
    grants.forgetAll()
  }

  // MARK: - Panel

  private func showPanel(prompt: VaultAccessPrompt, view: LAAuthenticationView) {
    let content = VaultUnlockView(
      vaultKey: prompt.vaultKey,
      caller: prompt.caller,
      callerChain: prompt.callerChain,
      headline: Self.headline(for: prompt.action),
      icon: AuthenticationIcon(view: view),
      onCancel: { [weak self] in self?.cancel(prompt: prompt) }
    )
    panel.show(content)
  }

  /// The localized reason `LocalAuthentication` shows in its own chrome.
  private static func reason(for prompt: VaultAccessPrompt) -> String {
    let what: String
    switch prompt.action {
    case .readSecret:
      what = "read a secret from vault \(prompt.vaultKey)"
    case let .resolveSecrets(purpose, count):
      let verb = purpose == .read ? "read" : "resolve"
      what = "\(verb) \(count) \(count == 1 ? "secret" : "secrets") from vault \(prompt.vaultKey)"
    case .listItems:
      what = "list items in vault \(prompt.vaultKey)"
    }
    if let caller = prompt.caller, !caller.isEmpty {
      return "let \(caller) \(what)"
    }
    return what
  }

  /// True for the accesses that expose secret values and so prompt on every
  /// request. A listing does not.
  private static func promptsEveryTime(_ action: VaultAction) -> Bool {
    switch action {
    case .readSecret, .resolveSecrets: return true
    case .listItems: return false
    }
  }

  /// One grant per vault, action and requesting process, so approving one
  /// caller's request does not authorize another's inside the reuse window, and
  /// approving a listing does not authorize a read.
  private static func grantKey(_ prompt: VaultAccessPrompt) -> GrantKey {
    let subject = GrantSubject(kind: .vault, id: prompt.vaultKey, label: nil)
    return GrantKey(subject: subject, caller: prompt.caller, scope: scope(for: prompt.action))
  }

  private static func scope(for action: VaultAction) -> String {
    switch action {
    case .readSecret: return "read"
    case .resolveSecrets: return "resolve"
    case .listItems: return "list"
    }
  }

  /// Reading or resolving a secret prompts every time. Listing exposes no
  /// values, so its approval is reused for the standard window.
  private static func policy(for action: VaultAction) -> GrantPolicy {
    promptsEveryTime(action) ? .everyUse : .standard
  }

  private static func headline(for action: VaultAction) -> String {
    switch action {
    case .readSecret: return "read a secret"
    case let .resolveSecrets(purpose, count):
      let verb = purpose == .read ? "read" : "resolve"
      return "\(verb) \(count) \(count == 1 ? "secret" : "secrets")"
    case .listItems: return "list a vault"
    }
  }
}

private struct VaultUnlockView: View {
  let vaultKey: String
  let caller: String?
  let callerChain: [ProcessNode]
  let headline: String
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

        Text("Vault \(vaultKey)")
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
      return "\(caller) wants to \(headline)"
    }
    let capitalized = headline.prefix(1).uppercased() + headline.dropFirst()
    return "Authorize: \(capitalized)"
  }
}

/// Bridges the core's delegate calls, which arrive off the main thread, onto
/// the main-actor model.
final class VaultUnlockPromptBridge: VaultPromptDelegate {
  private let model: VaultUnlockPromptModel

  init(model: VaultUnlockPromptModel) {
    self.model = model
  }

  func beginAuthorization(prompt: VaultAccessPrompt, peer: RequestActor) async throws -> UInt64 {
    await model.begin(prompt: prompt, peer: peer)
  }

  func endAuthorization(prompt: VaultAccessPrompt, outcome: PromptOutcome) async {
    await model.end(prompt: prompt, outcome: outcome)
  }
}
