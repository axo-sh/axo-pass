import AppKit
import AxoPassFFI
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// Draws the prompts gpg-agent asks for through `ap pinentry`.
///
/// If the passphrase is saved in the keychain, shows the biometric prompt (same as SSH signing).
/// Otherwise, or if gpg just rejected the saved passphrase, shows a text field for the passphrase.
@MainActor
final class PassphrasePromptModel {
  private let grants = AuthorizationGrants(label: "PassphrasePrompt")
  private var showTask: Task<Void, Never>?

  /// Resumed when the user answers the text field, the confirmation, or the
  /// message. Only one prompt is ever on screen: the broker serves requests
  /// serially.
  private var pending: CheckedContinuation<PromptAnswer, Never>?

  /// Where the prompts are drawn. `VaultsModel` watches it, so the app can step
  /// aside while one is up. Watching the panel rather than the broker's
  /// `begin`/`end` pair means a request served with no UI at all does not
  /// disturb the app's own unlock, and a caller that goes away mid-read cannot
  /// leave the app stepped aside for good.
  let panel = PromptPanel()

  private enum PromptAnswer {
    case passphrase(value: String, saveToKeychain: Bool)
    case confirmed
    case cancelled
  }

  // MARK: - Broker delegate

  /// Prepare a context to read the saved passphrase on, and put the biometric
  /// prompt on screen.
  func begin(prompt: PassphrasePrompt) -> UInt64 {
    let grant = grants.begin(Self.grantKey(prompt), caller: prompt.caller)

    // A context that is still authenticated reads the keychain with no prompt
    // at all. Delay the panel briefly so that case does not flash a window.
    showTask?.cancel()
    showTask = Task { [weak self] in
      try? await Task.sleep(for: .milliseconds(250))
      guard !Task.isCancelled else { return }
      self?.showUnlockPanel(prompt: prompt, view: grant.view)
    }

    return contextPointer(grant.context)
  }

  /// The read finished, successfully or not.
  func end(prompt: PassphrasePrompt, outcome: PromptOutcome) {
    showTask?.cancel()
    showTask = nil
    panel.hide()
    grants.end(Self.grantKey(prompt), outcome: outcome)
  }

  /// Ask the user to type the passphrase. Nil means they dismissed the prompt.
  func collect(prompt: PassphrasePrompt) async -> CollectedPassphrase? {
    showTask?.cancel()
    showTask = nil

    let answer = await withCheckedContinuation { continuation in
      pending = continuation
      showEntryPanel(prompt: prompt)
    }
    panel.hide()

    guard case .passphrase(let value, let save) = answer else { return nil }
    // The value crosses to the core as bytes, so the core never holds it as a
    // Swift string it cannot zero.
    return CollectedPassphrase(value: Data(value.utf8), saveToKeychain: save)
  }

  func confirm(description: String?) async -> Bool {
    let answer = await withCheckedContinuation { continuation in
      pending = continuation
      showMessagePanel(description: description, cancellable: true)
    }
    panel.hide()
    if case .confirmed = answer { return true }
    return false
  }

  func message(description: String?) async {
    _ = await withCheckedContinuation { continuation in
      pending = continuation
      showMessagePanel(description: description, cancellable: false)
    }
    panel.hide()
  }

  /// Dismiss the biometric prompt on the user's behalf. Invalidating the
  /// context fails the read in flight, which the broker reports as a
  /// cancellation.
  func cancelUnlock(prompt: PassphrasePrompt) {
    grants.forget(Self.grantKey(prompt))
  }

  /// Drop every passphrase authorization, so the next request prompts again.
  func forgetAll() {
    grants.forgetAll()
  }

  // MARK: - Panels

  private func showUnlockPanel(prompt: PassphrasePrompt, view: LAAuthenticationView) {
    let content = PassphraseUnlockView(
      prompt: prompt,
      icon: AuthenticationIcon(view: view),
      onCancel: { [weak self] in self?.cancelUnlock(prompt: prompt) }
    )
    panel.show(NSHostingView(rootView: content), width: 420)
  }

  private func showEntryPanel(prompt: PassphrasePrompt) {
    let content = PassphraseEntryView(
      prompt: prompt,
      // Nowhere to save it without a key grip to file it under.
      canSave: prompt.keyId != nil,
      onSubmit: { [weak self] value, save in
        self?.answer(.passphrase(value: value, saveToKeychain: save))
      },
      onCancel: { [weak self] in self?.answer(.cancelled) }
    )
    panel.show(NSHostingView(rootView: content), width: 420)
  }

  private func showMessagePanel(description: String?, cancellable: Bool) {
    let content = PassphraseMessageView(
      description: description,
      cancellable: cancellable,
      onConfirm: { [weak self] in self?.answer(.confirmed) },
      onCancel: { [weak self] in self?.answer(.cancelled) }
    )
    panel.show(NSHostingView(rootView: content), width: 360)
  }

  /// Resume whatever the panel is waiting on. Guarded because a continuation
  /// may only be resumed once, and a view can call back twice (the Return key
  /// and the button, say).
  private func answer(_ answer: PromptAnswer) {
    guard let continuation = pending else { return }
    pending = nil
    continuation.resume(returning: answer)
  }

  /// One grant per key and requesting process. A prompt with no key grip never
  /// reaches `begin`, since there is nothing in the keychain to unlock.
  private static func grantKey(_ prompt: PassphrasePrompt) -> GrantKey {
    let kind: GrantSubject.Kind = prompt.kind == .ssh ? .ssh : .gpg
    let id = prompt.keyId ?? ""
    let subject = GrantSubject(kind: kind, id: id, label: nil)
    return GrantKey(subject: subject, caller: prompt.caller)
  }
}

/// The inline biometric prompt for a passphrase already in the keychain.
private struct PassphraseUnlockView: View {
  let prompt: PassphrasePrompt
  let icon: AuthenticationIcon
  let onCancel: () -> Void

  var body: some View {
    VStack(spacing: 16) {
      icon

      VStack(spacing: 4) {
        Text(prompt.kind == .ssh ? "Unlock your SSH key" : "Unlock your OpenPGP key")
          .font(.headline)
          .multilineTextAlignment(.center)

        if let caller = prompt.caller, !caller.isEmpty {
          Text("Requested by \(caller)")
            .font(.body)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
        }
      }

      PinentryTranscript(prompt: prompt)

      Button("Cancel", action: onCancel)
        .keyboardShortcut(.cancelAction)
    }
    .padding(24)
    .frame(maxWidth: .infinity)
  }
}

/// The text field, for a key with nothing saved or one gpg has just rejected.
private struct PassphraseEntryView: View {
  let prompt: PassphrasePrompt
  let canSave: Bool
  let onSubmit: (String, Bool) -> Void
  let onCancel: () -> Void

  @State private var value = ""
  @State private var saveToKeychain = true
  @FocusState private var fieldFocused: Bool

  var body: some View {
    VStack(spacing: 16) {
      Image(systemName: "key.fill")
        .font(.system(size: 24))
        .foregroundStyle(.tint)
        .frame(width: 40, height: 40)

      VStack(spacing: 4) {
        Text(
          prompt.kind == .ssh ? "Enter your SSH key passphrase" : "Enter your OpenPGP passphrase"
        )
        .font(.headline)
        .multilineTextAlignment(.center)

        if let caller = prompt.caller, !caller.isEmpty {
          Text("Requested by \(caller)")
            .font(.body)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
        }
      }

      PinentryTranscript(prompt: prompt)

      VStack(alignment: .leading, spacing: 12) {
        SecureField(prompt.prompt ?? "Passphrase", text: $value)
          .textFieldStyle(.roundedBorder)
          .focused($fieldFocused)
          .onSubmit { onSubmit(value, saveToKeychain && canSave) }

        if canSave {
          Toggle("Save to Keychain and unlock with Touch ID", isOn: $saveToKeychain)
            .font(.subheadline)
        }
      }

      HStack {
        Spacer()
        Button("Cancel", action: onCancel)
          .keyboardShortcut(.cancelAction)
        Button("Unlock") { onSubmit(value, saveToKeychain && canSave) }
          .keyboardShortcut(.defaultAction)
          .disabled(value.isEmpty)
      }
    }
    .padding(24)
    .frame(width: 420)
    .onAppear { fieldFocused = true }
  }
}

/// A terminal-styled snippet of the request that triggered this prompt: the
/// key grip or fingerprint, any rejected-passphrase error, and the prompt
/// text gpg (or ssh) itself asked for.
private struct PinentryTranscript: View {
  let prompt: PassphrasePrompt

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      switch prompt.kind {
      case .gpg:
        line(label: "#", text: "gpg-agent — request", labelColor: .secondary, textColor: .secondary)
          + Text(" ").font(monoFont)
          + Text("NEED_PASSPHRASE").font(monoFont.weight(.semibold)).foregroundStyle(
            Color.accentColor)
      case .ssh:
        line(
          label: "#", text: "SSH_ASKPASS — request", labelColor: .secondary, textColor: .secondary)
      }

      if let keyId = prompt.keyId, !keyId.isEmpty {
        Text(keyId)
          .font(monoFont)
          .foregroundStyle(.primary)
      }

      if let description = prompt.description, !description.isEmpty {
        Text(description.trimmingCharacters(in: .whitespacesAndNewlines))
          .font(monoFont)
          .foregroundStyle(.primary)
      }

      if let errorMessage = prompt.errorMessage, !errorMessage.isEmpty {
        line(
          label: "ERROR", text: errorMessage.trimmingCharacters(in: .whitespacesAndNewlines),
          labelColor: .red, textColor: .red)
      }

      Text(prompt.prompt ?? "Passphrase")
        .font(monoFont.weight(.semibold))
        .foregroundStyle(Color.accentColor)
    }
    .textSelection(.enabled)
    .padding(14)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(
      RoundedRectangle(cornerRadius: 10, style: .continuous)
        .fill(.quaternary.opacity(0.5))
    )
  }

  private var monoFont: Font { .system(.body, design: .monospaced) }

  private func line(
    label: String, text: String, labelColor: Color = .accentColor, textColor: Color = .primary
  ) -> Text {
    Text(label).font(monoFont.weight(.semibold)).foregroundStyle(labelColor)
      + Text(" ").font(monoFont)
      + Text(text).font(monoFont).foregroundStyle(textColor)
  }
}

/// gpg's `CONFIRM` and `MESSAGE`, which carry no secret.
private struct PassphraseMessageView: View {
  let description: String?
  let cancellable: Bool
  let onConfirm: () -> Void
  let onCancel: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text(description?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "GPG needs your answer")
        .font(.subheadline)
        .fixedSize(horizontal: false, vertical: true)

      HStack {
        Spacer()
        if cancellable {
          Button("Cancel", action: onCancel)
            .keyboardShortcut(.cancelAction)
        }
        Button("OK", action: onConfirm)
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(20)
    .frame(width: 360)
  }
}

/// Bridges the core's delegate calls, which arrive off the main thread, onto
/// the main-actor model.
final class PassphrasePromptBridge: PassphrasePromptDelegate {
  private let model: PassphrasePromptModel

  init(model: PassphrasePromptModel) {
    self.model = model
  }

  func beginAuthorization(prompt: PassphrasePrompt) async throws -> UInt64 {
    await model.begin(prompt: prompt)
  }

  func collectPassphrase(prompt: PassphrasePrompt) async throws -> CollectedPassphrase? {
    await model.collect(prompt: prompt)
  }

  func endAuthorization(prompt: PassphrasePrompt, outcome: PromptOutcome) async {
    await model.end(prompt: prompt, outcome: outcome)
  }

  func confirm(description: String?) async -> Bool {
    await model.confirm(description: description)
  }

  func message(description: String?) async {
    await model.message(description: description)
  }
}
