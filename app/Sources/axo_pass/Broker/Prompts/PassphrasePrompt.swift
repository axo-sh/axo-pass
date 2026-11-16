import AppKit
import AxoPassFFI
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// Draws the prompts gpg-agent asks for through `ap pinentry`.
///
/// If the passphrase is saved in the keychain, shows the biometric prompt (same as SSH signing).
/// Otherwise, or if gpg just rejected the saved passphrase, shows a text field for the passphrase.
/// Also shows the biometric prompt for the `ap keychain` and `ap age` listings if the app is locked.
@MainActor
final class PassphrasePromptModel {
  private let grants = AuthorizationGrants(label: "PassphrasePrompt", controlSize: .small)
  private var showTask: Task<Void, Never>?

  /// Context of a listing prompt, which `ap keychain` and `ap age` ask for if
  /// the app is locked. A listing names no key, so it takes no grant and is
  /// never reused.
  private var listingContext: LAContext?

  /// Resumed when the user answers the text field, the confirmation, or the
  /// message. Only one prompt is ever on screen: the broker serves requests
  /// serially.
  private var pending: (id: UInt64, continuation: CheckedContinuation<PromptAnswer, Never>)?
  private var nextPromptID: UInt64 = 0
  private var typedPassphraseRequested = false

  /// Where the prompts are drawn. `VaultsModel` watches it, so the app can step
  /// aside while one is up. Watching the panel rather than the broker's
  /// `begin`/`end` pair means a request served with no UI at all does not
  /// disturb the app's own unlock, and a caller that goes away mid-read cannot
  /// leave the app stepped aside for good.
  let panel = PromptPanel()

  private enum PromptAnswer {
    case passphrase(value: String, saveToKeychain: Bool)
    case useSaved
    case confirmed
    case cancelled
  }

  // MARK: - Broker delegate

  /// Prepare a context to read the saved passphrase on, and put the biometric
  /// prompt on screen.
  func begin(prompt: PassphrasePrompt, peer: RequestActor) -> UInt64 {
    typedPassphraseRequested = false
    let context: LAContext
    let view: LAAuthenticationView
    if let key = Self.grantKey(prompt) {
      let grant = grants.begin(key, peer: peer)
      context = grant.context
      view = grant.view
    } else {
      listingContext?.invalidate()
      context = LAContext()
      // Creating the view suppresses the system dialog for this context, so it
      // has to exist before the broker evaluates.
      view = LAAuthenticationView(context: context, controlSize: .small)
      listingContext = context
    }

    // A context that is still authenticated reads the keychain with no prompt
    // at all. Delay the panel briefly so that case does not flash a window.
    showTask?.cancel()
    showTask = Task { [weak self] in
      try? await Task.sleep(for: .milliseconds(250))
      guard !Task.isCancelled else { return }
      self?.showUnlockPanel(prompt: prompt, view: view)
    }

    return contextPointer(context)
  }

  /// The read finished, successfully or not.
  func end(prompt: PassphrasePrompt, outcome: PromptOutcome) {
    showTask?.cancel()
    showTask = nil
    panel.hide()
    if let key = Self.grantKey(prompt) {
      grants.end(key, outcome: outcome)
    } else {
      endListing()
    }
  }

  /// Invalidate the listing context, so it cannot be evaluated again.
  private func endListing() {
    listingContext?.invalidate()
    listingContext = nil
  }

  /// Ask the user to type the passphrase. Nil means they dismissed the prompt.
  /// With `canUseSaved`, the panel also offers to unlock with the saved
  /// passphrase.
  func collect(prompt: PassphrasePrompt, canUseSaved: Bool) async -> CollectedPassphrase? {
    showTask?.cancel()
    showTask = nil

    let answer = await ask { showEntryPanel(prompt: prompt, canUseSaved: canUseSaved) }
    switch answer {
    case .passphrase(let value, let save):
      // The value crosses to the core as bytes, so the core never holds it as a
      // Swift string it cannot zero.
      return CollectedPassphrase(value: Data(value.utf8), saveToKeychain: save, useSaved: false)
    case .useSaved:
      return CollectedPassphrase(value: Data(), saveToKeychain: false, useSaved: true)
    case .confirmed, .cancelled:
      return nil
    }
  }

  func confirm(prompt: ConfirmPrompt) async -> Bool {
    let answer = await ask {
      showMessagePanel(
        description: prompt.description,
        okLabel: prompt.okLabel,
        cancelLabel: prompt.cancelLabel ?? "Cancel")
    }
    if case .confirmed = answer { return true }
    return false
  }

  func message(description: String?) async {
    _ = await ask { showMessagePanel(description: description, okLabel: nil, cancelLabel: nil) }
  }

  /// Put a panel up with `show` and wait for the user to answer it. The broker
  /// cancels the task when the requesting process disconnects, which answers the
  /// panel as dismissed.
  private func ask(_ show: () -> Void) async -> PromptAnswer {
    nextPromptID += 1
    let id = nextPromptID
    let answer = await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        pending = (id, continuation)
        show()
      }
    } onCancel: {
      Task { @MainActor [weak self] in self?.answer(.cancelled, id: id) }
    }
    panel.hide()
    return answer
  }

  /// Dismiss the biometric prompt on the user's behalf. Invalidating the
  /// context fails the read in flight, which the broker reports as a
  /// cancellation.
  func cancelUnlock(prompt: PassphrasePrompt) {
    if let key = Self.grantKey(prompt) {
      grants.forget(key)
    } else {
      endListing()
    }
  }

  /// Dismiss the biometric prompt and ask the broker for the text field
  /// instead.
  func requestTypedPassphrase(prompt: PassphrasePrompt) {
    typedPassphraseRequested = true
    cancelUnlock(prompt: prompt)
  }

  /// Whether the user chose to type the passphrase instead of using the saved
  /// one. Reading the value clears it.
  func takeTypedPassphraseRequest() -> Bool {
    defer { typedPassphraseRequested = false }
    return typedPassphraseRequested
  }

  /// Drop every passphrase authorization, so the next request prompts again.
  func forgetAll() {
    grants.forgetAll()
    endListing()
  }

  // MARK: - Panels

  private func showUnlockPanel(prompt: PassphrasePrompt, view: LAAuthenticationView) {
    let content = PassphraseUnlockView(
      prompt: prompt,
      icon: AuthenticationIcon(view: view),
      touchID: PromptCaller.hasTouchID(),
      onCancel: { [weak self] in
        // A listing does not take a typed passphrase, so Cancel ends the
        // request.
        if prompt.kind.isListing {
          self?.cancelUnlock(prompt: prompt)
        } else {
          self?.requestTypedPassphrase(prompt: prompt)
        }
      }
    )
    panel.show(content)
  }

  private func showEntryPanel(prompt: PassphrasePrompt, canUseSaved: Bool) {
    let content = PassphraseEntryView(
      prompt: prompt,
      // Nowhere to save it without a key grip to file it under.
      canSave: prompt.keyId != nil,
      touchID: canUseSaved ? PromptCaller.hasTouchID() : nil,
      onSubmit: { [weak self] value, save in
        self?.answer(.passphrase(value: value, saveToKeychain: save))
      },
      onUseSaved: { [weak self] in self?.answer(.useSaved) },
      onCancel: { [weak self] in self?.answer(.cancelled) }
    )
    panel.show(content)
  }

  /// A nil `cancelLabel` draws the panel with one button.
  private func showMessagePanel(description: String?, okLabel: String?, cancelLabel: String?) {
    let content = PassphraseMessageView(
      description: description,
      okLabel: okLabel ?? "OK",
      cancelLabel: cancelLabel,
      onConfirm: { [weak self] in self?.answer(.confirmed) },
      onCancel: { [weak self] in self?.answer(.cancelled) }
    )
    panel.show(content)
  }

  /// Resume whatever the panel is waiting on. Guarded because a continuation
  /// may only be resumed once, and a view can call back twice (the Return key
  /// and the button, say). With `id`, only that prompt is answered, so a late
  /// cancellation cannot answer the prompt that replaced it.
  private func answer(_ answer: PromptAnswer, id: UInt64? = nil) {
    guard let pending, id == nil || pending.id == id else { return }
    self.pending = nil
    pending.continuation.resume(returning: answer)
  }

  /// One grant per key and requesting process. Nil for a listing, which does
  /// not name a key. Any other prompt without a key grip never reaches `begin`,
  /// since it does not name a keychain entry to unlock.
  private static func grantKey(_ prompt: PassphrasePrompt) -> GrantKey? {
    let kind: GrantSubject.Kind
    switch prompt.kind {
    case .ssh: kind = .ssh
    case .gpg: kind = .gpg
    case .age: kind = .age
    case .keychainList, .ageList: return nil
    }
    let id = prompt.keyId ?? ""
    let subject = GrantSubject(kind: kind, id: id, label: nil)
    return GrantKey(subject: subject, caller: prompt.caller, callerIdentity: prompt.callerIdentity)
  }
}

extension PassphraseKind {
  /// Whether this is a listing for `ap keychain` or `ap age`, which does not
  /// name a key or take a typed passphrase.
  var isListing: Bool {
    self == .keychainList || self == .ageList
  }
}

/// The inline biometric prompt for a passphrase already in the keychain, or for
/// a listing if the app is locked.
private struct PassphraseUnlockView: View {
  let prompt: PassphrasePrompt
  let icon: AuthenticationIcon
  let touchID: Bool
  /// Falls back to the text field. Cancelling from there ends the request.
  let onCancel: () -> Void

  private var title: [HeadlinePart] {
    let (action, standalone) =
      switch prompt.kind {
      case .ssh: ("unlock your SSH key", "Unlock your SSH key")
      case .gpg: ("unlock your OpenPGP key", "Unlock your OpenPGP key")
      case .age: ("unlock your age key", "Unlock your age key")
      case .keychainList: ("list your saved passwords", "List your saved passwords")
      case .ageList: ("list your age keys", "List your age keys")
      }
    if let who = PromptCaller.appName(caller: prompt.caller, chain: prompt.callerChain) {
      return [.bold(who), .plain(" wants to \(action)")]
    }
    return [.plain(standalone)]
  }

  var body: some View {
    VStack(spacing: 14) {
      PromptConnection(callerChain: prompt.callerChain)

      PromptHeadline(parts: title)

      VStack(spacing: 8) {
        KeyInfoBox(prompt: prompt)
        CallerChainView(
          chain: prompt.callerChain,
          summary: PromptCaller.requesterName(chain: prompt.callerChain))
        // A listing does not carry prompt text to show.
        if !prompt.kind.isListing {
          PinentryTranscript(prompt: prompt)
        }
      }

      BiometricFooter(icon: icon, touchID: touchID, onCancel: onCancel)
    }
    .padding(24)
    .frame(maxWidth: .infinity)
  }
}

/// The text field, for a key with nothing saved or one gpg has just rejected.
private struct PassphraseEntryView: View {
  let prompt: PassphrasePrompt
  let canSave: Bool
  /// Non-nil if a saved passphrase can be tried again. The value is whether
  /// the Mac has Touch ID.
  let touchID: Bool?
  let onSubmit: (String, Bool) -> Void
  let onUseSaved: () -> Void
  let onCancel: () -> Void

  @State private var value = ""
  @State private var saveToKeychain = true
  @FocusState private var fieldFocused: Bool

  var body: some View {
    VStack(spacing: 14) {
      PromptConnection(callerChain: prompt.callerChain)

      PromptHeadline(parts: title)

      VStack(spacing: 8) {
        KeyInfoBox(prompt: prompt)
        CallerChainView(
          chain: prompt.callerChain,
          summary: PromptCaller.requesterName(chain: prompt.callerChain))
        PinentryTranscript(prompt: prompt)
      }

      VStack(alignment: .leading, spacing: 12) {
        RevealableSecureField(
          title: isQuestion ? "Answer" : "Passphrase",
          text: $value,
          focus: $fieldFocused,
          secret: !isQuestion,
          onSubmit: { onSubmit(value, saveToKeychain && canSave) })

        if canSave {
          Toggle("Save to Axo Pass and unlock with Touch ID", isOn: $saveToKeychain)
        }
      }

      HStack {
        Button("Cancel", action: onCancel)
          .keyboardShortcut(.cancelAction)
        if let touchID {
          Button(touchID ? "Use Touch ID" : "Use Saved", action: onUseSaved)
        }
        Spacer()
        Button(isQuestion ? "Continue" : "Unlock") { onSubmit(value, saveToKeychain && canSave) }
          .keyboardShortcut(.defaultAction)
          .disabled(value.isEmpty)
      }
      .padding(.top, 4)
    }
    .padding(24)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .onAppear { fieldFocused = true }
  }

  /// True for an ssh prompt that asks a yes/no question, such as the host key
  /// confirmation. The answer is not a secret.
  private var isQuestion: Bool {
    prompt.kind == .ssh && (prompt.prompt?.contains("(yes/no") ?? false)
  }

  private var title: [HeadlinePart] {
    if isQuestion { return [.plain("SSH prompt")] }
    let passphrase = prompt.kind == .ssh ? "SSH key passphrase" : "OpenPGP passphrase"
    if let who = PromptCaller.appName(caller: prompt.caller, chain: prompt.callerChain) {
      return [.bold(who), .plain(" is asking for your \(passphrase)")]
    }
    return [.plain("Enter your \(passphrase)")]
  }
}

/// Details of the key being unlocked, collapsed by default.
private struct KeyInfoBox: View {
  let prompt: PassphrasePrompt

  private var keyId: String? {
    guard let keyId = prompt.keyId, !keyId.isEmpty else { return nil }
    return keyId
  }

  private var description: String? {
    let text = prompt.description?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return text.isEmpty ? nil : text
  }

  private var keyIdLabel: String {
    switch prompt.kind {
    case .ssh: "Fingerprint"
    case .gpg: "Key grip"
    case .age, .keychainList, .ageList: "Key"
    }
  }

  private var kindName: String {
    switch prompt.kind {
    case .ssh: "SSH key"
    case .gpg: "OpenPGP key"
    case .age: "age key"
    case .keychainList: "saved passwords"
    case .ageList: "age keys"
    }
  }

  /// Key comment for SSH, or the quoted user ID in gpg's description.
  private var label: String? {
    guard let description else { return nil }
    guard prompt.kind == .gpg else { return description }
    return description.split(separator: "\n")
      .map { $0.trimmingCharacters(in: .whitespaces) }
      .first { $0.count > 1 && $0.hasPrefix("\"") && $0.hasSuffix("\"") }
      .map { String($0.dropFirst().dropLast()) }
  }

  /// Short identifier shown under the label.
  private var shortId: String? {
    switch prompt.kind {
    case .ssh:
      return keyId.map { "SHA256:" + $0.prefix(8) }
    case .gpg:
      if let description,
        let match = description.firstMatch(of: #/ID ([0-9A-Fa-f]+)/#)
      {
        return "ID " + match.1
      }
      return keyId.map { String($0.prefix(8)) }
    case .age, .keychainList, .ageList:
      return keyId.map { String($0.prefix(8)) }
    }
  }

  private var subtitle: String {
    ([label == nil ? nil : kindName] + [shortId]).compactMap { $0 }.joined(separator: " · ")
  }

  /// Key path named in ssh's "Enter passphrase for ..." prompt text.
  private var keyPath: String? {
    guard prompt.kind == .ssh, var text = prompt.prompt else { return nil }
    guard let range = text.range(of: "Enter passphrase for ", options: .caseInsensitive) else {
      return nil
    }
    text = String(text[range.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
    if let suffix = text.range(of: " (will confirm each use)") {
      text = String(text[..<suffix.lowerBound])
    }
    if text.hasSuffix(":") { text.removeLast() }
    if text.hasPrefix("key ") { text.removeFirst(4) }
    text = text.trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
    return text.hasPrefix("/") ? text : nil
  }

  /// Labeled values shown when the card is expanded.
  private var rows: [PromptDetailRow] {
    var rows: [PromptDetailRow] = []
    if prompt.kind == .gpg, let description {
      rows.append(PromptDetailRow(label: "Details", value: description))
    }
    if let keyPath {
      rows.append(PromptDetailRow(label: "Path", value: keyPath))
    }
    if let keyId {
      rows.append(PromptDetailRow(label: keyIdLabel, value: keyId))
    }
    return rows
  }

  var body: some View {
    if keyId != nil || description != nil {
      PromptSubjectCard(
        systemImage: "key.fill",
        title: label ?? kindName,
        detail: subtitle.isEmpty ? nil : subtitle,
        rows: rows)
    }
  }
}

/// A terminal-styled snippet of the request that triggered this prompt: the
/// key grip or fingerprint, any rejected-passphrase error, and the prompt
/// text gpg (or ssh) itself asked for.
private struct PinentryTranscript: View {
  let prompt: PassphrasePrompt

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      ScrollView(.horizontal, showsIndicators: true) {
        content
      }

      Divider()
        .padding(.vertical, 4)

      Text(prompt.prompt ?? "Passphrase")
        .font(monoFont)
        .lineSpacing(4)
        .foregroundStyle(.primary)
        .fixedSize(horizontal: false, vertical: true)
    }
    .padding(14)
    .textSelection(.enabled)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(
      RoundedRectangle(cornerRadius: 10, style: .continuous)
        .fill(.quaternary.opacity(0.5))
    )
  }

  private var content: some View {
    VStack(alignment: .leading, spacing: 6) {
      switch prompt.kind {
      case .gpg:
        line(label: "#", text: "gpg", labelColor: .secondary, textColor: .secondary)
      case .ssh:
        line(label: "#", text: "ssh", labelColor: .secondary, textColor: .secondary)
      case .age, .ageList:
        line(label: "#", text: "age", labelColor: .secondary, textColor: .secondary)
      case .keychainList:
        line(label: "#", text: "keychain", labelColor: .secondary, textColor: .secondary)
      }

      if let errorMessage = prompt.errorMessage, !errorMessage.isEmpty {
        line(
          label: "ERROR", text: errorMessage.trimmingCharacters(in: .whitespacesAndNewlines),
          labelColor: .red, textColor: .red)
      }
    }
    .fixedSize(horizontal: true, vertical: false)
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
  let okLabel: String
  /// Nil for a message, which has only the OK button.
  let cancelLabel: String?
  let onConfirm: () -> Void
  let onCancel: () -> Void

  private static let warningPrefix = "Warning: "

  var body: some View {
    VStack(spacing: 14) {
      Image(systemName: symbol)
        .font(.system(size: 36))
        .foregroundStyle(isWarning ? AnyShapeStyle(.yellow) : AnyShapeStyle(.secondary))
        .frame(width: 64, height: 64)

      PromptHeadline(parts: headlineParts)
        .fixedSize(horizontal: false, vertical: true)

      if let detail {
        Text(detail)
          .foregroundStyle(.secondary)
          .lineSpacing(3)
          .fixedSize(horizontal: false, vertical: true)
          .padding(12)
          .promptCard()
      }

      HStack {
        if let cancelLabel {
          Button(cancelLabel, action: onCancel)
            .keyboardShortcut(.cancelAction)
        }
        Spacer()
        Button(okLabel, action: onConfirm)
          .keyboardShortcut(.defaultAction)
      }
      .padding(.top, 4)
    }
    .padding(24)
    .frame(maxWidth: .infinity)
  }

  /// gpg's text split on blank lines. The first paragraph is the headline.
  private var paragraphs: [String] {
    let text = description?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return text.components(separatedBy: "\n\n")
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
      .filter { !$0.isEmpty }
  }

  private var isWarning: Bool {
    paragraphs.first?.hasPrefix(Self.warningPrefix) ?? false
  }

  private var symbol: String {
    if isWarning { return "exclamationmark.triangle.fill" }
    return cancelLabel == nil ? "info.circle" : "questionmark.circle"
  }

  /// The icon marks a warning, so the headline drops gpg's "Warning: " prefix.
  private var headline: String {
    guard let first = paragraphs.first else {
      return cancelLabel == nil ? "Message from GPG" : "GPG needs your answer"
    }
    return isWarning ? String(first.dropFirst(Self.warningPrefix.count)) : first
  }

  /// The headline with `**bold**` runs split out.
  private var headlineParts: [HeadlinePart] {
    headline.components(separatedBy: "**").enumerated().compactMap { index, text in
      guard !text.isEmpty else { return nil }
      return index % 2 == 1 ? .bold(text) : .plain(text)
    }
  }

  private var detail: String? {
    let rest = paragraphs.dropFirst()
    return rest.isEmpty ? nil : rest.joined(separator: "\n\n")
  }
}

/// Bridges the core's delegate calls, which arrive off the main thread, onto
/// the main-actor model.
final class PassphrasePromptBridge: PassphrasePromptDelegate {
  private let model: PassphrasePromptModel

  init(model: PassphrasePromptModel) {
    self.model = model
  }

  func beginAuthorization(prompt: PassphrasePrompt, peer: RequestActor) async throws -> UInt64 {
    await model.begin(prompt: prompt, peer: peer)
  }

  func collectPassphrase(prompt: PassphrasePrompt, canUseSaved: Bool) async throws
    -> CollectedPassphrase?
  {
    await model.collect(prompt: prompt, canUseSaved: canUseSaved)
  }

  func takeTypedPassphraseRequest() async -> Bool {
    await model.takeTypedPassphraseRequest()
  }

  func endAuthorization(prompt: PassphrasePrompt, outcome: PromptOutcome) async {
    await model.end(prompt: prompt, outcome: outcome)
  }

  func confirm(prompt: ConfirmPrompt) async -> Bool {
    await model.confirm(prompt: prompt)
  }

  func message(description: String?) async {
    await model.message(description: description)
  }
}
