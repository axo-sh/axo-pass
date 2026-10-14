import AppKit
import AxoPassFFI
import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// Draws the authorization prompt for `ap item list`, `ap item get`, `ap read`,
/// and `ap item set`, which the core's broker delegates here.
///
/// `ap` has no keychain entitlements, so the broker calls in here for a context
/// to unlock the vault on.
///
/// This model authenticates an `LAContext` itself, as the lock screen does,
/// and passes it to the core. `LAAuthenticationView` draws in our panel only
/// when this process runs the evaluation while the view is mounted. An
/// evaluation started by the core appears in the system dialog instead. The
/// core reads the vault key using the context it receives and does not
/// authenticate again, so one request raises one prompt.
///
/// Reads prompt every time. The grant lives for one request and is then dropped.
///
/// Listing does not read secret values, so its approval is reused within the
/// standard window. Grants are keyed on the action and the vault, so a listing's
/// approval never satisfies a read.
@MainActor
final class VaultUnlockPromptModel {
  private let grants = AuthorizationGrants(label: "VaultUnlockPrompt", controlSize: .small)
  private var showTask: Task<Void, Never>?

  /// The prompt `begin` is serving, while it waits on the user. The broker
  /// serves one request at a time, so there is at most one.
  private var beginning: VaultAccessPrompt?

  /// Where the user is choosing to store the passkey a registration prompt is
  /// for. Set while that prompt is up, and kept until it ends so the broker can
  /// read the answer after the evaluation returns.
  private var placement: PasskeyPlacementState?

  /// Resumes the broker when the user picks the account of a passkey sign-in.
  /// Set while the account list is on screen.
  private var accountChoice: CheckedContinuation<UInt32?, Never>?

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
    beginning = prompt
    defer { beginning = nil }

    if case .createPasskey(_, _, let choices) = prompt.action {
      placement = PasskeyPlacementState(choices: choices)
    } else {
      placement = nil
    }

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

  /// The vault and item the user chose for a passkey, read once the evaluation
  /// has returned. `nil` when the prompt is not a registration.
  func passkeyPlacement() -> PasskeyPlacementInfo? {
    placement?.answer
  }

  /// Show the passkeys of a sign-in and wait for the user to pick one. Called
  /// after the evaluation returned, so the vaults are already unlocked. Returns
  /// an index into `accounts`, or `nil` if the user cancelled.
  func choosePasskey(prompt: VaultAccessPrompt, accounts: [PasskeyAccountInfo]) async -> UInt32? {
    guard case .assertPasskey(let rpId, _) = prompt.action else { return nil }
    finishAccountChoice(nil)
    return await withCheckedContinuation { (continuation: CheckedContinuation<UInt32?, Never>) in
      accountChoice = continuation
      panel.show(
        PasskeyAccountChoiceView(
          rpId: rpId,
          callerChain: prompt.callerChain,
          appBundleId: VaultUnlockView.connectionBundleId(caller: prompt.caller, appRequester: nil),
          accounts: accounts,
          onChoose: { [weak self] index in self?.finishAccountChoice(UInt32(index)) },
          onCancel: { [weak self] in self?.finishAccountChoice(nil) }))
    }
  }

  private func finishAccountChoice(_ index: UInt32?) {
    let continuation = accountChoice
    accountChoice = nil
    continuation?.resume(returning: index)
  }

  /// The access finished, successfully or not.
  func end(prompt: VaultAccessPrompt, outcome: PromptOutcome) {
    // The broker stops waiting on a client that disconnects mid-choice.
    finishAccountChoice(nil)
    placement = nil
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

  /// The requesting process disconnected. Dismiss the prompt `begin` is waiting
  /// on, so it returns. Does nothing when `begin` has already returned, or has
  /// not started yet.
  func abandon() {
    guard let beginning else { return }
    cancel(prompt: beginning)
  }

  /// Drop every vault authorization, so the next request prompts again. Called
  /// when the app locks, and when the machine sleeps or the screen locks.
  func forgetAll() {
    grants.forgetAll()
  }

  // MARK: - Panel

  private func showPanel(prompt: VaultAccessPrompt, view: LAAuthenticationView) {
    let content = VaultUnlockView(
      // A registration picks its vault in the placement card instead.
      vaultKey: placement == nil ? prompt.vaultKey : "",
      placement: placement,
      caller: prompt.caller,
      callerChain: prompt.callerChain,
      appRequester: Self.appRequester(for: prompt.action),
      headline: Self.headline(for: prompt.action),
      login: Self.login(for: prompt.action),
      secrets: Self.secrets(for: prompt),
      notes: Self.notes(for: prompt.action),
      icon: AuthenticationIcon(view: view),
      touchID: PromptCaller.hasTouchID(),
      onCancel: { [weak self] in self?.cancel(prompt: prompt) }
    )
    panel.show(content)
  }

  /// List of the requested secrets, as `item/credential`. These are shown when the
  /// user expands the vault card. A secret in another vault is prefixed with
  /// that vault's key. Empty for actions that do not involve specific secrets.
  private static func secrets(for prompt: VaultAccessPrompt) -> [String] {
    switch prompt.action {
    case .readSecret(let itemKey, let credentialKey),
      .writeSecret(let itemKey, let credentialKey):
      return ["\(itemKey)/\(credentialKey)"]
    case .resolveSecrets(_, let refs):
      return refs.map { ref in
        let path = "\(ref.itemKey)/\(ref.credentialKey)"
        return ref.vaultKey == prompt.vaultKey ? path : "\(ref.vaultKey)/\(path)"
      }
    case .listItems, .listLogins, .fillLogin, .generateTotp, .saveLogin, .updateLoginPassword,
      .exportVaults, .importVaults, .addVault, .createPasskey, .assertPasskey:
      return []
    }
  }

  /// The app a login request is for, when the AutoFill extension named one.
  private static func appRequester(for action: VaultAction) -> String? {
    switch action {
    case .listLogins(let page, _), .fillLogin(let page, _, _, _), .generateTotp(let page, _):
      return page.requester
    default:
      return nil
    }
  }

  /// The account a request will use, shown in its own card instead of the headline.
  private static func login(for action: VaultAction) -> String? {
    switch action {
    case .fillLogin(_, _, let account, _), .updateLoginPassword(_, _, let account): return account
    case .saveLogin(_, let username): return username
    case .createPasskey(_, let userName, _): return userName.isEmpty ? nil : userName
    case .assertPasskey(_, let userName): return userName
    default: return nil
    }
  }

  /// Facts about the page that the user should see before approving a fill or a
  /// save. A listing has none, since it returns no secret.
  private static func notes(for action: VaultAction) -> [String] {
    switch action {
    case .fillLogin(let page, _, _, _), .generateTotp(let page, _), .saveLogin(let page, _),
      .updateLoginPassword(let page, _, _):
      var notes: [String] = []
      if !page.secure {
        notes.append("This page is not secure (http). Anyone on the network can read the password.")
      }
      if let top = page.topHost {
        notes.append("The form is in a frame on \(page.host), inside a page on \(top).")
      }
      return notes
    default:
      return []
    }
  }

  /// The localized reason `LocalAuthentication` shows in its own chrome.
  private static func reason(for prompt: VaultAccessPrompt) -> String {
    let what: String
    switch prompt.action {
    case .readSecret:
      what = "read a secret from vault \(prompt.vaultKey)"
    case .resolveSecrets(let purpose, let refs):
      let verb = purpose == .read ? "read" : "resolve"
      let count = refs.count
      what = "\(verb) \(count) \(count == 1 ? "secret" : "secrets") from vault \(prompt.vaultKey)"
    case .listItems:
      what = "list items in vault \(prompt.vaultKey)"
    case .listLogins(let page, _):
      what = "find logins for \(page.host)"
    case .fillLogin(let page, _, let account, _):
      what = "fill \(account ?? "a login") on \(page.host)"
    case .generateTotp(let page, _):
      what = "get a one-time code for \(page.host)"
    case .saveLogin(let page, let username):
      what = "save \(username ?? "a login") for \(page.host)"
    case .updateLoginPassword(let page, _, let account):
      what = "update the password of \(account ?? "a login") from \(page.host)"
    case .writeSecret(let itemKey, let credentialKey):
      what = "write \(itemKey)/\(credentialKey) in vault \(prompt.vaultKey)"
    case .exportVaults(let count):
      what = "export \(count) \(count == 1 ? "vault" : "vaults") to \(prompt.vaultKey)"
    case .importVaults(let count):
      what = "import \(count) \(count == 1 ? "vault" : "vaults") from \(prompt.vaultKey)"
    case .addVault(let path):
      what = "add the vault at \(path)"
    case .createPasskey(let rpId, _, _):
      what = "create a passkey for \(rpId)"
    case .assertPasskey(let rpId, let userName):
      what = userName.map { "sign in to \(rpId) as \($0)" } ?? "sign in to \(rpId) with a passkey"
    }
    if let caller = prompt.caller, !caller.isEmpty {
      return "let \(caller) \(what)"
    }
    return what
  }

  /// True for the accesses that expose or change secret values and so prompt on
  /// every request. A listing does not.
  private static func promptsEveryTime(_ action: VaultAction) -> Bool {
    switch action {
    case .readSecret, .resolveSecrets, .writeSecret, .exportVaults, .importVaults, .addVault,
      .createPasskey, .assertPasskey, .fillLogin, .generateTotp, .saveLogin, .updateLoginPassword:
      return true
    case .listItems, .listLogins: return false
    }
  }

  /// One grant per action, subject, and requesting process. Approving one
  /// caller's request does not authorize another's inside the reuse window, and
  /// approving a listing does not authorize a read.
  ///
  /// A login request is keyed on the record, so approving one login never
  /// approves another, and on the page's registrable domain, so approving a
  /// fill on one site never approves it on another.
  private static func grantKey(_ prompt: VaultAccessPrompt) -> GrantKey {
    let id: String
    switch prompt.action {
    case .fillLogin(_, let recordId, _, _), .generateTotp(_, let recordId),
      .updateLoginPassword(_, let recordId, _):
      id = recordId
    case .listLogins: id = "logins"
    // The vault key changes before the prompt ends, so it cannot name the
    // grant. A registration takes the user's choice, and a sign-in takes the
    // vault that signed.
    case .createPasskey, .assertPasskey: id = "passkey"
    default: id = prompt.vaultKey
    }
    let subject = GrantSubject(kind: .vault, id: id, label: nil)
    return GrantKey(
      subject: subject, caller: prompt.caller, callerIdentity: prompt.callerIdentity,
      scope: scope(for: prompt.action))
  }

  private static func scope(for action: VaultAction) -> String {
    switch action {
    case .readSecret: return "read"
    case .resolveSecrets: return "resolve"
    case .listItems: return "list"
    case .listLogins(let page, _): return "list-logins:\(page.domain)"
    case .fillLogin(let page, _, _, _): return "fill:\(page.domain)"
    case .generateTotp(let page, _): return "totp:\(page.domain)"
    case .saveLogin(let page, _): return "save:\(page.domain)"
    case .updateLoginPassword(let page, _, _): return "update:\(page.domain)"
    case .writeSecret: return "write"
    case .exportVaults: return "export"
    case .importVaults: return "import"
    case .addVault: return "add"
    case .createPasskey: return "passkey-create"
    case .assertPasskey: return "passkey-assert"
    }
  }

  /// Reading or resolving a secret prompts every time. Listing exposes no
  /// values, so its approval is reused for the standard window.
  private static func policy(for action: VaultAction) -> GrantPolicy {
    promptsEveryTime(action) ? .everyUse : .standard
  }

  private static func headline(for action: VaultAction) -> [HeadlinePart] {
    switch action {
    case .readSecret: return [.plain("read a secret")]
    case .resolveSecrets(let purpose, let refs):
      let verb = purpose == .read ? "read" : "resolve"
      let count = refs.count
      return [.plain("\(verb) \(count) \(count == 1 ? "secret" : "secrets")")]
    case .listItems: return [.plain("list a vault")]
    case .listLogins(let page, let all):
      return all
        ? [.plain("list logins, starting with those for "), .bold(page.host)]
        : [.plain("find logins for "), .bold(page.host)]
    case .fillLogin(let page, _, _, _):
      return [.plain("fill a login on "), .bold(page.host)]
    case .generateTotp(let page, _):
      return [.plain("get a one-time code for "), .bold(page.host)]
    case .saveLogin(let page, _):
      return [.plain("save a login for "), .bold(page.host)]
    case .updateLoginPassword(let page, _, _):
      return [.plain("update a password from "), .bold(page.host)]
    case .writeSecret: return [.plain("write a secret")]
    case .exportVaults(let count):
      return [.plain("export \(count) \(count == 1 ? "vault" : "vaults")")]
    case .importVaults(let count):
      return [.plain("import \(count) \(count == 1 ? "vault" : "vaults")")]
    case .addVault: return [.plain("add a vault")]
    case .createPasskey(let rpId, _, _): return [.plain("create a passkey for "), .bold(rpId)]
    case .assertPasskey(let rpId, _): return [.plain("sign in to "), .bold(rpId)]
    }
  }
}

/// The choices in a passkey registration prompt: which vault, and which login
/// in it. Defaults come from the broker, which suggests the login whose
/// username matches the account.
@MainActor
@Observable
final class PasskeyPlacementState {
  let vaults: [VaultInfo]
  let logins: [PasskeyLoginChoice]
  private let suggested: PasskeyLoginChoice?

  private(set) var vaultKey: String
  /// The chosen login's item key. `nil` means "New login".
  var itemKey: String?

  init(choices: PasskeyChoicesInfo) {
    vaults = choices.vaults
    logins = choices.logins
    suggested = choices.suggested.flatMap { index in
      Int(index) < choices.logins.count ? choices.logins[Int(index)] : nil
    }
    vaultKey = choices.defaultVault
    itemKey = suggested?.itemKey
  }

  /// The logins of the chosen vault whose websites match the relying party.
  var loginsInVault: [PasskeyLoginChoice] {
    logins.filter { $0.vaultKey == vaultKey }
  }

  /// Switch vaults. The login selection moves with it: the suggested login when
  /// it is in the new vault, otherwise "New login".
  func selectVault(_ key: String) {
    guard key != vaultKey else { return }
    vaultKey = key
    itemKey = suggested.flatMap { $0.vaultKey == key ? $0.itemKey : nil }
  }

  var answer: PasskeyPlacementInfo {
    PasskeyPlacementInfo(vaultKey: vaultKey, itemKey: itemKey)
  }
}

private struct PasskeyPlacementCard: View {
  @Bindable var state: PasskeyPlacementState

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      if state.vaults.count > 1 {
        Picker(
          "Vault",
          selection: Binding(get: { state.vaultKey }, set: { state.selectVault($0) })
        ) {
          ForEach(state.vaults, id: \.key) { vault in
            Text(vault.name ?? vault.key).tag(vault.key)
          }
        }
      } else {
        LabeledContent(
          "Vault", value: state.vaults.first.map { $0.name ?? $0.key } ?? state.vaultKey)
      }

      Picker("Save to", selection: $state.itemKey) {
        Text("New login").tag(String?.none)
        ForEach(state.loginsInVault, id: \.itemKey) { login in
          Text(Self.label(login)).tag(String?.some(login.itemKey))
        }
      }
    }
    .padding(12)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
  }

  private static func label(_ login: PasskeyLoginChoice) -> String {
    guard let username = login.username, !username.isEmpty else { return login.title }
    return "\(login.title) (\(username))"
  }
}

/// Account list of a passkey sign-in, shown after the vaults unlock. The vault
/// is named only if the passkeys span more than one.
private struct PasskeyAccountChoiceView: View {
  let rpId: String
  let callerChain: [ProcessNode]
  let appBundleId: String?
  let accounts: [PasskeyAccountInfo]
  let onChoose: (Int) -> Void
  let onCancel: () -> Void

  var body: some View {
    VStack(spacing: 14) {
      PromptConnection(
        callerChain: callerChain, fallbackSystemImage: "lock.fill", appBundleId: appBundleId)

      PromptHeadline(.plain("Choose an account for "), .bold(rpId))

      VStack(spacing: 8) {
        ForEach(Array(accounts.enumerated()), id: \.offset) { index, account in
          Button {
            onChoose(index)
          } label: {
            PromptSubjectCard(
              systemImage: "person.badge.key.fill", title: account.userName,
              detail: spansVaults ? account.vaultKey : nil
            )
            .contentShape(Rectangle())
          }
          .buttonStyle(.plain)
        }
      }

      HStack {
        Spacer()
        Button("Cancel", action: onCancel)
          .keyboardShortcut(.cancelAction)
      }
    }
    .padding(24)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private var spansVaults: Bool {
    Set(accounts.map(\.vaultKey)).count > 1
  }
}

private struct VaultUnlockView: View {
  let vaultKey: String
  /// Set for a passkey registration, which asks where to store the passkey.
  let placement: PasskeyPlacementState?
  let caller: String?
  let callerChain: [ProcessNode]
  /// The app an AutoFill request is for. `nil` means a browser.
  let appRequester: String?
  let headline: [HeadlinePart]
  let login: String?
  let secrets: [String]
  let notes: [String]
  let icon: AuthenticationIcon
  let touchID: Bool
  let onCancel: () -> Void

  var body: some View {
    VStack(spacing: 14) {
      PromptConnection(
        callerChain: callerChain, fallbackSystemImage: "lock.fill",
        appBundleId: Self.connectionBundleId(caller: caller, appRequester: appRequester))

      PromptHeadline(parts: title)

      ForEach(notes, id: \.self) { note in
        Label(note, systemImage: "exclamationmark.triangle")
          .font(.callout)
          .foregroundStyle(.orange)
          .multilineTextAlignment(.leading)
      }

      VStack(spacing: 8) {
        if let login {
          PromptSubjectCard(systemImage: "person.fill", title: login, detail: nil)
        }
        if let placement {
          PasskeyPlacementCard(state: placement)
        }
        // An AutoFill request spans every vault, so it carries no vault key.
        if !vaultKey.isEmpty {
          PromptSubjectCard(
            systemImage: "lock.fill", title: vaultKey, detail: nil, items: secrets)
        }
        if !isAutofillExtensionChain {
          CallerChainView(
            chain: callerChain,
            summary: isAutofill
              ? (requester ?? "Safari") : PromptCaller.requesterName(chain: callerChain))
        }
      }

      BiometricFooter(icon: icon, touchID: touchID, onCancel: onCancel)
    }
    .padding(24)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private static let safariBundleId = "com.apple.Safari"

  /// App shown in the connection header in place of the caller chain. An
  /// AutoFill request from a browser is shown as coming from Safari.
  static func connectionBundleId(caller: String?, appRequester: String?) -> String? {
    isAutofill(caller: caller) && appRequester == nil ? safariBundleId : nil
  }

  /// The core names the AutoFill extension as the caller. The extension reports
  /// the app that asked when the system identifies one, and a browser request
  /// is shown as coming from Safari.
  private static func isAutofill(caller: String?) -> Bool { caller == "AutoFill extension" }

  private var isAutofill: Bool { Self.isAutofill(caller: caller) }

  /// Whether the innermost process is the AutoFill extension. The prompt is
  /// clearly an AutoFill request, so the chain card would only repeat it.
  private var isAutofillExtensionChain: Bool {
    PromptCaller.requesterName(chain: callerChain) == "AxoPassAutoFill"
  }

  private var requester: String? {
    guard isAutofill else { return PromptCaller.appName(caller: caller, chain: callerChain) }
    return appRequester ?? "Safari"
  }

  private var title: [HeadlinePart] {
    if let who = requester {
      return [.bold(who), .plain(" wants to ")] + headline
    }
    guard case .plain(let first)? = headline.first else { return headline }
    let capitalized = first.prefix(1).uppercased() + first.dropFirst()
    return [.plain("Authorize: \(capitalized)")] + headline.dropFirst()
  }
}

/// Bridges the core's delegate calls, which arrive off the main thread, onto
/// the main-actor model.
final class VaultUnlockPromptBridge: VaultPromptDelegate {
  private let model: VaultUnlockPromptModel

  /// Called when a broker request writes to one or more vaults. An empty list
  /// means the written vault could not be named. `VaultsModel` passes this in
  /// to drop its item cache and re-index AutoFill.
  private let onVaultsChanged: (@Sendable ([String]) async -> Void)?

  init(
    model: VaultUnlockPromptModel,
    onVaultsChanged: (@Sendable ([String]) async -> Void)? = nil
  ) {
    self.model = model
    self.onVaultsChanged = onVaultsChanged
  }

  func beginAuthorization(prompt: VaultAccessPrompt, peer: RequestActor) async throws -> UInt64 {
    await model.begin(prompt: prompt, peer: peer)
  }

  func abandonAuthorization() async {
    await model.abandon()
  }

  func passkeyPlacement(prompt: VaultAccessPrompt) async -> PasskeyPlacementInfo? {
    await model.passkeyPlacement()
  }

  func choosePasskey(prompt: VaultAccessPrompt, accounts: [PasskeyAccountInfo]) async -> UInt32? {
    await model.choosePasskey(prompt: prompt, accounts: accounts)
  }

  func endAuthorization(prompt: VaultAccessPrompt, outcome: PromptOutcome) async {
    await model.end(prompt: prompt, outcome: outcome)
  }

  func vaultsChanged(vaultKeys: [String]) async {
    await onVaultsChanged?(vaultKeys)
  }
}
