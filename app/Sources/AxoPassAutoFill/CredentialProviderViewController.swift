import AppKit
import AuthenticationServices
import CryptoKit
import SwiftUI

/// The AutoFill credential provider.
///
/// The extension is sandboxed and holds no keychain entitlements, so it never
/// touches the vault itself. Every request goes to the app's broker over a
/// Mach service named under the App Group; the app raises the Touch ID prompt,
/// unlocks the vault on its own context, and records the audit event.
///
/// That means there is no silent fill: the vault is locked behind an
/// authentication the app owns, so `provideCredentialWithoutUserInteraction`
/// always reports that interaction is required.
@objc(CredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController {
  private var hosting: NSHostingView<CredentialListView>?
  private let model = CredentialListModel()

  override func viewDidLoad() {
    super.viewDidLoad()
    model.onSelect = { [weak self] item in self?.fill(item) }
    model.onCancel = { [weak self] in self?.cancel(.userCanceled) }
    model.onOpenApp = { [weak self] in self?.openHostApp() }

    let hosting = NSHostingView(rootView: CredentialListView(model: model))
    hosting.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(hosting)
    NSLayoutConstraint.activate([
      hosting.leadingAnchor.constraint(equalTo: view.leadingAnchor),
      hosting.trailingAnchor.constraint(equalTo: view.trailingAnchor),
      hosting.topAnchor.constraint(equalTo: view.topAnchor),
      hosting.bottomAnchor.constraint(equalTo: view.bottomAnchor),
    ])
    self.hosting = hosting
  }

  override func loadView() {
    view = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: 420))
  }

  // MARK: - Credential list

  override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
    loadList(for: serviceIdentifiers, purpose: .password)
  }

  /// A one-time code field. The list is the logins for the site that have a
  /// code.
  override func prepareOneTimeCodeCredentialList(
    for serviceIdentifiers: [ASCredentialServiceIdentifier]
  ) {
    loadList(for: serviceIdentifiers, purpose: .oneTimeCode)
  }

  private func loadList(
    for serviceIdentifiers: [ASCredentialServiceIdentifier], purpose: CredentialListModel.Purpose
  ) {
    // An app identifier is not a site, so it only names the requester. The
    // site to match comes from the first domain or URL identifier. App
    // identifiers exist from macOS 26.2.
    if #available(macOS 26.2, *) {
      let app = serviceIdentifiers.first { $0.type == .app }
      let site = serviceIdentifiers.first { $0.type != .app } ?? serviceIdentifiers.first
      model.load(
        service: site?.identifier, requester: app.map { $0.displayName ?? $0.identifier },
        purpose: purpose)
    } else {
      model.load(service: serviceIdentifiers.first?.identifier, purpose: purpose)
    }
  }

  /// A passkey sign-in where the user picked Axo Pass rather than one of our
  /// registered identities. The broker asserts with any stored passkey for the
  /// relying party that `allowedCredentials` permits. With several accounts on
  /// one site and no allow list, the authenticator picks one.
  override func prepareCredentialList(
    for serviceIdentifiers: [ASCredentialServiceIdentifier],
    requestParameters: ASPasskeyCredentialRequestParameters
  ) {
    guard BrokerClient.isAvailable else {
      model.report(BrokerError.unavailable)
      return
    }
    let rpID = requestParameters.relyingPartyIdentifier
    let clientDataHash = requestParameters.clientDataHash
    let prf = Self.prfInput(requestParameters.extensionInput?.prf)
    model.beginFilling(rpID)
    Task { [weak self] in
      do {
        let assertion = try await BrokerClient.assertPasskey(
          rpID: rpID,
          clientDataHash: clientDataHash,
          allowedCredentialIDs: requestParameters.allowedCredentials,
          prf: prf)
        self?.completeAssertion(
          rpID: rpID, clientDataHash: clientDataHash, assertion: assertion)
      } catch {
        self?.model.report(error)
      }
    }
  }

  // MARK: - Filling

  override func provideCredentialWithoutUserInteraction(for request: any ASCredentialRequest) {
    // The vault is locked behind an authentication the app owns, so there is
    // never a credential we can hand over without showing our UI first.
    cancel(.userInteractionRequired)
  }

  override func prepareInterfaceToProvideCredential(for request: any ASCredentialRequest) {
    if let passkeyRequest = request as? ASPasskeyCredentialRequest,
      let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
    {
      provideAssertion(passkeyRequest, identity: identity)
      return
    }

    if let identity = request.credentialIdentity as? ASOneTimeCodeCredentialIdentity {
      guard let recordID = identity.recordIdentifier, !recordID.isEmpty,
        !identity.serviceIdentifier.identifier.isEmpty
      else {
        cancel(.credentialIdentityNotFound)
        return
      }
      model.fillDirectly(
        recordID: recordID, service: identity.serviceIdentifier.identifier, user: identity.label,
        purpose: .oneTimeCode)
      return
    }

    guard let identity = request.credentialIdentity as? ASPasswordCredentialIdentity,
      let recordID = identity.recordIdentifier, !recordID.isEmpty,
      !identity.serviceIdentifier.identifier.isEmpty
    else {
      cancel(.credentialIdentityNotFound)
      return
    }
    model.fillDirectly(
      recordID: recordID, service: identity.serviceIdentifier.identifier, user: identity.user,
      purpose: .password)
  }

  // MARK: - Passkeys

  override func prepareInterface(
    forPasskeyRegistration registrationRequest: any ASCredentialRequest
  ) {
    guard let request = registrationRequest as? ASPasskeyCredentialRequest,
      let identity = registrationRequest.credentialIdentity as? ASPasskeyCredentialIdentity
    else {
      cancel(.failed)
      return
    }
    guard BrokerClient.isAvailable else {
      model.report(BrokerError.unavailable)
      return
    }

    let name = identity.userName.isEmpty ? identity.relyingPartyIdentifier : identity.userName
    var prf: BrokerClient.PRFRegistrationInput?
    if case .registration(let input) = request.extensionInput, let input = input.prf {
      prf = BrokerClient.PRFRegistrationInput(values: input.inputValues.map(Self.prfValues))
    }
    model.beginFilling(name)
    Task { [weak self] in
      do {
        let registration = try await BrokerClient.registerPasskey(
          rpID: identity.relyingPartyIdentifier,
          rpName: nil,
          userHandle: identity.userHandle,
          userName: identity.userName,
          userDisplayName: identity.userName,
          clientDataHash: request.clientDataHash,
          algorithms: request.supportedAlgorithms.map(\.rawValue),
          excludedCredentials: (request.excludedCredentials ?? []).map(\.credentialID),
          prf: prf)
        self?.completeRegistration(
          rpID: identity.relyingPartyIdentifier,
          clientDataHash: request.clientDataHash,
          registration: registration)
      } catch {
        self?.model.report(error)
      }
    }
  }

  private func provideAssertion(
    _ request: ASPasskeyCredentialRequest, identity: ASPasskeyCredentialIdentity
  ) {
    guard BrokerClient.isAvailable else {
      model.report(BrokerError.unavailable)
      return
    }
    let name = identity.userName.isEmpty ? identity.relyingPartyIdentifier : identity.userName
    var prf: BrokerClient.PRFAssertionInput?
    if case .assertion(let input) = request.extensionInput {
      prf = Self.prfInput(input.prf)
    }
    model.beginFilling(name)
    Task { [weak self] in
      do {
        let assertion = try await BrokerClient.assertPasskey(
          rpID: identity.relyingPartyIdentifier,
          clientDataHash: request.clientDataHash,
          allowedCredentialIDs: [identity.credentialID],
          prf: prf)
        self?.completeAssertion(
          rpID: identity.relyingPartyIdentifier,
          clientDataHash: request.clientDataHash,
          assertion: assertion)
      } catch {
        self?.model.report(error)
      }
    }
  }

  private func completeRegistration(
    rpID: String, clientDataHash: Data, registration: BrokerClient.Registration
  ) {
    var extensionOutput: ASPasskeyRegistrationCredentialExtensionOutput?
    if let prf = registration.prf {
      let output: ASAuthorizationPublicKeyCredentialPRFRegistrationOutput
      if let results = prf.results {
        output = ASAuthorizationPublicKeyCredentialPRFRegistrationOutput(
          first: SymmetricKey(data: results.first),
          second: results.second.map { SymmetricKey(data: $0) })
      } else {
        output = prf.enabled ? .supported : .unsupported
      }
      extensionOutput = ASPasskeyRegistrationCredentialExtensionOutput(prf: output)
    }
    let credential = ASPasskeyRegistrationCredential(
      relyingParty: rpID,
      clientDataHash: clientDataHash,
      credentialID: registration.credentialID,
      attestationObject: registration.attestationObject,
      extensionOutput: extensionOutput)
    extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
  }

  private func completeAssertion(
    rpID: String, clientDataHash: Data, assertion: BrokerClient.Assertion
  ) {
    let extensionOutput = assertion.prf.map { prf in
      ASPasskeyAssertionCredentialExtensionOutput(
        prf: ASAuthorizationPublicKeyCredentialPRFAssertionOutput(
          first: SymmetricKey(data: prf.first),
          second: prf.second.map { SymmetricKey(data: $0) }))
    }
    let credential = ASPasskeyAssertionCredential(
      userHandle: assertion.userHandle,
      relyingParty: rpID,
      signature: assertion.signature,
      clientDataHash: clientDataHash,
      authenticatorData: assertion.authenticatorData,
      credentialID: assertion.credentialID,
      extensionOutput: extensionOutput)
    extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
  }

  // MARK: - PRF

  // The system passes PRF inputs as the page gave them, unhashed. The app
  // applies the WebAuthn PRF hash.

  private static func prfValues(
    _ values: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues
  ) -> BrokerClient.PRFValues {
    BrokerClient.PRFValues(first: values.saltInput1, second: values.saltInput2)
  }

  private static func prfInput(
    _ input: ASAuthorizationPublicKeyCredentialPRFAssertionInput?
  ) -> BrokerClient.PRFAssertionInput? {
    guard let input else { return nil }
    return BrokerClient.PRFAssertionInput(
      values: input.inputValues.map(prfValues),
      perCredential: (input.perCredentialInputValues ?? [:]).mapValues(prfValues))
  }

  // MARK: - Site reports

  // Sites report through the system with the vault locked. The app records
  // each report, marks the passkey, and leaves it in the vault. A rejected
  // passkey is also removed from the identity store here, so it is not offered
  // before the app next re-registers identities.

  override func reportUnknownPublicKeyCredential(
    forRelyingParty relyingParty: String, credentialID: Data
  ) {
    Task {
      do {
        try await BrokerClient.reportUnknownPasskey(rpID: relyingParty, credentialID: credentialID)
      } catch {
        NSLog("AxoPassAutoFill: failed to relay a passkey report: %@", "\(error)")
      }
      await Self.removeIdentities(relyingParty: relyingParty) { $0.credentialID == credentialID }
    }
  }

  override func reportAllAcceptedPublicKeyCredentials(
    forRelyingParty relyingParty: String, userHandle: Data, acceptedCredentialIDs: [Data]
  ) {
    Task {
      do {
        try await BrokerClient.reportAcceptedPasskeys(
          rpID: relyingParty, userHandle: userHandle, credentialIDs: acceptedCredentialIDs)
      } catch {
        NSLog("AxoPassAutoFill: failed to relay a passkey report: %@", "\(error)")
      }
      await Self.removeIdentities(relyingParty: relyingParty) {
        $0.userHandle == userHandle && !acceptedCredentialIDs.contains($0.credentialID)
      }
    }
  }

  override func reportPublicKeyCredentialUpdate(
    forRelyingParty relyingParty: String, userHandle: Data, newName: String
  ) {
    Task {
      do {
        try await BrokerClient.reportPasskeyName(
          rpID: relyingParty, userHandle: userHandle, name: newName)
      } catch {
        NSLog("AxoPassAutoFill: failed to relay a passkey report: %@", "\(error)")
      }
    }
  }

  /// Remove the passkey identities of `relyingParty` that match `shouldRemove`
  /// from the system's identity store.
  private static func removeIdentities(
    relyingParty: String, where shouldRemove: (ASPasskeyCredentialIdentity) -> Bool
  ) async {
    let store = ASCredentialIdentityStore.shared
    let identities = await store.credentialIdentities(
      forService: nil, credentialIdentityTypes: .passkey)
    let stale: [any ASCredentialIdentity] = identities.filter { identity in
      guard let passkey = identity as? ASPasskeyCredentialIdentity else { return false }
      return passkey.relyingPartyIdentifier == relyingParty && shouldRemove(passkey)
    }
    guard !stale.isEmpty else { return }
    do {
      try await store.removeCredentialIdentities(stale)
    } catch {
      NSLog("AxoPassAutoFill: failed to remove passkey identities: %@", "\(error)")
    }
  }

  /// Ask the app to fill the login and hand the result back to the system.
  private func fill(_ login: Login) {
    guard let service = model.service, !service.isEmpty else {
      cancel(.credentialIdentityNotFound)
      return
    }
    let requester = model.requester
    model.beginFilling(login.accountName)
    switch model.purpose {
    case .password:
      // A login with no matching website came from the full list. The app asks
      // the user to confirm it.
      let unmatched = login.matched == nil
      Task { [weak self] in
        do {
          let fill = try await BrokerClient.fill(
            service: service, recordID: login.recordID, account: login.accountName,
            unmatched: unmatched, requester: requester)
          self?.complete(user: fill.username ?? login.accountName, password: fill.password)
        } catch {
          self?.model.report(error)
        }
      }
    case .oneTimeCode:
      Task { [weak self] in
        do {
          let code = try await BrokerClient.totp(
            service: service, recordID: login.recordID, requester: requester)
          self?.extensionContext.completeOneTimeCodeRequest(
            using: ASOneTimeCodeCredential(code: code), completionHandler: nil)
        } catch {
          self?.model.report(error)
        }
      }
    }
  }

  private func complete(user: String, password: String) {
    extensionContext.completeRequest(
      withSelectedCredential: ASPasswordCredential(user: user, password: password),
      completionHandler: nil)
  }

  private func cancel(_ code: ASExtensionError.Code) {
    extensionContext.cancelRequest(
      withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
  }

  /// Start the app when it is not already serving the broker. A sandboxed
  /// extension cannot launch it directly, so this goes through the extension
  /// context and the app's own URL scheme.
  private func openHostApp() {
    guard let url = URL(string: "axopass://open") else { return }
    extensionContext.open(url, completionHandler: nil)
  }

  // MARK: - Configuration

  override func prepareInterfaceForExtensionConfiguration() {
    model.showConfiguration { [weak self] in
      self?.extensionContext.completeExtensionConfigurationRequest()
    }
  }
}

/// Drives the extension's UI. The controller owns the AuthenticationServices
/// side; this holds only what is on screen.
@MainActor
@Observable
final class CredentialListModel {
  enum State {
    case loading
    case list(LoginList)
    case filling(String)
    case appUnavailable
    case configuration(() -> Void)
    case failed(String)
  }

  /// What the user is being asked for.
  enum Purpose {
    case password
    case oneTimeCode
  }

  private(set) var state: State = .loading
  private(set) var purpose: Purpose = .password
  private(set) var service: String?

  /// The site shown in the header and in the group titles: the host of the
  /// service, which may be a bare domain or a URL.
  var host: String? {
    guard let service, !service.isEmpty else { return nil }
    if service.contains("://"), let host = URLComponents(string: service)?.host { return host }
    return service
  }
  /// The name of the app that asked, when the system identifies one. `nil`
  /// means a browser.
  private(set) var requester: String?

  var onSelect: ((Login) -> Void)?
  var onCancel: (() -> Void)?
  var onOpenApp: (() -> Void)?

  func load(service: String?, requester: String? = nil, purpose: Purpose = .password) {
    self.service = service
    self.requester = requester
    self.purpose = purpose
    guard let service, !service.isEmpty else {
      state = .failed("AutoFill did not say which site this is for.")
      return
    }
    guard BrokerClient.isAvailable else {
      state = .appUnavailable
      return
    }
    state = .loading
    // The full list of logins is for filling a password. A one-time code is
    // only ever released for a login that matches the page.
    let all = purpose == .password
    Task { [weak self] in
      do {
        var list = try await BrokerClient.logins(
          service: service, requester: requester, all: all)
        if self?.purpose == .oneTimeCode {
          list.matches = list.matches.filter(\.hasTotp)
        }
        self?.state = .list(list)
      } catch {
        self?.report(error)
      }
    }
  }

  /// The system picked an identity for us; fill it and finish without ever
  /// showing a list. The app checks the record against `service` before it
  /// answers.
  func fillDirectly(recordID: String, service: String, user: String, purpose: Purpose) {
    self.service = service
    self.purpose = purpose
    guard BrokerClient.isAvailable else {
      state = .appUnavailable
      return
    }
    let login = Login(
      recordID: recordID, title: user, username: user.isEmpty ? nil : user,
      matched: Login.Matched(host: service))
    onSelect?(login)
  }

  func beginFilling(_ account: String) {
    state = .filling(account)
  }

  func showConfiguration(onDone: @escaping () -> Void) {
    state = .configuration(onDone)
  }

  func report(_ error: Error) {
    if case BrokerError.cancelled = error {
      onCancel?()
      return
    }
    if case BrokerError.unavailable = error {
      state = .appUnavailable
      return
    }
    state = .failed(error.localizedDescription)
  }

  func retry() {
    load(service: service, requester: requester, purpose: purpose)
  }
}
