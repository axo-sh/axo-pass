import AppKit
import AuthenticationServices
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
    // An app identifier is not a site, so it only names the requester. The
    // site to match comes from the first domain or URL identifier. App
    // identifiers exist from macOS 26.2.
    if #available(macOS 26.2, *) {
      let app = serviceIdentifiers.first { $0.type == .app }
      let site = serviceIdentifiers.first { $0.type != .app } ?? serviceIdentifiers.first
      model.load(
        service: site?.identifier, requester: app.map { $0.displayName ?? $0.identifier })
    } else {
      model.load(service: serviceIdentifiers.first?.identifier)
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
    model.beginFilling(rpID)
    Task { [weak self] in
      do {
        let assertion = try await BrokerClient.assertPasskey(
          rpID: rpID,
          clientDataHash: clientDataHash,
          allowedCredentialIDs: requestParameters.allowedCredentials)
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

    guard let identity = request.credentialIdentity as? ASPasswordCredentialIdentity,
      let recordID = identity.recordIdentifier, !recordID.isEmpty,
      !identity.serviceIdentifier.identifier.isEmpty
    else {
      cancel(.credentialIdentityNotFound)
      return
    }
    model.fillDirectly(
      recordID: recordID, service: identity.serviceIdentifier.identifier, user: identity.user)
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
          excludedCredentials: (request.excludedCredentials ?? []).map(\.credentialID))
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
    model.beginFilling(name)
    Task { [weak self] in
      do {
        let assertion = try await BrokerClient.assertPasskey(
          rpID: identity.relyingPartyIdentifier,
          clientDataHash: request.clientDataHash,
          allowedCredentialIDs: [identity.credentialID])
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
    let credential = ASPasskeyRegistrationCredential(
      relyingParty: rpID,
      clientDataHash: clientDataHash,
      credentialID: registration.credentialID,
      attestationObject: registration.attestationObject)
    extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
  }

  private func completeAssertion(
    rpID: String, clientDataHash: Data, assertion: BrokerClient.Assertion
  ) {
    let credential = ASPasskeyAssertionCredential(
      userHandle: assertion.userHandle,
      relyingParty: rpID,
      signature: assertion.signature,
      clientDataHash: clientDataHash,
      authenticatorData: assertion.authenticatorData,
      credentialID: assertion.credentialID)
    extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
  }

  /// Ask the app to fill the login and hand the result back to the system.
  private func fill(_ login: Login) {
    guard let service = model.service, !service.isEmpty else {
      cancel(.credentialIdentityNotFound)
      return
    }
    let requester = model.requester
    model.beginFilling(login.accountName)
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

  private(set) var state: State = .loading
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

  func load(service: String?, requester: String? = nil) {
    self.service = service
    self.requester = requester
    guard let service, !service.isEmpty else {
      state = .failed("AutoFill did not say which site this is for.")
      return
    }
    guard BrokerClient.isAvailable else {
      state = .appUnavailable
      return
    }
    state = .loading
    Task { [weak self] in
      do {
        let list = try await BrokerClient.logins(
          service: service, requester: requester, all: true)
        self?.state = .list(list)
      } catch {
        self?.report(error)
      }
    }
  }

  /// The system picked an identity for us; fill it and finish without ever
  /// showing a list. The app checks the record against `service` before it
  /// answers.
  func fillDirectly(recordID: String, service: String, user: String) {
    self.service = service
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
    load(service: service, requester: requester)
  }
}
