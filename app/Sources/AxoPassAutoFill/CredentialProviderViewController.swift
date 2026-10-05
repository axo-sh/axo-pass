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
    model.load(service: serviceIdentifiers.first?.identifier)
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

    guard let ref = CredentialRef(recordIdentifier: request.credentialIdentity.recordIdentifier)
    else {
      cancel(.credentialIdentityNotFound)
      return
    }
    let user = (request.credentialIdentity as? ASPasswordCredentialIdentity)?.user ?? ""
    model.fillDirectly(ref: ref, user: user)
  }

  // MARK: - Passkeys

  override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest)
  {
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

  /// Read the password and hand it back to the system.
  private func fill(_ item: AutofillItem) {
    guard let ref = CredentialRef(recordIdentifier: item.recordIdentifier) else {
      cancel(.credentialIdentityNotFound)
      return
    }
    model.beginFilling(item.accountName)
    Task { [weak self] in
      do {
        let password = try await BrokerClient.secret(for: ref)
        self?.complete(user: item.accountName, password: password)
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
    case list([AutofillItem])
    case filling(String)
    case appUnavailable
    case configuration(() -> Void)
    case failed(String)
  }

  private(set) var state: State = .loading
  private(set) var service: String?

  var onSelect: ((AutofillItem) -> Void)?
  var onCancel: (() -> Void)?
  var onOpenApp: (() -> Void)?

  func load(service: String?) {
    self.service = service
    guard BrokerClient.isAvailable else {
      state = .appUnavailable
      return
    }
    state = .loading
    Task { [weak self] in
      do {
        let items = try await BrokerClient.autofillItems(service: service)
        self?.state = .list(items)
      } catch {
        self?.report(error)
      }
    }
  }

  /// The system picked an identity for us; read it and finish without ever
  /// showing a list.
  func fillDirectly(ref: CredentialRef, user: String) {
    guard BrokerClient.isAvailable else {
      state = .appUnavailable
      return
    }
    let item = AutofillItem(
      vaultKey: ref.vaultKey, itemKey: ref.itemKey, title: user,
      username: user.isEmpty ? nil : user, passwordKey: ref.credentialKey, websites: [])
    onSelect?(item)
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
    load(service: service)
  }
}
