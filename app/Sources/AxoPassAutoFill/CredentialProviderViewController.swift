import AppKit
import AuthenticationServices
import SwiftUI

/// The AutoFill credential provider.
///
/// The extension is sandboxed and holds no keychain entitlements, so it never
/// touches the vault itself. Every request goes to the app's broker over a
/// socket in the App Group container; the app raises the Touch ID prompt,
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

  // MARK: - Filling

  override func provideCredentialWithoutUserInteraction(for request: any ASCredentialRequest) {
    // The vault is locked behind an authentication the app owns, so there is
    // never a credential we can hand over without showing our UI first.
    cancel(.userInteractionRequired)
  }

  override func prepareInterfaceToProvideCredential(for request: any ASCredentialRequest) {
    guard let ref = CredentialRef(recordIdentifier: request.credentialIdentity.recordIdentifier)
    else {
      cancel(.credentialIdentityNotFound)
      return
    }
    let user = (request.credentialIdentity as? ASPasswordCredentialIdentity)?.user ?? ""
    model.fillDirectly(ref: ref, user: user)
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
      username: user.isEmpty ? nil : user, passwordKey: ref.credentialKey, urls: [])
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
