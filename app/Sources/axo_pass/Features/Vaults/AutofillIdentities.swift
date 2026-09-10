import AuthenticationServices
import AxoPassFFI
import Foundation

/// Keeps the system's AutoFill index in step with the vaults.
///
/// The index holds only what the system already needs to offer a login: the
/// domain, the account name, and the coordinates of the credential to fill. No
/// password ever reaches it. The extension hands a record identifier back when
/// the user picks one, and the password is read from the vault then, behind the
/// usual prompt.
///
/// The index survives a lock. Clearing it would take the site out of the
/// browser's AutoFill menu entirely, which is the entry point a locked app
/// still needs; the vault itself stays locked either way.
///
/// Registration is a no-op until the user enables Axo Pass in System Settings ›
/// Passwords › Password Options.
enum AutofillIdentities {
  /// Replace the whole index with the current contents of the vaults. Called
  /// after an unlock, when every vault can be read on one authentication.
  static func refresh(from core: AxoPass) async {
    guard await isEnabled() else { return }

    let items: [AutofillItemInfo]
    do {
      items = try await core.listAutofillItems()
    } catch {
      NSLog("Failed to list autofill items: %@", String(describing: error))
      return
    }

    let identities = items.flatMap(passwordIdentities)
    do {
      try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities)
    } catch {
      NSLog("Failed to register autofill identities: %@", String(describing: error))
    }
  }

  /// One identity per URL on the item: the system matches on the service, so an
  /// item with three sites has to be registered three times.
  private static func passwordIdentities(
    for item: AutofillItemInfo
  ) -> [ASPasswordCredentialIdentity] {
    let user = item.username?.isEmpty == false ? item.username! : item.title
    let record = "\(item.vaultKey)/\(item.itemKey)/\(item.passwordKey)"
    return item.urls.compactMap { url in
      guard let host = serviceHost(url) else { return nil }
      return ASPasswordCredentialIdentity(
        serviceIdentifier: ASCredentialServiceIdentifier(identifier: host, type: .domain),
        user: user,
        recordIdentifier: record)
    }
  }

  /// Reduce a stored URL to the bare host the system matches on. Mirrors
  /// `service_host` in crates/core/src/secrets/vaults/autofill.rs.
  private static func serviceHost(_ value: String) -> String? {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }
    let candidate = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
    guard let host = URLComponents(string: candidate)?.host?.lowercased() else { return nil }
    return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
  }

  private static func isEnabled() async -> Bool {
    await ASCredentialIdentityStore.shared.state().isEnabled
  }
}
