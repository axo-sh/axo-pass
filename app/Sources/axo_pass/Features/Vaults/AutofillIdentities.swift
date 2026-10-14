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
    // Site reports received while the vaults were locked are written into the
    // vaults first, so the listings below leave out rejected passkeys.
    do {
      try await core.applyPasskeyReports()
    } catch {
      NSLog("Failed to apply passkey reports: %@", String(describing: error))
    }

    // Listing also replaces the broker's own login index, which answers the
    // clients that list without a prompt and offers the registration prompt its
    // logins, so it runs whether or not the system provider is enabled.
    let items: [AutofillItemInfo]
    do {
      items = try await core.listAutofillItems()
    } catch {
      NSLog("Failed to list autofill items: %@", String(describing: error))
      return
    }

    guard await isEnabled() else { return }

    let passkeys: [PasskeyIdentityInfo]
    do {
      passkeys = try await core.listPasskeyIdentities()
    } catch {
      NSLog("Failed to list passkey identities: %@", String(describing: error))
      passkeys = []
    }

    let identities: [ASCredentialIdentity] =
      items.flatMap(passwordIdentities) + items.flatMap(oneTimeCodeIdentities)
      + passkeys.map(passkeyIdentity)
    do {
      try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities)
    } catch {
      NSLog("Failed to register autofill identities: %@", String(describing: error))
    }
  }

  /// One passkey identity: the system matches on the relying party, and hands
  /// the record identifier back when the user picks it.
  private static func passkeyIdentity(
    for passkey: PasskeyIdentityInfo
  ) -> ASPasskeyCredentialIdentity {
    ASPasskeyCredentialIdentity(
      relyingPartyIdentifier: passkey.rpId,
      userName: passkey.userName.isEmpty ? passkey.rpId : passkey.userName,
      credentialID: passkey.credentialId,
      userHandle: passkey.userHandle,
      recordIdentifier: passkey.recordId)
  }

  /// One identity per host of the item: the system matches on the service, so
  /// an item with three sites has to be registered three times. The core
  /// decides the hosts from each website's match kind.
  private static func passwordIdentities(
    for item: AutofillItemInfo
  ) -> [ASPasswordCredentialIdentity] {
    let user = item.username?.isEmpty == false ? item.username! : item.title
    return item.hosts.map { host in
      ASPasswordCredentialIdentity(
        serviceIdentifier: ASCredentialServiceIdentifier(identifier: host, type: .domain),
        user: user,
        recordIdentifier: item.recordId)
    }
  }

  /// The same hosts for an item with a one-time code, so the code field's
  /// AutoFill menu offers it.
  private static func oneTimeCodeIdentities(
    for item: AutofillItemInfo
  ) -> [ASOneTimeCodeCredentialIdentity] {
    guard item.hasTotp else { return [] }
    let label = item.username?.isEmpty == false ? item.username! : item.title
    return item.hosts.map { host in
      ASOneTimeCodeCredentialIdentity(
        serviceIdentifier: ASCredentialServiceIdentifier(identifier: host, type: .domain),
        label: label,
        recordIdentifier: item.recordId)
    }
  }

  private static func isEnabled() async -> Bool {
    await ASCredentialIdentityStore.shared.state().isEnabled
  }
}
