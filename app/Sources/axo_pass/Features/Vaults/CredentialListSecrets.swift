import AxoPassFFI
import CryptoKit
import SwiftUI

extension CredentialList {
  var concealedCredentials: [CredentialInfo] {
    item.credentials.filter(\.kind.concealed)
  }

  var hasConcealed: Bool {
    !concealedCredentials.isEmpty
  }

  /// "All revealed" tracks only the concealed credentials; plain-text ones are
  /// always shown and are not toggled by Reveal/Hide All.
  var allRevealed: Bool {
    hasConcealed && concealedCredentials.allSatisfy { secrets[$0.key] != nil }
  }

  func revealAll() async {
    await withTaskGroup(of: Void.self) { group in
      for cred in item.credentials where secrets[cred.key] == nil && !revealing.contains(cred.key) {
        group.addTask { await reveal(cred) }
      }
    }
  }

  func hideAll() {
    for cred in concealedCredentials {
      secrets.removeValue(forKey: cred.key)
    }
  }

  func reveal(_ cred: CredentialInfo) async {
    revealing.insert(cred.key)
    errors.removeValue(forKey: cred.key)
    do {
      secrets[cred.key] = try await model.credentialSecret(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key
      )
    } catch {
      errors[cred.key] = String(describing: error)
    }
    revealing.remove(cred.key)
  }

  func hide(_ cred: CredentialInfo) {
    secrets.removeValue(forKey: cred.key)
  }

  /// Copy without revealing: if the secret is not already on screen, fetch a
  /// throwaway copy for the clipboard and do not store it in `secrets`. Returns
  /// whether the value reached the pasteboard.
  func copy(_ cred: CredentialInfo) async -> Bool {
    if let secret = secrets[cred.key] {
      return copyToPasteboard(secret)
    }
    revealing.insert(cred.key)
    errors.removeValue(forKey: cred.key)
    defer { revealing.remove(cred.key) }
    do {
      let secret = try await model.credentialSecret(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key
      )
      return copyToPasteboard(secret)
    } catch {
      errors[cred.key] = String(describing: error)
      return false
    }
  }

  private func copyToPasteboard(_ secret: SymmetricKey) -> Bool {
    secret.withUnsafeBytes { ptr in
      guard let str = String(bytes: ptr, encoding: .utf8) else { return false }
      secureCopy(str)
      return true
    }
  }

  /// Persist an edited credential. A changed id means adding the credential
  /// under the new key and deleting the old one, since the FFI has no rename.
  func save(
    _ cred: CredentialInfo, newKey: String, newTitle: String, newValue: String,
    newKind: FieldKindInfo?
  ) async {
    let ok: Bool
    if newKey == cred.key {
      ok = await model.addOrUpdateCredential(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key,
        title: newTitle, value: newValue, kind: newKind
      )
      if ok {
        applySavedSecret(newValue, for: cred.key, kind: newKind)
        errors.removeValue(forKey: cred.key)
      }
    } else {
      ok = await model.renameCredentialKey(
        vaultKey: vaultKey, itemKey: item.key, oldKey: cred.key, newKey: newKey,
        title: newTitle, value: newValue, kind: newKind
      )
      if ok {
        secrets[newKey] = secrets.removeValue(forKey: cred.key)
        applySavedSecret(newValue, for: newKey, kind: newKind)
        errors.removeValue(forKey: cred.key)
        if revealing.remove(cred.key) != nil { revealing.insert(newKey) }
      }
    }
    if !ok, let err = model.actionError {
      errors[cred.key] = err
    }
  }

  func quickSaveValue(_ cred: CredentialInfo, newValue: String) async {
    let ok = await model.addOrUpdateCredential(
      vaultKey: vaultKey, itemKey: item.key, credKey: cred.key, title: cred.title, value: newValue,
      kind: nil
    )
    if ok {
      refreshCachedSecret(newValue, for: cred.key)
      errors.removeValue(forKey: cred.key)
    } else if let err = model.actionError {
      errors[cred.key] = err
    }
  }

  /// Bring the secret cache in line with what was just saved. A credential the
  /// save made concealed goes back to hidden: `hideAll` on Done runs before the
  /// save, against the old kind, so it does not cover this. Otherwise the
  /// revealed value is refreshed. A credential the save made plain text is
  /// left out of the cache and reveals itself when its value view appears.
  private func applySavedSecret(_ value: String, for key: String, kind: FieldKindInfo?) {
    if kind?.concealed == true {
      secrets.removeValue(forKey: key)
      return
    }
    refreshCachedSecret(value, for: key)
  }

  /// Update a revealed value in the cache after a successful save, so the row
  /// stops showing what was there before. A credential that is not revealed is
  /// left alone: the next reveal fetches the new value. The row only requests a
  /// secret on first appearance, so a stale entry would otherwise persist.
  private func refreshCachedSecret(_ value: String, for key: String) {
    guard secrets[key] != nil else { return }
    var raw = Data(value.utf8)
    secrets[key] = SymmetricKey(data: raw)
    raw.resetBytes(in: raw.indices)
  }

  func delete(_ cred: CredentialInfo) async {
    let ok = await model.deleteCredential(vaultKey: vaultKey, itemKey: item.key, credKey: cred.key)
    if ok {
      secrets.removeValue(forKey: cred.key)
      errors.removeValue(forKey: cred.key)
    } else if let err = model.actionError {
      errors[cred.key] = err
    }
  }
}
