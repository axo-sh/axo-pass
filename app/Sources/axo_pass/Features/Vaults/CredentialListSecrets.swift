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
      return secureCopy(secret)
    }
    revealing.insert(cred.key)
    errors.removeValue(forKey: cred.key)
    defer { revealing.remove(cred.key) }
    do {
      let secret = try await model.credentialSecret(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key
      )
      return secureCopy(secret)
    } catch {
      errors[cred.key] = String(describing: error)
      return false
    }
  }

  /// Save a renamed title or id. A new id moves the cached secret, error, and
  /// selection to the new key.
  func rename(_ cred: CredentialInfo, field: CredentialRow.RenameField, to text: String) {
    renaming = nil
    switch field {
    case .title:
      guard text != cred.title else { return }
      Task {
        errors[cred.key] = await failureMessage {
          try await model.updateCredential(
            vaultKey: vaultKey, itemKey: item.key, credKey: cred.key, title: text)
        }
      }
    case .key:
      guard text != cred.key else { return }
      let oldKeys = Set(item.credentials.map(\.key))
      Task {
        let error = await failureMessage {
          try await model.updateCredential(
            vaultKey: vaultKey, itemKey: item.key, credKey: cred.key, newKey: text)
        }
        // The core may normalize the key. The new key is the one present in
        // the item now and absent before.
        let reloaded = model.item(vaultKey: vaultKey, itemKey: item.key)
        if error == nil,
          let newKey = reloaded?.credentials.map(\.key).first(where: { !oldKeys.contains($0) })
        {
          secrets[newKey] = secrets.removeValue(forKey: cred.key)
          errors.removeValue(forKey: cred.key)
          if selection.remove(.credential(cred.key)) != nil {
            selection.insert(.credential(newKey))
          }
        } else {
          errors[cred.key] = error
        }
      }
    }
  }

  /// Change the concealed or multiline option of a text credential. Applies
  /// immediately. A newly concealed credential is hidden again.
  func setTextOptions(_ cred: CredentialInfo, concealed: Bool, multiline: Bool) {
    let kind = FieldKindInfo(kind: "text", concealed: concealed, multiline: multiline)
    Task {
      let error = await failureMessage {
        try await model.updateCredential(
          vaultKey: vaultKey, itemKey: item.key, credKey: cred.key, kind: kind)
      }
      if error == nil, concealed, !cred.kind.concealed {
        secrets.removeValue(forKey: cred.key)
      }
      errors[cred.key] = error
    }
  }

  func quickSaveValue(_ cred: CredentialInfo, newValue: String) async {
    let ok = await model.addOrUpdateCredential(
      vaultKey: vaultKey, itemKey: item.key, credKey: cred.key, title: cred.title, value: newValue,
      kind: nil
    )
    if ok {
      refreshCachedSecret(newValue, for: cred.key)
    }
    finishEdit(cred.key, ok: ok)
  }

  /// Set or clear a credential error after a save.
  private func finishEdit(_ key: String, ok: Bool) {
    if ok {
      errors.removeValue(forKey: key)
    } else {
      errors[key] = model.actionError ?? "Failed to save."
    }
  }

  /// Update a revealed value in the cache after a successful save, so the row
  /// stops showing what was there before. A credential that is not revealed is
  /// left alone. The next reveal fetches the new value. The row only requests a
  /// secret on first appearance, so a stale entry would otherwise persist.
  private func refreshCachedSecret(_ value: String, for key: String) {
    guard secrets[key] != nil else { return }
    var raw = Data(value.utf8)
    secrets[key] = SymmetricKey(data: raw)
    raw.resetBytes(in: raw.indices)
  }

  /// Same as `refreshCachedSecret(_:for:)`, for a value changed outside the
  /// row. The new value is fetched from the vault.
  func refreshCachedSecret(for key: String) {
    guard secrets[key] != nil else { return }
    Task {
      if let secret = try? await model.credentialSecret(
        vaultKey: vaultKey, itemKey: item.key, credKey: key)
      {
        secrets[key] = secret
      }
    }
  }
}
