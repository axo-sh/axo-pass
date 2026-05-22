import AxoPassFFI
import CryptoKit
import SwiftUI

struct VaultDetailView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    if let item = model.selectedItem {
      CredentialList(item: item)
        .navigationTitle(item.title)
    } else {
      ContentUnavailableView("Select an item", systemImage: "list.bullet.rectangle")
    }
  }
}

private struct CredentialList: View {
  @Environment(VaultsModel.self) private var model
  let item: ItemInfo

  @State private var secrets: [String: SymmetricKey] = [:]
  @State private var errors: [String: String] = [:]
  @State private var revealing: Set<String> = []

  var body: some View {
    List {
      if item.credentials.isEmpty {
        Text("No credentials").foregroundStyle(.secondary)
      } else {
        ForEach(item.credentials, id: \.key) { cred in
          CredentialRow(
            cred: cred,
            secret: secrets[cred.key],
            error: errors[cred.key],
            isRevealing: revealing.contains(cred.key),
            onReveal: { Task { await reveal(cred) } },
            onHide: { hide(cred) },
            onCopy: { copy(cred) }
          )
        }
      }
    }
    .listStyle(.grouped)
    .onChange(of: item.key) {
      secrets = [:]
      errors = [:]
      revealing = []
    }
  }

  private func reveal(_ cred: CredentialInfo) async {
    revealing.insert(cred.key)
    errors.removeValue(forKey: cred.key)
    do {
      secrets[cred.key] = try await model.credentialSecret(
        itemKey: item.key, credKey: cred.key
      )
    } catch {
      errors[cred.key] = String(describing: error)
    }
    revealing.remove(cred.key)
  }

  private func hide(_ cred: CredentialInfo) {
    secrets.removeValue(forKey: cred.key)
  }

  private func copy(_ cred: CredentialInfo) {
    guard let secret = secrets[cred.key] else { return }
    secret.withUnsafeBytes { ptr in
      guard let str = String(bytes: ptr, encoding: .utf8) else { return }
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(str, forType: .string)
    }
  }
}
