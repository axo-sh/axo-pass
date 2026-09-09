import AxoPassFFI
import CryptoKit
import SwiftUI

struct VaultDetailView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    Group {
      if let selected = model.selectedItem {
        CredentialList(item: selected.item, vaultKey: selected.vaultKey)
      } else if model.isLoadingSelectedItems {
        DelayedProgressView()
      } else {
        ContentUnavailableView("Select an item", systemImage: "list.bullet.rectangle")
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(.windowBackground)
  }
}

private struct CredentialList: View {
  @Environment(VaultsModel.self) private var model
  let item: ItemInfo
  let vaultKey: String

  @State private var secrets: [String: SymmetricKey] = [:]
  @State private var errors: [String: String] = [:]
  @State private var revealing: Set<String> = []
  @State private var isEditing: Bool = false
  @State private var showingNewCredentialSheet = false

  var body: some View {
    ScrollView {
      VStack(spacing: 0) {
        InsetGroupedSection {
          if item.credentials.isEmpty {
            Text("No credentials")
              .foregroundStyle(.secondary)
              .padding(8)
              .frame(maxWidth: .infinity, alignment: .leading)
          } else {
            VStack(spacing: 8) {
              ForEach(Array(item.credentials.enumerated()), id: \.element.key) { index, cred in
                if index > 0 {
                  Divider()
                }
                row(for: cred)
              }
            }
          }
        }
        .overlay {
          if isEditing {
            RoundedRectangle(cornerRadius: 6)
              .strokeBorder(.tint, lineWidth: 2)
          }
        }
        .padding()
      }
    }
    .navigationTitle(item.title)
    .toolbar {
      ToolbarItemGroup(placement: .primaryAction) {
        if !isEditing, hasConcealed {
          Button(allRevealed ? "Hide All" : "Reveal All") {
            if allRevealed {
              hideAll()
            } else {
              Task { await revealAll() }
            }
          }
          .disabled(!revealing.isEmpty)
        }

        Button(isEditing ? "Done" : "Edit") {
          if isEditing {
            isEditing = false
            hideAll()
          } else {
            // Editing resubmits each credential's value along with its title,
            // so reveal everything before the edit forms appear.
            Task {
              await revealAll()
              isEditing = true
            }
          }
        }
        .disabled(!revealing.isEmpty)

        Button {
          showingNewCredentialSheet = true
        } label: {
          Label("Add Credential", systemImage: "plus")
        }
      }
    }
    .onChange(of: item.key) {
      secrets = [:]
      errors = [:]
      revealing = []
      isEditing = false
    }
    .sheet(isPresented: $showingNewCredentialSheet) {
      NewCredentialSheet { key, title, value, kind in
        await model.addOrUpdateCredential(
          vaultKey: vaultKey, itemKey: item.key, credKey: key, title: title, value: value,
          kind: kind
        )
      }
    }
  }

  @ViewBuilder
  private func row(for cred: CredentialInfo) -> some View {
    CredentialRow(
      cred: cred,
      secret: secrets[cred.key],
      error: errors[cred.key],
      isRevealing: revealing.contains(cred.key),
      isEditing: isEditing,
      onReveal: { Task { await reveal(cred) } },
      onHide: { hide(cred) },
      onCopy: { await copy(cred) },
      onSave: { newKey, newTitle, newValue, newKind in
        Task {
          await save(
            cred, newKey: newKey, newTitle: newTitle, newValue: newValue, newKind: newKind
          )
        }
      },
      onDelete: { Task { await delete(cred) } }
    )
  }

  private var concealedCredentials: [CredentialInfo] {
    item.credentials.filter(\.kind.concealed)
  }

  private var hasConcealed: Bool {
    !concealedCredentials.isEmpty
  }

  /// "All revealed" tracks only the concealed credentials; plain-text ones are
  /// always shown and are not toggled by Reveal/Hide All.
  private var allRevealed: Bool {
    hasConcealed && concealedCredentials.allSatisfy { secrets[$0.key] != nil }
  }

  private func revealAll() async {
    await withTaskGroup(of: Void.self) { group in
      for cred in item.credentials where secrets[cred.key] == nil && !revealing.contains(cred.key) {
        group.addTask { await reveal(cred) }
      }
    }
  }

  private func hideAll() {
    for cred in concealedCredentials {
      secrets.removeValue(forKey: cred.key)
    }
  }

  private func reveal(_ cred: CredentialInfo) async {
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

  private func hide(_ cred: CredentialInfo) {
    secrets.removeValue(forKey: cred.key)
  }

  /// Copy without revealing: if the secret is not already on screen, fetch a
  /// throwaway copy for the clipboard and do not store it in `secrets`. Returns
  /// whether the value reached the pasteboard.
  private func copy(_ cred: CredentialInfo) async -> Bool {
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
  private func save(
    _ cred: CredentialInfo, newKey: String, newTitle: String, newValue: String,
    newKind: FieldKindInfo?
  ) async {
    let ok: Bool
    if newKey == cred.key {
      ok = await model.addOrUpdateCredential(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key,
        title: newTitle, value: newValue, kind: newKind
      )
    } else {
      ok = await model.renameCredentialKey(
        vaultKey: vaultKey, itemKey: item.key, oldKey: cred.key, newKey: newKey,
        title: newTitle, value: newValue, kind: newKind
      )
      if ok {
        secrets[newKey] = secrets.removeValue(forKey: cred.key)
        errors.removeValue(forKey: cred.key)
        if revealing.remove(cred.key) != nil { revealing.insert(newKey) }
      }
    }
    if !ok, let err = model.actionError {
      errors[cred.key] = err
    }
  }

  private func delete(_ cred: CredentialInfo) async {
    let ok = await model.deleteCredential(vaultKey: vaultKey, itemKey: item.key, credKey: cred.key)
    if ok {
      secrets.removeValue(forKey: cred.key)
      errors.removeValue(forKey: cred.key)
    } else if let err = model.actionError {
      errors[cred.key] = err
    }
  }
}

private struct NewCredentialSheet: View {
  let onSubmit: (_ key: String, _ title: String, _ value: String, _ kind: FieldKindInfo) async -> Bool

  @Environment(\.dismiss) private var dismiss
  @State private var title: String = ""
  @State private var key: String = ""
  @State private var value: String = ""
  @State private var concealed: Bool = true
  @State private var multiline: Bool = false
  @State private var isSubmitting = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Credential").font(.headline)
      TextField("Title", text: $title)
      TextField("Key (a-z, 0-9, -, _)", text: $key)
      if concealed && !multiline {
        SecureField("Value", text: $value)
      } else {
        TextField("Value", text: $value, axis: .vertical)
          .lineLimit(multiline ? 3...12 : 1...1)
      }

      HStack(spacing: 16) {
        Toggle("Concealed", isOn: $concealed)
        Toggle("Multiline", isOn: $multiline)
      }
      .toggleStyle(.checkbox)

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Create") {
          Task {
            isSubmitting = true
            let kind = FieldKindInfo(kind: "text", concealed: concealed, multiline: multiline)
            if await onSubmit(key, title, value, kind) { dismiss() }
            isSubmitting = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || key.isEmpty || title.isEmpty || value.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 320)
  }
}
