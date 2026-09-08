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
                CredentialRow(
                  cred: cred,
                  secret: secrets[cred.key],
                  error: errors[cred.key],
                  isRevealing: revealing.contains(cred.key),
                  isEditing: isEditing,
                  onReveal: { Task { await reveal(cred) } },
                  onHide: { hide(cred) },
                  onCopy: { copy(cred) },
                  onSave: { newKey, newTitle, newValue in
                    Task { await save(cred, newKey: newKey, newTitle: newTitle, newValue: newValue) }
                  },
                  onDelete: { Task { await delete(cred) } }
                )
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
        if !isEditing {
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
      NewCredentialSheet { key, title, value in
        await model.addOrUpdateCredential(
          vaultKey: vaultKey, itemKey: item.key, credKey: key, title: title, value: value
        )
      }
    }
  }

  private var allRevealed: Bool {
    !item.credentials.isEmpty && item.credentials.allSatisfy { secrets[$0.key] != nil }
  }

  private func revealAll() async {
    await withTaskGroup(of: Void.self) { group in
      for cred in item.credentials where secrets[cred.key] == nil && !revealing.contains(cred.key) {
        group.addTask { await reveal(cred) }
      }
    }
  }

  private func hideAll() {
    secrets = [:]
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

  private func copy(_ cred: CredentialInfo) {
    guard let secret = secrets[cred.key] else { return }
    secret.withUnsafeBytes { ptr in
      guard let str = String(bytes: ptr, encoding: .utf8) else { return }
      secureCopy(str)
    }
  }

  /// Persist an edited credential. A changed id means adding the credential
  /// under the new key and deleting the old one, since the FFI has no rename.
  private func save(
    _ cred: CredentialInfo, newKey: String, newTitle: String, newValue: String
  ) async {
    let ok: Bool
    if newKey == cred.key {
      ok = await model.addOrUpdateCredential(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key,
        title: newTitle, value: newValue
      )
    } else {
      ok = await model.renameCredentialKey(
        vaultKey: vaultKey, itemKey: item.key, oldKey: cred.key, newKey: newKey,
        title: newTitle, value: newValue
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
  let onSubmit: (_ key: String, _ title: String, _ value: String) async -> Bool

  @Environment(\.dismiss) private var dismiss
  @State private var title: String = ""
  @State private var key: String = ""
  @State private var value: String = ""
  @State private var isSubmitting = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Credential").font(.headline)
      TextField("Title", text: $title)
      TextField("Key (a-z, 0-9, -, _)", text: $key)
      SecureField("Value", text: $value)

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Create") {
          Task {
            isSubmitting = true
            if await onSubmit(key, title, value) { dismiss() }
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
