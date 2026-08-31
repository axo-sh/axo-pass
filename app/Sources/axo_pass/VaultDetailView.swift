import AxoPassFFI
import CryptoKit
import SwiftUI

struct VaultDetailView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    if let item = model.selectedItem {
      CredentialList(item: item)
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
  @State private var isEditing: Bool = false
  @State private var showingNewCredentialSheet = false

  var body: some View {
    ScrollView {
      VStack(spacing: 0) {
        Text(item.title)
          .font(.title2)
          .fontWeight(.bold)
          .padding(.horizontal, 20)
          .padding(.vertical, 0)
          .frame(maxWidth: .infinity, alignment: .leading)

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
                  onSave: { newTitle in Task { await saveTitle(cred, newTitle: newTitle) } },
                  onDelete: { Task { await delete(cred) } }
                )
              }
            }.padding(0)
          }
        }
        .padding()
        .padding(.top, 0)
      }
    }
    .safeAreaInset(edge: .top) {
      HStack(spacing: 8) {
        Spacer()
        Button(allRevealed ? "Hide All" : "Reveal All") {
          if allRevealed {
            hideAll()
          } else {
            Task { await revealAll() }
          }
        }
        .buttonStyle(.bordered)
        // .controlSize(.small)
        .disabled(!revealing.isEmpty)

        Button(isEditing ? "Done" : "Edit") {
          isEditing.toggle()
        }
        .buttonStyle(.bordered)
        // .controlSize(.small)

        Button {
          showingNewCredentialSheet = true
        } label: {
          Label("Add Credential", systemImage: "plus")
        }
        .buttonStyle(.bordered)
        .labelStyle(.iconOnly)
      }
      .padding(.horizontal)
      .padding(.vertical, 8)
      .background(.ultraThinMaterial)
    }
    .ignoresSafeArea(edges: [.top, .bottom])
    .onChange(of: item.key) {
      secrets = [:]
      errors = [:]
      revealing = []
      isEditing = false
    }
    .sheet(isPresented: $showingNewCredentialSheet) {
      NewCredentialSheet { key, title, value in
        await model.addOrUpdateCredential(itemKey: item.key, credKey: key, title: title, value: value)
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

  /// Renaming a credential requires resubmitting its value too (the FFI
  /// takes title+value together), so reveal it first if it isn't already.
  private func saveTitle(_ cred: CredentialInfo, newTitle: String) async {
    if secrets[cred.key] == nil {
      await reveal(cred)
    }
    guard let secret = secrets[cred.key] else { return }
    let value = secret.withUnsafeBytes { ptr in
      String(bytes: ptr, encoding: .utf8) ?? ""
    }
    let ok = await model.addOrUpdateCredential(
      itemKey: item.key, credKey: cred.key, title: newTitle, value: value
    )
    if !ok, let err = model.actionError {
      errors[cred.key] = err
    }
  }

  private func delete(_ cred: CredentialInfo) async {
    let ok = await model.deleteCredential(itemKey: item.key, credKey: cred.key)
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
