import AxoPassFFI
import SwiftUI

struct VaultsSidebar: View {
  @Environment(VaultsModel.self) private var model
  @State private var showingNewVaultSheet = false
  @State private var renamingVaultKey: String? = nil

  private var selectionBinding: Binding<SidebarDestination?> {
    Binding(
      get: { model.sidebarSelection },
      set: { model.selectSidebarDestination($0) }
    )
  }

  var body: some View {
    List(selection: selectionBinding) {
      Section {
        vaultItems
      } header: {
        // Label("Secrets", systemImage: "list.bullet.rectangle.fill")
        Text("Secrets")
      }

      Label("SSH", systemImage: "asterisk")
        .tag(SidebarDestination.ssh)
      Label("Keys", systemImage: "key.fill")
        .tag(SidebarDestination.gpg)
      Label("Setup", systemImage: "terminal")
        .tag(SidebarDestination.setup)
    }
    .navigationSplitViewColumnWidth(min: 160, ideal: 200)
    .safeAreaInset(edge: .bottom) {
      HStack(spacing: 8) {
        Button {
          model.reload()
        } label: {
          Label("Reload", systemImage: "arrow.clockwise")
        }
        Button {
          showingNewVaultSheet = true
        } label: {
          Label("New Vault", systemImage: "plus")
        }
        Spacer()
        Button {
          model.lock()
        } label: {
          Label("Lock", systemImage: "lock")
        }
      }
      .labelStyle(.iconOnly)
      .buttonStyle(.borderless)
      .padding(.horizontal, 12)
      .padding(.vertical, 8)
    }
    .sheet(isPresented: $showingNewVaultSheet) {
      VaultFormSheet(mode: .create) { name, key in
        await model.addVault(name: name, key: key)
      }
    }
    .sheet(item: $renamingVaultKey) { vaultKey in
      let existing = model.vaults.first { $0.key == vaultKey }
      VaultFormSheet(mode: .rename(currentName: existing?.name ?? vaultKey)) { name, _ in
        await model.renameVault(vaultKey: vaultKey, newName: name)
      }
    }
  }

  @ViewBuilder
  private var vaultItems: some View {
    if let err = model.loadError {
      Label(err, systemImage: "exclamationmark.triangle")
        .font(.caption)
        .foregroundStyle(.red)
    } else if model.vaults.isEmpty {
      Text("No vaults")
        .font(.caption)
        .foregroundStyle(.secondary)
    } else {
      Label("All", systemImage: "lock")
        .tag(SidebarDestination.vault("all"))
      ForEach(model.vaults, id: \.key) { vault in
        Label(vault.name ?? vault.key, systemImage: "lock")
          .tag(SidebarDestination.vault(vault.key))
          .contextMenu {
            Button("Rename…") { renamingVaultKey = vault.key }
            Button("Delete", role: .destructive) {
              Task { await model.deleteVault(vault.key) }
            }
          }
      }
    }
  }
}

extension String: @retroactive Identifiable {
  public var id: String { self }
}

private struct VaultFormSheet: View {
  enum Mode {
    case create
    case rename(currentName: String)
  }

  let mode: Mode
  let onSubmit: (_ name: String?, _ key: String) async -> Bool

  @Environment(\.dismiss) private var dismiss
  @State private var name: String = ""
  @State private var key: String = ""
  @State private var isSubmitting = false
  @State private var error: String? = nil

  private var isCreating: Bool {
    if case .create = mode { return true }
    return false
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(isCreating ? "New Vault" : "Rename Vault")
        .font(.headline)

      TextField("Name", text: $name)
      if isCreating {
        TextField("Key (a-z, 0-9, -, _)", text: $key)
      }

      if let error {
        Text(error).font(.caption).foregroundStyle(.red)
      }

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button(isCreating ? "Create" : "Rename") {
          Task { await submit() }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || (isCreating && key.isEmpty))
      }
    }
    .padding(20)
    .frame(width: 320)
    .onAppear {
      if case .rename(let currentName) = mode { name = currentName }
    }
  }

  private func submit() async {
    isSubmitting = true
    error = nil
    let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
    let ok = await onSubmit(trimmedName.isEmpty ? nil : trimmedName, key)
    isSubmitting = false
    if ok { dismiss() }
  }
}
