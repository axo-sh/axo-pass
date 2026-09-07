import AxoPassFFI
import SwiftUI

struct VaultsSidebar: View {
  @Environment(VaultsModel.self) private var model
  @State private var showingNewVaultSheet = false
  @State private var renamingVaultKey: String? = nil
  @AppStorage("sidebar.secretsExpanded") private var secretsExpanded = true
  @AppStorage("sidebar.toolsExpanded") private var toolsExpanded = true

  private var selectionBinding: Binding<SidebarDestination?> {
    Binding(
      get: { model.sidebarSelection },
      set: { model.selectSidebarDestination($0) }
    )
  }

  var body: some View {
    List(selection: selectionBinding) {
      Section {
        if secretsExpanded {
          vaultItems
        }
      } header: {
        SidebarSectionHeader("Secrets", isExpanded: $secretsExpanded)
      }

      Section {
        if toolsExpanded {
          Label("SSH", systemImage: "asterisk")
            .tag(SidebarDestination.ssh)
          Label("GPG", systemImage: "key.fill")
            .tag(SidebarDestination.gpg)
        }
      } header: {
        SidebarSectionHeader("Tools", isExpanded: $toolsExpanded)
      }
    }
    .listStyle(.sidebar)
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
      Label {
        Text("All Secrets")
      } icon: {
        Image(systemName: "square.stack.3d.up.fill")
          .foregroundStyle(.tint)
      }
      .tag(SidebarDestination.vault("all"))

      ForEach(model.vaults, id: \.key) { vault in
        Label {
          Text(vault.name ?? vault.key)
        } icon: {
          Image(systemName: "circle.fill").hidden()
        }
        .tag(SidebarDestination.vault(vault.key))
        .contextMenu {
          Button("Rename…") { renamingVaultKey = vault.key }
          Button("Delete", role: .destructive) {
            Task { await model.deleteVault(vault.key) }
          }
        }
      }

      Button {
        showingNewVaultSheet = true
      } label: {
        Label("New Vault", systemImage: "plus")
          .font(.callout)
          .foregroundStyle(.secondary)
      }
      .buttonStyle(.plain)
      .listRowSeparator(.hidden)
    }
  }
}

private struct SidebarSectionHeader: View {
  let title: String
  @Binding var isExpanded: Bool

  init(_ title: String, isExpanded: Binding<Bool>) {
    self.title = title
    self._isExpanded = isExpanded
  }

  var body: some View {
    Button {
      withAnimation(.snappy(duration: 0.2)) { isExpanded.toggle() }
    } label: {
      HStack(spacing: 4) {
        Image(systemName: "chevron.right")
          .font(.system(size: 9, weight: .bold))
          .rotationEffect(.degrees(isExpanded ? 90 : 0))
        Text(title)
          .font(.caption2)
          .fontWeight(.semibold)
          .textCase(.uppercase)
          .kerning(0.6)
        Spacer(minLength: 0)
      }
      .foregroundStyle(.tertiary)
      .contentShape(.rect)
    }
    .buttonStyle(.plain)
    .padding(.top, 6)
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
