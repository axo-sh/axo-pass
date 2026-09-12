import AxoPassFFI
import SwiftUI

struct VaultsSidebar: View {
  @Environment(VaultsModel.self) private var model
  @State private var showingNewVaultSheet = false
  @State private var renamingVaultKey: String? = nil
  @State private var exportingVaultKey: String? = nil
  @State private var secretsExpanded = true
  @State private var toolsExpanded = true

  private var selectionBinding: Binding<SidebarDestination?> {
    Binding(
      // Highlight the row being loaded, so a click registers before the panes
      // switch to it.
      get: { model.sidebarHighlight },
      set: { model.selectSidebarDestination($0) }
    )
  }

  var body: some View {
    List(selection: selectionBinding) {
      Section(isExpanded: $secretsExpanded) {
        vaultItems
      } header: {
        SidebarSectionHeader("Secrets") { withAnimation { secretsExpanded.toggle() } }
      }

      Section(isExpanded: $toolsExpanded) {
        Label("SSH", systemImage: "asterisk")
          .tag(SidebarDestination.ssh)
        Label("GPG", systemImage: "key.fill")
          .tag(SidebarDestination.gpg)
        Label("Age", systemImage: "lock.rectangle.stack")
          .tag(SidebarDestination.age)
      } header: {
        SidebarSectionHeader("Tools") { withAnimation { toolsExpanded.toggle() } }
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
    .sheet(item: $exportingVaultKey) { vaultKey in
      VaultExportSheet(model: model, only: vaultKey)
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
        HStack(spacing: 4) {
          Label {
            Text(vault.name ?? vault.key)
          } icon: {
            Image(systemName: "circle.fill").hidden()
          }
          Spacer(minLength: 0)
          if model.isPendingSelection(.vault(vault.key)) {
            DelayedProgressView(size: .mini, expands: false)
          }
        }
        .tag(SidebarDestination.vault(vault.key))
        .contextMenu {
          Button("Rename…") { renamingVaultKey = vault.key }
          Button("Export Backup…") { exportingVaultKey = vault.key }
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
  let onTap: () -> Void

  init(_ title: String, onTap: @escaping () -> Void = {}) {
    self.title = title
    self.onTap = onTap
  }

  var body: some View {
    HStack(spacing: 4) {
      Text(title)
        .font(.caption2)
        .fontWeight(.semibold)
        .textCase(.uppercase)
        .kerning(0.6)
      Spacer(minLength: 0)
    }
    .foregroundStyle(.tertiary)
    .contentShape(.rect)
    .padding(.top, 6)
    .onTapGesture(perform: onTap)
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

      Form {
        TextField("Name", text: $name)
        if isCreating {
          TextField("Key", text: $key)
          LabeledContent("") {
            Text("a-z, 0-9, -, _")
              .font(.caption)
              .foregroundStyle(.secondary)
              .frame(maxWidth: .infinity, alignment: .leading)
          }
        }
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
