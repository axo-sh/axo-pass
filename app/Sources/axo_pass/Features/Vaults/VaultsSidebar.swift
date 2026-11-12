import AppKit
import AxoPassFFI
import SwiftUI

struct VaultsSidebar: View {
  @Environment(VaultsModel.self) private var model
  @Environment(SyncModel.self) private var sync
  @Environment(IssuesModel.self) private var issues
  @State private var showingNewVaultSheet = false
  @State private var deletingSyncedVault: SyncVaultRef? = nil
  @State private var renamingVaultKey: String? = nil
  @State private var exportingVaultKey: String? = nil
  @State private var versionsVaultKey: String? = nil
  @State private var secretsExpanded = true
  @State private var sourcesExpanded = true
  // Whether the selection after the unlock was checked. The sidebar is
  // created again at each unlock.
  @State private var checkedStartSelection = false

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
      todayRow

      Section(isExpanded: $secretsExpanded) {
        vaultItems
      } header: {
        SidebarSectionHeader("Secrets") { withAnimation { secretsExpanded.toggle() } }
      }

      Section(isExpanded: $sourcesExpanded) {
        sourceRow("SSH", systemImage: "asterisk", source: .ssh)
          .tag(SidebarDestination.ssh)
        sourceRow("GPG", systemImage: "key.fill", source: .gpg)
          .tag(SidebarDestination.gpg)
        Label("Age", systemImage: "lock.rectangle.stack")
          .tag(SidebarDestination.age)
      } header: {
        SidebarSectionHeader("Sources") { withAnimation { sourcesExpanded.toggle() } }
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
        // Add synced vaults to this Mac from the synced folder of the app.
        Menu {
          Button("Pair with Another Mac…") { sync.sheet = .pair(root: sync.folder, join: nil) }
          Button("Use a Recovery Kit…") { sync.sheet = .kitImport(root: sync.folder, join: nil) }
        } label: {
          Label("Add Synced Vaults", systemImage: "arrow.triangle.2.circlepath")
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Add synced vaults from another Mac or with a recovery kit")
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
    .sheet(item: $versionsVaultKey) { vaultKey in
      let existing = model.vaults.first { $0.key == vaultKey }
      VaultVersionsSheet(vaultKey: vaultKey, vaultName: existing?.name ?? vaultKey)
    }
    .syncSheets()
    .confirmationDialog(
      "Delete \(deletingSyncedVault?.name ?? "this vault") from this Mac?",
      isPresented: Binding(
        get: { deletingSyncedVault != nil }, set: { if !$0 { deletingSyncedVault = nil } }),
      presenting: deletingSyncedVault
    ) { vault in
      Button("Delete", role: .destructive) {
        Task { await model.deleteVault(vault.key) }
      }
    } message: { _ in
      Text(syncedVaultDeleteMessage)
    }
    // Read the sync state of each vault after the unlock and when the list
    // changes.
    .task(id: model.vaults) {
      await sync.reloadAll()
      // Saved passphrases are not listed while locked, so read them now.
      if !checkedStartSelection {
        checkedStartSelection = true
        await issues.refreshAll()
      }
    }
  }

  /// Today row with the count of counted issues. The count is red if the worst
  /// issue is broken.
  private var todayRow: some View {
    HStack(spacing: 4) {
      Label("Today", systemImage: "sun.max")
      Spacer(minLength: 0)
      let count = issues.countedIssues.count
      if count > 0 {
        Text("\(count)")
          .monospacedDigit()
          .foregroundStyle(issues.worstSeverity == .broken ? Color.red : Color.secondary)
      }
    }
    .tag(SidebarDestination.today)
  }

  /// Source row with a red dot if a broken issue belongs to `source`.
  private func sourceRow(_ title: String, systemImage: String, source: IssueSource) -> some View {
    let broken = issues.issues.first { $0.source == source && $0.severity == .broken }
    return HStack(spacing: 4) {
      Label(title, systemImage: systemImage)
      Spacer(minLength: 0)
      if let broken {
        Circle()
          .fill(.red)
          .frame(width: 6, height: 6)
          .help(broken.title)
      }
    }
  }

  @ViewBuilder
  private var vaultItems: some View {
    if model.vaults.isEmpty {
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
          VaultSyncSymbol(vault: syncRef(vault))
          if model.isPendingSelection(.vault(vault.key)) {
            DelayedProgressView(size: .mini, expands: false)
          }
        }
        .tag(SidebarDestination.vault(vault.key))
        .contextMenu {
          Button("Rename…") { renamingVaultKey = vault.key }
          Button("Export Backup…") { exportingVaultKey = vault.key }
          Button("Previous Versions…") { versionsVaultKey = vault.key }
          syncMenuItem(vault)
          Button("Delete", role: .destructive) {
            if sync.state(vault.key)?.isOn == true {
              deletingSyncedVault = syncRef(vault)
            } else {
              Task { await model.deleteVault(vault.key) }
            }
          }
        }
      }

      Label("Recently Deleted", systemImage: "trash")
        .tag(SidebarDestination.recentlyDeleted)

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

  private func syncRef(_ vault: VaultInfo) -> SyncVaultRef {
    SyncVaultRef(key: vault.key, name: vault.name ?? vault.key)
  }

  /// Turn sync on or off for `vault`. Disabled while its state is not read,
  /// failed to read, or an earlier turn-off waits for the synced folder.
  @ViewBuilder
  private func syncMenuItem(_ vault: VaultInfo) -> some View {
    switch sync.state(vault.key) {
    case .on:
      Button("Sync Status…") { sync.sheet = .status(syncRef(vault)) }
      Button("Turn Off Sync…") {
        sync.clearDisableError()
        sync.disableRequest = syncRef(vault)
      }
    case .off:
      Button("Turn On Sync…") { sync.sheet = .enable(syncRef(vault)) }
    default:
      Button("Turn On Sync…") {}.disabled(true)
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

/// Vault files that share a vault id or a vault key, grouped by id and then by
/// key, with a Show in Finder button for each file. A file that shares both is
/// in both groups.
struct DuplicateVaultsSheet: View {
  let duplicates: [DuplicateVaultInfo]
  let duplicateKeys: [DuplicateVaultKeyInfo]

  @Environment(\.dismiss) private var dismiss

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Vaults Not Shown")
        .font(.headline)

      Text(
        "Vault files with duplicate ids or keys found. Delete or move the duplicates out of the vault folder, then reopen this app."
      )
      .font(.callout)
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      ScrollView {
        VStack(alignment: .leading, spacing: 12) {
          ForEach(duplicates, id: \.vaultId) { duplicate in
            DuplicateFilesGroup(title: "Vault id \(duplicate.vaultId)", paths: duplicate.paths)
          }
          ForEach(duplicateKeys, id: \.key) { duplicate in
            DuplicateFilesGroup(title: "Vault key \(duplicate.key)", paths: duplicate.paths)
          }
        }
      }
      .frame(maxHeight: 320)

      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(20)
    .frame(width: 520)
  }
}

/// Paths of vault files that share one claim, under `title`, with a Show in
/// Finder button for each file.
private struct DuplicateFilesGroup: View {
  let title: String
  let paths: [String]

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      Text(title)
        .font(.caption)
        .foregroundStyle(.secondary)
        .textSelection(.enabled)
      ForEach(paths, id: \.self) { path in
        HStack(spacing: 8) {
          Text(path)
            .font(.callout.monospaced())
            .lineLimit(1)
            .truncationMode(.middle)
            .help(path)
          Spacer(minLength: 0)
          Button("Show in Finder") {
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
          }
          .controlSize(.small)
        }
      }
    }
    .padding(10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
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
