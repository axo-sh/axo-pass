import AppKit
import AxoPassFFI
import SwiftUI

/// Number of vaults listed before "Show more".
private let collapsedVaultLimit = 8

/// Grouping of the Library section.
private enum LibraryMode: String {
  case vaults
  case types
}

struct VaultsSidebar: View {
  let sshModel: SshModel
  let gpgModel: GpgModel
  let ageModel: AgeModel

  @Environment(VaultsModel.self) private var model
  @Environment(SyncModel.self) private var sync
  @Environment(IssuesModel.self) private var issues
  @Environment(WindowRequests.self) private var windows
  @State private var showingNewVaultSheet = false
  @State private var deletingVault: SyncVaultRef? = nil
  @State private var renamingVaultKey: String? = nil
  @State private var exportingVaultKey: String? = nil
  @State private var versionsVaultKey: String? = nil
  @AppStorage("sidebarLibraryExpanded") private var libraryExpanded = true
  @AppStorage("sidebarSourcesExpanded") private var sourcesExpanded = true
  @AppStorage("sidebarLibraryMode") private var libraryMode = LibraryMode.vaults
  @AppStorage("sidebarShowAllVaults") private var showAllVaults = false
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

  /// Open the command palette centered under the window's toolbar.
  private func showPalette() {
    guard let window = NSApp.keyWindow else { return }
    let toolbarBottom = window.frame.minY + window.contentLayoutRect.maxY
    let anchor = NSRect(x: window.frame.midX, y: toolbarBottom, width: 0, height: 0)
    windows.togglePalette(anchor, window.screen)
  }

  var body: some View {
    List(selection: selectionBinding) {
      todayRow
      Label {
        Text("Activity")
      } icon: {
        Image(systemName: "water.waves")
      }
      .tint(.blue)
      .tag(SidebarDestination.activity)

      Section {
        if libraryExpanded {
          LibraryModePicker(mode: $libraryMode)
          switch libraryMode {
          case .vaults: vaultItems
          case .types: typeItems
          }
        }
      } header: {
        SidebarSectionHeader("Library", isExpanded: libraryExpanded) {
          withAnimation(.snappy(duration: 0.2)) { libraryExpanded.toggle() }
        }
      }
      // The header has its own chevron, so hide the system disclosure button.
      .collapsible(false)

      Section {
        if sourcesExpanded {
          sourceRow("SSH", source: .ssh, count: sshModel.keys.count)
            .tag(SidebarDestination.ssh)
          sourceRow("GPG", source: .gpg, count: gpgModel.keys.count)
            .tag(SidebarDestination.gpg)
          sourceRow("Age", source: nil, count: ageModel.keys.count)
            .tag(SidebarDestination.age)
        }
      } header: {
        SidebarSectionHeader("Sources", isExpanded: sourcesExpanded) {
          withAnimation(.snappy(duration: 0.2)) { sourcesExpanded.toggle() }
        }
      }
      .collapsible(false)
    }
    .listStyle(.sidebar)
    .navigationSplitViewColumnWidth(min: 160, ideal: 200)
    .toolbar {
      ToolbarItemGroup(placement: .primaryAction) {
        // Push the search button to the trailing edge of the sidebar toolbar.
        Spacer()
        Button {
          showPalette()
        } label: {
          Label("Search", systemImage: "magnifyingglass")
        }
        .keyboardShortcut("k")
        .help("Search all items. ⌘K")
      }
    }
    .safeAreaInset(edge: .bottom) {
      HStack(spacing: 8) {
        Button {
          model.reload()
        } label: {
          Label("Reload", systemImage: "arrow.clockwise")
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
      "Delete \(deletingVault?.name ?? "this vault") from this Mac?",
      isPresented: Binding(
        get: { deletingVault != nil }, set: { if !$0 { deletingVault = nil } }),
      presenting: deletingVault
    ) { vault in
      Button("Delete", role: .destructive) {
        Task { await model.deleteVault(vault.key) }
      }
      Button("Cancel", role: .cancel) {}
        .keyboardShortcut(.defaultAction)
    } message: { vault in
      Text(sync.state(vault.key)?.isOn == true ? syncedVaultDeleteMessage : vaultDeleteMessage)
    }
    // Read the sync state of each vault after the unlock and when the list
    // changes.
    .task(id: model.vaults) {
      await sync.reloadAll()
      // Saved passphrases are not listed while locked, so read them now.
      if !checkedStartSelection {
        checkedStartSelection = true
        await issues.refreshAll()
        // Source rows show key counts before their panes are opened.
        await sshModel.reload()
        await gpgModel.reload()
        await ageModel.reload()
      }
    }
    // Item type counts need the items of every vault.
    .task(id: TypeCountsTrigger(mode: libraryMode, vaults: model.vaults)) {
      if libraryMode == .types { await model.loadAllItems() }
    }
  }

  /// Today row with the count of counted issues. The count is red if the worst
  /// issue is broken.
  private var todayRow: some View {
    HStack(spacing: 4) {
      Label {
        Text("Today")
      } icon: {
        Image(systemName: "sun.max.fill")
      }
      .tint(.orange)
      Spacer(minLength: 0)
      let count = issues.countedIssues.count
      if count > 0 {
        let broken = issues.worstSeverity == .broken
        Text("\(count)")
          .font(.caption.weight(.semibold))
          .monospacedDigit()
          .foregroundStyle(broken ? Color.white : Color.secondary)
          .padding(.horizontal, 6)
          .padding(.vertical, 1)
          .background(
            Capsule().fill(broken ? Color.red : Color.secondary.opacity(0.2))
          )
      }
    }
    .tag(SidebarDestination.today)
  }

  /// Source row with a status dot and the key count. The dot is red for a
  /// broken issue, orange for another counted issue, and green if the source
  /// has keys and no counted issue.
  private func sourceRow(
    _ title: String, source: IssueSource?, count: Int
  ) -> some View {
    let issue = source.flatMap { source in
      issues.countedIssues.first { $0.source == source }
    }
    let dotColor: Color?
    if let issue {
      dotColor = issue.severity == .broken ? .red : .orange
    } else {
      dotColor = count > 0 ? .green : nil
    }
    return HStack(spacing: 6) {
      Text(title)
      Spacer(minLength: 0)
      if let dotColor {
        Circle()
          .fill(dotColor)
          .frame(width: 6, height: 6)
          .help(issue?.title ?? "")
      }
      if count > 0 {
        Text("\(count)")
          .monospacedDigit()
          .foregroundStyle(.secondary)
      }
    }
  }

  private var allSecretsRow: some View {
    Label {
      Text("All Secrets")
    } icon: {
      Image(systemName: "square.stack.3d.up.fill")
    }
    .tint(.secondary)
    .tag(SidebarDestination.vault(allSecretsKey))
  }

  /// Vaults listed while the list is collapsed. The selected vault is always
  /// listed.
  private var visibleVaults: [VaultInfo] {
    guard !showAllVaults, model.vaults.count > collapsedVaultLimit else { return model.vaults }
    let shown = Array(model.vaults.prefix(collapsedVaultLimit))
    if let selected = model.selectedVault, !shown.contains(where: { $0.key == selected.key }) {
      return shown + [selected]
    }
    return shown
  }

  @ViewBuilder
  private var typeItems: some View {
    allSecretsRow
    ForEach(ItemType.allCases, id: \.self) { type in
      HStack(spacing: 4) {
        Label {
          Text(type.title)
        } icon: {
          Image(systemName: type.systemImage)
        }
        .tint(.secondary)
        Spacer(minLength: 0)
        if model.isPendingSelection(.itemType(type)) {
          DelayedProgressView(size: .mini, expands: false)
        } else if let count = model.itemCount(of: type), count > 0 {
          Text("\(count)")
            .monospacedDigit()
            .foregroundStyle(.secondary)
        }
      }
      .tag(SidebarDestination.itemType(type))
    }
  }

  @ViewBuilder
  private var vaultItems: some View {
    if model.vaults.isEmpty {
      Text("No vaults")
        .font(.caption)
        .foregroundStyle(.secondary)
    } else {
      allSecretsRow

      ForEach(visibleVaults, id: \.key) { vault in
        HStack(spacing: 4) {
          Label {
            Text(vault.name ?? vault.key)
          } icon: {
            VaultBadge(name: vault.name ?? vault.key, key: vault.key)
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
          Button("History…") { versionsVaultKey = vault.key }
          syncMenuItem(vault)
          Button("Delete…", role: .destructive) { deletingVault = syncRef(vault) }
        }
      }

      if model.vaults.count > collapsedVaultLimit {
        Button {
          withAnimation(.snappy(duration: 0.2)) { showAllVaults.toggle() }
        } label: {
          Label(showAllVaults ? "Show fewer" : "Show more", systemImage: "ellipsis")
            .foregroundStyle(.secondary)
        }
        .buttonStyle(.plain)
      }

      Label {
        Text("Recently Deleted")
          .foregroundStyle(.secondary)
      } icon: {
        Image(systemName: "trash")
      }
      .tint(.secondary)
      .tag(SidebarDestination.recentlyDeleted)

      Button {
        showingNewVaultSheet = true
      } label: {
        Label("New Vault", systemImage: "plus")
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

/// Task id for loading the item type counts.
private struct TypeCountsTrigger: Equatable {
  let mode: LibraryMode
  let vaults: [VaultInfo]
}

/// Section title with a chevron. A tap expands or collapses the section.
private struct SidebarSectionHeader: View {
  let title: String
  let isExpanded: Bool
  let onTap: () -> Void

  init(_ title: String, isExpanded: Bool, onTap: @escaping () -> Void) {
    self.title = title
    self.isExpanded = isExpanded
    self.onTap = onTap
  }

  var body: some View {
    HStack(spacing: 4) {
      Text(title)
        .font(.subheadline)
        .fontWeight(.medium)
      Image(systemName: "chevron.down")
        .font(.caption2.weight(.semibold))
        .rotationEffect(.degrees(isExpanded ? 0 : -90))
      Spacer(minLength: 0)
    }
    .foregroundStyle(.secondary)
    .contentShape(.rect)
    .padding(.top, 6)
    .onTapGesture(perform: onTap)
    .accessibilityAddTraits(.isButton)
    .accessibilityValue(isExpanded ? "Expanded" : "Collapsed")
  }
}

/// Segmented control that switches the Library section between vaults and
/// item types.
private struct LibraryModePicker: View {
  @Binding var mode: LibraryMode
  @Namespace private var selection

  var body: some View {
    HStack(spacing: 2) {
      segment(.vaults, title: "Vaults", systemImage: "archivebox")
      segment(.types, title: "Types", systemImage: "square.3.layers.3d")
    }
    .padding(2)
    .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 8))
    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.primary.opacity(0.08)))
    .padding(.vertical, 4)
  }

  private func segment(_ value: LibraryMode, title: String, systemImage: String) -> some View {
    let isSelected = mode == value
    return Button {
      withAnimation(.snappy(duration: 0.2)) { mode = value }
    } label: {
      Label(title, systemImage: systemImage)
        .font(.callout)
        .foregroundStyle(isSelected ? .primary : .secondary)
        .frame(maxWidth: .infinity)
        .padding(.vertical, 4)
        .background {
          if isSelected {
            RoundedRectangle(cornerRadius: 6)
              .fill(Color.primary.opacity(0.1))
              .matchedGeometryEffect(id: "selection", in: selection)
          }
        }
        .contentShape(.rect)
    }
    .buttonStyle(.plain)
    .accessibilityAddTraits(isSelected ? .isSelected : [])
  }
}

/// Rounded square with the first letter of a vault name. The color is derived
/// from the vault key, so it is the same on every launch.
struct VaultBadge: View {
  let name: String
  let key: String

  private static let colors: [Color] = [
    .purple, .orange, .indigo, .pink, .red, .blue, .green, .brown, .gray, .teal, .mint, .cyan,
  ]

  private var color: Color {
    let sum = key.unicodeScalars.reduce(0) { $0 &+ Int($1.value) }
    return Self.colors[sum % Self.colors.count]
  }

  var body: some View {
    Text(name.first.map { String($0).uppercased() } ?? "?")
      .font(.system(size: 10, weight: .bold))
      .foregroundStyle(.white)
      .frame(width: 16, height: 16)
      .background(color.gradient, in: RoundedRectangle(cornerRadius: 4))
      .accessibilityHidden(true)
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
