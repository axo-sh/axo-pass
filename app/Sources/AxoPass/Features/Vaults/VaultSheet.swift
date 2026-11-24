import AxoPassFFI
import SwiftUI

extension TitleSheetRequest {
  /// Rename sheet of vault `vault`. The sheet reads the vault name when it
  /// opens. A refused rename keeps the input in the sheet and reads the name
  /// again.
  @MainActor
  static func renameVault(_ vault: VaultInfo, model: VaultsModel) async -> Self {
    let reads = SheetReads(await model.vaultReads(vault.key))
    return TitleSheetRequest(
      heading: "Rename", actionLabel: "Rename", initialTitle: vault.name ?? vault.key,
      fieldLabel: "Name", vault: SyncVaultRef(key: vault.key, name: vault.name ?? vault.key)
    ) { name in
      do {
        try await model.renameVault(vaultKey: vault.key, newName: name, reads: reads.reads)
        return nil
      } catch {
        guard let refusal = EditRefusal(error) else { return error.userMessage }
        reads.reads = await model.vaultReads(vault.key)
        return refusal.sheetMessage(action: "Rename")
      }
    }
  }

  /// Key change sheet of vault `vault`.
  @MainActor
  static func changeVaultKey(_ vault: VaultInfo, model: VaultsModel) -> Self {
    TitleSheetRequest(
      heading: "Change Key", actionLabel: "Change", initialTitle: vault.key,
      fieldLabel: "Key", footnote: "a-z, 0-9, -, _. \(keyChangeWarning)",
      vault: SyncVaultRef(key: vault.key, name: vault.name ?? vault.key)
    ) { key in
      await model.changeVaultKey(vaultKey: vault.key, newKey: key)
        ? nil : (model.actionError ?? "Failed to change vault key.")
    }
  }
}

/// Title of a sheet about one vault: the vault badge and name, then the
/// section, such as "Vault > History". Without a section, the title is the
/// vault alone.
struct VaultSheetTitle: View {
  let name: String
  let key: String
  var section: String? = nil

  var body: some View {
    HStack(spacing: 6) {
      VaultBadge(name: name, key: key)
      Text(name)
        .lineLimit(1)
        .truncationMode(.middle)
      if let section {
        Image(systemName: "chevron.right")
          .font(.caption)
          .foregroundStyle(.tertiary)
        Text(section)
          .lineLimit(1)
      }
    }
    .font(.title2.weight(.semibold))
  }
}

/// Information and actions of one vault: name, key, sync status, AutoFill,
/// rename, key change, backup, history, sync, and delete. Opened from the vault
/// list in Settings > Vaults and from the sidebar. Sync status opens in a sheet
/// above this one. Turn-on replaces this sheet in the same window.
struct VaultSheet: View {
  @Environment(VaultsModel.self) private var model
  @Environment(SyncModel.self) private var sync
  @Environment(\.dismiss) private var dismiss

  let vault: SyncVaultRef

  @State private var titleSheet: TitleSheetRequest? = nil
  @State private var exporting = false
  @State private var showingVersions = false
  @State private var showingSyncStatus = false
  @State private var confirmingDelete = false

  /// Vault as listed, or nil after the vault is deleted or its key changed.
  private var info: VaultInfo? {
    model.vaults.first { $0.key == vault.key }
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      VaultSheetTitle(name: info?.name ?? vault.name, key: vault.key)
        .padding([.horizontal, .top], 20)

      Form {
        infoSection
        actionsSection
      }
      .formStyle(.grouped)
      .scrollBounceBehavior(.basedOnSize)

      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
      .padding([.horizontal, .bottom], 20)
      .padding(.top, 8)
    }
    .frame(width: 480)
    .onChange(of: info == nil) { _, gone in
      if gone { dismiss() }
    }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .task { await sync.reload(vault.key) }
    .sheet(item: $titleSheet) { request in
      TitleSheet(request: request)
    }
    .sheet(isPresented: $exporting) {
      VaultExportSheet(model: model, only: vault.key)
    }
    .sheet(isPresented: $showingSyncStatus) {
      SyncStatusSheet(vault: vault, host: sync.sheetHost)
    }
    .sheet(isPresented: $showingVersions) {
      VaultVersionsSheet(vaultKey: vault.key, vaultName: info?.name ?? vault.name)
    }
    .confirmationDialog(
      "Delete \(vault.name) from this Mac?", isPresented: $confirmingDelete
    ) {
      Button("Delete", role: .destructive) {
        Task { await model.deleteVault(vault.key) }
      }
      Button("Cancel", role: .cancel) {}
        .keyboardShortcut(.defaultAction)
    } message: {
      Text(sync.state(vault.key)?.isOn == true ? syncedVaultDeleteMessage : vaultDeleteMessage)
    }
  }

  // MARK: - Information

  private var infoSection: some View {
    Section {
      LabeledContent("Name") {
        HStack(spacing: 8) {
          Text(info?.name ?? vault.name).textSelection(.enabled)
          Button("Rename…") { rename() }
            .controlSize(.small)
            .disabled(info == nil)
        }
      }
      LabeledContent("Key") {
        HStack(spacing: 8) {
          Text(vault.key).textSelection(.enabled)
          Button("Change…") {
            if let info { titleSheet = .changeVaultKey(info, model: model) }
          }
          .controlSize(.small)
          .disabled(info == nil)
        }
      }
      if let id = info?.id {
        LabeledContent("Id") { Text(id).textSelection(.enabled) }
      }
      LabeledContent("Sync") {
        HStack(spacing: 8) {
          syncLabel
          syncAction
            .controlSize(.small)
        }
      }
      Toggle(
        "Suggest in AutoFill",
        isOn: Binding(
          get: { !model.autofillExcludedVaults.contains(vault.key) },
          set: { model.setAutofillExcluded(vaultKey: vault.key, excluded: !$0) }))
    }
  }

  @ViewBuilder
  private var syncLabel: some View {
    switch sync.state(vault.key) {
    case .on:
      if let report = sync.report(vault.key) {
        let summary = syncStatusSummary(report)
        HStack(spacing: 6) {
          Circle().fill(summary.color).frame(width: 8, height: 8)
          Text(summary.line)
        }
        .help(summary.help)
      } else {
        Text("On")
      }
    case .off:
      Text("Local").foregroundStyle(.secondary)
        .help("Not synced")
    case .turningOff:
      Text("Turning off").foregroundStyle(.secondary)
        .help(syncDisableInProgressMessage)
    case .unknown(let message):
      Text("Unknown").foregroundStyle(.secondary)
        .help("Could not read sync status: \(message)")
    case .none:
      ProgressView().controlSize(.small)
    }
  }

  // MARK: - Actions

  private var actionsSection: some View {
    Section {
      Button("Export Backup…") { exporting = true }
      Button("History…") { showingVersions = true }
      Button("Delete…", role: .destructive) { confirmingDelete = true }
    }
  }

  /// Sync status of a synced vault, or the turn-on of a vault with sync off.
  /// Disabled while the state is not read, failed to read, or an earlier
  /// turn-off waits for the synced folder.
  @ViewBuilder
  private var syncAction: some View {
    switch sync.state(vault.key) {
    case .on:
      Button("Status…") { showingSyncStatus = true }
    case .off:
      Button("Turn On…") { sync.sheet = .enable(vault) }
    default:
      Button("Turn On…") {}.disabled(true)
    }
  }

  private func rename() {
    guard let info else { return }
    Task { titleSheet = await .renameVault(info, model: model) }
  }
}
