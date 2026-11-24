import AppKit
import AxoPassFFI
import SwiftUI

struct SshPane: View {
  @Bindable var model: SshModel
  @Environment(VaultsModel.self) private var vaults
  @State private var showingAgents = false
  @State private var showingAddKeyConfirmation = false
  @State private var showingGenerateVaultKey = false
  @State private var showingImportVaultKey = false
  @State private var exportTarget: SshKeyExportTarget? = nil

  var body: some View {
    List(selection: $model.selectedFingerprint) {
      if let err = model.loadError {
        Label(err, systemImage: "exclamationmark.circle")
          .font(.caption)
          .foregroundStyle(.red)
      } else {
        ForEach(model.keys, id: \.fingerprintSha256) { key in
          SshKeyRow(key: key, place: place(of: key))
            .contextMenu {
              if key.isManaged {
                Button("Delete", role: .destructive) {
                  Task { await model.deleteManagedKey(fingerprintSha256: key.fingerprintSha256) }
                }
              }
              VaultKeyMenuItems(key: key) { exportTarget = $0 }
            }
        }
      }
    }
    .overlay {
      if model.loadError == nil && model.keys.isEmpty && !model.isLoading {
        emptyState
      }
    }
    .safeAreaInset(edge: .bottom) { agentSummaryBar }
    .paneBackground()
    .navigationTitle("SSH")
    .navigationSplitViewColumnWidth(min: 200, ideal: 260)
    .toolbar {
      ToolbarItem {
        Menu {
          Button("Generate Vault Key…") { showingGenerateVaultKey = true }
          Button("Import Key from File…") { showingImportVaultKey = true }
          Divider()
          Button("New Secure Enclave Key…") { showingAddKeyConfirmation = true }
        } label: {
          Label("Add Key", systemImage: "plus")
        }
      }
      ToolbarItem {
        Button {
          Task { await model.reload() }
        } label: {
          Label("Reload", systemImage: "arrow.clockwise")
        }
      }
    }
    .sheet(isPresented: $showingAgents) {
      SshAgentSheet(model: model)
    }
    .sheet(isPresented: $showingAddKeyConfirmation) {
      AddManagedKeySheet(model: model)
    }
    .sheet(isPresented: $showingGenerateVaultKey) {
      AddVaultKeySheet(mode: .generate, ssh: model)
    }
    .sheet(isPresented: $showingImportVaultKey) {
      AddVaultKeySheet(mode: .importFile, ssh: model)
    }
    .sheet(item: $exportTarget) { target in
      ExportSshKeySheet(target: target)
    }
    .task { await model.reload() }
    // Item titles of the vault keys come from the vaults' items.
    .task(id: model.keys.compactMap { $0.vaultKey?.vaultKey }) {
      await vaults.loadItemsForSshKeys(model.keys)
    }
    // The CLI can start or stop the agent while the window is visible, so poll while the pane
    // is on screen.
    .task {
      while !Task.isCancelled {
        try? await Task.sleep(for: .seconds(2))
        model.refreshAgentStatus()
      }
    }
    // The file may be edited outside the app, so re-read it on reactivation.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.refreshConfStatus()
      model.refreshAgentStatus()
    }
  }

  /// Vault and item of a vault key, for the row subtitle. Nil for other keys.
  private func place(of key: SshKeyEntry) -> String? {
    guard let location = key.vaultKey else { return nil }
    let place = vaults.sshKeyPlace(location)
    return "\(place.vault) · \(place.item)"
  }

  /// Shown with no keys. The buttons open the sheets of the toolbar menu. Keys
  /// in `~/.ssh` are listed without an import, so a key file is imported only
  /// to store it in a vault.
  private var emptyState: some View {
    ContentUnavailableView {
      Label("No SSH Keys", systemImage: KeyIcon.ssh.symbol)
    } description: {
      Text(
        "Generate a key in a vault, import a key file, or create a key that stays in the "
          + "Secure Enclave. Keys in ~/.ssh are listed without an import.")
    } actions: {
      Button("Generate Vault Key") { showingGenerateVaultKey = true }
      Button("Import Key from File") { showingImportVaultKey = true }
      Button("New Secure Enclave Key") { showingAddKeyConfirmation = true }
    }
  }

  /// SSH issues at the foot of the list. The controls live in the agent sheet
  /// this opens.
  private var agentSummaryBar: some View {
    SourceStatusBar(
      source: .ssh,
      healthyLabel: "Axo agent \(SshAgentStyle.label(model.axoAgentStatus?.status).lowercased())",
      healthyColor: SshAgentStyle.color(model.axoAgentStatus?.status),
      help: "SSH agent status"
    ) {
      showingAgents = true
    }
  }
}

extension SshKeyEntry: Identifiable {
  public var id: String { fingerprintSha256 }
}

private struct SshKeyRow: View {
  let key: SshKeyEntry
  /// Vault and item of a vault key.
  let place: String?

  var body: some View {
    VStack(alignment: .leading, spacing: 2) {
      HStack(spacing: 4) {
        Text(key.name).fontWeight(.semibold).lineLimit(1)
        Spacer(minLength: 6)
        if !key.agents.isEmpty {
          KeyBadge(text: "In agent", tint: .green)
        } else if !key.hasSavedPassword && key.location == .sshDir {
          KeyBadge(text: "No password")
        }
      }
      Text(subtitle)
        .font(.subheadline)
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .truncationMode(.middle)
    }
    .padding(.vertical, 3)
  }

  private var subtitle: String {
    var parts: [String] = [sshKeyTypeLabel(key.keyType), locationLabel]
    if let place { parts.append(place) }
    if let comment = key.comment, !comment.isEmpty, comment != key.name { parts.append(comment) }
    return parts.joined(separator: " · ")
  }

  private var locationLabel: String {
    switch key.location {
    case .secureEnclave: return "secure enclave"
    case .vaultKey: return "vault"
    case .sshDir: return "~/.ssh"
    case .transient: return "agent only"
    }
  }
}
