import AppKit
import AxoPassFFI
import SwiftUI

struct SshPane: View {
  @Bindable var model: SshModel
  @State private var showingAgents = false
  @State private var showingAddKeyConfirmation = false

  var body: some View {
    List(selection: $model.selectedFingerprint) {
      if let err = model.loadError {
        Label(err, systemImage: "exclamationmark.triangle")
          .font(.caption)
          .foregroundStyle(.red)
      } else {
        ForEach(model.keys, id: \.fingerprintSha256) { key in
          SshKeyRow(key: key)
            .contextMenu {
              if key.isManaged {
                Button("Delete", role: .destructive) {
                  Task { await model.deleteManagedKey(fingerprintSha256: key.fingerprintSha256) }
                }
              }
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
        Button {
          showingAddKeyConfirmation = true
        } label: {
          Label("New Managed Key", systemImage: "plus")
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
    .task { await model.reload() }
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

  /// Shown with no keys. "Generate Key" opens the sheet of the toolbar button.
  /// Keys in `~/.ssh` are listed without an import, so the import button stays
  /// disabled until the core has one.
  private var emptyState: some View {
    ContentUnavailableView {
      Label("No SSH Keys", systemImage: "key.horizontal")
    } description: {
      Text("Generate a key that stays in the Secure Enclave, or add keys to ~/.ssh.")
    } actions: {
      Button("Generate Key") { showingAddKeyConfirmation = true }
      Button("Import from ~/.ssh") {}
        .disabled(true)
        .help("Keys in ~/.ssh are listed here without an import. None were found.")
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
    var parts: [String] = [keyTypeLabel, locationLabel]
    if let comment = key.comment, !comment.isEmpty { parts.append(comment) }
    return parts.joined(separator: " · ")
  }

  private var keyTypeLabel: String {
    switch key.keyType {
    case .rsa: return "rsa"
    case .ed25519: return "ed25519"
    case .ecdsa: return "ecdsa"
    case .dsa: return "dsa"
    case .unknown: return "unknown"
    }
  }

  private var locationLabel: String {
    switch key.location {
    case .vault: return "secure enclave"
    case .sshDir: return "~/.ssh"
    case .transient: return "agent only"
    }
  }
}
