import AppKit
import AxoPassFFI
import SwiftUI

struct SshPane: View {
  @Bindable var model: SshModel
  @State private var showingAgents = false

  var body: some View {
    List(selection: $model.selectedFingerprint) {
      if let err = model.loadError {
        Label(err, systemImage: "exclamationmark.triangle")
          .font(.caption)
          .foregroundStyle(.red)
      } else if model.keys.isEmpty {
        Text("No SSH keys found").foregroundStyle(.secondary)
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
    .navigationTitle("SSH")
    .navigationSplitViewColumnWidth(min: 200, ideal: 260)
    .safeAreaInset(edge: .bottom) { agentSummaryBar }
    .toolbar {
      ToolbarItem {
        Button {
          Task { await model.addManagedKey() }
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
    .task { await model.reload() }
    // The file may be edited outside the app, so re-read it on reactivation.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.refreshConfStatus()
    }
  }

  /// Compact agent state at the foot of the list. The controls live in the
  /// agent sheet this opens.
  private var agentSummaryBar: some View {
    Button {
      showingAgents = true
    } label: {
      HStack(spacing: 6) {
        Circle()
          .fill(SshAgentStyle.color(model.axoAgentStatus?.status))
          .frame(width: 7, height: 7)
        Text(agentSummary)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
        Spacer()
        Image(systemName: "chevron.right")
          .font(.caption2)
          .foregroundStyle(.tertiary)
      }
      .contentShape(Rectangle())
      .padding(.horizontal, 12)
      .padding(.vertical, 8)
    }
    .buttonStyle(.plain)
    .background(.bar)
    .overlay(alignment: .top) { Divider() }
    .help("SSH agent status")
  }

  private var agentSummary: String {
    "Axo agent \(SshAgentStyle.label(model.axoAgentStatus?.status).lowercased())"
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
        if key.isManaged {
          Image(systemName: "lock.shield")
            .foregroundStyle(.blue)
            .help("Secure Enclave")
        }
        Spacer(minLength: 6)
        if !key.agents.isEmpty {
          SshKeyBadge(text: "In agent", tint: .green)
        } else if !key.hasSavedPassword && key.location == .sshDir {
          SshKeyBadge(text: "No password")
        }
      }
      Text(subtitle)
        .font(.caption)
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
    case .vault: return "vault"
    case .sshDir: return "~/.ssh"
    case .transient: return "agent only"
    }
  }
}
