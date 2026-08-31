import AxoPassFFI
import SwiftUI

struct SshPane: View {
  @State private var model = SshModel()
  @State private var showingSavePasswordSheet: SshKeyEntry? = nil

  var body: some View {
    List {
      Section("Agents") {
        agentStatusRow("Axo Pass Agent", status: model.axoAgentStatus)
        agentStatusRow("System Agent", status: model.systemAgentStatus)
      }

      Section("Keys") {
        if let err = model.loadError {
          Label(err, systemImage: "exclamationmark.triangle")
            .font(.caption)
            .foregroundStyle(.red)
        } else if model.keys.isEmpty {
          Text("No SSH keys found").foregroundStyle(.secondary)
        } else {
          ForEach(model.keys, id: \.fingerprintSha256) { key in
            SshKeyRow(key: key) {
              showingSavePasswordSheet = key
            }
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
    }
    .navigationTitle("SSH")
    .navigationSplitViewColumnWidth(min: 200, ideal: 260)
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
    .sheet(item: $showingSavePasswordSheet) { key in
      SavePasswordSheet(keyName: key.name) { password in
        await model.savePassword(fingerprint: key.fingerprintSha256, password: password)
      }
    }
    .task { await model.reload() }
  }

  @ViewBuilder
  private func agentStatusRow(_ title: String, status: SshAgentStatusResponse?) -> some View {
    HStack {
      Text(title)
      Spacer()
      if let status {
        Label(statusLabel(status.status), systemImage: statusIcon(status.status))
          .foregroundStyle(statusColor(status.status))
          .font(.caption)
      }
    }
  }

  private func statusLabel(_ status: SshAgentStatus) -> String {
    switch status {
    case .running: return "Running"
    case .notRunning: return "Not Running"
    case .staleSocket: return "Stale Socket"
    }
  }

  private func statusIcon(_ status: SshAgentStatus) -> String {
    switch status {
    case .running: return "checkmark.circle.fill"
    case .notRunning: return "circle"
    case .staleSocket: return "exclamationmark.triangle.fill"
    }
  }

  private func statusColor(_ status: SshAgentStatus) -> Color {
    switch status {
    case .running: return .green
    case .notRunning: return .secondary
    case .staleSocket: return .orange
    }
  }
}

extension SshKeyEntry: Identifiable {
  public var id: String { fingerprintSha256 }
}

private struct SshKeyRow: View {
  let key: SshKeyEntry
  let onSavePassword: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      HStack {
        Text(key.name).fontWeight(.semibold)
        if key.isManaged {
          Label("Managed", systemImage: "lock.shield").labelStyle(.iconOnly).foregroundStyle(.blue)
        }
        Spacer()
        if !key.hasSavedPassword {
          Button("Save Password", action: onSavePassword)
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
      }
      Text(key.fingerprintSha256)
        .font(.caption)
        .foregroundStyle(.secondary)
        .textSelection(.enabled)
      HStack(spacing: 6) {
        locationBadge
        ForEach(key.agents, id: \.self) { agent in
          Text(agent == .systemAgent ? "system agent" : "axo agent")
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(.tertiary, in: Capsule())
        }
      }
    }
    .padding(.vertical, 4)
  }

  private var locationBadge: some View {
    let label: String =
      switch key.location {
      case .vault: "vault"
      case .sshDir: "~/.ssh"
      case .transient: "agent only"
      }
    return Text(label)
      .font(.caption2)
      .padding(.horizontal, 6)
      .padding(.vertical, 2)
      .background(.quaternary, in: Capsule())
  }
}

private struct SavePasswordSheet: View {
  let keyName: String
  let onSubmit: (_ password: String) async -> Bool

  @Environment(\.dismiss) private var dismiss
  @State private var password: String = ""
  @State private var isSubmitting = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Save Password for \(keyName)").font(.headline)
      SecureField("Password", text: $password)

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Save") {
          Task {
            isSubmitting = true
            if await onSubmit(password) { dismiss() }
            isSubmitting = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || password.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 320)
  }
}
