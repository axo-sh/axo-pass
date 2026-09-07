import AppKit
import AxoPassFFI
import SwiftUI

/// Status and controls for the SSH agents. The `IdentityAgent` line that
/// points ssh at one of them is configured in Settings ▸ SSH.
struct SshAgentSheet: View {
  let model: SshModel

  @Environment(\.dismiss) private var dismiss
  @Environment(\.openSettings) private var openSettings

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      header
      Divider()

      axoAgentRow
      Divider()
      systemAgentRow
      if let error = model.agentError {
        Label(error, systemImage: "xmark.circle.fill")
          .font(.caption)
          .foregroundStyle(.red)
          .lineLimit(3)
          .fixedSize(horizontal: false, vertical: true)
      }

      Divider()
      HStack {
        Button("Refresh") { Task { await model.reload() } }
        Spacer()
        Button("SSH Settings…") {
          dismiss()
          NSApp.activate(ignoringOtherApps: true)
          openSettings()
        }
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(20)
    .frame(width: 420)
  }

  private var header: some View {
    HStack(spacing: 10) {
      Image(systemName: "bolt.horizontal.circle")
        .font(.title2)
        .foregroundStyle(.tint)
      Text("SSH Agents").font(.headline)
      Spacer()
    }
  }

  private var axoAgentRow: some View {
    HStack(alignment: .top) {
      titleAndPath("Axo Pass Agent", path: model.axoAgentStatus?.socketPath)
      Spacer()
      statusLabel(model.axoAgentStatus?.status)
      if model.isTogglingAgent {
        ProgressView().controlSize(.small)
      } else if model.axoAgentStatus?.status == .running {
        Button("Stop") { Task { await model.stopAgent() } }
          .controlSize(.small)
      } else {
        Button("Start") { Task { await model.startAgent() } }
          .controlSize(.small)
      }
    }
  }

  private var systemAgentRow: some View {
    HStack(alignment: .top) {
      titleAndPath("System Agent", path: model.systemAgentStatus?.socketPath)
      Spacer()
      statusLabel(model.systemAgentStatus?.status)
    }
  }

  /// An agent's name over its socket path. The system agent has no socket
  /// when `SSH_AUTH_SOCK` is unset.
  private func titleAndPath(_ title: String, path: String?) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(title)
      Text(path ?? "No socket")
        .font(.caption.monospaced())
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .truncationMode(.middle)
        .textSelection(.enabled)
    }
  }

  @ViewBuilder
  private func statusLabel(_ status: SshAgentStatus?) -> some View {
    if let status {
      Label(SshAgentStyle.label(status), systemImage: SshAgentStyle.icon(status))
        .foregroundStyle(SshAgentStyle.color(status))
        .font(.caption)
    }
  }
}

/// Shared presentation for `SshAgentStatus`. A nil status means the agent has
/// not been checked yet.
enum SshAgentStyle {
  static func label(_ status: SshAgentStatus?) -> String {
    switch status {
    case .running: return "Running"
    case .notRunning: return "Not Running"
    case .staleSocket: return "Stale Socket"
    case nil: return "Unknown"
    }
  }

  static func icon(_ status: SshAgentStatus?) -> String {
    switch status {
    case .running: return "checkmark.circle.fill"
    case .notRunning: return "circle"
    case .staleSocket: return "exclamationmark.triangle.fill"
    case nil: return "questionmark.circle"
    }
  }

  static func color(_ status: SshAgentStatus?) -> Color {
    switch status {
    case .running: return .green
    case .notRunning: return .secondary
    case .staleSocket: return .orange
    case nil: return .secondary
    }
  }
}
