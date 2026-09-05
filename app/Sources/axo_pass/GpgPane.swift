import AppKit
import AxoPassFFI
import SwiftUI

struct GpgPane: View {
  @State private var model = GpgModel()
  @State private var showingSetup = false

  var body: some View {
    List {
      Section {
        agentConfRow
      } header: {
        HStack {
          Text("GPG Agent")
          Spacer()
          HelpLink { showingSetup = true }
            .controlSize(.mini)
        }
      }

      Section("GPG") {
        HStack {
          Button {
            Task { await model.testIntegration() }
          } label: {
            if model.isTesting {
              Label("Testing…", systemImage: "hourglass")
            } else {
              Label("Test GPG Integration", systemImage: "checkmark.seal")
            }
          }
          .disabled(model.isTesting)

          if let result = model.testResult {
            switch result {
            case .success:
              Label("Signing works", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
            case .failure(let message):
              Label(message, systemImage: "xmark.circle.fill")
                .foregroundStyle(.red)
                .lineLimit(1)
            }
          }
        }
      }

      Section("Stored Passwords") {
        if let err = model.loadError {
          Label(err, systemImage: "exclamationmark.triangle")
            .font(.caption)
            .foregroundStyle(.red)
        } else if model.passwords.isEmpty {
          Text("No stored passwords").foregroundStyle(.secondary)
        } else {
          ForEach(model.passwords, id: \.keyId) { entry in
            HStack {
              VStack(alignment: .leading) {
                Text(entry.keyId).textSelection(.enabled)
                Text(label(for: entry.passwordType))
                  .font(.caption)
                  .foregroundStyle(.secondary)
              }
              Spacer()
            }
            .contextMenu {
              Button("Delete", role: .destructive) {
                Task { await model.delete(entry) }
              }
            }
          }
        }
      }
    }
    .sheet(isPresented: $showingSetup) {
      GpgSetupSheet(model: model)
    }
    .navigationTitle("Keys")
    .navigationSplitViewColumnWidth(min: 200, ideal: 260)
    .toolbar {
      ToolbarItem {
        Button {
          Task { await model.reload() }
        } label: {
          Label("Reload", systemImage: "arrow.clockwise")
        }
      }
    }
    .task { await model.reload() }
    // The file may be edited outside the app, so re-read it on reactivation.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.refreshConfStatus()
    }
  }

  @ViewBuilder
  private var agentConfRow: some View {
    HStack {
      VStack(alignment: .leading, spacing: 2) {
        Text("Passphrase Prompts")
        if let status = model.confStatus {
          Text(confDetail(status))
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
        }
      }
      Spacer()
      if let state = model.confStatus?.state {
        Label(confLabel(state), systemImage: confIcon(state))
          .foregroundStyle(confColor(state))
          .font(.caption)
        Button(state == .configured ? "Reconfigure…" : "Set Up…") {
          showingSetup = true
        }
        .controlSize(.small)
      }
    }
    .padding(.vertical, 2)
  }

  private func confDetail(_ status: GpgAgentConfStatus) -> String {
    status.currentProgram ?? status.confPath
  }

  private func confLabel(_ state: GpgPinentryState) -> String {
    switch state {
    case .configured: return "Configured"
    case .notConfigured: return "Not Configured"
    case .otherProgram: return "Other Pinentry"
    }
  }

  private func confIcon(_ state: GpgPinentryState) -> String {
    switch state {
    case .configured: return "checkmark.circle.fill"
    case .notConfigured: return "circle"
    case .otherProgram: return "exclamationmark.triangle.fill"
    }
  }

  private func confColor(_ state: GpgPinentryState) -> Color {
    switch state {
    case .configured: return .green
    case .notConfigured: return .secondary
    case .otherProgram: return .orange
    }
  }

  private func label(for type: PasswordEntryType) -> String {
    switch type {
    case .gpgKey: return "GPG key"
    case .sshKey: return "SSH key"
    case .ageKey: return "age key"
    case .other: return "Other"
    }
  }
}
