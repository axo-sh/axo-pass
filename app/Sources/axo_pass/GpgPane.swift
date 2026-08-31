import AxoPassFFI
import SwiftUI

struct GpgPane: View {
  @State private var model = GpgModel()

  var body: some View {
    List {
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
