import AppKit
import AxoPassFFI
import SwiftUI

/// Setup assistant for the `pinentry-program` line in `gpg-agent.conf`, which
/// is what routes gpg-agent's passphrase prompts into this app. Walks through
/// writing the line and then verifying it with a test signature.
struct GpgSetupSheet: View {
  let model: GpgModel

  @Environment(\.dismiss) private var dismiss

  private var status: GpgAgentConfStatus? { model.confStatus }
  private var isConfigured: Bool { status?.state == .configured }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      header
      Divider()
      explanation
      if let line = status?.expectedLine {
        configLine(line)
      } else {
        unavailableNotice
      }
      manualInstructions
      Divider()
      footer
    }
    .padding(20)
    .frame(width: 460)
  }

  private var header: some View {
    HStack(spacing: 10) {
      Image(systemName: "lock.doc")
        .font(.title2)
        .foregroundStyle(.tint)
      VStack(alignment: .leading, spacing: 2) {
        Text("GPG Setup").font(.headline)
        Text(status?.confPath ?? "~/.gnupg/gpg-agent.conf")
          .font(.caption)
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      }
    }
  }

  @ViewBuilder
  private var explanation: some View {
    Text(
      "gpg-agent runs the program named by `pinentry-program` whenever it needs a passphrase. "
        + "Pointing it at Axo Pass shows those prompts in this app."
    )
    .fixedSize(horizontal: false, vertical: true)

    if let current = status?.currentProgram {
      Label {
        VStack(alignment: .leading, spacing: 2) {
          Text("Another pinentry is configured. It will be commented out.")
          Text(current)
            .font(.caption.monospaced())
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
        }
      } icon: {
        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
      }
      .fixedSize(horizontal: false, vertical: true)
    }
  }

  private func configLine(_ line: String) -> some View {
    HStack(alignment: .top, spacing: 8) {
      Text(line)
        .font(.caption.monospaced())
        .textSelection(.enabled)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
      Button {
        copy(line)
      } label: {
        Image(systemName: "document.on.document")
      }
      .buttonStyle(.borderless)
      .help("Copy to clipboard")
    }
    .padding(10)
    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
  }

  private var unavailableNotice: some View {
    Label(
      "Could not find the bundled ap-pinentry helper. Automatic setup is only available when "
        + "running the installed app.",
      systemImage: "exclamationmark.triangle.fill"
    )
    .foregroundStyle(.orange)
    .fixedSize(horizontal: false, vertical: true)
  }

  private var manualInstructions: some View {
    DisclosureGroup("Configure manually") {
      VStack(alignment: .leading, spacing: 6) {
        Text("Add the line above to \(status?.confPath ?? "~/.gnupg/gpg-agent.conf"), then run:")
        commandRow("gpgconf --reload gpg-agent")
      }
      .font(.callout)
      .padding(.top, 6)
      .frame(maxWidth: .infinity, alignment: .leading)
    }
  }

  private func commandRow(_ command: String) -> some View {
    HStack(spacing: 8) {
      Text(command)
        .font(.caption.monospaced())
        .textSelection(.enabled)
      Button {
        copy(command)
      } label: {
        Image(systemName: "document.on.document")
      }
      .buttonStyle(.borderless)
      .help("Copy to clipboard")
    }
  }

  @ViewBuilder
  private var footer: some View {
    HStack {
      resultLabel
      Spacer()
      Button(isConfigured ? "Done" : "Cancel") { dismiss() }
        .keyboardShortcut(.cancelAction)
      if isConfigured {
        Button("Test Signing") {
          Task { await model.testIntegration() }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(model.isTesting)
      } else {
        Button("Add to gpg-agent.conf") {
          Task { await model.configureAgentConf() }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(model.isConfiguring || status?.expectedLine == nil)
      }
    }
  }

  @ViewBuilder
  private var resultLabel: some View {
    if model.isConfiguring {
      Label("Writing…", systemImage: "hourglass").foregroundStyle(.secondary)
    } else if model.isTesting {
      Label("Testing…", systemImage: "hourglass").foregroundStyle(.secondary)
    } else if let error = model.configureError {
      Label(error, systemImage: "xmark.circle.fill")
        .foregroundStyle(.red)
        .lineLimit(2)
    } else if let result = model.testResult {
      switch result {
      case .success:
        Label("Signing works", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
      case .failure(let message):
        Label(message, systemImage: "xmark.circle.fill")
          .foregroundStyle(.red)
          .lineLimit(2)
      }
    } else if isConfigured {
      Label("Configured", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
    }
  }

  private func copy(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
  }
}
