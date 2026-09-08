import AppKit
import AxoPassFFI
import SwiftUI

/// Setup assistant for the `IdentityAgent` line in `~/.ssh/config`, which
/// routes ssh's agent requests into this app's SSH agent. Walks through
/// writing the line.
struct SshSetupSheet: View {
  let model: SshModel

  @Environment(\.dismiss) private var dismiss

  private var status: SshAgentConfStatus? { model.confStatus }
  private var isConfigured: Bool { status?.state == .configured }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      header
      Divider()
      explanation
      if let status {
        configLine(expectedLine(for: status))
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
      Image(systemName: "key")
        .font(.title2)
        .foregroundStyle(.tint)
      VStack(alignment: .leading, spacing: 2) {
        Text("SSH Agent Setup").font(.headline)
        Text(status?.configPath ?? "~/.ssh/config")
          .font(.caption)
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      }
    }
  }

  @ViewBuilder
  private var explanation: some View {
    Text(
      "ssh asks whatever `IdentityAgent` names for your keys and signatures. Pointing it at "
        + "Axo Pass's agent socket routes ssh through this app."
    )
    .fixedSize(horizontal: false, vertical: true)

    if let current = status?.currentAgent {
      Label {
        VStack(alignment: .leading, spacing: 2) {
          Text("Another agent is configured. It will be commented out.")
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

  private func expectedLine(for status: SshAgentConfStatus) -> String {
    "IdentityAgent \"\(status.expectedAgent)\""
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

  private var manualInstructions: some View {
    DisclosureGroup("Configure manually") {
      VStack(alignment: .leading, spacing: 6) {
        Text("Add the following to \(status?.configPath ?? "~/.ssh/config"):")
        Text("Host *\n  \(status.map(expectedLine) ?? "")")
          .font(.caption.monospaced())
          .textSelection(.enabled)
      }
      .font(.callout)
      .padding(.top, 6)
      .frame(maxWidth: .infinity, alignment: .leading)
    }
  }

  @ViewBuilder
  private var footer: some View {
    HStack {
      resultLabel
      Spacer()
      Button(isConfigured ? "Done" : "Cancel") { dismiss() }
        .keyboardShortcut(.cancelAction)
      if !isConfigured {
        Button("Add to ~/.ssh/config") {
          Task { await model.configureAgentConf() }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(model.isConfiguring)
      }
    }
  }

  @ViewBuilder
  private var resultLabel: some View {
    if model.isConfiguring {
      Label("Writing…", systemImage: "hourglass").foregroundStyle(.secondary)
    } else if let error = model.configureError {
      Label(error, systemImage: "xmark.circle.fill")
        .foregroundStyle(.red)
        .lineLimit(2)
    } else if isConfigured {
      Label("Configured", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
    }
  }

  private func copy(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
  }
}
