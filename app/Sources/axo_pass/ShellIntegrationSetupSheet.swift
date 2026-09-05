import AppKit
import AxoPassFFI
import SwiftUI

/// Setup assistant for the `ap` shell integration block appended to
/// `~/.zshrc` (or `$ZDOTDIR/.zshrc`). Idempotent, so this mostly matters
/// again after the block's own content changes.
struct ShellIntegrationSetupSheet: View {
  let model: ShellIntegrationModel

  @Environment(\.dismiss) private var dismiss

  private var status: ShellIntegrationStatus? { model.status }
  private var isConfigured: Bool { status?.configured == true }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      header
      Divider()
      explanation
      manualInstructions
      Divider()
      footer
    }
    .padding(20)
    .frame(width: 460)
  }

  private var header: some View {
    HStack(spacing: 10) {
      Image(systemName: "terminal")
        .font(.title2)
        .foregroundStyle(.tint)
      VStack(alignment: .leading, spacing: 2) {
        Text("Shell Integration Setup").font(.headline)
        Text(status?.zshrcPath ?? "~/.zshrc")
          .font(.caption)
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      }
    }
  }

  private var explanation: some View {
    Text(
      "Appends a block to \(status?.zshrcPath ?? "~/.zshrc") that aliases `ap` to the bundled "
        + "CLI and sources its shell environment. When running from the installed app, it also "
        + "points ssh's SSH_ASKPASS at the bundled askpass helper, so ssh and ssh-add prompts "
        + "route into Axo Pass instead of a terminal or GUI dialog."
    )
    .fixedSize(horizontal: false, vertical: true)
  }

  private static let blockText = """
    alias ap="/path/to/ap"
    source <(ap shellenv zsh)
    export SSH_ASKPASS="/path/to/ap-ssh-askpass"
    export SSH_ASKPASS_REQUIRE=force
    """

  private var manualInstructions: some View {
    DisclosureGroup("What gets added") {
      VStack(alignment: .leading, spacing: 6) {
        Text("A block like this is appended to \(status?.zshrcPath ?? "~/.zshrc"):")
        Text(Self.blockText)
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
      Button(isConfigured ? "Reconfigure" : "Set Up") {
        Task { await model.configure() }
      }
      .keyboardShortcut(.defaultAction)
      .disabled(model.isConfiguring)
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
}
