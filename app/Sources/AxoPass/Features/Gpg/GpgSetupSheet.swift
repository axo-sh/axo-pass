import AxoPassFFI
import SwiftUI

/// Setup assistant for the `pinentry-program` line in `gpg-agent.conf`, which
/// is what routes gpg-agent's passphrase prompts into this app. Steps: read
/// what changes, write the line, and verify it with a test signature.
struct GpgSetupSheet: View {
  let model: GpgModel

  @Environment(\.dismiss) private var dismiss

  private enum Step {
    case overview
    case configure
    case done
  }

  @State private var navigator: SetupNavigator<Step>
  /// Pinentry configured before setup. Captured before the write, since the
  /// status no longer reports it afterward.
  @State private var replacedProgram: String?

  init(model: GpgModel) {
    self.model = model
    _navigator = State(
      initialValue: SetupNavigator(
        start: model.confStatus?.state == .configured ? .done : .overview))
  }

  private var status: GpgAgentConfStatus? { model.confStatus }
  private var isConfigured: Bool { status?.state == .configured }
  private var confPath: String { status?.confPath ?? "~/.gnupg/gpg-agent.conf" }

  var body: some View {
    SetupAssistantFrame(navigator: navigator, error: error) { step in
      switch step {
      case .overview: overviewStep
      case .configure: configureStep
      case .done: doneStep
      }
    }
    .onChange(of: isConfigured) { _, configured in
      if configured && navigator.step == .configure { navigator.go(to: .done) }
    }
  }

  /// Error of the write on the configure step, or of the test on the last step.
  private var error: String? {
    switch navigator.step {
    case .overview: nil
    case .configure: model.configureError
    case .done:
      if case .failure(let message) = model.testResult { message } else { nil }
    }
  }

  private var overviewStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "GPG Setup",
        detail:
          "gpg-agent runs the program named by `pinentry-program` whenever it needs a passphrase. Pointing it at Axo Pass shows those prompts in this app."
      )
      Text("The setup edits \(confPath).")
        .font(.callout)
        .textSelection(.enabled)
      if let current = status?.currentProgram {
        SetupReplaceWarning(
          message: "Another pinentry is configured. It will be commented out.", current: current)
      }
      Spacer(minLength: 0)
      HStack {
        Spacer()
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Continue") {
          replacedProgram = status?.currentProgram
          navigator.go(to: .configure)
        }
        .keyboardShortcut(.defaultAction)
      }
    }
  }

  private var configureStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "Add to gpg-agent.conf", detail: "This line is added to \(confPath).")
      if let line = status?.expectedLine {
        SetupCodeBlock(text: line)
      } else {
        Label(
          "Could not find the bundled ap-pinentry helper. Automatic setup is only available when running the installed app.",
          systemImage: "exclamationmark.triangle.fill"
        )
        .foregroundStyle(.orange)
        .fixedSize(horizontal: false, vertical: true)
      }
      VStack(alignment: .leading, spacing: 6) {
        Text("To add it yourself, edit the file, then run:")
        SetupCodeBlock(text: "gpgconf --reload gpg-agent")
      }
      .font(.callout)
      .frame(maxWidth: .infinity, alignment: .leading)
      Spacer(minLength: 0)
      HStack {
        Button("Back") { navigator.go(to: .overview, forward: false) }
        Spacer()
        if model.isConfiguring {
          ProgressView().controlSize(.small)
        }
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Add to gpg-agent.conf") {
          Task { await model.configureAgentConf() }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(model.isConfiguring || status?.expectedLine == nil)
      }
    }
  }

  private var doneStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "GPG Ready", detail: "gpg-agent prompts for passphrases in Axo Pass.")
      SetupDoneSummary(
        path: confPath, activeLine: status?.expectedLine, replaced: replacedProgram)
      if case .success = model.testResult {
        Label("Signing works", systemImage: "checkmark.circle.fill")
          .font(.callout)
          .foregroundStyle(.green)
      }
      Spacer(minLength: 0)
      HStack {
        Button("Test Signing") {
          Task { await model.testIntegration() }
        }
        .disabled(model.isTesting)
        if model.isTesting {
          ProgressView().controlSize(.small)
        }
        Spacer()
        Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
      }
    }
  }
}
