import AxoPassFFI
import SwiftUI

/// Setup assistant for the `IdentityAgent` line in `~/.ssh/config`, which
/// routes ssh's agent requests into this app's SSH agent. Steps: read what
/// changes, write the line, and see the result.
struct SshSetupSheet: View {
  let model: SshModel

  @Environment(\.dismiss) private var dismiss

  private enum Step {
    case overview
    case configure
    case done
  }

  @State private var navigator: SetupNavigator<Step>
  /// Agent configured before setup. Captured before the write, since the
  /// status no longer reports it afterward.
  @State private var replacedAgent: String?

  init(model: SshModel) {
    self.model = model
    _navigator = State(
      initialValue: SetupNavigator(
        start: model.confStatus?.state == .configured ? .done : .overview))
  }

  private var status: SshAgentConfStatus? { model.confStatus }
  private var isConfigured: Bool { status?.state == .configured }
  private var configPath: String { status?.configPath ?? "~/.ssh/config" }

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
        title: "SSH Agent Setup",
        detail:
          "ssh asks whatever `IdentityAgent` names for your keys and signatures. Pointing it at Axo Pass's agent socket routes ssh through this app."
      )
      Text("The setup edits \(configPath).")
        .font(.callout)
        .textSelection(.enabled)
      if let current = status?.currentAgent {
        SetupReplaceWarning(
          message: "Another agent is configured. It will be commented out.", current: current)
      }
      Spacer(minLength: 0)
      HStack {
        Spacer()
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Continue") {
          replacedAgent = status?.currentAgent
          navigator.go(to: .configure)
        }
        .keyboardShortcut(.defaultAction)
        .disabled(status == nil)
      }
    }
  }

  private var configureStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "Add to ~/.ssh/config",
        detail: "This line is added to \(configPath).")
      if let status {
        SetupCodeBlock(text: "Host *\n  \(expectedLine(for: status))")
      }
      Spacer(minLength: 0)
      HStack {
        Button("Back") { navigator.go(to: .overview, forward: false) }
        Spacer()
        if model.isConfiguring {
          ProgressView().controlSize(.small)
        }
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Add to ~/.ssh/config") {
          Task { await model.configureAgentConf() }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(model.isConfiguring)
      }
    }
  }

  private var doneStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(title: "SSH Agent Ready", detail: "ssh now uses the Axo Pass agent.")
      SetupDoneCard(
        summary: "Configured in \(configPath).",
        code: status.map { "Host *\n  \(expectedLine(for: $0))" }
      ) {
        if let replacedAgent { SetupReplacedRow(replaced: replacedAgent) }
        if case .success = model.testResult {
          SetupCardRow(symbol: "checkmark.circle.fill", tint: .green) {
            Text("SSH connected to Axo Pass SSH agent.")
          }
        }
      }
      Spacer(minLength: 0)
      HStack {
        Button("Test Connection") {
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

  private func expectedLine(for status: SshAgentConfStatus) -> String {
    "IdentityAgent \"\(status.expectedAgent)\""
  }
}
