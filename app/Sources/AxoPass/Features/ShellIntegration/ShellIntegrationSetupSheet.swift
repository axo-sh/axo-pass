import AxoPassFFI
import SwiftUI

/// Setup assistant for the `ap` shell integration block appended to
/// `~/.zshrc` (or `$ZDOTDIR/.zshrc`). Steps: write the block, and see the
/// result. A configured shell opens on the last step.
struct ShellIntegrationSetupSheet: View {
  let model: ShellIntegrationModel

  @Environment(\.dismiss) private var dismiss

  private enum Step {
    case setup
    case manual
    case done
  }

  @State private var navigator: SetupNavigator<Step>
  @State private var manualNotFound = false

  init(model: ShellIntegrationModel) {
    self.model = model
    _navigator = State(
      initialValue: SetupNavigator(start: model.status?.configured == true ? .done : .setup))
  }

  private var status: ShellIntegrationStatus? { model.status }
  private var isConfigured: Bool { status?.configured == true }
  private var zshrcPath: String { status?.zshrcPath ?? "~/.zshrc" }

  /// Block lines as the write produces them, without the trailing newline.
  private var blockText: String? {
    status?.block.trimmingCharacters(in: .newlines)
  }

  var body: some View {
    SetupAssistantFrame(
      navigator: navigator,
      error: navigator.step == .setup || navigator.step == .manual
        ? model.configureError : nil,
      minHeight: navigator.step == .done ? 540 : 360
    ) { step in
      switch step {
      case .setup: setupStep
      case .manual: manualStep
      case .done: doneStep
      }
    }
    .onChange(of: isConfigured) { _, configured in
      if configured && (navigator.step == .setup || navigator.step == .manual) {
        navigator.go(to: .done)
      }
    }
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    {
      _ in
      if navigator.step == .manual && !model.isConfiguring { checkManual() }
    }
  }

  /// Link `ap` and look for the hook in a new zsh. Moves to the last step if
  /// found.
  private func checkManual() {
    Task {
      let found = await model.linkAndVerify()
      manualNotFound = !found && model.configureError == nil
    }
  }

  private var setupStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Shell Integration Setup")
        .font(.title2)
        .fontWeight(.semibold)
      Text(
        "**ap** is the Axo Pass command line tool. It can read secrets from your vaults and run commands with secrets in their environment, protected by Touch ID."
      )
      .lineSpacing(3)
      .fixedSize(horizontal: false, vertical: true)
      Text(
        "The following makes **ap** available in your terminal. It links **ap** into `~/.local/bin` and appends a block to \(zshrcPath) that adds the folder to your PATH and configures your shell. It also configures SSH to ask Axo Pass for key passphrases."
      )
      .lineSpacing(3)
      .fixedSize(horizontal: false, vertical: true)
      if let blockText {
        SetupCodeBlock(text: blockText)
      }
      if let status, status.hookConfigured, !status.symlinkOk {
        Label {
          (Text(status.symlinkPath).bold()
            + Text(" is missing or points to another binary. Setup restores it."))
            .textSelection(.enabled)
        } icon: {
          Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.orange)
        }
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
      }
      Spacer(minLength: 0)
      HStack {
        Button("Add It Myself…") {
          manualNotFound = false
          navigator.go(to: .manual)
        }
        Spacer()
        if model.isConfiguring {
          ProgressView().controlSize(.small)
        }
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Continue") {
          Task {
            await model.configure()
            if model.configureError == nil { navigator.go(to: .done) }
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(model.isConfiguring)
      }
    }
  }

  private var manualStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Add It Yourself")
        .font(.title2)
        .fontWeight(.semibold)
      Text(
        "Add these lines to a file zsh loads, such as \(zshrcPath), `~/.zshenv`, or a file in your dotfiles. Setup links **ap** into `~/.local/bin` but does not edit your shell files."
      )
      .lineSpacing(3)
      .fixedSize(horizontal: false, vertical: true)
      if let blockText {
        SetupCodeBlock(text: blockText)
      }
      if manualNotFound {
        Label {
          Text(
            "A new zsh did not load the integration. Check the file you edited, then check again.")
        } icon: {
          Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.orange)
        }
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
      }
      Spacer(minLength: 0)
      HStack {
        Button("Back") { navigator.go(to: .setup, forward: false) }
        Spacer()
        if model.isConfiguring {
          ProgressView().controlSize(.small)
        }
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Check") { checkManual() }
          .keyboardShortcut(.defaultAction)
          .disabled(model.isConfiguring)
      }
    }
  }

  private var doneStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "Shell Integration Ready", detail: "New terminal windows will pick up the change.")
      SetupDoneCard(
        summary: status?.zshrcConfigured == false
          ? "Detected in your zsh startup files." : "Configured in \(zshrcPath).",
        code: blockText
      ) {
        if let status {
          SetupCardRow(
            symbol: status.symlinkOk ? "checkmark.circle.fill" : "exclamationmark.circle.fill",
            tint: status.symlinkOk ? .green : .orange
          ) {
            Text(status.symlinkPath).bold()
              + Text(
                status.symlinkOk
                  ? " links to the bundled ap." : " is missing or points to another binary.")
          }
        }
      }
      VStack(alignment: .leading, spacing: 12) {
        Text("Getting Started")
          .font(.headline)
        ExampleCommand(
          text: "ap read axo://vault/item/password",
          detail: "Print a secret.")
        ExampleCommand(
          text: "API_KEY=axo://vault/item/token ap exec -- ./deploy.sh",
          detail: "Run a command with interpolated secrets in its environment.")
        ExampleCommand(
          text: "ap exec --env-file .env -- ./deploy.sh",
          detail: "Run a command with interpolated secrets from a dotenv file.")
      }
      Spacer(minLength: 0)
      HStack {
        Spacer()
        Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
      }
    }
  }
}

/// Command in a code block with a one line description below.
private struct ExampleCommand: View {
  let text: String
  let detail: String

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(detail)
        .font(.caption)
        .foregroundStyle(.secondary)
      SetupCodeBlock(text: text)
    }
  }
}
