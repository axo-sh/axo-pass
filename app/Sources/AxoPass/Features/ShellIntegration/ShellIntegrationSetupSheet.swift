import AxoPassFFI
import SwiftUI

/// Setup assistant for the `ap` shell integration block appended to
/// `~/.zshrc` (or `$ZDOTDIR/.zshrc`). Steps: read what changes, write the
/// block, and see the result. A configured shell opens on the last step.
struct ShellIntegrationSetupSheet: View {
  let model: ShellIntegrationModel

  @Environment(\.dismiss) private var dismiss

  private enum Step {
    case overview
    case configure
    case manual
    case done
  }

  @State private var navigator: SetupNavigator<Step>
  @State private var manualNotFound = false

  init(model: ShellIntegrationModel) {
    self.model = model
    _navigator = State(
      initialValue: SetupNavigator(start: model.status?.configured == true ? .done : .overview))
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
      error: navigator.step == .configure || navigator.step == .manual
        ? model.configureError : nil
    ) { step in
      switch step {
      case .overview: overviewStep
      case .configure: configureStep
      case .manual: manualStep
      case .done: doneStep
      }
    }
    .onChange(of: isConfigured) { _, configured in
      if configured && (navigator.step == .configure || navigator.step == .manual) {
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

  private var overviewStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "Shell Integration Setup",
        detail:
          "Symlinks `ap` into `~/.local/bin` so it resolves in scripts and non-zsh tools, then appends a block to \(zshrcPath) that puts `~/.local/bin` on your PATH and sources the bundled CLI's shell environment.",
        detailLineSpacing: 3
      )
      Text(
        "When running from the installed app, the shell environment also points SSH_ASKPASS at the bundled askpass helper. ssh and ssh-add prompts then route into Axo Pass instead of a terminal or GUI dialog."
      )
      .font(.callout)
      .lineSpacing(3)
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)
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
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Continue") { navigator.go(to: .configure) }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  private var manualStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "Add It Yourself",
        detail:
          "Add these lines to a file zsh loads, such as \(zshrcPath), `~/.zshenv`, or a file in your dotfiles. Setup links `ap` into `~/.local/bin` but does not edit your shell files.",
        detailLineSpacing: 3
      )
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
        Button("Back") { navigator.go(to: .overview, forward: false) }
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

  private var configureStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "Add to \(zshrcPath)", detail: "A block like this is appended to \(zshrcPath).")
      if let blockText {
        SetupCodeBlock(text: blockText)
      }
      Spacer(minLength: 0)
      HStack {
        Button("Back") { navigator.go(to: .overview, forward: false) }
        Spacer()
        if model.isConfiguring {
          ProgressView().controlSize(.small)
        }
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Set Up") {
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

  private var doneStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "Shell Integration Ready", detail: "New terminal windows pick up the change.")
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
      Spacer(minLength: 0)
      HStack {
        Spacer()
        Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
      }
    }
  }
}
