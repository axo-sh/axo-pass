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
    case done
  }

  @State private var navigator: SetupNavigator<Step>

  init(model: ShellIntegrationModel) {
    self.model = model
    _navigator = State(
      initialValue: SetupNavigator(start: model.status?.configured == true ? .done : .overview))
  }

  private var status: ShellIntegrationStatus? { model.status }
  private var isConfigured: Bool { status?.configured == true }
  private var zshrcPath: String { status?.zshrcPath ?? "~/.zshrc" }

  private static let blockText = """
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
      export PATH="$HOME/.local/bin:$PATH"
    fi
    source <(ap shellenv zsh)
    export SSH_ASKPASS="/path/to/ap-ssh-askpass"
    export SSH_ASKPASS_REQUIRE=force
    """

  var body: some View {
    SetupAssistantFrame(
      navigator: navigator,
      error: navigator.step == .configure ? model.configureError : nil
    ) { step in
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

  private var overviewStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "Shell Integration Setup",
        detail:
          "Symlinks `ap` into `~/.local/bin` so it resolves in scripts and non-zsh tools, then appends a block to \(zshrcPath) that puts `~/.local/bin` on your PATH and sources the bundled CLI's shell environment."
      )
      Text(
        "When running from the installed app, the block also points SSH_ASKPASS at the bundled askpass helper. ssh and ssh-add prompts then route into Axo Pass instead of a terminal or GUI dialog."
      )
      .font(.callout)
      .fixedSize(horizontal: false, vertical: true)
      Spacer(minLength: 0)
      HStack {
        Spacer()
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Continue") { navigator.go(to: .configure) }
          .keyboardShortcut(.defaultAction)
      }
    }
  }

  private var configureStep: some View {
    VStack(alignment: .leading, spacing: 16) {
      SetupHeader(
        title: "Add to \(zshrcPath)", detail: "A block like this is appended to \(zshrcPath).")
      SetupCodeBlock(text: Self.blockText)
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
      SetupDoneSummary(path: zshrcPath, activeLine: Self.blockText)
      Spacer(minLength: 0)
      HStack {
        Spacer()
        Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
      }
    }
  }
}
