import SwiftUI

/// Last page of the first run. Offers the SSH agent and `ap` shell setups,
/// which open the same assistants as Settings, a recorder for the global
/// palette shortcut, and two example `ap` commands.
struct WelcomeIntegrationsPage: View {
  let ssh: SshModel
  let shell: ShellIntegrationModel
  let onDone: () -> Void

  private enum Setup: String, Identifiable {
    case ssh, shell
    var id: String { rawValue }
  }

  @State private var setup: Setup? = nil
  @AppStorage(Preferences.Key.paletteHotKey)
  private var paletteHotKey: HotKey?

  private var sshConfigured: Bool { ssh.confStatus?.state == .configured }
  private var shellConfigured: Bool { shell.status?.configured == true }

  var body: some View {
    VStack(spacing: 20) {
      VStack(spacing: 6) {
        Text("Connect your tools")
          .font(.title)
          .fontWeight(.semibold)
        Text("Every step is optional and can be done later in Settings.")
          .foregroundStyle(.secondary)
          .multilineTextAlignment(.center)
          .fixedSize(horizontal: false, vertical: true)
      }

      VStack(spacing: 10) {
        IntegrationRow(
          title: "SSH agent",
          detail: "Use SSH keys stored in Axo Pass with ssh and git.",
          symbol: "key.fill",
          isConfigured: sshConfigured
        ) { setup = .ssh }

        IntegrationRow(
          title: "ap command",
          detail: "Add `ap` to zsh and route ssh passphrase prompts into Axo Pass.",
          symbol: "terminal.fill",
          isConfigured: shellConfigured
        ) { setup = .shell }

        CardRow(
          title: "Global shortcut",
          detail: "Open the search palette from any app.",
          symbol: "command.square.fill"
        ) {
          HotKeyRecorder(hotKey: $paletteHotKey)
        }
        if paletteHotKey != nil, GlobalHotKey.shared.registrationFailed {
          Text("This shortcut is in use by another app. Choose a different one.")
            .font(.caption)
            .foregroundStyle(.red)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
      }

      VStack(alignment: .leading, spacing: 8) {
        Text("Useful commands")
          .font(.headline)
        ExampleCommand(
          text: "ap read axo://vault/item/password",
          detail: "Print a secret.")
        ExampleCommand(
          text: "API_KEY=axo://vault/item/token ap exec -- ./deploy.sh",
          detail: "Run a command with a secret in its environment.")
      }
      .frame(maxWidth: .infinity, alignment: .leading)

      HStack {
        Spacer()
        Button("Done", action: onDone)
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(32)
    .frame(width: 460)
    .onAppear {
      ssh.refreshConfStatus()
      shell.refreshStatus()
    }
    .sheet(item: $setup) { setup in
      switch setup {
      case .ssh: SshSetupSheet(model: ssh)
      case .shell: ShellIntegrationSetupSheet(model: shell)
      }
    }
  }
}

/// Icon, title, and detail in a rounded card, with a setup button or a
/// checkmark if configured.
private struct IntegrationRow: View {
  let title: String
  let detail: String
  let symbol: String
  let isConfigured: Bool
  let action: () -> Void

  var body: some View {
    CardRow(title: title, detail: detail, symbol: symbol) {
      if isConfigured {
        Image(systemName: "checkmark.circle.fill")
          .foregroundStyle(.green)
          .accessibilityLabel("Set up")
      } else {
        Button("Set Up…", action: action)
      }
    }
  }
}

/// Icon, title, and detail in a rounded card, with trailing content.
private struct CardRow<Trailing: View>: View {
  let title: String
  let detail: String
  let symbol: String
  @ViewBuilder let trailing: Trailing

  var body: some View {
    HStack(spacing: 12) {
      TodayIcon(symbol: symbol, color: .accentColor)
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
          .fontWeight(.medium)
        Text(detail)
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
      }
      Spacer(minLength: 0)
      trailing
    }
    .padding(.horizontal, 14)
    .padding(.vertical, 10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    .overlay {
      RoundedRectangle(cornerRadius: 10)
        .strokeBorder(.separator)
    }
  }
}

/// Command in a code block with a one line description below.
private struct ExampleCommand: View {
  let text: String
  let detail: String

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      SetupCodeBlock(text: text)
      Text(detail)
        .font(.caption)
        .foregroundStyle(.secondary)
    }
  }
}
