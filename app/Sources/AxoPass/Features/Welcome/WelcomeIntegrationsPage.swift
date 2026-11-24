import SwiftUI

/// Last page of the first run. Offers the SSH agent and `ap` shell setups,
/// which open the same assistants as Settings, and a recorder for the global
/// palette shortcut.
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
        Text("Connect Your Tools")
          .font(.title)
          .fontWeight(.semibold)
        Text(
          "Optional; you can set these up later in Settings. GPG and age integrations are also supported there."
        )
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .fixedSize(horizontal: false, vertical: true)
      }

      VStack(spacing: 10) {
        CardGroup {
          IntegrationRow(
            title: "SSH agent",
            detail: "Use SSH keys stored in Axo Pass with ssh and git.",
            symbol: "key.fill",
            isConfigured: sshConfigured
          ) { setup = .ssh }

          Divider()

          IntegrationRow(
            title: "command",
            detail: "Add **ap** to zsh and route ssh passphrase prompts into Axo Pass.",
            symbol: "terminal.fill",
            titleCode: "ap",
            isConfigured: shellConfigured
          ) { setup = .shell }

          Divider()

          CardRow(
            title: "Global shortcut",
            detail: "Open the search palette from any app.",
            symbol: "command.square.fill"
          ) {
            HotKeyRecorder(hotKey: $paletteHotKey)
          }
        }
        if paletteHotKey != nil, GlobalHotKey.shared.registrationFailed {
          Text("This shortcut is in use by another app. Choose a different one.")
            .font(.caption)
            .foregroundStyle(.red)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
      }

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

/// Icon, title, and detail in a row, with a setup button or, if configured,
/// a view button and a checkmark.
private struct IntegrationRow: View {
  let title: String
  let detail: LocalizedStringKey
  let symbol: String
  var titleCode: String? = nil
  let isConfigured: Bool
  let action: () -> Void

  var body: some View {
    CardRow(title: title, detail: detail, symbol: symbol, titleCode: titleCode) {
      if isConfigured {
        HStack(spacing: 10) {
          Button("View", action: action)
          Image(systemName: "checkmark.circle.fill")
            .foregroundStyle(.green)
            .accessibilityLabel("Set up")
        }
      } else {
        Button("Set Up…", action: action)
      }
    }
  }
}

/// Icon, title, and detail in a row, with trailing content.
private struct CardRow<Trailing: View>: View {
  let title: String
  let detail: LocalizedStringKey
  let symbol: String
  /// Command name shown in a monospaced capsule before the title.
  var titleCode: String? = nil
  @ViewBuilder let trailing: Trailing

  var body: some View {
    HStack(spacing: 12) {
      TodayIcon(symbol: symbol, color: .accentColor)
      VStack(alignment: .leading, spacing: 2) {
        HStack(spacing: 5) {
          if let titleCode {
            Text(titleCode)
              .font(.system(.callout, design: .monospaced))
              .padding(.horizontal, 7)
              .padding(.vertical, 1)
              .background(.quaternary, in: Capsule())
          }
          Text(title)
            .fontWeight(.medium)
        }
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
  }
}

/// Rounded card that stacks rows, separated by dividers.
private struct CardGroup<Content: View>: View {
  @ViewBuilder let content: Content

  var body: some View {
    VStack(spacing: 0) {
      content
    }
    .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    .overlay {
      RoundedRectangle(cornerRadius: 10)
        .strokeBorder(.separator)
    }
  }
}
