import AppKit
import AxoPassFFI
import SwiftUI

/// The content of the Settings scene in `App.swift`.
///
/// Settings are only available while the app is unlocked, so a lock closes the
/// window as well as disabling the menu item.
struct SettingsView: View {
  @Environment(VaultsModel.self) private var model
  @State private var window: NSWindow?

  var body: some View {
    TabView {
      GeneralSettingsView()
        .tabItem { Label("General", systemImage: "gearshape") }
      SecuritySettingsView()
        .tabItem { Label("Security", systemImage: "lock.shield") }
      SshSettingsView()
        .tabItem { Label("SSH", systemImage: "key.horizontal") }
    }
    .padding(20)
    .frame(width: 440, height: 250, alignment: .top)
    .navigationTitle("Axo Pass Settings")
    .background(
      WindowAccessor {
        window = $0
        closeIfLocked()
      }
    )
    .onChange(of: model.isAppUnlocked) { _, _ in closeIfLocked() }
  }

  private func closeIfLocked() {
    guard !model.isAppUnlocked else { return }
    window?.close()
  }
}

/// Axo Pass ▸ Settings, replacing the item the `Settings` scene installs so it
/// can be disabled while the app is locked.
struct SettingsMenuItem: View {
  @Environment(VaultsModel.self) private var model
  @Environment(\.openSettings) private var openSettings

  var body: some View {
    Button("Settings…") {
      NSApp.setActivationPolicy(.regular)
      NSApp.activate(ignoringOtherApps: true)
      openSettings()
    }
    .keyboardShortcut(",", modifiers: .command)
    .disabled(!model.isAppUnlocked)
  }
}

private struct GeneralSettingsView: View {
  @AppStorage(Preferences.Key.autoLockMinutes)
  private var autoLockMinutes = Preferences.defaultAutoLockMinutes

  var body: some View {
    Form {
      Picker("Lock when idle for:", selection: $autoLockMinutes) {
        ForEach(Preferences.autoLockChoices, id: \.self) { minutes in
          Text(Preferences.label(forAutoLockMinutes: minutes)).tag(minutes)
        }
      }
      .fixedSize()
      Text("App always locks on screen lock or sleep.")
        .settingsCaption()
    }
  }
}

private struct SecuritySettingsView: View {
  @AppStorage(Preferences.Key.reuseApprovals)
  private var reuseApprovals = Preferences.defaultReuseApprovals

  var body: some View {
    Form {
      Toggle(
        "Reuse an approval for up to \(Self.absolute)",
        isOn: $reuseApprovals)
      Text(
        """
        After you approve an SSH, GPG, or `ap` request, the same program can repeat it \
        on the same key without prompting. That ends \(Self.idle) after its last request, \
        or \(Self.absolute) after the initial approval, whichever comes first. Reading a secret \
        always prompts.
        """
      )
      .settingsCaption()
    }
  }

  private static let absolute = duration(GrantPolicy.reuseWindow.absolute)
  private static let idle = duration(GrantPolicy.reuseWindow.idle)

  /// A reuse window in words. The windows are whole minutes in a release build
  /// and seconds in a debug one.
  private static func duration(_ seconds: TimeInterval) -> String {
    let value = Int(seconds)
    if value >= 60, value % 60 == 0 {
      let minutes = value / 60
      return minutes == 1 ? "1 minute" : "\(minutes) minutes"
    }
    return value == 1 ? "1 second" : "\(value) seconds"
  }
}

/// The `IdentityAgent` line in `~/.ssh/config`, which decides whether ssh
/// talks to this app's agent. The agents' own status lives in the SSH pane.
private struct SshSettingsView: View {
  @State private var model = SshModel()
  @State private var showingSetup = false

  private var state: SshIdentityAgentState? { model.confStatus?.state }

  var body: some View {
    Form {
      LabeledContent("IdentityAgent:") {
        HStack(spacing: 6) {
          if let state {
            Label(label(state), systemImage: icon(state))
              .foregroundStyle(color(state))
          }
          if model.isConfiguring {
            ProgressView().controlSize(.small)
          }
        }
      }
      if let path = model.confStatus?.configPath {
        Text(path)
          .font(.callout.monospaced())
          .textSelection(.enabled)
          .settingsCaption()
      }
      LabeledContent("") {
        HStack {
          if state != .configured {
            Button("Add to ~/.ssh/config") {
              Task { await model.configureAgentConf() }
            }
            .disabled(model.isConfiguring)
          }
          Button("Setup Assistant…") { showingSetup = true }
        }
      }
      if let error = model.configureError {
        Text(error)
          .foregroundStyle(.red)
          .settingsCaption()
      }
      Text("ssh asks whatever `IdentityAgent` names for your keys and signatures.")
        .settingsCaption()
    }
    // This pane's rows are denser than the other tabs', which are a control
    // and a caption apiece, so they need the room.
    .padding(.horizontal, 10)
    .padding(.vertical, 12)
    .task { model.refreshConfStatus() }
    // The file may be edited outside the app, so re-read it on reactivation.
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification))
    { _ in
      model.refreshConfStatus()
    }
    .sheet(isPresented: $showingSetup) {
      SshSetupSheet(model: model)
    }
  }

  private func label(_ state: SshIdentityAgentState) -> String {
    switch state {
    case .configured: return "Configured"
    case .notConfigured: return "Not Configured"
    case .otherAgent: return "Other Agent"
    }
  }

  private func icon(_ state: SshIdentityAgentState) -> String {
    switch state {
    case .configured: return "checkmark.circle.fill"
    case .notConfigured: return "circle"
    case .otherAgent: return "exclamationmark.triangle.fill"
    }
  }

  private func color(_ state: SshIdentityAgentState) -> Color {
    switch state {
    case .configured: return .green
    case .notConfigured: return .secondary
    case .otherAgent: return .orange
    }
  }
}

extension View {
  /// Explanatory text under a control, in the column the controls occupy.
  fileprivate func settingsCaption() -> some View {
    LabeledContent("") {
      self
        .font(.callout)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }
  }
}
