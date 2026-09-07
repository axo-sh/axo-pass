import AppKit
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
    }
    .padding(20)
    .frame(width: 440, height: 200, alignment: .top)
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
