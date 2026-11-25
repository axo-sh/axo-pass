import AppKit
import SunshineUI
import SwiftUI

@main
struct AxoPassApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
  @Environment(\.openWindow) private var openWindow
  @Environment(\.openSettings) private var openSettings

  var body: some Scene {
    // `.defaultLaunchBehavior(.suppressed)` keeps SwiftUI from opening these on
    // launch: a broker-only launch shows no window at all. They open in response
    // to `WindowRequests`, or to the Audit Log menu item.
    Window("Axo Pass", id: Self.mainWindowID) {
      ContentView()
        .environment(appDelegate.model)
        .environment(appDelegate.sync)
        .environment(appDelegate.issues)
        .environment(appDelegate.windows)
        .sunshineUpdater(appDelegate.updaterUI, appName: "Axo Pass", style: .cornerIndicator)
        // warning: setting frame can cause the side nav to flicker when toggling.
        // .frame(minWidth: 400, minHeight: 400)
        .onAppear { appDelegate.model.reload() }
        .background(WindowAccessor { appDelegate.adoptMainWindow($0) })
    }
    // The app always opens locked, and the lock screen has no title bar. Set on
    // the scene rather than on the window later, so the bar is never drawn and
    // then taken away. `ContentView` restores it on unlock.
    .windowStyle(.titleBar)
    .defaultSize(width: 960, height: 560)
    .defaultLaunchBehavior(.suppressed)
    .onChange(of: appDelegate.windows.mainOpens, initial: true) { _, count in
      guard count > 0 else { return }
      NSApp.setActivationPolicy(.regular)
      NSApp.activate(ignoringOtherApps: true)
      // The welcome window stands in for the main window until first run
      // finishes.
      let pending = appDelegate.windows.isFirstRunPending()
      openWindow(id: pending ? Self.welcomeWindowID : Self.mainWindowID)
    }
    // Requests from the status item. Each window is only available while
    // unlocked; a locked app shows the main window, and its lock screen,
    // instead. While first run is pending, that is the welcome window.
    .onChange(of: appDelegate.windows.auditOpens) { _, _ in
      openUnlocked { openWindow(id: Self.auditWindowID) }
    }
    .onChange(of: appDelegate.windows.keychainOpens) { _, _ in
      openUnlocked { openWindow(id: Self.keychainWindowID) }
    }
    .onChange(of: appDelegate.windows.settingsOpens) { _, _ in
      openUnlocked { openSettings() }
    }

    // Shown in place of the main window if no vault exists and first run is
    // not complete. Never open together with the main window. It carries the
    // sync sheets for that reason, see `syncSheets()`.
    Window("Welcome to Axo Pass", id: Self.welcomeWindowID) {
      WelcomeView()
        .environment(appDelegate.model)
        .environment(appDelegate.sync)
        .environment(appDelegate.issues)
        .environment(appDelegate.windows)
        .background(WindowAccessor { appDelegate.adoptWelcomeWindow($0) })
    }
    .windowStyle(.hiddenTitleBar)
    .windowBackgroundDragBehavior(.enabled)
    .windowResizability(.contentSize)
    .defaultLaunchBehavior(.suppressed)

    Window("Audit Log", id: Self.auditWindowID) {
      AuditLogWindow()
        .environment(appDelegate.model)
        .frame(minWidth: 640, minHeight: 360)
        // Only reachable from an unlocked app, so a relaunch (always locked)
        // must never reopen it. See `adoptMainWindow` in `AppDelegate`.
        .background(
          WindowAccessor {
            $0.isRestorable = false
            $0.isExcludedFromWindowsMenu = true
          })
    }
    .defaultSize(width: 900, height: 520)
    .defaultLaunchBehavior(.suppressed)

    Window("Sync Log", id: Self.syncLogWindowID) {
      SyncLogWindow()
        .environment(appDelegate.model)
        .frame(minWidth: 640, minHeight: 360)
        // Only reachable from an unlocked app, so a relaunch (always locked)
        // must never reopen it. See `adoptMainWindow` in `AppDelegate`.
        .background(
          WindowAccessor {
            $0.isRestorable = false
            $0.isExcludedFromWindowsMenu = true
          })
    }
    .defaultSize(width: 900, height: 520)
    .defaultLaunchBehavior(.suppressed)

    Window("App Keychain", id: Self.keychainWindowID) {
      KeychainWindow()
        .environment(appDelegate.model)
        .frame(minWidth: 640, minHeight: 360)
        // Only reachable from an unlocked app, so a relaunch (always locked)
        // must never reopen it. See `adoptMainWindow` in `AppDelegate`.
        .background(
          WindowAccessor {
            $0.isRestorable = false
            $0.isExcludedFromWindowsMenu = true
          })
    }
    .defaultSize(width: 900, height: 520)
    .defaultLaunchBehavior(.suppressed)

    // Needs no vault access, so it opens even while locked.
    Window("Generate Password", id: Self.generatorWindowID) {
      PasswordGeneratorView()
        .frame(width: 340)
        .background(
          WindowAccessor {
            $0.isRestorable = false
            $0.isExcludedFromWindowsMenu = true
          })
    }
    .windowResizability(.contentSize)
    .defaultLaunchBehavior(.suppressed)

    Settings {
      SettingsView()
        .environment(appDelegate.model)
        .environment(appDelegate.sync)
        .environment(appDelegate.issues)
        .environment(appDelegate.windows)
        .environmentObject(appDelegate.updaterUI)
    }
    .commands {
      CheckForUpdatesCommand(appDelegate.updaterUI)
      CommandGroup(replacing: .appSettings) {
        SettingsMenuItem()
          .environment(appDelegate.model)
      }
      CommandGroup(after: .appSettings) {
        LockMenuItem()
          .environment(appDelegate.model)
      }
      CommandGroup(replacing: .appTermination) {
        QuitMenuItem(appDelegate: appDelegate)
      }
      CommandGroup(after: .newItem) {
        NewVaultMenuItem()
        NewItemMenuItem()
        Divider()
        GeneratePasswordMenuItem()
      }
      CommandGroup(after: .toolbar) {
        PaletteMenuItem(windows: appDelegate.windows)
          .environment(appDelegate.model)
        ReloadMenuItem()
          .environment(appDelegate.model)
        ShowDismissedMenuItem()
      }
      CommandGroup(after: .help) {
        AuditLogMenuItem(windows: appDelegate.windows)
          .environment(appDelegate.model)
        SyncLogMenuItem(windows: appDelegate.windows)
          .environment(appDelegate.model)
        KeychainMenuItem(windows: appDelegate.windows)
          .environment(appDelegate.model)
      }
      #if DEBUG
        CommandMenu("Developer") {
          DeveloperMenu(windows: appDelegate.windows, issues: appDelegate.issues)
        }
      #endif
      // Declared rather than left to the default menu: the passphrase panel
      // is shown from a launch that opens no window, and pasting a
      // passphrase out of a password manager needs these key equivalents.
      TextEditingCommands()
    }
  }

  private func openUnlocked(_ open: () -> Void) {
    guard appDelegate.model.isAppUnlocked, !appDelegate.windows.isFirstRunPending() else {
      appDelegate.windows.requestMain()
      return
    }
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
    open()
  }

  static let mainWindowID = "main"
  static let welcomeWindowID = "welcome"
  static let auditWindowID = "audit"
  static let syncLogWindowID = "sync-log"
  static let keychainWindowID = "keychain"
  static let generatorWindowID = "generator"
}

/// View ▸ Show Dismissed Issues, which lists dismissed issues on Today.
private struct ShowDismissedMenuItem: View {
  @AppStorage(Preferences.Key.showDismissedIssues) private var isOn = false

  var body: some View {
    Toggle("Show Dismissed Issues", isOn: $isOn)
  }
}

/// Action of the File ▸ New Vault… item. Set by the sidebar of the key window.
private struct NewVaultActionKey: FocusedValueKey {
  typealias Value = () -> Void
}

/// Action of the File ▸ New Item… item. Set by the item list of the key window,
/// and absent if no vault is selected.
private struct NewItemActionKey: FocusedValueKey {
  typealias Value = () -> Void
}

extension FocusedValues {
  var newVaultAction: (() -> Void)? {
    get { self[NewVaultActionKey.self] }
    set { self[NewVaultActionKey.self] = newValue }
  }

  var newItemAction: (() -> Void)? {
    get { self[NewItemActionKey.self] }
    set { self[NewItemActionKey.self] = newValue }
  }
}

/// File ▸ New Vault…. Disabled unless the main window is unlocked and key.
private struct NewVaultMenuItem: View {
  @FocusedValue(\.newVaultAction) private var action

  var body: some View {
    Button("New Vault…") { action?() }
      .disabled(action == nil)
  }
}

/// File ▸ New Item…. Disabled unless a vault is selected in the key window.
private struct NewItemMenuItem: View {
  @FocusedValue(\.newItemAction) private var action

  var body: some View {
    Button("New Item…") { action?() }
      .keyboardShortcut("n", modifiers: .command)
      .disabled(action == nil)
  }
}

/// File ▸ Generate Password…, a standalone generator.
private struct GeneratePasswordMenuItem: View {
  @Environment(\.openWindow) private var openWindow

  var body: some View {
    Button("Generate Password…") {
      NSApp.setActivationPolicy(.regular)
      NSApp.activate(ignoringOtherApps: true)
      openWindow(id: AxoPassApp.generatorWindowID)
    }
  }
}

#if DEBUG
  /// Developer menu of debug builds. Previews and resets the first-run screens,
  /// and shows placeholder content for screenshots.
  private struct DeveloperMenu: View {
    let windows: WindowRequests
    let issues: IssuesModel
    @Bindable private var overrides = DevOverrides.shared

    var body: some View {
      Toggle(
        "Show Welcome Window",
        isOn: Binding(
          get: { overrides.forceWelcome },
          set: { on in
            overrides.forceWelcome = on
            // Open it now when turned on.
            if on { windows.requestMain() }
          }))
      Toggle("Show Setup Checklist", isOn: $overrides.showChecklist)
      Toggle("Show Marketing Content", isOn: $overrides.showMarketingContent)
      Divider()
      Button("Reset First Run") { Preferences.hasCompletedFirstRun = false }
      Button("Reset Setup Checklist") { issues.restoreSetupSteps() }
      Button("Reset All Dismissed Issues") { issues.restoreAll() }
      Divider()
      Menu("Reset App State") {
        ForEach(DevReset.Kind.allCases, id: \.self) { kind in
          Button(kind.title + "…") { DevReset.run(kind) }
        }
      }
    }
  }
#endif

/// Axo Pass ▸ Lock, bound to Command-L. Disabled while already locked.
private struct LockMenuItem: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    Button("Lock") { model.lock() }
      .keyboardShortcut("l", modifiers: .command)
      .disabled(!model.isAppUnlocked)
  }
}

/// View ▸ Show Command Palette.
private struct PaletteMenuItem: View {
  let windows: WindowRequests
  @Environment(VaultsModel.self) private var model

  var body: some View {
    Button("Show Command Palette") { windows.toggleKeyWindowPalette() }
      .keyboardShortcut("k", modifiers: .command)
      .disabled(!model.isAppUnlocked)
  }
}

/// View ▸ Reload. Rescans the vaults on disk.
private struct ReloadMenuItem: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    Button("Reload") { model.reload() }
      .keyboardShortcut("r", modifiers: .command)
      .disabled(!model.isAppUnlocked)
  }
}

/// Help ▸ Audit Log. The Audit Log is only available while unlocked; a locked
/// app shows the main window, and its lock screen, instead.
private struct AuditLogMenuItem: View {
  let windows: WindowRequests
  @Environment(VaultsModel.self) private var model
  @Environment(\.openWindow) private var openWindow

  var body: some View {
    Button("Audit Log") {
      guard model.isAppUnlocked, !windows.isFirstRunPending() else {
        windows.requestMain()
        return
      }
      NSApp.setActivationPolicy(.regular)
      NSApp.activate(ignoringOtherApps: true)
      openWindow(id: AxoPassApp.auditWindowID)
    }
    .disabled(!model.isAppUnlocked)
  }
}

/// Help ▸ Sync Log. Only available while unlocked; a locked app shows the main
/// window, and its lock screen, instead.
private struct SyncLogMenuItem: View {
  let windows: WindowRequests
  @Environment(VaultsModel.self) private var model
  @Environment(\.openWindow) private var openWindow

  var body: some View {
    Button("Sync Log") {
      guard model.isAppUnlocked, !windows.isFirstRunPending() else {
        windows.requestMain()
        return
      }
      NSApp.setActivationPolicy(.regular)
      NSApp.activate(ignoringOtherApps: true)
      openWindow(id: AxoPassApp.syncLogWindowID)
    }
    .disabled(!model.isAppUnlocked)
  }
}

/// Help ▸ App Keychain. Read-only, and only available while unlocked; a locked
/// app shows the main window, and its lock screen, instead.
private struct KeychainMenuItem: View {
  let windows: WindowRequests
  @Environment(VaultsModel.self) private var model
  @Environment(\.openWindow) private var openWindow

  var body: some View {
    Button("App Keychain") {
      guard model.isAppUnlocked, !windows.isFirstRunPending() else {
        windows.requestMain()
        return
      }
      NSApp.setActivationPolicy(.regular)
      NSApp.activate(ignoringOtherApps: true)
      openWindow(id: AxoPassApp.keychainWindowID)
    }
    .disabled(!model.isAppUnlocked)
  }
}
