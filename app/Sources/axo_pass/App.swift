import AppKit
import SwiftUI

@main
struct AxoPassApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
  @Environment(\.openWindow) private var openWindow

  var body: some Scene {
    // `.defaultLaunchBehavior(.suppressed)` keeps SwiftUI from opening these on
    // launch: a broker-only launch shows no window at all. They open in response
    // to `WindowRequests`, or to the Audit Log menu item.
    Window("Axo Pass", id: Self.mainWindowID) {
      ContentView()
        .environment(appDelegate.model)
        .frame(minWidth: 640, minHeight: 400)
        .onAppear { appDelegate.model.reload() }
        .background(WindowAccessor { appDelegate.adoptMainWindow($0) })
    }
    .defaultSize(width: 960, height: 560)
    .defaultLaunchBehavior(.suppressed)
    .onChange(of: appDelegate.windows.mainOpens, initial: true) { _, count in
      guard count > 0 else { return }
      NSApp.setActivationPolicy(.regular)
      NSApp.activate(ignoringOtherApps: true)
      openWindow(id: Self.mainWindowID)
    }

    Window("Audit Log", id: Self.auditWindowID) {
      AuditLogWindow()
        .environment(appDelegate.model)
        .frame(minWidth: 640, minHeight: 360)
    }
    .defaultSize(width: 900, height: 520)
    .defaultLaunchBehavior(.suppressed)

    // Only here because `App` needs a scene to hang commands off; it renders
    // nothing and its Settings menu item is removed.
    Settings { EmptyView() }
      .commands {
        CommandGroup(replacing: .appSettings) {}
        CommandGroup(after: .help) {
          AuditLogMenuItem(windows: appDelegate.windows)
            .environment(appDelegate.model)
        }
        // Declared rather than left to the default menu: the passphrase panel
        // is shown from a launch that opens no window, and pasting a
        // passphrase out of a password manager needs these key equivalents.
        TextEditingCommands()
      }
  }

  static let mainWindowID = "main"
  static let auditWindowID = "audit"
}

/// Help ▸ Audit Log. The Audit Log is only available while unlocked; a locked
/// app shows the main window, and its lock screen, instead.
private struct AuditLogMenuItem: View {
  let windows: WindowRequests
  @Environment(VaultsModel.self) private var model
  @Environment(\.openWindow) private var openWindow

  var body: some View {
    Button("Audit Log") {
      guard model.isAppUnlocked else {
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
