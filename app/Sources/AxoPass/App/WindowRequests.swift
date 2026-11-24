import AppKit
import Observation

/// Window-open requests raised from AppKit callbacks.
///
/// `openWindow` and `openSettings` are only readable from a scene, so AppKit
/// code bumps a counter here and the scene in `App.swift` opens the window in
/// response.
@Observable
@MainActor
final class WindowRequests {
  private(set) var mainOpens = 0
  private(set) var auditOpens = 0
  private(set) var keychainOpens = 0
  private(set) var settingsOpens = 0

  /// Toggles the command palette under a rect in screen coordinates. Set by
  /// `StatusItemController`.
  var togglePalette: (NSRect, NSScreen?) -> Void = { _, _ in }

  /// Toggle the command palette centered under the key window's toolbar.
  func toggleKeyWindowPalette() {
    guard let window = NSApp.keyWindow else { return }
    let toolbarBottom = window.frame.minY + window.contentLayoutRect.maxY
    let anchor = NSRect(x: window.frame.midX, y: toolbarBottom, width: 0, height: 0)
    togglePalette(anchor, window.screen)
  }

  /// Whether the welcome window stands in for the main window. True until a
  /// choice in the welcome window finishes, if no vault exists. Set by
  /// `AppDelegate`.
  var isFirstRunPending: () -> Bool = { false }

  /// Ask for the main window. The scene in `App.swift` opens the welcome window
  /// instead while `isFirstRunPending`.
  func requestMain() {
    PanelAppVisibility.shared.windowRequested()
    mainOpens += 1
  }
  func requestAudit() {
    PanelAppVisibility.shared.windowRequested()
    auditOpens += 1
  }
  func requestKeychain() {
    PanelAppVisibility.shared.windowRequested()
    keychainOpens += 1
  }
  /// Selected Settings tab.
  var settingsTab: SettingsTab = .terminal

  /// Ask for the Settings window, at `tab` if given.
  func requestSettings(tab: SettingsTab? = nil) {
    if let tab { settingsTab = tab }
    PanelAppVisibility.shared.windowRequested()
    settingsOpens += 1
  }
}
