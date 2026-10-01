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

  func requestMain() { mainOpens += 1 }
  func requestAudit() { auditOpens += 1 }
  func requestKeychain() { keychainOpens += 1 }
  func requestSettings() { settingsOpens += 1 }
}
