import Observation

/// Window-open requests raised from AppKit callbacks.
///
/// `openWindow` is only readable from a scene, so `AppDelegate` bumps a counter
/// here and the scene in `App.swift` opens the window in response.
@Observable
@MainActor
final class WindowRequests {
  private(set) var mainOpens = 0

  func requestMain() { mainOpens += 1 }
}
