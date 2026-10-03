import AppKit

/// Keeps a hidden app hidden while a floating panel is up.
///
/// Ordering a window front in an app hidden with Command-H unhides the whole
/// app, so the main window comes back along with the panel. While the first
/// panel is up and the app was hidden, the app's other windows are made
/// transparent so the panel is the only thing drawn. When the last panel goes
/// away, the app is hidden again and the windows are restored.
///
/// Known limitation: if the user unhides the app while a panel is up, the app
/// is hidden again when the panel closes.
@MainActor
final class PanelAppVisibility {
  static let shared = PanelAppVisibility()

  private var panelCount = 0
  private var covered: [NSWindow] = []
  /// Windows waiting for the app to finish hiding before they are restored.
  private var pendingRestore: [NSWindow] = []
  private var hideObserver: NSObjectProtocol?

  /// Call before ordering a panel front.
  func panelWillShow() {
    panelCount += 1
    guard panelCount == 1, NSApp.isHidden else { return }
    // The locked main window has no title bar, so `canBecomeMain` is false for
    // it. Normal level excludes the status item windows.
    covered = NSApp.windows.filter { $0.level == .normal && !($0 is NSPanel) }
    for window in covered {
      window.alphaValue = 0
      window.ignoresMouseEvents = true
    }
  }

  /// Call when the user asks for one of the app's windows. The covered windows
  /// are shown and the app stays visible when the panel closes.
  func windowRequested() {
    for window in covered {
      window.alphaValue = 1
      window.ignoresMouseEvents = false
    }
    covered = []
  }

  /// Call after ordering a panel out.
  func panelDidHide() {
    panelCount = max(0, panelCount - 1)
    guard panelCount == 0, !covered.isEmpty else { return }
    // Hiding is not immediate, so the windows stay transparent until the app
    // reports it is hidden. A timeout restores them if that never happens.
    pendingRestore = covered
    covered = []
    hideObserver = NotificationCenter.default.addObserver(
      forName: NSApplication.didHideNotification, object: nil, queue: .main
    ) { [weak self] _ in
      MainActor.assumeIsolated { self?.restorePending() }
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
      MainActor.assumeIsolated { self?.restorePending() }
    }
    NSApp.hide(nil)
  }

  private func restorePending() {
    if let hideObserver { NotificationCenter.default.removeObserver(hideObserver) }
    hideObserver = nil
    for window in pendingRestore {
      window.alphaValue = 1
      window.ignoresMouseEvents = false
    }
    pendingRestore = []
  }
}
