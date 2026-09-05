import AppKit

/// The floating panel a broker prompt is drawn in. One per prompt model.
///
/// The panel sits at `.floating`, which is above every app's normal windows, so
/// it is visible whether or not the system lets us come forward.
@MainActor
final class PromptPanel {
  /// Called when the panel goes up, and again when it comes down. The app steps
  /// back from the biometric hardware and the cross-process auth lock while one
  /// is up, so its own lock screen does not fight the panel for Touch ID.
  var onVisibleChange: ((Bool) -> Void)?

  private var panel: NSPanel?

  var isVisible: Bool { panel != nil }

  /// Replace whatever is on screen with `view` and bring the app forward: gpg,
  /// ssh or a git commit in a terminal triggered this, so the user is looking
  /// at another app.
  func show(_ view: NSView, width: CGFloat) {
    hide()

    let panel = NSPanel(
      contentRect: NSRect(x: 0, y: 0, width: width, height: 200),
      styleMask: [.titled, .fullSizeContentView, .nonactivatingPanel],
      backing: .buffered,
      defer: false
    )
    panel.titleVisibility = .hidden
    panel.titlebarAppearsTransparent = true
    panel.isMovableByWindowBackground = true
    panel.isFloatingPanel = true
    panel.level = .floating
    panel.hidesOnDeactivate = false
    panel.contentView = view
    panel.setContentSize(view.fittingSize)
    panel.center()
    panel.orderFrontRegardless()

    // `NSApplication.activate(ignoringOtherApps:)` is deprecated on macOS 14+
    // and does nothing while another app is frontmost; `NSRunningApplication`
    // still takes effect there. The panel is non-activating, so it takes key
    // and receives typing either way.
    NSApp.activate(ignoringOtherApps: true)
    NSRunningApplication.current.activate(options: [.activateAllWindows])
    panel.makeKey()

    self.panel = panel
    onVisibleChange?(true)
  }

  func hide() {
    guard let panel else { return }
    panel.orderOut(nil)
    self.panel = nil
    onVisibleChange?(false)
  }
}
