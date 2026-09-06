import AppKit

/// The floating panel a broker prompt is drawn in. One per prompt model.
///
/// The panel sits at `.floating`, which is above every app's normal windows, so
/// it is visible whether or not the system lets us come forward.
@MainActor
final class PromptPanel {
  /// Every broker prompt is drawn at this width, so the panels the user sees
  /// for signing, vault access and passphrase entry line up.
  static let standardWidth: CGFloat = 400

  /// Called when the panel goes up, and again when it comes down. The app steps
  /// back from the biometric hardware and the cross-process auth lock while one
  /// is up, so its own lock screen does not fight the panel for Touch ID.
  var onVisibleChange: ((Bool) -> Void)?

  private var panel: NSPanel?

  var isVisible: Bool { panel != nil }

  /// Replace whatever is on screen with `view`: gpg, ssh or a git commit in a
  /// terminal triggered this, so the user is looking at another app.
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
    // Pin the view to `width` and take only the height from its fit. Left to
    // `view.fittingSize`, a wide line in the request transcript would stretch
    // the panel past `width`, so the panels would not line up.
    view.translatesAutoresizingMaskIntoConstraints = false
    let widthConstraint = view.widthAnchor.constraint(equalToConstant: width)
    widthConstraint.isActive = true
    view.layoutSubtreeIfNeeded()
    let height = view.fittingSize.height
    widthConstraint.isActive = false
    view.translatesAutoresizingMaskIntoConstraints = true
    panel.setContentSize(NSSize(width: width, height: height))
    panel.center()
    // The panel is non-activating and sits at `.floating`, so it draws above
    // other apps and takes key for typing without activating axo-pass. Calling
    // `NSApp.activate` or `NSRunningApplication.activate` here would pull every
    // other axo-pass window to the front along with the panel.
    panel.orderFrontRegardless()
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
