import AppKit
import SwiftUI

/// The floating panel a broker prompt is drawn in. One per prompt model.
///
/// The panel sits at `.floating`, which is above every app's normal windows, so
/// it is visible whether or not the system lets us come forward. It is a
/// hand-rolled `NSPanel` because SwiftUI has no non-activating window scene:
/// gpg, ssh or a git commit in another app's terminal triggers the prompt, and
/// the panel must take key for typing without activating axo-pass.
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
  private var host: NSHostingController<AnyView>?
  private var sizeObservation: NSKeyValueObservation?

  var isVisible: Bool { panel != nil }

  /// Replace whatever is on screen with `content`. Reuses the panel if one is
  /// already up, swapping only the SwiftUI content.
  func show(_ content: some View) {
    // Pin the width and let SwiftUI pick the height. `fixedSize(vertical:)`
    // makes the content keep its ideal height while the panel animates to
    // match, so a disclosure opening is revealed by clipping rather than by
    // squeezing the rows.
    let root = AnyView(
      content
        .frame(width: Self.standardWidth, alignment: .top)
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxHeight: .infinity, alignment: .top)
    )

    if let host {
      host.rootView = root
      panel?.makeKey()
      return
    }

    let host = NSHostingController(rootView: root)
    host.sizingOptions = [.preferredContentSize]
    // The window frame changes during layout. With a safe area to track, the
    // hosting view invalidates it mid-layout and AppKit raises an exception.
    // The panel has no full size content view, so there are no insets to lose.
    host.safeAreaRegions = []

    let panel = NSPanel(
      contentRect: NSRect(x: 0, y: 0, width: Self.standardWidth, height: 200),
      styleMask: [.titled, .nonactivatingPanel],
      backing: .buffered,
      defer: false
    )
    panel.titleVisibility = .hidden
    panel.titlebarAppearsTransparent = true
    panel.isMovableByWindowBackground = true
    panel.isFloatingPanel = true
    panel.level = .floating
    panel.hidesOnDeactivate = false
    panel.contentViewController = host
    panel.setContentSize(host.preferredContentSize)
    panel.center()

    // Follow the content when a disclosure inside the prompt opens or closes,
    // resizing from the top edge so the title bar stays put.
    sizeObservation = host.observe(\.preferredContentSize) { [weak self] host, _ in
      // This fires during the window's layout pass. Changing the frame there
      // invalidates the hosting view's safe area mid-layout, which AppKit
      // raises as an exception, so the resize runs on the next turn.
      MainActor.assumeIsolated {
        let height = host.preferredContentSize.height
        DispatchQueue.main.async {
          MainActor.assumeIsolated {
            self?.resize(toContentHeight: height)
          }
        }
      }
    }

    // The panel is non-activating and sits at `.floating`, so it draws above
    // other apps and takes key for typing without activating axo-pass. Calling
    // `NSApp.activate` or `NSRunningApplication.activate` here would pull every
    // other axo-pass window to the front along with the panel.
    panel.orderFrontRegardless()
    panel.makeKey()

    self.panel = panel
    self.host = host
    onVisibleChange?(true)
  }

  /// Grow or shrink the panel to a new content height, keeping its top edge
  /// fixed so the prompt appears to expand and collapse downward.
  private func resize(toContentHeight contentHeight: CGFloat) {
    guard let panel, contentHeight > 0 else { return }

    let chrome = panel.frame.height - panel.contentLayoutRect.height
    let targetHeight = contentHeight + chrome
    var frame = panel.frame
    guard abs(frame.height - targetHeight) >= 0.5 else { return }

    frame.origin.y += frame.height - targetHeight
    frame.size.height = targetHeight

    NSAnimationContext.runAnimationGroup { context in
      context.duration = 0.22
      context.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
      panel.animator().setFrame(frame, display: true)
    }
  }

  func hide() {
    guard let panel else { return }
    sizeObservation = nil
    host = nil
    panel.orderOut(nil)
    self.panel = nil
    onVisibleChange?(false)
  }
}
