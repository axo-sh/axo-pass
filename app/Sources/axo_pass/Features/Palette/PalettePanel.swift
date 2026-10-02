import AppKit
import SwiftUI

/// Keys the palette handles before the search field sees them.
enum PaletteKey {
  case up, down, enter, commandEnter, commandK, tab, shiftTab, escape, deleteInEmptyField
}

/// The floating window the palette is drawn in, anchored under the status item.
///
/// Like `PromptPanel`, it is a non-activating `NSPanel`: it takes key for typing
/// without activating Axo Pass, so the app the user was in stays frontmost and
/// gets the copied value. It closes when it loses key.
@MainActor
final class PalettePanel {
  static let width: CGFloat = 560

  /// Called when the panel closes, for any reason.
  var onClose: (() -> Void)?
  /// Called for the navigation keys. Returns true when the key was handled.
  var onKey: ((PaletteKey) -> Bool)?
  /// Called when Option goes down or up while the panel is key.
  var onOptionChange: ((Bool) -> Void)?
  /// Whether losing key should leave the panel open. True while a system
  /// dialog the palette raised, such as the login password prompt, is up.
  var staysOpenOnResignKey: () -> Bool = { false }

  private var panel: KeyPanel?
  private var host: NSHostingController<AnyView>?
  private var sizeObservation: NSKeyValueObservation?
  private var resignObserver: NSObjectProtocol?
  /// Top edge of the panel in screen coordinates. Resizing keeps it fixed.
  private var top: CGFloat = 0

  var isVisible: Bool { panel != nil }

  /// Show `content` under `button`.
  func show(_ content: some View, below button: NSStatusBarButton) {
    if panel != nil { hide() }

    let host = NSHostingController(rootView: AnyView(content.frame(width: Self.width)))
    host.sizingOptions = [.preferredContentSize]
    // The panel is borderless, so there are no safe area insets to track. Without
    // this, a frame change during the window's layout pass invalidates the
    // hosting view's safe area and requests a constraint update mid-layout, which
    // AppKit raises as an exception.
    host.safeAreaRegions = []

    let panel = KeyPanel(
      contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 300),
      styleMask: [.borderless, .nonactivatingPanel],
      backing: .buffered,
      defer: false
    )
    panel.isFloatingPanel = true
    panel.level = .floating
    panel.hidesOnDeactivate = false
    panel.isOpaque = false
    panel.backgroundColor = .clear
    panel.hasShadow = true
    panel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
    panel.contentViewController = host
    panel.onKey = { [weak self] key in self?.onKey?(key) ?? false }
    panel.onOptionChange = { [weak self] held in self?.onOptionChange?(held) }

    place(panel, below: button, height: host.preferredContentSize.height)

    sizeObservation = host.observe(\.preferredContentSize) { [weak self] host, _ in
      MainActor.assumeIsolated {
        self?.resize(toHeight: host.preferredContentSize.height)
      }
    }
    resignObserver = NotificationCenter.default.addObserver(
      forName: NSWindow.didResignKeyNotification, object: panel, queue: .main
    ) { [weak self] _ in
      MainActor.assumeIsolated {
        guard let self, !self.staysOpenOnResignKey() else { return }
        self.hide()
      }
    }

    panel.orderFrontRegardless()
    panel.makeKey()

    self.panel = panel
    self.host = host
  }

  func hide() {
    guard let panel else { return }
    if let resignObserver { NotificationCenter.default.removeObserver(resignObserver) }
    resignObserver = nil
    sizeObservation = nil
    host = nil
    self.panel = nil
    panel.orderOut(nil)
    onClose?()
  }

  /// Bring the panel back to key, after a system dialog it raised has closed.
  func makeKey() {
    panel?.makeKey()
  }

  /// Centre the panel under the status item, kept inside the visible frame of
  /// the screen the status item is on.
  private func place(_ panel: NSPanel, below button: NSStatusBarButton, height: CGFloat) {
    guard let buttonWindow = button.window else {
      panel.center()
      top = panel.frame.maxY
      return
    }
    let anchor = buttonWindow.convertToScreen(button.convert(button.bounds, to: nil))
    let visible = (buttonWindow.screen ?? NSScreen.main)?.visibleFrame ?? anchor
    top = anchor.minY - 6
    var x = anchor.midX - Self.width / 2
    x = min(max(x, visible.minX + 8), visible.maxX - Self.width - 8)
    panel.setFrame(NSRect(x: x, y: top - height, width: Self.width, height: height), display: true)
  }

  private func resize(toHeight height: CGFloat) {
    guard let panel, height > 0, abs(panel.frame.height - height) >= 0.5 else { return }
    var frame = panel.frame
    frame.origin.y = top - height
    frame.size.height = height
    panel.setFrame(frame, display: true)
    // A clear window's shadow follows its content, which just changed shape.
    panel.invalidateShadow()
  }
}

/// A borderless panel that can take key, and that routes the palette's
/// navigation keys before the search field's editor consumes them.
private final class KeyPanel: NSPanel {
  var onKey: ((PaletteKey) -> Bool)?
  var onOptionChange: ((Bool) -> Void)?

  override var canBecomeKey: Bool { true }
  override var canBecomeMain: Bool { false }

  override func resignKey() {
    super.resignKey()
    // The key-up of a held Option is not delivered to a window that is no
    // longer key.
    onOptionChange?(false)
  }

  override func sendEvent(_ event: NSEvent) {
    if event.type == .flagsChanged {
      onOptionChange?(event.modifierFlags.contains(.option))
    }
    if event.type == .keyDown, let key = paletteKey(for: event), onKey?(key) == true {
      return
    }
    super.sendEvent(event)
  }

  private func paletteKey(for event: NSEvent) -> PaletteKey? {
    let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
    let command = flags.contains(.command)
    switch event.keyCode {
    case 126: return .up
    case 125: return .down
    case 36, 76: return command ? .commandEnter : .enter
    case 48 where flags.isEmpty: return .tab
    case 48 where flags == .shift: return .shiftTab
    case 53: return .escape
    case 51: return fieldIsEmpty ? .deleteInEmptyField : nil
    case 40 where command: return .commandK
    default: return nil
    }
  }

  /// Whether the focused text field, if any, holds no text.
  private var fieldIsEmpty: Bool {
    guard let editor = firstResponder as? NSTextView else { return false }
    return editor.string.isEmpty
  }
}
