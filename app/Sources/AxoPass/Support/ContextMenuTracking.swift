import AppKit
import SwiftUI

extension View {
  /// Report when a context menu opens on this view and when it closes. A right
  /// click or Control-click inside the view frame counts as opening.
  func onContextMenuTracking(_ onChange: @escaping (Bool) -> Void) -> some View {
    background(ContextMenuTracker(onChange: onChange))
  }
}

/// Watches clicks that open a context menu inside its frame. Does not take
/// part in hit testing, so the menu still comes from the SwiftUI view above.
/// Watching stops if the view leaves its window.
private struct ContextMenuTracker: NSViewRepresentable {
  let onChange: (Bool) -> Void

  func makeNSView(context: Context) -> TrackerView {
    let view = TrackerView()
    view.onChange = onChange
    return view
  }

  func updateNSView(_ view: TrackerView, context: Context) {
    view.onChange = onChange
  }

  final class TrackerView: NSView {
    var onChange: ((Bool) -> Void)?
    private var monitor: Any?
    private var menuObserver: NSObjectProtocol?
    private var isOpen = false

    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    override func viewDidMoveToWindow() {
      super.viewDidMoveToWindow()
      stopWatching()
      if window != nil { startWatching() }
    }

    private func startWatching() {
      monitor = NSEvent.addLocalMonitorForEvents(matching: [.rightMouseDown, .leftMouseDown]) {
        [weak self] event in
        self?.handle(event)
        return event
      }
      menuObserver = NotificationCenter.default.addObserver(
        forName: NSMenu.didEndTrackingNotification, object: nil, queue: .main
      ) { [weak self] _ in
        MainActor.assumeIsolated { self?.close() }
      }
    }

    private func stopWatching() {
      if let monitor { NSEvent.removeMonitor(monitor) }
      if let menuObserver { NotificationCenter.default.removeObserver(menuObserver) }
      monitor = nil
      menuObserver = nil
    }

    private func handle(_ event: NSEvent) {
      let opensMenu =
        event.type == .rightMouseDown
        || (event.type == .leftMouseDown && event.modifierFlags.contains(.control))
      guard opensMenu, event.window === window else { return }
      let point = convert(event.locationInWindow, from: nil)
      guard bounds.contains(point) else { return }
      isOpen = true
      onChange?(true)
    }

    private func close() {
      guard isOpen else { return }
      isOpen = false
      onChange?(false)
    }
  }
}
