import AppKit
import SwiftUI

/// Owns the model and the broker, and asks the scenes in `App.swift` to open
/// windows.
///
/// The broker starts the app with `open -g`, leaving a marker to say the launch
/// is its own (see `crates/core/src/core/app_broker/mod.rs`). In that case no
/// window is opened and the app runs as an accessory (no Dock icon): the prompt
/// is an `NSPanel` that shows on its own. Opening the app from the Dock or
/// Finder afterwards opens the window and restores the Dock icon.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
  let model = VaultsModel()
  let windows = WindowRequests()

  /// The main scene's window, handed over by `WindowAccessor` once SwiftUI has
  /// built it. Held weakly: the scene owns its lifetime.
  private weak var mainWindow: NSWindow?

  func applicationDidFinishLaunching(_ notification: Notification) {
    observeWindowClose()

    // Start the broker off the window's lifetime: a headless launch has no
    // window, and closing the window later must not stop serving prompts.
    Task { await model.startBroker() }

    if model.takeBrokerLaunchRequest() {
      NSApp.setActivationPolicy(.accessory)
    } else {
      windows.requestMain()
    }
  }

  /// Reopen from the Dock or the Finder. `open` sends this to an app that is
  /// already running, so it is also how a second broker request arrives, and
  /// serving one must not put a window on screen or pull focus.
  func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
    if model.takeBrokerLaunchRequest() { return false }
    windows.requestMain()
    return true
  }

  /// The broker and SSH agent outlive the window.
  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    false
  }

  /// Called from the main scene's content once its window exists.
  func adoptMainWindow(_ window: NSWindow) {
    mainWindow = window
  }

  /// Closing the main window leaves the broker serving with nothing to show, so
  /// step back out of the Dock rather than keeping an icon that opens nothing.
  ///
  /// This observes the notification rather than becoming the window's delegate:
  /// the window belongs to a SwiftUI scene, which installs a delegate of its
  /// own and relies on it.
  private func observeWindowClose() {
    NotificationCenter.default.addObserver(
      forName: NSWindow.willCloseNotification,
      object: nil,
      queue: .main
    ) { [weak self] notification in
      let closing = notification.object as? NSWindow
      MainActor.assumeIsolated {
        guard let self, let closing, closing === self.mainWindow else { return }
        NSApp.setActivationPolicy(.accessory)
      }
    }
  }
}

/// Hands the enclosing `NSWindow` to `AppDelegate`. SwiftUI owns the window of
/// a `Window` scene, so this is how the few AppKit-only behaviours reach it.
struct WindowAccessor: NSViewRepresentable {
  let onWindow: (NSWindow) -> Void

  func makeNSView(context: Context) -> NSView {
    let view = NSView(frame: .zero)
    // The view has no window until it joins the hierarchy, which happens after
    // this returns.
    DispatchQueue.main.async {
      if let window = view.window { onWindow(window) }
    }
    return view
  }

  func updateNSView(_ view: NSView, context: Context) {
    if let window = view.window { onWindow(window) }
  }
}
