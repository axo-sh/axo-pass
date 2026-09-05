import AppKit
import SwiftUI

/// Owns the model, the broker, and the main window.
///
/// The broker starts the app with `open -g`, leaving a marker to say the launch
/// is its own (see `crates/core/src/core/app_broker/mod.rs`). In that case no
/// window is built and the app runs as an accessory (no Dock icon): the prompt
/// is an `NSPanel` that shows on its own. Opening the app from the Dock or
/// Finder afterwards builds the window and restores the Dock icon.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
  let model = VaultsModel()
  private var mainWindow: NSWindow?

  func applicationDidFinishLaunching(_ notification: Notification) {
    // Start the broker off the window's lifetime: a headless launch has no
    // window, and closing the window later must not stop serving prompts.
    Task { await model.startBroker() }

    if model.takeBrokerLaunchRequest() {
      NSApp.setActivationPolicy(.accessory)
    } else {
      showMainWindow()
    }
  }

  /// Reopen from the Dock or the Finder. `open` sends this to an app that is
  /// already running, so it is also how a second broker request arrives, and
  /// serving one must not put a window on screen or pull focus.
  func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
    if model.takeBrokerLaunchRequest() { return false }
    showMainWindow()
    return true
  }

  /// The broker and SSH agent outlive the window.
  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    false
  }

  /// Closing the window leaves the broker serving with nothing to show, so step
  /// back out of the Dock rather than keeping an icon that opens nothing. The
  /// window is kept: a reopen brings the same one back.
  func windowWillClose(_ notification: Notification) {
    guard notification.object as AnyObject === mainWindow else { return }
    NSApp.setActivationPolicy(.accessory)
  }

  private func showMainWindow() {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)

    if let window = mainWindow {
      model.reload()
      window.makeKeyAndOrderFront(nil)
      return
    }

    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 960, height: 560),
      styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
      backing: .buffered,
      defer: false
    )
    window.title = "Axo Pass"
    window.titleVisibility = .hidden
    window.titlebarAppearsTransparent = true
    window.isReleasedWhenClosed = false
    window.minSize = NSSize(width: 640, height: 400)
    window.delegate = self

    let host = NSHostingController(rootView: ContentView().environment(model))
    // Otherwise the controller shrinks the window to the SwiftUI view's
    // fitting size, which a NavigationSplitView collapses to almost nothing.
    host.sizingOptions = []
    window.contentViewController = host

    window.setFrameAutosaveName("AxoPassMain")
    if !window.setFrameUsingName("AxoPassMain") {
      window.setContentSize(NSSize(width: 960, height: 560))
      window.center()
    }
    mainWindow = window

    model.reload()
    window.makeKeyAndOrderFront(nil)
  }
}
