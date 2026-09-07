import AppKit
import SwiftUI

/// Owns the model and the broker, and asks the scenes in `App.swift` to open
/// windows.
///
/// The broker starts the app with `open -g --args --broker` to say the launch
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
    Preferences.registerDefaults()
    observeWindowClose()

    // Start the broker off the window's lifetime: a headless launch has no
    // window, and closing the window later must not stop serving prompts.
    Task { await model.startBroker() }

    if model.isBrokerLaunch() {
      NSApp.setActivationPolicy(.accessory)
    } else {
      windows.requestMain()
    }
  }

  /// Reopen from the Dock or the Finder. The broker never sends one: it only
  /// runs `open` when no app is running, so a reopen is always a person.
  func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
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
    // AppKit would otherwise reopen this window on the next launch, including a
    // broker launch that must show no window at all. A launch by a person opens
    // it through `WindowRequests` instead, so nothing is lost.
    window.isRestorable = false
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

extension View {
  /// Merges the title bar into the content when `hidden`, leaving the window
  /// buttons in place. The lock screen uses this so its window is a plain
  /// panel.
  func titleBarHidden(_ hidden: Bool) -> some View {
    background(TitleBarStyle(hidden: hidden))
  }
}

/// Applies the title bar style to the enclosing window, and keeps applying it:
/// SwiftUI attaches the toolbar and settles the title bar after the view update
/// that asked for the style, so a single pass is undone a moment later.
///
/// A window that holds, or has held, a `NavigationSplitView` keeps its
/// `NSToolbar`, which draws the title bar background even when the bar itself is
/// transparent. Hiding the toolbar is therefore part of the style rather than
/// something SwiftUI is left to manage.
private struct TitleBarStyle: NSViewRepresentable {
  let hidden: Bool

  func makeCoordinator() -> Coordinator { Coordinator() }

  func makeNSView(context: Context) -> NSView {
    let view = NSView(frame: .zero)
    // The view has no window until it joins the hierarchy, which happens after
    // this returns.
    context.coordinator.attach(to: view, hidden: hidden)
    return view
  }

  func updateNSView(_ view: NSView, context: Context) {
    context.coordinator.attach(to: view, hidden: hidden)
  }

  /// Reapplies the wanted style whenever the window updates.
  @MainActor
  final class Coordinator {
    private var hidden = false
    /// Latches once the title bar has been shown, and clears on the way back to
    /// hidden. Without it, the wait for the toolbar below would re-hide the bar
    /// every time SwiftUI swaps toolbars, which it does on each pane change.
    private var isShown = false
    private weak var window: NSWindow?
    // `nonisolated(unsafe)` so `deinit` can unregister. Only ever touched on the
    // main thread: SwiftUI creates, updates and releases the coordinator there.
    private nonisolated(unsafe) var observer: (any NSObjectProtocol)?

    /// `.fullSizeContentView` is deliberately not part of this. The scene's
    /// `.hiddenTitleBar` style leaves it set for the window's whole life, which
    /// is what a unified toolbar wants anyway. Removing it misplaces the split
    /// view's toolbar items.
    struct Style {
      let titleVisibility: NSWindow.TitleVisibility
      let titlebarAppearsTransparent: Bool

      /// What `.windowStyle(.hiddenTitleBar)` gives the scene, which is how the
      /// window is born.
      static let hidden = Style(titleVisibility: .hidden, titlebarAppearsTransparent: true)

      /// A title bar that draws its own background, over full size content.
      static let shown = Style(titleVisibility: .visible, titlebarAppearsTransparent: false)
    }

    deinit {
      if let observer { NotificationCenter.default.removeObserver(observer) }
    }

    func attach(to view: NSView, hidden: Bool) {
      self.hidden = hidden
      apply()
      // The window is nil until the view joins the hierarchy, so observation
      // starts on the next pass rather than here.
      DispatchQueue.main.async { [weak self, weak view] in
        MainActor.assumeIsolated {
          guard let self, let window = view?.window else { return }
          self.observe(window)
          self.apply()
        }
      }
    }

    /// `didUpdateNotification` fires whenever the window redraws, which covers
    /// SwiftUI installing a toolbar or restoring the title bar behind our back.
    /// `apply` is idempotent, so reapplying on every pass costs nothing.
    private func observe(_ window: NSWindow) {
      guard window !== self.window else { return }
      if let observer { NotificationCenter.default.removeObserver(observer) }
      self.window = window
      observer = NotificationCenter.default.addObserver(
        forName: NSWindow.didUpdateNotification,
        object: window,
        queue: .main
      ) { [weak self] _ in
        MainActor.assumeIsolated { self?.apply() }
      }
    }

    private func apply() {
      guard let window else { return }

      // On unlock, SwiftUI builds the split view and installs its toolbar a
      // moment after the content swap. Showing the title bar before then draws
      // it empty for a frame and the toolbar flickers in after it, so the bar
      // stays merged until the toolbar is there and both land together. The
      // unlocked content always has one: `NavigationSplitView` contributes the
      // sidebar toggle.
      if hidden {
        isShown = false
      } else if window.toolbar != nil {
        isShown = true
      }

      let wanted: Style = isShown ? .shown : .hidden

      // Written only when it differs: this runs from the window's own update
      // notification, and writing back would ask for another update.
      if window.titleVisibility != wanted.titleVisibility {
        window.titleVisibility = wanted.titleVisibility
      }
      if window.titlebarAppearsTransparent != wanted.titlebarAppearsTransparent {
        window.titlebarAppearsTransparent = wanted.titlebarAppearsTransparent
      }
      if let toolbar = window.toolbar, toolbar.isVisible == hidden {
        toolbar.isVisible = !hidden
      }
    }
  }
}
