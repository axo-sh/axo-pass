import AppKit
import AxoPassFFI
import SunshineCore
import SunshineUI
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
  /// Sync of the vaults. One instance for the app, on the core of `model`.
  private(set) lazy var sync = SyncModel(vaults: model)
  /// Issues of the app, read from `model`, `sync`, and the SSH, GPG, shell, and
  /// AutoFill checks.
  private(set) lazy var issues = IssuesModel(vaults: model, sync: sync)
  let windows = WindowRequests()
  /// Notifications for urgent issues.
  private lazy var issueNotifier = IssueNotifier(issues: issues, vaults: model, windows: windows)

  /// Auto-update against GitHub Releases. An update installs only if it is
  /// signed by the same Developer ID Team as the running app.
  private(set) lazy var updaterUI: SunshineUpdaterUIController =
    AppDelegate.updaterUIFactory?() ?? AppDelegate.makeUpdaterUI()

  /// Set by an untracked local build (`SunshineFakeUpdate.swift`, gitignored) to
  /// drive the update UI from canned release data. Nil in a normal build.
  static var updaterUIFactory: (() -> SunshineUpdaterUIController)?

  private static func makeUpdaterUI() -> SunshineUpdaterUIController {
    let controller = SunshineUpdaterUIController(
      updater: SunshineUpdater(
        configuration: SunshineConfiguration(
          owner: "axo-sh",
          repo: "axo-pass",
          checkInterval: 3600
        )
      )
    )
    // Match `.sunshineUpdater(style:)` in `App.swift` up front, so a check that
    // finishes before that modifier's `.task` runs still routes to the corner
    // indicator rather than popping a sheet.
    controller.updateUIStyle = .cornerIndicator
    return controller
  }

  /// The main scene's window, handed over by `WindowAccessor` once SwiftUI has
  /// built it. Held weakly: the scene owns its lifetime.
  private weak var mainWindow: NSWindow?

  /// The welcome scene's window. Held weakly like `mainWindow`.
  private weak var welcomeWindow: NSWindow?

  /// The menu bar icon, its palette and its menu. Present for every launch,
  /// including a broker launch, so an app without a window can still be
  /// reached and quit.
  private var statusItem: StatusItemController?

  /// Alerts if the app bundle is moved or deleted while running.
  private let locationMonitor = AppLocationMonitor()

  func applicationDidFinishLaunching(_ notification: Notification) {
    // A launch from a disk image offers to move the app before any setup runs.
    // A broker launch shows no prompt.
    if !model.isBrokerLaunch(), let source = MoveToApplications.diskImageBundle() {
      Task {
        await MoveToApplications.offer(source: source)
        finishLaunching()
      }
      return
    }
    finishLaunching()
  }

  private func finishLaunching() {
    Preferences.registerDefaults()
    // List the vaults before any window is requested, since first run is
    // pending only if none exists. A Mac that already has a vault never shows
    // the welcome window, even if every vault is deleted later.
    model.reload()
    if !model.vaults.isEmpty { Preferences.hasCompletedFirstRun = true }
    windows.isFirstRunPending = { [weak model] in
      guard let model else { return false }
      #if DEBUG
        if DevOverrides.shared.forceWelcome { return true }
      #endif
      return !Preferences.hasCompletedFirstRun && model.vaults.isEmpty && model.loadError == nil
    }
    locationMonitor.start()
    // The sync manager started with the core of `model`. Events sent before
    // this are only logged, except the pairing counts, which are replayed.
    sync.register()
    issues.start()
    issueNotifier.start()
    observeWindowClose()
    statusItem = StatusItemController(model: model, issues: issues, windows: windows) {
      [weak self] in
      guard let self else { return }
      // The result shows in the main window.
      self.windows.requestMain()
      self.updaterUI.checkForUpdatesButtonTapped()
    }

    // Confirms a pending relaunch from a previous update. Must run early.
    SunshineUpdater.confirmSuccessfulRelaunchIfNeeded()

    // Start the broker off the window's lifetime: a headless launch has no
    // window, and closing the window later must not stop serving prompts.
    Task { await model.startBroker() }

    let brokerLaunch = model.isBrokerLaunch()
    Task { await AgentService.shared.sync(launch: true, startIfStopped: !brokerLaunch) }

    // Install browser manifests that are missing, and point the ones we own
    // back at the bundled host. Manifests that name another host are left
    // alone.
    Task { await ensureBrowserManifests() }

    if brokerLaunch {
      NSApp.setActivationPolicy(.accessory)
    } else {
      windows.requestMain()
    }
  }

  /// Check the agent against the bundled `ap` when the app comes to the front,
  /// since an update replaces the binary under a running agent. Re-read the
  /// issues, since files may have changed outside the app.
  func applicationDidBecomeActive(_ notification: Notification) {
    Task { await AgentService.shared.sync(launch: false) }
    Task { await issues.refreshAll() }
  }

  /// The app always starts from a locked state, so a relaunch shows only the
  /// lock screen. Here we globally decline restoration.
  func application(_ app: NSApplication, shouldSaveApplicationState coder: NSCoder) -> Bool {
    false
  }

  func application(_ app: NSApplication, shouldRestoreApplicationState coder: NSCoder) -> Bool {
    false
  }

  /// Reopen from the Dock or the Finder. The broker never sends one: it only
  /// runs `open` when no app is running, so a reopen is always a person.
  func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
    windows.requestMain()
    return true
  }

  /// Stop the sync manager, which deletes a pending pairing request.
  func applicationWillTerminate(_ notification: Notification) {
    syncShutdown()
  }

  /// The broker and SSH agent outlive the window.
  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    false
  }

  /// Called from the welcome scene's content once its window exists.
  func adoptWelcomeWindow(_ window: NSWindow) {
    welcomeWindow = window
    // A relaunch shows the welcome window again through `WindowRequests` if
    // first run is still pending, so restoration is not needed.
    window.isRestorable = false
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
  /// The welcome window does the same, unless first run finished. Then the
  /// main window opens next and restores the Dock icon.
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
        guard let self, let closing else { return }
        if closing === self.mainWindow {
          NSApp.setActivationPolicy(.accessory)
        } else if closing === self.welcomeWindow, !Preferences.hasCompletedFirstRun {
          NSApp.setActivationPolicy(.accessory)
        }
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
  /// buttons in place. The lock screen and pages such as Today use this so the
  /// bar is not visible.
  func titleBarHidden(_ hidden: Bool) -> some View {
    modifier(TitleBarStyle(hidden: hidden))
  }
}

/// Applies the title bar style to the enclosing window.
///
/// The lock screen carries an empty toolbar and an empty navigation title of its
/// own, so the window always has an `NSToolbar` and the bar being hidden holds
/// nothing. Without that, SwiftUI installs the split view's toolbar a moment
/// after the content swap and the bar flickers.
private struct TitleBarStyle: ViewModifier {
  let hidden: Bool
  @Environment(\.scenePhase) private var scenePhase
  @State private var window: NSWindow?

  func body(content: Content) -> some View {
    content
      .background(
        WindowAccessor { window in
          if self.window !== window { self.window = window }
          apply(to: window)
        }
      )
      .onChange(of: hidden) { apply(to: window) }
      // AppKit settles the title bar again when the window returns to the
      // front, so the wanted style is reapplied there too.
      .onChange(of: scenePhase) { _, phase in
        if phase == .active { apply(to: window) }
      }
  }

  /// Note: we don't use `.fullSizeContentView`. Setting causes the split view's toolbar items to
  /// get out of place.
  ///
  /// `titleVisibility` is left visible. Hiding it shrinks the unified toolbar
  /// from 52 to 38 points, and SwiftUI restores it shortly after, so the
  /// window buttons move on launch. The hidden views set an empty title.
  private func apply(to window: NSWindow?) {
    guard let window else { return }
    window.titlebarAppearsTransparent = hidden
  }
}
