import AppKit
import Foundation

/// Locks the app after a stretch without user input, and immediately when the
/// machine sleeps or the screen locks.
///
/// Only input delivered to this app counts as activity. Working in another app
/// is not a reason to keep the vaults decrypted.
@MainActor
final class AutoLock {
  /// Idle time before locking.
  static let timeout: TimeInterval = 5 * 60

  private let onLock: () -> Void
  private var timer: Timer?
  private var eventMonitor: Any?
  private var observers: [(NotificationCenter, NSObjectProtocol)] = []

  private static let activityEvents: NSEvent.EventTypeMask = [
    .keyDown, .flagsChanged, .leftMouseDown, .rightMouseDown, .otherMouseDown,
    .scrollWheel, .mouseMoved,
  ]

  init(onLock: @escaping () -> Void) {
    self.onLock = onLock
  }

  /// Start watching. Call once the app is unlocked.
  func start() {
    stop()

    eventMonitor = NSEvent.addLocalMonitorForEvents(matching: Self.activityEvents) {
      [weak self] event in
      self?.restartTimer()
      return event
    }

    observe(NSWorkspace.shared.notificationCenter, NSWorkspace.willSleepNotification)
    observe(
      DistributedNotificationCenter.default(),
      Notification.Name("com.apple.screenIsLocked"))

    restartTimer()
  }

  /// Stop watching. Call on lock, so a locked app holds no timer or monitor.
  func stop() {
    timer?.invalidate()
    timer = nil
    if let eventMonitor { NSEvent.removeMonitor(eventMonitor) }
    eventMonitor = nil
    for (center, observer) in observers { center.removeObserver(observer) }
    observers = []
  }

  private func observe(_ center: NotificationCenter, _ name: Notification.Name) {
    let observer = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
      MainActor.assumeIsolated { self?.fire() }
    }
    observers.append((center, observer))
  }

  private func restartTimer() {
    timer?.invalidate()
    timer = Timer.scheduledTimer(withTimeInterval: Self.timeout, repeats: false) { [weak self] _ in
      MainActor.assumeIsolated { self?.fire() }
    }
  }

  private func fire() {
    stop()
    onLock()
  }
}
