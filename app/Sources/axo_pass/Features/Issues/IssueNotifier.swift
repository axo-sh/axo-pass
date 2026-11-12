import AppKit
import Foundation
import Observation
import UserNotifications

/// Posts a macOS notification when an urgent issue appears. One instance for
/// the app, and the delegate of the notification center.
///
/// Only these issues notify: agent not running while ssh or the shell
/// integration points at it, sync stopped, pairing requests, and vault key
/// state. Each issue id notifies at most once per `repeatInterval`. Issues
/// present when watching starts do not notify. Watching starts after
/// `launchDelay`, so state that loads after launch does not look like a
/// change. Clicking a notification opens Today.
@MainActor
final class IssueNotifier: NSObject {
  /// Category of issue notifications.
  nonisolated static let category = "issue"

  private static let launchDelay: Duration = .seconds(20)
  private static let repeatInterval: TimeInterval = 60 * 60
  /// A stopped agent does not notify for this long after the app stops it.
  private static let stopGrace: TimeInterval = 60

  private let issues: IssuesModel
  private let vaults: VaultsModel
  private let windows: WindowRequests

  /// Ids of notifying issues at the last check.
  private var active: Set<String> = []
  /// Time of the last notification of each issue id.
  private var lastPosted: [String: Date] = [:]

  init(issues: IssuesModel, vaults: VaultsModel, windows: WindowRequests) {
    self.issues = issues
    self.vaults = vaults
    self.windows = windows
    super.init()
  }

  /// Become the notification center delegate and ask for permission, then
  /// start watching after `launchDelay`. Call once at launch.
  func start() {
    let center = UNUserNotificationCenter.current()
    center.delegate = self
    center.requestAuthorization(options: [.alert]) { _, error in
      if let error {
        NSLog("IssueNotifier: notification permission failed: %@", String(describing: error))
      }
    }
    Task { [weak self] in
      try? await Task.sleep(for: Self.launchDelay)
      guard let self else { return }
      self.active = Set(self.notifying().map(\.id))
      self.observe()
    }
  }

  /// Check now and again each time the issues change.
  private func observe() {
    let current = withObservationTracking {
      notifying()
    } onChange: { [weak self] in
      Task { @MainActor in self?.observe() }
    }
    let now = Date()
    for issue in current where !active.contains(issue.id) {
      if let last = lastPosted[issue.id], now.timeIntervalSince(last) < Self.repeatInterval {
        continue
      }
      if isStoppedByApp(issue) { continue }
      lastPosted[issue.id] = now
      post(issue)
    }
    active = Set(current.map(\.id))
  }

  /// Current issues of the kinds that notify.
  private func notifying() -> [Issue] {
    issues.issues.filter { issue in
      switch issue {
      case .agentNotRunning(_, let inUse): return inUse
      case .syncStopped, .pairingRequests, .vaultKeyState: return true
      default: return false
      }
    }
  }

  /// Whether `issue` is a stopped agent that the app stopped within
  /// `stopGrace`. The issue is still recorded as active, so it does not
  /// notify after the grace ends.
  private func isStoppedByApp(_ issue: Issue) -> Bool {
    guard case .agentNotRunning = issue,
      let stopped = AgentService.shared.lastStopRequest
    else { return false }
    return Date().timeIntervalSince(stopped) < Self.stopGrace
  }

  private func post(_ issue: Issue) {
    let content = UNMutableNotificationContent()
    content.title = issue.title
    content.body = body(issue)
    content.categoryIdentifier = Self.category
    let request = UNNotificationRequest(
      identifier: "issue-\(issue.id)", content: content, trigger: nil)
    UNUserNotificationCenter.current().add(request) { error in
      if let error {
        NSLog("IssueNotifier: could not post notification: %@", String(describing: error))
      }
    }
  }

  private func body(_ issue: Issue) -> String {
    switch issue {
    case .agentNotRunning:
      return "ssh cannot use keys in Axo Pass until the agent starts."
    case .syncStopped:
      return "Changes to this vault are not synced."
    default:
      return "Open Axo Pass to review."
    }
  }

  /// Open the main window on the Today page.
  private func showToday() {
    vaults.selectSidebarDestination(.today)
    windows.requestMain()
  }
}

extension IssueNotifier: UNUserNotificationCenterDelegate {
  /// Show issue notifications while the app is active. Other notifications
  /// are not shown while the app is active.
  nonisolated func userNotificationCenter(
    _ center: UNUserNotificationCenter, willPresent notification: UNNotification
  ) async -> UNNotificationPresentationOptions {
    notification.request.content.categoryIdentifier == Self.category ? [.banner, .list] : []
  }

  /// Open Today for a clicked issue notification.
  nonisolated func userNotificationCenter(
    _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse
  ) async {
    guard response.notification.request.content.categoryIdentifier == Self.category else {
      return
    }
    await showToday()
  }
}
