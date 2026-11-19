import Foundation
import UserNotifications

/// A kind of notification that reports use of a key or login. Each kind has its
/// own switch in Settings.
///
/// A request that the user answers on a prompt never notifies as a cancellation,
/// since the user already knows about it.
enum ActivityNotification: String, CaseIterable, Identifiable {
  /// A key signed for SSH.
  case signatures
  /// A GPG, SSH passphrase, or age request answered from an earlier approval.
  case reusedApprovals
  /// A login filled for a browser without a prompt.
  case loginFills
  /// A request that failed.
  case failures

  var id: String { rawValue }

  /// `UserDefaults` key of the switch.
  var key: String { "notifications.\(rawValue)" }

  var label: String {
    switch self {
    case .signatures: return "SSH signatures"
    case .reusedApprovals: return "Reused approvals"
    case .loginFills: return "Logins filled without a prompt"
    case .failures: return "Failed requests"
    }
  }

  var caption: String {
    switch self {
    case .signatures: return "A key signed for ssh."
    case .reusedApprovals: return "A GPG or `ap` request used an earlier approval."
    case .loginFills: return "A browser filled a login from an earlier approval."
    case .failures: return "A request to use a key or login failed."
    }
  }

  var isEnabled: Bool {
    UserDefaults.standard.bool(forKey: key)
  }

  /// Every kind is on until the user turns it off.
  static var defaults: [String: Any] {
    Dictionary(uniqueKeysWithValues: allCases.map { ($0.key, true) })
  }

  /// Post a notification if this kind is on. A notification with the same
  /// `identifier` replaces an earlier one, so repeated use of one key does not
  /// stack.
  func post(title: String, body: String, identifier: String = UUID().uuidString) {
    guard isEnabled else { return }
    let content = UNMutableNotificationContent()
    content.title = title
    content.body = body
    let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
    UNUserNotificationCenter.current().add(request) { error in
      if let error {
        NSLog("ActivityNotification: could not post notification: %@", String(describing: error))
      }
    }
  }
}
