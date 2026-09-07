import Foundation

/// The values the user sets in the Settings window.
///
/// Views bind to these keys with `@AppStorage`; code outside a view reads them
/// through the static properties here. Both go through the same `UserDefaults`,
/// so a change made in the window is visible to the rest of the app without
/// further plumbing.
enum Preferences {
  enum Key {
    /// Idle minutes before the app locks. 0 means never.
    static let autoLockMinutes = "general.autoLockMinutes"
    /// Whether an approval may be reused inside its window, or every request
    /// prompts.
    static let reuseApprovals = "security.reuseApprovals"
  }

  static let defaultAutoLockMinutes = 5
  static let defaultReuseApprovals = true

  /// The values offered in Settings, in minutes. 0 is "Never".
  static let autoLockChoices = [1, 5, 15, 30, 60, 0]

  /// Register defaults so a read before the user has ever opened Settings
  /// returns the same value the window shows.
  static func registerDefaults() {
    UserDefaults.standard.register(defaults: [
      Key.autoLockMinutes: defaultAutoLockMinutes,
      Key.reuseApprovals: defaultReuseApprovals,
    ])
  }

  /// Idle time before the app locks, or nil when the user has turned the idle
  /// lock off. Locking on sleep and on screen lock is not configurable.
  static var autoLockTimeout: TimeInterval? {
    let minutes = UserDefaults.standard.integer(forKey: Key.autoLockMinutes)
    guard minutes > 0 else { return nil }
    return TimeInterval(minutes) * 60
  }

  static var reuseApprovals: Bool {
    UserDefaults.standard.bool(forKey: Key.reuseApprovals)
  }

  static func label(forAutoLockMinutes minutes: Int) -> String {
    switch minutes {
    case 0: return "Never"
    case 1: return "1 minute"
    case 60: return "1 hour"
    default: return "\(minutes) minutes"
    }
  }
}
