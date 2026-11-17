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
    /// Whether the SSH agent starts at login, as a launchd service.
    static let sshStartOnLogin = "ssh.startOnLogin"
    /// The system-wide shortcut that shows the palette, as a `HotKey` raw
    /// value. Absent when none is set.
    static let paletteHotKey = "general.paletteHotKey"
    /// Item ids whose "Use this item for AutoFill?" banner the user
    /// dismissed.
    static let dismissedConversions = "autofill.dismissedConversions"
    /// Item id pairs (`<id>|<id>`, sorted) whose "Merge logins?" banner the
    /// user dismissed.
    static let dismissedMerges = "autofill.dismissedMerges"
    /// Whether the banner about turning on the AutoFill provider has been
    /// shown or dismissed.
    static let autofillSetupBannerSeen = "autofill.setupBannerSeen"
    /// Path of the synced folder of the app. Vaults turned on later sync with
    /// it. Unset until the user chooses one.
    static let syncFolder = "sync.folder"
    /// Dismissed advice issues, as `Issue.id` to the end of the snooze in
    /// seconds since 1970. A dismissal without an end is stored as 0.
    static let dismissedIssues = "issues.dismissed"
    /// Whether a choice in the welcome window finished, or a vault existed at
    /// launch. Unset on a new Mac.
    static let hasCompletedFirstRun = "firstRun.completed"
  }

  static let defaultAutoLockMinutes = 5
  static let defaultReuseApprovals = true
  static let defaultSshStartOnLogin = true

  /// The values offered in Settings, in minutes. 0 is "Never".
  static let autoLockChoices = [1, 5, 15, 30, 60, 0]

  /// Register defaults so a read before the user has ever opened Settings
  /// returns the same value the window shows.
  static func registerDefaults() {
    UserDefaults.standard.register(defaults: [
      Key.autoLockMinutes: defaultAutoLockMinutes,
      Key.reuseApprovals: defaultReuseApprovals,
      Key.sshStartOnLogin: defaultSshStartOnLogin,
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

  static var hasCompletedFirstRun: Bool {
    get { UserDefaults.standard.bool(forKey: Key.hasCompletedFirstRun) }
    set { UserDefaults.standard.set(newValue, forKey: Key.hasCompletedFirstRun) }
  }

  static var paletteHotKey: HotKey? {
    UserDefaults.standard.string(forKey: Key.paletteHotKey).flatMap(HotKey.init(rawValue:))
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
