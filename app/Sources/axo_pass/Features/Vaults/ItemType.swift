import AxoPassFFI

/// Item groups in the Types view of the sidebar. Derived from item credentials,
/// so one item can be in more than one group.
enum ItemType: String, CaseIterable, Hashable {
  case logins
  case passkeys
  case oneTimeCodes
  case other

  var title: String {
    switch self {
    case .logins: return "Logins"
    case .passkeys: return "Passkeys"
    case .oneTimeCodes: return "One-Time Codes"
    case .other: return "Other Items"
    }
  }

  var systemImage: String {
    switch self {
    case .logins: return "key"
    case .passkeys: return "person.badge.key"
    case .oneTimeCodes: return "clock.badge.checkmark"
    case .other: return "doc.text"
    }
  }

  func contains(_ item: ItemInfo) -> Bool {
    switch self {
    case .logins: return item.isLogin
    case .passkeys: return !item.passkeyCredentials.isEmpty
    case .oneTimeCodes: return item.totpCredential != nil
    case .other: return !item.isLogin && item.totpCredential == nil
    }
  }
}
