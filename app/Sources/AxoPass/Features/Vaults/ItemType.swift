import AxoPassFFI

/// Item groups in the Types view of the sidebar. Derived from item credentials,
/// so one item can be in more than one group.
enum ItemType: String, CaseIterable, Hashable {
  case logins
  case passkeys
  case sshKeys
  case oneTimeCodes
  case files
  case other

  var title: String {
    switch self {
    case .logins: return "Logins"
    case .passkeys: return "Passkeys"
    case .sshKeys: return "SSH Keys"
    case .oneTimeCodes: return "One-Time Codes"
    case .files: return "Files"
    case .other: return "Other Items"
    }
  }

  var systemImage: String {
    switch self {
    case .logins: return "key"
    case .passkeys: return "person.badge.key"
    case .sshKeys: return KeyIcon.ssh.symbol
    case .oneTimeCodes: return "clock.badge.checkmark"
    case .files: return "doc"
    case .other: return "doc.text"
    }
  }

  func contains(_ item: ItemInfo) -> Bool {
    switch self {
    case .logins: return item.isLogin
    case .passkeys: return !item.passkeyCredentials.isEmpty
    case .sshKeys: return item.isSshKey
    case .oneTimeCodes: return item.totpCredential != nil
    case .files: return !item.fileCredentials.isEmpty
    case .other:
      return !item.isLogin && !item.isSshKey && item.totpCredential == nil
        && item.fileCredentials.isEmpty
    }
  }
}
