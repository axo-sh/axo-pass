import AxoPassFFI
import Foundation
import Observation

/// Keys, credentials, and items used since the start of today, read from the
/// audit log. Successful access events only. Item listings are left out, since
/// they name no secret.
@Observable
@MainActor
final class UsedTodayModel {
  /// Most events read for one day.
  private static let limit: UInt32 = 5000

  private let core = AxoPass()

  private(set) var entries: [UsedTodayEntry] = []
  private(set) var loadError: String? = nil

  func reload() async {
    let start = Calendar.current.startOfDay(for: Date())
    let filter = AuditFilterInput(
      sinceRfc3339: ISO8601DateFormatter.auditPlain.string(from: start),
      untilRfc3339: nil,
      actions: [],
      categories: [],
      kind: .access,
      requesters: [],
      outcomes: [.succeeded],
      query: nil,
      detailId: nil,
      limit: Self.limit,
      offset: 0
    )
    do {
      let events = try await core.listAuditEvents(filter: filter)
      entries = UsedTodayEntry.group(events)
      loadError = nil
    } catch {
      loadError = String(describing: error)
    }
  }
}

extension AuditEventRecord {
  /// Whether the subject id is a name or path the user chose. False for SSH
  /// fingerprints and GPG keygrips. False for an event recorded without
  /// account details, whose id is a short id of the vault, item, or credential
  /// or is missing.
  var subjectNamesAccount: Bool {
    guard let id = subjectId, !id.isEmpty else { return false }
    switch subjectKind {
    case .sshKey: return !id.hasPrefix("SHA256:")
    case .gpgKey, nil: return false
    case .vault, .item, .credential, .ageIdentity:
      let shortIds = [detail["vault_id"], detail["item_id"], detail["credential_id"]]
      return !shortIds.contains(id)
    }
  }
}

/// What a used-today entry is.
enum UsedTodayKind {
  case sshKey
  case gpgKey
  /// Browser login fill, one-time code, or passkey sign-in, grouped by site.
  case login
  /// Site used only through passkey sign-ins. Display only.
  case passkey
  case credential
  case item
  case vault
  case ageIdentity

  init(_ kind: AuditSubjectKind) {
    switch kind {
    case .sshKey: self = .sshKey
    case .gpgKey: self = .gpgKey
    case .credential: self = .credential
    case .item: self = .item
    case .vault: self = .vault
    case .ageIdentity: self = .ageIdentity
    }
  }

  /// Title of a subject whose name was not recorded and cannot be looked up.
  var genericLabel: String {
    switch self {
    case .sshKey: return "SSH key"
    case .gpgKey: return "GPG key"
    case .login: return "Login"
    case .passkey: return "Passkey"
    case .credential: return "Credential"
    case .item: return "Item"
    case .vault: return "Vault"
    case .ageIdentity: return "Age key"
    }
  }
}

/// Key or item named by an audit event. Rows open the subject from it.
struct AuditSubjectRef {
  let kind: UsedTodayKind
  /// Audit subject id. The site for logins and passkeys. A short id or
  /// fingerprint if the event was recorded without account details.
  let subjectId: String
  /// Short vault id and vault key, if recorded.
  let vaultId: String?
  let vaultKey: String?
  /// Short item id, if recorded.
  let itemId: String?
  /// False if the event was recorded without account details, so the title
  /// has to be looked up.
  let hasName: Bool
}

/// Uses of one subject today.
struct UsedTodayEntry: Identifiable {
  let kind: UsedTodayKind
  /// Audit subject id. The site for logins and passkeys.
  let subjectId: String
  let label: String
  /// Number of successful uses today.
  var count: Int
  /// Programs that used the subject, most recent first.
  var callers: [String]
  /// Actions on the subject, most recent first. Login fills use `login.fill`
  /// and `login.totp`.
  var actions: [String]
  let lastUsed: Date?
  /// Short vault id and vault key of the last use, if recorded.
  let vaultId: String?
  let vaultKey: String?
  /// Short item id of the last use, if recorded.
  let itemId: String?
  /// False if the last use was recorded without account details.
  let hasName: Bool

  var id: String { "\(kind)-\(subjectId)" }

  /// Key or item of the last use.
  var ref: AuditSubjectRef {
    AuditSubjectRef(
      kind: kind, subjectId: subjectId, vaultId: vaultId, vaultKey: vaultKey, itemId: itemId,
      hasName: hasName)
  }

  /// Kind to show. A site used only through passkey sign-ins shows as a
  /// passkey.
  var displayKind: UsedTodayKind {
    kind == .login && actions == ["passkey.asserted"] ? .passkey : kind
  }

  /// Group events by subject. Events come newest first. Entries are ordered
  /// by count, then by last use.
  static func group(_ events: [AuditEventRecord]) -> [UsedTodayEntry] {
    var byId: [String: UsedTodayEntry] = [:]
    var order: [String] = []
    for event in events where event.action != "item.listed" {
      guard let subject = subject(of: event) else { continue }
      let row = AuditLogRow(event)
      let id = "\(subject.kind)-\(subject.id)"
      let caller = callerName(event)
      if var entry = byId[id] {
        entry.count += 1
        if let caller, !entry.callers.contains(caller) { entry.callers.append(caller) }
        if !entry.actions.contains(subject.action) { entry.actions.append(subject.action) }
        byId[id] = entry
      } else {
        byId[id] = UsedTodayEntry(
          kind: subject.kind, subjectId: subject.id, label: subject.label, count: 1,
          callers: caller.map { [$0] } ?? [], actions: [subject.action],
          lastUsed: row.timestamp, vaultId: event.detail["vault_id"],
          vaultKey: event.detail["vault"], itemId: itemId(of: event), hasName: subject.hasName)
        order.append(id)
      }
    }
    return order.compactMap { byId[$0] }.sorted {
      if $0.count != $1.count { return $0.count > $1.count }
      return ($0.lastUsed ?? .distantPast) > ($1.lastUsed ?? .distantPast)
    }
  }

  /// Kind, grouping id, label, and action of an event. Browser login requests
  /// name a login record with no label, so they are grouped by site instead.
  /// `hasName` is false if the event was recorded without account details. The
  /// label is then generic and the id is a short id or fingerprint. Nil if the
  /// event has no subject.
  static func subject(
    of event: AuditEventRecord
  ) -> (kind: UsedTodayKind, id: String, label: String, action: String, hasName: Bool)? {
    let request = event.detail["login_request"]
    let loginAction = request == "totp" ? "login.totp" : "login.fill"
    if request != nil, let host = event.detail["service_host"] {
      return (.login, host, host, loginAction, true)
    }
    if request == "fill" || request == "totp" {
      return (.login, groupingId(of: event), UsedTodayKind.login.genericLabel, loginAction, false)
    }
    guard let kind = event.subjectKind else { return nil }
    let namedId = event.subjectNamesAccount ? event.subjectId : nil
    // A passkey sign-in names the site, so it joins the login row of that
    // site.
    if event.action == "passkey.asserted" {
      if let namedId { return (.login, namedId, namedId, event.action, true) }
      return (
        .login, groupingId(of: event), UsedTodayKind.passkey.genericLabel, event.action, false
      )
    }
    let label = event.subjectLabel.flatMap { $0.isEmpty ? nil : $0 }
    let title = label ?? namedId ?? UsedTodayKind(kind).genericLabel
    return (
      UsedTodayKind(kind), groupingId(of: event), title, event.action,
      label != nil || namedId != nil
    )
  }

  /// Subject id of the event, or the first id the event records if the subject
  /// has none. The event id if it records no id.
  private static func groupingId(of event: AuditEventRecord) -> String {
    if let id = event.subjectId, !id.isEmpty { return id }
    let keys = ["credential_id", "item_id", "vault_id", "passkey_credential_id"]
    return keys.lazy.compactMap { event.detail[$0] }.first { !$0.isEmpty } ?? event.id
  }

  /// Short item id of the event. The first id if the event names several.
  static func itemId(of event: AuditEventRecord) -> String? {
    if let id = event.detail["item_id"], !id.isEmpty { return id }
    return event.detail["item_ids"]?.split(separator: ",").first.map(String.init)
  }

  /// Program name of the event: the caller, or the file name of the
  /// executable. The executable is omitted if the event was recorded without
  /// account details.
  static func callerName(_ event: AuditEventRecord) -> String? {
    if let caller = event.caller, !caller.isEmpty { return caller }
    guard let path = event.actorExecutable, !path.isEmpty else { return nil }
    return URL(fileURLWithPath: path).lastPathComponent
  }
}
