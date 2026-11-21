import AxoPassFFI
import Foundation
import Observation

/// Uses of keys, credentials, and logins, newest first, read from the audit
/// log. Access events of every outcome are listed. Item listings and grant
/// events are left out, since they name no use of a secret.
@Observable
@MainActor
final class ActivityModel {
  /// Audit events read per page.
  private static let pageSize: UInt32 = 200

  private let core = AxoPass()

  private(set) var events: [ActivityEvent] = []
  private(set) var loadError: String? = nil
  private(set) var isLoading = false
  /// False once a page comes back short, meaning the log has no more rows.
  private(set) var hasMore = true

  var filter: ActivityFilter = .all {
    didSet { if oldValue != filter { Task { await reload() } } }
  }

  /// Audit rows read so far, including rows that are left out. Offset of the
  /// next page.
  private var offset: UInt32 = 0
  /// Incremented on each reload. A page read for an earlier generation is
  /// dropped.
  private var generation = 0

  /// Read the first page again. Listed events stay until the new page replaces
  /// them if `clearing` is false.
  func reload(clearing: Bool = true) async {
    generation += 1
    if clearing { events = [] }
    offset = 0
    hasMore = true
    isLoading = false
    await loadMore()
  }

  func loadMore() async {
    guard !isLoading, hasMore else { return }
    isLoading = true
    let current = generation
    let input = AuditFilterInput(
      sinceRfc3339: nil,
      untilRfc3339: nil,
      actions: [],
      categories: filter.categories,
      kind: .access,
      requesters: filter.requesters,
      outcomes: [],
      query: nil,
      detailId: nil,
      limit: Self.pageSize,
      offset: offset
    )
    do {
      let page = try await core.listAuditEvents(filter: input)
      guard current == generation else { return }
      offset += UInt32(page.count)
      hasMore = page.count == Int(Self.pageSize)
      let loaded = page.compactMap(ActivityEvent.init)
      if offset == UInt32(page.count) {
        events = loaded
      } else {
        events.append(contentsOf: loaded)
      }
      loadError = nil
    } catch {
      guard current == generation else { return }
      loadError = error.userMessage
    }
    isLoading = false
  }
}

/// Filter chip of the Activity page.
enum ActivityFilter: CaseIterable {
  case all
  case browser
  case cli
  case ssh
  case gpg

  var label: String {
    switch self {
    case .all: return "All"
    case .browser: return "Browser"
    case .cli: return "CLI"
    case .ssh: return "SSH"
    case .gpg: return "GPG"
    }
  }

  fileprivate var requesters: [AuditRequesterKind] {
    switch self {
    case .browser: return [.browser, .autofill]
    case .cli: return [.cli]
    default: return []
    }
  }

  fileprivate var categories: [AuditCategory] {
    switch self {
    case .ssh: return [.ssh]
    case .gpg: return [.gpg]
    default: return []
    }
  }
}

/// One use of a key, credential, or login.
struct ActivityEvent: Identifiable {
  let row: AuditLogRow
  let kind: UsedTodayKind
  let label: String
  /// Audit action. Login fills use `login.fill` and `login.totp`.
  let action: String
  let caller: String?
  let ref: AuditSubjectRef

  var id: String { row.id }
  var record: AuditEventRecord { row.record }
  var date: Date? { row.timestamp }

  /// Kind to show. A passkey sign-in shows as a passkey.
  var displayKind: UsedTodayKind {
    action == "passkey.asserted" ? .passkey : kind
  }

  /// Browser that asked for a login fill, if verified.
  var browser: String? {
    guard let name = record.detail["browser"], !name.isEmpty, name != "unverified" else {
      return nil
    }
    return name
  }

  /// SSH server host of a signature, if recorded.
  var host: String? {
    record.detail["host"].flatMap { $0.isEmpty ? nil : $0 }
  }

  /// Site a login request was made for, if recorded.
  var site: String? {
    record.detail["service_host"].flatMap { $0.isEmpty ? nil : $0 }
  }

  /// Nil for item listings, grant events, and events with no subject.
  init?(_ record: AuditEventRecord) {
    guard record.action != "item.listed", !record.action.hasPrefix("auth."),
      let subject = UsedTodayEntry.subject(of: record)
    else { return nil }
    row = AuditLogRow(record)
    kind = subject.kind
    label = subject.label
    action = subject.action
    caller = UsedTodayEntry.callerName(record)
    ref = AuditSubjectRef(
      kind: subject.kind, subjectId: subject.id, vaultId: record.detail["vault_id"],
      vaultKey: record.detail["vault"], itemId: UsedTodayEntry.itemId(of: record),
      hasName: subject.hasName)
  }
}
