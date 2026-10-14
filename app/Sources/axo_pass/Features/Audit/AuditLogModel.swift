import AppKit
import AxoPassFFI
import Foundation
import Observation

/// Backs the Audit Log window. The window is only opened while the app is
/// unlocked, but the core does not gate log reads on vault state, so this owns
/// its own `AxoPass` handle like `SshModel` does.
@Observable
@MainActor
final class AuditLogModel {
  private let core = AxoPass()

  /// One page of results, newest first.
  private static let pageSize: UInt32 = 200

  var events: [AuditLogRow] = []
  var loadError: String? = nil
  var isLoading = false
  /// False once a page comes back short, meaning the log has no more rows.
  private(set) var hasMore = true

  // Filter state, bound to the window's controls.
  var query: String = "" {
    didSet { if oldValue != query { scheduleReload() } }
  }
  var requester: AuditRequesterKind? = nil {
    didSet { if oldValue != requester { Task { await reload() } } }
  }
  var category: AuditCategory? = nil {
    didSet { if oldValue != category { Task { await reload() } } }
  }
  var kind: AuditActionKind? = nil {
    didSet { if oldValue != kind { Task { await reload() } } }
  }

  private var reloadTask: Task<Void, Never>? = nil

  private var filter: AuditFilterInput {
    AuditFilterInput(
      sinceRfc3339: nil,
      untilRfc3339: nil,
      actions: [],
      categories: category.map { [$0] } ?? [],
      kind: kind,
      requesters: requester.map { [$0] } ?? [],
      outcomes: [],
      query: query.isEmpty ? nil : query,
      limit: Self.pageSize,
      offset: UInt32(events.count)
    )
  }

  /// Debounce the search field: reload a short moment after typing stops.
  private func scheduleReload() {
    reloadTask?.cancel()
    reloadTask = Task {
      try? await Task.sleep(for: .milliseconds(200))
      guard !Task.isCancelled else { return }
      await reload()
    }
  }

  func reload() async {
    events = []
    hasMore = true
    await loadMore()
  }

  func loadMore() async {
    guard !isLoading, hasMore else { return }
    isLoading = true
    defer { isLoading = false }
    do {
      let page = try await core.listAuditEvents(filter: filter)
      hasMore = page.count == Int(Self.pageSize)
      events.append(contentsOf: page.map(AuditLogRow.init))
      loadError = nil
    } catch {
      loadError = String(describing: error)
    }
  }

  /// Every audit action with its description, for the help sheet.
  func actionCatalog() -> [AuditActionInfo] {
    core.auditActions()
  }

  func revealInFinder() {
    let path = core.auditLogPath()
    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
  }
}

extension AuditCategory: CaseIterable {
  /// Categories in toolbar order.
  public static var allCases: [AuditCategory] {
    [.ssh, .gpg, .age, .vault, .item, .credential, .passkey, .grant, .broker]
  }

  var label: String {
    switch self {
    case .ssh: return "SSH"
    case .gpg: return "GPG"
    case .age: return "Age"
    case .vault: return "Vaults"
    case .item: return "Items"
    case .credential: return "Credentials"
    case .passkey: return "Passkeys"
    case .grant: return "Grants"
    case .broker: return "Broker"
    }
  }
}

extension AuditRequesterKind: CaseIterable {
  /// Requesters in toolbar order.
  public static var allCases: [AuditRequesterKind] {
    [.app, .cli, .browser, .autofill, .sshClient, .gpgClient, .other]
  }

  var label: String {
    switch self {
    case .app: return "App"
    case .cli: return "CLI"
    case .browser: return "Browser"
    case .autofill: return "AutoFill"
    case .sshClient: return "SSH clients"
    case .gpgClient: return "GPG clients"
    case .other: return "Other"
    }
  }
}

/// A displayable audit event. Wraps the FFI record with formatted fields and a
/// stable identity for `Table`.
struct AuditLogRow: Identifiable, Hashable {
  let record: AuditEventRecord

  init(_ record: AuditEventRecord) { self.record = record }

  var id: String { record.id }

  var timestamp: Date? {
    ISO8601DateFormatter.auditFractional.date(from: record.at)
      ?? ISO8601DateFormatter.auditPlain.date(from: record.at)
  }

  var timeText: String {
    guard let date = timestamp else { return record.at }
    return AuditLogRow.displayFormatter.string(from: date)
  }

  var action: String { record.action }

  /// The stable identifier: a key fingerprint, keygrip, or vault path. The
  /// comment or title is shown only in the detail pane, never here, so a row
  /// names the same key the same way regardless of what it is labelled.
  var subjectText: String {
    if let sid = record.subjectId, !sid.isEmpty { return sid }
    if let label = record.subjectLabel, !label.isEmpty { return label }
    return "—"
  }

  /// What the subject is. An id alone does not say: a grant on vault `default`
  /// and a credential in it read the same way otherwise.
  var subjectKindText: String? {
    switch record.subjectKind {
    case .sshKey: return "SSH key"
    case .gpgKey: return "GPG key"
    case .credential: return "Credential"
    case .item: return "Item"
    case .vault: return "Vault"
    case .ageIdentity: return "age identity"
    case nil: return nil
    }
  }

  var callerText: String {
    record.caller ?? record.actorExecutable ?? "—"
  }

  var outcomeText: String {
    switch record.outcome {
    case .succeeded: return "Succeeded"
    case .cancelled: return "Cancelled"
    case .denied: return "Denied"
    case .failed: return "Failed"
    }
  }

  var requesterText: String { record.requester.label }

  var sourceText: String {
    switch record.source {
    case .agent: return "SSH agent"
    case .pinentry: return "pinentry"
    case .app: return "App"
    case .cli: return "CLI"
    case .askpass: return "askpass"
    }
  }

  /// Actor chain, innermost first, joined for display.
  var chainText: String {
    record.actorChain.isEmpty ? "—" : record.actorChain.joined(separator: " ← ")
  }

  var detailPairs: [(String, String)] {
    record.detail.sorted { $0.key < $1.key }.map { ($0.key, $0.value) }
  }

  private static let displayFormatter: DateFormatter = {
    let f = DateFormatter()
    f.dateStyle = .short
    f.timeStyle = .medium
    return f
  }()
}

extension ISO8601DateFormatter {
  nonisolated(unsafe) static let auditFractional: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
  }()

  nonisolated(unsafe) static let auditPlain = ISO8601DateFormatter()
}
