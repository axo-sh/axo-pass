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
  var source: AuditSourceKind? = nil {
    didSet { if oldValue != source { Task { await reload() } } }
  }
  var actionGroup: AuditActionGroup = .all {
    didSet { if oldValue != actionGroup { Task { await reload() } } }
  }

  private var reloadTask: Task<Void, Never>? = nil

  private var filter: AuditFilterInput {
    AuditFilterInput(
      sinceRfc3339: nil,
      untilRfc3339: nil,
      actions: actionGroup.actions,
      sources: source.map { [$0] } ?? [],
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

  func revealInFinder() {
    let path = core.auditLogPath()
    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
  }
}

/// The coarse action filter offered in the toolbar.
enum AuditActionGroup: String, CaseIterable, Identifiable {
  case all
  case ssh
  case gpg
  case secrets
  case vault
  case auth

  var id: String { rawValue }

  var label: String {
    switch self {
    case .all: return "All events"
    case .ssh: return "SSH"
    case .gpg: return "GPG"
    case .secrets: return "Secrets"
    case .vault: return "Vault"
    case .auth: return "Grants"
    }
  }

  /// The dotted action strings this group selects. Empty means no constraint.
  var actions: [String] {
    switch self {
    case .all:
      return []
    case .ssh:
      return [
        "ssh.sign", "ssh.passphrase", "ssh.key_add", "ssh.key_remove",
        "ssh.session_bind", "ssh.agent_start", "ssh.agent_stop",
      ]
    case .gpg:
      return [
        "gpg.passphrase", "gpg.confirm", "gpg.message", "gpg.passphrase_saved",
        "gpg.agent_conf_changed",
      ]
    case .secrets:
      return ["secret.read", "secret.inject", "secret.exec", "age.decrypt", "age.encrypt"]
    case .vault:
      return [
        "vault.unlock", "vault.lock", "vault.autolock", "vault.item_created",
        "vault.item_updated", "vault.item_deleted", "vault.created", "vault.exported",
        "vault.imported",
      ]
    case .auth:
      return ["auth.grant_created", "auth.grant_reused", "auth.grant_expired"]
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
