import AxoPassFFI
import SwiftUI

/// Item shown by `ItemHistorySheet`. The title and credential titles are
/// captured when the sheet opens, so the sheet still has them if the item is
/// removed.
struct ItemHistoryTarget: Identifiable {
  let itemId: String
  let title: String
  /// Credential titles by credential id.
  let credentialTitles: [String: String]
  /// Credentials with their creation time, as stored in the vault.
  let creations: [CredentialCreation]
  var id: String { itemId }

  init(_ item: ItemInfo) {
    itemId = item.id
    title = item.title
    credentialTitles = Dictionary(
      item.credentials.map { ($0.id, $0.title) }, uniquingKeysWith: { first, _ in first })
    creations = item.credentials.map {
      CredentialCreation(
        id: $0.id, title: $0.title, date: Date(timeIntervalSince1970: TimeInterval($0.createdAt)))
    }
  }
}

/// Creation of one credential, from its stored creation time.
struct CredentialCreation: Identifiable {
  let id: String
  let title: String
  let date: Date
}

/// Row of the history list. Either an audit event or the stored creation of a
/// credential.
private enum HistoryEntry: Identifiable {
  case event(AuditLogRow)
  case created(CredentialCreation)

  var id: String {
    switch self {
    case .event(let row): return row.id
    case .created(let creation): return "created-\(creation.id)"
    }
  }

  var date: Date {
    switch self {
    case .event(let row): return row.timestamp ?? .distantPast
    case .created(let creation): return creation.date
    }
  }
}

/// Changes to one item and its credentials, newest first, read from the audit
/// log. Reads of values are left out.
struct ItemHistorySheet: View {
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let target: ItemHistoryTarget

  /// Audit events read per page.
  private static let pageSize: UInt32 = 100

  /// Audit actions that record the creation of a credential.
  private static let creationActions: Set<String> = ["credential.created", "passkey.registered"]

  @State private var events: [AuditLogRow]? = nil
  @State private var hasMore = true
  @State private var isLoading = false
  @State private var errorMessage: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("History of \(target.title)").font(.headline)

      if let events {
        let listed = entries(for: events)
        if listed.isEmpty && !hasMore {
          Text("No changes").foregroundStyle(.secondary)
        } else {
          // The list is as tall as its rows, and scrolls past the maximum height.
          ViewThatFits(in: .vertical) {
            entryList(listed)
            ScrollView { entryList(listed) }
          }
          .frame(maxHeight: 360)
        }
      } else {
        ProgressView().frame(maxWidth: .infinity, minHeight: 80)
      }

      Text("Changes are read from the audit log on this Mac.")
        .font(.caption)
        .foregroundStyle(.secondary)

      if let errorMessage {
        Text(errorMessage)
          .font(.caption)
          .foregroundStyle(.red)
          .textSelection(.enabled)
      }

      HStack {
        Spacer()
        Button("Done") { dismiss() }
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(20)
    .frame(width: 520)
    // Every page is read, since the list is not lazy and the credential
    // creation entries need all events.
    .task(id: events?.count) { await loadMore() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
  }

  /// Audit events, with a creation entry for each credential that has no
  /// creation event. The creation entries are added once every event is
  /// loaded, so a creation event is never missed. Newest first.
  private func entries(for events: [AuditLogRow]) -> [HistoryEntry] {
    var entries = events.map(HistoryEntry.event)
    guard !hasMore else { return entries }
    let recorded = Set(
      events.filter { Self.creationActions.contains($0.action) }
        .compactMap { $0.record.detail["credential_id"] })
    entries += target.creations.filter { !recorded.contains($0.id) }.map(HistoryEntry.created)
    return entries.enumerated()
      .sorted { ($0.element.date, $1.offset) > ($1.element.date, $0.offset) }
      .map(\.element)
  }

  private func entryList(_ listed: [HistoryEntry]) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      ForEach(listed) { entry in
        switch entry {
        case .event(let event): row(event)
        case .created(let creation): creationRow(creation)
        }
        if entry.id != listed.last?.id || hasMore { Divider() }
      }
      if hasMore {
        ProgressView()
          .controlSize(.small)
          .frame(maxWidth: .infinity)
          .padding(.vertical, 8)
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private func creationRow(_ creation: CredentialCreation) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 10) {
      VStack(alignment: .leading, spacing: 2) {
        Text(Self.label("credential.created"))
        Text(creation.title)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
      }
      Spacer(minLength: 8)
      Text(creation.date.formatted(date: .abbreviated, time: .shortened))
        .font(.callout)
        .monospacedDigit()
        .foregroundStyle(.secondary)
    }
    .padding(.vertical, 6)
  }

  private func row(_ event: AuditLogRow) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 10) {
      VStack(alignment: .leading, spacing: 2) {
        Text(Self.label(event.action))
        Text(subtitle(event))
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
      }
      Spacer(minLength: 8)
      VStack(alignment: .trailing, spacing: 2) {
        Text(event.timestamp?.formatted(date: .abbreviated, time: .shortened) ?? event.record.at)
          .font(.callout)
          .monospacedDigit()
          .foregroundStyle(.secondary)
        if event.record.outcome != .succeeded {
          Text(event.outcomeText)
            .font(.caption)
            .foregroundStyle(event.record.outcome == .failed ? .red : .orange)
        }
      }
    }
    .padding(.vertical, 6)
    .help(event.action)
  }

  /// Credential title, then who made the change.
  private func subtitle(_ event: AuditLogRow) -> String {
    var parts: [String] = []
    if let credId = event.record.detail["credential_id"] {
      parts.append(target.credentialTitles[credId] ?? "Removed credential")
    }
    parts.append(event.requesterText)
    if event.record.requester != .app, let caller = event.record.caller, !caller.isEmpty {
      parts.append(caller)
    }
    return parts.joined(separator: " · ")
  }

  private func loadMore() async {
    guard !isLoading, hasMore else { return }
    isLoading = true
    defer { isLoading = false }
    do {
      let page = try await model.itemHistory(
        itemId: target.itemId, limit: Self.pageSize, offset: UInt32(events?.count ?? 0))
      hasMore = page.count == Int(Self.pageSize)
      events = (events ?? []) + page
    } catch {
      hasMore = false
      if events == nil { events = [] }
      errorMessage = String(describing: error)
    }
  }

  /// Short description of an audit action, as shown in a history row.
  private static func label(_ action: String) -> String {
    switch action {
    case "item.created": return "Created item"
    case "item.updated": return "Changed item"
    case "item.deleted": return "Moved item to Recently Deleted"
    case "item.restored": return "Restored item"
    case "item.purged": return "Deleted item permanently"
    case "item.merged": return "Merged items"
    case "item.moved": return "Moved item to another vault"
    case "item.websites_changed": return "Changed websites"
    case "item.converted": return "Converted to a login"
    case "credential.created": return "Added credential"
    case "credential.updated": return "Changed credential"
    case "credential.deleted": return "Deleted credential"
    case "credential.restored": return "Restored credential"
    case "credential.purged": return "Deleted credential permanently"
    case "credential.history_restored": return "Restored previous value"
    case "credential.history_purged": return "Deleted previous value"
    case "credential.role_changed": return "Changed credential role"
    case "passkey.registered": return "Created passkey"
    case "passkey.moved": return "Moved passkey"
    case "passkey.reported": return "Website reported passkey"
    case "passkey.renamed": return "Renamed passkey"
    default: return action
    }
  }
}
