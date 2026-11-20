import AxoPassFFI
import SwiftUI

/// Item shown by `ItemHistorySheet`. The title is captured when the sheet
/// opens, so the sheet still has a title if the item is removed.
struct ItemHistoryTarget: Identifiable {
  let vaultKey: String
  let itemKey: String
  let title: String
  var id: String { "\(vaultKey)/\(itemKey)" }

  init(_ item: ItemInfo, vaultKey: String) {
    self.vaultKey = vaultKey
    itemKey = item.key
    title = item.title
  }
}

/// History of one item, newest first, as stored in the vault. Covers the item
/// creation, value changes of its credentials, and credential deletions.
struct ItemHistorySheet: View {
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let target: ItemHistoryTarget

  @State private var events: [ItemHistoryEventInfo]? = nil
  @State private var errorMessage: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("History of \(target.title)").font(.headline)

      if let events {
        if events.isEmpty {
          Text("No changes").foregroundStyle(.secondary)
        } else {
          // The list is as tall as its rows, and scrolls past the maximum height.
          ViewThatFits(in: .vertical) {
            eventList(events)
            ScrollView { eventList(events) }
          }
          .frame(maxHeight: 360)
        }
      } else {
        ProgressView().frame(maxWidth: .infinity, minHeight: 80)
      }

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
    .task { await load() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
  }

  private func eventList(_ events: [ItemHistoryEventInfo]) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      ForEach(Array(events.enumerated()), id: \.offset) { index, event in
        row(event)
        if index < events.count - 1 { Divider() }
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private func row(_ event: ItemHistoryEventInfo) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 10) {
      VStack(alignment: .leading, spacing: 2) {
        Text(Self.label(event.kind))
        if let subtitle = subtitle(event) {
          Text(subtitle)
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
        }
      }
      Spacer(minLength: 8)
      Text(
        Date(timeIntervalSince1970: TimeInterval(event.at))
          .formatted(date: .abbreviated, time: .shortened)
      )
      .font(.callout)
      .monospacedDigit()
      .foregroundStyle(.secondary)
    }
    .padding(.vertical, 6)
  }

  /// Credential title, and whether the credential is deleted. Nil for an
  /// event of the item.
  private func subtitle(_ event: ItemHistoryEventInfo) -> String? {
    guard let title = event.credentialTitle else { return nil }
    if event.credentialDeleted && event.kind != .credentialDeleted {
      return "\(title) · Deleted"
    }
    return title
  }

  private func load() async {
    do {
      events = try await model.itemHistory(vaultKey: target.vaultKey, itemKey: target.itemKey)
    } catch {
      events = []
      errorMessage = String(describing: error)
    }
  }

  /// Short description of an event kind, as shown in a history row.
  private static func label(_ kind: ItemHistoryKind) -> String {
    switch kind {
    case .itemCreated: return "Created item"
    case .valueCreated: return "Added credential"
    case .valueUpdated: return "Changed credential value"
    case .credentialDeleted: return "Deleted credential"
    case .other: return "Changed credential"
    }
  }
}
