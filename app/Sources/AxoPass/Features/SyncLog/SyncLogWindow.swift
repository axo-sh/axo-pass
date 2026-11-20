import AxoPassFFI
import Observation
import SwiftUI

/// Rows of the in-memory sync log. The log has no change callback, so the
/// window polls it while it is open.
@Observable
@MainActor
final class SyncLogModel {
  private(set) var rows: [SyncLogRow] = []

  func reload() {
    rows = syncLogEntries().enumerated().map { SyncLogRow(index: $0.offset, entry: $0.element) }
      .sorted { $0.last > $1.last }
  }

  func clear() {
    clearSyncLog()
    rows = []
  }
}

struct SyncLogRow: Identifiable {
  let index: Int
  let level: SyncLogLevelInfo
  let vaultId: String?
  let message: String
  let detail: String?
  let count: UInt32
  let first: Date
  let last: Date

  var id: Int { index }

  init(index: Int, entry: SyncLogEntryInfo) {
    self.index = index
    level = entry.level
    vaultId = entry.vaultId
    message = entry.message
    detail = entry.detail
    count = entry.count
    first = Self.parse(entry.first)
    last = Self.parse(entry.last)
  }

  var levelText: String {
    switch level {
    case .info: return "Info"
    case .warn: return "Warning"
    case .error: return "Error"
    }
  }

  private static func parse(_ text: String) -> Date {
    ISO8601DateFormatter.auditFractional.date(from: text)
      ?? ISO8601DateFormatter.auditPlain.date(from: text) ?? .distantPast
  }
}

/// The Sync Log window: recent sync events of this session, opened from
/// Help ▸ Sync Log. The log is in memory, holds a bounded number of rows, and
/// merges repeats of an event into one row.
struct SyncLogWindow: View {
  @State private var model = SyncLogModel()
  @Environment(VaultsModel.self) private var vaults
  @Environment(\.dismiss) private var dismiss

  private static let refreshInterval: Duration = .seconds(2)

  var body: some View {
    NavigationStack {
      Table(model.rows) {
        TableColumn("Time") { row in
          Text(row.last, format: .dateTime.month().day().hour().minute().second())
        }
        .width(min: 120, ideal: 140)
        TableColumn("Level", value: \.levelText)
          .width(min: 60, ideal: 70)
        TableColumn("Vault") { row in
          Text(vaultText(row))
        }
        .width(min: 100, ideal: 140)
        TableColumn("Event") { row in
          Text(eventText(row))
        }
        TableColumn("Detail") { row in
          Text(row.detail ?? "")
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
        }
      }
      .overlay {
        if model.rows.isEmpty {
          ContentUnavailableView(
            "No sync events",
            systemImage: "arrow.triangle.2.circlepath",
            description: Text("Events are kept in memory until Axo Pass quits."))
        }
      }
      .navigationTitle("Sync Log")
      .toolbar {
        ToolbarItemGroup(placement: .primaryAction) {
          Button {
            model.reload()
          } label: {
            Label("Refresh", systemImage: "arrow.clockwise")
          }

          Button(role: .destructive) {
            model.clear()
          } label: {
            Label("Clear", systemImage: "trash")
          }
          .disabled(model.rows.isEmpty)
        }
      }
    }
    .task {
      while !Task.isCancelled {
        model.reload()
        try? await Task.sleep(for: Self.refreshInterval)
      }
    }
    // Details can name buckets and files, so locking takes the window down.
    .onChange(of: vaults.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
  }

  private func vaultText(_ row: SyncLogRow) -> String {
    guard let id = row.vaultId else { return "" }
    return vaults.vaultName(id: id) ?? id
  }

  private func eventText(_ row: SyncLogRow) -> String {
    row.count > 1 ? "\(row.message) (\(row.count) times)" : row.message
  }
}
