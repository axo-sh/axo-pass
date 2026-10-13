import AxoPassFFI
import CryptoKit
import SwiftUI

/// Credential shown by `PreviousValuesSheet`. The title is captured when the
/// sheet opens, so the sheet still has a title if the credential is removed.
struct PreviousValuesTarget: Identifiable {
  let key: String
  let title: String
  var id: String { key }
}

/// Previous values of one credential. A replaced value stays in the vault until
/// it is deleted permanently here.
struct PreviousValuesSheet: View {
  @Environment(VaultsModel.self) private var model
  @Environment(\.dismiss) private var dismiss

  let vaultKey: String
  let itemKey: String
  let credKey: String
  let title: String
  /// Called after a previous value becomes the current value.
  let onValueChanged: () -> Void

  @State private var entries: [HistoryEntryInfo]? = nil
  @State private var revealed: [String: SymmetricKey] = [:]
  @State private var errorMessage: String? = nil
  @State private var copiedId: String? = nil
  @State private var confirmingPurge: HistoryEntryInfo? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Previous Values of \(title)").font(.headline)

      Group {
        if let entries {
          if entries.isEmpty {
            Text("No previous values")
              .foregroundStyle(.secondary)
              .frame(maxWidth: .infinity, maxHeight: .infinity)
          } else {
            List(entries, id: \.id) { entry in
              row(entry)
            }
          }
        } else {
          ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        }
      }
      .frame(height: 280)

      Text(
        "Replaced values stay in the vault until you delete them permanently."
      )
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
    .frame(width: 480)
    .task { await load() }
    .onChange(of: model.isAppUnlocked) { _, unlocked in
      if !unlocked { dismiss() }
    }
    .confirmationDialog(
      "Delete this previous value permanently?",
      isPresented: Binding(
        get: { confirmingPurge != nil }, set: { if !$0 { confirmingPurge = nil } }),
      presenting: confirmingPurge
    ) { entry in
      Button("Delete Permanently", role: .destructive) { purge(entry) }
    } message: { _ in
      Text("The value is erased from the vault. This cannot be undone.")
    }
  }

  private func row(_ entry: HistoryEntryInfo) -> some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack {
        Text(
          "Replaced "
            + Date(timeIntervalSince1970: TimeInterval(entry.replacedAt)).formatted()
        )
        .font(.callout)
        .foregroundStyle(.secondary)
        Spacer(minLength: 0)
        Button(copiedId == entry.id ? "Copied" : "Copy") { Task { await copy(entry) } }
        Button("Restore as Current") { restore(entry) }
        Button("Delete…") { confirmingPurge = entry }
      }
      .controlSize(.small)
      SecretBox(
        revealed: revealedText(entry),
        lineLimit: 1,
        onToggle: { revealed[entry.id] == nil ? reveal(entry) : hide(entry) }
      )
    }
    .padding(.vertical, 4)
  }

  private func revealedText(_ entry: HistoryEntryInfo) -> String? {
    guard let secret = revealed[entry.id] else { return nil }
    return secret.withUnsafeBytes { String(bytes: $0, encoding: .utf8) ?? "(binary data)" }
  }

  private func load() async {
    do {
      entries = try await model.credentialHistory(
        vaultKey: vaultKey, itemKey: itemKey, credKey: credKey)
    } catch {
      entries = []
      errorMessage = String(describing: error)
    }
  }

  private func fetch(_ entry: HistoryEntryInfo) async throws -> SymmetricKey {
    try await model.historyValue(
      vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, historyId: entry.id)
  }

  private func reveal(_ entry: HistoryEntryInfo) {
    errorMessage = nil
    Task {
      do {
        revealed[entry.id] = try await fetch(entry)
      } catch {
        errorMessage = String(describing: error)
      }
    }
  }

  private func hide(_ entry: HistoryEntryInfo) {
    revealed.removeValue(forKey: entry.id)
  }

  /// Copy without revealing the value on screen.
  private func copy(_ entry: HistoryEntryInfo) async {
    errorMessage = nil
    do {
      let value: SymmetricKey
      if let secret = revealed[entry.id] {
        value = secret
      } else {
        value = try await fetch(entry)
      }
      if secureCopy(value) {
        copiedId = entry.id
        try? await Task.sleep(for: .seconds(1.2))
        // Another row may have been copied since.
        if copiedId == entry.id { copiedId = nil }
      } else {
        errorMessage = "The value is not text."
      }
    } catch {
      errorMessage = String(describing: error)
    }
  }

  private func restore(_ entry: HistoryEntryInfo) {
    errorMessage = nil
    Task {
      errorMessage = await failureMessage {
        try await model.restoreHistoryValue(
          vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, historyId: entry.id)
      }
      revealed = [:]
      if errorMessage == nil { onValueChanged() }
      await load()
    }
  }

  private func purge(_ entry: HistoryEntryInfo) {
    errorMessage = nil
    Task {
      errorMessage = await failureMessage {
        try await model.purgeHistoryValue(
          vaultKey: vaultKey, itemKey: itemKey, credKey: credKey, historyId: entry.id)
      }
      revealed.removeValue(forKey: entry.id)
      await load()
    }
  }
}
