import AxoPassFFI
import CryptoKit
import SwiftUI

/// List of deleted items and credentials across all vaults.
struct RecentlyDeletedPane: View {
  @Environment(VaultsModel.self) private var vaults
  @Bindable var model: RecentlyDeletedModel

  var body: some View {
    VStack(spacing: 0) {
      messages
      if model.entries.isEmpty {
        if model.isLoading {
          DelayedProgressView()
        } else {
          ContentUnavailableView(
            "Nothing deleted", systemImage: "trash",
            description: Text("Deleted items appear here."))
        }
      } else {
        List(selection: $model.selection) {
          ForEach(model.entries) { entry in
            row(entry)
              .tag(entry.id)
              .padding(6)
          }
        }
      }
    }
    .paneBackground()
    .navigationSplitViewColumnWidth(min: 200, ideal: 240)
    .navigationTitle("Recently Deleted")
    .task { await model.reload(using: vaults) }
  }

  /// Restore notice and errors. Shown above the list and the empty state.
  @ViewBuilder
  private var messages: some View {
    if model.notice != nil || model.actionError != nil || model.loadError != nil {
      VStack(alignment: .leading, spacing: 4) {
        if let notice = model.notice {
          Text(notice).foregroundStyle(.secondary)
        }
        if let actionError = model.actionError {
          Text(actionError).foregroundStyle(.red)
        }
        if let loadError = model.loadError {
          Text(loadError).foregroundStyle(.red)
        }
      }
      .font(.caption)
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.horizontal, 12)
      .padding(.vertical, 8)
    }
  }

  private func row(_ entry: DeletedEntry) -> some View {
    HStack(alignment: .top, spacing: 8) {
      Image(systemName: icon(entry))
        .foregroundStyle(.secondary)
        .frame(width: 18)
      VStack(alignment: .leading, spacing: 2) {
        Text(entry.title).lineLimit(1)
        Text(location(entry))
          .font(.subheadline)
          .foregroundStyle(.secondary)
          .lineLimit(1)
        Text(entry.deletedAt, style: .relative)
          .font(.caption)
          .foregroundStyle(.tertiary)
      }
    }
  }

  private func icon(_ entry: DeletedEntry) -> String {
    switch entry {
    case .item: "list.bullet.rectangle"
    case .credential: "key"
    }
  }

  /// Where the entry lived, as `vault` or `vault / item`.
  private func location(_ entry: DeletedEntry) -> String {
    let vault = vaults.vaults.first { $0.key == entry.vaultKey }
    let vaultName = vault?.name ?? entry.vaultKey
    switch entry {
    case .item: return vaultName
    case .credential(_, let cred): return "\(vaultName) / \(cred.itemTitle)"
    }
  }
}

/// Details of the selected deleted entry, with its values.
struct RecentlyDeletedDetailView: View {
  let model: RecentlyDeletedModel

  var body: some View {
    Group {
      if let entry = model.selectedEntry {
        // The id resets reveal state when the selection changes.
        RecentlyDeletedDetail(model: model, entry: entry)
          .id(entry.id)
      } else if !model.entries.isEmpty {
        ContentUnavailableView("Select a deleted item", systemImage: "trash")
      }
    }
    .paneBackground()
  }
}

private struct RecentlyDeletedDetail: View {
  @Environment(VaultsModel.self) private var vaults
  let model: RecentlyDeletedModel
  let entry: DeletedEntry

  @State private var confirmingPurge = false
  @State private var isWorking = false

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 20) {
        header
        actions
        Divider()
        values
      }
      .padding(20)
      .frame(maxWidth: .infinity, alignment: .leading)
    }
    .navigationTitle(entry.title)
    .confirmationDialog(
      "Delete \"\(entry.title)\" permanently?",
      isPresented: $confirmingPurge
    ) {
      Button("Delete Permanently", role: .destructive) {
        run { await model.purge(entry, using: vaults) }
      }
    } message: {
      Text(purgeMessage)
    }
  }

  private var header: some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(entry.title).font(.title2).fontWeight(.semibold)
      Text(entry.key)
        .font(.callout)
        .foregroundStyle(.secondary)
        .textSelection(.enabled)
      Text(locationText)
        .font(.callout)
        .foregroundStyle(.secondary)
      Text("Deleted \(entry.deletedAt.formatted())")
        .font(.callout)
        .foregroundStyle(.secondary)
    }
  }

  private var actions: some View {
    HStack {
      Button("Restore") {
        run { await model.restore(entry, using: vaults) }
      }
      Button("Delete Permanently", role: .destructive) { confirmingPurge = true }
      if isWorking { ProgressView().controlSize(.small) }
    }
  }

  @ViewBuilder
  private var values: some View {
    switch entry {
    case .item(let vaultKey, let item):
      if item.credentials.isEmpty {
        Text("No credentials").foregroundStyle(.secondary)
      }
      ForEach(item.credentials, id: \.id) { cred in
        DeletedSecretRow(
          vaultKey: vaultKey, itemId: item.id, credId: cred.id, title: cred.title,
          key: cred.key,
          note: cred.deletedBeforeItem ? "Deleted before the item" : nil,
          isFile: cred.kind.kind == "file", file: cred.file)
      }
    case .credential(let vaultKey, let cred):
      DeletedSecretRow(
        vaultKey: vaultKey, itemId: cred.itemId, credId: cred.id, title: cred.title,
        key: cred.key, note: nil, isFile: cred.kind.kind == "file", file: cred.file)
    }
  }

  private var locationText: String {
    let vault = vaults.vaults.first { $0.key == entry.vaultKey }
    let vaultName = vault?.name ?? entry.vaultKey
    switch entry {
    case .item: return "Item in \(vaultName)"
    case .credential(_, let cred): return "Credential of \(cred.itemTitle) in \(vaultName)"
    }
  }

  private var purgeMessage: String {
    switch entry {
    case .item(_, let item):
      "The item and its \(item.credentials.count) credential(s) are erased from the vault. \(Self.retainedNote)"
    case .credential:
      "Its value is erased from the vault. \(Self.retainedNote)"
    }
  }

  private static let retainedNote =
    "Previous versions of the vault keep it for up to 30 days, unless you erase them."

  /// Run an action that removes the entry. The view is replaced when the list
  /// reloads without it.
  private func run(_ action: @escaping () async -> Void) {
    isWorking = true
    Task {
      await action()
      isWorking = false
    }
  }
}

/// One deleted credential with its value. The value is masked until clicked. A
/// deleted file shows its details only. Its contents open after a restore.
private struct DeletedSecretRow: View {
  @Environment(VaultsModel.self) private var vaults

  let vaultKey: String
  let itemId: String
  let credId: String
  let title: String
  let key: String
  let note: String?
  let isFile: Bool
  let file: FileInfo?

  @State private var secret: SymmetricKey? = nil
  @State private var isRevealing = false
  @State private var error: String? = nil
  @State private var justCopied = false

  var body: some View {
    if isFile {
      fileBody
    } else {
      secretBody
    }
  }

  private var fileBody: some View {
    VStack(alignment: .leading, spacing: 6) {
      VStack(alignment: .leading, spacing: 2) {
        Text(title).fontWeight(.semibold)
        Text(key + (note.map { " · \($0)" } ?? ""))
          .font(.subheadline)
          .foregroundStyle(.secondary)
      }
      HStack(spacing: 10) {
        Image(systemName: file?.symbolName ?? "doc")
          .foregroundStyle(.secondary)
        VStack(alignment: .leading, spacing: 2) {
          Text(file?.name ?? "Unreadable file record").lineLimit(1).truncationMode(.middle)
          if let file {
            Text(file.detail).font(.caption).foregroundStyle(.secondary)
          }
        }
      }
      Text("Restore it to preview or save the file.")
        .font(.caption)
        .foregroundStyle(.secondary)
    }
  }

  private var secretBody: some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack(alignment: .firstTextBaseline) {
        VStack(alignment: .leading, spacing: 2) {
          Text(title).fontWeight(.semibold)
          Text(key + (note.map { " · \($0)" } ?? ""))
            .font(.subheadline)
            .foregroundStyle(.secondary)
        }
        Spacer(minLength: 0)
        if isRevealing { ProgressView().controlSize(.small) }
        Button(justCopied ? "Copied" : "Copy") { Task { await copy() } }
          .controlSize(.small)
      }
      SecretBox(
        revealed: revealedText,
        lineLimit: nil,
        onToggle: { secret == nil ? reveal() : hide() }
      )
      if let error {
        Text(error).font(.caption).foregroundStyle(.red)
      }
    }
  }

  private var revealedText: String? {
    guard let secret else { return nil }
    return secret.withUnsafeBytes { String(bytes: $0, encoding: .utf8) ?? "(binary data)" }
  }

  private func reveal() {
    guard !isRevealing else { return }
    isRevealing = true
    error = nil
    Task {
      do {
        secret = try await fetch()
      } catch {
        self.error = String(describing: error)
      }
      isRevealing = false
    }
  }

  private func hide() {
    secret = nil
  }

  /// Copy without revealing the value on screen.
  private func copy() async {
    error = nil
    do {
      let value: SymmetricKey
      if let secret {
        value = secret
      } else {
        value = try await fetch()
      }
      if secureCopy(value) {
        justCopied = true
        try? await Task.sleep(for: .seconds(1.2))
        justCopied = false
      } else {
        error = "Value is not text."
      }
    } catch {
      self.error = String(describing: error)
    }
  }

  private func fetch() async throws -> SymmetricKey {
    try await vaults.deletedCredentialSecret(vaultKey: vaultKey, itemId: itemId, credId: credId)
  }
}
