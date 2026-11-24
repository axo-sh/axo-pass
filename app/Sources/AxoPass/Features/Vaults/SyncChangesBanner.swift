import AxoPassFFI
import SwiftUI

/// Changes that other devices made to the selected synced vault and that the
/// user did not: items shown with a suffixed key, with Keep and Rename, keys
/// that changed, websites added, and role slots changed. Dismiss clears the
/// changes. The suffixed keys stay listed until they are kept or renamed.
struct SyncChangesBanner: View {
  @Environment(SyncModel.self) private var sync
  @Environment(VaultsModel.self) private var model

  let vault: VaultInfo

  @State private var titleSheet: TitleSheetRequest? = nil
  @State private var isWorking = false
  @State private var error: String? = nil

  private var report: SyncReportInfo? { sync.report(vault.key) }

  /// An item or a credential of an item.
  private struct Entry {
    let item: ItemInfo
    let credential: CredentialInfo?

    /// Name the notice uses.
    var name: String {
      if let credential { return "\(credential.title) in “\(item.title)”" }
      return "“\(item.title)”"
    }

    /// Key the entry is shown with.
    var key: String { credential?.key ?? item.key }
  }

  /// Entry of `ref`, if the vault holds it as a loaded item.
  private func entry(_ ref: EntityRefInfo) -> Entry? {
    let items = model.cachedItems(in: vault.key)
    if ref.isCredential {
      for item in items {
        if let credential = item.credentials.first(where: { $0.id == ref.id }) {
          return Entry(item: item, credential: credential)
        }
      }
      return nil
    }
    return items.first { $0.id == ref.id }.map { Entry(item: $0, credential: nil) }
  }

  /// Item with id `id`.
  private func item(_ id: String) -> ItemInfo? {
    model.cachedItems(in: vault.key).first { $0.id == id }
  }

  var body: some View {
    let suffixed = (report?.suffixedKeys ?? []).compactMap { ref in
      entry(ref).map { (ref, $0) }
    }
    let lines = changeLines()
    if !suffixed.isEmpty || !lines.isEmpty {
      VStack(alignment: .leading, spacing: 8) {
        if !suffixed.isEmpty {
          Label("Keys shown with a suffix", systemImage: "number")
            .font(.headline)
          Text(
            "These share a key with another entry, so they show with a suffix. Keep the suffix as the key, or rename the entry."
          )
          .font(.callout)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
          ForEach(suffixed, id: \.0.id) { ref, entry in
            suffixedRow(ref, entry)
          }
        }
        if !lines.isEmpty {
          Label("Changes from other devices", systemImage: "arrow.triangle.2.circlepath")
            .font(.headline)
          ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
            Text(line)
              .font(.callout)
              .foregroundStyle(.secondary)
              .fixedSize(horizontal: false, vertical: true)
          }
          Button("Dismiss") { dismissNotices() }
            .controlSize(.small)
            .disabled(isWorking)
        }
        if let error { SyncErrorLabel(message: error) }
      }
      .padding(10)
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(.quaternary)
      .sheet(item: $titleSheet) { request in
        TitleSheet(request: request)
      }
    }
  }

  private func suffixedRow(_ ref: EntityRefInfo, _ entry: Entry) -> some View {
    HStack(alignment: .firstTextBaseline, spacing: 8) {
      VStack(alignment: .leading, spacing: 2) {
        Text(entry.name)
          .font(.callout)
        Text(entry.key)
          .font(.callout.monospaced())
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      }
      Spacer(minLength: 8)
      Button("Keep \(entry.key)") { keep(ref) }
        .controlSize(.small)
        .disabled(isWorking)
      // A credential has no key editor, so only an item offers Rename.
      if entry.credential == nil {
        Button("Rename…") {
          titleSheet = TitleSheetRequest.changeItemKey(
            entry.item, vaultKey: vault.key, model: model)
        }
        .controlSize(.small)
        .disabled(isWorking)
      }
    }
  }

  /// Text of each change, in the order of the notices. A change to an entry
  /// that is not loaded or is deleted is left out.
  private func changeLines() -> [String] {
    (report?.notices ?? []).compactMap { notice in
      switch notice {
      case .itemKeyChanged(let itemId):
        guard let item = item(itemId) else { return nil }
        return
          "The key of “\(item.title)” changed to \(item.key). Its path is now \(vault.key)/\(item.key)."
      case .credentialKeyChanged(let credentialId):
        guard let entry = entry(EntityRefInfo(isCredential: true, id: credentialId)) else {
          return nil
        }
        return "The key of \(entry.name) changed to \(entry.key)."
      case .websiteAdded(let itemId):
        guard let item = item(itemId) else { return nil }
        return "A website was added to “\(item.title)”. AutoFill can now offer it on that site."
      case .slotChanged(let itemId):
        guard let item = item(itemId) else { return nil }
        return "The username, password, or one-time code of “\(item.title)” changed."
      }
    }
  }

  private func keep(_ ref: EntityRefInfo) {
    run { try await sync.keepKeys(vaultKey: vault.key, entities: [ref]) }
  }

  private func dismissNotices() {
    run { try await sync.dismissNotices(vaultKey: vault.key) }
  }

  private func run(_ action: @escaping () async throws -> Void) {
    error = nil
    isWorking = true
    Task {
      defer { isWorking = false }
      do {
        try await action()
      } catch FfiError.AuthExpired {
        // The app locked.
      } catch {
        self.error = error.userMessage
      }
    }
  }
}
