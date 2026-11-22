import AxoPassFFI
import SwiftUI

/// Conflicts of a synced vault, or of one item. Each conflict lists the values
/// that Macs saved concurrently, with the Mac and time of each. Keeping one
/// value replaces the others on every Mac.
struct ConflictsSheet: View {
  @Environment(VaultsModel.self) private var model
  @Environment(SyncModel.self) private var sync
  @Environment(\.dismiss) private var dismiss

  let vault: SyncVaultRef
  /// Item the list is limited to. Nil lists every conflict of the vault.
  let itemKey: String?

  @State private var conflicts: [ConflictInfo]? = nil
  /// Concealed values shown on request, by conflict and write id.
  @State private var revealed: Set<String> = []
  @State private var resolving: String? = nil
  @State private var errorMessage: String? = nil

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(heading).font(.headline)

      if let conflicts {
        if conflicts.isEmpty {
          Text("No conflicts")
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, minHeight: 60)
        } else {
          // The list is as tall as its rows, and scrolls past the maximum
          // height.
          ViewThatFits(in: .vertical) {
            conflictList(conflicts)
            ScrollView { conflictList(conflicts) }
          }
          .frame(maxHeight: 420)
        }
      } else {
        ProgressView().frame(maxWidth: .infinity, minHeight: 80)
      }

      Text(
        "Each value was saved on a different Mac before they synced. Keep one to replace the others on every Mac. Field values not kept stay in the field history."
      )
      .font(.caption)
      .foregroundStyle(.secondary)
      .fixedSize(horizontal: false, vertical: true)

      if let errorMessage {
        SyncErrorLabel(message: errorMessage)
      }

      HStack {
        if resolving != nil { ProgressView().controlSize(.small) }
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

  private var heading: String {
    if itemKey != nil, let title = conflicts?.first?.itemTitle {
      return "Conflicts in \(title)"
    }
    return "Conflicts in \(vault.name)"
  }

  private func conflictList(_ conflicts: [ConflictInfo]) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      ForEach(conflicts, id: \.registerId) { conflict in
        conflictSection(conflict)
        if conflict.registerId != conflicts.last?.registerId { Divider() }
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private func conflictSection(_ conflict: ConflictInfo) -> some View {
    VStack(alignment: .leading, spacing: 8) {
      Text(title(of: conflict))
        .fontWeight(.semibold)
      ForEach(conflict.values, id: \.writeId) { value in
        valueRow(value, of: conflict)
      }
    }
    .padding(.vertical, 10)
  }

  /// Item, field, and register of a conflict, such as "GitHub · Password ·
  /// Value".
  private func title(of conflict: ConflictInfo) -> String {
    let register = registerName(conflict.register)
    if conflict.entityKind == "vault" { return "Vault \(register.lowercased())" }
    let parts = [
      itemKey == nil ? conflict.itemTitle ?? "Item" : nil,
      conflict.credentialTitle,
      register,
    ]
    return parts.compactMap { $0 }.joined(separator: " · ")
  }

  private func valueRow(_ value: ConflictValueInfo, of conflict: ConflictInfo) -> some View {
    let id = "\(conflict.registerId)/\(value.writeId)"
    return VStack(alignment: .leading, spacing: 6) {
      HStack(spacing: 6) {
        Text(origin(of: value))
          .font(.callout)
          .foregroundStyle(.secondary)
        if value.shown {
          Text("Shown")
            .font(.caption.weight(.medium))
            .foregroundStyle(.tint)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(Color.accentColor.opacity(0.15), in: Capsule())
            .help("The vault shows this value until the conflict is resolved.")
        }
        Spacer(minLength: 0)
        Button("Keep This") { keep(value, of: conflict) }
          .disabled(resolving != nil)
      }
      .controlSize(.small)
      if value.concealed {
        SecretBox(
          revealed: revealed.contains(id) ? value.text : nil,
          lineLimit: 1,
          onToggle: {
            if revealed.remove(id) == nil { revealed.insert(id) }
          })
      } else {
        Text(value.text.isEmpty ? " " : value.text)
          .font(.system(.body, design: .monospaced))
          .textSelection(.enabled)
          .lineLimit(1)
          .truncationMode(.tail)
          .padding(.vertical, 6)
          .padding(.horizontal, 8)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
      }
    }
  }

  /// Mac that wrote a value and when, by the clock of that Mac.
  private func origin(of value: ConflictValueInfo) -> String {
    let mac = value.thisMac ? "This Mac" : (value.macName ?? "Unknown Mac")
    let time = Date(timeIntervalSince1970: TimeInterval(value.writtenAt)).formatted()
    return "\(mac) · \(time)"
  }

  private func load() async {
    do {
      let all = try await model.conflicts(vault.key)
      conflicts = itemKey.map { key in all.filter { $0.itemKey == key } } ?? all
    } catch {
      conflicts = []
      errorMessage = error.userMessage
    }
  }

  private func keep(_ value: ConflictValueInfo, of conflict: ConflictInfo) {
    errorMessage = nil
    resolving = conflict.registerId
    Task {
      do {
        try await model.resolveConflict(vaultKey: vault.key, conflict: conflict, value: value)
      } catch {
        if let refusal = EditRefusal(error), refusal.reason == .changed {
          errorMessage = "The values changed on another Mac. The list shows the current values."
        } else {
          errorMessage = error.userMessage
        }
      }
      revealed = []
      await load()
      await sync.reload(vault.key)
      resolving = nil
    }
  }
}
