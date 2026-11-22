import AxoPassFFI
import SwiftUI

/// Edit that a synced vault refused, as `FfiError.EditRefused` reports it.
/// Nothing of the edit was saved.
struct EditRefusal: Equatable {
  enum Reason: Equatable {
    /// The register changed on another Mac since the edit read it.
    case changed
    /// The register holds a conflict, which is resolved before an edit.
    case conflicted
    /// The edit did not carry the write ids of the register.
    case notRead
  }

  let reason: Reason
  /// `vault`, `item`, or `credential`.
  let entityKind: String
  /// Short id of the item or credential. Empty for the vault.
  let entityId: String
  let register: String
  let message: String

  /// Refusal that `error` reports, or nil for any other error.
  init?(_ error: Error) {
    guard let ffi = error as? FfiError,
      case .EditRefused(let reason, let entityKind, let entityId, let register, let message) = ffi
    else { return nil }
    switch reason {
    case "changed": self.reason = .changed
    case "conflicted": self.reason = .conflicted
    default: self.reason = .notRead
    }
    self.entityKind = entityKind
    self.entityId = entityId
    self.register = register
    self.message = message
  }

  /// Message of a sheet that keeps the input. `action` is the label of its
  /// save button.
  func sheetMessage(action: String) -> String {
    switch reason {
    case .changed:
      "Changed on another Mac. Your input is kept. \(action) again to apply it to the current value."
    case .conflicted:
      "This value has a conflict. Resolve the conflict first. Your input is kept."
    case .notRead:
      "The vault changed since it was read. Your input is kept. \(action) again to apply it."
    }
  }
}

/// Item or credential that a draft changes. Ids do not change with keys.
struct DraftTarget: Hashable {
  let vaultKey: String
  let itemId: String
  /// Nil for a change to the item itself.
  let credentialId: String?
}

/// Unsaved change of a refused edit.
enum DraftChange: Equatable {
  case convertToLogin
  case credentialTitle(String)
  case credentialKey(String)
  case credentialValue(String)
  case credentialKind(FieldKindInfo)
  /// Role assigned to the credential (`assign`) or cleared from it.
  case role(String, assign: Bool)

  /// Short description for the notice. A value is not shown, since it can be a
  /// secret.
  var summary: String {
    switch self {
    case .convertToLogin: "The AutoFill conversion"
    case .credentialTitle(let title): "The new title “\(title)”"
    case .credentialKey(let key): "The new key “\(key)”"
    case .credentialValue: "The new value"
    case .credentialKind: "The new field options"
    case .role(_, let assign): assign ? "The new role" : "The role change"
    }
  }
}

/// Refused edit with its unsaved change.
struct EditDraft: Equatable {
  let change: DraftChange
  let refusal: EditRefusal
}

/// Reads of an edit made in a sheet. A refusal replaces them with the current
/// reads, so the next submit applies the input kept in the sheet to the
/// current values.
@MainActor
final class SheetReads {
  var reads: [RegisterRead]

  init(_ reads: [RegisterRead]) {
    self.reads = reads
  }
}

extension TitleSheetRequest {
  /// Rename sheet of `item` in vault `vaultKey`. The sheet reads the item
  /// when it opens. A refused rename keeps the input in the sheet.
  @MainActor
  static func renameItem(_ item: ItemInfo, vaultKey: String, model: VaultsModel) -> Self {
    let reads = SheetReads(item.reads)
    return TitleSheetRequest(
      heading: "Rename Item", actionLabel: "Rename", initialTitle: item.title
    ) { [itemKey = item.key] title in
      await model.submitSheetEdit(
        reads, vaultKey: vaultKey, itemKey: itemKey, action: "Rename"
      ) {
        try await model.renameItem(
          vaultKey: vaultKey, itemKey: itemKey, title: title, reads: reads.reads)
      }
    }
  }

  /// Key change sheet of `item` in vault `vaultKey`, as `renameItem`.
  @MainActor
  static func changeItemKey(_ item: ItemInfo, vaultKey: String, model: VaultsModel) -> Self {
    let reads = SheetReads(item.reads)
    return TitleSheetRequest(
      heading: "Change Item Key", actionLabel: "Change", initialTitle: item.key,
      fieldLabel: "Key", footnote: keyChangeWarning
    ) { [itemKey = item.key] key in
      await model.submitSheetEdit(
        reads, vaultKey: vaultKey, itemKey: itemKey, action: "Change"
      ) {
        try await model.changeItemKey(
          vaultKey: vaultKey, itemKey: itemKey, newKey: key, reads: reads.reads)
      }
    }
  }
}

extension ItemInfo {
  /// Conflicted registers of the item itself, such as the title or a role
  /// slot.
  var itemConflicts: [RegisterRead] {
    reads.filter { $0.conflicted && $0.entityKind == "item" }
  }

  /// Conflicted registers of credential `cred`.
  func conflicts(of cred: CredentialInfo) -> [RegisterRead] {
    reads.filter { $0.conflicted && $0.entityKind == "credential" && $0.entityId == cred.id }
  }

  /// Whether the item or any of its credentials has a conflict.
  var hasConflicts: Bool {
    reads.contains(where: \.conflicted)
  }
}

extension ConflictInfo {
  /// Register of the conflict, unique within a vault. Two registers written
  /// by the same transactions hold the same `read`.
  var registerId: String {
    "\(entityKind)/\(entityId)/\(register)"
  }
}

/// Display name of a register, as `RegisterRead.register` gives it.
func registerName(_ register: String) -> String {
  switch register {
  case "name": "Name"
  case "title": "Title"
  case "category": "Category"
  case "key": "Key"
  case "username": "Username field"
  case "password": "Password field"
  case "totp": "One-time code field"
  case "kind": "Kind"
  case "value": "Value"
  default: register
  }
}

extension VaultsModel {
  /// Draft of `target`, if an edit to it was refused.
  func draft(_ target: DraftTarget) -> EditDraft? {
    drafts[target]
  }

  /// Run `action`, the save of `change` to `target`. A refusal keeps the
  /// change as a draft of `target`. A save drops the draft. Returns the
  /// message of any other error.
  func saveEdit(
    _ target: DraftTarget, _ change: DraftChange, _ action: () async throws -> Void
  ) async -> String? {
    do {
      try await action()
      drafts.removeValue(forKey: target)
      return nil
    } catch {
      if let refusal = EditRefusal(error) {
        drafts[target] = EditDraft(change: change, refusal: refusal)
        return nil
      }
      return error.userMessage
    }
  }

  /// Run `action`, the save of an item edit made in a sheet. Returns the
  /// message for the sheet, or nil on success. A refusal replaces `reads` with
  /// the current reads of item `itemKey`, so the next submit reapplies the
  /// input. `action` is the label of the save button.
  func submitSheetEdit(
    _ reads: SheetReads, vaultKey: String, itemKey: String, action: String,
    _ save: () async throws -> Void
  ) async -> String? {
    do {
      try await save()
      return nil
    } catch {
      guard let refusal = EditRefusal(error) else { return error.userMessage }
      reads.reads = item(vaultKey: vaultKey, itemKey: itemKey)?.reads ?? []
      return refusal.sheetMessage(action: action)
    }
  }

  /// Drop the draft of `target`.
  func discardDraft(_ target: DraftTarget) {
    drafts.removeValue(forKey: target)
  }

  /// Conflicts of a synced vault, each with its values. Empty for a vault
  /// that is not synced.
  func conflicts(_ vaultKey: String) async throws -> [ConflictInfo] {
    try await core.listConflicts(vaultKey: vaultKey)
  }

  /// Keep `value` of `conflict`. It replaces every value on every Mac. Field
  /// values not kept go to the field history. Throws `FfiError.EditRefused`
  /// if the values changed since `conflict` was listed. Items reload either
  /// way.
  func resolveConflict(vaultKey: String, conflict: ConflictInfo, value: ConflictValueInfo)
    async throws
  {
    let result: Result<Void, Error>
    do {
      try await core.resolveConflict(
        vaultKey: vaultKey, entityKind: conflict.entityKind, entityId: conflict.entityId,
        register: conflict.register, read: conflict.read, chosenWriteId: value.writeId)
      result = .success(())
    } catch {
      result = .failure(error)
    }
    await syncedVaultChanged(vaultKey)
    try result.get()
  }
}

/// Notice under a row whose edit was refused. Offers to reapply the kept
/// input to the current values, or to discard it.
struct DraftNotice: View {
  let draft: EditDraft
  let onReapply: () -> Void
  let onDiscard: () -> Void
  /// Opens the conflict resolution sheet. Shown for a conflict refusal.
  let onResolve: (() -> Void)?

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      Label {
        VStack(alignment: .leading, spacing: 2) {
          Text(heading).fontWeight(.semibold)
          Text(detail)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        }
      } icon: {
        Image(systemName: "exclamationmark.arrow.triangle.2.circlepath")
          .foregroundStyle(.orange)
      }
      .font(.callout)
      HStack {
        Spacer()
        Button("Discard", action: onDiscard)
        if draft.refusal.reason == .conflicted, let onResolve {
          Button("Resolve Conflict…", action: onResolve)
        }
        Button("Reapply", action: onReapply)
      }
      .controlSize(.small)
    }
    .padding(10)
    .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
  }

  private var heading: String {
    switch draft.refusal.reason {
    case .changed: "Changed on another Mac"
    case .conflicted: "Resolve the conflict first"
    case .notRead: "Not saved"
    }
  }

  private var detail: String {
    let summary = draft.change.summary
    switch draft.refusal.reason {
    case .changed:
      return "\(summary) is not saved. The current values are shown. Reapply it to replace them."
    case .conflicted:
      return "\(summary) is kept. Choose a value for the conflict, then reapply it."
    case .notRead:
      return "\(summary) is not saved, since the vault changed while it was edited. Reapply it."
    }
  }
}

/// Line under a row whose values conflict, with a button that opens the
/// conflict resolution sheet.
struct ConflictMarker: View {
  let registers: [RegisterRead]
  let onResolve: () -> Void

  var body: some View {
    HStack(spacing: 6) {
      Image(systemName: "arrow.triangle.branch")
        .foregroundStyle(.orange)
      Text(text)
        .foregroundStyle(.secondary)
      Spacer(minLength: 0)
      Button("Resolve…", action: onResolve)
        .controlSize(.small)
    }
    .font(.callout)
  }

  private var text: String {
    let names = registers.map { registerName($0.register) }.joined(separator: ", ")
    return "Conflict: \(names)"
  }
}
