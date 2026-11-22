import AxoPassFFI
import SwiftUI

extension CredentialList {
  /// Draft target of credential `cred` of this item.
  func draftTarget(_ cred: CredentialInfo) -> DraftTarget {
    DraftTarget(vaultKey: vaultKey, itemId: item.id, credentialId: cred.id)
  }

  /// Draft target of this item itself.
  var itemDraftTarget: DraftTarget {
    DraftTarget(vaultKey: vaultKey, itemId: item.id, credentialId: nil)
  }

  /// Draft notice and conflict marker of the item itself, shown under the
  /// header.
  @ViewBuilder
  var itemNotices: some View {
    if let draft = model.draft(itemDraftTarget) {
      DraftNotice(
        draft: draft,
        onReapply: { reapplyItem(draft) },
        onDiscard: { model.discardDraft(itemDraftTarget) },
        onResolve: resolveAction)
    }
    let conflicts = item.itemConflicts
    if !conflicts.isEmpty {
      ConflictMarker(registers: conflicts, onResolve: openConflicts)
    }
  }

  /// Draft notice and conflict marker of credential `cred`, shown under its
  /// row.
  @ViewBuilder
  func credentialNotices(_ cred: CredentialInfo) -> some View {
    let target = draftTarget(cred)
    if let draft = model.draft(target) {
      DraftNotice(
        draft: draft,
        onReapply: { reapply(draft, to: cred) },
        onDiscard: { model.discardDraft(target) },
        onResolve: resolveAction)
    }
    let conflicts = item.conflicts(of: cred)
    if !conflicts.isEmpty {
      ConflictMarker(registers: conflicts, onResolve: openConflicts)
    }
  }

  /// Opens the conflicts of this item. Nil in a window without the sync
  /// sheets.
  private var resolveAction: (() -> Void)? {
    guard sync != nil else { return nil }
    return { openConflicts() }
  }

  /// Show the conflicts of this item in the sync sheets.
  func openConflicts() {
    let name = model.vaults.first { $0.key == vaultKey }?.name ?? vaultKey
    sync?.sheet = .conflicts(SyncVaultRef(key: vaultKey, name: name), itemKey: item.key)
  }

  /// Save the kept input of `draft` to `cred` again, with the current reads.
  /// The item reloaded after the refusal, so `item` holds the current values.
  private func reapply(_ draft: EditDraft, to cred: CredentialInfo) {
    let reads = item.reads
    switch draft.change {
    case .credentialTitle(let title):
      saveRename(cred, field: .title, to: title, reads: reads)
    case .credentialKey(let key):
      saveRename(cred, field: .key, to: key, reads: reads)
    case .credentialValue(let value):
      Task { await quickSaveValue(cred, newValue: value, reads: reads) }
    case .credentialKind(let kind):
      saveKind(cred, kind, reads: reads)
    case .role(let role, let assign):
      Task { await saveRole(cred, role: role, assign: assign, reads: reads) }
    case .convertToLogin:
      reapplyItem(draft)
    }
  }

  /// Save the kept input of an item draft again, with the current reads.
  private func reapplyItem(_ draft: EditDraft) {
    guard draft.change == .convertToLogin else { return }
    let reads = item.reads
    Task { await convertToLogin(reads: reads) }
  }
}
