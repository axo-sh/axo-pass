import AxoPassFFI
import CryptoKit
import SwiftUI
import UniformTypeIdentifiers

struct VaultDetailView: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    Group {
      if let selected = model.selectedItem {
        CredentialList(item: selected.item, vaultKey: selected.vaultKey)
      } else if model.isLoadingSelectedItems {
        DelayedProgressView()
      } else {
        ContentUnavailableView("Select an item", systemImage: "list.bullet.rectangle")
      }
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(.windowBackground)
  }
}

/// Inset applied to each credential row. The drop indicator is offset by this
/// much to reach the row edge where the separator is drawn.
private let credentialRowInset: CGFloat = 8

/// Drag payload for credential reordering. A dedicated type keeps the drag
/// inside the app: the credential key is not exported as plain text, and text
/// dragged in from elsewhere does not decode into a drop.
private struct CredentialDrag: Codable, Transferable {
  let itemKey: String
  let credKey: String

  static var transferRepresentation: some TransferRepresentation {
    CodableRepresentation(contentType: .axoCredentialDrag)
  }
}

extension UTType {
  fileprivate static let axoCredentialDrag = UTType(
    exportedAs: "com.breakfastlabs.axo-pass.credential-drag"
  )
}

private struct CredentialList: View {
  @Environment(VaultsModel.self) private var model
  let item: ItemInfo
  let vaultKey: String

  @State private var secrets: [String: SymmetricKey] = [:]
  @State private var errors: [String: String] = [:]
  @State private var revealing: Set<String> = []
  @State private var isEditing: Bool = false
  @State private var showingNewCredentialSheet = false
  // Local override of credential order while a drag-reorder is pending its
  // reload. Cleared once the model returns the credentials in the new order.
  @State private var pendingOrder: [String]? = nil
  // Where a drag would currently insert, for the drop indicator.
  @State private var dropTarget: DropTarget? = nil

  /// A drag inserts before a given credential, or at the end of the list. The
  /// end is its own case because no row's leading indicator can address it.
  private enum DropTarget: Equatable {
    case before(String)
    case end
  }

  var body: some View {
    List {
      Section {
        header
          .listRowSeparator(.hidden)
          .listRowInsets(EdgeInsets(top: 8, leading: 4, bottom: 16, trailing: 4))
      }
      Section {
        if item.credentials.isEmpty {
          Text("No credentials")
            .foregroundStyle(.secondary)
        } else {
          ForEach(displayCredentials, id: \.key) { cred in
            reorderableRow(cred)
              .listRowInsets(
                EdgeInsets(
                  top: credentialRowInset, leading: credentialRowInset,
                  bottom: credentialRowInset, trailing: credentialRowInset
                )
              )
              // The separator otherwise runs to the list's edge, past the row's
              // trailing inset, so it looks wider than the row content.
              .alignmentGuide(.listRowSeparatorLeading) { $0[.leading] }
              .alignmentGuide(.listRowSeparatorTrailing) { $0[.trailing] }
          }
          endDropZone
            .listRowSeparator(.hidden)
            .listRowInsets(
              EdgeInsets(
                top: 0, leading: credentialRowInset, bottom: 0, trailing: credentialRowInset
              )
            )
        }
      }
    }
    .listStyle(.inset)
    .animation(.snappy(duration: 0.2), value: displayCredentials.map(\.key))
    .animation(.easeInOut(duration: 0.1), value: dropTarget)
    .overlay {
      if isEditing {
        RoundedRectangle(cornerRadius: 6)
          .strokeBorder(.tint, lineWidth: 2)
          .padding(8)
          .allowsHitTesting(false)
      }
    }
    .navigationTitle(item.title)
    .toolbar {
      ToolbarItemGroup(placement: .primaryAction) {
        // Push the item actions to the trailing edge of the toolbar.
        Spacer()

        if !isEditing, hasConcealed {
          Button(allRevealed ? "Hide All" : "Reveal All") {
            if allRevealed {
              hideAll()
            } else {
              Task { await revealAll() }
            }
          }
          .disabled(!revealing.isEmpty)
        }

        Button(isEditing ? "Done" : "Edit") {
          if isEditing {
            isEditing = false
            hideAll()
          } else {
            // Editing resubmits each credential's value along with its title,
            // so reveal everything before the edit forms appear.
            Task {
              await revealAll()
              isEditing = true
            }
          }
        }
        .disabled(!revealing.isEmpty)

        Button {
          showingNewCredentialSheet = true
        } label: {
          Label("Add Credential", systemImage: "plus")
        }
      }
    }
    .onChange(of: item.key) {
      secrets = [:]
      errors = [:]
      revealing = []
      isEditing = false
      pendingOrder = nil
    }
    .onChange(of: item.credentials.map(\.key)) {
      // The reload after a reorder delivers the persisted order; drop the
      // local override so the two cannot diverge.
      pendingOrder = nil
    }
    .sheet(isPresented: $showingNewCredentialSheet) {
      NewCredentialSheet { key, title, value, kind in
        await model.addOrUpdateCredential(
          vaultKey: vaultKey, itemKey: item.key, credKey: key, title: title, value: value,
          kind: kind
        )
      }
    }
  }

  private var header: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "lock.fill")
        .font(.system(size: 26))
        .foregroundStyle(.tint)
        .frame(width: 34)
      VStack(alignment: .leading, spacing: 2) {
        Text(item.title).font(.title2).fontWeight(.semibold)
        Text(item.key)
          .font(.callout)
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      }
      Spacer(minLength: 12)
    }
  }

  /// Credentials in display order: the pending drag order when set, otherwise
  /// the order the model returned (persisted position, then title).
  private var displayCredentials: [CredentialInfo] {
    guard let pendingOrder else { return item.credentials }
    let byKey = Dictionary(item.credentials.map { ($0.key, $0) }, uniquingKeysWith: { a, _ in a })
    let ordered = pendingOrder.compactMap { byKey[$0] }
    return ordered.count == item.credentials.count ? ordered : item.credentials
  }

  /// A credential row with a drag handle for reordering, plus a drop indicator
  /// on the row the drag is over. Reordering is an edit-mode action, alongside
  /// the other structural edits. The row keeps one view identity across the
  /// edit toggle so CredentialRow retains its draft state, so nothing here
  /// branches on isEditing: a branch would give the row a new identity and
  /// reset it.
  private func reorderableRow(_ cred: CredentialInfo) -> some View {
    HStack(alignment: .top, spacing: 0) {
      credentialRowBody(cred)
      dragHandle(cred)
    }
    .overlay(alignment: .top) {
      // The overlay sits inside the row insets, so pull the indicator back
      // out to the row's top edge, where the separator is drawn.
      dropIndicator(for: .before(cred.key))
        .offset(y: -credentialRowInset)
    }
    .dropDestination(for: CredentialDrag.self) { dropped, _ in
      dropTarget = nil
      guard let moved = reorderDragKey(dropped.first) else { return false }
      reorder(moved: moved, before: cred.key)
      return true
    } isTargeted: { targeted in
      setDropTarget(.before(cred.key), targeted: targeted)
    }
  }

  /// The only drag source for a reorder, shown in edit mode. SwiftUI has no way
  /// to disable `draggable` in place, and applying it conditionally would
  /// rebuild the row, so the handle carries it instead: hit testing off means no
  /// drag starts. A handle also keeps the drag from competing with the text
  /// fields inside the row. Its width collapses outside edit mode so the row
  /// content is not inset on the trailing edge for a handle that is not there.
  private func dragHandle(_ cred: CredentialInfo) -> some View {
    Image(systemName: "line.3.horizontal")
      .font(.caption)
      .foregroundStyle(.tertiary)
      .frame(width: isEditing ? 18 : 0, height: 20)
      .clipped()
      .contentShape(Rectangle())
      .draggable(CredentialDrag(itemKey: item.key, credKey: cred.key)) {
        credentialRowBody(cred)
          .frame(width: 340)
          .padding(8)
          .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
          .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.tint, lineWidth: 1))
      }
      .opacity(isEditing ? 1 : 0)
      .allowsHitTesting(isEditing)
      .animation(.easeInOut(duration: 0.12), value: isEditing)
  }

  /// A short strip after the last row, so a drag can reach the final slot. No
  /// row's leading indicator addresses it, since each marks "insert before".
  private var endDropZone: some View {
    Color.clear
      .frame(height: credentialRowInset * 2)
      .contentShape(Rectangle())
      .overlay(alignment: .top) { dropIndicator(for: .end) }
      .dropDestination(for: CredentialDrag.self) { dropped, _ in
        dropTarget = nil
        guard let moved = reorderDragKey(dropped.first) else { return false }
        reorder(moved: moved, before: nil)
        return true
      } isTargeted: { targeted in
        setDropTarget(.end, targeted: targeted)
      }
  }

  /// The insertion bar, drawn on the row edge it marks. Empty unless the drag
  /// is currently over `target`.
  @ViewBuilder
  private func dropIndicator(for target: DropTarget) -> some View {
    if dropTarget == target {
      Rectangle()
        .fill(.tint)
        .frame(height: 2)
        .padding(.horizontal, -credentialRowInset)
        // Centre the bar on the edge rather than hanging it below.
        .offset(y: -1)
    }
  }

  private func setDropTarget(_ target: DropTarget, targeted: Bool) {
    guard isEditing else { return }
    if targeted {
      dropTarget = target
    } else if dropTarget == target {
      dropTarget = nil
    }
  }

  /// The credential key a drag carries, or nil when the drag is not a reorder
  /// of a credential belonging to this item.
  private func reorderDragKey(_ drag: CredentialDrag?) -> String? {
    guard isEditing, let drag, drag.itemKey == item.key,
      item.credentials.contains(where: { $0.key == drag.credKey })
    else { return nil }
    return drag.credKey
  }

  @ViewBuilder
  private func credentialRowBody(_ cred: CredentialInfo) -> some View {
    CredentialRow(
      cred: cred,
      secret: secrets[cred.key],
      error: errors[cred.key],
      isRevealing: revealing.contains(cred.key),
      isEditing: isEditing,
      onReveal: { Task { await reveal(cred) } },
      onHide: { hide(cred) },
      onCopy: { await copy(cred) },
      onSave: { newKey, newTitle, newValue, newKind in
        Task {
          await save(
            cred, newKey: newKey, newTitle: newTitle, newValue: newValue, newKind: newKind
          )
        }
      },
      onQuickSaveValue: { newValue in
        Task { await quickSaveValue(cred, newValue: newValue) }
      },
      onDelete: { Task { await delete(cred) } }
    )
  }

  /// Move `moved` to just before `target`, or to the end when `target` is nil,
  /// and persist the new order.
  private func reorder(moved: String, before target: String?) {
    guard moved != target else { return }
    var keys = displayCredentials.map(\.key)
    guard let from = keys.firstIndex(of: moved) else { return }
    keys.remove(at: from)
    let insertAt = target.flatMap { keys.firstIndex(of: $0) } ?? keys.count
    keys.insert(moved, at: insertAt)
    guard keys != displayCredentials.map(\.key) else { return }
    pendingOrder = keys
    Task {
      let ok = await model.reorderCredentials(
        vaultKey: vaultKey, itemKey: item.key, orderedKeys: keys
      )
      // A failed reorder reloads the original order, so the key list does not
      // change and the onChange above never fires. Drop the override here so
      // the rows snap back instead of showing an order that was not saved.
      if !ok {
        pendingOrder = nil
        if let err = model.actionError {
          errors[moved] = err
        }
      }
    }
  }

  private func quickSaveValue(_ cred: CredentialInfo, newValue: String) async {
    let ok = await model.addOrUpdateCredential(
      vaultKey: vaultKey, itemKey: item.key, credKey: cred.key, title: cred.title, value: newValue,
      kind: nil
    )
    if ok {
      refreshCachedSecret(newValue, for: cred.key)
      errors.removeValue(forKey: cred.key)
    } else if let err = model.actionError {
      errors[cred.key] = err
    }
  }

  private var concealedCredentials: [CredentialInfo] {
    item.credentials.filter(\.kind.concealed)
  }

  private var hasConcealed: Bool {
    !concealedCredentials.isEmpty
  }

  /// "All revealed" tracks only the concealed credentials; plain-text ones are
  /// always shown and are not toggled by Reveal/Hide All.
  private var allRevealed: Bool {
    hasConcealed && concealedCredentials.allSatisfy { secrets[$0.key] != nil }
  }

  private func revealAll() async {
    await withTaskGroup(of: Void.self) { group in
      for cred in item.credentials where secrets[cred.key] == nil && !revealing.contains(cred.key) {
        group.addTask { await reveal(cred) }
      }
    }
  }

  private func hideAll() {
    for cred in concealedCredentials {
      secrets.removeValue(forKey: cred.key)
    }
  }

  private func reveal(_ cred: CredentialInfo) async {
    revealing.insert(cred.key)
    errors.removeValue(forKey: cred.key)
    do {
      secrets[cred.key] = try await model.credentialSecret(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key
      )
    } catch {
      errors[cred.key] = String(describing: error)
    }
    revealing.remove(cred.key)
  }

  private func hide(_ cred: CredentialInfo) {
    secrets.removeValue(forKey: cred.key)
  }

  /// Copy without revealing: if the secret is not already on screen, fetch a
  /// throwaway copy for the clipboard and do not store it in `secrets`. Returns
  /// whether the value reached the pasteboard.
  private func copy(_ cred: CredentialInfo) async -> Bool {
    if let secret = secrets[cred.key] {
      return copyToPasteboard(secret)
    }
    revealing.insert(cred.key)
    errors.removeValue(forKey: cred.key)
    defer { revealing.remove(cred.key) }
    do {
      let secret = try await model.credentialSecret(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key
      )
      return copyToPasteboard(secret)
    } catch {
      errors[cred.key] = String(describing: error)
      return false
    }
  }

  private func copyToPasteboard(_ secret: SymmetricKey) -> Bool {
    secret.withUnsafeBytes { ptr in
      guard let str = String(bytes: ptr, encoding: .utf8) else { return false }
      secureCopy(str)
      return true
    }
  }

  /// Persist an edited credential. A changed id means adding the credential
  /// under the new key and deleting the old one, since the FFI has no rename.
  private func save(
    _ cred: CredentialInfo, newKey: String, newTitle: String, newValue: String,
    newKind: FieldKindInfo?
  ) async {
    let ok: Bool
    if newKey == cred.key {
      ok = await model.addOrUpdateCredential(
        vaultKey: vaultKey, itemKey: item.key, credKey: cred.key,
        title: newTitle, value: newValue, kind: newKind
      )
      if ok {
        applySavedSecret(newValue, for: cred.key, kind: newKind)
        errors.removeValue(forKey: cred.key)
      }
    } else {
      ok = await model.renameCredentialKey(
        vaultKey: vaultKey, itemKey: item.key, oldKey: cred.key, newKey: newKey,
        title: newTitle, value: newValue, kind: newKind
      )
      if ok {
        secrets[newKey] = secrets.removeValue(forKey: cred.key)
        applySavedSecret(newValue, for: newKey, kind: newKind)
        errors.removeValue(forKey: cred.key)
        if revealing.remove(cred.key) != nil { revealing.insert(newKey) }
      }
    }
    if !ok, let err = model.actionError {
      errors[cred.key] = err
    }
  }

  /// Bring the secret cache in line with what was just saved. A credential the
  /// save made concealed goes back to hidden: `hideAll` on Done runs before the
  /// save, against the old kind, so it does not cover this. Otherwise the
  /// revealed value is refreshed. A credential the save made plain text is
  /// left out of the cache and reveals itself when its value view appears.
  private func applySavedSecret(_ value: String, for key: String, kind: FieldKindInfo?) {
    if kind?.concealed == true {
      secrets.removeValue(forKey: key)
      return
    }
    refreshCachedSecret(value, for: key)
  }

  /// Update a revealed value in the cache after a successful save, so the row
  /// stops showing what was there before. A credential that is not revealed is
  /// left alone: the next reveal fetches the new value. The row only requests a
  /// secret on first appearance, so a stale entry would otherwise persist.
  private func refreshCachedSecret(_ value: String, for key: String) {
    guard secrets[key] != nil else { return }
    var raw = Data(value.utf8)
    secrets[key] = SymmetricKey(data: raw)
    raw.resetBytes(in: raw.indices)
  }

  private func delete(_ cred: CredentialInfo) async {
    let ok = await model.deleteCredential(vaultKey: vaultKey, itemKey: item.key, credKey: cred.key)
    if ok {
      secrets.removeValue(forKey: cred.key)
      errors.removeValue(forKey: cred.key)
    } else if let err = model.actionError {
      errors[cred.key] = err
    }
  }
}

private struct NewCredentialSheet: View {
  let onSubmit:
    (_ key: String, _ title: String, _ value: String, _ kind: FieldKindInfo) async -> Bool

  @Environment(\.dismiss) private var dismiss
  @State private var title: String = ""
  @State private var key: String = ""
  @State private var value: String = ""
  @State private var concealed: Bool = true
  @State private var multiline: Bool = false
  @State private var isSubmitting = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Credential").font(.headline)
      Form {
        TextField("Title", text: $title)
        TextField("Key (a-z, 0-9, -, _)", text: $key)
        if concealed && !multiline {
          SecureField("Value", text: $value)
        } else {
          TextField("Value", text: $value, axis: .vertical)
            .lineLimit(multiline ? 3...12 : 1...1)
        }

        HStack(spacing: 16) {
          Toggle("Concealed", isOn: $concealed)
          Toggle("Multiline", isOn: $multiline)
        }
        .toggleStyle(.checkbox)
      }

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Create") {
          Task {
            isSubmitting = true
            let kind = FieldKindInfo(kind: "text", concealed: concealed, multiline: multiline)
            if await onSubmit(key, title, value, kind) { dismiss() }
            isSubmitting = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || key.isEmpty || title.isEmpty || value.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 320)
  }
}
