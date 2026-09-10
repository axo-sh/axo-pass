import AxoPassFFI
import SwiftUI
import UniformTypeIdentifiers

/// Drag payload for credential reordering. A dedicated type keeps the drag
/// inside the app: the credential key is not exported as plain text, and text
/// dragged in from elsewhere does not decode into a drop.
struct CredentialDrag: Codable, Transferable {
  let itemKey: String
  let credKey: String

  static var transferRepresentation: some TransferRepresentation {
    CodableRepresentation(contentType: .axoCredentialDrag)
  }
}

extension UTType {
  fileprivate static let axoCredentialDrag = UTType(
    exportedAs: "com.breakfastlabs.frittata.credential-drag"
  )
}

extension CredentialList {
  /// A drag inserts before a given credential, or at the end of the list. The
  /// end is its own case because no row's leading indicator can address it.
  enum DropTarget: Equatable {
    case before(String)
    case end
  }

  /// Credentials in display order: the pending drag order when set, otherwise
  /// the order the model returned (persisted position, then title).
  var displayCredentials: [CredentialInfo] {
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
  func reorderableRow(_ cred: CredentialInfo) -> some View {
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
  var endDropZone: some View {
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
}
