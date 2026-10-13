import AxoPassFFI
import SwiftUI
import UniformTypeIdentifiers

/// Drag payload for moving an item into a folder. The dedicated type limits
/// the drag to the app. Item keys are not exported as plain text, and text
/// dragged in from elsewhere does not decode into a drop.
struct ItemDrag: Codable, Transferable {
  let vaultKey: String
  let itemKey: String

  static var transferRepresentation: some TransferRepresentation {
    CodableRepresentation(contentType: .axoItemDrag)
  }
}

extension UTType {
  fileprivate static let axoItemDrag = UTType(
    exportedAs: "com.breakfastlabs.frittata.item-drag"
  )
}

/// Indent of an item row inside a folder, relative to a top-level row.
private let folderItemIndent: CGFloat = 16

struct ItemsPane: View {
  @Environment(VaultsModel.self) private var model
  @Environment(\.undoManager) private var undoManager
  @State private var showingNewItemSheet = false
  @State private var titleSheet: TitleSheetRequest? = nil
  // Collapsed folder ids.
  @State private var collapsedFolders: Set<String> = []
  // Drop highlight target. A folder id for drops into that folder, or an
  // unfiled item's `unfiledDropID`.
  @State private var dropTarget: String? = nil

  /// Folders in the selected vault. Empty for "All Secrets", which lists items
  /// from all vaults without grouping.
  private var folders: [FolderInfo] {
    guard !model.isAllSecrets, let key = model.selectedVaultKey else { return [] }
    return model.folders(for: key)
  }

  var body: some View {
    @Bindable var model = model
    Group {
      if model.isLoadingSelectedItems {
        DelayedProgressView()
      } else if (model.selectedVault != nil || model.isAllSecrets)
        && !(model.displayItems.isEmpty && folders.isEmpty)
      {
        List(selection: $model.selectedItemRef) {
          if folders.isEmpty {
            itemRows(model.displayItems)
          } else {
            ForEach(folders, id: \.id) { folder in
              folderGroup(folder)
            }
            unfiledRows
          }
        }
      }
    }
    .paneBackground()
    .navigationSplitViewColumnWidth(min: 200, ideal: 240)
    .navigationTitle(
      model.selectedVault.map { $0.name ?? $0.key }
        ?? (model.isAllSecrets ? "All Secrets" : "")
    )
    .toolbar {
      ToolbarItem(placement: .primaryAction) {
        Button {
          newFolder()
        } label: {
          Label("New Folder", systemImage: "folder.badge.plus")
        }
        .disabled(model.selectedVault == nil)
      }
      ToolbarItem(placement: .primaryAction) {
        Button {
          showingNewItemSheet = true
        } label: {
          Label("New Item", systemImage: "plus")
        }
        .disabled(model.selectedVault == nil)
      }
    }
    .sheet(isPresented: $showingNewItemSheet) {
      NewItemSheet { key, title in
        guard let vaultKey = model.selectedVaultKey else { return "No vault selected." }
        if await model.addOrUpdateItem(vaultKey: vaultKey, itemKey: key, itemTitle: title) {
          return nil
        }
        return model.actionError ?? "Failed to create item."
      }
    }
    .sheet(item: $titleSheet) { request in
      TitleSheet(request: request)
    }
  }

  private func itemRows(_ items: [DisplayItem]) -> some View {
    ForEach(items) { display in
      itemRow(display)
    }
  }

  private func itemRow(_ display: DisplayItem) -> some View {
    ItemRow(item: display.item)
      .tag(display.id)
      .padding(6)
      .draggable(ItemDrag(vaultKey: display.vaultKey, itemKey: display.item.key))
      .contextMenu { itemMenu(display) }
  }

  /// Folder row followed by its indented items when expanded. Dropping an item
  /// on the folder or its items moves it into the folder.
  @ViewBuilder
  private func folderGroup(_ folder: FolderInfo) -> some View {
    let items = model.displayItems.filter { $0.item.folderId == folder.id }
    let isExpanded = !collapsedFolders.contains(folder.id)
    FolderRow(
      title: folder.title,
      isExpanded: isExpanded,
      isDropTarget: dropTarget == folder.id
    ) {
      withAnimation(.snappy(duration: 0.2)) {
        if isExpanded {
          collapsedFolders.insert(folder.id)
        } else {
          collapsedFolders.remove(folder.id)
        }
      }
    }
    .padding(6)
    .contextMenu { folderMenu(folder) }
    .modifier(dropModifier(targetID: folder.id, folderId: folder.id))

    if isExpanded {
      ForEach(items) { display in
        itemRow(display)
          .padding(.leading, folderItemIndent)
          .modifier(dropModifier(targetID: folder.id, folderId: folder.id))
      }
    }
  }

  /// Unfiled items, listed after the folders. Dropping an item on one of them
  /// removes it from its folder.
  private var unfiledRows: some View {
    ForEach(model.displayItems.filter { $0.item.folderId == nil }) { display in
      let targetID = unfiledDropID(display)
      itemRow(display)
        .background(dropHighlight(dropTarget == targetID))
        .modifier(dropModifier(targetID: targetID, folderId: nil))
    }
  }

  private func unfiledDropID(_ display: DisplayItem) -> String {
    "item:\(display.item.key)"
  }

  private func dropModifier(targetID: String, folderId: String?) -> ItemDropModifier {
    ItemDropModifier(
      targetID: targetID,
      dropTarget: $dropTarget
    ) { drag in
      guard drag.vaultKey == model.selectedVaultKey else { return false }
      Task {
        try? await model.moveItem(
          vaultKey: drag.vaultKey, itemKey: drag.itemKey, folderId: folderId)
      }
      return true
    }
  }

  @ViewBuilder
  private func itemMenu(_ display: DisplayItem) -> some View {
    let vaultFolders = model.folders(for: display.vaultKey)
    if !vaultFolders.isEmpty {
      Menu("Move to") {
        ForEach(vaultFolders, id: \.id) { folder in
          Button(folder.title) { move(display, to: folder.id) }
            .disabled(display.item.folderId == folder.id)
        }
        Divider()
        Button("No Folder") { move(display, to: nil) }
          .disabled(display.item.folderId == nil)
      }
    }
    Button("Delete", role: .destructive) {
      Task {
        await model.deleteItem(
          vaultKey: display.vaultKey, itemKey: display.item.key, undoManager: undoManager)
      }
    }
  }

  @ViewBuilder
  private func folderMenu(_ folder: FolderInfo) -> some View {
    if let vaultKey = model.selectedVaultKey {
      Button("Rename…") {
        titleSheet = TitleSheetRequest(
          heading: "Rename Folder", actionLabel: "Rename", initialTitle: folder.title
        ) { title in
          await failureMessage {
            try await model.renameFolder(vaultKey: vaultKey, folderId: folder.id, title: title)
          }
        }
      }
      Button("Delete", role: .destructive) {
        Task { try? await model.deleteFolder(vaultKey: vaultKey, folderId: folder.id) }
      }
    }
  }

  private func move(_ display: DisplayItem, to folderId: String?) {
    Task {
      try? await model.moveItem(
        vaultKey: display.vaultKey, itemKey: display.item.key, folderId: folderId)
    }
  }

  private func newFolder() {
    guard let vaultKey = model.selectedVaultKey else { return }
    titleSheet = TitleSheetRequest(heading: "New Folder", actionLabel: "Create") { title in
      await failureMessage { try await model.createFolder(vaultKey: vaultKey, title: title) }
    }
  }
}

private func dropHighlight(_ isTargeted: Bool) -> some View {
  RoundedRectangle(cornerRadius: 6)
    .fill(isTargeted ? AnyShapeStyle(.tint.opacity(0.2)) : AnyShapeStyle(.clear))
}

/// Accepts a dropped `ItemDrag`. Records in `dropTarget` whether a drag is
/// over this row.
private struct ItemDropModifier: ViewModifier {
  let targetID: String
  @Binding var dropTarget: String?
  let onDrop: (ItemDrag) -> Bool

  func body(content: Content) -> some View {
    content.dropDestination(for: ItemDrag.self) { dropped, _ in
      dropTarget = nil
      guard let drag = dropped.first else { return false }
      return onDrop(drag)
    } isTargeted: { targeted in
      if targeted {
        dropTarget = targetID
      } else if dropTarget == targetID {
        dropTarget = nil
      }
    }
  }
}

/// Folder row in the item list with a disclosure chevron and title. Clicking
/// it collapses or expands the folder.
private struct FolderRow: View {
  let title: String
  let isExpanded: Bool
  let isDropTarget: Bool
  let onToggle: () -> Void

  var body: some View {
    HStack(spacing: 6) {
      Image(systemName: "chevron.right")
        .font(.caption.weight(.semibold))
        .foregroundStyle(.secondary)
        .rotationEffect(.degrees(isExpanded ? 90 : 0))
        .frame(width: 10)
      Text(title)
        .lineLimit(1)
      Spacer(minLength: 0)
    }
    .background(dropHighlight(isDropTarget).padding(-6))
    .contentShape(.rect)
    .onTapGesture(perform: onToggle)
  }
}

private struct NewItemSheet: View {
  let onSubmit: (_ key: String, _ title: String) async -> String?

  @Environment(\.dismiss) private var dismiss
  @State private var title: String = ""
  @State private var key: String = ""
  @State private var isSubmitting = false
  @State private var errorMessage: String?

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("New Item").font(.headline)
      Form {
        TextField("Title", text: $title)
        TextField("Key", text: $key)
        LabeledContent("") {
          Text("a-z, 0-9, -, _")
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
      }

      if let errorMessage {
        Text(errorMessage)
          .font(.caption)
          .foregroundStyle(.red)
      }

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Create") {
          Task {
            isSubmitting = true
            errorMessage = nil
            if let error = await onSubmit(key, title) {
              errorMessage = error
            } else {
              dismiss()
            }
            isSubmitting = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || key.isEmpty || title.isEmpty)
      }
    }
    .padding(20)
    .frame(width: 320)
  }
}

private struct ItemRow: View {
  let item: ItemInfo
  var body: some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(item.title)
      Text("\(item.credentials.count) credential\(item.credentials.count == 1 ? "" : "s")")
        .font(.subheadline)
        .foregroundStyle(.secondary)
    }
  }
}
