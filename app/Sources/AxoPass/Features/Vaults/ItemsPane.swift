import AuthenticationServices
import AxoPassFFI
import SwiftUI
import UniformTypeIdentifiers

/// Drag payload for moving an item into a folder. The dedicated type limits
/// the drag to the app. Item keys are not exported as plain text, and text
/// dragged in from elsewhere does not decode into a drop.
struct ItemDrag: Codable, Transferable {
  let vaultKey: String
  let itemKeys: [String]

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
  @State private var showingNewLoginSheet = false
  @State private var showingImport = false
  @State private var showingItemImport = false
  @State private var titleSheet: TitleSheetRequest? = nil
  @State private var historyTarget: ItemHistoryTarget? = nil
  @State private var moveError: String? = nil
  // Item the delete confirmation is open for.
  @State private var deletingItem: DisplayItem? = nil
  // Collapsed folder ids.
  @State private var collapsedFolders: Set<String> = []
  // Drop highlight target. A folder id for drops into that folder, or an
  // unfiled item's `unfiledDropID`.
  @State private var dropTarget: String? = nil

  /// Folders in the selected vault. Empty for "All Secrets" and the item types,
  /// which list items from all vaults without grouping.
  private var folders: [FolderInfo] {
    guard !model.isAllVaults, let key = model.selectedVaultKey else { return [] }
    return model.folders(for: key)
  }

  /// List selection. One row selects through `selectedItemRef` so the detail
  /// pane follows. Two or more rows are held in `multiSelection` and the detail
  /// pane is empty.
  private var listSelection: Binding<Set<ItemRef>> {
    Binding(
      get: {
        if let ref = model.selectedItemRef { return [ref] }
        let visible = Set(model.displayItems.map(\.id))
        return model.multiSelection.intersection(visible)
      },
      set: { selection in
        if selection.count > 1 {
          model.selectedItemRef = nil
          model.multiSelection = selection
        } else {
          model.multiSelection = []
          model.selectedItemRef = selection.first
        }
      })
  }

  /// Items an action on `display` applies to. All selected items if `display`
  /// is part of a multi-row selection, otherwise `display` alone.
  private func actionTargets(_ display: DisplayItem) -> [DisplayItem] {
    guard model.multiSelection.contains(display.id) else { return [display] }
    return model.displayItems.filter {
      $0.vaultKey == display.vaultKey && model.multiSelection.contains($0.id)
    }
  }

  var body: some View {
    Group {
      if model.isLoadingSelectedItems {
        DelayedProgressView()
      } else if (model.selectedVault != nil || model.isAllVaults)
        && !(model.displayItems.isEmpty && folders.isEmpty)
      {
        List(selection: listSelection) {
          if folders.isEmpty {
            itemRows(model.displayItems)
          } else {
            ForEach(folders, id: \.id) { folder in
              folderGroup(folder)
            }
            unfiledRows
          }
        }
      } else if let vault = model.selectedVault, model.itemLoadFailures[vault.key] == nil {
        emptyState
      }
    }
    .safeAreaInset(edge: .top, spacing: 0) {
      if model.showAutofillSetupBanner {
        AutofillSetupBanner()
      }
      if let vault = model.selectedVault {
        SyncNoticeBanner(vault: vault)
        SyncChangesBanner(vault: vault)
      }
    }
    .paneBackground()
    .navigationSplitViewColumnWidth(min: 200, ideal: 240)
    .navigationTitle(model.itemListTitle)
    .focusedSceneValue(
      \.newItemAction,
      model.selectedVault == nil ? nil : { showingNewItemSheet = true }
    )
    .toolbar {
      ToolbarItem(placement: .primaryAction) {
        Menu {
          Button("New Login…") { showingNewLoginSheet = true }
          Button("New Item…") { showingNewItemSheet = true }
          Divider()
          Button("New Folder") { newFolder() }
        } label: {
          Label("New", systemImage: "plus")
        }
        .disabled(model.selectedVault == nil)
      }
    }
    .sheet(isPresented: $showingImport) {
      VaultImportSheet(model: model)
    }
    .sheet(isPresented: $showingItemImport) {
      ItemImportSheet(model: model)
    }
    .sheet(isPresented: $showingNewItemSheet) {
      NewItemSheet { key, title in
        guard let vaultKey = model.selectedVaultKey else { return "No vault selected." }
        if await model.addItem(vaultKey: vaultKey, itemKey: key, itemTitle: title) {
          return nil
        }
        return model.actionError ?? "Failed to create item."
      }
    }
    .alert(
      "Could Not Move Item",
      isPresented: Binding(get: { moveError != nil }, set: { if !$0 { moveError = nil } })
    ) {
      Button("OK") { moveError = nil }
    } message: {
      Text(moveError ?? "")
    }
    .sheet(isPresented: $showingNewLoginSheet) {
      NewItemSheet(heading: "New Login") { key, title in
        guard let vaultKey = model.selectedVaultKey else { return "No vault selected." }
        let created = await model.createLogin(vaultKey: vaultKey, itemKey: key, title: title)
        return created == nil ? (model.actionError ?? "Failed to create login.") : nil
      }
    }
    .sheet(item: $titleSheet) { request in
      TitleSheet(request: request)
    }
    .sheet(item: $historyTarget) { target in
      ItemHistorySheet(target: target)
    }
    .confirmationDialog(
      "Delete \"\(deletingItem?.item.title ?? "this item")\"?",
      isPresented: Binding(
        get: { deletingItem != nil }, set: { if !$0 { deletingItem = nil } }),
      titleVisibility: .visible,
      presenting: deletingItem
    ) { display in
      Button("Delete", role: .destructive) {
        Task {
          await model.deleteItem(
            vaultKey: display.vaultKey, itemKey: display.item.key, undoManager: undoManager)
        }
      }
      Button("Cancel", role: .cancel) {}
        .keyboardShortcut(.defaultAction)
    } message: { _ in
      Text("You can restore the item from Recently Deleted.")
    }
  }

  /// Shown for a vault with no items. "New Login" and "New Item" open the
  /// sheets of the toolbar menu. "Import" offers a password manager export or
  /// a backup.
  private var emptyState: some View {
    ContentUnavailableView {
      Label("No Items", systemImage: "tray")
    } description: {
      Text("Add a login, or import items from a backup or another password manager.")
    } actions: {
      Button("New Login") { showingNewLoginSheet = true }
      Button("New Item") { showingNewItemSheet = true }
      Menu("Import") {
        Button("Import Passwords…") { showingItemImport = true }
        Button("Import Backup…") { showingImport = true }
      }
      .menuStyle(.button)
      .fixedSize()
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
      .listRowSeparator(.hidden)
      .draggable(
        ItemDrag(
          vaultKey: display.vaultKey, itemKeys: actionTargets(display).map(\.item.key))
      )
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
    .listRowSeparator(.hidden)
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
        try? await model.moveItems(
          vaultKey: drag.vaultKey, itemKeys: drag.itemKeys, folderId: folderId)
      }
      return true
    }
  }

  @ViewBuilder
  private func itemMenu(_ display: DisplayItem) -> some View {
    let targets = actionTargets(display)
    let vaultFolders = model.folders(for: display.vaultKey)
    if !vaultFolders.isEmpty {
      Menu("Move to") {
        ForEach(vaultFolders, id: \.id) { folder in
          Button(folder.title) { move(targets, to: folder.id) }
            .disabled(targets.allSatisfy { $0.item.folderId == folder.id })
        }
        Divider()
        Button("No Folder") { move(targets, to: nil) }
          .disabled(targets.allSatisfy { $0.item.folderId == nil })
      }
    }
    if targets.count == 1 {
      Button("Rename…") {
        titleSheet = TitleSheetRequest.renameItem(
          display.item, vaultKey: display.vaultKey, model: model)
      }
      Button("Change Key…") {
        titleSheet = TitleSheetRequest.changeItemKey(
          display.item, vaultKey: display.vaultKey, model: model)
      }
      Button("History…") {
        historyTarget = ItemHistoryTarget(display.item, vaultKey: display.vaultKey)
      }
    }
    let otherVaults = model.vaults.filter { $0.key != display.vaultKey }
    if !otherVaults.isEmpty {
      Menu("Move to Vault") {
        ForEach(otherVaults, id: \.key) { vault in
          Button(vault.name ?? vault.key) { moveToVault(targets, destVaultKey: vault.key) }
        }
      }
    }
    if targets.count == 1 {
      Button("Delete…", role: .destructive) { deletingItem = display }
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

  /// Move items to another vault. Items whose key is free in the destination
  /// move immediately. For each item whose key is taken, ask for a new key in
  /// turn.
  private func moveToVault(_ displays: [DisplayItem], destVaultKey: String) {
    Task {
      let destKeys = Set(await model.destinationItems(in: destVaultKey).map(\.key))
      var conflicts: [DisplayItem] = []
      for display in displays {
        if destKeys.contains(display.item.key) {
          conflicts.append(display)
        } else if let error = await failureMessage({
          try await model.moveItemToVault(
            vaultKey: display.vaultKey, itemKey: display.item.key, destVaultKey: destVaultKey,
            destItemKey: nil)
        }) {
          moveError = error
          return
        }
      }
      promptForKey(conflicts[...], destVaultKey: destVaultKey)
    }
  }

  /// Ask for a new key for the first item, move it, then continue with the rest.
  private func promptForKey(_ pending: ArraySlice<DisplayItem>, destVaultKey: String) {
    guard let display = pending.first else { return }
    titleSheet = TitleSheetRequest(
      heading: "Key Already Used", actionLabel: "Move", initialTitle: display.item.key,
      fieldLabel: "Key"
    ) { key in
      let error = await failureMessage {
        try await model.moveItemToVault(
          vaultKey: display.vaultKey, itemKey: display.item.key, destVaultKey: destVaultKey,
          destItemKey: key)
      }
      if error == nil {
        Task { @MainActor in
          promptForKey(pending.dropFirst(), destVaultKey: destVaultKey)
        }
      }
      return error
    }
  }

  private func move(_ displays: [DisplayItem], to folderId: String?) {
    guard let vaultKey = displays.first?.vaultKey else { return }
    Task {
      try? await model.moveItems(
        vaultKey: vaultKey, itemKeys: displays.map(\.item.key), folderId: folderId)
    }
  }

  private func newFolder() {
    guard let vaultKey = model.selectedVaultKey else { return }
    titleSheet = TitleSheetRequest(heading: "New Folder", actionLabel: "Create") { title in
      await failureMessage { try await model.createFolder(vaultKey: vaultKey, title: title) }
    }
  }
}

/// Tells the user, once, that the system's AutoFill provider is off.
private struct AutofillSetupBanner: View {
  @Environment(VaultsModel.self) private var model

  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      Label("Turn on AutoFill", systemImage: "key.viewfinder")
        .font(.subheadline.weight(.semibold))
      Text("Enable Axo Pass in System Settings to fill logins in Safari and other apps.")
        .font(.caption)
        .foregroundStyle(.secondary)
      HStack {
        Button("Open System Settings") {
          ASSettingsHelper.openCredentialProviderAppSettings { _ in }
          model.dismissAutofillSetupBanner()
        }
        Button("Not Now") { model.dismissAutofillSetupBanner() }
      }
      .controlSize(.small)
    }
    .padding(10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .opaqueBannerBackground()
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
  var heading = "New Item"
  let onSubmit: (_ key: String, _ title: String) async -> String?

  @Environment(\.dismiss) private var dismiss
  @State private var title: String = ""
  @State private var key: String = ""
  @State private var isSubmitting = false
  @State private var errorMessage: String?

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(heading).font(.headline)
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
    HStack(spacing: 10) {
      Monogram(title: item.title, host: item.siteHosts.first)
      VStack(alignment: .leading, spacing: 2) {
        Text(item.title)
        Text(item.subtitle)
          .font(.subheadline)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
      }
      if item.hasConflicts {
        Spacer(minLength: 0)
        Image(systemName: "arrow.triangle.branch")
          .foregroundStyle(.orange)
          .help("Values from more than one Mac conflict. Open the item to resolve them.")
      }
    }
  }
}
