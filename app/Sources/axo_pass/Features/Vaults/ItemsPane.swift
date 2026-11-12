import AuthenticationServices
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
  @State private var showingNewLoginSheet = false
  @State private var searchQuery = ""
  @State private var titleSheet: TitleSheetRequest? = nil
  @State private var renamingItem: DisplayItem? = nil
  @State private var moveError: String? = nil
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

  private var isSearching: Bool {
    !searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
  }

  /// Items matching the search, without folder grouping.
  private var searchResults: [DisplayItem] {
    model.displayItems.filter { $0.item.matches(searchQuery: searchQuery) }
  }

  var body: some View {
    @Bindable var model = model
    Group {
      if model.isLoadingSelectedItems {
        DelayedProgressView()
      } else if isSearching, model.selectedVault != nil || model.isAllVaults {
        if searchResults.isEmpty {
          ContentUnavailableView.search(text: searchQuery)
        } else {
          List(selection: $model.selectedItemRef) {
            itemRows(searchResults)
          }
        }
      } else if (model.selectedVault != nil || model.isAllVaults)
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
    .safeAreaInset(edge: .top, spacing: 0) {
      if model.showAutofillSetupBanner {
        AutofillSetupBanner()
      }
      if let vault = model.selectedVault {
        SyncNoticeBanner(vault: vault)
      }
    }
    .paneBackground()
    .navigationSplitViewColumnWidth(min: 200, ideal: 240)
    .navigationTitle(model.itemListTitle)
    .searchable(text: $searchQuery, prompt: "Search")
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
        Menu {
          Button("New Login…") { showingNewLoginSheet = true }
          Button("New Item…") { showingNewItemSheet = true }
        } label: {
          Label("New", systemImage: "plus")
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
    .alert(
      "Could Not Move Item",
      isPresented: Binding(get: { moveError != nil }, set: { if !$0 { moveError = nil } })
    ) {
      Button("OK") { moveError = nil }
    } message: {
      Text(moveError ?? "")
    }
    .sheet(item: $renamingItem) { display in
      RenameItemSheet(title: display.item.title, key: display.item.key) { title, key in
        await failureMessage {
          try await model.renameItem(
            vaultKey: display.vaultKey, itemKey: display.item.key, title: title, newKey: key)
        }
      }
    }
    .sheet(isPresented: $showingNewLoginSheet) {
      NewLoginSheet(
        onSubmit: { website, username, password, key, title in
          guard let vaultKey = model.selectedVaultKey else { return "No vault selected." }
          let created = await model.createLogin(
            vaultKey: vaultKey, website: website,
            username: username.isEmpty ? nil : username, password: password,
            itemKey: key.isEmpty ? nil : key, title: title.isEmpty ? nil : title)
          return created == nil ? (model.actionError ?? "Failed to create login.") : nil
        },
        generatePassword: { length, symbols in
          model.generatePassword(length: length, symbols: symbols)
        })
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
    Button("Rename…") { renamingItem = display }
    let otherVaults = model.vaults.filter { $0.key != display.vaultKey }
    if !otherVaults.isEmpty {
      Menu("Move to Vault") {
        ForEach(otherVaults, id: \.key) { vault in
          Button(vault.name ?? vault.key) { moveToVault(display, destVaultKey: vault.key) }
        }
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

  /// Move an item to another vault. If the destination has an item with the
  /// key, ask for a new key first.
  private func moveToVault(_ display: DisplayItem, destVaultKey: String) {
    Task {
      let taken = await model.destinationItems(in: destVaultKey).contains {
        $0.key == display.item.key
      }
      if taken {
        titleSheet = TitleSheetRequest(
          heading: "Key Already Used", actionLabel: "Move", initialTitle: display.item.key,
          fieldLabel: "Key"
        ) { key in
          await failureMessage {
            try await model.moveItemToVault(
              vaultKey: display.vaultKey, itemKey: display.item.key, destVaultKey: destVaultKey,
              destItemKey: key)
          }
        }
      } else if let error = await failureMessage({
        try await model.moveItemToVault(
          vaultKey: display.vaultKey, itemKey: display.item.key, destVaultKey: destVaultKey,
          destItemKey: nil)
      }) {
        moveError = error
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
    .background(.quaternary)
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

/// Sheet that edits the title and key of an item.
struct RenameItemSheet: View {
  let onSubmit: (_ title: String, _ key: String) async -> String?

  @Environment(\.dismiss) private var dismiss
  @State private var title: String
  @State private var key: String
  @State private var isSubmitting = false
  @State private var errorMessage: String?

  init(title: String, key: String, onSubmit: @escaping (String, String) async -> String?) {
    _title = State(initialValue: title)
    _key = State(initialValue: key)
    self.onSubmit = onSubmit
  }

  private var trimmedTitle: String { title.trimmingCharacters(in: .whitespacesAndNewlines) }
  private var trimmedKey: String { key.trimmingCharacters(in: .whitespacesAndNewlines) }

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Rename Item").font(.headline)
      Form {
        TextField("Title", text: $title)
        TextField("Key", text: $key)
        LabeledContent("") {
          Text("Changing the key breaks references to the old key.")
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
        Button("Rename") {
          Task {
            isSubmitting = true
            errorMessage = nil
            if let error = await onSubmit(trimmedTitle, trimmedKey) {
              errorMessage = error
            } else {
              dismiss()
            }
            isSubmitting = false
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(isSubmitting || trimmedKey.isEmpty || trimmedTitle.isEmpty)
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
    }
  }
}
