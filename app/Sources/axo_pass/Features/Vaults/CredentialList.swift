import AppKit
import AxoPassFFI
import CryptoKit
import SwiftUI

/// Inset applied to each credential row.
let credentialRowInset: CGFloat = 8

/// Horizontal inset of rows inside a section. Leaves room for the section
/// outline.
private let sectionContentInset: CGFloat = 14

/// Placeholder title for new sections. The title field opens immediately for
/// renaming.
private let newSectionTitle = "New Section"

/// Item credentials and sections, edited in place as in Finder. Rows can be
/// selected and dragged at any time. Return or double-click renames the
/// selected row. Delete removes the selection, with undo. ⌘C copies the
/// selected credential, in the outline or the login card. Other actions are in
/// the context menu.
struct CredentialList: View {
  /// A title or id being renamed in place.
  enum RenameTarget: Equatable {
    case credential(String, CredentialRow.RenameField)
    case section(String)
  }

  @Environment(VaultsModel.self) var model
  /// Nil in windows without the SSH pane.
  @Environment(SshModel.self) var ssh: SshModel?
  @Environment(\.undoManager) var undoManager
  let item: ItemInfo
  let vaultKey: String

  @State var secrets: [String: SymmetricKey] = [:]
  @State var errors: [String: String] = [:]
  @State var sectionErrors: [String: String] = [:]
  @State var revealing: Set<String> = []
  @State var selection: Set<CredentialEntry> = []
  @State var renaming: RenameTarget? = nil
  @State var collapsedSections: Set<String> = []
  // Local override of the row order while a move is being saved. Cleared once
  // the save finishes and the model has reloaded.
  @State var pendingEntries: [CredentialEntry]? = nil
  // Section created by Add Section with an unconfirmed title. Escape while
  // naming deletes it.
  @State private var unnamedSection: String? = nil
  // Section creation error. Shown separately since there is no row for it.
  @State var listError: String? = nil
  // Decrypted copy of a file open in Quick Look. Removed when it closes.
  @State var previewURL: URL? = nil
  // Keys of file credentials being read or replaced.
  @State var fileBusy: Set<String> = []
  @State private var showingNewCredentialSheet = false
  @State private var showingRenameItemSheet = false
  // Credential whose previous values are shown.
  @State private var previousValuesTarget: PreviousValuesTarget? = nil
  // Item whose history is shown.
  @State private var historyTarget: ItemHistoryTarget? = nil
  // Key of the passkey the move sheet is open for.
  @State private var movingPasskey: String? = nil
  // Key of the selected login card credential. Selecting a card row clears the
  // outline selection, and selecting outline rows clears this.
  @State var cardSelection: String? = nil
  // Key of the credential a copy shortcut just copied. Its row shows the copy
  // confirmation until this is cleared.
  @State var shortcutCopied: String? = nil
  // Incremented to move focus to the outline.
  @State var outlineFocusRequest = 0
  // Entries the delete confirmation is open for.
  @State var pendingDelete: Set<CredentialEntry>? = nil
  // Key of the login card credential a context menu is open for. Its row shows
  // the menu target outline.
  @State var cardMenuTarget: String? = nil
  // Login field whose editor the login card shows.
  @State var addingLoginField: LoginField? = nil
  // Login card shows the new website field.
  @State var addingWebsite = false

  var body: some View {
    CredentialOutline(
      entries: listedEntries,
      collapsedSections: collapsedSections,
      selection: $selection,
      scrollTarget: renamingSection.map(CredentialEntry.section),
      isRenaming: renaming != nil,
      focusRequest: outlineFocusRequest,
      // Outline rows are hosted in their own NSHostingViews, which do not
      // inherit this view's environment.
      banner: { AnyView(banner(isEmphasized: $0).environment(model)) },
      row: { entry, state in AnyView(row(entry, state: state).environment(model)) },
      menu: { menuItems(for: $0) },
      normalizeSelection: normalizedSelection,
      onSetCollapsed: { id, collapsed in
        if collapsed {
          collapsedSections.insert(id)
        } else {
          collapsedSections.remove(id)
        }
      },
      onMove: moveEntries,
      onPrimaryAction: startRename,
      onOpen: { selected in
        if !quickLook(selected) { startRename(selected) }
      },
      onQuickLook: quickLook,
      onDelete: delete,
      onMouseDown: { cardSelection = nil }
    )
    .onCopyCommand {
      copySelection()
      return []
    }
    .onChange(of: selection) { _, new in
      if !new.isEmpty { cardSelection = nil }
    }
    .quickLookPreview($previewURL)
    .onChange(of: previewURL) { old, new in
      if old != new { previewClosed(old) }
    }
    .onDisappear { previewClosed(previewURL) }
    .background {
      Button("Copy Username", action: copyUsername)
        .keyboardShortcut("c", modifiers: [.command, .shift])
        .opacity(0)
        .frame(width: 0, height: 0)
        .accessibilityHidden(true)
    }
    .navigationTitle(item.title)
    .toolbar {
      ToolbarItemGroup(placement: .primaryAction) {
        // Push the item actions to the trailing edge of the toolbar.
        Spacer()

        Button(allRevealed ? "Hide All" : "Reveal All") {
          if allRevealed {
            hideAll()
          } else {
            Task { await revealAll() }
          }
        }
        .disabled(!hasConcealed || !revealing.isEmpty)

        Menu {
          addMenuButtons
        } label: {
          Label("Add", systemImage: "plus")
        }
        .help("Add to this item.")

        Button {
          historyTarget = ItemHistoryTarget(item, vaultKey: vaultKey)
        } label: {
          Label("History", systemImage: "clock.arrow.circlepath")
        }
        .help("Show item history.")
      }
    }
    .confirmationDialog(
      pendingDelete.map(deleteTitle) ?? "Delete?",
      isPresented: Binding(
        get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
      titleVisibility: .visible,
      presenting: pendingDelete
    ) { selected in
      Button("Delete", role: .destructive) { performDelete(selected) }
      Button("Cancel", role: .cancel) {}
        .keyboardShortcut(.defaultAction)
    } message: { selected in
      Text(deleteMessage(selected))
    }
    .sheet(item: $historyTarget) { target in
      ItemHistorySheet(target: target)
    }
    .sheet(item: $previousValuesTarget) { target in
      PreviousValuesSheet(
        vaultKey: vaultKey, itemKey: item.key, credKey: target.key, title: target.title,
        onValueChanged: { refreshCachedSecret(for: target.key) })
    }
    .sheet(isPresented: $showingRenameItemSheet) {
      RenameItemSheet(title: item.title, key: item.key) { title, newKey in
        await failureMessage {
          try await model.renameItem(
            vaultKey: vaultKey, itemKey: item.key, title: title, newKey: newKey)
        }
      }
    }
    .sheet(isPresented: $showingNewCredentialSheet) {
      NewCredentialSheet { key, title, value, kind in
        if await model.addCredential(
          vaultKey: vaultKey, itemKey: item.key, credKey: key, title: title, value: value,
          kind: kind
        ) {
          return nil
        }
        return model.actionError ?? "Failed to create credential."
      }
    }
    .sheet(
      isPresented: Binding(
        get: { movingPasskey != nil }, set: { if !$0 { movingPasskey = nil } })
    ) {
      if let credKey = movingPasskey {
        MovePasskeySheet(sourceVaultKey: vaultKey, sourceItemKey: item.key) { destVault, destItem in
          if await model.movePasskey(
            vaultKey: vaultKey, itemKey: item.key, credKey: credKey, destVaultKey: destVault,
            destItemKey: destItem)
          {
            secrets.removeValue(forKey: credKey)
            return nil
          }
          return model.actionError ?? "Failed to move the passkey."
        }
      }
    }
  }

  private var renamingSection: String? {
    if case .section(let id)? = renaming { return id }
    return nil
  }

  /// Top row. Item title and key, the login banners and card, then list
  /// messages. Header is inset to the login card edge.
  private func banner(isEmphasized: Bool) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      header
        .padding(
          EdgeInsets(
            top: 20, leading: credentialRowInset, bottom: 16, trailing: credentialRowInset))

      VStack(alignment: .leading, spacing: credentialRowInset * 2) {
        loginSection(isEmphasized: isEmphasized)
      }
      .padding(.horizontal, credentialRowInset)

      if let listError {
        Text(listError)
          .font(.caption)
          .foregroundStyle(.red)
          .padding(4)
      }

      if let undoFailure = model.undoFailure, undoFailure.vaultKey == vaultKey,
        undoFailure.itemKey == item.key
      {
        Text(undoFailure.message)
          .font(.caption)
          .foregroundStyle(.red)
          .textSelection(.enabled)
          .padding(4)
      }

      if item.credentials.isEmpty, item.sections.isEmpty {
        // Aligned with a credential row's text, which sits at the row inset
        // plus CredentialRow's own horizontal padding.
        Text("No credentials")
          .foregroundStyle(.secondary)
          .padding(
            EdgeInsets(
              top: credentialRowInset, leading: credentialRowInset + 6,
              bottom: credentialRowInset, trailing: credentialRowInset + 6
            ))
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  /// The item's identity: a monogram, the title, and for a login the account
  /// and site. The item key is for the CLI, so a login shows it only in the
  /// header's tooltip and context menu.
  private var header: some View {
    HStack(alignment: .center, spacing: 12) {
      Monogram(title: item.title, host: item.siteHosts.first, size: 40)
      VStack(alignment: .leading, spacing: 2) {
        Text(item.title).font(.title2).fontWeight(.semibold)
        Text(headerSubtitle)
          .font(.callout)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
          .textSelection(.enabled)
      }
    }
    .help("Item key: \(item.key)")
    .contextMenu {
      Button("Rename Item…") { showingRenameItemSheet = true }
      Button("Copy Item Key", action: copyItemKey)
      Button("History…") { historyTarget = ItemHistoryTarget(item, vaultKey: vaultKey) }
      Divider()
      addMenuButtons
    }
  }

  /// Add menu entry.
  private struct AddAction {
    let title: String
    let action: () -> Void
  }

  /// Add menu entries in groups. A login lists its missing fields first, in
  /// login card order.
  private var addActionGroups: [[AddAction]] {
    let general = [
      AddAction(title: "Add Credential…") { showingNewCredentialSheet = true },
      AddAction(title: "Add File…") { addFile() },
      AddAction(title: "Add Section") { newSection() },
    ]
    guard item.isLogin else { return [general] }
    var login: [AddAction] = []
    if item.usernameCredential == nil {
      login.append(AddAction(title: "Add Username") { addingLoginField = .username })
    }
    if item.passwordCredential == nil {
      login.append(AddAction(title: "Add Password") { addingLoginField = .password })
    }
    if item.totpCredential == nil {
      login.append(AddAction(title: "Add One-Time Code") { addingLoginField = .totp })
    }
    login.append(AddAction(title: "Add Website") { addingWebsite = true })
    return [login, general]
  }

  /// Add menu entries as menu buttons.
  @ViewBuilder
  private var addMenuButtons: some View {
    ForEach(Array(addActionGroups.enumerated()), id: \.offset) { index, group in
      if index > 0 { Divider() }
      ForEach(group, id: \.title) { entry in
        Button(entry.title, action: entry.action)
      }
    }
  }

  /// Add menu entries as outline context menu items.
  private var addMenuItems: [OutlineMenuItem] {
    addActionGroups.enumerated().flatMap { index, group in
      (index > 0 ? [OutlineMenuItem.divider] : [])
        + group.map { entry in OutlineMenuItem.action(entry.title, entry.action) }
    }
  }

  private func copyItemKey() {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(item.key, forType: .string)
  }

  private var headerSubtitle: String {
    guard item.isLogin else { return item.key }
    let parts = [item.username, item.siteHosts.first].compactMap { $0 }.filter { !$0.isEmpty }
    return parts.isEmpty ? item.key : parts.joined(separator: " · ")
  }

  /// Row content with insets. The outline row view draws the highlight and
  /// section outline behind it.
  private func row(_ entry: CredentialEntry, state: OutlineRowState) -> some View {
    // Hierarchical colors turn light on the accent highlight, matching the
    // native highlight.
    rowContent(entry, outline: state.outline)
      .environment(\.backgroundProminence, state.isProminent ? .increased : .standard)
  }

  @ViewBuilder
  private func rowContent(_ entry: CredentialEntry, outline: SectionOutline.Position?)
    -> some View
  {
    switch entry {
    case .section(let id):
      if let section = item.sections.first(where: { $0.id == id }) {
        // Insets are the same expanded and collapsed, so the header height
        // does not change. The bottom inset leaves room for the outline and
        // highlight to close under a collapsed title.
        sectionHeader(section)
          .padding(
            EdgeInsets(
              top: SectionOutline.gap + 12, leading: sectionContentInset + 6,
              bottom: 12, trailing: sectionContentInset + 6))
      }
    case .credential(let key):
      if let cred = item.credentials.first(where: { $0.key == key }) {
        // Credentials in a section are inset further to clear the outline.
        let side = outline == nil ? credentialRowInset : sectionContentInset
        credentialRowBody(cred)
          .padding(
            EdgeInsets(
              top: credentialRowInset, leading: side,
              bottom: outline == .bottom ? credentialRowInset + 8 : credentialRowInset,
              trailing: side))
      }
    }
  }

  private func sectionHeader(_ section: SectionInfo) -> some View {
    SectionHeader(
      title: section.title,
      count: credentialCount(inSection: section.id),
      isCollapsed: collapsedSections.contains(section.id),
      isRenaming: renaming == .section(section.id),
      error: sectionErrors[section.id],
      onToggleCollapsed: {
        if collapsedSections.remove(section.id) == nil {
          collapsedSections.insert(section.id)
        }
      },
      onRename: { renameSection(section, to: $0) },
      onCancelRename: { cancelSectionRename(section.id) }
    )
  }

  /// A credential row. `fieldLabel` gives it the login card layout.
  func credentialRowBody(_ cred: CredentialInfo, fieldLabel: String? = nil) -> some View {
    CredentialRow(
      cred: cred,
      vaultKey: vaultKey,
      itemKey: item.key,
      secret: secrets[cred.key],
      error: errors[cred.key],
      isRevealing: revealing.contains(cred.key),
      renaming: renamingField(of: cred.key),
      onReveal: { Task { await reveal(cred) } },
      onHide: { hide(cred) },
      onCopy: { await copy(cred) },
      onRename: { field, text in rename(cred, field: field, to: text) },
      onCancelRename: { renaming = nil },
      onQuickSaveValue: { newValue in
        Task { await quickSaveValue(cred, newValue: newValue) }
      },
      onDelete: { delete([.credential(cred.key)]) },
      onMove: { movingPasskey = cred.key },
      onStartRename: { field in renaming = .credential(cred.key, field) },
      onShowPreviousValues: {
        previousValuesTarget = PreviousValuesTarget(key: cred.key, title: cred.title)
      },
      onSetRole: { role, assign in
        Task { await setRole(cred, role: role, assign: assign) }
      },
      fileFailure: model.fileFailure(vaultKey: vaultKey, itemKey: item.key, credKey: cred.key),
      isFileBusy: fileBusy.contains(cred.key),
      onPreviewFile: { previewFile(cred) },
      onSaveFile: { saveFile(cred) },
      onReplaceFile: { replaceFile(cred) },
      onReplaceFileWith: { replaceFile(cred, with: $0) },
      fieldLabel: fieldLabel,
      showsCopied: shortcutCopied == cred.key,
      isDuplicatePasskey: item.hasDuplicate(of: cred)
    )
  }

  private func renamingField(of key: String) -> CredentialRow.RenameField? {
    if case .credential(key, let field)? = renaming { return field }
    return nil
  }

  // MARK: - Context menu

  /// Context menu for the targeted rows. Empty targets mean empty space.
  private func menuItems(for selected: Set<CredentialEntry>) -> [OutlineMenuItem] {
    guard !selected.isEmpty else {
      return [
        .action("Rename Item…") { showingRenameItemSheet = true },
        .action("Copy Item Key") { copyItemKey() },
        .action("History…") { historyTarget = ItemHistoryTarget(item, vaultKey: vaultKey) },
        .divider,
      ] + addMenuItems
    }

    var items: [OutlineMenuItem] = []
    if let entry = renameTarget(selected) {
      items += singleEntryMenu(entry)
      items.append(.divider)
    }

    let keys = Set(
      selected.compactMap { entry -> String? in
        if case .credential(let key) = entry { return key }
        return nil
      })
    // Selected sections move as a whole by dragging. They cannot be moved
    // into another section.
    if !keys.isEmpty, !selected.contains(where: \.isSection), !item.sections.isEmpty {
      items.append(
        .submenu(
          "Move to Section",
          [.action("No Section") { moveCredentials(keys, toSection: nil) }, .divider]
            + item.sections.map { section in
              .action(section.title) { moveCredentials(keys, toSection: section.id) }
            }))
      items.append(.divider)
    }

    items.append(.action("Delete…") { delete(selected) })
    return items
  }

  private func singleEntryMenu(_ entry: CredentialEntry) -> [OutlineMenuItem] {
    switch entry {
    case .section(let id):
      return [.action("Rename") { renaming = .section(id) }]
    case .credential(let key):
      guard let cred = item.credentials.first(where: { $0.key == key }) else { return [] }
      var items: [OutlineMenuItem] = [
        .action("Rename") { renaming = .credential(key, .title) },
        .action("Change Key") { renaming = .credential(key, .key) },
        .divider,
      ]
      if cred.kind.kind == "file" {
        // A file has no text value, so it has no previous values to show.
        items += [
          .action("Quick Look") { previewFile(cred) },
          .action("Save…") { saveFile(cred) },
          .action("Replace…") { replaceFile(cred) },
        ]
      } else {
        items.append(
          .action("History…") {
            previousValuesTarget = PreviousValuesTarget(key: key, title: cred.title)
          })
      }
      if cred.kind.kind == "ssh-key", let ssh,
        let entry = ssh.vaultKeyEntry(vaultKey: vaultKey, itemKey: item.key, credentialKey: key)
      {
        items.append(
          .action("Show in SSH") {
            ssh.show(fingerprintSha256: entry.fingerprintSha256, vaults: model)
          })
      }
      let roles = roleMenuItems(for: cred)
      if !roles.isEmpty {
        items += [.divider] + roles
      }
      // Concealed and multiline apply only to freeform text credentials. The
      // password role always conceals the value, so it hides them too.
      if cred.kind.kind == "text", cred.role != "password" {
        items += [
          .divider,
          .toggle("Concealed", isOn: cred.kind.concealed) {
            setTextOptions(cred, concealed: $0, multiline: cred.kind.multiline)
          },
          .toggle("Multiline", isOn: cred.kind.multiline) {
            setTextOptions(cred, concealed: cred.kind.concealed, multiline: $0)
          },
        ]
      }
      return items
    }
  }

  /// Autofill role actions for a credential. A one-time code credential can only
  /// be the code source, and a passkey or a file takes no role.
  private func roleMenuItems(for cred: CredentialInfo) -> [OutlineMenuItem] {
    func roleItem(_ role: String, assign: String, clear: String) -> OutlineMenuItem {
      let isAssigned = cred.role == role
      return .action(isAssigned ? clear : assign) {
        Task { await setRole(cred, role: role, assign: !isAssigned) }
      }
    }
    switch cred.kind.kind {
    case "passkey", "file", "unknown":
      return []
    case "totp":
      return [
        roleItem("totp", assign: "Use for One-Time Code", clear: "Stop Using for One-Time Code")
      ]
    default:
      return [
        roleItem("username", assign: "Use as Username", clear: "Stop Using as Username"),
        roleItem("password", assign: "Use as Password", clear: "Stop Using as Password"),
      ]
    }
  }

  /// Rename the title of the single selected row. Triggered by Return or
  /// double-click.
  private func startRename(_ selected: Set<CredentialEntry>) {
    guard let entry = renameTarget(selected) else { return }
    switch entry {
    case .section(let id): renaming = .section(id)
    case .credential(let key): renaming = .credential(key, .title)
    }
  }

  /// Open Quick Look if the selection is a single file credential. Returns
  /// false otherwise.
  private func quickLook(_ selected: Set<CredentialEntry>) -> Bool {
    guard selected.count == 1, case .credential(let key)? = selected.first,
      let cred = item.credentials.first(where: { $0.key == key }), cred.kind.kind == "file"
    else { return false }
    previewFile(cred)
    return true
  }

  // MARK: - Sections

  /// Create a section with a placeholder title and start renaming it.
  private func newSection() {
    listError = nil
    Task {
      do {
        let id = try await model.createSection(
          vaultKey: vaultKey, itemKey: item.key, title: newSectionTitle)
        unnamedSection = id
        selection = [.section(id)]
        renaming = .section(id)
      } catch {
        listError = String(describing: error)
      }
    }
  }

  private func renameSection(_ section: SectionInfo, to title: String) {
    renaming = nil
    unnamedSection = nil
    guard title != section.title else { return }
    Task {
      sectionErrors[section.id] = await failureMessage {
        try await model.renameSection(
          vaultKey: vaultKey, itemKey: item.key, sectionId: section.id, title: title)
      }
    }
  }

  /// Handle Escape while renaming a section. Removes a new section that was
  /// never named.
  private func cancelSectionRename(_ id: String) {
    renaming = nil
    guard unnamedSection == id else { return }
    unnamedSection = nil
    selection.remove(.section(id))
    Task {
      try? await model.deleteSection(vaultKey: vaultKey, itemKey: item.key, sectionId: id)
    }
  }
}

/// Section header with a title and disclosure chevron. Collapsed sections show
/// a credential count.
private struct SectionHeader: View {
  let title: String
  let count: Int
  let isCollapsed: Bool
  let isRenaming: Bool
  let error: String?
  let onToggleCollapsed: () -> Void
  let onRename: (String) -> Void
  let onCancelRename: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      HStack(spacing: 6) {
        Button(action: onToggleCollapsed) {
          Image(systemName: "chevron.right")
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .rotationEffect(.degrees(isCollapsed ? 0 : 90))
            .animation(.snappy(duration: 0.2), value: isCollapsed)
            .frame(width: 12, height: 12)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .help(isCollapsed ? "Expand" : "Collapse")

        Group {
          if isRenaming {
            InlineRenameField(
              initial: title, placeholder: "Section", onCommit: onRename,
              onCancel: onCancelRename)
          } else {
            Text(title)
          }
        }
        .font(.title3)
        .fontWeight(.semibold)

        if isCollapsed {
          Text("\(count)")
            .font(.callout)
            .foregroundStyle(.secondary)
        }
        Spacer(minLength: 0)
      }
      if let error {
        Text(error).font(.caption).foregroundStyle(.red)
      }
    }
  }
}
